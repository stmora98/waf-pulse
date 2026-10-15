"""Azure Advisor recommendations, read tenant wide from Azure Resource Graph (Reader is enough)."""
from collections import defaultdict

from . import graph
from .findings import make_finding, subscription_of

MAX_ROWS = 20000
MAX_FINDINGS = 5000

ADVISOR_QUERY = """
advisorresources
| where type =~ 'microsoft.advisor/recommendations'
| extend category = tostring(properties.category),
         impact = tostring(properties.impact),
         recommendationType = tostring(properties.recommendationTypeId),
         impactedType = tolower(tostring(properties.impactedField)),
         impactedName = tostring(properties.impactedValue),
         problem = tostring(properties.shortDescription.problem),
         solution = tostring(properties.shortDescription.solution),
         resourceId = tostring(properties.resourceMetadata.resourceId),
         annualSavings = todouble(properties.extendedProperties.annualSavingsAmount),
         currency = tostring(properties.extendedProperties.savingsCurrency)
| project id, subscriptionId, category, impact, recommendationType, impactedType, impactedName,
          problem, solution, resourceId, annualSavings, currency
"""

CATEGORY_TO_PILLAR = {
    "highavailability": "Reliability",
    "reliability": "Reliability",
    "security": "Security",
    "cost": "Cost Optimization",
    "operationalexcellence": "Operational Excellence",
    "performance": "Performance Efficiency",
}
IMPACT_TO_SEVERITY = {"high": "high", "medium": "medium", "low": "low"}


def to_pillar(category):
    return CATEGORY_TO_PILLAR.get(str(category or "").strip().lower(), "Operational Excellence")


def to_severity(impact):
    return IMPACT_TO_SEVERITY.get(str(impact or "").strip().lower(), "medium")


def evaluate(run_id, rows):
    """Returns (findings, stats, savings). One rule per Advisor recommendation type."""
    findings, groups = [], defaultdict(set)
    meta, savings = {}, defaultdict(lambda: {"annual": 0.0, "bySubscription": defaultdict(float)})

    for row in rows:
        rule = f"ADV-{row.get('recommendationType') or 'unknown'}"
        resource = row.get("resourceId") or row.get("id", "")
        sub = (row.get("subscriptionId") or subscription_of(resource)).lower()
        groups[(rule, sub)].add(resource.lower())
        meta.setdefault(
            rule,
            {
                "pillar": to_pillar(row.get("category")), "severity": to_severity(row.get("impact")),
                "type": row.get("impactedType", ""), "problem": row.get("problem") or "Azure Advisor recommendation",
                "solution": row.get("solution") or "",
            },
        )
        if row.get("annualSavings") and row.get("currency"):
            savings[row["currency"]]["annual"] += float(row["annualSavings"])
            savings[row["currency"]]["bySubscription"][sub] += float(row["annualSavings"])
        if len(findings) < MAX_FINDINGS:
            info = meta[rule]
            findings.append(
                make_finding(
                    run_id, rule_id=rule, source="advisor", pillar=info["pillar"], severity=info["severity"],
                    title=info["problem"], recommendation=info["solution"] or info["problem"],
                    resource_id=resource, resource_name=row.get("impactedName", ""),
                    resource_type=info["type"], subscription_id=sub,
                )
            )

    stats = [
        {
            "ruleId": rule, "source": "advisor", "pillar": meta[rule]["pillar"], "severity": meta[rule]["severity"],
            "subscriptionId": sub, "affected": len(resources), "applicable": None,
            "applicableType": meta[rule]["type"],
        }
        for (rule, sub), resources in groups.items()
    ]
    clean_savings = {
        currency: {"annual": round(value["annual"], 2),
                   "bySubscription": {sub: round(amount, 2) for sub, amount in value["bySubscription"].items()}}
        for currency, value in savings.items()
    }
    return findings, stats, clean_savings


def collect(credential, run_id, subscriptions):
    rows = []
    for chunk in graph.chunks(subscriptions):
        rows.extend(graph.query(credential, chunk, ADVISOR_QUERY, max_rows=MAX_ROWS))
    return evaluate(run_id, rows)
