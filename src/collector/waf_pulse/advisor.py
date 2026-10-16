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


def _is_commitment(row):
    return bool(row.get("term") and row.get("commitmentType"))


def _commitments(rows):
    """Reservation and savings plan recommendations. Advisor repeats each one for every term (1 and 3 years) and
    lookback window (7, 30 and 60 days), and they are alternatives, so only the longest lookback per term is kept
    and the terms are never added together."""
    best = {}
    for row in rows:
        if not _is_commitment(row) or not row.get("annualSavings") or not row.get("currency"):
            continue
        sub = (row.get("subscriptionId") or "").lower()
        key = (sub, row["commitmentType"].lower(), row["currency"], row["term"])
        if key not in best or (row.get("lookbackDays") or 0) > (best[key].get("lookbackDays") or 0):
            best[key] = row
    items = {}
    for (sub, kind, currency, term), row in best.items():
        item = items.setdefault(
            (sub, kind, currency),
            {"subscriptionId": sub, "resourceType": row["commitmentType"], "currency": currency, "terms": {},
             "lookbackDays": row.get("lookbackDays"), "solution": row.get("solution") or "",
             "recommendationType": row.get("recommendationType") or "unknown", "impact": row.get("impact")},
        )
        item["terms"][term] = round(float(row["annualSavings"]), 2)
    return sorted(items.values(), key=lambda item: max(item["terms"].values()), reverse=True)


def _terms_text(item):
    names = {"P1Y": "1 year", "P3Y": "3 years"}
    return "; ".join(f"{names.get(term, term)}: {amount:,.0f} {item['currency']} per year"
                     for term, amount in sorted(item["terms"].items()))


def evaluate(run_id, rows):
    """Returns (findings, stats, dataset). One rule per Advisor recommendation type.
    dataset = {"savings": usage savings, "commitments": reservation and savings plan options}."""
    findings, groups = [], defaultdict(set)
    meta, savings = {}, defaultdict(lambda: {"annual": 0.0, "bySubscription": defaultdict(float)})

    def remember(rule, row):
        meta.setdefault(
            rule,
            {
                "pillar": to_pillar(row.get("category")), "severity": to_severity(row.get("impact")),
                "type": row.get("impactedType", ""), "problem": row.get("problem") or "Azure Advisor recommendation",
                "solution": row.get("solution") or "",
            },
        )

    for row in rows:
        if _is_commitment(row):
            continue
        rule = f"ADV-{row.get('recommendationType') or 'unknown'}"
        resource = row.get("resourceId") or row.get("id", "")
        sub = (row.get("subscriptionId") or subscription_of(resource)).lower()
        groups[(rule, sub)].add(resource.lower())
        remember(rule, row)
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

    commitments = _commitments(rows)
    for item in commitments:
        rule = f"ADV-{item['recommendationType']}"
        remember(rule, {"category": "Cost", "impact": item["impact"], "impactedType": "",
                        "problem": item["solution"] or "Commitment discount recommendation", "solution": item["solution"]})
        resource = f"/subscriptions/{item['subscriptionId']}/commitments/{item['resourceType'].lower()}"
        groups[(rule, item["subscriptionId"])].add(resource)
        findings.append(
            make_finding(
                run_id, rule_id=rule, source="advisor", pillar="Cost Optimization", severity=meta[rule]["severity"],
                title=meta[rule]["problem"], recommendation=f"{meta[rule]['solution']}. Estimated savings: {_terms_text(item)}.",
                resource_id=resource, resource_name=item["resourceType"], resource_type="",
                subscription_id=item["subscriptionId"],
            )
        )

    stats = [
        {
            "ruleId": rule, "source": "advisor", "pillar": meta[rule]["pillar"], "severity": meta[rule]["severity"],
            "subscriptionId": sub, "affected": len(resources), "applicable": None,
            "applicableTypes": [meta[rule]["type"]] if meta[rule]["type"] else [],
        }
        for (rule, sub), resources in groups.items()
    ]
    clean_savings = {
        currency: {"annual": round(value["annual"], 2),
                   "bySubscription": {sub: round(amount, 2) for sub, amount in value["bySubscription"].items()}}
        for currency, value in savings.items()
    }
    return findings, stats, {"savings": clean_savings, "commitments": commitments}

def collect(credential, run_id, subscriptions):
    rows = []
    for chunk in graph.chunks(subscriptions):
        rows.extend(graph.query(credential, chunk, ADVISOR_QUERY, max_rows=MAX_ROWS))
    return evaluate(run_id, rows)
