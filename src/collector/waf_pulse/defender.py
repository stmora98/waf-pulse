"""Microsoft Defender for Cloud (Secure Score, score controls, unhealthy recommendations) from Resource Graph.

Needs Reader only. When Defender for Cloud is not enabled the queries simply return nothing.
"""
from . import graph
from .findings import make_finding, subscription_of

MAX_ROWS = 20000
MAX_FINDINGS = 3000

SECURE_SCORE_QUERY = """
securityresources
| where type =~ 'microsoft.security/securescores'
| project subscriptionId,
          current = todouble(properties.score.current),
          max = todouble(properties.score.max),
          percentage = todouble(properties.score.percentage)
"""

CONTROLS_QUERY = """
securityresources
| where type =~ 'microsoft.security/securescores/securescorecontrols'
| project subscriptionId,
          control = tostring(properties.displayName),
          unhealthy = toint(properties.unhealthyResourceCount),
          healthy = toint(properties.healthyResourceCount),
          current = todouble(properties.score.current),
          max = todouble(properties.score.max)
| where unhealthy > 0
"""

ASSESSMENT_SUMMARY_QUERY = """
securityresources
| where type =~ 'microsoft.security/assessments'
| extend code = tostring(properties.status.code),
         displayName = coalesce(tostring(properties.displayName), tostring(properties.metadata.displayName)),
         severity = tostring(properties.metadata.severity)
| summarize unhealthy = countif(code =~ 'Unhealthy'), healthy = countif(code =~ 'Healthy')
    by assessment = name, displayName, severity, subscriptionId
| where unhealthy > 0
"""

UNHEALTHY_RESOURCES_QUERY = """
securityresources
| where type =~ 'microsoft.security/assessments'
| where tostring(properties.status.code) =~ 'Unhealthy'
| project assessment = name, subscriptionId, resourceId = tostring(properties.resourceDetails.Id)
"""

SEVERITY_MAP = {"high": "high", "medium": "medium", "low": "low"}


def percentage(row):
    """Secure Score is reported as a 0-1 ratio. Falls back to current / max."""
    value = row.get("percentage")
    if value is None and row.get("max"):
        value = (row.get("current") or 0) / row["max"]
    if value is None:
        return None
    return round(value * 100, 1) if value <= 1 else round(value, 1)


def evaluate(run_id, scores, controls, summary, unhealthy):
    """Returns (findings, stats, dataset). Rows are the raw Resource Graph results."""
    secure_scores = [
        {"subscriptionId": row["subscriptionId"].lower(), "current": row.get("current"), "max": row.get("max"),
         "percentage": percentage(row)}
        for row in scores
    ]

    control_totals = {}
    for row in controls:
        item = control_totals.setdefault(row["control"], {"control": row["control"], "unhealthy": 0, "healthy": 0})
        item["unhealthy"] += int(row.get("unhealthy") or 0)
        item["healthy"] += int(row.get("healthy") or 0)
    top_controls = sorted(control_totals.values(), key=lambda item: item["unhealthy"], reverse=True)[:15]

    meta, stats = {}, []
    for row in summary:
        severity = SEVERITY_MAP.get(str(row.get("severity", "")).lower(), "medium")
        rule = f"MDC-{row['assessment']}"
        meta[row["assessment"]] = {"rule": rule, "severity": severity, "title": row.get("displayName") or rule}
        stats.append(
            {
                "ruleId": rule, "source": "defender", "pillar": "Security", "severity": severity,
                "subscriptionId": row["subscriptionId"].lower(), "affected": int(row["unhealthy"]),
                "applicable": int(row["unhealthy"]) + int(row.get("healthy") or 0),
            }
        )

    findings = []
    for row in unhealthy:
        info = meta.get(row.get("assessment"))
        if not info or not row.get("resourceId") or len(findings) >= MAX_FINDINGS:
            continue
        findings.append(
            make_finding(
                run_id, rule_id=info["rule"], source="defender", pillar="Security", severity=info["severity"],
                title=info["title"], recommendation=info["title"], resource_id=row["resourceId"],
                subscription_id=row.get("subscriptionId") or subscription_of(row["resourceId"]),
            )
        )

    dataset = {"secureScores": secure_scores, "topControls": top_controls}
    return findings, stats, dataset


def collect(credential, run_id, subscriptions):
    results = {}
    errors = []
    for name, kql in (("scores", SECURE_SCORE_QUERY), ("controls", CONTROLS_QUERY),
                      ("summary", ASSESSMENT_SUMMARY_QUERY), ("unhealthy", UNHEALTHY_RESOURCES_QUERY)):
        rows = []
        try:
            for chunk in graph.chunks(subscriptions):
                rows.extend(graph.query(credential, chunk, kql, max_rows=MAX_ROWS))
        except Exception as exc:  # Defender data is optional, a failure must not fail the run
            errors.append({"ruleId": f"defender-{name}", "error": str(exc)[:300]})
        results[name] = rows
    findings, stats, dataset = evaluate(run_id, results["scores"], results["controls"], results["summary"],
                                        results["unhealthy"])
    return findings, stats, dataset, errors
