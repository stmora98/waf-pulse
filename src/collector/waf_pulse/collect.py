"""Assessment logic: turn Resource Graph results into findings, summaries and scores."""
import hashlib

from . import graph, scoring
from .rules import INVENTORY_QUERY, RESOURCE_GROUP_INVENTORY_QUERY, RULES, SEVERITIES

MAX_FINDINGS_PER_RULE = 1000


def build_finding(run_id, rule, row):
    resource_id = str(row.get("id", ""))
    digest = hashlib.sha1(f"{run_id}|{rule.id}|{resource_id.lower()}".encode("utf-8")).hexdigest()
    return {
        "id": digest,
        "runId": run_id,
        "subscriptionId": row.get("subscriptionId", ""),
        "ruleId": rule.id,
        "pillar": rule.pillar,
        "severity": rule.severity,
        "title": rule.title,
        "recommendation": rule.recommendation,
        "resourceId": resource_id,
        "resourceName": row.get("name", ""),
        "resourceType": row.get("type", ""),
    }


def _inventory(credential, subscription_id):
    """Returns ({type: count} including resource groups, total resources excluding resource groups)."""
    resources = graph.query(credential, subscription_id, INVENTORY_QUERY)
    groups = graph.query(credential, subscription_id, RESOURCE_GROUP_INVENTORY_QUERY)
    counts = {}
    for row in resources + groups:
        resource_type = str(row.get("type", "")).lower()
        counts[resource_type] = counts.get(resource_type, 0) + int(row.get("count_", 0))
    total = sum(int(row.get("count_", 0)) for row in resources)
    return counts, total


def collect_subscription(credential, run_id, subscription):
    """Runs the inventory and every rule for one subscription. Returns findings and a small result record."""
    sub_id = subscription["id"]
    inventory, resource_count = _inventory(credential, sub_id)
    top_types = [
        {"type": rtype, "count": count}
        for rtype, count in sorted(inventory.items(), key=lambda item: item[1], reverse=True)[:10]
    ]

    findings, counts, rule_stats, errors = [], {}, [], []
    for rule in RULES:
        try:
            rows = graph.query(credential, sub_id, rule.query, max_rows=MAX_FINDINGS_PER_RULE)
        except Exception as exc:  # one failing rule must not fail the whole subscription
            errors.append({"ruleId": rule.id, "error": str(exc)[:300]})
            continue
        for row in rows:
            findings.append(build_finding(run_id, rule, row))
        bucket = counts.setdefault(rule.pillar, {})
        bucket[rule.severity] = bucket.get(rule.severity, 0) + len(rows)
        rule_stats.append(
            {
                "ruleId": rule.id,
                "pillar": rule.pillar,
                "severity": rule.severity,
                "affected": len(rows),
                "applicable": sum(inventory.get(rtype, 0) for rtype in rule.applies_to),
            }
        )

    result = {
        "subscriptionId": sub_id,
        "name": subscription.get("name", ""),
        "resourceCount": resource_count,
        "findingCount": len(findings),
        "topTypes": top_types,
        "counts": counts,
        "ruleStats": rule_stats,
        "errors": errors,
    }
    return findings, result


def build_summary(run_id, started_utc, completed_utc, trigger, results):
    """Aggregates per-subscription results into the tenant summary and per-subscription score documents."""
    tenant_counts, type_totals, errors = {}, {}, []
    resource_total = finding_total = 0
    subscriptions, score_docs = [], []

    for result in results:
        scoring.merge_counts(tenant_counts, result["counts"])
        resource_total += result["resourceCount"]
        finding_total += result["findingCount"]
        errors.extend({"subscriptionId": result["subscriptionId"], **error} for error in result["errors"])
        for item in result["topTypes"]:
            type_totals[item["type"]] = type_totals.get(item["type"], 0) + item["count"]

        sub_scores = scoring.score_pillars(result["ruleStats"])
        subscriptions.append(
            {
                "id": result["subscriptionId"],
                "name": result["name"],
                "resourceCount": result["resourceCount"],
                "findingCount": result["findingCount"],
                "scores": sub_scores,
            }
        )
        score_docs.append(
            {
                "id": f"{run_id}:{result['subscriptionId']}",
                "subscriptionId": result["subscriptionId"],
                "runId": run_id,
                "completedUtc": completed_utc,
                "scores": sub_scores,
            }
        )

    severity_totals = {s: 0 for s in SEVERITIES}
    for by_severity in tenant_counts.values():
        for severity, count in by_severity.items():
            severity_totals[severity] += count

    tenant_stats = scoring.merge_rule_stats(result["ruleStats"] for result in results)
    top_types = sorted(type_totals.items(), key=lambda item: item[1], reverse=True)[:10]
    summary = {
        "id": run_id,
        "runId": run_id,
        "startedUtc": started_utc,
        "completedUtc": completed_utc,
        "trigger": trigger,
        "subscriptionCount": len(results),
        "resourceCount": resource_total,
        "findingCount": finding_total,
        "scores": scoring.score_pillars(tenant_stats),
        "counts": tenant_counts,
        "severityTotals": severity_totals,
        "subscriptions": sorted(subscriptions, key=lambda item: item["findingCount"], reverse=True),
        "topTypes": [{"type": name, "count": count} for name, count in top_types],
        "errors": errors,
    }
    return summary, score_docs
