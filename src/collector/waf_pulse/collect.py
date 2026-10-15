"""Assessment logic: built-in rules per subscription, and the aggregation of every source into the run summary.

Every source (built-in rules, checklists, Advisor, Defender) produces findings plus statistics rows:

    {ruleId, source, pillar, severity, subscriptionId, affected, applicable}

The summary and the pillar scores are computed from those rows only.
"""
from collections import defaultdict

from . import graph, scoring
from .findings import finding_key, make_finding, retention_seconds  # noqa: F401  (re-exported)
from .rules import (
    ALL_RESOURCES, INVENTORY_QUERY, RESOURCE_GROUP_INVENTORY_QUERY, RESOURCE_GROUP_TYPE, RULES, SEVERITIES,
)

MAX_FINDINGS_PER_RULE = 1000


def build_finding(run_id, rule, row):
    return make_finding(
        run_id, rule_id=rule.id, source=rule.source, pillar=rule.pillar, severity=rule.severity,
        title=rule.title, recommendation=rule.recommendation, resource_id=row.get("id", ""),
        resource_name=row.get("name", ""), resource_type=row.get("type", ""),
        subscription_id=row.get("subscriptionId", ""),
    )


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


def _applicable(rule, inventory, total):
    if ALL_RESOURCES in rule.applies_to:
        return total
    return sum(inventory.get(resource_type, 0) for resource_type in rule.applies_to)


def collect_subscription(credential, run_id, subscription):
    """Runs the inventory and every built-in rule for one subscription. Returns (findings, stats document)."""
    sub_id = subscription["id"].lower()
    inventory, total = _inventory(credential, sub_id)

    findings, stats, errors = [], [], []
    for rule in RULES:
        try:
            rows = graph.query(credential, sub_id, rule.query, max_rows=MAX_FINDINGS_PER_RULE)
        except Exception as exc:  # one failing rule must not fail the whole subscription
            errors.append({"ruleId": rule.id, "error": str(exc)[:300]})
            continue
        findings.extend(build_finding(run_id, rule, row) for row in rows)
        stats.append(
            {
                "ruleId": rule.id, "source": rule.source, "pillar": rule.pillar, "severity": rule.severity,
                "subscriptionId": sub_id, "affected": len(rows), "applicable": _applicable(rule, inventory, total),
            }
        )
    return findings, {"stats": stats, "inventory": {sub_id: inventory}, "errors": errors}


def _merge_inventory(documents):
    merged = defaultdict(dict)
    for document in documents:
        for sub, counts in (document.get("inventory") or {}).items():
            bucket = merged[sub]
            for resource_type, count in counts.items():
                bucket[resource_type] = bucket.get(resource_type, 0) + count
    return merged


def _dataset(datasets, name):
    return [item["data"] for item in datasets if item.get("name") == name]


def build_summary(run_id, started_utc, completed_utc, trigger, subscriptions, stats_documents, datasets=()):
    """Aggregates every statistics document into the tenant summary and per subscription score documents."""
    names = {sub["id"].lower(): sub["name"] for sub in subscriptions}
    inventory = _merge_inventory(stats_documents)

    all_stats, errors = [], []
    for document in stats_documents:
        all_stats.extend(dict(stat) for stat in document.get("stats", []))
        errors.extend(document.get("errors", []))

    # Sources that cannot count the evaluated resources (Advisor) leave `applicable` empty: use the inventory.
    for stat in all_stats:
        stat["subscriptionId"] = (stat.get("subscriptionId") or "unknown").lower()
        if stat.get("applicable") is None:
            counted = inventory.get(stat["subscriptionId"], {}).get(stat.get("applicableType", ""), 0)
            stat["applicable"] = max(counted, stat["affected"])

    by_subscription = defaultdict(list)
    for stat in all_stats:
        by_subscription[stat["subscriptionId"]].append(stat)

    type_totals = defaultdict(int)
    resources_by_sub = {}
    for sub, counts in inventory.items():
        resources_by_sub[sub] = sum(count for rtype, count in counts.items() if rtype != RESOURCE_GROUP_TYPE)
        for rtype, count in counts.items():
            type_totals[rtype] += count

    tenant_stats = scoring.merge_rule_stats([all_stats])
    counts = {}
    severity_totals = {severity: 0 for severity in SEVERITIES}
    sources = {}
    for stat in tenant_stats:
        bucket = counts.setdefault(stat["pillar"], {})
        bucket[stat["severity"]] = bucket.get(stat["severity"], 0) + stat["affected"]
        severity_totals[stat["severity"]] += stat["affected"]
    for stat in all_stats:
        info = sources.setdefault(stat["source"], {"rules": set(), "findings": 0})
        if stat["applicable"] > 0:
            info["rules"].add(stat["ruleId"])
        info["findings"] += stat["affected"]
    sources = {name: {"rules": len(info["rules"]), "findings": info["findings"]} for name, info in sources.items()}

    subscription_rows, score_docs = [], []
    for sub in sorted(set(names) | set(by_subscription) | set(inventory)):
        if sub == "unknown":
            continue
        scores = scoring.score_pillars(by_subscription.get(sub, []))
        subscription_rows.append(
            {
                "id": sub, "name": names.get(sub, sub), "resourceCount": resources_by_sub.get(sub, 0),
                "findingCount": sum(stat["affected"] for stat in by_subscription.get(sub, [])), "scores": scores,
            }
        )
        score_docs.append(
            {"id": f"{run_id}:{sub}", "subscriptionId": sub, "runId": run_id, "completedUtc": completed_utc,
             "scores": scores}
        )

    summary = {
        "id": run_id,
        "runId": run_id,
        "startedUtc": started_utc,
        "completedUtc": completed_utc,
        "trigger": trigger,
        "subscriptionCount": len(subscriptions),
        "resourceCount": sum(resources_by_sub.values()),
        "findingCount": sum(stat["affected"] for stat in all_stats),
        "scores": scoring.score_pillars(tenant_stats),
        "counts": counts,
        "severityTotals": severity_totals,
        "sources": sources,
        "subscriptions": sorted(subscription_rows, key=lambda item: item["findingCount"], reverse=True),
        "topTypes": [
            {"type": name, "count": count}
            for name, count in sorted(type_totals.items(), key=lambda item: item[1], reverse=True)
            if name != RESOURCE_GROUP_TYPE
        ][:10],
        "errors": errors,
    }
    summary.update(_defender_insights(datasets, names))
    savings = _advisor_savings(datasets)
    if savings:
        summary["advisorSavings"] = savings
    return summary, score_docs


def _defender_insights(datasets, names):
    secure_scores, controls = [], {}
    for data in _dataset(datasets, "defender"):
        secure_scores.extend(data.get("secureScores", []))
        for item in data.get("topControls", []):
            total = controls.setdefault(item["control"], {"control": item["control"], "unhealthy": 0, "healthy": 0})
            total["unhealthy"] += item["unhealthy"]
            total["healthy"] += item["healthy"]
    if not secure_scores and not controls:
        return {}
    measured = [item["percentage"] for item in secure_scores if item.get("percentage") is not None]
    return {
        "secureScore": {
            "average": round(sum(measured) / len(measured), 1) if measured else None,
            "subscriptions": sorted(
                ({**item, "name": names.get(item["subscriptionId"], item["subscriptionId"])} for item in secure_scores),
                key=lambda item: item["percentage"] if item.get("percentage") is not None else 101,
            ),
            "topControls": sorted(controls.values(), key=lambda item: item["unhealthy"], reverse=True)[:15],
        }
    }


def _advisor_savings(datasets):
    totals = defaultdict(float)
    for data in _dataset(datasets, "advisor"):
        for currency, value in (data.get("savings") or {}).items():
            totals[currency] += value.get("annual", 0)
    return {currency: round(amount, 2) for currency, amount in totals.items()}
