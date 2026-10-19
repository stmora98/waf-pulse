"""Assessment logic: built-in rules and inventory run tenant wide, and every source is aggregated into the run summary.

Every source (built-in rules, checklists, Advisor, Defender) produces findings plus statistics rows:

    {ruleId, source, pillar, severity, subscriptionId, affected, applicable}

`applicable` is the number of resources the check evaluated. Sources that cannot count them leave it empty and
list the resource types instead (`applicableTypes`), and the summary fills it in from the inventory. The summary
and the pillar scores are computed from those rows only.
"""
from collections import Counter, defaultdict

from . import graph, scoring
from .findings import finding_key, make_finding, retention_seconds, subscription_of  # noqa: F401  (re-exported)
from .rules import (
    ALL_RESOURCES, INVENTORY_QUERY, RESOURCE_GROUP_INVENTORY_QUERY, RESOURCE_GROUP_TYPE, RULES, SEVERITIES,
)

RULES_PER_ACTIVITY = 5
MAX_ROWS_PER_RULE = 5000
MAX_FINDINGS_PER_RULE = 1000
INVENTORY_MAX_ROWS = 200000

_RULES_BY_ID = {rule.id: rule for rule in RULES}


def build_finding(run_id, rule, row):
    return make_finding(
        run_id, rule_id=rule.id, source=rule.source, pillar=rule.pillar, severity=rule.severity,
        title=rule.title, recommendation=rule.recommendation, resource_id=row.get("id", ""),
        resource_name=row.get("name", ""), resource_type=row.get("type", ""),
        subscription_id=row.get("subscriptionId", ""),
    )


def rule_batches():
    """The built-in rules grouped so each activity runs a few of them."""
    return [RULES[i:i + RULES_PER_ACTIVITY] for i in range(0, len(RULES), RULES_PER_ACTIVITY)]


RESOURCE_LIST_QUERY = """
resources
| extend detail = case(
    type =~ 'microsoft.compute/virtualmachines',
      strcat(tostring(properties.hardwareProfile.vmSize), ' · ', tostring(properties.storageProfile.osDisk.osType), ' · ',
             replace_string(tostring(properties.extended.instanceView.powerState.displayStatus), 'VM ', '')),
    type =~ 'microsoft.compute/disks',
      strcat(tostring(sku.name), ' · ', tostring(properties.diskSizeGB), ' GB · ', tostring(properties.diskState)),
    type =~ 'microsoft.storage/storageaccounts', strcat(tostring(sku.name), ' · ', tostring(kind)),
    type =~ 'microsoft.web/sites', strcat(tostring(kind), ' · ', tostring(properties.state)),
    type =~ 'microsoft.web/serverfarms', strcat(tostring(sku.name), ' x', tostring(sku.capacity)),
    tostring(sku.name))
| project id, name, type = tolower(type), subscriptionId, resourceGroup, location, detail,
          tags = array_length(bag_keys(tags)), tagBag = tags
"""
MAX_RESOURCE_LIST = 5000
MAX_TAGS_PER_RESOURCE = 8


def clean_tags(bag):
    """[[key, value], ...] of the tags of a resource for the inventory, so the dashboard can scope by tag: at most
    MAX_TAGS_PER_RESOURCE of them, each shortened."""
    if not isinstance(bag, dict):
        return []
    return [[str(k)[:64], str(v)[:64]] for k, v in list(bag.items())[:MAX_TAGS_PER_RESOURCE]]


def collect_resource_list(credential, subscription_ids):
    """The resources themselves, so every count on the dashboard can lead to the list behind it.
    Returns (rows, truncated): a tenant with more than MAX_RESOURCE_LIST resources keeps the first ones."""
    rows = []
    for chunk in graph.chunks(subscription_ids):
        rows.extend(graph.query(credential, chunk, RESOURCE_LIST_QUERY, max_rows=MAX_RESOURCE_LIST + 1))
        if len(rows) > MAX_RESOURCE_LIST:
            break
    cleaned = [
        {"id": str(r.get("id", "")), "name": str(r.get("name", "")), "type": str(r.get("type", "")).lower(),
         "subscriptionId": str(r.get("subscriptionId", "")).lower(), "resourceGroup": str(r.get("resourceGroup", "")),
         "location": str(r.get("location", "")), "detail": str(r.get("detail") or "").strip(" ·"), "tags": int(r.get("tags") or 0),
         "tagList": clean_tags(r.get("tagBag"))}
        for r in rows[:MAX_RESOURCE_LIST]
    ]
    return cleaned, len(rows) > MAX_RESOURCE_LIST


def collect_inventory(credential, subscription_ids):
    """Resource counts per subscription and type, for the whole tenant."""
    inventory = defaultdict(dict)
    for chunk in graph.chunks(subscription_ids):
        for kql in (INVENTORY_QUERY, RESOURCE_GROUP_INVENTORY_QUERY):
            for row in graph.query(credential, chunk, kql, max_rows=INVENTORY_MAX_ROWS):
                sub, resource_type = str(row.get("subscriptionId", "")).lower(), str(row.get("type", "")).lower()
                counts = inventory[sub]
                counts[resource_type] = counts.get(resource_type, 0) + int(row.get("count_", 0))
    return {"stats": [], "errors": [], "inventory": dict(inventory)}


def collect_rules(credential, run_id, subscription_ids, rules):
    """Runs the given built-in rules over all subscriptions. Returns (findings, stats document)."""
    findings, stats, evaluated, errors = [], [], [], []
    for rule in rules:
        rows = []
        try:
            for chunk in graph.chunks(subscription_ids):
                rows.extend(graph.query(credential, chunk, rule.query, max_rows=MAX_ROWS_PER_RULE))
        except Exception as exc:  # one failing rule must not fail the others
            errors.append({"ruleId": rule.id, "error": str(exc).splitlines()[0][:200]})
            continue
        evaluated.append(rule.id)
        findings.extend(build_finding(run_id, rule, row) for row in rows[:MAX_FINDINGS_PER_RULE])
        per_subscription = Counter(
            (str(row.get("subscriptionId", "")) or subscription_of(row.get("id"))).lower() for row in rows
        )
        for sub, affected in per_subscription.items():
            stats.append(
                {
                    "ruleId": rule.id, "source": rule.source, "pillar": rule.pillar, "severity": rule.severity,
                    "subscriptionId": sub, "affected": affected, "applicable": None,
                    "applicableTypes": list(rule.applies_to),
                }
            )
    return findings, {"stats": stats, "evaluated": evaluated, "errors": errors}


def _merge_inventory(documents):
    merged = defaultdict(dict)
    for document in documents:
        for sub, counts in (document.get("inventory") or {}).items():
            bucket = merged[sub.lower()]
            for resource_type, count in counts.items():
                bucket[resource_type] = bucket.get(resource_type, 0) + count
    return merged


def _applicable(types, counts):
    if ALL_RESOURCES in types:
        return sum(count for resource_type, count in counts.items() if resource_type != RESOURCE_GROUP_TYPE)
    return sum(counts.get(resource_type, 0) for resource_type in types)


def _dataset(datasets, name):
    return [item["data"] for item in datasets if item.get("name") == name]


def _complete_statistics(documents, inventory):
    """Fills `applicable` from the inventory and adds the zero rows of rules that evaluated clean in a subscription."""
    stats, present = [], set()
    for document in documents:
        for stat in document.get("stats", []):
            stat = dict(stat)
            stat["subscriptionId"] = (stat.get("subscriptionId") or "unknown").lower()
            if stat.get("applicable") is None:
                types = stat.get("applicableTypes") or ([stat["applicableType"]] if stat.get("applicableType") else [])
                stat["applicable"] = max(_applicable(types, inventory.get(stat["subscriptionId"], {})), stat["affected"])
            present.add((stat["ruleId"], stat["subscriptionId"]))
            stats.append(stat)

    for document in documents:
        for rule_id in document.get("evaluated", []):
            rule = _RULES_BY_ID.get(rule_id)
            if rule is None:
                continue
            for sub, counts in inventory.items():
                if (rule_id, sub) in present:
                    continue
                applicable = _applicable(rule.applies_to, counts)
                if applicable > 0:
                    stats.append(
                        {"ruleId": rule.id, "source": rule.source, "pillar": rule.pillar, "severity": rule.severity,
                         "subscriptionId": sub, "affected": 0, "applicable": applicable}
                    )
    return stats


def rule_stats_rows(stats_documents):
    """The statistics of every rule in every subscription, kept apart from the summary so the dashboard can score any
    part of the tenant (a filter on tags, resource groups, regions...) the same way the collector scores the whole:
    [{r: rule, p: pillar, v: severity, s: source, u: subscription, a: affected, n: applicable, t: resource types it
    evaluates ("*" for all of them) or None}]."""
    inventory = _merge_inventory(stats_documents)
    rows = []
    for stat in _complete_statistics(stats_documents, inventory):
        rule = _RULES_BY_ID.get(stat["ruleId"])
        types = stat.get("applicableTypes") or ([stat["applicableType"]] if stat.get("applicableType") else None)
        if not types and rule is not None:
            types = list(rule.applies_to)
        rows.append({"r": stat["ruleId"], "p": stat["pillar"], "v": stat["severity"], "s": stat.get("source", ""),
                     "u": stat["subscriptionId"], "a": int(stat["affected"]), "n": int(stat["applicable"]),
                     "t": [str(t).lower() for t in types] if types else None})
    return rows


def build_summary(run_id, started_utc, completed_utc, trigger, subscriptions, stats_documents, datasets=()):
    """Aggregates every statistics document into the tenant summary and per subscription score documents."""
    names = {sub["id"].lower(): sub["name"] for sub in subscriptions}
    inventory = _merge_inventory(stats_documents)
    all_stats = _complete_statistics(stats_documents, inventory)
    errors = [error for document in stats_documents for error in document.get("errors", [])]

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
    for stat in tenant_stats:
        bucket = counts.setdefault(stat["pillar"], {})
        bucket[stat["severity"]] = bucket.get(stat["severity"], 0) + stat["affected"]
        severity_totals[stat["severity"]] += stat["affected"]

    sources = {}
    for stat in all_stats:
        info = sources.setdefault(stat["source"], {"rules": set(), "findings": 0})
        if stat["applicable"] > 0:
            info["rules"].add(stat["ruleId"])
        info["findings"] += stat["affected"]
    sources = {name: {"rules": len(info["rules"]), "findings": info["findings"]} for name, info in sources.items()}

    subscription_rows, score_docs = [], []
    for sub in sorted(set(names) | set(by_subscription) | set(inventory)):
        if sub in ("unknown", "tenant"):
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
    governance = _dataset(datasets, "governance")
    if governance:
        summary["governance"] = governance[0]
    measured = _dataset(datasets, "metrics")
    if measured:
        summary["metrics"] = measured[0]
    finance = _dataset(datasets, "finops")
    if finance:
        summary["finops"] = finance[0]
    for key in ("diagnostics", "keyvault", "entra", "lifecycle"):
        found = _dataset(datasets, key)
        if found:
            summary[key] = found[0]
    savings = _advisor_savings(datasets)
    if savings:
        summary["advisorSavings"] = savings
        summary["advisorSavingsBySubscription"] = _advisor_savings_by_subscription(datasets)
    commitments = _commitments(datasets, names)
    if commitments:
        summary["commitments"] = commitments
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

def _advisor_savings_by_subscription(datasets):
    """{subscription: {currency: annual amount}} of the usage savings, so a part of the tenant can show its own."""
    result = defaultdict(lambda: defaultdict(float))
    for data in _dataset(datasets, "advisor"):
        for currency, value in (data.get("savings") or {}).items():
            for sub, amount in (value.get("bySubscription") or {}).items():
                result[str(sub).lower()][currency] += amount
    return {sub: {currency: round(amount, 2) for currency, amount in values.items()} for sub, values in result.items()}


def _commitments(datasets, names):
    """Reservation and savings plan options. Terms are alternatives, so they are totalled per term, never together."""
    items, totals = [], defaultdict(lambda: defaultdict(float))
    for data in _dataset(datasets, "advisor"):
        for item in data.get("commitments") or []:
            items.append({**item, "subscriptionName": names.get(item["subscriptionId"], item["subscriptionId"])})
            for term, amount in item["terms"].items():
                totals[item["currency"]][term] += amount
    if not items:
        return {}
    items.sort(key=lambda item: max(item["terms"].values()), reverse=True)
    return {
        "items": items[:50],
        "totals": {currency: {term: round(amount, 2) for term, amount in terms.items()}
                   for currency, terms in totals.items()},
    }
