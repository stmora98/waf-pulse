"""Right-sizing view helpers: which resources are over or under sized, from the metrics dataset."""

import re
from collections import Counter

import insights

ASSESSMENTS = ("idle", "under", "right", "saturated")

# page kind -> (title, dataset kinds, label of each assessment, columns)
KINDS = {
    "vm": ("Virtual machines", ("vm",),
           {"idle": "Idle (under 5% CPU)", "under": "Underutilized (under 15%)", "right": "Right-sized",
            "saturated": "Saturated (80% or more)"}),
    "sql": ("SQL databases", ("sql_dtu", "sql_vcore"),
            {"idle": "Idle", "under": "Oversized (under 10%)", "right": "Right-sized", "saturated": "Saturated (80% or more)"}),
    "plan": ("App Service plans", ("plan",),
             {"idle": "Idle", "under": "Underutilized (under 20% CPU)", "right": "Right-sized",
              "saturated": "Saturated (80% CPU or 85% memory)"}),
    "storage": ("Storage accounts", ("storage",),
                {"idle": "No transactions", "under": "Underutilized", "right": "In use", "saturated": "Saturated"}),
}
HIDDEN_WHEN_EMPTY = {"storage": ("under", "saturated"), "sql": ("idle",), "plan": ("idle",)}


def counts(metrics, kind):
    """{assessment: count, nodata: count} for a page kind, summing the dataset kinds behind it."""
    distribution = metrics.get("distribution") or {}
    total = {name: 0 for name in (*ASSESSMENTS, "nodata")}
    for source in KINDS[kind][1]:
        for name, value in (distribution.get(source) or {}).items():
            if name in total:
                total[name] += value
    return total


def visible_assessments(kind, totals):
    hidden = HIDDEN_WHEN_EMPTY.get(kind, ())
    return [name for name in ASSESSMENTS if name not in hidden or totals.get(name)]


def resources(metrics, kind, assessment=None, subscription=None):
    """The resources of a page kind, optionally narrowed to one assessment and one subscription."""
    kinds = KINDS[kind][1]
    return [r for r in metrics.get("resources") or []
            if r.get("kind") in kinds and (not assessment or r.get("assessment") == assessment)
            and (not subscription or r.get("subscriptionId") == subscription)]


# ---------------------------------------------------------------------------------------------------------
# The table: utilization joined with what Advisor says and what each resource costs.

KIND_TYPES = {
    "vm": ("microsoft.compute/virtualmachines",),
    "sql": ("microsoft.sql/servers/databases", "microsoft.sql/managedinstances"),
    "plan": ("microsoft.web/serverfarms",),
    "storage": ("microsoft.storage/storageaccounts",),
}
FACETS = {"subscription": ("subscriptionId", "Subscription"), "group": ("resourceGroup", "Resource group"),
          "assessment": ("assessment", "Assessment")}
ADVICE_FILTER = {"with": "With an Advisor recommendation", "without": "Without one"}
# reference lines of the utilization chart, in percent, by metrics kind (the thresholds of the collector)
MARKS = {"vm": ((5, "Idle"), (15, "Underutilized"), (80, "Saturated")), "sql_dtu": ((10, "Oversized"), (80, "Saturated")),
         "sql_vcore": ((10, "Oversized"), (80, "Saturated")), "plan": ((20, "Underutilized"), (80, "Saturated"))}
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
ASSESSMENT_ORDER = {"idle": 0, "under": 1, "saturated": 2, "right": 3}
SORTS = {"assessment": "Assessment", "cost": "Cost", "savings": "Savings", "cpu": "Average"}
MENU = (("subscription", "Subscription", "facet"), ("group", "Resource group", "facet"), ("assessment", "Assessment", "facet"),
        ("advice", "Advisor recommendation", "radio"), ("name", "Name", "text"))


def parse_filters(args):
    filters = insights.parse_filters(args, FACETS, ("subscription", "assessment"), {"advice": ADVICE_FILTER})
    for field, valid in (("assessment", lambda v: v in ASSESSMENTS), ("subscription", lambda v: bool(GUID.fullmatch(v)))):
        if field in filters:
            filters[field]["values"] = [v for v in filters[field]["values"] if valid(v)]
            if not filters[field]["values"]:
                del filters[field]
    return filters


def build_rows(metrics, kind, advice, costs):
    """The rows of a page kind: every measured resource, plus the resources Advisor flagged that were not measured
    (a stopped virtual machine, for example), each with its Advisor advice and its cost of the last 30 days."""
    advice_by_id = {a["id"]: a for a in advice or []}
    cost_by_id = {c["id"]: c["cost"] for c in costs or []}
    kinds = KINDS[kind][1]
    rows, seen = [], set()
    for item in metrics.get("resources") or []:
        if item.get("kind") not in kinds:
            continue
        key = str(item["id"]).lower()
        seen.add(key)
        rows.append({**item, "cost": cost_by_id.get(key), "advice": advice_by_id.get(key), "source": "metrics"})
    for key, item in advice_by_id.items():
        if key in seen or item.get("type", "").lower() not in KIND_TYPES[kind]:
            continue
        rows.append({
            "kind": kind, "id": key, "name": item["name"], "subscriptionId": item["subscriptionId"],
            "resourceGroup": insights.resource_group_of(key), "detail": item.get("currentSku", ""), "avg": None, "max": None,
            "assessment": "idle" if item["action"].lower() == "shutdown" else "under", "cost": cost_by_id.get(key),
            "advice": item, "source": "advisor"})
    return rows


def apply_filters(rows, filters, skip=None):
    result = []
    for row in rows:
        keep = True
        for field, spec in filters.items():
            if field == skip:
                continue
            if field in FACETS:
                hit = str(row.get(FACETS[field][0], "")).lower() in {v.lower() for v in spec["values"]}
                keep = hit if spec["op"] == "eq" else not hit
            elif field == "advice":
                keep = bool(row.get("advice")) == (spec["values"][0] == "with")
            elif field == "name":
                keep = spec["values"][0].lower() in str(row.get("name", "")).lower()
            if not keep:
                break
        if keep:
            result.append(row)
    return result


def filter_choices(rows, filters, labels, names):
    """The values to offer for each facet and how many rows each would give, with the other filters applied."""
    choices = {}
    for field, (key, _) in FACETS.items():
        counter = Counter(str(r.get(key, "")) for r in apply_filters(rows, filters, skip=field) if r.get(key))
        for value in filters.get(field, {}).get("values", []):
            if not any(v.lower() == value.lower() for v in counter):
                counter[value] = 0
        entries = [[value, names.get(value.lower(), value) if field == "subscription" else labels.get(value, value) if field == "assessment" else value, count]
                   for value, count in counter.items()]
        entries.sort(key=lambda e: (-e[2], str(e[1]).lower()))
        choices[field] = entries[:300]
    return choices


def sort_rows(rows, order):
    if order == "cost":
        return sorted(rows, key=lambda r: -(r.get("cost") or 0))
    if order == "savings":
        return sorted(rows, key=lambda r: -((r.get("advice") or {}).get("monthlySavings") or 0))
    if order == "cpu":
        return sorted(rows, key=lambda r: (r.get("avg") is None, r.get("avg") or 0))
    return sorted(rows, key=lambda r: (ASSESSMENT_ORDER.get(r.get("assessment"), 9), r.get("avg") if r.get("avg") is not None else -1))


def totals(metrics, advice, costs):
    """The headline numbers of the page, over every resource type."""
    cost_by_id = {c["id"]: c["cost"] for c in costs or []}
    acting = [r for r in metrics.get("resources") or [] if r.get("assessment") in ("idle", "under")]
    saving = sum(a.get("monthlySavings") or 0 for a in advice or [])
    currencies = [a.get("currency") for a in advice or [] if a.get("currency")]
    return {
        "toAct": len(acting) + sum(1 for a in advice or [] if str(a["id"]).lower() not in {str(r["id"]).lower() for r in metrics.get("resources") or []}),
        "monthlySavings": round(saving, 2), "currency": currencies[0] if currencies else "USD", "advised": len(advice or []),
        "spentOnThem": round(sum(cost_by_id.get(str(r["id"]).lower(), 0) for r in acting), 2),
    }
