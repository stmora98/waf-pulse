"""Right-sizing view helpers: which resources are over or under sized, from the metrics dataset."""

import re
from collections import Counter

import insights

ASSESSMENTS = ("idle", "under", "right", "saturated")

def _n(value):
    return f"{value:g}"


def _labels(kind, limits):
    vm, sql, plan = limits["vm"], limits["sql"], limits["plan"]
    aks, cosmos, redis = limits["aks"], limits["cosmos"], limits["redis"]
    return {
        "aks": {"idle": "Idle", "under": f"Underutilized (under {_n(aks['under'])}% node CPU)", "right": "Right-sized",
                "saturated": f"Saturated ({_n(aks['saturated'])}% CPU or 85% memory)"},
        "cosmos": {"idle": "Idle", "under": f"Mostly unused (under {_n(cosmos['under'])}% of the RU/s)", "right": "Right-sized",
                   "saturated": f"Close to the limit ({_n(cosmos['saturated'])}% or more)"},
        "redis": {"idle": "Idle", "under": f"Underutilized (under {_n(redis['under'])}% CPU)", "right": "Right-sized",
                  "saturated": f"Saturated ({_n(redis['saturated'])}% CPU or 90% memory)"},
        "vm": {"idle": f"Idle (under {_n(vm['idle'])}% CPU)", "under": f"Underutilized (under {_n(vm['under'])}%)", "right": "Right-sized",
               "saturated": f"Saturated ({_n(vm['saturated'])}% or more)"},
        "sql": {"idle": "Idle", "under": f"Oversized (under {_n(sql['under'])}%)", "right": "Right-sized",
                "saturated": f"Saturated ({_n(sql['saturated'])}% or more)"},
        "plan": {"idle": "Idle", "under": f"Underutilized (under {_n(plan['under'])}% CPU)", "right": "Right-sized",
                 "saturated": f"Saturated ({_n(plan['saturated'])}% CPU or {_n(PLAN_MEMORY_SATURATED)}% memory)"},
        "storage": {"idle": "No transactions", "under": "Underutilized", "right": "In use", "saturated": "Saturated"},
    }[kind]


def kind_labels(kind, limits=None):
    """The text of each assessment of a page kind, with the thresholds in force."""
    return _labels(kind, limits or DEFAULT_THRESHOLDS)


# The thresholds the collector uses (percent of average utilization); keep in step with waf_pulse.metrics.
DEFAULT_THRESHOLDS = {"vm": {"idle": 5, "under": 15, "saturated": 80}, "sql": {"under": 10, "saturated": 80},
                      "plan": {"under": 20, "saturated": 80}, "aks": {"under": 20, "saturated": 80},
                      "cosmos": {"under": 10, "saturated": 80}, "redis": {"under": 10, "saturated": 80}}
# kind -> (threshold group, second metric saturates from, second metric blocks "under" from), as in waf_pulse.metrics.GENERIC
GENERIC = {"sql_mi": ("sql", None, None), "aks": ("aks", 85, 60), "cosmos": ("cosmos", None, None), "redis": ("redis", 90, 50)}
VM_MEMORY_BOUND, VM_MEMORY_SATURATED, PLAN_MEMORY_SATURATED = 70, 90, 85
THRESHOLD_FIELDS = (("vm", "idle", "Virtual machines: idle below"), ("vm", "under", "underutilized below"), ("vm", "saturated", "saturated from"),
                    ("sql", "under", "SQL databases: oversized below"), ("sql", "saturated", "saturated from"),
                    ("plan", "under", "App Service plans: underutilized below"), ("plan", "saturated", "saturated from"),
                    ("aks", "under", "AKS clusters: underutilized below"), ("aks", "saturated", "saturated from"),
                    ("cosmos", "under", "Cosmos DB: mostly unused below"), ("cosmos", "saturated", "close to the limit from"),
                    ("redis", "under", "Redis caches: underutilized below"), ("redis", "saturated", "saturated from"))

# page kind -> (title, dataset kinds, label of each assessment)
KINDS = {
    "vm": ("Virtual machines", ("vm",), kind_labels("vm")),
    "sql": ("SQL databases", ("sql_dtu", "sql_vcore", "sql_mi"), kind_labels("sql")),
    "plan": ("App Service plans", ("plan",), kind_labels("plan")),
    "aks": ("AKS clusters", ("aks",), kind_labels("aks")),
    "cosmos": ("Cosmos DB accounts", ("cosmos",), kind_labels("cosmos")),
    "redis": ("Redis caches", ("redis",), kind_labels("redis")),
    "storage": ("Storage accounts", ("storage",), kind_labels("storage")),
}


def validate_thresholds(value):
    """(thresholds, errors) from what the visitor sent: every group complete, numbers above 0 and up to 100, each level
    above the one before it."""
    errors, result = [], {}
    if not isinstance(value, dict):
        return None, ["Send the thresholds as an object."]
    for group, defaults in DEFAULT_THRESHOLDS.items():
        values = value.get(group)
        if values is None:
            result[group] = dict(defaults)  # saved before this group existed
            continue
        if not isinstance(values, dict):
            errors.append(f"The {group} thresholds must be an object.")
            continue
        numbers = {}
        for name in defaults:
            number = values.get(name)
            if isinstance(number, bool) or not isinstance(number, (int, float)) or not 0 < number <= 100:
                errors.append(f"{group} {name} must be a number above 0 and up to 100.")
            else:
                numbers[name] = number
        if len(numbers) == len(defaults):
            ordered = list(numbers.values())
            if ordered != sorted(set(ordered)):
                errors.append(f"The {group} thresholds must go up from the lowest level to the highest.")
            else:
                result[group] = numbers
    return (result, []) if not errors else (None, errors)


def resolve_thresholds(saved):
    """The defaults with the saved values on top (when they are valid as a whole)."""
    if saved:
        checked, errors = validate_thresholds(saved)
        if not errors:
            return checked
    return {group: dict(values) for group, values in DEFAULT_THRESHOLDS.items()}


def assess(record, limits):
    """The assessment of a measured record with the thresholds, the same rules as the collector."""
    kind, average = record.get("kind"), record.get("avg")
    if kind == "storage" or average is None:
        return record.get("assessment")
    if kind == "vm":
        vm = limits["vm"]
        memory = record.get("memory")
        if average >= vm["saturated"] or (memory is not None and memory >= VM_MEMORY_SATURATED):
            return "saturated"
        if memory is not None and memory >= VM_MEMORY_BOUND:
            return "right"
        return "idle" if average < vm["idle"] else "under" if average < vm["under"] else "right"
    if kind in GENERIC:
        group, saturates, blocks = GENERIC[kind]
        other = record.get("memory")
        if average >= limits[group]["saturated"] or (other is not None and saturates is not None and other >= saturates):
            return "saturated"
        if other is not None and blocks is not None and other >= blocks:
            return "right"
        return "under" if average < limits[group]["under"] else "right"
    if kind in ("sql_dtu", "sql_vcore"):
        sql = limits["sql"]
        return "under" if average < sql["under"] else "saturated" if average >= sql["saturated"] else "right"
    if kind == "plan":
        plan = limits["plan"]
        if average >= plan["saturated"] or (record.get("memory") is not None and record["memory"] >= PLAN_MEMORY_SATURATED):
            return "saturated"
        return "under" if average < plan["under"] else "right"
    return record.get("assessment")


def reassess(metrics, saved):
    """A copy of the metrics dataset with every resource and the distribution judged by the saved thresholds. The
    dataset is returned as is when they are the defaults."""
    limits = resolve_thresholds(saved)
    if limits == DEFAULT_THRESHOLDS or not metrics:
        return metrics, limits
    records = []
    for item in metrics.get("resources") or []:
        assessment = assess(item, limits)
        changed = {**item, "assessment": assessment}
        if item.get("kind") == "vm":
            if assessment == "right" and item.get("memory", 0) >= VM_MEMORY_BOUND and item["avg"] < limits["vm"]["under"]:
                changed["note"] = "memory-bound"
            else:
                changed.pop("note", None)
        records.append(changed)
    distribution = {}
    for source, old in (metrics.get("distribution") or {}).items():
        mine = [r for r in records if r.get("kind") == source]
        if source == "storage" or len(mine) != sum(old.get(name, 0) for name in ASSESSMENTS):
            distribution[source] = old
            continue
        counted = Counter(r["assessment"] for r in mine)
        distribution[source] = {**{name: counted.get(name, 0) for name in ASSESSMENTS}, "nodata": old.get("nodata", 0)}
    return {**metrics, "resources": records, "distribution": distribution}, limits
HIDDEN_WHEN_EMPTY = {"storage": ("under", "saturated"), "sql": ("idle",), "plan": ("idle",), "aks": ("idle",), "cosmos": ("idle",), "redis": ("idle",)}


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
    "aks": ("microsoft.containerservice/managedclusters",),
    "cosmos": ("microsoft.documentdb/databaseaccounts",),
    "redis": ("microsoft.cache/redis",),
}
AVG_LABEL = {"vm": "CPU", "sql": "DTU", "plan": "CPU", "aks": "node CPU", "cosmos": "RU", "redis": "CPU"}
WITH_MEMORY = ("plan", "aks", "redis")
FACETS = {"subscription": ("subscriptionId", "Subscription"), "group": ("resourceGroup", "Resource group"),
          "assessment": ("assessment", "Assessment")}
ADVICE_FILTER = {"with": "With an Advisor recommendation", "without": "Without one"}
SCHEDULE_FILTER = {"with": "Used in office hours only", "without": "Not a candidate"}
RADIOS = {"advice": ADVICE_FILTER, "schedule": SCHEDULE_FILTER}
RADIO_LABELS = {"advice": "Advisor", "schedule": "Auto-shutdown"}
def marks(kind, limits=None):
    """Reference lines of the utilization chart, in percent: the thresholds in force for a metrics kind."""
    limits = limits or DEFAULT_THRESHOLDS
    vm, sql, plan = limits["vm"], limits["sql"], limits["plan"]
    return {"vm": ((vm["idle"], "Idle"), (vm["under"], "Underutilized"), (vm["saturated"], "Saturated")),
            "sql_dtu": ((sql["under"], "Oversized"), (sql["saturated"], "Saturated")),
            "sql_vcore": ((sql["under"], "Oversized"), (sql["saturated"], "Saturated")),
            "plan": ((plan["under"], "Underutilized"), (plan["saturated"], "Saturated")),
            "sql_mi": ((sql["under"], "Oversized"), (sql["saturated"], "Saturated")),
            "aks": ((limits["aks"]["under"], "Underutilized"), (limits["aks"]["saturated"], "Saturated")),
            "cosmos": ((limits["cosmos"]["under"], "Mostly unused"), (limits["cosmos"]["saturated"], "Close to the limit")),
            "redis": ((limits["redis"]["under"], "Underutilized"), (limits["redis"]["saturated"], "Saturated"))}.get(kind, ())


GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
ASSESSMENT_ORDER = {"idle": 0, "under": 1, "saturated": 2, "right": 3}
SORTS = {"assessment": "Assessment", "cost": "Cost", "savings": "Savings", "cpu": "Average"}
MENU = (("subscription", "Subscription", "facet"), ("group", "Resource group", "facet"), ("assessment", "Assessment", "facet"),
        ("advice", "Advisor recommendation", "radio"), ("schedule", "Auto-shutdown candidate", "radio"), ("name", "Name", "text"))


def parse_filters(args):
    filters = insights.parse_filters(args, FACETS, ("subscription", "assessment"), RADIOS)
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
        cost = cost_by_id.get(key)
        row = {**item, "cost": cost, "advice": advice_by_id.get(key), "source": "metrics"}
        if item.get("scheduleCandidate") and cost is not None:
            row["scheduleSaving"] = round(cost * item["schedule"]["saving"], 2)
        rows.append(row)
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
            elif field == "schedule":
                keep = bool(row.get("scheduleCandidate")) == (spec["values"][0] == "with")
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
        "scheduleSavings": round(sum(cost_by_id.get(str(r["id"]).lower(), 0) * r["schedule"]["saving"]
                                     for r in metrics.get("resources") or [] if r.get("scheduleCandidate")), 2),
        "scheduleMachines": sum(1 for r in metrics.get("resources") or [] if r.get("scheduleCandidate")),
    }


def schedule_text(schedule):
    """One line about when a machine is used, from the collector's {hours, window, start, weekend, saving}."""
    end = (schedule["start"] + schedule["window"]) % 24
    return (f"busy about {schedule['window']} h a day ({schedule['start']:02d}:00-{end:02d}:00 UTC), "
            f"{'weekdays only' if schedule['weekend'] else 'every day'}")


PRODUCTION = re.compile(r"^(prod|production|prd|live)", re.I)


def risk(row):
    """What to weigh before changing a machine: {level, reasons}. Only virtual machines carry the context."""
    reasons = []
    env = str(row.get("env") or "")
    if env and PRODUCTION.match(env):
        reasons.append("tagged as production")
    if row.get("ha") == "none":
        reasons.append("single instance: resizing restarts it and the service is down meanwhile")
    elif row.get("ha") in ("set", "zone"):
        reasons.append("in an availability " + ("set" if row["ha"] == "set" else "zone") + ": resize one machine at a time")
    if row.get("note") == "memory-bound":
        reasons.append("memory is busy: pick a size with the same memory")
    level = "high" if env and PRODUCTION.match(env) else "normal"
    return {"level": level, "reasons": reasons}


def track(history):
    """What changed in Advisor's right-sizing savings. history: [(label, advice rows)] oldest first, only runs that have
    advice. Returns None with fewer than two runs, else {points, saved, resolved, new, currency}: `resolved` are the
    resources that had a recommendation in the previous run and no longer do, with what they were worth per month."""
    history = [(label, rows) for label, rows in history if rows is not None]
    if len(history) < 2:
        return None
    points = [(label, round(sum(a.get("monthlySavings") or 0 for a in rows), 2)) for label, rows in history]
    before = {str(a["id"]).lower(): a for a in history[-2][1]}
    now = {str(a["id"]).lower(): a for a in history[-1][1]}
    resolved = sorted((a for key, a in before.items() if key not in now), key=lambda a: -(a.get("monthlySavings") or 0))
    new = sorted((a for key, a in now.items() if key not in before), key=lambda a: -(a.get("monthlySavings") or 0))
    currencies = [a.get("currency") for _, rows in history for a in rows if a.get("currency")]
    return {"points": points, "resolved": resolved[:15], "new": new[:15], "currency": currencies[0] if currencies else "USD",
            "saved": round(sum(a.get("monthlySavings") or 0 for a in resolved), 2),
            "added": round(sum(a.get("monthlySavings") or 0 for a in new), 2), "runs": len(history)}

