"""Chargeback and showback: what each subscription, resource group and tag value cost, from the amortized cost the collector keeps.
Subscriptions and resource groups come with the cost per month; the resources inside a resource group are the most expensive
ones of the last 30 days. Tags give the share of the cost nobody can be charged for (no tag)."""
from collections import defaultdict

ALL = "all"
UNTAGGED = "(untagged)"
RESOURCES_PER_GROUP = 8


def months_of(rows):
    return sorted({month for row in rows for month in row.get("months", {})})


def pick_period(months, requested, current):
    """A month that exists, "all" for the sum of every month, or the last complete month (the latest one when none is complete)."""
    if requested == ALL or requested in months:
        return requested
    complete = [m for m in months if m < current]
    return (complete or months or [ALL])[-1]


def _cost(row, period):
    months = row.get("months", {})
    return sum(months.values()) if period == ALL else months.get(period, 0.0)


def group_ok(resolved, sub, rg):
    """Resource group totals follow the subscription, management group and resource group filters; filters on a type, region or tag
    need a resource and are reported by `limited`."""
    if not resolved.sub_ok(sub):
        return False
    for entry in resolved.filters:
        if entry["f"] == "rg":
            hit = rg.lower() in {v.lower() for v in entry["v"]}
            if hit != (entry["op"] == "eq"):
                return False
    return True


def limited(resolved):
    return any(f["f"] in ("type", "loc", "tag") for f in resolved.filters)


def matrix(rows, label_of, period_months, top=7):
    """{series, periods, values} for the stacked chart: the biggest `top` labels, the rest added up as Other."""
    totals, values = defaultdict(float), defaultdict(lambda: defaultdict(float))
    for row in rows:
        name = label_of(row)
        for month, cost in row.get("months", {}).items():
            totals[name] += cost
            values[name][month] += cost
    ranked = [name for name, _ in sorted(totals.items(), key=lambda item: -item[1])]
    keep, rest = ranked[:top], ranked[top:]
    out = {name: {m: round(values[name].get(m, 0.0), 2) for m in period_months} for name in keep}
    if rest:
        out["Other"] = {m: round(sum(values[n].get(m, 0.0) for n in rest), 2) for m in period_months}
        keep = keep + ["Other"]
    return {"series": keep, "periods": list(period_months), "values": out}


def hierarchy(rows, resolved, names, period, resource_costs=None):
    """Subscriptions with their resource groups (and the biggest resources of each group), most expensive first:
    [{id, name, total, share, groups: [{rg, total, share, resources: [{id, name, cost}]}]}]. `resource_costs` is [{id, cost}]."""
    chosen = [row for row in rows if group_ok(resolved, row["sub"], row["rg"])]
    by_sub = defaultdict(list)
    for row in chosen:
        cost = _cost(row, period)
        if cost:
            by_sub[row["sub"]].append((row, cost))
    grand = sum(cost for items in by_sub.values() for _, cost in items)
    resources = defaultdict(list)
    for item in resource_costs or []:
        parts = str(item["id"]).split("/")
        lowered = [p.lower() for p in parts]
        if len(parts) > 8 and lowered[1] == "subscriptions" and "resourcegroups" in lowered:
            resources[(lowered[2], lowered[lowered.index("resourcegroups") + 1])].append(
                {"id": item["id"], "name": parts[-1], "cost": item["cost"]})
    result = []
    for sub, items in by_sub.items():
        total = sum(cost for _, cost in items)
        groups = []
        for row, cost in sorted(items, key=lambda pair: -pair[1]):
            listed = sorted(resources.get((sub, row["rg"].lower()), []), key=lambda r: -r["cost"])[:RESOURCES_PER_GROUP]
            groups.append({"rg": row["rg"], "total": round(cost, 2), "share": round(100 * cost / grand, 1) if grand else 0.0, "resources": listed})
        result.append({"id": sub, "name": names.get(sub, sub), "total": round(total, 2), "share": round(100 * total / grand, 1) if grand else 0.0, "groups": groups})
    result.sort(key=lambda s: -s["total"])
    return result


def tag_values(rows, key, resolved, period):
    """The values of one tag with their cost: ({total, untagged, untaggedPercent, entries: [{value, cost, share}]}). The empty value is
    cost without the tag."""
    totals = defaultdict(float)
    for row in rows:
        if row["key"] == key and resolved.sub_ok(row["sub"]):
            totals[row["value"]] += _cost(row, period)
    total = sum(totals.values())
    values = [{"value": value or UNTAGGED, "untagged": not value, "cost": round(cost, 2), "share": round(100 * cost / total, 1) if total else 0.0}
              for value, cost in sorted(totals.items(), key=lambda item: -item[1]) if cost]
    untagged = round(totals.get("", 0.0), 2)
    return {"total": round(total, 2), "untagged": untagged, "untaggedPercent": round(100 * untagged / total, 1) if total else None, "entries": values}


def tag_keys(rows):
    seen = []
    for row in rows:
        if row["key"] not in seen:
            seen.append(row["key"])
    return seen


def hierarchy_csv(subs, period):
    out = []
    for sub in subs:
        for group in sub["groups"]:
            out.append([sub["name"], sub["id"], group["rg"], period, group["total"], group["share"]])
    return ["Subscription", "Subscription id", "Resource group", "Period", "Cost", "Share %"], out


def tag_csv(result, key, period):
    return ["Tag", "Value", "Period", "Cost", "Share %"], [[key, "" if v["untagged"] else v["value"], period, v["cost"], v["share"]] for v in result["entries"]]
