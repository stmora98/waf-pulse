"""Cost breakdowns for the Cost page, shaped after the views of the FinOps hub dashboard: spend by service, region,
resource group and resource type over time, the days behind a spike, the most expensive resources and how much of
the bill is covered by commitments.

Everything comes from the Cost Management query API (amortized cost, which the hub calls effective cost), so no
FinOps hub or export is needed. The API accepts two groupings per query, so every query carries two dimensions
and each dimension is later totalled on its own.
"""
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from . import finops

TOP_SERIES = 7
TOP_RESOURCES = 15
RESOURCE_DAYS = 30
OTHER = "Other"
COMMITMENT_MODELS = ("reservation", "savingsplan")
WORKERS = 3

# name -> (granularity, grouping, days or None). Every one asks for amortized cost.
QUERIES = {
    "serviceLocation": ("Monthly", ("ServiceName", "ResourceLocation"), None),
    "groupType": ("Monthly", ("ResourceGroupName", "ResourceType"), None),
    "dailyService": ("Daily", ("ServiceName",), finops.DAILY_WINDOW_DAYS),
    "pricing": ("Monthly", ("PricingModel",), None),
    "benefits": ("Monthly", ("BenefitName", "ChargeType"), None),
    "resources": ("None", ("ResourceId",), RESOURCE_DAYS),
    "subGroup": ("Monthly", ("SubscriptionId", "ResourceGroupName"), None),
}
TAG_PREFIX = "tag:"
TAG_DIMENSIONS = ("TagKey", "TagValue", "SubscriptionId")
MAX_TAG_KEYS = 6
MAX_TAG_VALUES = 40
MAX_CHARGEBACK = 600
OTHER_VALUES = "(other values)"
# Tag keys that usually carry a cost owner, tried before the rest.
ALLOCATION_KEYS = ("costcenter", "cost-center", "cost_center", "businessunit", "business-unit", "department", "team", "owner",
                   "project", "application", "app", "workload", "environment", "env")


def parse_grouped(properties, dimensions):
    """[{period, <dimension>: value, cost, currency}] from a grouped query, whatever the column order is."""
    names = [column["name"].lower() for column in properties.get("columns", [])]

    def index(*candidates):
        for candidate in candidates:
            if candidate in names:
                return names.index(candidate)
        return None

    cost_i, currency_i = index("cost", "pretaxcost"), index("currency")
    period_i = index("billingmonth", "usagedate", "billingperiod")
    dimension_i = {name: index(name.lower()) for name in dimensions}
    if cost_i is None or any(i is None for i in dimension_i.values()):
        return []
    rows = []
    for row in properties.get("rows", []):
        item = {name: str(row[i] or "") for name, i in dimension_i.items()}
        item["cost"] = float(row[cost_i] or 0)
        item["currency"] = row[currency_i] if currency_i is not None else ""
        period = str(row[period_i]) if period_i is not None else ""
        if period.isdigit() and len(period) == 8:
            period = f"{period[:4]}-{period[4:6]}-{period[6:8]}"
        item["period"] = period[:10]
        rows.append(item)
    return rows


def tag_body(now, key):
    """Monthly amortized cost per value of one tag and per subscription. Cost without the tag comes back with a null TagValue."""
    body = finops.query_body(now, kind="AmortizedCost", granularity="Monthly", grouping=())
    body["dataset"]["grouping"] = [{"type": "TagKey", "name": key}, {"type": "Dimension", "name": "SubscriptionId"}]
    return body


def fetch(token, scope, name, now):
    if name.startswith(TAG_PREFIX):
        status, pages = finops._query(token, scope, tag_body(now, name[len(TAG_PREFIX):]))
        if status != "ok":
            return None
        return [row for page in pages for row in parse_grouped(page, TAG_DIMENSIONS)]
    granularity, grouping, days = QUERIES[name]
    body = finops.query_body(now, kind="AmortizedCost", granularity=granularity, grouping=grouping, days=days)
    status, pages = finops._query(token, scope, body)
    if status != "ok":
        return None
    return [row for page in pages for row in parse_grouped(page, grouping)]


def matrix(rows, dimension, period_of, top=TOP_SERIES):
    """Totals of one dimension per period: {series: [names], periods: [...], values: {name: {period: cost}}}.
    The largest `top` names are kept, the rest is added up as "Other"."""
    totals, values = defaultdict(float), defaultdict(lambda: defaultdict(float))
    for row in rows:
        name = row.get(dimension) or "Unknown"
        period = period_of(row)
        if not period:
            continue
        totals[name] += row["cost"]
        values[name][period] += row["cost"]
    ranked = [name for name, _ in sorted(totals.items(), key=lambda item: -item[1])]
    keep, rest = ranked[:top], ranked[top:]
    periods = sorted({period for series in values.values() for period in series})
    out = {name: {p: round(values[name].get(p, 0.0), 2) for p in periods} for name in keep}
    if rest:
        out[OTHER] = {p: round(sum(values[name].get(p, 0.0) for name in rest), 2) for p in periods}
        keep = keep + [OTHER]
    return {"series": keep, "periods": periods, "values": out}


def monthly(row):
    return row["period"][:7]


def daily(row):
    return row["period"]


def commitment_coverage(rows, now):
    """Share of the last full month (and of this month so far) paid through reservations or savings plans."""
    result = {}
    current = now.strftime("%Y-%m")
    months = sorted({monthly(row) for row in rows if monthly(row)})
    for label, month in (("thisMonth", current), ("lastMonth", next((m for m in reversed(months) if m < current), None))):
        if not month:
            continue
        total = sum(row["cost"] for row in rows if monthly(row) == month)
        committed = sum(row["cost"] for row in rows
                        if monthly(row) == month and row["PricingModel"].lower().replace(" ", "") in COMMITMENT_MODELS)
        if total > 0:
            result[label] = {"month": month, "percent": round(100 * committed / total, 1), "committed": round(committed, 2)}
    return result


UNUSED_CHARGES = {"unusedreservation": "reservation", "unusedsavingsplan": "savingsplan"}
MIN_UNUSED = 25.0          # unused commitment (in the currency) below which an under-used one is not worth a finding
UNDERUSED_PERCENT = 80.0   # utilization below this is under-used


def commitment_utilization(rows, now):
    """How much of each reservation and savings plan was used in the last full month, from the amortized cost: the cost of the
    usage it covered (used) against the charges for the part nobody used (unused). [{name, kind, month, used, unused, percent,
    currency}], the least used first. Empty when there are no commitments."""
    current = now.strftime("%Y-%m")
    months = sorted({monthly(row) for row in rows if monthly(row)})
    last = next((m for m in reversed(months) if m < current), None)
    if not last:
        return []
    items = {}
    for row in rows:
        if monthly(row) != last:
            continue
        kind = UNUSED_CHARGES.get(str(row.get("ChargeType", "")).lower().replace(" ", ""))
        name = row.get("BenefitName", "")
        if not kind and not name:
            continue
        entry = items.setdefault(name or f"(unnamed {kind})", {"kind": "", "used": 0.0, "unused": 0.0, "currency": row.get("currency", "")})
        if kind:
            entry["kind"], entry["unused"] = kind, entry["unused"] + row["cost"]
        else:
            entry["used"] += row["cost"]
    result = []
    for name, entry in items.items():
        total = entry["used"] + entry["unused"]
        result.append({"name": name, "kind": entry["kind"] or "commitment", "month": last, "used": round(entry["used"], 2), "unused": round(entry["unused"], 2),
                       "percent": round(100 * entry["used"] / total, 1) if total > 0 else None, "currency": entry["currency"]})
    result.sort(key=lambda item: (item["percent"] is None, item["percent"] if item["percent"] is not None else 0, -item["unused"]))
    return result[:30]


def discover_tag_keys(credential, subscriptions, override=""):
    """The tag keys worth a cost allocation view: those in COST_TAG_KEYS (comma separated) when set, else the keys with few distinct
    values (an owner or a cost center, not a timestamp), the usual allocation keys first. Empty when Resource Graph cannot be read."""
    wanted = [key.strip() for key in (override or "").split(",") if key.strip()]
    if wanted:
        return wanted[:MAX_TAG_KEYS]
    from . import graph

    kql = ("resources | where isnotempty(tags) | extend k = bag_keys(tags) | mv-expand k to typeof(string) "
           "| extend v = tostring(tags[k]) | summarize resources = count(), distinctValues = dcount(v) by k "
           "| where distinctValues <= 60 | top 40 by resources desc")
    try:
        rows = graph.query(credential, list(subscriptions), kql, max_rows=60)
    except Exception:
        return []
    keys = [(str(row.get("k") or ""), int(row.get("resources") or 0)) for row in rows if row.get("k")]
    keys.sort(key=lambda item: (ALLOCATION_KEYS.index(item[0].lower()) if item[0].lower() in ALLOCATION_KEYS else len(ALLOCATION_KEYS), -item[1]))
    return [key for key, _ in keys[:MAX_TAG_KEYS]]


def chargeback_rows(rows):
    """What each resource group cost per month: [{sub, rg, months: {month: cost}}], the most expensive first. Cost that belongs to
    no resource group (marketplace, support) comes with an empty rg."""
    merged = {}
    for row in rows:
        sub = row.get("SubscriptionId", "").lower()
        key = (sub, row.get("ResourceGroupName", "").lower())
        entry = merged.setdefault(key, {"sub": sub, "rg": row.get("ResourceGroupName", ""), "months": defaultdict(float)})
        entry["months"][monthly(row)] += row["cost"]
    result = [{"sub": e["sub"], "rg": e["rg"], "months": {m: round(c, 2) for m, c in sorted(e["months"].items()) if m}} for e in merged.values()]
    result = [r for r in result if any(c for c in r["months"].values())]
    result.sort(key=lambda r: -sum(r["months"].values()))
    return result[:MAX_CHARGEBACK]


def tag_rows(key, rows):
    """Cost per value of one tag, per subscription and month: [{key, value, sub, months}]. The values beyond the biggest
    MAX_TAG_VALUES are added up as "(other values)" per subscription; an empty value is cost without the tag."""
    totals = defaultdict(float)
    for row in rows:
        totals[row.get("TagValue", "")] += row["cost"]
    keep = {value for value, _ in sorted(totals.items(), key=lambda item: -item[1])[:MAX_TAG_VALUES]}
    merged = {}
    for row in rows:
        value = row.get("TagValue", "")
        value = value if value in keep else OTHER_VALUES
        sub = row.get("SubscriptionId", "").lower()
        entry = merged.setdefault((value.lower(), sub), {"key": key, "value": value, "sub": sub, "months": defaultdict(float)})
        entry["months"][monthly(row)] += row["cost"]
    result = [{**e, "months": {m: round(c, 2) for m, c in sorted(e["months"].items()) if m}} for e in merged.values()]
    return [r for r in result if any(c for c in r["months"].values())]


def top_resources(rows):
    totals = defaultdict(float)
    for row in rows:
        if row["ResourceId"]:
            totals[row["ResourceId"].lower()] += row["cost"]
    return [{"id": resource, "name": resource.rstrip("/").rsplit("/", 1)[-1], "cost": round(cost, 2)}
            for resource, cost in sorted(totals.items(), key=lambda item: -item[1])[:TOP_RESOURCES] if cost > 0]


MAX_COSTS = 1500


def resource_costs(rows):
    """What each resource cost in the last 30 days (amortized), the most expensive first: [{id (lower), cost}]."""
    totals = defaultdict(float)
    for row in rows:
        if row["ResourceId"]:
            totals[row["ResourceId"].lower()] += row["cost"]
    ranked = sorted(totals.items(), key=lambda item: -item[1])
    return [{"id": resource, "cost": round(cost, 2)} for resource, cost in ranked[:MAX_COSTS] if cost > 0]


def build(raw, now):
    """raw: {query name: rows or None}. Returns the dataset section for the page, with only what could be read."""
    out = {}
    if raw.get("serviceLocation"):
        out["byService"] = matrix(raw["serviceLocation"], "ServiceName", monthly)
        out["byLocation"] = matrix(raw["serviceLocation"], "ResourceLocation", monthly)
    if raw.get("groupType"):
        out["byResourceGroup"] = matrix(raw["groupType"], "ResourceGroupName", monthly)
        out["byResourceType"] = matrix(raw["groupType"], "ResourceType", monthly)
    if raw.get("dailyService"):
        out["dailyByService"] = matrix(raw["dailyService"], "ServiceName", daily, top=5)
    if raw.get("pricing"):
        out["byPricingModel"] = matrix(raw["pricing"], "PricingModel", monthly)
        out["commitmentCoverage"] = commitment_coverage(raw["pricing"], now)
    if raw.get("benefits"):
        out["commitmentUtilization"] = commitment_utilization(raw["benefits"], now)
    if raw.get("resources"):
        out["topResources"] = top_resources(raw["resources"])
    tag_keys = [name[len(TAG_PREFIX):] for name, rows in raw.items() if name.startswith(TAG_PREFIX) and rows]
    if tag_keys:
        out["tagKeys"] = tag_keys
    return out


def collect(token, scopes, now, deadline, clock=time.monotonic, costs=None, tag_keys=(), extras=None):
    """scopes: one tenant scope, or one scope per subscription. Rows of the same query are added together.
    `tag_keys` adds one cost query per tag key; `extras` receives the rows kept apart from the summary (chargeback, tagCosts).
    Returns (section, partial) where partial says some scope could not be read within the time budget."""
    names = [*QUERIES, *(TAG_PREFIX + key for key in tag_keys)]
    raw, partial = {name: None for name in names}, False

    def run(job):
        scope, name = job
        if clock() > deadline:
            return name, None, True
        try:
            return name, fetch(token, scope, name, now), False
        except Exception:
            return name, None, False

    jobs = [(scope, name) for scope in scopes for name in names]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for name, rows, skipped in pool.map(run, jobs):
            partial = partial or skipped or rows is None
            if rows is not None:
                raw[name] = (raw[name] or []) + rows
    if costs is not None and raw.get("resources"):
        costs.extend(resource_costs(raw["resources"]))
    if extras is not None:
        extras["chargeback"] = chargeback_rows(raw["subGroup"]) if raw.get("subGroup") else []
        extras["tagCosts"] = [row for key in tag_keys if raw.get(TAG_PREFIX + key) for row in tag_rows(key, raw[TAG_PREFIX + key])]
    return build(raw, now), partial
