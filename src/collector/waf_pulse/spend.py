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
    "resources": ("None", ("ResourceId",), RESOURCE_DAYS),
}


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


def fetch(token, scope, name, now):
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
    if raw.get("resources"):
        out["topResources"] = top_resources(raw["resources"])
    return out


def collect(token, scopes, now, deadline, clock=time.monotonic, costs=None):
    """scopes: one tenant scope, or one scope per subscription. Rows of the same query are added together.
    Returns (section, partial) where partial says some scope could not be read within the time budget."""
    raw, partial = {name: None for name in QUERIES}, False

    def run(job):
        scope, name = job
        if clock() > deadline:
            return name, None, True
        try:
            return name, fetch(token, scope, name, now), False
        except Exception:
            return name, None, False

    jobs = [(scope, name) for scope in scopes for name in QUERIES]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for name, rows, skipped in pool.map(run, jobs):
            partial = partial or skipped or rows is None
            if rows is not None:
                raw[name] = (raw[name] or []) + rows
    if costs is not None and raw.get("resources"):
        costs.extend(resource_costs(raw["resources"]))
    return build(raw, now), partial
