"""FinOps: monthly spend, budgets and spend anomalies from Azure Cost Management (Cost Management Reader).

Spend is read per subscription for the last six months. Cost Management throttles hard, so every call honours the
retry headers, and the whole step stops starting new subscriptions after a time budget instead of running forever.
"""
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import requests

from .findings import make_finding

SCOPE = "https://management.azure.com/.default"
COST_API = "2023-11-01"
BUDGET_API = "2023-05-01"
MONTHS = 6
MAX_ATTEMPTS = 6
MAX_PAGES = 10
REQUEST_TIMEOUT = 90
TIME_BUDGET_SECONDS = 240
WORKERS = 2
SPIKE_PERCENT = 30
SPIKE_MIN_INCREASE = 50.0
TOP = 10

_sleep = time.sleep
_now = time.monotonic

RETRY_HEADERS = (
    "Retry-After",
    "x-ms-ratelimit-microsoft.costmanagement-entity-retry-after",
    "x-ms-ratelimit-microsoft.costmanagement-tenant-retry-after",
    "x-ms-ratelimit-microsoft.costmanagement-client-retry-after",
)


def retry_seconds(headers):
    waits = []
    for name in RETRY_HEADERS:
        try:
            waits.append(float(headers.get(name)))
        except (TypeError, ValueError):
            continue
    return min(max(waits), 60.0) if waits else 10.0


def _call(method, url, token, body=None):
    for attempt in range(MAX_ATTEMPTS):
        last = attempt == MAX_ATTEMPTS - 1
        try:
            response = requests.request(method, url, headers={"Authorization": f"Bearer {token}"}, json=body,
                                        timeout=REQUEST_TIMEOUT)
        except (requests.ConnectionError, requests.Timeout):
            if last:
                raise
            _sleep(min(2 ** attempt, 30))
            continue
        if (response.status_code == 429 or response.status_code >= 500) and not last:
            _sleep(retry_seconds(response.headers) if response.status_code == 429 else min(2 ** attempt, 30))
            continue
        return response
    return response


def month_start(value):
    return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def query_body(now, months=MONTHS):
    start = month_start(now)
    for _ in range(months - 1):
        start = month_start(start - timedelta(days=1))
    return {
        "type": "ActualCost", "timeframe": "Custom",
        "timePeriod": {"from": start.strftime("%Y-%m-%dT00:00:00Z"), "to": now.strftime("%Y-%m-%dT00:00:00Z")},
        "dataset": {"granularity": "Monthly", "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
                    "grouping": [{"type": "Dimension", "name": "ServiceName"}]},
    }


def parse_costs(properties):
    """Rows of a Cost Management query as [{month, service, cost, currency}], whatever the column order is."""
    names = [column["name"].lower() for column in properties.get("columns", [])]

    def index(*candidates):
        for candidate in candidates:
            if candidate in names:
                return names.index(candidate)
        return None

    cost_i, month_i = index("cost", "pretaxcost"), index("billingmonth", "usagedate", "billingperiod")
    service_i, currency_i = index("servicename"), index("currency")
    if cost_i is None or month_i is None:
        return []
    rows = []
    for row in properties.get("rows", []):
        month = str(row[month_i])[:7]
        rows.append({"month": month, "service": row[service_i] if service_i is not None else "",
                     "cost": float(row[cost_i] or 0), "currency": row[currency_i] if currency_i is not None else ""})
    return rows


def fetch_costs(token, subscription, now):
    """Returns (status, rows). status: ok, denied (no permission) or unavailable (no cost data for this offer)."""
    url = f"https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.CostManagement/query?api-version={COST_API}"
    rows = []
    for _ in range(MAX_PAGES):
        response = _call("POST", url, token, query_body(now))
        if response.status_code in (401, 403):
            return "denied", []
        if response.status_code in (400, 404):
            return "unavailable", []
        response.raise_for_status()
        properties = response.json().get("properties", {})
        rows.extend(parse_costs(properties))
        url = properties.get("nextLink")
        if not url:
            break
    return "ok", rows


def parse_budgets(body):
    budgets = []
    for item in (body or {}).get("value", []):
        props = item.get("properties", {})
        amount = float(props.get("amount") or 0)
        spent = float((props.get("currentSpend") or {}).get("amount") or 0)
        forecast = float((props.get("forecastSpend") or {}).get("amount") or 0)
        budgets.append(
            {"name": item.get("name", ""), "id": item.get("id", ""), "amount": amount, "spent": spent,
             "forecast": forecast, "timeGrain": props.get("timeGrain", ""),
             "currency": (props.get("currentSpend") or {}).get("unit", ""),
             "percent": round(spent / amount * 100, 1) if amount else 0.0}
        )
    return budgets


def fetch_budgets(token, subscription):
    url = f"https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Consumption/budgets?api-version={BUDGET_API}"
    response = _call("GET", url, token)
    if response.status_code in (401, 403):
        return "denied", []
    if response.status_code in (400, 404):
        return "unavailable", []
    response.raise_for_status()
    return "ok", parse_budgets(response.json())


def monthly_totals(rows):
    totals = {}
    for row in rows:
        totals[row["month"]] = totals.get(row["month"], 0.0) + row["cost"]
    return dict(sorted(totals.items()))


def complete_months(months, now):
    """Months before the current one: the current month is still accumulating and would look like a drop."""
    current = now.strftime("%Y-%m")
    return [month for month in months if month < current]


def forecast_next(totals, complete):
    """Last full month plus the average monthly change of the last three full months. Never negative."""
    values = [totals[m] for m in complete][-4:]
    if len(values) < 2:
        return None
    changes = [b - a for a, b in zip(values, values[1:])]
    return round(max(0.0, values[-1] + sum(changes) / len(changes)), 2)


def evaluate(run_id, results, now=None):
    """results: {subscription: {costStatus, rows, budgetStatus, budgets}}. Returns (findings, stats, dataset, errors)."""
    now = now or datetime.now(timezone.utc)
    findings, stats, all_rows = [], [], []

    def stat(rule, severity, sub, affected, applicable):
        stats.append({"ruleId": rule, "source": "finops", "pillar": "Cost Optimization", "severity": severity,
                      "subscriptionId": sub, "affected": affected, "applicable": applicable})

    def finding(rule, severity, title, recommendation, resource_id, sub, name=""):
        findings.append(make_finding(run_id, rule_id=rule, source="finops", pillar="Cost Optimization",
                                     severity=severity, title=title, recommendation=recommendation,
                                     resource_id=resource_id, resource_name=name, subscription_id=sub))

    budgets_out, per_sub_months, coverage = [], {}, {"ok": 0, "denied": 0, "unavailable": 0, "error": 0}
    for sub, item in results.items():
        status = item.get("costStatus", "error")
        coverage[status if status in coverage else "error"] += 1
        rows = item.get("rows", [])
        all_rows.extend(rows)
        per_sub_months[sub] = monthly_totals(rows)

        if item.get("budgetStatus") == "ok":
            budgets = item.get("budgets", [])
            stat("FIN-BUD-001", "low", sub, 0 if budgets else 1, 1)
            if not budgets:
                finding("FIN-BUD-001", "low", "Subscription has no budget",
                        "Create a budget with alerts so unexpected spend is noticed early.",
                        f"/subscriptions/{sub}", sub)
            if budgets:
                over = [b for b in budgets if b["amount"] and b["spent"] >= b["amount"]]
                forecast_over = [b for b in budgets if b["amount"] and b["spent"] < b["amount"] <= b["forecast"]]
                stat("FIN-BUD-002", "medium", sub, len(over), len(budgets))
                stat("FIN-BUD-003", "low", sub, len(forecast_over), len(budgets))
                for b in over:
                    finding("FIN-BUD-002", "medium", f"Budget '{b['name']}' is exhausted ({b['percent']}% spent)",
                            "Review the spend, raise the budget or reduce usage.", b["id"], sub, b["name"])
                for b in forecast_over:
                    finding("FIN-BUD-003", "low", f"Budget '{b['name']}' is forecast to be exceeded",
                            "Review the forecast and act before the budget is reached.", b["id"], sub, b["name"])
            budgets_out.extend({**b, "subscriptionId": sub} for b in budgets)

        complete = complete_months(per_sub_months[sub], now)
        if len(complete) >= 2:
            before, after = per_sub_months[sub][complete[-2]], per_sub_months[sub][complete[-1]]
            grew = after - before >= SPIKE_MIN_INCREASE and before > 0 and (after / before - 1) * 100 >= SPIKE_PERCENT
            stat("FIN-COST-001", "medium", sub, 1 if grew else 0, 1)
            if grew:
                finding("FIN-COST-001", "medium",
                        f"Spend grew {round((after / before - 1) * 100)}% from {complete[-2]} to {complete[-1]}",
                        "Find out which services drove the increase and whether it is expected.",
                        f"/subscriptions/{sub}", sub)

    totals = monthly_totals(all_rows)
    complete = complete_months(list(totals), now)
    last = complete[-1] if complete else None
    previous = complete[-2] if len(complete) > 1 else None
    currencies = [row["currency"] for row in all_rows if row["currency"]]
    currency = max(set(currencies), key=currencies.count) if currencies else ""

    services = {}
    for row in all_rows:
        if row["month"] == last:
            services[row["service"] or "Unknown"] = services.get(row["service"] or "Unknown", 0.0) + row["cost"]

    by_subscription = sorted(
        ({"subscriptionId": sub, "last": round(months.get(last, 0.0), 2), "previous": round(months.get(previous, 0.0), 2)}
         for sub, months in per_sub_months.items()), key=lambda i: i["last"], reverse=True)[:TOP]

    dataset = {
        "currency": currency,
        "months": [{"month": m, "cost": round(c, 2), "partial": m >= now.strftime("%Y-%m")} for m, c in totals.items()],
        "lastMonth": last,
        "lastMonthCost": round(totals[last], 2) if last else None,
        "monthOverMonthPercent": round((totals[last] / totals[previous] - 1) * 100, 1) if last and previous and totals[previous] else None,
        "forecastNextMonth": forecast_next(totals, complete),
        "topServices": [{"service": s, "cost": round(c, 2)} for s, c in sorted(services.items(), key=lambda i: -i[1])[:TOP]],
        "bySubscription": by_subscription,
        "budgets": sorted(budgets_out, key=lambda b: -b["percent"])[:20],
        "coverage": coverage,
    }
    errors = []
    if coverage["denied"]:
        errors.append({"ruleId": "finops-permission", "error": f"Cost data was not readable for {coverage['denied']} "
                       "subscription(s). Grant the service principal Cost Management Reader."})
    if coverage["error"]:
        errors.append({"ruleId": "finops-error", "error": f"Cost data could not be read for {coverage['error']} subscription(s)."})
    return findings, stats, dataset, errors


def collect(credential, run_id, subscription_ids, now=None):
    now = now or datetime.now(timezone.utc)
    token = credential.get_token(SCOPE).token
    deadline = _now() + TIME_BUDGET_SECONDS

    def run(sub):
        if _now() > deadline:
            return sub, {"costStatus": "error", "rows": []}
        item = {}
        try:
            item["costStatus"], item["rows"] = fetch_costs(token, sub, now)
        except Exception:
            item["costStatus"], item["rows"] = "error", []
        try:
            item["budgetStatus"], item["budgets"] = fetch_budgets(token, sub)
        except Exception:
            item["budgetStatus"], item["budgets"] = "error", []
        return sub, item

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = dict(pool.map(run, [s.lower() for s in subscription_ids]))
    return evaluate(run_id, results, now)
