"""FinOps: monthly spend, budgets and spend anomalies from Azure Cost Management (Cost Management Reader).

Spend is read per subscription for the last six months. Cost Management throttles hard, so every call honours the
retry headers, and the whole step stops starting new subscriptions after a time budget instead of running forever.
"""
import logging
import os
import statistics
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
TIME_BUDGET_SECONDS = 420
BREAKDOWN_BUDGET_SECONDS = 240
WORKERS = 3
DAILY_WINDOW_DAYS = 60
ANOMALY_RECENT_DAYS = 14
ANOMALY_SCORE = 3.0
ANOMALY_MIN_PERCENT = 25
TENANT = "tenant"
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


def query_body(now, months=MONTHS, kind="ActualCost", granularity="Monthly", grouping=("ServiceName",), days=None):
    """A Cost Management query. Actual cost is what is billed; amortized cost spreads reservations and savings
    plans over their term, which the FinOps hub calls effective cost."""
    if days:
        start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        start = month_start(now)
        for _ in range(months - 1):
            start = month_start(start - timedelta(days=1))
    dataset = {"granularity": granularity, "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}}}
    if grouping:
        dataset["grouping"] = [{"type": "Dimension", "name": name} for name in grouping]
    return {
        "type": kind, "timeframe": "Custom",
        "timePeriod": {"from": start.strftime("%Y-%m-%dT00:00:00Z"), "to": now.strftime("%Y-%m-%dT00:00:00Z")},
        "dataset": dataset,
    }


def parse_costs(properties):
    """Rows of a Cost Management query as [{month, service, cost, currency}], whatever the column order is.
    A SubscriptionId column, present in tenant wide queries, is kept as `subscriptionId`."""
    names = [column["name"].lower() for column in properties.get("columns", [])]

    def index(*candidates):
        for candidate in candidates:
            if candidate in names:
                return names.index(candidate)
        return None

    cost_i, month_i = index("cost", "pretaxcost"), index("billingmonth", "usagedate", "billingperiod")
    service_i, currency_i, sub_i = index("servicename"), index("currency"), index("subscriptionid")
    if cost_i is None or month_i is None:
        return []
    rows = []
    for row in properties.get("rows", []):
        item = {"month": str(row[month_i])[:7], "service": row[service_i] if service_i is not None else "",
                "cost": float(row[cost_i] or 0), "currency": row[currency_i] if currency_i is not None else ""}
        if sub_i is not None:
            item["subscriptionId"] = str(row[sub_i]).lower()
        rows.append(item)
    return rows


def parse_daily(properties):
    """[{date, cost}] from a daily query without grouping."""
    names = [column["name"].lower() for column in properties.get("columns", [])]
    if "cost" not in names and "pretaxcost" not in names:
        return []
    cost_i = names.index("cost") if "cost" in names else names.index("pretaxcost")
    date_i = names.index("usagedate") if "usagedate" in names else None
    if date_i is None:
        return []
    totals = {}
    for row in properties.get("rows", []):
        day = str(row[date_i])
        day = f"{day[:4]}-{day[4:6]}-{day[6:8]}" if day.isdigit() and len(day) == 8 else day[:10]
        totals[day] = totals.get(day, 0.0) + float(row[cost_i] or 0)
    return [{"date": day, "cost": round(cost, 2)} for day, cost in sorted(totals.items())]


def _query(token, scope, body):
    """Runs a Cost Management query at a scope and follows pagination. Returns (status, [properties])."""
    url = f"https://management.azure.com{scope}/providers/Microsoft.CostManagement/query?api-version={COST_API}"
    pages = []
    for _ in range(MAX_PAGES):
        response = _call("POST", url, token, body)
        if response.status_code in (401, 403):
            return "denied", []
        if response.status_code in (400, 404):
            return "unavailable", []
        response.raise_for_status()
        properties = response.json().get("properties", {})
        pages.append(properties)
        url = properties.get("nextLink")
        if not url:
            break
    return "ok", pages


def fetch_costs(token, subscription, now):
    """Billed cost per month and service for one subscription. Returns (status, rows)."""
    status, pages = _query(token, f"/subscriptions/{subscription}", query_body(now))
    return status, [row for page in pages for row in parse_costs(page)]


def fetch_tenant_costs(token, tenant_id, now):
    """Billed cost per subscription, month and service in one call, where the tenant root management group can
    be queried (Enterprise Agreement and Microsoft Customer Agreement). Other offers return `unavailable`."""
    scope = f"/providers/Microsoft.Management/managementGroups/{tenant_id}"
    body = query_body(now, grouping=("SubscriptionId", "ServiceName"))
    status, pages = _query(token, scope, body)
    return status, [row for page in pages for row in parse_costs(page)]


def fetch_effective(token, scope, now):
    """Amortized (effective) cost per month for a scope: {month: cost}."""
    status, pages = _query(token, scope, query_body(now, kind="AmortizedCost", grouping=None))
    return status, monthly_totals([row for page in pages for row in parse_costs(page)])


def fetch_daily(token, scope, now):
    status, pages = _query(token, scope, query_body(now, granularity="Daily", grouping=None, days=DAILY_WINDOW_DAYS))
    return status, [point for page in pages for point in parse_daily(page)]


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


def detect_anomalies(daily):
    """Days that cost far more than in the days just before, like the anomaly view of the FinOps hub dashboard.
    Each day is compared with the previous two weeks (robust z-score: median and median absolute deviation), so a
    lasting rise in spend is a new normal after a few days and only sudden spikes are flagged. A minimum relative
    gap avoids flagging tiny differences on a very stable bill."""
    anomalies = []
    for index in range(ANOMALY_RECENT_DAYS, len(daily)):
        window = [point["cost"] for point in daily[index - ANOMALY_RECENT_DAYS:index]]
        median = statistics.median(window)
        if median <= 0:
            continue
        mad = statistics.median(abs(value - median) for value in window)
        scale = 1.4826 * mad if mad > 0 else median * 0.05
        cost = daily[index]["cost"]
        percent = (cost / median - 1) * 100
        previous = daily[index - 1]["cost"]
        # Only the day the spend jumps: the days after a lasting rise are the new normal, not new anomalies.
        jumped = previous <= 0 or (cost / previous - 1) * 100 >= ANOMALY_MIN_PERCENT
        if jumped and (cost - median) / scale >= ANOMALY_SCORE and percent >= ANOMALY_MIN_PERCENT:
            anomalies.append({"date": daily[index]["date"], "cost": round(cost, 2), "expected": round(median, 2),
                              "percent": round(percent, 1)})
    return anomalies


def _sum_effective(results):
    totals = {}
    for item in results.values():
        for month, cost in (item.get("effective") or {}).items():
            totals[month] = totals.get(month, 0.0) + cost
    return dict(sorted(totals.items()))


def _sum_daily(results):
    totals = {}
    for item in results.values():
        for point in item.get("daily") or []:
            totals[point["date"]] = totals.get(point["date"], 0.0) + point["cost"]
    return [{"date": day, "cost": round(cost, 2)} for day, cost in sorted(totals.items())]


def evaluate(run_id, results, now=None, tenant=None, mode="subscriptions"):
    """results: {subscription: {costStatus, rows, budgetStatus, budgets, effective, daily}}.
    tenant: {effective, daily} read once at tenant scope, when that scope could be queried.
    Returns (findings, stats, dataset, errors)."""
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

    # Effective cost and the daily series are tenant totals: they are only shown when every subscription was read.
    everything_read = bool(results) and coverage["ok"] == len(results)
    tenant = tenant or {}
    effective = tenant.get("effective") or (_sum_effective(results) if everything_read else {})
    daily = tenant.get("daily") or (_sum_daily(results) if everything_read else [])
    anomalies = detect_anomalies(daily)
    recent_from = (now - timedelta(days=ANOMALY_RECENT_DAYS)).strftime("%Y-%m-%d")
    recent = [a for a in anomalies if a["date"] >= recent_from]
    if len(daily) >= ANOMALY_RECENT_DAYS:
        stat("FIN-COST-002", "medium", TENANT, len(recent), ANOMALY_RECENT_DAYS)
        for item in recent:
            finding("FIN-COST-002", "medium",
                    f"Spend on {item['date']} was {item['percent']:g}% above the usual daily level "
                    f"({item['cost']:,.0f} against {item['expected']:,.0f}{' ' + currency if currency else ''})",
                    "Open Cost analysis for that day, find the service or resource behind the increase and "
                    "confirm it was expected.", f"cost-anomaly/{item['date']}", TENANT, item["date"])

    services = {}
    for row in all_rows:
        if row["month"] == last:
            services[row["service"] or "Unknown"] = services.get(row["service"] or "Unknown", 0.0) + row["cost"]

    by_subscription = sorted(
        ({"subscriptionId": sub, "last": round(months.get(last, 0.0), 2), "previous": round(months.get(previous, 0.0), 2)}
         for sub, months in per_sub_months.items()), key=lambda i: i["last"], reverse=True)[:TOP]

    dataset = {
        "currency": currency,
        "scope": mode,
        "months": [{"month": m, "cost": round(c, 2), "partial": m >= now.strftime("%Y-%m"),
                    "effective": round(effective[m], 2) if m in effective else None} for m, c in totals.items()],
        "lastMonth": last,
        "lastMonthCost": round(totals[last], 2) if last else None,
        "lastMonthEffective": round(effective[last], 2) if last and last in effective else None,
        "monthOverMonthPercent": round((totals[last] / totals[previous] - 1) * 100, 1) if last and previous and totals[previous] else None,
        "forecastNextMonth": forecast_next(totals, complete),
        "topServices": [{"service": s, "cost": round(c, 2)} for s, c in sorted(services.items(), key=lambda i: -i[1])[:TOP]],
        "bySubscription": by_subscription,
        "budgets": sorted(budgets_out, key=lambda b: -b["percent"])[:20],
        "daily": daily[-DAILY_WINDOW_DAYS:],
        "anomalies": anomalies[-TOP:],
        "coverage": coverage,
    }
    errors = []
    if coverage["denied"]:
        errors.append({"ruleId": "finops-permission", "error": f"Cost data was not readable for {coverage['denied']} "
                       "subscription(s). Grant the service principal Cost Management Reader."})
    if coverage["error"]:
        errors.append({"ruleId": "finops-error", "error": f"Cost data could not be read for {coverage['error']} subscription(s)."})
    return findings, stats, dataset, errors


COMMITMENT_KIND = {"reservation": "Reservation", "savingsplan": "Savings plan", "commitment": "Commitment"}


def commitment_findings(run_id, items):
    """(findings, stats) of the reservations and savings plans that were used less than they should: they are paid whether used or not."""
    from . import spend

    findings, under = [], 0
    for item in items:
        if item["percent"] is None or item["percent"] >= spend.UNDERUSED_PERCENT or item["unused"] < spend.MIN_UNUSED:
            continue
        under += 1
        label = COMMITMENT_KIND.get(item["kind"], "Commitment")
        findings.append(make_finding(
            run_id, rule_id="FIN-COM-001", source="finops", pillar="Cost Optimization", severity="high" if item["percent"] < 50 else "medium",
            title=f"{label} '{item['name']}' was used {item['percent']:g}% in {item['month']}: {item['unused']:,.0f} {item['currency']} paid for nothing".strip(),
            recommendation="Exchange or resize the commitment (reservations can be exchanged), move workloads onto it, or stop renewing it.",
            resource_id=f"/commitments/{item['kind']}/{item['name']}", resource_name=item["name"], subscription_id=TENANT))
    stats = [{"ruleId": "FIN-COM-001", "source": "finops", "pillar": "Cost Optimization", "severity": "medium", "subscriptionId": TENANT,
              "affected": under, "applicable": len(items)}] if items else []
    return findings, stats


def collect(credential, run_id, subscription_ids, now=None):
    """Tenant scope first (one call for every subscription, like the FinOps hub reading a billing scope), then
    one subscription at a time where the tenant scope cannot be queried."""
    now = now or datetime.now(timezone.utc)
    token = credential.get_token(SCOPE).token
    deadline = _now() + TIME_BUDGET_SECONDS
    subscriptions = [s.lower() for s in subscription_ids]
    tenant_id = os.environ.get("COLLECTOR_TENANT_ID", "")

    results, tenant, mode = {}, None, "subscriptions"
    if tenant_id:
        try:
            status, rows = fetch_tenant_costs(token, tenant_id, now)
        except Exception:
            status, rows = "error", []
        if status == "ok":
            mode = "tenant"
            scope = f"/providers/Microsoft.Management/managementGroups/{tenant_id}"
            by_sub = {}
            for row in rows:
                by_sub.setdefault(row.get("subscriptionId", ""), []).append(
                    {key: value for key, value in row.items() if key != "subscriptionId"})
            results = {sub: {"costStatus": "ok", "rows": by_sub.get(sub, [])} for sub in subscriptions}
            tenant = {}
            for name, fetch in (("effective", fetch_effective), ("daily", fetch_daily)):
                try:
                    tenant[name] = fetch(token, scope, now)[1]
                except Exception:
                    tenant[name] = None

    def run(sub):
        item = results.get(sub, {})
        if _now() > deadline:
            return sub, {**item, "costStatus": item.get("costStatus", "error"), "rows": item.get("rows", [])}
        if mode != "tenant":
            try:
                item["costStatus"], item["rows"] = fetch_costs(token, sub, now)
                if item["costStatus"] == "ok":
                    item["effective"] = fetch_effective(token, f"/subscriptions/{sub}", now)[1]
                    item["daily"] = fetch_daily(token, f"/subscriptions/{sub}", now)[1]
            except Exception:
                item["costStatus"], item["rows"] = item.get("costStatus", "error"), item.get("rows", [])
                if item["costStatus"] == "ok":
                    item["costStatus"] = "error"
        try:
            item["budgetStatus"], item["budgets"] = fetch_budgets(token, sub)
        except Exception:
            item["budgetStatus"], item["budgets"] = "error", []
        return sub, item

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = dict(pool.map(run, subscriptions))
    findings, stats, dataset, errors = evaluate(run_id, results, now, tenant, mode)
    if dataset.get("months"):
        from . import spend  # imported here because spend builds on this module

        scopes = ([f"/providers/Microsoft.Management/managementGroups/{tenant_id}"] if mode == "tenant"
                  else [f"/subscriptions/{sub}" for sub, item in results.items() if item.get("costStatus") == "ok"])
        resource_costs = []
        try:
            section, partial = spend.collect(token, scopes, now, _now() + BREAKDOWN_BUDGET_SECONDS, _now, costs=resource_costs)
        except Exception:
            logging.exception("Cost breakdowns could not be read")
            section, partial = {}, True
        if section:
            dataset["breakdowns"] = {**section, "partial": partial}
            extra_findings, extra_stats = commitment_findings(run_id, section.get("commitmentUtilization") or [])
            findings.extend(extra_findings)
            stats.extend(extra_stats)
        dataset["resourceCosts"] = resource_costs  # kept apart from the summary by the activity
    return findings, stats, dataset, errors
