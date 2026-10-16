from datetime import datetime, timezone

import pytest

import app as dashboard_app
import cost_view
import data
from waf_pulse import finops

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)
SUB, SUB2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"


def row(month, service, cost, currency="USD"):
    return {"month": month, "service": service, "cost": cost, "currency": currency}


def budget(name="b", amount=100, spent=10, forecast=20, sub=SUB):
    return {"name": name, "id": f"/subscriptions/{sub}/providers/Microsoft.Consumption/budgets/{name}", "amount": amount,
            "spent": spent, "forecast": forecast, "timeGrain": "Monthly", "currency": "USD",
            "percent": round(spent / amount * 100, 1)}


# --- parsing --------------------------------------------------------------------------------------------

def test_parse_costs_finds_columns_in_any_order():
    properties = {"columns": [{"name": "ServiceName"}, {"name": "Currency"}, {"name": "UsageDate"}, {"name": "PreTaxCost"}],
                  "rows": [["Storage", "USD", "2026-05-01T00:00:00", 12.5], ["SQL", "USD", "2026-06-01T00:00:00", None]]}
    assert finops.parse_costs(properties) == [row("2026-05", "Storage", 12.5), row("2026-06", "SQL", 0.0)]
    assert finops.parse_costs({"columns": [{"name": "Other"}], "rows": [[1]]}) == []
    assert finops.parse_costs({}) == []


def test_parse_budgets_computes_percent_and_tolerates_missing_fields():
    body = {"value": [{"name": "b1", "id": "i1", "properties": {"amount": 200.0, "timeGrain": "Monthly",
                                                                  "currentSpend": {"amount": 50, "unit": "USD"},
                                                                  "forecastSpend": {"amount": 90}}},
                      {"name": "b2", "properties": {}}]}
    first, second = finops.parse_budgets(body)
    assert (first["percent"], first["forecast"], first["currency"]) == (25.0, 90.0, "USD")
    assert second["amount"] == 0 and second["percent"] == 0.0
    assert finops.parse_budgets(None) == []


def test_query_body_covers_the_last_six_months_up_to_today():
    body = finops.query_body(NOW)
    assert body["timePeriod"] == {"from": "2026-05-01T00:00:00Z", "to": "2026-10-15T00:00:00Z"}
    assert body["type"] == "ActualCost" and body["dataset"]["granularity"] == "Monthly"
    assert finops.query_body(datetime(2026, 2, 3, tzinfo=timezone.utc))["timePeriod"]["from"] == "2025-09-01T00:00:00Z"


def test_retry_seconds_uses_the_largest_header_and_a_default():
    assert finops.retry_seconds({"Retry-After": "5", "x-ms-ratelimit-microsoft.costmanagement-entity-retry-after": "30"}) == 30
    assert finops.retry_seconds({"Retry-After": "500"}) == 60
    assert finops.retry_seconds({}) == 10
    assert finops.retry_seconds({"Retry-After": "soon"}) == 10


# --- requests -------------------------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def script(monkeypatch, responses, slept=None):
    queue = list(responses)

    def fake_request(method, url, **kwargs):
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(finops.requests, "request", fake_request)
    monkeypatch.setattr(finops, "_sleep", (slept if slept is not None else []).append)
    return queue


def test_call_waits_when_throttled_and_retries_server_errors_and_dropped_connections(monkeypatch):
    slept = []
    script(monkeypatch, [FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(503),
                         finops.requests.ConnectionError("reset"), FakeResponse(200, {"ok": 1})], slept)
    assert finops._call("GET", "u", "t").json() == {"ok": 1}
    assert slept == [7.0, 2, 4]


def test_call_returns_the_last_response_when_it_never_recovers(monkeypatch):
    script(monkeypatch, [FakeResponse(429) for _ in range(finops.MAX_ATTEMPTS)])
    assert finops._call("GET", "u", "t").status_code == 429


def test_fetch_costs_status_and_pagination(monkeypatch):
    page1 = FakeResponse(200, {"properties": {"columns": [{"name": "Cost"}, {"name": "BillingMonth"}],
                                              "rows": [[1.0, "2026-09-01T00:00:00"]], "nextLink": "https://next"}})
    page2 = FakeResponse(200, {"properties": {"columns": [{"name": "Cost"}, {"name": "BillingMonth"}],
                                              "rows": [[2.0, "2026-09-01T00:00:00"]]}})
    script(monkeypatch, [page1, page2])
    status, rows = finops.fetch_costs("t", SUB, NOW)
    assert status == "ok" and sum(r["cost"] for r in rows) == 3.0

    script(monkeypatch, [FakeResponse(403)])
    assert finops.fetch_costs("t", SUB, NOW) == ("denied", [])
    script(monkeypatch, [FakeResponse(400)])
    assert finops.fetch_costs("t", SUB, NOW) == ("unavailable", [])
    script(monkeypatch, [FakeResponse(500)] * finops.MAX_ATTEMPTS)
    with pytest.raises(RuntimeError):
        finops.fetch_costs("t", SUB, NOW)


def test_fetch_budgets_status(monkeypatch):
    script(monkeypatch, [FakeResponse(200, {"value": [{"name": "b", "properties": {"amount": 10}}]})])
    status, budgets = finops.fetch_budgets("t", SUB)
    assert status == "ok" and budgets[0]["name"] == "b"
    script(monkeypatch, [FakeResponse(401)])
    assert finops.fetch_budgets("t", SUB) == ("denied", [])


# --- arithmetic -----------------------------------------------------------------------------------------

def test_months_totals_and_the_month_in_progress():
    totals = finops.monthly_totals([row("2026-09", "a", 1), row("2026-08", "a", 2), row("2026-09", "b", 3)])
    assert totals == {"2026-08": 2.0, "2026-09": 4.0}
    assert finops.complete_months(["2026-08", "2026-09", "2026-10"], NOW) == ["2026-08", "2026-09"]


def test_forecast_continues_the_recent_trend_and_never_goes_negative():
    totals = {"m1": 100.0, "m2": 120.0, "m3": 140.0}
    assert finops.forecast_next(totals, ["m1", "m2", "m3"]) == 160.0
    assert finops.forecast_next({"a": 100.0, "b": 10.0}, ["a", "b"]) == 0.0
    assert finops.forecast_next({"a": 100.0}, ["a"]) is None


# --- evaluation -----------------------------------------------------------------------------------------

def result(rows=None, budgets=None, cost="ok", budget_status="ok"):
    return {"costStatus": cost, "rows": rows or [], "budgetStatus": budget_status, "budgets": budgets or []}


def by_rule(stats, rule):
    return {s["subscriptionId"]: s for s in stats if s["ruleId"] == rule}


def test_budget_checks():
    results = {SUB: result(budgets=[]),
               SUB2: result(budgets=[budget("full", 100, 120, 130, SUB2), budget("risky", 100, 60, 150, SUB2), budget("fine", 100, 10, 20, SUB2)])}
    findings, stats, dataset, errors = finops.evaluate("r", results, NOW)

    assert (by_rule(stats, "FIN-BUD-001")[SUB]["affected"], by_rule(stats, "FIN-BUD-001")[SUB2]["affected"]) == (1, 0)
    over, forecast = by_rule(stats, "FIN-BUD-002")[SUB2], by_rule(stats, "FIN-BUD-003")[SUB2]
    assert (over["affected"], over["applicable"]) == (1, 3) and (forecast["affected"], forecast["applicable"]) == (1, 3)
    titles = sorted(f["title"] for f in findings)
    assert "Subscription has no budget" in titles
    assert any("'full' is exhausted" in t for t in titles) and any("'risky' is forecast" in t for t in titles)
    assert dataset["budgets"][0]["name"] == "full"  # most used first
    assert all(f["source"] == "finops" and f["pillar"] == "Cost Optimization" for f in findings)


def test_unreadable_budgets_do_not_create_findings():
    findings, stats, dataset, errors = finops.evaluate("r", {SUB: result(budget_status="denied")}, NOW)
    assert not by_rule(stats, "FIN-BUD-001") and findings == []


def test_spend_spike_needs_both_a_percentage_and_a_minimum_increase():
    spike = [row("2026-08", "a", 100), row("2026-09", "a", 300), row("2026-10", "a", 5)]
    small = [row("2026-08", "a", 10), row("2026-09", "a", 30)]  # +200% but only 20
    findings, stats, _, _ = finops.evaluate("r", {SUB: result(spike), SUB2: result(small)}, NOW)
    rows = by_rule(stats, "FIN-COST-001")
    assert rows[SUB]["affected"] == 1 and rows[SUB2]["affected"] == 0
    assert "grew 200%" in next(f["title"] for f in findings if f["ruleId"] == "FIN-COST-001")
    # a single complete month cannot be compared
    assert not by_rule(finops.evaluate("r", {SUB: result([row("2026-09", "a", 5)])}, NOW)[1], "FIN-COST-001")


def test_dataset_summarizes_months_services_and_coverage():
    rows = [row("2026-07", "Storage", 100), row("2026-08", "Storage", 120), row("2026-08", "SQL", 30),
            row("2026-09", "Storage", 150), row("2026-09", "SQL", 50), row("2026-10", "Storage", 20)]
    results = {SUB: result(rows), SUB2: result(cost="denied", budget_status="denied")}
    _, _, dataset, errors = finops.evaluate("r", results, NOW)

    assert dataset["lastMonth"] == "2026-09" and dataset["lastMonthCost"] == 200.0
    assert dataset["monthOverMonthPercent"] == pytest.approx(33.3, abs=0.1)  # 200 vs 150
    assert dataset["months"][-1] == {"month": "2026-10", "cost": 20.0, "partial": True, "effective": None}
    assert dataset["months"][0]["partial"] is False
    assert dataset["topServices"][0] == {"service": "Storage", "cost": 150.0}
    assert dataset["forecastNextMonth"] == pytest.approx(250.0, abs=0.01)  # 100 -> 150 -> 200: average +50
    assert dataset["currency"] == "USD" and dataset["coverage"]["ok"] == 1 and dataset["coverage"]["denied"] == 1
    assert errors[0]["ruleId"] == "finops-permission" and "Cost Management Reader" in errors[0]["error"]


def test_evaluate_without_any_data():
    findings, stats, dataset, errors = finops.evaluate("r", {}, NOW)
    assert findings == [] and dataset["months"] == [] and dataset["lastMonthCost"] is None and errors == []


# --- collection -----------------------------------------------------------------------------------------

class Credential:
    def get_token(self, scope):
        assert scope == finops.SCOPE
        return type("T", (), {"token": "t"})()


def test_collect_reads_every_subscription_and_isolates_failures(monkeypatch):
    def fake_costs(token, sub, now):
        if sub == SUB2:
            raise RuntimeError("boom")
        return "ok", [row("2026-08", "a", 10), row("2026-09", "a", 20)]

    monkeypatch.setattr(finops, "fetch_costs", fake_costs)
    monkeypatch.setattr(finops, "fetch_budgets", lambda token, sub: ("ok", []))
    findings, stats, dataset, errors = finops.collect(Credential(), "r", [SUB.upper(), SUB2], NOW)
    assert dataset["coverage"] == {"ok": 1, "denied": 0, "unavailable": 0, "error": 1}
    assert errors[0]["ruleId"] == "finops-error"
    assert SUB in by_rule(stats, "FIN-BUD-001")  # subscription ids are normalised


def test_collect_stops_starting_work_after_the_time_budget(monkeypatch):
    calls = []
    monkeypatch.setattr(finops, "fetch_costs", lambda token, sub, now: calls.append(sub) or ("ok", []))
    monkeypatch.setattr(finops, "fetch_budgets", lambda token, sub: ("ok", []))
    clock = iter([0.0] + [finops.TIME_BUDGET_SECONDS + 1] * 10)
    monkeypatch.setattr(finops, "_now", lambda: next(clock))
    _, _, dataset, errors = finops.collect(Credential(), "r", [SUB, SUB2], NOW)
    assert calls == [] and dataset["coverage"]["error"] == 2


# --- chart and page -------------------------------------------------------------------------------------

def test_nice_ceiling():
    assert [cost_view._nice_ceiling(v) for v in (0, 7, 130, 460, 2400)] == [1.0, 10, 200, 500, 2500]


def test_chart_scales_bars_to_the_largest_month():
    geometry = cost_view.chart([{"month": "2026-08", "cost": 100.0, "partial": False},
                                {"month": "2026-09", "cost": 50.0, "partial": True}])
    first, second = geometry["bars"]
    assert first["height"] == pytest.approx(second["height"] * 2, rel=0.01)
    assert second["partial"] and not first["partial"] and first["x"] < second["x"]
    assert geometry["grid"][0]["label"] == "0" and cost_view.chart([])["bars"] == []


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, summary):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: summary)


FINOPS = {"currency": "USD", "lastMonth": "2026-09", "lastMonthCost": 1234.0, "monthOverMonthPercent": 12.5,
          "forecastNextMonth": 1500.0,
          "months": [{"month": "2026-08", "cost": 1000.0, "partial": False}, {"month": "2026-09", "cost": 1234.0, "partial": False},
                     {"month": "2026-10", "cost": 300.0, "partial": True}],
          "topServices": [{"service": "<b>Storage</b>", "cost": 900.0}],
          "bySubscription": [{"subscriptionId": SUB, "last": 1234.0, "previous": 1000.0}],
          "budgets": [{"name": "Team", "amount": 3000.0, "spent": 472.0, "forecast": 1001.0, "timeGrain": "Monthly",
                       "currency": "USD", "percent": 15.7, "subscriptionId": SUB}],
          "coverage": {"ok": 1, "denied": 1, "unavailable": 0, "error": 0}}


def test_cost_page_shows_effective_cost_daily_chart_and_anomalies(client, monkeypatch):
    finops = dict(FINOPS, lastMonthEffective=1180.0, scope="tenant",
                  daily=[{"date": f"2026-09-{d:02d}", "cost": 40.0} for d in range(1, 21)],
                  anomalies=[{"date": "2026-09-14", "cost": 300.0, "expected": 40.0, "percent": 650.0}])
    serve(monkeypatch, {"runId": "r1", "finops": finops, "advisorSavings": {"USD": 3804.0}})
    html = client.get("/cost").get_data(as_text=True)
    assert "billed cost" in html and "effective cost" in html and "1,180" in html
    assert "Daily spend" in html and "2026-09-14" in html and "+650%" in html and "Read once at the tenant scope" in html
    assert html.count('<svg class="chart"') == 2


def test_cost_page_lists_reservation_and_savings_plan_options(client, monkeypatch):
    commitments = {"totals": {"USD": {"P1Y": 900.0, "P3Y": 1200.0}},
                   "items": [{"subscriptionName": "<One>", "resourceType": "virtualmachines", "currency": "USD",
                              "terms": {"P1Y": 400.0, "P3Y": 689.0}}]}
    serve(monkeypatch, {"runId": "r1", "finops": FINOPS, "commitments": commitments})
    html = client.get("/cost").get_data(as_text=True)
    assert "Rate optimization" in html and "689 USD" in html and "not added together" in html
    assert "<strong>900</strong> USD per year with 1 year" in html and "&lt;One&gt;" in html

def test_cost_page_renders_and_escapes(client, monkeypatch):
    serve(monkeypatch, {"runId": "r1", "finops": FINOPS, "advisorSavings": {"USD": 3804.0}})
    html = client.get("/cost").get_data(as_text=True)
    assert "1,234" in html and "+12.5%" in html and "1,500" in html and "3,804" in html
    assert '<rect class="bar partial"' in html and "<progress" in html and "Team" in html
    assert "<b>Storage</b>" not in html and "&lt;b&gt;Storage&lt;/b&gt;" in html
    assert "1 need the Cost Management Reader role" in html
    assert "style=" not in html


def test_cost_page_explains_a_missing_role_and_handles_errors(client, monkeypatch):
    serve(monkeypatch, {"runId": "r1", "finops": {"months": [], "coverage": {"ok": 0, "denied": 3, "unavailable": 0, "error": 0}}})
    assert "not readable for 3 subscription" in client.get("/cost").get_data(as_text=True)
    serve(monkeypatch, {"runId": "r1"})
    assert b"needs the" in client.get("/cost").data

    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: (_ for _ in ()).throw(RuntimeError("secret detail")))
    response = client.get("/cost")
    assert response.status_code == 503 and b"secret detail" not in response.data


# --- FinOps hub methodology: effective cost, anomalies and tenant scope ----------------------------------

def daily(*costs, start="2026-09-01"):
    first = datetime.fromisoformat(start)
    return [{"date": (first.replace(day=1) + __import__("datetime").timedelta(days=i)).strftime("%Y-%m-%d"), "cost": c}
            for i, c in enumerate(costs)]


def test_parse_daily_accepts_both_date_formats_and_groups_nothing():
    properties = {"columns": [{"name": "Cost"}, {"name": "UsageDate"}, {"name": "Currency"}],
                  "rows": [[1.5, 20260901, "USD"], [2.0, "2026-09-02T00:00:00", "USD"], [0.5, 20260901, "USD"]]}
    assert finops.parse_daily(properties) == [{"date": "2026-09-01", "cost": 2.0}, {"date": "2026-09-02", "cost": 2.0}]
    assert finops.parse_daily({"columns": [{"name": "Cost"}], "rows": [[1]]}) == []
    assert finops.parse_daily({}) == []


def test_query_body_supports_amortized_cost_daily_ranges_and_groupings():
    body = finops.query_body(NOW, kind="AmortizedCost", grouping=None)
    assert body["type"] == "AmortizedCost" and "grouping" not in body["dataset"]
    body = finops.query_body(NOW, granularity="Daily", grouping=None, days=60)
    assert body["dataset"]["granularity"] == "Daily" and body["timePeriod"]["from"] == "2026-08-16T00:00:00Z"
    grouped = finops.query_body(NOW, grouping=("SubscriptionId", "ServiceName"))
    assert [g["name"] for g in grouped["dataset"]["grouping"]] == ["SubscriptionId", "ServiceName"]


def test_parse_costs_keeps_the_subscription_of_tenant_wide_queries():
    properties = {"columns": [{"name": "Cost"}, {"name": "BillingMonth"}, {"name": "SubscriptionId"}, {"name": "ServiceName"}],
                  "rows": [[5.0, "2026-09-01T00:00:00", "ABC", "SQL"]]}
    assert finops.parse_costs(properties) == [{"month": "2026-09", "service": "SQL", "cost": 5.0, "currency": "", "subscriptionId": "abc"}]


def test_detect_anomalies_flags_only_clear_spikes():
    steady = [100.0, 102.0, 98.0, 101.0, 99.0, 100.0, 103.0, 97.0, 100.0, 101.0, 99.0, 100.0, 102.0, 98.0, 100.0]
    assert finops.detect_anomalies(daily(*steady)) == []
    found = finops.detect_anomalies(daily(*(steady + [400.0, 100.0])))
    assert len(found) == 1 and found[0]["cost"] == 400.0 and found[0]["expected"] == 100.0 and found[0]["percent"] == 300.0


def test_a_lasting_rise_in_spend_is_not_an_anomaly():
    # 20 days at ~30, then a permanent step to ~45: the old level must not make every later day look unusual.
    level_shift = [30.0, 31.0, 29.0, 30.0, 32.0] * 4 + [45.0, 44.0, 46.0, 45.0, 47.0, 45.0, 44.0, 46.0, 45.0, 45.0] * 2
    found = finops.detect_anomalies(daily(*level_shift))
    assert [a["date"] for a in found] == ["2026-09-21"]  # only the day the spend jumped, not every day after it


def test_detect_anomalies_ignores_small_gaps_short_series_and_drops():
    assert finops.detect_anomalies(daily(*([100.0] * 14 + [120.0]))) == []  # +20% is below the minimum gap
    assert finops.detect_anomalies(daily(*([100.0] * 5 + [900.0]))) == []  # not enough history to compare
    assert finops.detect_anomalies(daily(*([100.0] * 14 + [1.0]))) == []  # cheaper days are not anomalies
    assert finops.detect_anomalies(daily(*[0.0] * 20)) == []


def test_perfectly_flat_history_still_detects_a_spike():
    found = finops.detect_anomalies(daily(*([50.0] * 20 + [500.0])))
    assert len(found) == 1 and found[0]["cost"] == 500.0

def test_effective_cost_and_daily_series_are_summed_when_every_subscription_was_read():
    results = {SUB: {**result([row("2026-09", "a", 100)]), "effective": {"2026-09": 90.0}, "daily": daily(10, 10)},
               SUB2: {**result([row("2026-09", "a", 50)]), "effective": {"2026-09": 55.0}, "daily": daily(5, 5)}}
    _, _, dataset, _ = finops.evaluate("r", results, NOW)
    assert dataset["months"][0]["effective"] == 145.0 and dataset["lastMonthEffective"] == 145.0
    assert [p["cost"] for p in dataset["daily"]] == [15.0, 15.0]


def test_partial_coverage_does_not_show_incomplete_tenant_totals():
    results = {SUB: {**result([row("2026-09", "a", 100)]), "effective": {"2026-09": 90.0}, "daily": daily(10)},
               SUB2: result(cost="denied")}
    _, _, dataset, _ = finops.evaluate("r", results, NOW)
    assert dataset["months"][0]["effective"] is None and dataset["daily"] == []


def test_recent_anomalies_become_a_cost_finding_and_old_ones_do_not():
    series = [100.0] * 60
    series[-3] = 600.0   # two days before "today"
    series[20] = 700.0   # long ago
    start = NOW - __import__("datetime").timedelta(days=60)
    points = [{"date": (start + __import__("datetime").timedelta(days=i)).strftime("%Y-%m-%d"), "cost": c} for i, c in enumerate(series)]
    findings, stats, dataset, _ = finops.evaluate("r", {}, NOW, tenant={"daily": points, "effective": {}}, mode="tenant")
    row = next(s for s in stats if s["ruleId"] == "FIN-COST-002")
    assert row["subscriptionId"] == "tenant" and (row["affected"], row["applicable"]) == (1, finops.ANOMALY_RECENT_DAYS)
    titles = [f["title"] for f in findings if f["ruleId"] == "FIN-COST-002"]
    assert len(titles) == 1 and "500% above" in titles[0] and titles[0].endswith("(600 against 100)")
    assert len(dataset["anomalies"]) == 2 and dataset["scope"] == "tenant"


def test_collect_uses_the_tenant_scope_when_it_works(monkeypatch):
    monkeypatch.setenv("COLLECTOR_TENANT_ID", "tenant-1")
    calls = []
    tenant_rows = [dict(row("2026-09", "SQL", 30), subscriptionId=SUB), dict(row("2026-09", "SQL", 20), subscriptionId=SUB2)]
    monkeypatch.setattr(finops, "fetch_tenant_costs", lambda token, tenant, now: ("ok", tenant_rows))
    monkeypatch.setattr(finops, "fetch_effective", lambda token, scope, now: calls.append(scope) or ("ok", {"2026-09": 48.0}))
    monkeypatch.setattr(finops, "fetch_daily", lambda token, scope, now: ("ok", daily(1, 2)))
    monkeypatch.setattr(finops, "fetch_costs", lambda *a: (_ for _ in ()).throw(AssertionError("must not query per subscription")))
    monkeypatch.setattr(finops, "fetch_budgets", lambda token, sub: ("ok", []))
    _, _, dataset, _ = finops.collect(Credential(), "r", [SUB, SUB2], NOW)
    assert dataset["scope"] == "tenant" and dataset["months"][0]["cost"] == 50.0 and dataset["months"][0]["effective"] == 48.0
    assert calls == ["/providers/Microsoft.Management/managementGroups/tenant-1"]


def test_collect_falls_back_to_subscriptions_when_the_tenant_scope_is_not_valid(monkeypatch):
    monkeypatch.setenv("COLLECTOR_TENANT_ID", "tenant-1")
    monkeypatch.setattr(finops, "fetch_tenant_costs", lambda token, tenant, now: ("unavailable", []))
    monkeypatch.setattr(finops, "fetch_costs", lambda token, sub, now: ("ok", [row("2026-09", "a", 10)]))
    monkeypatch.setattr(finops, "fetch_effective", lambda token, scope, now: ("ok", {"2026-09": 9.0}))
    monkeypatch.setattr(finops, "fetch_daily", lambda token, scope, now: ("ok", daily(1, 1)))
    monkeypatch.setattr(finops, "fetch_budgets", lambda token, sub: ("ok", []))
    _, _, dataset, _ = finops.collect(Credential(), "r", [SUB], NOW)
    assert dataset["scope"] == "subscriptions" and dataset["lastMonthEffective"] == 9.0
    assert dataset["months"][0]["effective"] == 9.0