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
    assert dataset["months"][-1] == {"month": "2026-10", "cost": 20.0, "partial": True}
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
