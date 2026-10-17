import pytest

import app as dashboard_app
import data


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


FINOPS = {"currency": "USD", "lastMonth": "2026-09", "lastMonthCost": 1234.0, "monthOverMonthPercent": 12.5,
          "forecastNextMonth": 1500.0,
          "months": [{"month": "2026-08", "cost": 1000.0, "partial": False}, {"month": "2026-09", "cost": 1234.0, "partial": False},
                     {"month": "2026-10", "cost": 300.0, "partial": True}],
          "bySubscription": [], "budgets": [], "coverage": {"ok": 1, "denied": 0, "unavailable": 0, "error": 0}}

BREAKDOWNS = {
    "byService": {"series": ["<b>Storage</b>", "Other"], "periods": ["2026-08", "2026-09"],
                  "values": {"<b>Storage</b>": {"2026-08": 100.0, "2026-09": 150.0}, "Other": {"2026-08": 10.0, "2026-09": 5.0}}},
    "byLocation": {"series": ["east"], "periods": ["2026-09"], "values": {"east": {"2026-09": 9.0}}},
    "byPricingModel": {"series": ["OnDemand", "Reservation"], "periods": ["2026-09"],
                       "values": {"OnDemand": {"2026-09": 60.0}, "Reservation": {"2026-09": 40.0}}},
    "commitmentCoverage": {"lastMonth": {"month": "2026-09", "percent": 40.0, "committed": 40.0}},
    "dailyByService": {"series": ["A"], "periods": ["2026-09-01", "2026-09-02"],
                       "values": {"A": {"2026-09-01": 3.0, "2026-09-02": 4.0}}},
    "topResources": [{"id": "/s/db", "name": "<i>db</i>", "cost": 99.0}],
    "partial": True,
}


def serve(monkeypatch, finops, findings=()):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: {"runId": "r1", "finops": finops})
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: list(findings))


def test_cost_page_draws_the_breakdowns_like_the_hub_dashboard(client, monkeypatch):
    serve(monkeypatch, dict(FINOPS, breakdowns=BREAKDOWNS))
    html = client.get("/pillar/cost").get_data(as_text=True)
    assert "Trends by dimension" in html and "By service" in html and "By region" in html
    assert "By resource group" not in html  # only what was read is drawn
    assert "<b>Storage</b>" not in html and "&lt;b&gt;Storage&lt;/b&gt;" in html and "+50%" in html
    assert "Cost by pricing model" in html and "40.0% of last month" in html and "Covered by commitments" in html
    assert "Most expensive resources" in html and "&lt;i&gt;db&lt;/i&gt;" in html
    assert "Some scopes could not be read in time" in html and 'href="#trends"' in html
    assert 'class="col-0"' in html and 'class="col-other"' in html and "style=" not in html


def test_cost_page_without_breakdowns_keeps_the_totals(client, monkeypatch):
    serve(monkeypatch, FINOPS)
    html = client.get("/pillar/cost").get_data(as_text=True)
    assert "Monthly spend" in html and "Trends by dimension" not in html and 'href="#trends"' not in html


def test_cost_page_lists_hybrid_benefit_rules(client, monkeypatch):
    finding = {"id": "1", "ruleId": "COST-AHB-001", "severity": "low", "pillar": "Cost Optimization", "title": "Windows VM",
               "source": "builtin", "resourceId": "/s/vm", "resourceName": "vm", "subscriptionId": "s1"}
    serve(monkeypatch, FINOPS, [finding])
    html = client.get("/pillar/cost").get_data(as_text=True)
    assert "Azure Hybrid Benefit" in html and 'href="/rule/COST-AHB-001"' in html
