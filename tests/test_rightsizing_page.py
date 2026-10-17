import pytest

import app as dashboard_app
import data

SUB = "11111111-1111-1111-1111-111111111111"

METRICS = {
    "lookbackDays": 30,
    "measured": {"vm": 4, "plan": 1},
    "distribution": {"vm": {"idle": 2, "under": 1, "right": 1, "saturated": 0, "nodata": 3},
                     "plan": {"idle": 0, "under": 1, "right": 0, "saturated": 0, "nodata": 0},
                     "sql_dtu": {"idle": 0, "under": 0, "right": 0, "saturated": 0, "nodata": 0}},
    "resources": [
        {"kind": "vm", "id": "/s/vm1", "name": "<b>vm1</b>", "subscriptionId": SUB, "resourceGroup": "rg1", "detail": "Standard_D8as_v5",
         "avg": 3.9, "max": 80.5, "assessment": "idle"},
        {"kind": "vm", "id": "/s/vm2", "name": "vm2", "subscriptionId": SUB, "resourceGroup": "rg2", "detail": "Standard_D2s_v3",
         "avg": 12.0, "max": 30.0, "assessment": "under"},
        {"kind": "vm", "id": "/s/vm3", "name": "vm3", "subscriptionId": SUB, "resourceGroup": "rg2", "detail": "Standard_B2s",
         "avg": 40.0, "max": 60.0, "assessment": "right"},
        {"kind": "plan", "id": "/s/plan", "name": "plan1", "subscriptionId": SUB, "resourceGroup": "rg1", "detail": "B1 x1",
         "avg": 10.0, "max": 20.0, "memory": 55.0, "assessment": "under"},
    ],
}


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, summary):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: summary)
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])


def page(client, query=""):
    return client.get("/rightsizing" + query).get_data(as_text=True)


def test_rightsizing_charts_link_to_the_resource_lists(client, monkeypatch):
    serve(monkeypatch, {"runId": "r1", "metrics": METRICS, "subscriptions": [{"id": SUB, "name": "Prod"}]})
    html = page(client)
    assert "Virtual machines by utilization" in html and "App Service plans by utilization" in html
    assert "SQL databases by utilization" not in html  # nothing measured, so no chart
    assert 'href="/rightsizing?kind=vm&amp;assessment=idle#resources"' in html
    assert "Idle (under 5% CPU)" in html and "Underutilized (under 15%)" in html and "3 without metrics" in html
    assert 'class="bar as-idle"' in html and 'class="bar as-under"' in html


def test_rightsizing_table_shows_size_cpu_and_assessment_and_escapes(client, monkeypatch):
    serve(monkeypatch, {"runId": "r1", "metrics": METRICS, "subscriptions": [{"id": SUB, "name": "Prod"}]})
    html = page(client, "?kind=vm")
    assert "Standard_D8as_v5" in html and "3.9" in html and "80.5" in html and "Prod" in html and "rg1" in html
    assert "<b>vm1</b>" not in html and "&lt;b&gt;vm1&lt;/b&gt;" in html
    assert "Avg CPU %" in html and "Max %" in html and 'data-filter-table="rs"' in html


def test_rightsizing_filters_by_assessment_and_ignores_bad_input(client, monkeypatch):
    serve(monkeypatch, {"runId": "r1", "metrics": METRICS})
    html = page(client, "?kind=vm&assessment=under")
    assert "vm2" in html and "vm3" not in html and "&lt;b&gt;vm1" not in html
    assert "vm1" in page(client, "?kind=nope&assessment=nope&subscription=%27%20OR%201%3D1")  # falls back to the default view
    assert "plan1" in page(client, "?kind=plan") and "Avg memory %" in page(client, "?kind=plan")


def test_rightsizing_without_metrics_or_data_store(client, monkeypatch):
    serve(monkeypatch, {"runId": "r1"})
    assert "No utilization data yet" in page(client)
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: (_ for _ in ()).throw(RuntimeError("secret")))
    response = client.get("/rightsizing")
    assert response.status_code == 503 and b"secret" not in response.data


def test_security_page_shows_defender_coverage_and_secure_score_controls(client, monkeypatch):
    summary = {"runId": "r1", "subscriptions": [{"id": SUB, "name": "Prod"}],
               "governance": {"defender": {"plans": 3, "enabled": 1, "notEnabled": ["SqlServers"], "detail": [
                   {"plan": "VirtualMachines", "tier": "Standard", "subPlan": "P2", "subscriptionId": SUB},
                   {"plan": "<i>SqlServers</i>", "tier": "Free", "subPlan": "", "subscriptionId": SUB}]}},
               "secureScore": {"average": 60, "subscriptions": [], "topControls": [
                   {"control": "Enable MFA", "unhealthy": 3, "healthy": 1}]}}
    serve(monkeypatch, summary)
    html = client.get("/pillar/security").get_data(as_text=True)
    assert "Defender for Cloud coverage" in html and "1 of 3 plan(s)" in html and "VirtualMachines" in html and "P2" in html
    assert "&lt;i&gt;SqlServers&lt;/i&gt;" in html and "Prod" in html and "Standard (threat protection on)" in html
    assert "Secure Score controls" in html and "Enable MFA" in html and "25%" in html


def test_overview_lists_what_each_source_could_read(client, monkeypatch):
    summary = {"runId": "r1", "completedUtc": "t", "subscriptionCount": 1, "resourceCount": 5, "findingCount": 0, "scores": {},
               "sources": {"builtin": {"rules": 20, "findings": 4}, "checklist": {"rules": 41, "findings": 2}},
               "errors": [{"ruleId": "CHK-1", "error": "bad"}],
               "keyvault": {"vaults": 2, "readable": 1, "denied": 1},
               "entra": {"available": {"apps": True, "guests": False, "incidents": False}},
               "finops": {"months": [{"month": "2026-09"}], "coverage": {"ok": 1, "denied": 1, "error": 0}},
               "subscriptions": []}
    serve(monkeypatch, summary)
    html = client.get("/").get_data(as_text=True)
    assert "Data source coverage" in html and "1 check(s) could not run" in html
    assert "1 vault(s) could not be listed" in html and "Needs Graph permissions for guest users, Defender XDR incidents" in html
    assert "1 subscription(s) need the Cost Management Reader role" in html
    assert 'class="chip as-saturated">No access' not in html  # Cost Management is partial, not missing
    assert 'class="chip as-under">Partial' in html and 'class="chip as-right">Available' in html

def test_rightsizing_opens_the_first_type_that_has_data(client, monkeypatch):
    metrics = {"lookbackDays": 30, "distribution": {"plan": {"idle": 0, "under": 1, "right": 0, "saturated": 0, "nodata": 0}},
               "resources": [{"kind": "plan", "id": "/s/p", "name": "only-plan", "subscriptionId": SUB, "resourceGroup": "rg",
                              "detail": "B1 x1", "avg": 5.0, "assessment": "under"}]}
    serve(monkeypatch, {"runId": "r1", "metrics": metrics})
    html = page(client)
    assert "only-plan" in html and "<h3>App Service plans</h3>" in html
