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


def serve(monkeypatch, summary, rows=None):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: summary)
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: (rows or {}).get(kind, []))


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
    assert "Avg CPU %" in html and "Max %" in html


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

# ---- advice, cost, filters and CSV

ADVICE = [
    {"id": "/s/vm1", "name": "<b>vm1</b>", "subscriptionId": SUB, "type": "microsoft.compute/virtualmachines", "action": "Resize",
     "targetSku": "Standard_D4as_v5", "currentSku": "Standard_D8as_v5", "monthlySavings": 120.5, "currency": "USD", "cpuP95": 8, "memoryP95": 20, "networkP95": 1},
    {"id": "/subscriptions/" + SUB + "/resourcegroups/rg9/providers/microsoft.compute/virtualmachines/stopped", "name": "stopped", "subscriptionId": SUB,
     "type": "microsoft.compute/virtualmachines", "action": "Shutdown", "targetSku": "", "currentSku": "Standard_D2s_v3", "monthlySavings": 20,
     "currency": "USD", "cpuP95": 0, "memoryP95": None, "networkP95": None},
]
COSTS = [{"id": "/s/vm1", "cost": 300.0}, {"id": "/s/vm2", "cost": 55.0}]


def serve_all(monkeypatch):
    serve(monkeypatch, {"runId": "r1", "metrics": METRICS, "subscriptions": [{"id": SUB, "name": "Prod"}]}, {"advice": ADVICE, "costs": COSTS})


def test_rightsizing_shows_cost_advice_and_resources_only_advisor_knows(client, monkeypatch):
    serve_all(monkeypatch)
    html = page(client, "?kind=vm")
    assert "Cost (30 d)" in html and ">300<" in html and "→ Standard_D4as_v5" in html and "saves 120" in html
    assert "P95 CPU 8%" in html and "stopped" in html and "Shut down" in html and "from Advisor, no metrics" in html
    assert "<b>vm1</b>" not in html


def test_rightsizing_headline_numbers(client, monkeypatch):
    serve_all(monkeypatch)
    html = page(client)
    assert "Advisor savings" in html and ">140<" in html and "2 recommendation(s)" in html and "Spent on them" in html and ">355<" in html


def test_rightsizing_filter_by_advisor_and_name_and_sort(client, monkeypatch):
    serve_all(monkeypatch)
    with_advice = page(client, "?kind=vm&advice=with")
    assert "stopped" in with_advice and "vm3" not in with_advice
    by_name = page(client, "?kind=vm&name=vm2")
    assert "vm2" in by_name and "vm3" not in by_name
    ordered = page(client, "?kind=vm&sort=cost")
    assert ordered.index("vm2") < ordered.index("vm3")


def test_rightsizing_filter_bar_carries_the_menu(client, monkeypatch):
    serve_all(monkeypatch)
    html = page(client, "?kind=vm&assessment=idle")
    assert 'id="filterbar"' in html and "Advisor recommendation" in html and "Download CSV" in html
    assert 'class="fpill"' in html


def test_rightsizing_csv_has_the_rows_and_guards_formulas(client, monkeypatch):
    metrics = {**METRICS, "resources": [{**METRICS["resources"][0], "name": "=HYPERLINK(1)"}, METRICS["resources"][1]]}
    serve(monkeypatch, {"runId": "r1", "metrics": metrics, "subscriptions": [{"id": SUB, "name": "Prod"}]}, {"advice": ADVICE, "costs": COSTS})
    response = client.get("/rightsizing.csv?kind=vm")
    text = response.get_data(as_text=True)
    assert response.mimetype == "text/csv" and "attachment" in response.headers["Content-Disposition"]
    assert text.splitlines()[0].lstrip("\ufeff").startswith("Name,Type,Subscription")
    assert "'=HYPERLINK(1)" in text and ",=HYPERLINK" not in text and "Standard_D4as_v5" in text and "stopped" in text
    assert "Shutdown,Shutdown" not in text


def test_rightsizing_csv_without_data(client, monkeypatch):
    serve(monkeypatch, {"runId": "r1", "subscriptions": []})
    assert client.get("/rightsizing.csv").status_code == 404


def test_resources_csv(client, monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: {"runId": "r1", "subscriptions": [{"id": SUB, "name": "Prod"}]})
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])
    rows = [{"id": "/subscriptions/" + SUB + "/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/+evil", "name": "+evil",
             "type": "microsoft.compute/virtualmachines", "subscriptionId": SUB, "resourceGroup": "rg1", "location": "eastus", "detail": "x", "tags": 0}]
    monkeypatch.setattr(data, "resources", lambda run_id: (rows, False))
    response = client.get("/resources.csv?location=eastus")
    text = response.get_data(as_text=True)
    assert response.mimetype == "text/csv" and "'+evil" in text and "Prod" in text

# ---- memory, disk, network and the utilization curve

def test_trend_geometry_breaks_lines_where_a_day_has_no_data():
    import charts
    chart = charts.trend({"from": "2026-10-01", "cpu": [10, None, 30, 40], "cpuMax": [20, None, 50, 90], "mem": [50, 50, 50, 50]}, marks=[(80, "Saturated")])
    cpu = next(c for c in chart["curves"] if c["key"] == "cpu")
    assert len(cpu["lines"]) == 2 and len(cpu["dots"]) == 3 and cpu["dots"][0]["tip"] == "2026-10-01 · Average CPU 10%"
    assert [c["key"] for c in chart["curves"]] == ["cpuMax", "cpu", "mem"]
    assert chart["marks"][0]["label"] == "Saturated" and chart["ticks"][0]["label"] == "10-01"
    assert charts.trend(None) is None and charts.trend({"from": "2026-10-01", "cpu": [None, None]}) is None
    assert len(charts.trend({"from": "bad", "cpu": [5]})["curves"][0]["lines"]) == 1


def test_vm_table_shows_memory_disk_and_network_and_the_memory_bound_note(client, monkeypatch):
    vm = {**METRICS["resources"][1], "memory": 74.5, "iops": 12.3, "iopsMax": 40.1, "net": 3.2, "netMax": 9.9, "note": "memory-bound", "assessment": "right"}
    metrics = {**METRICS, "resources": [vm]}
    serve(monkeypatch, {"runId": "r1", "metrics": metrics, "subscriptions": [{"id": SUB, "name": "Prod"}]})
    html = page(client, "?kind=vm")
    assert "Memory %" in html and "Disk IOPS %" in html and "Network Mbps" in html
    assert "74.5" in html and "12.3" in html and "peak 40.1" in html and "3.2" in html and "low CPU but memory in use" in html


def test_resource_page_shows_utilization_advice_cost_and_the_curve(client, monkeypatch):
    rid = "/subscriptions/" + SUB + "/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
    vm = {**METRICS["resources"][0], "id": rid, "name": "vm1", "memory": 60.0, "vcpus": 4, "memoryGB": 16}
    summary = {"runId": "r1", "metrics": {**METRICS, "resources": [vm]}, "subscriptions": [{"id": SUB, "name": "Prod"}]}
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: summary)
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])
    monkeypatch.setattr(data, "resources", lambda run_id: ([{"id": rid, "name": "vm1", "type": "microsoft.compute/virtualmachines", "subscriptionId": SUB,
                                                              "resourceGroup": "rg1", "location": "eastus", "detail": "x", "tags": 0}], False))
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: {"advice": [{**ADVICE[0], "id": rid}], "costs": [{"id": rid.lower(), "cost": 77.0}]}[kind])
    monkeypatch.setattr(data, "series_of", lambda run_id, resource_id: {"id": rid.lower(), "from": "2026-10-01", "cpu": [4, 5, 6], "cpuMax": [30, 40, 50], "mem": [60, 61, 62]})
    html = client.get("/resource?id=" + rid).get_data(as_text=True)
    assert "Utilization and right-sizing" in html and "→ Standard_D4as_v5" in html and ">77<" in html and "60.0%" in html and "4 vCPU" in html
    assert 'class="chart trend"' in html and "curve-cpuMax" in html and "Idle" in html
