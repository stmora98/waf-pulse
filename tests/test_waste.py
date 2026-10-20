import json

import pytest

import app as dashboard_app
import data
import waste

SUB = "11111111-1111-1111-1111-111111111111"


def rid(kind, name):
    return f"/subscriptions/{SUB}/resourceGroups/rg/providers/{kind}/{name}"


def finding(rule, name, kind="Microsoft.Compute/disks", pillar="Cost Optimization", severity="medium", title=None):
    return {"ruleId": rule, "resourceId": rid(kind, name), "subscriptionId": SUB, "resourceName": name, "resourceType": kind.lower(), "title": title or f"Title {rule}",
            "severity": severity, "pillar": pillar, "source": "builtin", "recommendation": "x"}


FINDINGS = [finding("COST-DISK-001", "d1"), finding("COST-DISK-001", "d2"), finding("COST-DISK-001", "d3"), finding("COST-IP-001", "ip1", "Microsoft.Network/publicIPAddresses"),
            finding("MET-VM-001", "vm1", "Microsoft.Compute/virtualMachines"), finding("COST-AHB-001", "vm2", "Microsoft.Compute/virtualMachines"), finding("SEC-X", "s", pillar="Security")]
COSTS = [{"id": rid("Microsoft.Compute/disks", "d1").lower(), "cost": 40.0}, {"id": rid("Microsoft.Compute/disks", "d2").lower(), "cost": 10.5},
         {"id": rid("Microsoft.Network/publicIPAddresses", "ip1").lower(), "cost": 3.65}, {"id": rid("Microsoft.Compute/virtualMachines", "vm1").lower(), "cost": 200.0},
         {"id": rid("Microsoft.Compute/virtualMachines", "vm2").lower(), "cost": 999.0}]


def test_savings_add_up_what_the_removable_resources_cost():
    result = waste.savings(FINDINGS, COSTS)
    assert [(r["ruleId"], r["resources"], r["costed"], r["saves"]) for r in result["rules"]] == [("MET-VM-001", 1, 1, 200.0), ("COST-DISK-001", 3, 2, 50.5), ("COST-IP-001", 1, 1, 3.65)]
    assert result["total"] == 254.15 and result["resources"] == 5 and result["costed"] == 4
    assert result["by_rule"] == {"MET-VM-001": 200.0, "COST-DISK-001": 50.5, "COST-IP-001": 3.65}  # licensing and security rules are not "remove" rules
    assert [t["name"] for t in result["rules"][1]["top"]] == ["d1", "d2"] and result["rules"][1]["top"][0]["cost"] == 40.0
    assert waste.savings([], COSTS)["rules"] == [] and waste.savings(FINDINGS, [])["total"] == 0


def test_a_resource_with_several_findings_of_one_rule_counts_once():
    twice = [finding("COST-DISK-001", "d1"), finding("COST-DISK-001", "D1")]
    assert waste.savings(twice, COSTS)["rules"][0]["resources"] == 1 and waste.savings(twice, COSTS)["total"] == 40.0


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, costs=COSTS, finops=None):
    summary = {"runId": "r1", "scores": {}, "subscriptions": [{"id": SUB, "name": "Prod", "resourceCount": 5, "scores": {}}], "counts": {}, "severityTotals": {},
               "finops": finops or {"currency": "USD", "months": []}}
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: json.loads(json.dumps(summary)))
    monkeypatch.setattr(data, "all_findings", lambda run_id, pillar=None, *a, **k: [f for f in FINDINGS if not pillar or f["pillar"] == pillar])
    monkeypatch.setattr(data, "resources", lambda run_id: ([], False))
    monkeypatch.setattr(data, "get_setting", lambda name: None)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: list(costs) if kind == "costs" else [])
    monkeypatch.setattr(data, "history", lambda limit=30: [])


def test_cost_page_lists_the_waste(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/pillar/cost").get_data(as_text=True)
    assert 'id="waste"' in html and "Waste you can remove" in html and ">254<" in html and "Shut down or delete the idle virtual machines" in html and "4 of the 5 resource(s)" in html
    assert html.index("Shut down or delete") < html.index("Delete the public IP addresses")


def test_action_items_show_what_each_recommendation_saves(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/actions").get_data(as_text=True)
    assert "Saves (30 d)" in html and "<strong>200</strong>" in html and "<strong>50</strong>" in html
    serve(monkeypatch, costs=[])
    assert "Saves (30 d)" not in client.get("/actions").get_data(as_text=True)


def test_the_cost_page_without_waste_has_no_panel(client, monkeypatch):
    serve(monkeypatch, costs=[{"id": "/other", "cost": 5.0}])
    html = client.get("/pillar/cost").get_data(as_text=True)
    assert 'id="waste"' in html and ">0<" in html  # the findings exist but none has a known cost
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])
    assert 'id="waste"' not in client.get("/pillar/cost").get_data(as_text=True)


def test_commitment_utilization_panel(client, monkeypatch):
    months = [{"month": "2026-09", "cost": 100.0, "partial": False, "effective": None}, {"month": "2026-08", "cost": 90.0, "partial": False, "effective": None}]
    finops = {"currency": "USD", "months": months, "lastMonth": "2026-09", "lastMonthCost": 100.0, "coverage": {"ok": 1}, "monthOverMonthPercent": None, "forecastNextMonth": None, "topServices": [], "bySubscription": [], "budgets": [], "daily": [], "anomalies": [], "breakdowns": {"commitmentUtilization": [
        {"name": "ri-vms", "kind": "reservation", "month": "2026-09", "used": 400, "unused": 600, "percent": 40.0, "currency": "USD"},
        {"name": "sp-a", "kind": "savingsplan", "month": "2026-09", "used": 950, "unused": 50, "percent": 95.0, "currency": "USD"}]}}
    serve(monkeypatch, finops=finops)
    html = client.get("/pillar/cost").get_data(as_text=True)
    assert "Utilization of the reservations and savings plans you bought" in html and "ri-vms" in html and "40.0%" in html and "as-saturated" in html and "Savings plan" in html
