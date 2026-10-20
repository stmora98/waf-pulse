import pytest

import app as dashboard_app
import chargeback
import data
import scope

SUB_A, SUB_B = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"
RG_ROWS = [
    {"sub": SUB_A, "rg": "rg-web", "months": {"2026-08": 100.0, "2026-09": 120.0}},
    {"sub": SUB_A, "rg": "rg-data", "months": {"2026-09": 80.0}},
    {"sub": SUB_B, "rg": "<b>rg-x</b>", "months": {"2026-09": 50.0}},
]
TAG_ROWS = [
    {"key": "CostCenter", "value": "1001", "sub": SUB_A, "months": {"2026-09": 150.0}},
    {"key": "CostCenter", "value": "", "sub": SUB_A, "months": {"2026-09": 50.0}},
    {"key": "CostCenter", "value": "2002", "sub": SUB_B, "months": {"2026-09": 50.0}},
    {"key": "Owner", "value": "ana", "sub": SUB_A, "months": {"2026-09": 10.0}},
]
COSTS = [{"id": f"/subscriptions/{SUB_A}/resourceGroups/rg-web/providers/Microsoft.Compute/virtualMachines/vm1", "cost": 70.0}]
FINOPS = {"currency": "USD", "lastMonth": "2026-09", "months": [{"month": "2026-08", "cost": 1.0}, {"month": "2026-09", "cost": 2.0}], "breakdowns": {}}


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, finops=FINOPS, rows=RG_ROWS, tags=TAG_ROWS):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: {"runId": "r1", "finops": finops, "subscriptions": [{"id": SUB_A, "name": "Prod"}, {"id": SUB_B, "name": "Dev"}]})
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])
    monkeypatch.setattr(data, "resources", lambda run_id: ([], False))
    kinds = {"chargeback": rows, "tagcosts": tags, "costs": COSTS, "rulestats": []}
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: kinds.get(kind, []))


def test_pick_period():
    months = ["2026-08", "2026-09", "2026-10"]
    assert chargeback.pick_period(months, None, "2026-10") == "2026-09"
    assert chargeback.pick_period(months, "2026-08", "2026-10") == "2026-08"
    assert chargeback.pick_period(months, "all", "2026-10") == "all"
    assert chargeback.pick_period(["2026-10"], "bad", "2026-10") == "2026-10"


def test_hierarchy_totals_share_and_resources():
    resolved = scope.resolve([])
    subs = chargeback.hierarchy(RG_ROWS, resolved, {SUB_A: "Prod"}, "2026-09", COSTS)
    assert [s["name"] for s in subs] == ["Prod", SUB_B]
    assert subs[0]["total"] == 200.0 and subs[0]["share"] == 80.0
    assert [g["rg"] for g in subs[0]["groups"]] == ["rg-web", "rg-data"]
    assert subs[0]["groups"][0]["resources"][0]["name"] == "vm1"
    assert chargeback.hierarchy(RG_ROWS, resolved, {}, "all")[0]["total"] == 300.0


def test_filters_apply_to_groups():
    rows = RG_ROWS
    only_sub = scope.resolve([{"f": "sub", "op": "eq", "v": [SUB_B]}])
    assert [s["id"] for s in chargeback.hierarchy(rows, only_sub, {}, "2026-09")] == [SUB_B]
    no_web = scope.resolve([{"f": "rg", "op": "ne", "v": ["RG-WEB"]}])
    assert [g["rg"] for g in chargeback.hierarchy(rows, no_web, {}, "2026-09")[0]["groups"]] == ["rg-data"]
    assert chargeback.limited(scope.resolve([{"f": "loc", "op": "eq", "v": ["westeurope"]}]))


def test_tag_values_and_untagged_share():
    result = chargeback.tag_values(TAG_ROWS, "CostCenter", scope.resolve([]), "2026-09")
    assert result["total"] == 250.0 and result["untagged"] == 50.0 and result["untaggedPercent"] == 20.0
    assert [v["value"] for v in result["entries"]] == ["1001", chargeback.UNTAGGED, "2002"] or result["entries"][0]["value"] == "1001"
    only_a = chargeback.tag_values(TAG_ROWS, "CostCenter", scope.resolve([{"f": "sub", "op": "eq", "v": [SUB_A]}]), "2026-09")
    assert only_a["total"] == 200.0
    assert chargeback.tag_keys(TAG_ROWS) == ["CostCenter", "Owner"]


def test_page_hierarchy_escapes_and_nests(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/chargeback").get_data(as_text=True)
    assert "Prod" in html and "rg-web" in html and "&lt;b&gt;rg-x&lt;/b&gt;" in html and "<b>rg-x</b>" not in html
    assert "vm1" in html and "Subscriptions and resource groups" in html
    assert "2026-09" in html and 'href="/chargeback.csv' in html


def test_page_tag_view(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/chargeback?view=tag&key=CostCenter&month=2026-09").get_data(as_text=True)
    assert "Without this tag" in html and "20.0" in html and "(untagged)" in html and "1001" in html
    other = client.get("/chargeback?view=tag&key=nope").get_data(as_text=True)
    assert "CostCenter" in other  # unknown key falls back to the first


def test_page_without_tag_costs_explains_the_setting(client, monkeypatch):
    serve(monkeypatch, tags=[])
    html = client.get("/chargeback?view=tag").get_data(as_text=True)
    assert "COST_TAG_KEYS" in html


def test_page_without_cost_data(client, monkeypatch):
    serve(monkeypatch, finops=None)
    assert "no cost data yet" in client.get("/chargeback").get_data(as_text=True)
    assert client.get("/chargeback.csv").status_code == 404


def test_csv_downloads_guard_formulas(client, monkeypatch):
    serve(monkeypatch, rows=[{"sub": SUB_A, "rg": "=cmd", "months": {"2026-09": 5.0}}])
    body = client.get("/chargeback.csv?month=2026-09").get_data(as_text=True)
    assert "Resource group" in body and "'=cmd" in body
    tags = client.get("/chargeback.csv?view=tag&key=CostCenter&month=2026-09")
    assert "Tag,Value,Period,Cost,Share %" in tags.get_data(as_text=True) and tags.headers["Content-Disposition"].startswith("attachment")


def test_nav_has_chargeback(client, monkeypatch):
    serve(monkeypatch)
    assert 'href="/chargeback"' in client.get("/chargeback").get_data(as_text=True)
