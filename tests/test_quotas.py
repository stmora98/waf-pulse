import json

import pytest

import app as dashboard_app
import data
import scope
from waf_pulse import graph, quotas, rest

SUB = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"


def usage(name, current, limit, key=None):
    return {"name": {"value": key or name.replace(" ", ""), "localizedValue": name}, "currentValue": current, "limit": limit, "unit": "Count"}


def test_usages_keep_the_quotas_that_are_in_use_and_big_enough_to_run_out():
    body = {"value": [usage("Total Regional vCPUs", 90, 100), usage("Dedicated hosts", 1, 1), usage("Idle family", 0, 100), usage("Small", 3, 3), usage("Bad", None, 10), {"name": None, "currentValue": 5, "limit": 10}]}
    rows = quotas.parse_usages(body, "compute", SUB, "eastus")
    assert [(r["name"], r["current"], r["limit"], r["percent"]) for r in rows] == [("Total Regional vCPUs", 90, 100, 90.0), ("", 5, 10, 50.0)]
    assert quotas.parse_usages(None, "compute", SUB, "eastus") == [] and rows[0]["region"] == "eastus" and rows[0]["service"] == "compute"


def test_quotas_close_to_the_limit_are_findings_by_how_close():
    rows = (quotas.parse_usages({"value": [usage("DSv3 vCPUs", 96, 100), usage("Total Regional vCPUs", 85, 100), usage("Public IPs", 10, 1000)]}, "compute", SUB, "eastus")
            + quotas.parse_usages({"value": [usage("Public IP Addresses", 960, 1000)]}, "network", OTHER, "westus"))
    findings, stats, dataset = quotas.evaluate("r", rows)
    by_rule = {(f["ruleId"], f["resourceName"]) for f in findings}
    assert by_rule == {("REL-QUOTA-002", "DSv3 vCPUs · eastus"), ("REL-QUOTA-001", "Total Regional vCPUs · eastus"), ("REL-QUOTA-002", "Public IP Addresses · westus")}
    first = next(f for f in findings if f["resourceName"].startswith("DSv3"))
    assert first["title"] == "DSv3 vCPUs is at 96% of its quota in eastus (96 of 100)" and first["severity"] == "high" and first["pillar"] == "Reliability" and first["source"] == "quotas"
    assert first["resourceId"] == f"/subscriptions/{SUB}/providers/microsoft.compute/locations/eastus/usages/DSv3vCPUs"
    assert {(s["ruleId"], s["subscriptionId"], s["affected"], s["applicable"]) for s in stats} == {
        ("REL-QUOTA-001", SUB, 1, 3), ("REL-QUOTA-002", SUB, 1, 3), ("REL-QUOTA-001", OTHER, 0, 1), ("REL-QUOTA-002", OTHER, 1, 1)}
    assert dataset["checked"] == 4 and dataset["atRisk"] == 3 and dataset["rows"][0]["percent"] == 96.0 and "key" not in dataset["rows"][0]


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


class Cred:
    def get_token(self, scope):
        return type("T", (), {"token": "t"})()


def test_collect_reads_each_region_and_service_and_reports_refusals(monkeypatch):
    monkeypatch.setattr(graph, "query", lambda c, s, kql, max_rows=0: [{"subscriptionId": SUB, "location": "eastus"}, {"subscriptionId": SUB, "location": "westus"}])
    calls = []

    def fake_get(url, token, params=None, headers=None):
        calls.append(url)
        if "Microsoft.Network" in url and "westus" in url:
            return Resp(403)
        return Resp(200, {"value": [usage("Total Regional vCPUs", 99, 100)]}) if "Microsoft.Compute" in url else Resp(200, {"value": []})

    monkeypatch.setattr(rest, "get", fake_get)
    findings, stats, dataset, errors = quotas.collect(Cred(), "r", [SUB])
    assert len(calls) == 4 and {f["resourceName"] for f in findings} == {"Total Regional vCPUs · eastus", "Total Regional vCPUs · westus"}
    assert errors == [{"ruleId": "quotas-permission", "error": "1 quota read(s) were refused: grant Reader on the subscriptions."}] and dataset["regionsRead"] == 2


def test_collect_survives_a_failing_region_listing(monkeypatch):
    monkeypatch.setattr(graph, "query", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("Forbidden\nmore")))
    findings, stats, dataset, errors = quotas.collect(Cred(), "r", [SUB])
    assert findings == [] and errors == [{"ruleId": "quotas-regions", "error": "Forbidden"}] and dataset["checked"] == 0


# --- the dashboard panel -------------------------------------------------------------------------------------------

QUOTAS = {"checked": 3, "atRisk": 2, "regionsRead": 2, "rows": [
    {"service": "compute", "subscriptionId": SUB, "region": "eastus", "name": "DSv3 vCPUs", "current": 96, "limit": 100, "percent": 96.0},
    {"service": "network", "subscriptionId": OTHER, "region": "westus", "name": "Public IP Addresses", "current": 850, "limit": 1000, "percent": 85.0},
    {"service": "compute", "subscriptionId": SUB, "region": "eastus", "name": "Total Regional vCPUs", "current": 10, "limit": 100, "percent": 10.0}]}


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, with_quotas=True):
    summary = {"runId": "r1", "scores": {}, "counts": {}, "severityTotals": {}, "subscriptions": [{"id": SUB, "name": "Prod", "resourceCount": 3, "scores": {}}, {"id": OTHER, "name": "Dev", "resourceCount": 2, "scores": {}}]}
    if with_quotas:
        summary["quotas"] = QUOTAS
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: json.loads(json.dumps(summary)))
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])
    monkeypatch.setattr(data, "resources", lambda run_id: ([], False))
    monkeypatch.setattr(data, "get_setting", lambda name: None)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: [])
    monkeypatch.setattr(data, "history", lambda limit=30: [])


def test_the_reliability_page_shows_the_quotas_closest_to_the_limit(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/pillar/reliability").get_data(as_text=True)
    assert 'id="quotas"' in html and "DSv3 vCPUs" in html and "96.0%" in html and "as-saturated" in html and "as-under" in html and "3 compute and network quotas" in html and "Prod" in html
    assert html.index("DSv3 vCPUs") < html.index("Public IP Addresses") < html.index("Total Regional vCPUs")
    serve(monkeypatch, with_quotas=False)
    assert 'id="quotas"' not in client.get("/pillar/reliability").get_data(as_text=True)


def test_quotas_follow_the_subscription_filters(client, monkeypatch):
    serve(monkeypatch)
    client.set_cookie(scope.COOKIE, scope.encode(scope.sanitize([{"f": "sub", "v": [OTHER]}])), domain="localhost")
    html = client.get("/pillar/reliability").get_data(as_text=True)
    assert "Public IP Addresses" in html and "DSv3 vCPUs" not in html and "1 compute and network quotas" in html
    client.set_cookie(scope.COOKIE, scope.encode(scope.sanitize([{"f": "sub", "op": "ne", "v": [SUB, OTHER]}])), domain="localhost")
    assert "No quota in use in the filtered subscriptions" in client.get("/pillar/reliability").get_data(as_text=True)
