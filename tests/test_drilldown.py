import pytest

import app as dashboard_app
import data
import insights
from waf_pulse import collect, store

SUB = "11111111-1111-1111-1111-111111111111"
SUB2 = "22222222-2222-2222-2222-222222222222"


def res(name, kind="microsoft.compute/virtualmachines", sub=SUB, group="rg1", location="eastus", detail="Standard_D2s_v3 · Linux · running"):
    return {"id": f"/subscriptions/{sub}/resourceGroups/{group}/providers/{kind}/{name}", "name": name, "type": kind,
            "subscriptionId": sub, "resourceGroup": group, "location": location, "detail": detail, "tags": 2}


ROWS = [res("vm-a"), res("vm-b", group="rg2"), res("<b>disk</b>", "microsoft.compute/disks", detail="Premium_LRS · 128 GB"),
        res("kv1", "microsoft.keyvault/vaults", sub=SUB2, detail="standard")]

SUMMARY = {"runId": "r1", "completedUtc": "t", "subscriptionCount": 2, "resourceCount": 4, "findingCount": 2, "scores": {},
           "counts": {}, "severityTotals": {}, "sources": {}, "errors": [],
           "subscriptions": [{"id": SUB, "name": "Prod", "resourceCount": 3, "findingCount": 2},
                             {"id": SUB2, "name": "Dev", "resourceCount": 1, "findingCount": 0}]}

FINDINGS = [
    {"id": "1", "ruleId": "R-1", "severity": "high", "pillar": "Security", "title": "Backup is off", "source": "builtin",
     "resourceId": ROWS[0]["id"].upper(), "resourceName": "vm-a", "resourceType": "Microsoft.Compute/virtualMachines",
     "subscriptionId": SUB, "recommendation": "Turn it on"},
    {"id": "2", "ruleId": "R-2", "severity": "low", "pillar": "Cost Optimization", "title": "Old size", "source": "builtin",
     "resourceId": ROWS[0]["id"], "resourceName": "vm-a", "resourceType": "Microsoft.Compute/virtualMachines",
     "subscriptionId": SUB, "recommendation": "Resize"},
]


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, rows=ROWS, truncated=False, findings=FINDINGS):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: SUMMARY)
    monkeypatch.setattr(data, "resources", lambda run_id: (rows, truncated))

    def fake(run_id, pillar=None, rule_id=None, limit=5000, resource_id=None):
        return [f for f in findings if (not resource_id or f["resourceId"].lower() == resource_id.lower())]

    monkeypatch.setattr(data, "all_findings", fake)


def test_the_resource_list_shows_what_is_behind_a_count(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/resources?type=microsoft.compute/virtualmachines").get_data(as_text=True)
    assert "Virtual machines" in html and "<span class=\"muted\">· 2</span>" in html
    assert "vm-a" in html and "vm-b" in html and "Standard_D2s_v3" in html and "rg2" in html and "eastus" in html
    assert "kv1" not in html and "&lt;b&gt;disk" not in html  # other types are left out
    assert 'href="/resource?id=' in html and "Prod" in html


def test_the_list_filters_by_subscription_group_and_text_and_escapes(client, monkeypatch):
    serve(monkeypatch)
    assert "kv1" in client.get(f"/resources?subscription={SUB2}").get_data(as_text=True)
    assert "vm-b" not in client.get("/resources?group=rg1").get_data(as_text=True)
    found = client.get("/resources?q=premium").get_data(as_text=True)
    assert "&lt;b&gt;disk&lt;/b&gt;" in found and "<b>disk</b>" not in found and "vm-a" not in found
    bad = client.get("/resources?type=%27%20OR%201%3D1&subscription=x&group=%3Cscript%3E&page=abc")
    assert bad.status_code == 200 and "vm-a" in bad.get_data(as_text=True)  # invalid filters are ignored


def test_the_list_is_paged_and_the_type_chips_count_every_type(client, monkeypatch):
    many = [res(f"vm{i:03d}") for i in range(130)]
    serve(monkeypatch, many)
    first = client.get("/resources").get_data(as_text=True)
    assert "vm099" in first and "vm100" not in first and "Page 1 of 2" in first and "Virtual machines: 130" in first
    assert "vm100" in client.get("/resources?page=2").get_data(as_text=True)


def test_the_list_explains_a_run_without_inventory_and_store_errors(client, monkeypatch):
    serve(monkeypatch, rows=[])
    assert "collected from the next run" in client.get("/resources").get_data(as_text=True)
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: (_ for _ in ()).throw(RuntimeError("secret")))
    response = client.get("/resources")
    assert response.status_code == 503 and b"secret" not in response.data


def test_a_resource_shows_its_facts_and_all_its_findings(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/resource", query_string={"id": ROWS[0]["id"]}).get_data(as_text=True)
    assert "vm-a" in html and "Virtual machines" in html and "Standard_D2s_v3" in html and "Prod" in html
    assert "Findings for this resource" in html and 'href="/rule/R-1"' in html and 'href="/rule/R-2"' in html
    assert html.index("Backup is off") < html.index("Old size")  # most severe first; ids differ only by case


def test_a_resource_missing_from_the_list_falls_back_to_its_findings(client, monkeypatch):
    serve(monkeypatch, rows=[])
    html = client.get("/resource", query_string={"id": ROWS[0]["id"]}).get_data(as_text=True)
    assert "vm-a" in html and 'href="/rule/R-1"' in html


def test_resource_ids_are_validated(client, monkeypatch):
    serve(monkeypatch)
    for bad in ("", "not-an-id", "/x<script>", "/" + "a" * 700):
        assert client.get("/resource", query_string={"id": bad}).status_code == 404
    assert "not in the latest run" in client.get("/resource", query_string={"id": "/subscriptions/none"}).get_data(as_text=True)


def test_counts_lead_to_the_lists_behind_them(client, monkeypatch):
    serve(monkeypatch)
    monkeypatch.setattr(data, "summary", lambda run_id: {**SUMMARY, "scores": {"Security": 40},
                                                         "counts": {"Security": {"high": 1}}})
    overview = client.get("/").get_data(as_text=True)
    assert 'href="/resources"' in overview and 'href="/actions"' in overview and 'href="#subscriptions"' in overview
    assert f'href="/resources?subscription={SUB}"' in overview
    assert "/resources?type=microsoft.compute/virtualmachines" in overview  # the resource type bars
    assert "/resource?id=" in overview  # the resources with most findings
    pillar = client.get("/pillar/security").get_data(as_text=True)
    assert 'href="/affected?pillar=Security&amp;severity=high"' in pillar and "see the list" in pillar
    rule = client.get("/rule/R-1").get_data(as_text=True)
    assert 'href="/resource?id=' in rule
    assert 'href="/resources"' in client.get("/pillar/security").get_data(as_text=True)  # the menu entry


def test_the_menu_has_a_resources_entry(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/resources").get_data(as_text=True)
    assert '<span class="side-label">Resources</span>' in html and 'class="side-link active" href="/resources"' in html


# --- helpers ------------------------------------------------------------------------------------------

def test_filter_resources_combines_filters():
    assert [r["name"] for r in insights.filter_resources(ROWS, "microsoft.compute/virtualmachines", SUB, "RG1")] == ["vm-a"]
    assert insights.filter_resources(ROWS, None, None, None, "  ") == ROWS
    assert [r["name"] for r in insights.filter_resources(ROWS, query="WESTUS")] == []


def test_friendly_types_and_findings_per_resource():
    assert insights.friendly_type("Microsoft.Compute/virtualMachines") == "Virtual machines"
    assert insights.friendly_type("microsoft.cdn/profiles") == "cdn/profiles"
    assert insights.findings_per_resource(FINDINGS) == {ROWS[0]["id"].lower(): 2}


# --- collector --------------------------------------------------------------------------------------------

def test_the_resource_list_is_cleaned_and_capped(monkeypatch):
    rows = [{"id": "/s/a", "name": "A", "type": "Microsoft.Compute/VirtualMachines", "subscriptionId": "S1", "resourceGroup": "rg",
             "location": "eastus", "detail": "D2 ·  · ", "tags": None}] + [{"id": f"/s/{i}", "name": str(i), "type": "x"} for i in range(5)]
    monkeypatch.setattr(collect.graph, "chunks", lambda ids: [ids])
    monkeypatch.setattr(collect.graph, "query", lambda *a, **k: rows)
    monkeypatch.setattr(collect, "MAX_RESOURCE_LIST", 3)
    cleaned, truncated = collect.collect_resource_list(None, ["s1"])
    assert truncated is True and len(cleaned) == 3
    assert cleaned[0] == {"id": "/s/a", "name": "A", "type": "microsoft.compute/virtualmachines", "subscriptionId": "s1",
                          "resourceGroup": "rg", "location": "eastus", "detail": "D2", "tags": 0}
    monkeypatch.setattr(collect, "MAX_RESOURCE_LIST", 10)
    assert collect.collect_resource_list(None, ["s1"])[1] is False


def test_the_resource_list_is_stored_in_chunks_apart_from_the_summary(monkeypatch):
    saved = []
    monkeypatch.setattr(store, "_save_run_document", lambda run_id, kind, key, payload: saved.append((kind, key, payload)))
    monkeypatch.setattr(store, "RESOURCE_CHUNK", 2)
    store.save_resources("r1", [{"id": str(i)} for i in range(5)], truncated=True)
    assert [(kind, key, len(p["rows"])) for kind, key, p in saved] == [
        ("resources", "inventory:0", 2), ("resources", "inventory:1", 2), ("resources", "inventory:2", 1)]
    assert all(p["truncated"] for _, _, p in saved)


def test_the_findings_of_one_resource_are_queried_without_caring_about_case(monkeypatch):
    seen = {}

    class Container:
        def query_items(self, query, parameters=None, partition_key=None):
            seen.update(query=query, parameters=parameters, partition_key=partition_key)
            return iter([{"id": "1", "_rid": "x"}])

    class Db:
        def get_container_client(self, name):
            return Container()

    monkeypatch.setattr(data, "_db", lambda: Db())
    assert data.all_findings("r1", resource_id="/Subscriptions/S1/x") == [{"id": "1", "_rid": "x"}]
    assert "STRINGEQUALS(c.resourceId, @resource, true)" in seen["query"]
    assert {"name": "@resource", "value": "/Subscriptions/S1/x"} in seen["parameters"] and seen["partition_key"] == "r1"


# --- affected resources and the link to Azure ------------------------------------------------------------

TENANT = "00000000-1111-2222-3333-444444444444"


def many_findings():
    vm = ROWS[0]["id"]
    return FINDINGS + [
        {"id": "3", "ruleId": "R-1", "severity": "high", "pillar": "Security", "title": "Backup is off", "source": "builtin",
         "resourceId": ROWS[1]["id"], "resourceName": "vm-b", "resourceType": "Microsoft.Compute/virtualMachines",
         "subscriptionId": SUB, "recommendation": "Turn it on"},
        {"id": "4", "ruleId": "R-3", "severity": "medium", "pillar": "Security", "title": "Entra <app>", "source": "entra",
         "resourceId": "/tenant/applications/abc", "resourceName": "my-app", "resourceType": "microsoft.graph/applications",
         "subscriptionId": "tenant", "recommendation": "Rotate"},
    ]


def test_a_count_opens_the_resources_behind_it_with_a_link_to_azure(client, monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    serve(monkeypatch, findings=many_findings())
    html = client.get("/affected?pillar=Security&severity=high").get_data(as_text=True)
    assert "Affected resources" in html and "<span class=\"muted\">· 2</span>" in html  # vm-a and vm-b
    assert "vm-a" in html and "vm-b" in html and "my-app" not in html and "Prod" in html and "rg2" in html
    assert f'href="https://portal.azure.com/#@{TENANT}/resource{ROWS[1]["id"]}"' in html
    # vm-a was reported with an upper case id by one source: the link uses the inventory's spelling.
    assert f'href="https://portal.azure.com/#@{TENANT}/resource{ROWS[0]["id"]}"' in html and ROWS[0]["id"].upper() not in html
    assert 'target="_blank"' in html and 'rel="noopener noreferrer"' in html and "Open in Azure" in html
    assert 'href="/resource?id=' in html and 'href="/actions?pillar=Security&amp;severity=high"' in html


def test_the_resources_are_grouped_and_ordered_by_their_worst_finding(client, monkeypatch):
    serve(monkeypatch, findings=many_findings())
    html = client.get("/affected").get_data(as_text=True)
    assert html.index("vm-a") < html.index("my-app")  # high before medium
    row = html[html.index("vm-a"):html.index("vm-b")]
    assert 'class="chip high">high</span> 2' in row and "Old size" in row  # two findings on the same resource, any case
    assert html.count("vm-a") >= 1 and "Entra &lt;app&gt;" in html and "Entra <app>" not in html


def test_things_that_are_not_azure_resources_get_no_azure_link(client, monkeypatch):
    serve(monkeypatch, findings=many_findings())
    html = client.get("/affected?source=entra").get_data(as_text=True)
    assert "my-app" in html and "portal.azure.com" not in html and "Open in Azure" not in html


def test_a_single_rule_shows_its_title_and_filters_are_validated(client, monkeypatch):
    serve(monkeypatch, findings=many_findings())
    html = client.get("/affected?rule=R-1").get_data(as_text=True)
    assert "Backup is off" in html and "What to do about it" in html and 'href="/rule/R-1"' in html
    bad = client.get("/affected?pillar=%27%20OR%201%3D1&severity=nope&source=x&rule=bad%20rule&page=abc")
    assert bad.status_code == 200 and "vm-a" in bad.get_data(as_text=True)


def test_the_affected_list_is_paged_and_handles_errors(client, monkeypatch):
    rows = [{"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/p/t/r{i:03d}", "ruleId": "R", "severity": "low", "pillar": "Security",
             "title": "t", "source": "builtin", "resourceId": f"/subscriptions/{SUB}/resourceGroups/rg/providers/p/t/r{i:03d}",
             "resourceName": f"r{i:03d}", "resourceType": "p/t", "subscriptionId": SUB} for i in range(130)]
    serve(monkeypatch, findings=rows)
    first = client.get("/affected").get_data(as_text=True)
    assert "r099" in first and "r100" not in first and "Page 1 of 2" in first and "r100" in client.get("/affected?page=2").get_data(as_text=True)
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: (_ for _ in ()).throw(RuntimeError("secret")))
    response = client.get("/affected")
    assert response.status_code == 503 and b"secret" not in response.data


def test_every_list_of_resources_offers_the_azure_link(client, monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", TENANT)
    serve(monkeypatch, findings=many_findings())
    expected = f"https://portal.azure.com/#@{TENANT}/resource{ROWS[0]['id']}"
    assert expected in client.get("/resources").get_data(as_text=True)
    assert expected in client.get("/resource", query_string={"id": ROWS[0]["id"]}).get_data(as_text=True)
    assert expected in client.get("/rule/R-1").get_data(as_text=True)


def test_the_portal_link_is_only_built_for_azure_resources():
    vm = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    assert insights.portal_url(vm, TENANT) == f"https://portal.azure.com/#@{TENANT}/resource{vm}"
    assert insights.portal_url(vm) == f"https://portal.azure.com/#resource{vm}"  # without a tenant
    assert insights.portal_url(vm, "not a guid") == f"https://portal.azure.com/#resource{vm}"
    assert insights.portal_url(f"/subscriptions/{SUB}", TENANT).endswith(f"resource/subscriptions/{SUB}")
    for not_azure in ("/tenant/applications/x", "cost-anomaly/2026-10-01", "", None, f"/subscriptions/{SUB}/commitments/vm", "/" + "a" * 900):
        assert insights.portal_url(not_azure, TENANT) is None


def test_group_by_resource_counts_and_ranks():
    rows = insights.group_by_resource(many_findings())
    assert [(r["name"], r["severity"], r["count"]) for r in rows] == [("vm-a", "high", 2), ("vm-b", "high", 1), ("my-app", "medium", 1)]
    assert rows[0]["resourceGroup"].lower() == "rg1" and rows[0]["pillars"] == ["Cost Optimization", "Security"] and rows[0]["titles"] == ["Backup is off", "Old size"]
    assert insights.group_by_resource([{"title": "no resource"}]) == []
