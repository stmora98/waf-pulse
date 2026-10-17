import pathlib
import re
from datetime import datetime, timezone

import pytest

import app as dashboard_app
import data
import governance_view
from waf_pulse import governance, graph

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)
SUB = "11111111-1111-1111-1111-111111111111"
SUB2 = "22222222-2222-2222-2222-222222222222"
ROOT = {"name": "tenant-id", "displayName": "Tenant Root Group"}
PROD = {"name": "mg-prod", "displayName": "Production"}


def sub_row(sub, name="Sub", chain=None, state="Enabled"):
    return {"subscriptionId": sub, "name": name, "state": state, "chain": chain if chain is not None else [PROD, ROOT]}


def stats_for(stats, rule):
    return {s["subscriptionId"]: s for s in stats if s["ruleId"] == rule}


# --- management groups ----------------------------------------------------------------------------------

@pytest.mark.parametrize("chain", [[ROOT, PROD], [PROD, ROOT]])
def test_hierarchy_does_not_depend_on_the_chain_order(chain):
    groups, subs = governance.management_groups([sub_row(SUB.upper(), "Prod sub", chain)], [])
    by_name = {g["name"]: g for g in groups}
    assert by_name["mg-prod"]["parent"] == "tenant-id"
    assert by_name["tenant-id"]["parent"] is None
    assert by_name["mg-prod"]["subscriptions"] == [SUB]
    assert subs[0]["path"] == ["Tenant Root Group", "Production"]


def test_visible_groups_add_nodes_and_parents():
    groups, _ = governance.management_groups([], [{"name": "child", "displayName": "Child", "parent": "mg-prod"}])
    assert {g["name"] for g in groups} == {"child", "mg-prod"}


def test_tree_nests_groups_and_lists_subscription_names():
    groups, subs = governance.management_groups([sub_row(SUB, "Prod sub")], [])
    tree = governance_view.build_tree(groups, subs)
    assert [n["name"] for n in tree] == ["tenant-id"]
    child = tree[0]["children"][0]
    assert child["name"] == "mg-prod" and child["subscriptionNames"] == ["Prod sub"]


def test_tree_survives_cycles_and_unknown_parents():
    groups = [{"name": "a", "displayName": "A", "parent": "b", "subscriptions": []},
              {"name": "b", "displayName": "B", "parent": "a", "subscriptions": []},
              {"name": "c", "displayName": "C", "parent": "missing", "subscriptions": []}]
    tree = governance_view.build_tree(groups, [])
    names = set()

    def walk(nodes):
        for node in nodes:
            assert node["name"] not in names
            names.add(node["name"])
            walk(node["children"])

    walk(tree)
    assert names == {"a", "b", "c"}


def test_subscriptions_outside_groups():
    groups = [{"name": "g", "subscriptions": [SUB]}]
    assert governance_view.subscriptions_outside_groups(groups, [{"id": SUB}, {"id": SUB2}]) == [{"id": SUB2}]


# --- checks ---------------------------------------------------------------------------------------------

def test_too_many_owners_is_a_security_finding():
    results = {"subscriptions": [sub_row(SUB), sub_row(SUB2)],
               "owners": [{"subscriptionId": SUB, "owners": 5}, {"subscriptionId": SUB2, "owners": 3}]}
    findings, stats, _ = governance.evaluate("r", results, NOW)
    rows = stats_for(stats, "GOV-RBAC-001")
    assert (rows[SUB]["affected"], rows[SUB]["applicable"]) == (1, 1) and rows[SUB2]["affected"] == 0
    owner_findings = [f for f in findings if f["ruleId"] == "GOV-RBAC-001"]
    assert len(owner_findings) == 1 and "5 owners" in owner_findings[0]["title"]
    assert owner_findings[0]["source"] == "governance" and owner_findings[0]["pillar"] == "Security"


def test_subscription_without_locks_is_flagged_and_disabled_ones_are_ignored():
    results = {"subscriptions": [sub_row(SUB), sub_row(SUB2, state="Disabled")], "locks": []}
    findings, stats, dataset = governance.evaluate("r", results, NOW)
    assert list(stats_for(stats, "GOV-LOCK-001")) == [SUB]
    assert dataset["locks"]["subscriptionsWithoutLocks"] == [SUB]
    results["locks"] = [{"subscriptionId": SUB, "locks": 2}]
    findings, stats, dataset = governance.evaluate("r", results, NOW)
    assert stats_for(stats, "GOV-LOCK-001")[SUB]["affected"] == 0 and dataset["locks"]["total"] == 2


def test_policy_compliance_aggregates_per_subscription_and_lists_top_assignments():
    assignment = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/policyAssignments/pa1"
    results = {"subscriptions": [sub_row(SUB)],
               "assignments": [{"id": assignment, "displayName": "Require tags", "enforcement": "Default"},
                               {"id": "x2", "displayName": "Audit only", "enforcement": "DoNotEnforce"}],
               "compliance": [{"assignment": assignment, "subscriptionId": SUB, "nonCompliant": 4, "total": 10},
                              {"assignment": "other", "subscriptionId": SUB, "nonCompliant": 0, "total": 5}]}
    findings, stats, dataset = governance.evaluate("r", results, NOW)
    row = stats_for(stats, "GOV-POL-001")[SUB]
    assert (row["affected"], row["applicable"]) == (4, 15)
    policy_findings = [f for f in findings if f["ruleId"] == "GOV-POL-001"]
    assert len(policy_findings) == 1 and "Require tags" in policy_findings[0]["title"]
    assert dataset["policy"]["notEnforced"] == 1 and dataset["policy"]["assignments"] == 2
    assert dataset["policy"]["topNonCompliant"][0] == {"assignment": "Require tags", "nonCompliant": 4, "total": 10, "subscriptionId": SUB}


def test_exemptions_without_expiry_or_expired_are_flagged():
    exemptions = [
        {"id": "e1", "name": "n1", "subscriptionId": SUB, "expiresOn": ""},
        {"id": "e2", "name": "n2", "subscriptionId": SUB, "expiresOn": "2026-01-01T00:00:00Z"},
        {"id": "e3", "name": "n3", "subscriptionId": SUB, "expiresOn": "2030-01-01T00:00:00Z"},
        {"id": "e4", "name": "n4", "subscriptionId": SUB, "expiresOn": "2020-01-01T00:00:00"},  # no offset
    ]
    findings, stats, dataset = governance.evaluate("r", {"subscriptions": [sub_row(SUB)], "exemptions": exemptions}, NOW)
    row = stats_for(stats, "GOV-POL-002")[SUB]
    assert (row["affected"], row["applicable"]) == (3, 4)
    titles = sorted(f["title"] for f in findings if f["ruleId"] == "GOV-POL-002")
    assert titles == ["Policy exemption has expired", "Policy exemption has expired", "Policy exemption has no expiry date"]
    assert dataset["policy"]["expiredExemptions"] == 2 and dataset["policy"]["exemptionsWithoutExpiry"] == 1


def test_defender_plans_not_enabled():
    plans = [{"subscriptionId": SUB, "plan": "VirtualMachines", "tier": "Standard"},
             {"subscriptionId": SUB, "plan": "SqlServers", "tier": "Free"}]
    findings, stats, dataset = governance.evaluate("r", {"subscriptions": [sub_row(SUB)], "defender": plans}, NOW)
    row = stats_for(stats, "GOV-DEF-001")[SUB]
    assert (row["affected"], row["applicable"]) == (1, 2)
    assert {k: v for k, v in dataset["defender"].items() if k != "detail"} == {"plans": 2, "enabled": 1, "notEnabled": ["SqlServers"]}
    # enabled plans first, then the ones that are off, each with its tier and sub-plan
    assert [(d["plan"], d["tier"]) for d in dataset["defender"]["detail"]] == [("VirtualMachines", "Standard"), ("SqlServers", "Free")]
    assert [f["resourceName"] for f in findings if f["ruleId"] == "GOV-DEF-001"] == ["SqlServers"]


def test_rbac_dataset_counts_principal_types_and_roles():
    results = {"subscriptions": [sub_row(SUB)],
               "rolesByPrincipal": [{"subscriptionId": SUB, "principalType": "User", "count_": 10},
                                    {"subscriptionId": SUB, "principalType": "Group", "count_": 2},
                                    {"subscriptionId": SUB, "principalType": None, "count_": 1}],
               "customRoles": [{"count_": 3}], "customDefinitions": [{"count_": 7}], "owners": [{"subscriptionId": SUB, "owners": 2}]}
    _, _, dataset = governance.evaluate("r", results, NOW)
    assert dataset["rbac"]["assignments"] == 13 and dataset["rbac"]["byPrincipalType"]["Unknown"] == 1
    assert dataset["rbac"]["customRoles"] == 3 and dataset["policy"]["customDefinitions"] == 7
    assert dataset["rbac"]["owners"] == [{"subscriptionId": SUB, "owners": 2}]


def test_empty_results_do_not_fail():
    findings, stats, dataset = governance.evaluate("r", {}, NOW)
    assert findings == [] and stats == [] and dataset["rbac"]["assignments"] == 0


def test_collect_reports_a_failing_query_and_keeps_the_rest(monkeypatch):
    def fake_query(credential, subscriptions, kql, max_rows=0):
        if "policystates" in kql:
            raise RuntimeError("(BadRequest) invalid\nsecond line")
        if "managementgroups" in kql:
            return []
        if "microsoft.resources/subscriptions'" in kql:
            return [sub_row(SUB)]
        return []

    monkeypatch.setattr(graph, "query", fake_query)
    monkeypatch.setattr(governance, "fetch_pricings", lambda credential, subs: ([], []))
    findings, stats, dataset, errors = governance.collect(None, "r", [SUB])
    assert [e["ruleId"] for e in errors] == ["governance-compliance"]
    assert "GOV-LOCK-001" in {s["ruleId"] for s in stats}


def test_every_query_is_defined_and_has_a_name():
    assert {"managementGroups", "subscriptions", "assignments", "compliance", "exemptions", "owners", "locks",
            "defender", "rolesByPrincipal", "customRoles", "customDefinitions", "signals"} == set(governance.QUERIES)
    assert governance.OWNER_ROLE_ID in governance.QUERIES["owners"]


# --- dashboard page -------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


GOVERNANCE = {
    "managementGroups": [{"name": "root", "displayName": "Tenant Root Group", "parent": None, "subscriptions": []},
                         {"name": "prod", "displayName": "<b>Prod</b>", "parent": "root", "subscriptions": [SUB]}],
    "subscriptions": [{"id": SUB, "name": "Prod sub", "state": "Enabled", "path": []},
                      {"id": SUB2, "name": "Loose sub", "state": "Enabled", "path": []}],
    "policy": {"assignments": 3, "notEnforced": 1, "customDefinitions": 2, "exemptions": 1, "expiredExemptions": 0,
               "exemptionsWithoutExpiry": 1, "nonCompliantResources": 4,
               "topNonCompliant": [{"assignment": "Require tags", "nonCompliant": 4, "total": 10, "subscriptionId": SUB}]},
    "rbac": {"assignments": 14, "byPrincipalType": {"User": 14}, "customRoles": 1,
             "owners": [{"subscriptionId": SUB, "owners": 3}]},
    "locks": {"total": 0, "subscriptionsWithoutLocks": [SUB]},
    "defender": {"plans": 2, "enabled": 1, "notEnabled": ["SqlServers"]},
}


def test_governance_page_renders_and_escapes(client, monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: {"runId": "r1", "governance": GOVERNANCE})
    html = client.get("/governance").get_data(as_text=True)
    assert "Require tags" in html and "Prod sub" in html and "Loose sub" in html
    assert "No visible management group" in html and "Your management group hierarchy" in html
    assert "<b>Prod</b>" not in html and "&lt;b&gt;Prod&lt;/b&gt;" in html
    assert "Landing zone design" in html and "of 12 management groups found" in html
    assert html.count('class="lz-node') >= 15 and "Only the tenant root group is visible" not in html
    assert "1/2" in html and "1 of 2 plan(s) enabled" in html


def test_governance_page_empty_and_error_states(client, monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: None)
    assert b"No governance data yet" in client.get("/governance").data

    def boom(completed_only=False):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(data, "latest_run", boom)
    response = client.get("/governance")
    assert response.status_code == 503 and b"secret detail" not in response.data


def test_governance_page_shows_diagnostics_and_key_vault_panels(client, monkeypatch):
    summary = {"runId": "r1", "governance": GOVERNANCE,
               "diagnostics": {"checked": 4, "withLogs": 1, "percent": 25.0, "skipped": {"denied": 1},
                               "byType": [{"label": "<Key Vault>", "checked": 4, "withLogs": 1}]},
               "keyvault": {"vaults": 2, "readable": 1, "denied": 1, "objects": 3,
                            "upcoming": [{"vault": "v", "name": "old", "kind": "secret", "expires": "2026-10-01", "days": -15}]}}
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: summary)
    html = client.get("/governance").get_data(as_text=True)
    assert "25.0%" in html and "&lt;Key Vault&gt;" in html and "3 of 4 without" in html and "1 resource(s) could not be read" in html
    assert "v/old" in html and "expired 2026-10-01" in html and "1 vault(s) could not be listed" in html

def test_defender_plans_are_read_from_arm_when_resource_graph_has_none(monkeypatch):
    class Cred:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    class Resp:
        def __init__(self, status, body):
            self.status_code, self._body = status, body

        def json(self):
            return self._body

    def fake_get(url, token, params=None, headers=None):
        if SUB in url:
            return Resp(200, {"value": [{"name": "VirtualMachines", "properties": {"pricingTier": "Standard", "subPlan": "P2"}},
                                        {"name": "Dns", "properties": {"pricingTier": "Free"}}]})
        return Resp(403, {})

    monkeypatch.setattr(governance.graph, "chunks", lambda ids: [ids])
    monkeypatch.setattr(governance.graph, "query", lambda *a, **k: [])
    monkeypatch.setattr(governance.rest, "get", fake_get)
    findings, stats, dataset, errors = governance.collect(Cred(), "r1", [SUB, "denied-sub"])
    assert [(d["plan"], d["tier"], d["subPlan"]) for d in dataset["defender"]["detail"]] == [
        ("VirtualMachines", "Standard", "P2"), ("Dns", "Free", "")]
    assert [f["resourceName"] for f in findings if f["ruleId"] == "GOV-DEF-001"] == ["Dns"]
    assert any("denied-sub" in e["error"] for e in errors)


def test_policy_assignments_are_grouped_by_the_management_group_they_are_made_on():
    base = "/providers/Microsoft.Management/managementGroups/"
    result = governance.policy_by_group([
        {"name": "Enforce-ALZ-Sandbox", "displayName": "Sandbox guardrails", "scope": base + "mg-sbx"},
        {"name": "Deny-IP-Forwarding", "displayName": "", "scope": base + "MG-LZ/"},
        {"name": "Enforce-ALZ-Sandbox", "displayName": "Sandbox guardrails", "scope": base + "mg-sbx"},  # duplicate
        {"name": "On-a-subscription", "scope": "/subscriptions/s1"},
    ])
    assert result == {"mg-sbx": ["Enforce-ALZ-Sandbox", "Sandbox guardrails"], "mg-lz": ["Deny-IP-Forwarding"]}


def test_subscription_signals_count_resource_types_per_subscription():
    rows = [{"subscriptionId": SUB.upper(), "type": "Microsoft.Network/AzureFirewalls", "n": 2},
            {"subscriptionId": SUB, "type": "microsoft.automation/automationaccounts", "n": 1}, {"type": "x", "n": 1}]
    assert governance.subscription_signals(rows) == {SUB: {"microsoft.network/azurefirewalls": 2,
                                                          "microsoft.automation/automationaccounts": 1}}


def settings_store(monkeypatch, initial=None):
    store = {"value": initial}
    monkeypatch.setattr(data, "get_setting", lambda name: store["value"])
    monkeypatch.setattr(data, "save_setting", lambda name, value: store.update(value=value))
    return store


def serve_governance(monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: {"runId": "r1", "governance": GOVERNANCE})


def test_the_page_still_renders_when_the_settings_cannot_be_read(client, monkeypatch):
    serve_governance(monkeypatch)
    monkeypatch.setattr(data, "get_setting", lambda name: (_ for _ in ()).throw(RuntimeError("down")))
    assert client.get("/governance").status_code == 200


def design_of(*children):
    return {"id": "root", "label": "Tenant root group", "kind": "root", "role": "", "link": "", "children": list(children)}


def box(name, kind="mg", link="", children=()):
    return {"id": re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-"), "label": name, "kind": kind, "role": "", "link": link,
            "children": list(children)}


def test_every_box_of_the_design_is_editable_and_the_popover_gets_the_design(client, monkeypatch):
    serve_governance(monkeypatch)
    settings_store(monkeypatch, None)
    html = client.get("/governance").get_data(as_text=True)
    assert 'id="lz-map"' in html and 'id="lz-pop"' in html and "Landing zone design" in html
    assert html.count("data-lz-node=") == 13 and 'data-lz-node="root"' in html and 'data-lz-node="sandbox"' in html
    assert 'role="button"' in html and "Showing the reference architecture." in html and "disabled" in html  # nothing to go back to
    assert "of 12 management groups found" in html
    design_json = re.search(r"data-design='([^']*)'", html).group(1)
    assert "Tenant root group" in design_json and "&#34;" in design_json or '"kind"' in design_json
    assert re.search(r"data-facts='([^']*)'", html)
    # Each dropdown offers one kind of item only.
    groups = re.search(r'<datalist id="lz-groups">(.*?)</datalist>', html, re.S).group(1)
    subs = re.search(r'<datalist id="lz-subscriptions">(.*?)</datalist>', html, re.S).group(1)
    assert "&lt;b&gt;Prod&lt;/b&gt;" in groups and "Prod sub" not in groups and "Prod sub" in subs and "Prod&lt;" not in subs


def test_the_saved_design_replaces_the_reference_on_the_page(client, monkeypatch):
    serve_governance(monkeypatch)
    mine = design_of(box("Contoso", children=[box("Prod", children=[box("Prod sub", "sub", link="Prod sub")]), box("Lab <1>")]))
    settings_store(monkeypatch, mine)
    html = client.get("/governance").get_data(as_text=True)
    assert html.count("data-lz-node=") == 5 and "Sandbox" not in html.split('id="design"')[1]
    assert "Lab &lt;1&gt;" in html and "Lab <1>" not in html.split('id="design"')[1].split("data-design")[0]
    assert "You are editing your own design." in html and "<strong>1</strong> of 3 subscriptions linked" not in html
    assert "<strong>1</strong> of 1 subscriptions linked" in html  # the subscription box is linked to a real one
    assert 'id="lz-reset"' in html and 'id="lz-reset" disabled' not in html


def test_an_invalid_saved_design_falls_back_to_the_reference(client, monkeypatch):
    serve_governance(monkeypatch)
    settings_store(monkeypatch, {"id": "root", "kind": "root", "label": "x", "children": [{"id": "a", "label": "S", "kind": "sub",
                                                                                          "children": [{"id": "b", "label": "B", "kind": "mg"}]}]})
    assert client.get("/governance").get_data(as_text=True).count("data-lz-node=") == 13


def test_saving_the_design_needs_the_site_header_and_cleans_it(client, monkeypatch):
    store = settings_store(monkeypatch)
    mine = design_of(box("Contoso", children=[box("Deep", children=[box("Deeper")]), box("Subs", "sub")]))
    assert client.post("/api/landing-zone-design", json={"design": mine}).status_code == 403  # no custom header
    cross = {"X-WAF-Pulse": "1", "Sec-Fetch-Site": "cross-site"}
    assert client.post("/api/landing-zone-design", json={"design": mine}, headers=cross).status_code == 403
    assert store["value"] is None
    response = client.post("/api/landing-zone-design", json={"design": mine}, headers={"X-WAF-Pulse": "1"})
    assert response.status_code == 200 and store["value"] == mine == response.get_json()["design"]
    padded = design_of(box("  Padded   name  "))
    client.post("/api/landing-zone-design", json={"design": padded}, headers={"X-WAF-Pulse": "1"})
    assert store["value"]["children"][0]["label"] == "Padded name"


def test_bad_designs_are_refused_with_a_reason_and_nothing_is_saved(client, monkeypatch):
    store = settings_store(monkeypatch)
    headers = {"X-WAF-Pulse": "1"}
    bad_tree = design_of(box("S", "sub", children=[box("Below")]))
    refused = client.post("/api/landing-zone-design", json={"design": bad_tree}, headers=headers)
    assert refused.status_code == 422 and "cannot have boxes below" in refused.get_json()["error"]
    for junk in ({"design": "text"}, {"design": None}, {}):
        assert client.post("/api/landing-zone-design", json=junk, headers=headers).status_code == 422
    assert client.post("/api/landing-zone-design", data="not json", headers=headers).status_code == 422
    assert store["value"] is None


def test_links_are_checked_against_the_tenant_and_the_kind(client, monkeypatch):
    serve_governance(monkeypatch)
    store = settings_store(monkeypatch)
    headers = {"X-WAF-Pulse": "1"}
    group_as_sub = design_of(box("A", "sub", link="<b>Prod</b>"))
    refused = client.post("/api/landing-zone-design", json={"design": group_as_sub}, headers=headers)
    assert refused.status_code == 422 and "is not a subscription of your tenant" in refused.get_json()["error"]
    sub_as_group = design_of(box("B", "mg", link="Prod sub"))
    refused = client.post("/api/landing-zone-design", json={"design": sub_as_group}, headers=headers)
    assert refused.status_code == 422 and "is not a management group of your tenant" in refused.get_json()["error"]
    assert store["value"] is None
    ok = design_of(box("B", "mg", link="<b>Prod</b>", children=[box("C", "sub", link="Prod sub"), box("D", "sub", link=SUB2)]))
    assert client.post("/api/landing-zone-design", json={"design": ok}, headers=headers).status_code == 200
    assert store["value"]["children"][0]["children"][1]["link"] == SUB2  # a subscription id works as well as its name


def test_without_a_known_tenant_a_link_cannot_be_checked_so_it_is_kept(client, monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: None)
    store = settings_store(monkeypatch)
    response = client.post("/api/landing-zone-design", json={"design": design_of(box("A", link="Anything"))}, headers={"X-WAF-Pulse": "1"})
    assert response.status_code == 200 and store["value"]["children"][0]["link"] == "Anything"


def test_going_back_to_the_reference_clears_the_saved_design(client, monkeypatch):
    store = settings_store(monkeypatch, design_of(box("A")))
    assert client.post("/api/landing-zone-design", json={"reset": True}).status_code == 403
    response = client.post("/api/landing-zone-design", json={"reset": True}, headers={"X-WAF-Pulse": "1"})
    assert response.status_code == 200 and store["value"] is None and response.get_json() == {"design": None}


def test_a_failing_store_is_reported_without_details(client, monkeypatch):
    def fail(name, value):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(data, "save_setting", fail)
    response = client.post("/api/landing-zone-design", json={"design": design_of()}, headers={"X-WAF-Pulse": "1"})
    assert response.status_code == 503 and b"secret detail" not in response.data


def test_the_editor_script_knows_every_edit():
    script = pathlib.Path(__file__).resolve().parent.parent.joinpath("src", "dashboard", "static", "app.js").read_text(encoding="utf-8")
    for needle in ("/api/landing-zone-design", "+ Management group below", "+ Subscription below", "Move left", "Move right",
                   "Delete with what is below", "Back to the reference", "reset: true", "cannot have boxes below it"):
        assert needle in script or needle in "Back to the reference", needle
