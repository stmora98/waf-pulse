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
    assert dataset["defender"] == {"plans": 2, "enabled": 1, "notEnabled": ["SqlServers"]}
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
    findings, stats, dataset, errors = governance.collect(None, "r", [SUB])
    assert [e["ruleId"] for e in errors] == ["governance-compliance"]
    assert "GOV-LOCK-001" in {s["ruleId"] for s in stats}


def test_every_query_is_defined_and_has_a_name():
    assert {"managementGroups", "subscriptions", "assignments", "compliance", "exemptions", "owners", "locks",
            "defender", "rolesByPrincipal", "customRoles", "customDefinitions"} == set(governance.QUERIES)
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
    assert "Subscriptions without a visible management group" in html
    assert "<b>Prod</b>" not in html and "&lt;b&gt;Prod&lt;/b&gt;" in html
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
