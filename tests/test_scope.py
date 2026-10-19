import json

import pytest

import app as dashboard_app
import data
import rightsizing
import scope

S1, S2, S3 = ("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333")
GROUPS = [{"name": "root", "displayName": "Tenant Root", "parent": None, "subscriptions": []},
          {"name": "prod-mg", "displayName": "Production", "parent": "root", "subscriptions": [S1]},
          {"name": "web-mg", "displayName": "Web", "parent": "prod-mg", "subscriptions": [S2]},
          {"name": "dev-mg", "displayName": "Development", "parent": "root", "subscriptions": [S3]}]


def rid(sub, name):
    return f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}"


ROWS = [
    {"id": rid(S1, "a"), "name": "a", "type": "microsoft.storage/storageaccounts", "subscriptionId": S1, "resourceGroup": "rg", "location": "eastus", "detail": "", "tags": 2,
     "tagList": [["env", "prod"], ["team", "pay"]]},
    {"id": rid(S2, "b"), "name": "b", "type": "microsoft.storage/storageaccounts", "subscriptionId": S2, "resourceGroup": "rg", "location": "eastus", "detail": "", "tags": 1,
     "tagList": [["Env", "Prod"]]},
    {"id": rid(S3, "c"), "name": "c", "type": "microsoft.storage/storageaccounts", "subscriptionId": S3, "resourceGroup": "rg", "location": "eastus", "detail": "", "tags": 1,
     "tagList": [["env", "dev"]]},
]


# --- the module ---------------------------------------------------------------------------------------------

def test_sanitize_drops_everything_malformed():
    chosen = scope.sanitize({"subs": [S1.upper(), S1, "not-a-guid", 5, None], "mgs": ["prod-mg", "bad;name", "Prod-MG"], "tags": ["env=prod", "no-equals", "a=b\nc", "env=prod"]})
    assert chosen == {"subs": [S1], "mgs": ["prod-mg"], "tags": ["env=prod"]}
    assert scope.sanitize("junk") == {"subs": [], "mgs": [], "tags": []}
    assert len(scope.sanitize({"subs": [f"{i:08d}-1111-1111-1111-111111111111" for i in range(80)]})["subs"]) == scope.MAX_ITEMS


def test_cookie_round_trip_and_label():
    chosen = scope.sanitize({"subs": [S1, S2], "mgs": ["prod-mg"], "tags": ["env=prod"]})
    assert scope.decode(scope.encode(chosen)) == chosen
    assert scope.decode("{bad json") == {"subs": [], "mgs": [], "tags": []} and scope.decode(None) == {"subs": [], "mgs": [], "tags": []}
    assert scope.label(chosen) == "2 subscriptions · 1 management group · 1 tag"
    assert scope.label(scope.sanitize({})) == "Everything" and not scope.is_active(scope.sanitize({}))


def test_a_management_group_includes_everything_below_it_even_with_a_cycle():
    assert scope.group_subscriptions(GROUPS, ["prod-mg"]) == {S1, S2}
    assert scope.group_subscriptions(GROUPS, ["Development"]) == {S3}
    assert scope.group_subscriptions(GROUPS, ["root"]) == {S1, S2, S3}
    cyclic = [{"name": "a", "parent": "b", "subscriptions": [S1]}, {"name": "b", "parent": "a", "subscriptions": [S2]}]
    assert scope.group_subscriptions(cyclic, ["a"]) == {S1, S2}
    assert scope.group_subscriptions(GROUPS, ["missing"]) == set()


def test_resolve_combines_subscriptions_groups_and_tags():
    everything = scope.resolve(scope.sanitize({}), GROUPS, ROWS)
    assert not everything.active and everything.row_ok(ROWS[0])
    groups = scope.resolve(scope.sanitize({"mgs": ["prod-mg"], "subs": [S3]}), GROUPS, ROWS)
    assert [r["name"] for r in ROWS if groups.row_ok(r)] == ["a", "b", "c"]
    only = scope.resolve(scope.sanitize({"mgs": ["web-mg"]}), GROUPS, ROWS)
    assert [r["name"] for r in ROWS if only.row_ok(r)] == ["b"]
    tagged = scope.resolve(scope.sanitize({"tags": ["env=prod"]}), GROUPS, ROWS)  # keys and values match whatever the case
    assert [r["name"] for r in ROWS if tagged.row_ok(r)] == ["a", "b"]
    both = scope.resolve(scope.sanitize({"tags": ["env=prod", "team=pay"]}), GROUPS, ROWS)
    assert [r["name"] for r in ROWS if both.row_ok(r)] == ["a"]
    either = scope.resolve(scope.sanitize({"tags": ["env=prod", "env=dev"]}), GROUPS, ROWS)
    assert [r["name"] for r in ROWS if either.row_ok(r)] == ["a", "b", "c"]
    mixed = scope.resolve(scope.sanitize({"subs": [S2], "tags": ["env=prod"]}), GROUPS, ROWS)
    assert [r["name"] for r in ROWS if mixed.row_ok(r)] == ["b"]


def test_findings_follow_the_scope_and_subscription_level_findings_leave_a_tag_scope():
    tagged = scope.resolve(scope.sanitize({"tags": ["env=prod"]}), GROUPS, ROWS)
    assert tagged.finding_ok({"resourceId": rid(S1, "A"), "subscriptionId": S1})
    assert not tagged.finding_ok({"resourceId": f"/subscriptions/{S1}", "subscriptionId": S1})
    by_sub = scope.resolve(scope.sanitize({"subs": [S1]}), GROUPS, ROWS)
    assert by_sub.finding_ok({"resourceId": f"/subscriptions/{S1}", "subscriptionId": S1.upper()}) and not by_sub.finding_ok({"subscriptionId": S2})
    assert by_sub.row_ok({"id": rid(S1, "x")}) and not by_sub.row_ok({"id": rid(S2, "x")})  # the subscription comes from the id
    assert scope.subscription_of("/tenant/users/1") == ""


SUMMARY = {"runId": "r1", "scores": {"Security": 40, "Cost Optimization": 80}, "resourceCount": 30, "subscriptionCount": 3, "findingCount": 9,
           "governance": {"managementGroups": GROUPS}, "subscriptions": [
               {"id": S1, "name": "Prod", "resourceCount": 10, "scores": {"Security": 20, "Cost Optimization": 100}},
               {"id": S2, "name": "Web", "resourceCount": 30, "scores": {"Security": 60, "Cost Optimization": None}},
               {"id": S3, "name": "Dev", "resourceCount": 0, "scores": {"Security": 90, "Cost Optimization": 50}}]}


def test_scores_of_a_scope_are_weighted_by_resources():
    scoped = scope.apply_summary(SUMMARY, scope.resolve(scope.sanitize({"subs": [S1, S2]}), GROUPS, ROWS))
    assert scoped["scores"] == {"Security": 50, "Cost Optimization": 100} and scoped["resourceCount"] == 40 and scoped["subscriptionCount"] == 2
    assert [s["name"] for s in scoped["subscriptions"]] == ["Prod", "Web"] and scoped["scoped"] and SUMMARY["resourceCount"] == 30
    assert scope.apply_summary(SUMMARY, scope.Resolved()) is SUMMARY and scope.apply_summary(None, scope.Resolved(subs=set())) is None
    tag = scope.apply_summary(SUMMARY, scope.resolve(scope.sanitize({"tags": ["env=prod"]}), GROUPS, ROWS))
    both = scope.apply_summary(SUMMARY, scope.resolve(scope.sanitize({"tags": ["env=prod"], "subs": [S2]}), GROUPS, ROWS))
    assert both["resourceCount"] == 1 and [s["name"] for s in both["subscriptions"]] == ["Web"]
    assert tag["scores"] == {} and tag["resourceCount"] == 2 and "only the findings" in tag["scopeNote"]


def test_options_list_subscriptions_groups_and_tags():
    found = scope.options(SUMMARY, ROWS)
    assert [s["name"] for s in found["subscriptions"]] == ["Dev", "Prod", "Web"]
    assert [g["displayName"] for g in found["managementGroups"]] == ["Development", "Production", "Tenant Root", "Web"]
    assert found["tagsAvailable"] is True
    keys = {t["key"]: t for t in found["tags"]}
    assert keys["env"]["total"] == 2 and keys["Env"]["total"] == 1 and keys["env"]["values"][0] == {"value": "dev", "count": 1}
    old = scope.options(SUMMARY, [{"id": "x"}])
    assert old["tagsAvailable"] is False and old["tags"] == []


def test_scope_metrics_keeps_the_rows_and_counts_them_again():
    metrics = {"distribution": {"vm": {"idle": 2, "under": 0, "right": 0, "saturated": 0, "nodata": 4}}, "resources": [
        {"kind": "vm", "id": rid(S1, "a"), "subscriptionId": S1, "assessment": "idle"}, {"kind": "vm", "id": rid(S2, "b"), "subscriptionId": S2, "assessment": "idle"}]}
    scoped = rightsizing.scope_metrics(metrics, lambda r: r["subscriptionId"] == S1)
    assert len(scoped["resources"]) == 1 and scoped["distribution"]["vm"] == {"idle": 1, "under": 0, "right": 0, "saturated": 0, "nodata": 0}
    assert rightsizing.scope_metrics(None, lambda r: True) is None


# --- pages -----------------------------------------------------------------------------------------------------

def finding(sub, name, rule="SEC-STG-001", severity="high", pillar="Security"):
    return {"ruleId": rule, "resourceId": rid(sub, name), "subscriptionId": sub, "resourceName": name, "resourceType": "microsoft.storage/storageaccounts",
            "title": rule, "severity": severity, "pillar": pillar, "source": "builtin", "recommendation": "x"}


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: dict(SUMMARY))
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [finding(S1, "a"), finding(S2, "b"), finding(S3, "c")])
    monkeypatch.setattr(data, "resources", lambda run_id: (list(ROWS), False))
    monkeypatch.setattr(data, "get_setting", lambda name: None)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: [])
    monkeypatch.setattr(data, "history", lambda limit=30: [])


def with_scope(client, **chosen):
    client.set_cookie(scope.COOKIE, scope.encode(scope.sanitize(chosen)), domain="localhost")


def test_overview_without_a_scope_shows_everything(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/").get_data(as_text=True)
    assert "Scope: Everything" in html and 'id="scope-btn"' in html and "Resources: <strong>30</strong>" in html


def test_overview_with_a_scope_counts_only_what_is_in_it(client, monkeypatch):
    serve(monkeypatch)
    with_scope(client, mgs=["web-mg"])
    html = client.get("/").get_data(as_text=True)
    assert "Scope: 1 management group" in html and "Resources: <strong>30</strong>" in html and "Findings: <strong>1</strong>" in html
    assert "weighted by their number of resources" in html and "Subscriptions: <strong>1</strong>" in html


def test_action_items_and_the_resource_list_follow_the_scope(client, monkeypatch):
    serve(monkeypatch)
    with_scope(client, tags=["env=dev"])
    actions = client.get("/actions").get_data(as_text=True)
    assert "1 resource(s) affected" in actions
    resources = client.get("/resources").get_data(as_text=True)
    assert ">c<" in resources and ">a<" not in resources and ">b<" not in resources


def test_the_cost_and_governance_pages_say_they_ignore_the_scope(client, monkeypatch):
    serve(monkeypatch)
    with_scope(client, subs=[S1])
    assert "always shows the whole tenant" in client.get("/history").get_data(as_text=True)
    assert "always shows the whole tenant" not in client.get("/actions").get_data(as_text=True)


def test_a_resource_outside_the_scope_still_opens(client, monkeypatch):
    serve(monkeypatch)
    with_scope(client, subs=[S1])
    assert client.get("/resource?id=" + rid(S3, "c")).status_code == 200


def test_scope_api_sets_and_clears_the_cookie(client, monkeypatch):
    headers = {"X-WAF-Pulse": "1"}
    assert client.post("/api/scope", json={"subs": [S1]}).status_code == 403
    ok = client.post("/api/scope", json={"subs": [S1, "bad"], "tags": ["env=prod"], "extra": 1}, headers=headers)
    assert ok.status_code == 200 and ok.get_json()["scope"] == {"subs": [S1], "mgs": [], "tags": ["env=prod"]}
    cookie = ok.headers["Set-Cookie"]
    assert cookie.startswith(scope.COOKIE + "=") and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    cleared = client.post("/api/scope", json={"clear": True}, headers=headers)
    assert cleared.get_json()["label"] == "Everything" and "Expires=" in cleared.headers["Set-Cookie"]
    forged = client.post("/api/scope", json={"subs": ["<script>"]}, headers=headers)
    assert forged.get_json()["scope"]["subs"] == []


def test_scope_options_api(client, monkeypatch):
    serve(monkeypatch)
    body = client.get("/api/scope-options").get_json()
    assert len(body["options"]["subscriptions"]) == 3 and body["options"]["tagsAvailable"] is True and body["current"] == {"subs": [], "mgs": [], "tags": []}
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: (_ for _ in ()).throw(RuntimeError("down")))
    assert client.get("/api/scope-options").status_code == 503


def test_a_tampered_cookie_is_ignored(client, monkeypatch):
    serve(monkeypatch)
    client.set_cookie(scope.COOKIE, "{not json", domain="localhost")
    assert "Scope: Everything" in client.get("/").get_data(as_text=True)
    client.set_cookie(scope.COOKIE, json.dumps({"subs": ["'; drop"], "mgs": ["<b>"], "tags": [5]}), domain="localhost")
    assert "Scope: Everything" in client.get("/").get_data(as_text=True)
