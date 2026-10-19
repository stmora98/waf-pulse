import json

import pytest

import app as dashboard_app
import data
import rightsizing
import scope
import scoring
from waf_pulse import scoring as collector_scoring

S1, S2, S3 = ("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333")
GROUPS = [{"name": "root", "displayName": "Tenant Root", "parent": None, "subscriptions": []},
          {"name": "prod-mg", "displayName": "Production", "parent": "root", "subscriptions": [S1]},
          {"name": "web-mg", "displayName": "Web", "parent": "prod-mg", "subscriptions": [S2]},
          {"name": "dev-mg", "displayName": "Development", "parent": "root", "subscriptions": [S3]}]
STORAGE = "microsoft.storage/storageaccounts"


def rid(sub, name, rg="rg"):
    return f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}"


def inv(sub, name, rg="rg", loc="eastus", tags=()):
    return {"id": rid(sub, name, rg), "name": name, "type": STORAGE, "subscriptionId": sub, "resourceGroup": rg, "location": loc, "detail": "", "tags": len(tags), "tagList": [list(t) for t in tags]}


ROWS = [inv(S1, "a", tags=[("env", "prod"), ("team", "pay")]), inv(S1, "a2", rg="rg2", loc="westus"), inv(S2, "b", tags=[("Env", "Prod")]), inv(S3, "c", loc="westus", tags=[("env", "dev")])]


def F(*items):
    return scope.sanitize({"filters": list(items)})


# --- the list of filters ------------------------------------------------------------------------------------

def test_sanitize_keeps_only_well_formed_filters():
    filters = F({"f": "sub", "op": "eq", "v": [S1.upper(), "not-a-guid", 5]}, {"f": "mg", "v": ["prod-mg", "bad;name"]},
                {"f": "loc", "op": "ne", "v": ["eastus", "eastus", "EastUS"]}, {"f": "bogus", "v": ["x"]}, {"f": "rg", "v": []},
                {"f": "tag", "k": "env", "op": "eq", "v": ["prod"]}, {"f": "tag", "k": "owner", "op": "ne"}, {"f": "tag", "v": ["x"]}, {"f": "tag", "k": "a=b", "v": []}, "junk")
    assert filters == [{"f": "sub", "op": "eq", "v": [S1]}, {"f": "mg", "op": "eq", "v": ["prod-mg"]}, {"f": "loc", "op": "ne", "v": ["eastus"]},
                       {"f": "tag", "op": "eq", "v": ["prod"], "k": "env"}, {"f": "tag", "op": "ne", "v": [], "k": "owner"}]
    assert scope.sanitize("junk") == [] and scope.sanitize(None) == [] and scope.sanitize({"filters": "x"}) == []
    assert len(scope.sanitize({"filters": [{"f": "rg", "v": [f"rg{i}"]} for i in range(40)]})) == scope.MAX_FILTERS


def test_names_are_only_labels_for_values_that_are_in_the_filter():
    entry = F({"f": "sub", "v": [S1], "n": {S1: "Prod", S2: "Other", "x": 5}})[0]
    assert entry["n"] == {S1: "Prod"} and scope.describe(entry) == "Subscription equals Prod"
    assert scope.sanitize([{"f": "sub", "v": [S1], "n": "junk"}])[0].get("n") is None
    assert len(F({"f": "sub", "v": [S1], "n": {S1: "A"}}, {"f": "sub", "v": [S1], "n": {S1: "B"}})) == 1  # the label does not make a filter different


def test_cookie_round_trip_old_cookies_and_descriptions():
    filters = F({"f": "sub", "op": "ne", "v": [S1]}, {"f": "tag", "k": "env", "v": ["prod", "dev"]}, {"f": "tag", "k": "owner", "op": "ne", "v": []})
    assert scope.decode(scope.encode(filters)) == filters
    assert [scope.describe(f) for f in filters] == [f"Subscription does not equal {S1}", "Tag env equals prod, dev", "Tag owner is missing"]
    assert scope.describe({"f": "tag", "k": "owner", "op": "eq", "v": []}) == "Tag owner exists"
    assert scope.decode("{bad") == [] and scope.decode(None) == [] and scope.label([]) == "No filters" and scope.label(filters) == "3 filters"
    legacy = scope.decode(json.dumps({"subs": [S1], "mgs": ["prod-mg"], "tags": ["env=prod", "env=dev", "team=pay"]}))
    assert [f["f"] for f in legacy] == ["sub", "mg", "tag", "tag"] and legacy[2] == {"f": "tag", "op": "eq", "v": ["prod", "dev"], "k": "env"}


def test_a_management_group_includes_everything_below_it_even_with_a_cycle():
    assert scope.group_subscriptions(GROUPS, ["prod-mg"]) == {S1, S2}
    assert scope.group_subscriptions(GROUPS, ["Development"]) == {S3}
    cyclic = [{"name": "a", "parent": "b", "subscriptions": [S1]}, {"name": "b", "parent": "a", "subscriptions": [S2]}]
    assert scope.group_subscriptions(cyclic, ["a"]) == {S1, S2} and scope.group_subscriptions(GROUPS, ["missing"]) == set()


# --- matching -----------------------------------------------------------------------------------------------------

def finding(sub, name, rule="SEC-STG-001", severity="high", pillar="Security", rg="rg"):
    return {"ruleId": rule, "resourceId": rid(sub, name, rg), "subscriptionId": sub, "resourceName": name, "resourceType": STORAGE,
            "title": rule, "severity": severity, "pillar": pillar, "source": "builtin", "recommendation": "x"}


def names(resolved, rows=ROWS):
    return [r["name"] for r in rows if resolved.row_ok(r)]


def test_subscription_and_group_filters_with_equals_and_does_not_equal():
    r = lambda *filters: scope.resolve(F(*filters), GROUPS, ROWS)
    assert names(r({"f": "sub", "v": [S1]})) == ["a", "a2"]
    assert names(r({"f": "sub", "op": "ne", "v": [S1]})) == ["b", "c"]
    assert names(r({"f": "mg", "v": ["prod-mg"]})) == ["a", "a2", "b"]
    assert names(r({"f": "mg", "op": "ne", "v": ["web-mg"]})) == ["a", "a2", "c"]
    assert names(r({"f": "mg", "v": ["prod-mg"]}, {"f": "sub", "op": "ne", "v": [S1]})) == ["b"]  # every filter has to hold
    assert not scope.resolve(F(), GROUPS).active and scope.resolve(F(), GROUPS).row_ok({"id": "x"})
    assert r({"f": "sub", "op": "ne", "v": [S1]}).sub_ok("tenant") is False  # tenant objects are in no subscription


def test_resource_filters_use_the_inventory():
    r = lambda *filters: scope.resolve(F(*filters), GROUPS, ROWS)
    assert names(r({"f": "rg", "v": ["RG2"]})) == ["a2"]
    assert names(r({"f": "loc", "v": ["westus"]})) == ["a2", "c"]
    assert names(r({"f": "loc", "op": "ne", "v": ["westus"]})) == ["a", "b"]
    assert names(r({"f": "type", "v": [STORAGE.upper()]})) == ["a", "a2", "b", "c"]
    assert names(r({"f": "tag", "k": "ENV", "v": ["PROD"]})) == ["a", "b"]  # keys and values match whatever the case
    assert names(r({"f": "tag", "k": "env", "v": ["prod", "dev"]})) == ["a", "b", "c"]
    assert names(r({"f": "tag", "k": "team", "v": []})) == ["a"]  # has the tag, any value
    assert names(r({"f": "tag", "k": "team", "op": "ne", "v": []})) == ["a2", "b", "c"]  # lacks the tag
    assert names(r({"f": "tag", "k": "env", "op": "ne", "v": ["prod"]}, {"f": "loc", "v": ["westus"]})) == ["a2", "c"]


def test_findings_follow_the_filters_and_non_resources_leave_resource_level_ones():
    r = scope.resolve(F({"f": "tag", "k": "env", "v": ["prod"]}), GROUPS, ROWS)
    assert r.finding_ok(finding(S1, "A")) and not r.finding_ok(finding(S3, "c"))
    assert not r.finding_ok({"resourceId": f"/subscriptions/{S1}", "subscriptionId": S1, "resourceType": ""})
    assert not r.finding_ok(finding(S1, "unknown-to-the-inventory"))  # tags unknown
    by_rg = scope.resolve(F({"f": "rg", "v": ["rg2"]}), GROUPS, ROWS)
    group_finding = {"resourceId": f"/subscriptions/{S1}/resourceGroups/rg2", "subscriptionId": S1, "resourceType": ""}
    assert by_rg.finding_ok(group_finding) and by_rg.finding_ok(finding(S1, "zzz", rg="rg2")) and not by_rg.finding_ok(finding(S1, "a"))
    by_sub = scope.resolve(F({"f": "sub", "v": [S1]}), GROUPS)
    assert by_sub.finding_ok({"resourceId": f"/subscriptions/{S1}", "subscriptionId": S1.upper()}) and not by_sub.finding_ok({"subscriptionId": S2})
    assert by_sub.row_ok({"id": rid(S1, "x")}) and not by_sub.row_ok({"id": rid(S2, "x")})
    assert scope.subscription_of("/tenant/users/1") == ""


# --- scores -------------------------------------------------------------------------------------------------------

def stat(rule, pillar, severity, sub, affected, applicable, types=None, source="builtin"):
    return {"r": rule, "p": pillar, "v": severity, "s": source, "u": sub, "a": affected, "n": applicable, "t": types}


RULESTATS = [
    stat("SEC-STG-001", "Security", "high", S1, 1, 2, [STORAGE]), stat("SEC-STG-001", "Security", "high", S2, 0, 1, [STORAGE]), stat("SEC-STG-001", "Security", "high", S3, 1, 1, [STORAGE]),
    stat("COST-X", "Cost Optimization", "medium", S1, 1, 4, ["*"]), stat("COST-X", "Cost Optimization", "medium", S2, 0, 3, ["*"]),
    stat("OPS-DIAG-001", "Operational Excellence", "medium", S1, 2, 5, None, "diagnostics"), stat("COST-STG-002", "Cost Optimization", "low", S1, 1, 2, [STORAGE]),
    stat("ENTRA-1", "Security", "medium", "tenant", 1, 4, None, "entra"),
]
FINDINGS = [finding(S1, "a"), finding(S3, "c"), finding(S1, "a", rule="COST-X", pillar="Cost Optimization", severity="medium"),
            finding(S1, "a2", rule="OPS-DIAG-001", pillar="Operational Excellence", severity="medium")]
SUMMARY = {"runId": "r1", "scores": {"Security": 40}, "resourceCount": 30, "subscriptionCount": 3, "findingCount": 9, "diagnostics": {"checked": 5, "withLogs": 3, "percent": 60.0, "byType": [{"x": 1}], "skipped": {}},
           "lifecycle": {"checked": 2, "withPolicy": 1, "percent": 50.0}, "governance": {"managementGroups": GROUPS, "defender": {"plans": 4, "enabled": 2, "detail": [
               {"plan": "VMs", "tier": "Standard", "subscriptionId": S1}, {"plan": "SQL", "tier": "Free", "subscriptionId": S1}, {"plan": "VMs", "tier": "Standard", "subscriptionId": S2}, {"plan": "VMs", "tier": "Free", "subscriptionId": S3}]}},
           "subscriptions": [{"id": S1, "name": "Prod", "resourceCount": 10, "findingCount": 3, "scores": {}}, {"id": S2, "name": "Web", "resourceCount": 30, "findingCount": 0, "scores": {}},
                             {"id": S3, "name": "Dev", "resourceCount": 5, "findingCount": 1, "scores": {}}],
           "secureScore": {"average": 60.0, "subscriptions": [{"subscriptionId": S1, "name": "Prod", "percentage": 40.0}, {"subscriptionId": S2, "name": "Web", "percentage": 80.0}, {"subscriptionId": S3, "name": "Dev", "percentage": None}],
                           "topControls": [{"control": "MFA", "unhealthy": 3, "healthy": 1}]},
           "advisorSavings": {"USD": 900.0}, "advisorSavingsBySubscription": {S1: {"USD": 300.0}, S2: {"USD": 600.0}},
           "commitments": {"items": [{"subscriptionId": S1, "currency": "USD", "terms": {"P1Y": 100.0, "P3Y": 250.0}}, {"subscriptionId": S2, "currency": "USD", "terms": {"P1Y": 50.0}}],
                           "totals": {"USD": {"P1Y": 150.0, "P3Y": 250.0}}}}


def as_collector(rows):
    return [{"ruleId": r["r"], "pillar": r["p"], "severity": r["v"], "affected": r["a"], "applicable": r["n"]} for r in rows]


def test_dashboard_scoring_is_the_collectors_scoring():
    for stats in (as_collector(RULESTATS), as_collector(RULESTATS[:3]), []):
        assert scoring.score_pillars(scoring.merge_rule_stats(stats)) == collector_scoring.score_pillars(collector_scoring.merge_rule_stats([stats]))
    assert scoring.PILLARS == tuple(collector_scoring.PILLARS) and scoring.WEIGHTS == collector_scoring.WEIGHTS and scoring.SEVERITY_CAPS == collector_scoring.SEVERITY_CAPS


def test_a_filter_on_subscriptions_scores_those_subscriptions_exactly():
    everything = scope.scoped_stats(RULESTATS, scope.resolve(F({"f": "sub", "op": "ne", "v": ["00000000-0000-0000-0000-000000000000"]}), GROUPS))
    assert len(everything) == len(RULESTATS) - 1  # the tenant level row is in no subscription
    only = scope.apply_summary(SUMMARY, scope.resolve(F({"f": "mg", "v": ["web-mg"]}), GROUPS), RULESTATS, None)
    assert only["scores"]["Security"] == 100 and only["scores"]["Cost Optimization"] == 100 and only["scoped"] is True
    both = scope.apply_summary(SUMMARY, scope.resolve(F({"f": "sub", "v": [S1, S3]}), GROUPS), RULESTATS, None)
    assert both["scores"]["Security"] == 33  # 2 of 3 storage accounts are affected: 100 - 2/3 * 100
    assert both["subscriptionCount"] == 2 and both["resourceCount"] == 15 and [s["name"] for s in both["subscriptions"]] == ["Prod", "Dev"]


def test_resource_filters_count_the_affected_resources_and_scale_what_a_rule_evaluates():
    resolved = scope.resolve(F({"f": "tag", "k": "env", "v": ["prod"]}), GROUPS, ROWS)
    stats = {(s["ruleId"], s["subscription"]): (s["affected"], s["applicable"]) for s in scope.scoped_stats(RULESTATS, resolved, FINDINGS)}
    assert stats == {("SEC-STG-001", S1): (1, 1),  # one of the two accounts of S1 carries the tag, and it is the affected one
                     ("SEC-STG-001", S2): (0, 1),
                     ("COST-X", S1): (1, 2), ("COST-X", S2): (0, 3),  # a rule over every type: scaled by the share of the resources that stay
                     ("OPS-DIAG-001", S1): (0, 2), ("COST-STG-002", S1): (0, 1)}  # S3 has no tagged resource and the tenant level row has no subscription
    summary = scope.apply_summary(SUMMARY, resolved, RULESTATS, FINDINGS)
    assert summary["resourceCount"] == 2 and summary["scores"]["Security"] is not None and summary["diagnostics"]["checked"] >= 0
    assert any("only the subscription and management group filters" in n for n in summary["scopeNotes"])


def test_applicable_never_drops_below_what_is_affected():
    resolved = scope.resolve(F({"f": "loc", "v": ["westus"]}), GROUPS, ROWS)
    for item in scope.scoped_stats(RULESTATS, resolved, FINDINGS):
        assert item["applicable"] >= item["affected"] > -1 and item["applicable"] > 0


def test_insights_kept_per_subscription_follow_the_filters():
    summary = scope.apply_summary(SUMMARY, scope.resolve(F({"f": "sub", "v": [S1]}), GROUPS), RULESTATS, None)
    assert summary["secureScore"]["average"] == 40.0 and [s["name"] for s in summary["secureScore"]["subscriptions"]] == ["Prod"] and summary["secureScore"]["controlsTenantWide"]
    assert summary["governance"]["defender"]["plans"] == 2 and summary["governance"]["defender"]["enabled"] == 1 and SUMMARY["governance"]["defender"]["plans"] == 4
    assert summary["advisorSavings"] == {"USD": 300.0}
    assert [i["subscriptionId"] for i in summary["commitments"]["items"]] == [S1] and summary["commitments"]["totals"] == {"USD": {"P1Y": 100.0, "P3Y": 250.0}}
    assert summary["diagnostics"]["checked"] == 5 and summary["diagnostics"]["withLogs"] == 3 and summary["diagnostics"]["byType"] == []
    assert summary["lifecycle"]["checked"] == 2 and summary["lifecycle"]["withPolicy"] == 1
    other = scope.apply_summary(SUMMARY, scope.resolve(F({"f": "sub", "v": [S2]}), GROUPS), RULESTATS, None)
    assert other["diagnostics"]["percent"] is None and other["advisorSavings"] == {"USD": 600.0} and other["commitments"]["totals"] == {"USD": {"P1Y": 50.0}}
    assert scope.apply_summary(SUMMARY, scope.resolve(F(), GROUPS)) is SUMMARY and scope.apply_summary(None, scope.resolve(F({"f": "sub", "v": [S1]}))) is None


def test_without_rule_statistics_the_summary_says_scores_are_missing():
    summary = scope.apply_summary(SUMMARY, scope.resolve(F({"f": "sub", "v": [S1]}), GROUPS), [], None)
    assert summary["scores"] == {} and any("refresh" in n for n in summary["scopeNotes"])
    truncated = scope.apply_summary(SUMMARY, scope.resolve(F({"f": "rg", "v": ["rg"]}), GROUPS, ROWS, truncated=True), RULESTATS, FINDINGS)
    assert any("truncated" in n for n in truncated["scopeNotes"])


def test_options_list_every_field_with_counts():
    found = scope.options(SUMMARY, ROWS)
    fields = found["fields"]
    assert [o["text"] for o in fields["sub"]["options"]] == ["Dev", "Prod", "Web"]
    assert [o["text"] for o in fields["mg"]["options"]] == ["Development", "Production", "Tenant Root", "Web"]
    assert fields["rg"]["options"][0] == {"value": "rg", "text": "rg", "count": 3} and fields["loc"]["options"][0] == {"value": "eastus", "text": "eastus", "count": 2}
    assert fields["type"]["options"] == [{"value": STORAGE, "text": STORAGE, "count": 4}]
    keys = {k["key"]: k for k in fields["tag"]["keys"]}
    assert keys["env"]["count"] == 2 and keys["Env"]["count"] == 1 and keys["env"]["values"][0] == {"value": "dev", "count": 1} and found["tagsAvailable"] is True
    old = scope.options(SUMMARY, [{"id": "x"}])
    assert old["tagsAvailable"] is False and old["fields"]["tag"]["keys"] == []


def test_scope_metrics_keeps_the_rows_counts_them_again_and_lists_the_worst():
    metrics = {"distribution": {"vm": {"idle": 2, "under": 0, "right": 0, "saturated": 0, "nodata": 4}}, "measured": {"vm": 6}, "resources": [
        {"kind": "vm", "id": rid(S1, "a"), "subscriptionId": S1, "assessment": "idle", "avg": 2.0, "name": "a", "detail": "D2"},
        {"kind": "vm", "id": rid(S2, "b"), "subscriptionId": S2, "assessment": "saturated", "avg": 95.0, "name": "b", "detail": "D4"}]}
    scoped = rightsizing.scope_metrics(metrics, scope.resolve(F({"f": "sub", "v": [S1]}), GROUPS).row_ok)
    assert len(scoped["resources"]) == 1 and scoped["distribution"]["vm"] == {"idle": 1, "under": 0, "right": 0, "saturated": 0, "nodata": 0}
    assert scoped["measured"] == {"vm": 1} and scoped["topUnderutilized"] == [{"name": "a", "detail": "D2", "value": 2.0}] and scoped["topSaturated"] == []
    assert rightsizing.scope_metrics(None, lambda r: True) is None
    by_tag = rightsizing.scope_metrics(metrics, scope.resolve(F({"f": "tag", "k": "env", "v": ["prod"]}), GROUPS, ROWS).row_ok)
    assert [r["name"] for r in by_tag["resources"]] == ["a", "b"]  # the inventory knows the tags of the resource behind each row


# --- pages -----------------------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: json.loads(json.dumps(SUMMARY)))
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: list(FINDINGS))
    monkeypatch.setattr(data, "resources", lambda run_id: (list(ROWS), False))
    monkeypatch.setattr(data, "get_setting", lambda name: None)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: list(RULESTATS) if kind == "rulestats" else [])
    monkeypatch.setattr(data, "history", lambda limit=30: [])


def with_filters(client, *filters):
    client.set_cookie(scope.COOKIE, scope.encode(F(*filters)), domain="localhost")


def test_overview_without_filters_shows_the_runs_own_numbers(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/").get_data(as_text=True)
    assert 'id="scope-bar"' in html and "+ Add filter" in html and "Resources: <strong>30</strong>" in html and "Clear all" not in html


def test_overview_with_filters_scores_and_counts_what_is_left(client, monkeypatch):
    serve(monkeypatch)
    with_filters(client, {"f": "mg", "v": ["web-mg"]})
    html = client.get("/").get_data(as_text=True)
    assert "Management group equals web-mg" in html and "Clear all" in html and "Resources: <strong>30</strong>" in html and "Subscriptions: <strong>1</strong>" in html
    assert 'data-scope-remove="0"' in html


def test_filters_on_tags_change_what_the_lists_and_scores_show(client, monkeypatch):
    serve(monkeypatch)
    with_filters(client, {"f": "tag", "k": "env", "v": ["dev"]})
    html = client.get("/").get_data(as_text=True)
    assert "Findings: <strong>1</strong>" in html and "Resources: <strong>1</strong>" in html and "Tag env equals dev" in html
    resources = client.get("/resources").get_data(as_text=True)
    assert ">c<" in resources and ">a<" not in resources
    assert "1 resource(s) affected" in client.get("/actions").get_data(as_text=True)
    assert "Security" in client.get("/pillar/security").get_data(as_text=True)


def test_the_cost_history_and_governance_pages_say_they_ignore_the_filters(client, monkeypatch):
    serve(monkeypatch)
    with_filters(client, {"f": "sub", "v": [S1]})
    assert "always shows the whole tenant" in client.get("/history").get_data(as_text=True)
    assert "always shows the whole tenant" not in client.get("/actions").get_data(as_text=True)


def test_a_resource_outside_the_filters_still_opens(client, monkeypatch):
    serve(monkeypatch)
    with_filters(client, {"f": "sub", "v": [S1]})
    assert client.get("/resource?id=" + rid(S3, "c")).status_code == 200


def test_scope_api_sets_and_clears_the_cookie(client, monkeypatch):
    headers = {"X-WAF-Pulse": "1"}
    body = {"filters": [{"f": "sub", "op": "ne", "v": [S1, "bad"]}, {"f": "tag", "k": "env", "v": ["prod"]}, {"f": "x", "v": ["y"]}]}
    assert client.post("/api/scope", json=body).status_code == 403
    ok = client.post("/api/scope", json=body, headers=headers)
    assert ok.status_code == 200 and ok.get_json()["filters"] == [{"f": "sub", "op": "ne", "v": [S1]}, {"f": "tag", "op": "eq", "v": ["prod"], "k": "env"}]
    cookie = ok.headers["Set-Cookie"]
    assert cookie.startswith(scope.COOKIE + "=") and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    cleared = client.post("/api/scope", json={"clear": True}, headers=headers)
    assert cleared.get_json()["label"] == "No filters" and "Expires=" in cleared.headers["Set-Cookie"]
    big = {"filters": [{"f": "rg", "v": [f"group-{i:03d}-" + "x" * 60 for i in range(50)]} for _ in range(1)] + [{"f": "tag", "k": f"k{i}", "v": ["v" * 60] * 1} for i in range(11)]}
    assert client.post("/api/scope", json=big, headers=headers).status_code == 422


def test_scope_options_api(client, monkeypatch):
    serve(monkeypatch)
    body = client.get("/api/scope-options").get_json()
    assert len(body["options"]["fields"]["sub"]["options"]) == 3 and body["options"]["tagsAvailable"] is True and body["current"] == []
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: (_ for _ in ()).throw(RuntimeError("down")))
    assert client.get("/api/scope-options").status_code == 503


def test_tampered_and_old_cookies(client, monkeypatch):
    serve(monkeypatch)
    client.set_cookie(scope.COOKIE, "{not json", domain="localhost")
    assert "Clear all" not in client.get("/").get_data(as_text=True)
    client.set_cookie(scope.COOKIE, json.dumps([{"f": "sub", "v": ["'; drop"]}, {"f": "<b>", "v": ["x"]}]), domain="localhost")
    assert "Clear all" not in client.get("/").get_data(as_text=True)
    client.set_cookie(scope.COOKIE, json.dumps({"subs": [S1], "mgs": [], "tags": ["env=prod"]}), domain="localhost")  # a cookie of the first version
    html = client.get("/").get_data(as_text=True)
    assert "Tag env equals prod" in html and f"Subscription equals {S1}" in html


def test_without_rule_statistics_the_page_still_renders(client, monkeypatch):
    serve(monkeypatch)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: (_ for _ in ()).throw(RuntimeError("down")) if kind == "rulestats" else [])
    with_filters(client, {"f": "sub", "v": [S1]})
    assert "refresh to see scores" in client.get("/").get_data(as_text=True)

def test_the_cost_page_adds_the_spend_of_the_filtered_resources(client, monkeypatch):
    serve(monkeypatch)
    summary = {**json.loads(json.dumps(SUMMARY)), "finops": {"currency": "USD", "months": [], "coverage": {}}}
    monkeypatch.setattr(data, "summary", lambda run_id: json.loads(json.dumps(summary)))
    costs = [{"id": rid(S1, "a").lower(), "cost": 300.0}, {"id": rid(S3, "c").lower(), "cost": 100.0}, {"id": "/subscriptions/x/gone", "cost": 50.0}]
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: list(RULESTATS) if kind == "rulestats" else (costs if kind == "costs" else []))
    plain = client.get("/pillar/cost").get_data(as_text=True)
    assert "Spend of the filtered resources" not in plain
    with_filters(client, {"f": "tag", "k": "env", "v": ["prod"]})
    html = client.get("/pillar/cost").get_data(as_text=True)
    assert "Spend of the filtered resources" in html and ">300<" in html and "1 resource(s)" in html and "66.7% of the listed spend" in html
    assert "50 USD of that belongs to resources the inventory does not list" in html and "always for the whole tenant" in html
    assert "always shows the whole tenant" not in html and "By resource group" in html and ">100<" not in html
    with_filters(client, {"f": "loc", "v": ["nowhere"]})
    assert "No resource with cost matches" in client.get("/pillar/cost").get_data(as_text=True)
