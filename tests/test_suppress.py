from datetime import date, datetime, timezone

import pytest

import app as dashboard_app
import data
import suppress
from waf_pulse import suppress as collector

SUB = "11111111-1111-1111-1111-111111111111"
RID = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def finding(rule, resource, sub=SUB):
    return {"ruleId": rule, "resourceId": resource, "subscriptionId": sub, "resourceName": resource.rsplit("/", 1)[-1], "title": rule,
            "severity": "high", "pillar": "Security", "source": "builtin", "recommendation": "x"}


# --- the dashboard module ---------------------------------------------------------------------------------

def test_add_builds_an_entry_with_an_end_date():
    entries, error = suppress.add([], {"ruleId": "SEC-STG-001", "resourceId": RID, "days": 30, "reason": "  accepted  ", "resourceName": "acct"}, NOW)
    assert error is None and len(entries) == 1
    entry = entries[0]
    assert entry["until"] == "2026-11-18" and entry["reason"] == "accepted" and entry["resourceId"] == RID and entry["createdUtc"].startswith("2026-10-19")
    forever, _ = suppress.add([], {"ruleId": "SEC-STG-001", "days": 0}, NOW)
    assert forever[0]["until"] == "" and forever[0]["resourceId"] == ""


@pytest.mark.parametrize("body", [None, "x", {}, {"ruleId": "bad id!", "days": 0}, {"ruleId": "R", "resourceId": "no-slash", "days": 0},
                                  {"ruleId": "R", "days": 7}, {"ruleId": "R", "days": True}, {"ruleId": "R", "days": "30"}])
def test_add_rejects_bad_requests(body):
    entries, error = suppress.add([], body, NOW)
    assert entries is None and error


def test_adding_the_same_target_replaces_it_and_the_list_is_capped():
    first, _ = suppress.add([], {"ruleId": "R1", "resourceId": RID, "days": 30}, NOW)
    second, _ = suppress.add(first, {"ruleId": "r1", "resourceId": RID.upper().replace("/SUBSCRIPTIONS", "/subscriptions"), "days": 90}, NOW)
    assert len(second) == 1 and second[0]["until"] == "2027-01-17"  # same rule and resource, whatever the case
    again, _ = suppress.add(first, {"ruleId": "R1", "resourceId": RID, "days": 90}, NOW)
    assert len(again) == 1 and again[0]["until"] == "2027-01-17"
    full = [{"ruleId": f"R{i}", "resourceId": ""} for i in range(suppress.MAX_ENTRIES)]
    assert suppress.add(full, {"ruleId": "NEW", "days": 0}, NOW)[0] is None


def test_remove_and_clean():
    entries, _ = suppress.add([], {"ruleId": "R1", "days": 0}, NOW)
    assert suppress.remove(entries, entries[0]["id"]) == []
    assert suppress.clean("junk") == [] and suppress.clean([{"ruleId": "bad id!"}, 5, {"ruleId": "OK", "resourceId": "no"}]) == []


def test_split_hides_by_rule_or_by_resource_until_the_end_date():
    other = RID.replace("acct", "other")
    findings = [finding("SEC-STG-001", RID), finding("SEC-STG-001", other), finding("SEC-STG-002", RID)]
    one, _ = suppress.add([], {"ruleId": "sec-stg-001", "resourceId": RID, "days": 30}, NOW)
    visible, hidden = suppress.split(findings, one, date(2026, 10, 20))
    assert [(f["ruleId"], f["resourceName"]) for f in hidden] == [("SEC-STG-001", "acct")] and len(visible) == 2
    whole, _ = suppress.add([], {"ruleId": "SEC-STG-001", "days": 30}, NOW)
    assert len(suppress.split(findings, whole, date(2026, 10, 20))[1]) == 2
    assert suppress.split(findings, one, date(2026, 12, 1)) == (findings, [])  # snooze ended


# --- the collector keeps the counts in step ---------------------------------------------------------------

def test_collector_matching_agrees_with_the_dashboard():
    entry = {"ruleId": "SEC-STG-001", "resourceId": RID.lower(), "until": ""}
    assert collector.matches(entry, "sec-stg-001", RID) and not collector.matches(entry, "SEC-STG-001", RID + "x")
    assert collector.matches({"ruleId": "R", "resourceId": ""}, "r", "/any") and not collector.matches({"ruleId": "R"}, "X", "/any")
    assert collector.active([{"ruleId": "R", "until": "2026-10-18"}, {"ruleId": "R", "until": "2026-10-19"}, {"ruleId": "R"}, {"until": ""}, 3], date(2026, 10, 19)) == [
        {"ruleId": "R", "until": "2026-10-19"}, {"ruleId": "R"}]


def test_collector_lowers_affected_by_the_findings_it_hides():
    docs = [{"stats": [{"ruleId": "SEC-STG-001", "subscriptionId": SUB, "affected": 3, "applicable": 5},
                       {"ruleId": "SEC-STG-002", "subscriptionId": SUB, "affected": 1, "applicable": 5}], "errors": []}, {"errors": []}]
    findings = [finding("SEC-STG-001", RID), finding("SEC-STG-001", RID.replace("acct", "b")), finding("SEC-STG-002", RID)]
    entries = [{"ruleId": "SEC-STG-001", "resourceId": RID, "until": ""}, {"ruleId": "SEC-STG-002", "resourceId": "", "until": "2026-10-01"}]
    result, hidden = collector.apply(docs, findings, entries, date(2026, 10, 19))
    assert hidden == 1 and result[0]["stats"][0]["affected"] == 2 and result[0]["stats"][1]["affected"] == 1  # the second one expired
    assert result[1] == {"errors": []} and docs[0]["stats"][0]["affected"] == 3  # input untouched
    whole, hidden = collector.apply(docs, findings, [{"ruleId": "SEC-STG-001", "resourceId": ""}], date(2026, 10, 19))
    assert hidden == 2 and whole[0]["stats"][0]["affected"] == 1
    assert collector.apply(docs, findings, None) == (docs, 0)


# --- pages and API ------------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, saved):
    store = {"suppressions": saved}
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: {"runId": "r1", "subscriptions": [], "suppressed": 2})
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [finding("SEC-STG-001", RID), finding("SEC-STG-001", RID.replace("acct", "keep"))])
    monkeypatch.setattr(data, "get_setting", lambda name: store.get(name))
    monkeypatch.setattr(data, "save_setting", lambda name, value: store.update({name: value}))
    return store


def test_suppressed_findings_leave_the_lists(client, monkeypatch):
    saved, _ = suppress.add([], {"ruleId": "SEC-STG-001", "resourceId": RID, "days": 0}, NOW)
    serve(monkeypatch, saved)
    html = client.get("/rule/SEC-STG-001").get_data(as_text=True)
    assert "keep" in html and ">acct<" not in html and 'class="suppress-btn"' in html


def test_api_adds_and_restores(client, monkeypatch):
    store = serve(monkeypatch, [])
    headers = {"X-WAF-Pulse": "1"}
    assert client.post("/api/suppressions", json={"add": {"ruleId": "SEC-STG-001", "days": 30}}).status_code == 403
    ok = client.post("/api/suppressions", json={"add": {"ruleId": "SEC-STG-001", "resourceId": RID, "days": 30, "reason": "ok", "ruleTitle": "T", "resourceName": "acct"}}, headers=headers)
    assert ok.status_code == 200 and ok.get_json() == {"count": 1} and store["suppressions"][0]["reason"] == "ok"
    bad = client.post("/api/suppressions", json={"add": {"ruleId": "SEC-STG-001", "days": 7}}, headers=headers)
    assert bad.status_code == 422 and "error" in bad.get_json()
    entry_id = store["suppressions"][0]["id"]
    assert client.post("/api/suppressions", json={"remove": entry_id}, headers=headers).status_code == 200 and store["suppressions"] == []


def test_suppressions_page_lists_and_marks_expired(client, monkeypatch):
    live, _ = suppress.add([], {"ruleId": "SEC-STG-001", "resourceId": RID, "days": 0, "reason": "accepted risk", "resourceName": "acct", "ruleTitle": "Public blobs"}, NOW)
    old = [{**live[0], "id": "x", "ruleId": "SEC-STG-002", "until": "2020-01-01", "resourceId": "", "ruleTitle": "Old one"}]
    serve(monkeypatch, live + old)
    html = client.get("/suppressions").get_data(as_text=True)
    assert "Public blobs" in html and "accepted risk" in html and "Forever" in html and "expired" in html and "All resources" in html
    assert "left out <strong>2</strong>" in html and 'data-restore="x"' in html


def test_empty_suppressions_page(client, monkeypatch):
    serve(monkeypatch, [])
    assert "Nothing is suppressed" in client.get("/suppressions").get_data(as_text=True)
