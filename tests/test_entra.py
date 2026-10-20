from datetime import datetime, timedelta, timezone

from waf_pulse import entra

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


def iso(days):
    return (NOW + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def app(name, *creds, kind="passwordCredentials"):
    return {"id": f"id-{name}", "appId": f"app-{name}", "displayName": name,
            kind: [{"startDateTime": iso(s), "endDateTime": iso(e)} for s, e in creds]}


def rules_of(findings):
    return sorted((f["resourceName"], f["ruleId"]) for f in findings)


def test_app_credentials_expired_expiring_and_long_lived():
    apps = [app("expired", (-400, -10)), app("soon", (-300, 10)), app("fine", (-30, 300)),
            app("rotating", (-300, 10), (-5, 360)),  # a new secret already covers the old one
            app("forever", (-10, 1500)), app("nocreds"), app("cert", (-60, 5), kind="keyCredentials")]
    findings, stats, dataset = entra.evaluate_apps("r1", apps, NOW)

    assert rules_of(findings) == [("cert", "OPS-APP-002"), ("expired", "SEC-APP-001"), ("forever", "SEC-APP-003"),
                                  ("soon", "OPS-APP-002")]
    soon = next(f for f in findings if f["resourceName"] == "soon")
    assert "expires in 10 days" in soon["title"] and soon["subscriptionId"] == "tenant"
    assert dataset["apps"] == 7 and dataset["withCredentials"] == 6
    assert [(item["app"], item["days"]) for item in dataset["expiredOrExpiring"]][:2] == [("expired", -10), ("cert", 5)]
    by_rule = {s["ruleId"]: s for s in stats}
    assert by_rule["OPS-APP-002"]["affected"] == 2 and by_rule["OPS-APP-002"]["applicable"] == 6


def test_no_app_credentials_means_no_rows():
    assert entra.evaluate_apps("r1", [app("nocreds")], NOW) == ([], [], {"apps": 1, "withCredentials": 0,
                                                                          "expiredOrExpiring": [], "expiredApps": 0})


def test_only_old_pending_guest_invitations_are_findings():
    guests = [
        {"id": "1", "userPrincipalName": "old@x", "createdDateTime": iso(-90), "externalUserState": "PendingAcceptance"},
        {"id": "2", "userPrincipalName": "new@x", "createdDateTime": iso(-3), "externalUserState": "PendingAcceptance"},
        {"id": "3", "userPrincipalName": "ok@x", "createdDateTime": iso(-90), "externalUserState": "Accepted"},
    ]
    findings, stats, dataset = entra.evaluate_guests("r1", guests, NOW)
    assert [f["resourceName"] for f in findings] == ["old@x"]
    assert dataset == {"total": 3, "pendingInvitations": 2, "staleInvitations": 1}
    assert stats[0]["affected"] == 1 and stats[0]["applicable"] == 3


def test_open_incidents_become_findings_with_their_severity():
    incidents = [{"id": "1", "displayName": "Ransomware", "severity": "high", "status": "active"},
                 {"id": "2", "displayName": "Noise", "severity": "informational", "status": "inProgress"},
                 {"id": "3", "displayName": "Done", "severity": "high", "status": "resolved"}]
    findings, stats, dataset = entra.evaluate_incidents("r1", incidents)
    assert sorted((f["resourceName"], f["severity"]) for f in findings) == [("Noise", "low"), ("Ransomware", "high")]
    assert dataset == {"open": 2, "bySeverity": {"high": 1, "low": 1}} and stats[0]["applicable"] is None


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


def test_fetch_all_follows_pages_and_reports_missing_permissions(monkeypatch):
    pages = iter([Resp(200, {"value": [1], "@odata.nextLink": "https://next"}), Resp(200, {"value": [2]})])
    monkeypatch.setattr(entra.rest, "get", lambda *a, **k: next(pages))
    assert entra.fetch_all("t", "/applications") == ([1, 2], "ok")
    monkeypatch.setattr(entra.rest, "get", lambda *a, **k: Resp(403))
    assert entra.fetch_all("t", "/applications") == ([], "denied")
    monkeypatch.setattr(entra.rest, "get", lambda *a, **k: Resp(500))
    assert entra.fetch_all("t", "/applications") == ([], "error")


def test_collect_keeps_the_parts_that_are_allowed(monkeypatch):
    class Cred:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    def fake_get(url, token, params=None, headers=None):
        if url.endswith("/applications"):
            return Resp(200, {"value": [app("soon", (-300, 10))]})
        return Resp(403)

    monkeypatch.setattr(entra.rest, "get", fake_get)
    findings, stats, dataset, errors = entra.collect(Cred(), "r1", now=NOW)
    assert [f["ruleId"] for f in findings] == ["OPS-APP-002"] and errors == []
    assert dataset["available"] == {"apps": True, "guests": False, "incidents": False, "policies": False, "roles": False, "mfa": False, "risky": False, "recommendations": False}
    assert "guests" not in dataset and dataset["permissions"]["guests"] == "User.Read.All"
