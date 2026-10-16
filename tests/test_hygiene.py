from datetime import datetime, timezone

import pytest

from waf_pulse import diagnostics, keyvault, rest

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


# --- rest ---------------------------------------------------------------------------------------------

class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


def test_rest_retries_throttling_and_server_errors(monkeypatch):
    answers = iter([Resp(429, headers={"Retry-After": "1"}), Resp(503), Resp(200, {"ok": 1})])
    sleeps = []
    monkeypatch.setattr(rest.requests, "get", lambda *a, **k: next(answers))
    monkeypatch.setattr(rest, "_sleep", sleeps.append)
    assert rest.get("https://x", "t").json() == {"ok": 1} and sleeps == [1.0, 2]


def test_rest_returns_client_errors_without_retrying(monkeypatch):
    calls = []
    monkeypatch.setattr(rest.requests, "get", lambda *a, **k: calls.append(1) or Resp(403))
    assert rest.get("https://x", "t").status_code == 403 and len(calls) == 1


# --- diagnostics ----------------------------------------------------------------------------------------

def setting(workspace="ws", enabled=True):
    return {"properties": {"workspaceId": workspace, "logs": [{"enabled": enabled}], "metrics": []}}


def test_a_setting_needs_a_destination_and_something_enabled():
    assert diagnostics.sends_somewhere({"value": [setting()]})
    assert not diagnostics.sends_somewhere({"value": [setting(enabled=False)]})
    assert not diagnostics.sends_somewhere({"value": [setting(workspace=None)]})
    assert not diagnostics.sends_somewhere({"value": []}) and not diagnostics.sends_somewhere(None)


def test_diagnostics_evaluate_counts_coverage_and_skips():
    rows = [{"id": f"/subscriptions/s1/{n}", "name": n, "type": "Microsoft.KeyVault/vaults", "subscriptionId": "S1"}
            for n in ("a", "b", "c", "d", "e")]
    outcomes = {"/subscriptions/s1/a": "yes", "/subscriptions/s1/b": "no", "/subscriptions/s1/c": "denied",
                "/subscriptions/s1/d": "unsupported"}
    findings, stats, dataset = diagnostics.evaluate("r1", rows, outcomes)

    assert [f["resourceName"] for f in findings] == ["b"] and findings[0]["source"] == "diagnostics"
    assert "Key Vault does not send" in findings[0]["title"]
    assert stats == [{"ruleId": "OPS-DIAG-001", "source": "diagnostics", "pillar": "Operational Excellence",
                      "severity": "medium", "subscriptionId": "s1", "affected": 1, "applicable": 2}]
    assert dataset["percent"] == 50.0 and dataset["skipped"] == {"denied": 1, "error": 0, "unsupported": 1, "notChecked": 1}


def test_diagnostics_check_maps_status_codes(monkeypatch):
    class Cred:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    for status, body, expected in [(200, {"value": [setting()]}, "yes"), (200, {"value": []}, "no"), (403, {}, "denied"),
                                   (404, {}, "unsupported"), (500, {}, "error")]:
        monkeypatch.setattr(diagnostics.rest, "get", lambda *a, _s=status, _b=body, **k: Resp(_s, _b))
        assert diagnostics.check(Cred(), "/subscriptions/s/x") == expected


# --- key vault ------------------------------------------------------------------------------------------

def ts(days):
    return int(NOW.timestamp() + days * 86400)


def items(*specs):
    return [{"id": f"https://v.vault.azure.net/secrets/{name}", "attributes": attrs, **extra} for name, attrs, extra in specs]


VAULT = {"id": "/subscriptions/s1/v", "name": "v", "subscriptionId": "S1", "vaultUri": "https://v.vault.azure.net/"}


def test_keyvault_classifies_expired_soon_and_missing_expiry():
    parsed = keyvault.parse_objects(items(
        ("old", {"exp": ts(-5)}, {}), ("soon", {"exp": ts(10)}, {}), ("fine", {"exp": ts(200)}, {}),
        ("none", {}, {}), ("off", {"enabled": False}, {}), ("cert-secret", {}, {"managed": True})), "secrets")
    rules = {o["name"]: keyvault.classify(o, NOW)[0] for o in parsed}
    assert rules == {"old": "SEC-KVX-001", "soon": "SEC-KVX-002", "fine": None, "none": "OPS-KVX-003", "off": None,
                     "cert-secret": None}


def test_certificates_without_expiry_are_not_flagged():
    cert = keyvault.parse_objects([{"id": "https://v/certificates/c", "attributes": {}}], "certificates")[0]
    assert keyvault.classify(cert, NOW) == (None, None)


def test_keyvault_evaluate_builds_findings_stats_and_upcoming_list():
    objects = {VAULT["id"]: keyvault.parse_objects(items(
        ("old", {"exp": ts(-5)}, {}), ("soon", {"exp": ts(10)}, {}), ("none", {}, {}), ("fine", {"exp": ts(200)}, {})),
        "secrets")}
    other = {"id": "/subscriptions/s1/locked", "name": "locked", "subscriptionId": "S1", "vaultUri": "https://l/"}
    findings, stats, dataset = keyvault.evaluate("r1", [VAULT, other], objects, {other["id"]}, NOW)

    assert sorted(f["ruleId"] for f in findings) == ["OPS-KVX-003", "SEC-KVX-001", "SEC-KVX-002"]
    expired = next(f for f in findings if f["ruleId"] == "SEC-KVX-001")
    assert expired["resourceName"] == "v/old" and "expired" in expired["title"] and expired["severity"] == "high"
    soon = next(f for f in findings if f["ruleId"] == "SEC-KVX-002")
    assert "expires in 9 days" in soon["title"] or "expires in 10 days" in soon["title"]
    by_rule = {s["ruleId"]: s for s in stats}
    assert by_rule["SEC-KVX-001"]["applicable"] == 4 and by_rule["SEC-KVX-001"]["affected"] == 1
    assert dataset["vaults"] == 2 and dataset["readable"] == 1 and dataset["denied"] == 1 and dataset["objects"] == 4
    assert [u["name"] for u in dataset["upcoming"]] == ["old", "soon"] and dataset["upcoming"][0]["days"] < 0


def test_keyvault_list_objects_follows_pages_and_reports_denied(monkeypatch):
    pages = iter([Resp(200, {"value": [{"id": "a"}], "nextLink": "https://next"}), Resp(200, {"value": [{"id": "b"}]})])
    monkeypatch.setattr(keyvault.rest, "get", lambda *a, **k: next(pages))
    assert keyvault.list_objects("t", "https://v/", "secrets") == ([{"id": "a"}, {"id": "b"}], "ok")
    monkeypatch.setattr(keyvault.rest, "get", lambda *a, **k: Resp(403))
    assert keyvault.list_objects("t", "https://v/", "secrets") == ([], "denied")


def test_keyvault_collect_marks_unreadable_vaults_as_denied(monkeypatch):
    class Cred:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    monkeypatch.setattr(keyvault.graph, "chunks", lambda ids: [ids])
    monkeypatch.setattr(keyvault.graph, "query", lambda *a, **k: [VAULT])
    monkeypatch.setattr(keyvault.rest, "get", lambda *a, **k: Resp(403))
    findings, stats, dataset, errors = keyvault.collect(Cred(), "r1", ["s1"], now=NOW)
    assert findings == [] and dataset["denied"] == 1 and dataset["readable"] == 0 and errors == []
