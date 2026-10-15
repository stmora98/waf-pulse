import pytest

import app as dashboard_app
import data


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def test_health_does_not_touch_the_data_store(client, monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("health must not call Cosmos DB")

    monkeypatch.setattr(data, "latest_run", boom)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_security_headers_are_set(client):
    response = client.get("/api/health")
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def test_empty_state(client, monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: None)
    response = client.get("/")
    assert response.status_code == 200
    assert b"No assessment has completed yet" in response.data


def test_data_store_error_is_generic(client, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("secret connection detail")

    monkeypatch.setattr(data, "latest_run", fail)
    response = client.get("/")
    assert response.status_code == 200
    assert b"not reachable" in response.data
    assert b"secret connection detail" not in response.data


def test_dashboard_renders_scores_and_escapes_findings(client, monkeypatch):
    run = {"id": "r1", "status": "completed", "startedUtc": "t0"}
    summary = {
        "runId": "r1", "completedUtc": "2026-01-01T00:00:00+00:00", "subscriptionCount": 1,
        "resourceCount": 5, "findingCount": 1,
        "scores": {"Security": 72, "Reliability": 100, "Cost Optimization": 90,
                   "Operational Excellence": 100, "Performance Efficiency": None},
        "severityTotals": {"critical": 0, "high": 1, "medium": 0, "low": 0},
        "subscriptions": [{"id": "s1", "name": "Prod", "resourceCount": 5, "findingCount": 1}],
        "errors": [],
    }
    finding = {"severity": "high", "pillar": "Security", "title": "<script>alert(1)</script>",
               "resourceId": "/x", "resourceName": "acct", "recommendation": "Fix it"}
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: run)
    monkeypatch.setattr(data, "summary", lambda run_id: summary)
    monkeypatch.setattr(data, "findings", lambda *args, **kwargs: [finding])

    html = client.get("/").get_data(as_text=True)
    assert "72" in html and "n/a" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_refresh_requires_custom_header(client):
    assert client.post("/api/refresh").status_code == 403


def test_refresh_rejects_cross_site_requests(client):
    response = client.post("/api/refresh", headers={"X-WAF-Pulse": "1", "Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403


def test_refresh_queues_a_request(client, monkeypatch):
    queued = []
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"status": "completed"})
    monkeypatch.setattr(data, "request_refresh", lambda: queued.append(True))
    response = client.post("/api/refresh", headers={"X-WAF-Pulse": "1"})
    assert response.status_code == 202 and queued == [True]


def test_refresh_is_refused_while_running(client, monkeypatch):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"status": "running"})
    monkeypatch.setattr(data, "request_refresh", lambda: (_ for _ in ()).throw(AssertionError("must not queue")))
    assert client.post("/api/refresh", headers={"X-WAF-Pulse": "1"}).status_code == 409


def test_invalid_filters_are_ignored(client, monkeypatch):
    seen = {}

    def fake_findings(run_id, pillar=None, severity=None, limit=200, source=None):
        seen.update(pillar=pillar, severity=severity, source=source)
        return []

    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: {
        "runId": "r1", "completedUtc": "t", "subscriptionCount": 0, "resourceCount": 0, "findingCount": 0,
        "scores": {}, "severityTotals": {}, "subscriptions": [], "errors": []})
    monkeypatch.setattr(data, "findings", fake_findings)
    client.get("/?pillar=%27%20OR%201%3D1&severity=nope&source=x")
    assert seen == {"pillar": None, "severity": None, "source": None}
    client.get("/?pillar=Security&severity=high&source=checklist")
    assert seen == {"pillar": "Security", "severity": "high", "source": "checklist"}


def test_new_insight_blocks_render_and_escape(client, monkeypatch):
    run = {"id": "r1", "status": "completed", "startedUtc": "t0"}
    summary = {
        "runId": "r1", "completedUtc": "2026-01-01T00:00:00+00:00", "subscriptionCount": 1, "resourceCount": 5,
        "findingCount": 3, "scores": {"Security": 40, "Reliability": 90, "Cost Optimization": 100,
                                      "Operational Excellence": 100, "Performance Efficiency": None},
        "severityTotals": {"critical": 0, "high": 1, "medium": 1, "low": 1},
        "sources": {"builtin": {"rules": 20, "findings": 1}, "checklist": {"rules": 41, "findings": 2}},
        "secureScore": {"average": 62.5, "subscriptions": [{"name": "Prod", "percentage": 62.5}],
                        "topControls": [{"control": "Enable MFA", "unhealthy": 7, "healthy": 1}]},
        "advisorSavings": {"USD": 3804.0},
        "subscriptions": [{"id": "s1", "name": "Prod", "resourceCount": 5, "findingCount": 3}],
        "errors": [{"ruleId": "CHK-1", "error": "<b>bad query</b>"}],
    }
    finding = {"severity": "high", "pillar": "Security", "title": "Use private endpoints", "source": "checklist",
               "resourceId": "/x", "resourceName": "acct", "recommendation": "r",
               "link": "https://learn.microsoft.com/x"}
    unsafe = dict(finding, title="Other", link="javascript:alert(1)", source="advisor")
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: run)
    monkeypatch.setattr(data, "summary", lambda run_id: summary)
    monkeypatch.setattr(data, "findings", lambda *args, **kwargs: [finding, unsafe])

    html = client.get("/").get_data(as_text=True)
    assert "Secure Score" in html and "62.5%" in html and "Enable MFA" in html
    assert "3,804 USD" in html
    assert "Review checklists: 2" in html and "Built-in rules: 1" in html
    assert 'href="https://learn.microsoft.com/x"' in html
    assert "javascript:alert(1)" not in html  # only https links are rendered
    assert "<b>bad query</b>" not in html and "&lt;b&gt;bad query&lt;/b&gt;" in html
    assert "1 check(s) could not run" in html
