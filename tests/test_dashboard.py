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
    assert response.status_code == 503
    assert b"not reachable" in response.data
    assert b"secret connection detail" not in response.data


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


SUMMARY = {
    "runId": "r1", "completedUtc": "2026-01-01T00:00:00+00:00", "subscriptionCount": 1, "resourceCount": 5,
    "findingCount": 3, "scores": {"Security": 40, "Reliability": 90, "Cost Optimization": 100,
                                  "Operational Excellence": 100, "Performance Efficiency": None},
    "counts": {"Security": {"high": 2, "low": 1}},
    "severityTotals": {"critical": 0, "high": 2, "medium": 0, "low": 1},
    "sources": {"builtin": {"rules": 20, "findings": 1}, "checklist": {"rules": 41, "findings": 2}},
    "secureScore": {"average": 62.5, "subscriptions": [{"name": "Prod", "percentage": 62.5}],
                    "topControls": [{"control": "Enable MFA", "unhealthy": 7, "healthy": 1}]},
    "advisorSavings": {"USD": 3804.0},
    "subscriptions": [{"id": "s1", "name": "Prod", "resourceCount": 5, "findingCount": 3}],
    "errors": [{"ruleId": "CHK-1", "error": "<b>bad query</b>"}],
}

FINDINGS = [
    {"id": "1", "ruleId": "R-1", "severity": "high", "pillar": "Security", "title": "<script>alert(1)</script>",
     "source": "checklist", "resourceId": "/subscriptions/s1/a", "resourceName": "acct",
     "resourceType": "Microsoft.Storage/storageAccounts", "subscriptionId": "s1", "recommendation": "Fix it",
     "link": "https://learn.microsoft.com/x"},
    {"id": "2", "ruleId": "R-1", "severity": "high", "pillar": "Security", "title": "<script>alert(1)</script>",
     "source": "checklist", "resourceId": "/subscriptions/s1/b", "resourceName": "acct2",
     "resourceType": "Microsoft.Storage/storageAccounts", "subscriptionId": "s1", "recommendation": "Fix it",
     "link": "https://learn.microsoft.com/x"},
    {"id": "3", "ruleId": "R-2", "severity": "low", "pillar": "Security", "title": "Other", "source": "advisor",
     "resourceId": "/subscriptions/s1/c", "resourceName": "vm", "resourceType": "Microsoft.Compute/virtualMachines",
     "subscriptionId": "s1", "recommendation": "r", "link": "javascript:alert(1)"},
]


def serve(monkeypatch, summary=None, findings=None):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed", "startedUtc": "t0"})
    monkeypatch.setattr(data, "summary", lambda run_id: summary or SUMMARY)
    rows = FINDINGS if findings is None else findings
    monkeypatch.setattr(data, "all_findings", lambda run_id, pillar=None, rule_id=None, limit=5000: [
        f for f in rows if (not pillar or f["pillar"] == pillar) and (not rule_id or f["ruleId"] == rule_id)])
    monkeypatch.setattr(data, "findings", lambda *a, **k: rows)


def test_overview_shows_scores_charts_and_top_recommendations(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/").get_data(as_text=True)
    assert "40" in html and "n/a" in html and "2 critical or high" in html
    assert 'href="/pillar/security"' in html and "Findings by pillar and severity" in html
    assert "Top recommendations" in html and 'href="/rule/R-1"' in html
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "storage/storageaccounts" in html and html.count("<svg") >= 4
    assert "1 check(s) could not run" in html and "<b>bad query</b>" not in html and "&lt;b&gt;bad query&lt;/b&gt;" in html


def test_old_filter_links_land_on_the_findings_page(client, monkeypatch):
    serve(monkeypatch)
    response = client.get("/?pillar=Security&severity=high&source=checklist")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/findings?pillar=Security&severity=high&source=checklist")


def test_pillar_page_groups_findings_by_recommendation(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/pillar/security").get_data(as_text=True)
    assert "Security score" in html
    assert html.count('href="/rule/R-1"') == 1 and 'href="/rule/R-2"' in html
    assert "Secure Score" in html and "62.5%" in html and "Enable MFA" in html
    assert "Key Vault expirations" not in html  # no data for it in this summary
    assert 'id="rec-filter"' in html and 'data-filter-table="recs"' in html


def test_cost_pillar_shows_savings_and_unknown_pillars_are_404(client, monkeypatch):
    serve(monkeypatch)
    assert "3,804 USD" in client.get("/pillar/cost").get_data(as_text=True)
    assert client.get("/pillar/nope").status_code == 404


def test_rule_page_lists_affected_resources_and_history(client, monkeypatch):
    serve(monkeypatch)
    monkeypatch.setattr(data, "rule_history", lambda rule_id: {"r0": 1, "r1": 2})
    monkeypatch.setattr(data, "history", lambda limit=30: [
        {"id": "r1", "startedUtc": "2026-10-02T00:00:00+00:00"}, {"id": "r0", "startedUtc": "2026-10-01T00:00:00+00:00"}])
    html = client.get("/rule/R-1").get_data(as_text=True)
    assert "acct" in html and "acct2" in html and "Fix it" in html and "History" in html
    assert 'href="https://learn.microsoft.com/x"' in html and "&lt;script&gt;" in html
    assert 'class="line' in html


def test_rule_page_without_findings_and_with_a_bad_id(client, monkeypatch):
    serve(monkeypatch)
    assert b"no findings in the latest run" in client.get("/rule/NOPE").data
    assert client.get("/rule/bad%20id!").status_code == 404


def test_findings_page_ignores_invalid_filters_and_blocks_unsafe_links(client, monkeypatch):
    seen = {}

    def fake_findings(run_id, pillar=None, severity=None, limit=200, source=None):
        seen.update(pillar=pillar, severity=severity, source=source)
        return FINDINGS

    serve(monkeypatch)
    monkeypatch.setattr(data, "findings", fake_findings)
    client.get("/findings?pillar=%27%20OR%201%3D1&severity=nope&source=x")
    assert seen == {"pillar": None, "severity": None, "source": None}
    html = client.get("/findings?pillar=Security&severity=high&source=checklist").get_data(as_text=True)
    assert seen == {"pillar": "Security", "severity": "high", "source": "checklist"}
    assert 'href="https://learn.microsoft.com/x"' in html and "javascript:alert(1)" not in html
    assert "Review checklists: 2" in html and "Built-in rules: 1" in html
