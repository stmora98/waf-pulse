import pytest
from azure.cosmos.exceptions import CosmosResourceNotFoundError

import app as dashboard_app
import data
import history

RUN_A = "11111111-1111-1111-1111-111111111111"
RUN_B = "22222222-2222-2222-2222-222222222222"
RUN_C = "33333333-3333-3333-3333-333333333333"


def run(run_id, hour, findings=0, scores=None, status="completed"):
    return {
        "id": run_id, "status": status, "trigger": "manual",
        "startedUtc": f"2026-10-15T{hour:02d}:00:00+00:00", "completedUtc": f"2026-10-15T{hour:02d}:00:07+00:00",
        "resourceCount": 100, "findingCount": findings, "scores": scores,
    }


def scores(security, reliability=100):
    return {"Security": security, "Reliability": reliability, "Cost Optimization": 100,
            "Operational Excellence": 100, "Performance Efficiency": None}


def finding(key, severity="high", title="t"):
    return {"key": key, "severity": severity, "title": title, "pillar": "Security",
            "resourceId": f"/r/{key}", "resourceName": key}


# --- pure functions -------------------------------------------------------------------------------------

def test_duration_and_time_formatting():
    assert history.duration_seconds(run(RUN_A, 9)) == 7
    assert history.duration_seconds({"startedUtc": "x"}) is None
    assert history.short_time("2026-10-15T09:05:00+00:00") == "10-15 09:05"
    assert history.short_time(None) == ""


def test_trend_without_runs_is_empty():
    chart = history.trend([])
    assert chart["runs"] == 0 and chart["series"] == []


def test_trend_orders_oldest_left_and_skips_unscored_pillars():
    newest_first = [run(RUN_B, 10, scores=scores(80)), run(RUN_A, 9, scores=scores(40))]
    chart = history.trend(newest_first)
    by_pillar = {s["pillar"]: s for s in chart["series"]}

    assert chart["runs"] == 2
    assert "Performance Efficiency" not in by_pillar
    first, second = by_pillar["Security"]["dots"]
    assert first["x"] < second["x"]
    assert first["y"] > second["y"]  # 40 is lower on the chart than 80
    assert [label["text"] for label in chart["labels"]] == ["10-15 09:00", "10-15 10:00"]


def test_trend_ignores_failed_and_unscored_runs():
    chart = history.trend([run(RUN_B, 10, status="failed"), run(RUN_A, 9, scores=None)])
    assert chart["runs"] == 0


def test_trend_with_one_run_is_centered():
    chart = history.trend([run(RUN_A, 9, scores=scores(70))])
    dot = chart["series"][0]["dots"][0]
    assert chart["left"] < dot["x"] < chart["right"]


def test_compare_matches_findings_by_stable_key():
    base = [finding("a", "low"), finding("b", "high"), finding("c", "medium")]
    target = [finding("b", "high"), finding("d", "critical"), finding("e", "low")]
    result = history.compare(base, target)
    assert result["unchangedCount"] == 1
    assert result["newCount"] == 2 and [f["key"] for f in result["new"]] == ["d", "e"]  # critical first
    assert result["resolvedCount"] == 2 and [f["key"] for f in result["resolved"]] == ["c", "a"]


def test_compare_ignores_findings_without_a_key():
    result = history.compare([{"severity": "low"}], [finding("x")])
    assert result["resolvedCount"] == 0 and result["newCount"] == 1


def test_compare_caps_listed_findings_but_keeps_counts():
    target = [finding(str(i)) for i in range(history.MAX_LISTED + 25)]
    result = history.compare([], target)
    assert result["newCount"] == history.MAX_LISTED + 25
    assert len(result["new"]) == history.MAX_LISTED


def test_score_deltas_handle_missing_scores():
    rows = {r["pillar"]: r for r in history.score_deltas(scores(50), scores(80))}
    assert rows["Security"]["delta"] == 30
    assert rows["Performance Efficiency"]["delta"] is None
    assert all(r["delta"] is None for r in history.score_deltas(None, scores(80)))


# --- routes ---------------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


@pytest.fixture()
def three_runs(monkeypatch):
    runs = [run(RUN_C, 11, 3, scores(90)), run(RUN_B, 10, 5, scores(60)), run(RUN_A, 9, 9, scores(40))]
    findings = {
        RUN_A: [finding("a"), finding("b"), finding("c")],
        RUN_B: [finding("b"), finding("c"), finding("d")],
        RUN_C: [finding("c"), finding("e", title="<script>x</script>")],
    }
    monkeypatch.setattr(data, "history", lambda limit=30: runs)
    monkeypatch.setattr(data, "run_findings", lambda run_id, limit=5000: findings[run_id])
    return runs


def test_history_page_lists_runs_and_chart(client, three_runs):
    html = client.get("/history").get_data(as_text=True)
    assert "<svg" in html and "line-security" in html
    assert f"base={RUN_B}&amp;target={RUN_C}" in html  # each run links to the previous completed run
    assert "style=" not in html  # the CSP forbids inline styles


def test_history_page_empty_and_error(client, monkeypatch):
    monkeypatch.setattr(data, "history", lambda limit=30: [])
    assert b"No runs yet" in client.get("/history").data

    def boom(limit=30):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(data, "history", boom)
    response = client.get("/history")
    assert b"not reachable" in response.data and b"secret detail" not in response.data


def test_compare_defaults_to_latest_two_completed_runs(client, three_runs):
    body = client.get("/api/compare").get_json()
    assert body["target"]["id"] == RUN_C and body["base"]["id"] == RUN_B
    assert body["newCount"] == 1 and body["resolvedCount"] == 2 and body["unchangedCount"] == 1
    assert {row["pillar"]: row["delta"] for row in body["scores"]}["Security"] == 30


def test_compare_page_escapes_finding_text(client, three_runs):
    html = client.get("/compare").get_data(as_text=True)
    assert "<script>x</script>" not in html and "&lt;script&gt;x&lt;/script&gt;" in html


def test_compare_with_explicit_runs(client, three_runs):
    body = client.get(f"/api/compare?base={RUN_A}&target={RUN_C}").get_json()
    assert body["base"]["id"] == RUN_A and body["target"]["id"] == RUN_C


def test_compare_needs_two_completed_runs(client, monkeypatch):
    monkeypatch.setattr(data, "history", lambda limit=30: [run(RUN_A, 9, scores=scores(50))])
    assert client.get("/api/compare").status_code == 409
    assert b"At least two completed runs" in client.get("/compare").data


def test_compare_rejects_malformed_ids(client, three_runs):
    assert client.get("/api/compare?base=../../etc&target=x").status_code == 400
    assert client.get("/compare?base=' OR 1=1&target=1").status_code == 400


def test_compare_unknown_run_is_not_found(client, three_runs, monkeypatch):
    def missing(run_id):
        raise CosmosResourceNotFoundError(message="not found")

    monkeypatch.setattr(data, "run", missing)
    unknown = "99999999-9999-9999-9999-999999999999"
    assert client.get(f"/api/compare?base={unknown}&target={RUN_C}").status_code == 404
