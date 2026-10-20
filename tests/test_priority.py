import json

import pytest

import app as dashboard_app
import data
import priority
import scope
import scoring

S1 = "11111111-1111-1111-1111-111111111111"


def stat(rule, severity, affected, applicable, pillar="Security"):
    return {"ruleId": rule, "pillar": pillar, "severity": severity, "affected": affected, "applicable": applicable}


STATS = [stat("A", "high", 5, 10), stat("B", "medium", 2, 10), stat("C", "low", 1, 100), stat("D", "high", 0, 10), stat("COST", "medium", 4, 8, "Cost Optimization")]


def test_impact_is_the_score_gain_from_solving_a_rule_everywhere():
    gains = priority.impacts(STATS)
    security = [s for s in STATS if s["pillar"] == "Security"]
    before = scoring.pillar_score(security)
    for rule in ("A", "B", "C"):
        after = scoring.pillar_score([{**s, "affected": 0} if s["ruleId"] == rule else s for s in security])
        assert gains[rule] == {"points": after - before, "pillar": "Security", "before": before}
    assert "D" not in gains and gains["COST"]["pillar"] == "Cost Optimization"
    assert gains["A"]["points"] > gains["B"]["points"] > 0  # the high severity rule that reaches half the resources is worth more
    assert priority.impacts([]) == {} and priority.impacts([stat("X", "low", 0, 0)]) == {}


def test_solving_the_only_serious_finding_lifts_the_severity_cap():
    stats = [stat("CRIT", "critical", 1, 100), stat("LOW", "low", 0, 100)]
    gains = priority.impacts(stats)
    assert gains["CRIT"]["before"] <= 49 and gains["CRIT"]["points"] >= 50


def rule(rule_id, severity, resources, title=None, pillar="Security"):
    return {"ruleId": rule_id, "title": title or rule_id, "severity": severity, "pillar": pillar, "resources": resources}


def test_fix_first_orders_by_points_then_internet_then_severity():
    rules = [rule("A", "high", 5), rule("B", "medium", 2), rule("C", "low", 1), rule("E", "high", 3), rule("F", "high", 3)]
    findings = [{"ruleId": "B", "resourceId": "/x/ONE"}, {"ruleId": "C", "resourceId": "/x/two"}]
    stats = STATS + [stat("E", "high", 0, 10), stat("F", "high", 0, 10)]  # no points for E and F
    rows = priority.fix_first(stats, rules, findings, exposed={"/x/one"})
    assert [r["ruleId"] for r in rows] == ["A", "B", "E", "F", "C"] and rows[1]["internet"] == 1 and rows[4]["internet"] == 0
    assert all(r["points"] == 0 for r in rows[2:])  # without points the severity decides: C is low and reaches one resource of a hundred
    tied = priority.fix_first([stat("P", "high", 0, 10), stat("Q", "high", 0, 10)], [rule("P", "high", 3), rule("Q", "high", 3)], [{"ruleId": "Q", "resourceId": "/x/q"}], exposed={"/x/q"})
    assert [r["ruleId"] for r in tied] == ["Q", "P"]  # with the same points the one that faces the internet goes first
    assert priority.fix_first(STATS, rules, findings, pillar="Cost Optimization") == []
    assert len(priority.fix_first(STATS, rules * 5, findings, limit=3)) == 3


# --- pages ----------------------------------------------------------------------------------------------------

def finding(rule, sub, name, severity="high", pillar="Security"):
    return {"ruleId": rule, "resourceId": f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}", "subscriptionId": sub, "resourceName": name,
            "resourceType": "microsoft.compute/virtualmachines", "title": f"Title of {rule}", "severity": severity, "pillar": pillar, "source": "builtin", "recommendation": "x"}


RULESTATS = [{"r": "SEC-A", "p": "Security", "v": "high", "s": "builtin", "u": S1, "a": 2, "n": 4, "t": None}, {"r": "SEC-B", "p": "Security", "v": "medium", "s": "builtin", "u": S1, "a": 1, "n": 4, "t": None},
             {"r": "COST-A", "p": "Cost Optimization", "v": "low", "s": "builtin", "u": S1, "a": 1, "n": 2, "t": None}]
FINDINGS = [finding("SEC-A", S1, "web1"), finding("SEC-A", S1, "web2"), finding("SEC-B", S1, "db1", "medium"), finding("COST-A", S1, "web1", "low", "Cost Optimization")]
RUNS = [{"id": f"r{i}", "status": "completed", "startedUtc": f"2026-10-{10 + i:02d}T10:00:00+00:00", "scores": {"Security": 40 + i * 5, "Cost Optimization": 60}} for i in range(3)][::-1]


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, runs=RUNS, rulestats=RULESTATS, secrows=()):
    summary = {"runId": "r1", "scores": {"Security": 50, "Cost Optimization": 60}, "subscriptions": [{"id": S1, "name": "Prod", "resourceCount": 4, "scores": {}}], "counts": {}, "severityTotals": {}}
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: json.loads(json.dumps(summary)))
    monkeypatch.setattr(data, "all_findings", lambda run_id, pillar=None, *a, **k: [f for f in FINDINGS if not pillar or f["pillar"] == pillar])
    monkeypatch.setattr(data, "resources", lambda run_id: ([], False))
    monkeypatch.setattr(data, "get_setting", lambda name: None)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: list(rulestats) if kind == "rulestats" else list(secrows) if kind == "secrows" else [])
    monkeypatch.setattr(data, "history", lambda limit=30: list(runs))


def test_overview_lists_what_to_fix_first_and_the_trend(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/").get_data(as_text=True)
    assert 'id="fix-first"' in html and "Title of SEC-A" in html and "points" in html and "Score over time" in html
    assert html.index("Title of SEC-A") < html.index("Title of SEC-B")


def test_the_page_marks_what_faces_the_internet(client, monkeypatch):
    exposed = {"t": "exposed", "id": FINDINGS[1]["resourceId"].upper(), "subscriptionId": S1, "ip": "1.2.3.4"}
    serve(monkeypatch, secrows=[exposed])
    html = client.get("/pillar/security").get_data(as_text=True)
    assert 'id="fix-first"' in html and 'class="chip high">1<' in html
    assert "Pillar</th>" not in html.split('id="fix-first"')[1].split("</table>")[0]  # a pillar page does not repeat the pillar


def test_pillar_pages_show_only_their_pillar_and_its_own_trend(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/pillar/cost").get_data(as_text=True)
    assert "Title of COST-A" in html and "Title of SEC-A" not in html and "Cost Optimization score over time" in html
    assert "polyline" in html


def test_without_statistics_or_history_the_panels_stay_out(client, monkeypatch):
    serve(monkeypatch, runs=RUNS[:1], rulestats=[])
    html = client.get("/").get_data(as_text=True)
    assert 'id="fix-first"' not in html and "Score over time" not in html


def test_fix_first_follows_the_filters(client, monkeypatch):
    serve(monkeypatch)
    client.set_cookie(scope.COOKIE, scope.encode(scope.sanitize([{"f": "sub", "op": "ne", "v": [S1]}])), domain="localhost")
    html = client.get("/").get_data(as_text=True)
    assert 'id="fix-first"' not in html  # nothing is left in the filters
