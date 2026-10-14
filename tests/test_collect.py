from waf_pulse import collect, graph
from waf_pulse.rules import INVENTORY_QUERY, RULES


def test_finding_id_is_stable_and_cosmos_safe():
    rule = RULES[0]
    row = {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a", "name": "a", "type": "t", "subscriptionId": "s"}
    first = collect.build_finding("run1", rule, row)
    second = collect.build_finding("run1", rule, dict(row, id=row["id"].upper()))
    assert first["id"] == second["id"]
    assert not any(ch in first["id"] for ch in "/\\?#")
    assert collect.build_finding("run2", rule, row)["id"] != first["id"]


def test_collect_subscription_counts_findings_and_survives_a_failing_rule(monkeypatch):
    failing = RULES[1].query

    def fake_query(credential, subscription_id, kql, max_rows=0):
        if kql == INVENTORY_QUERY:
            return [{"type": "a/b", "count_": 7}, {"type": "c/d", "count_": 3}]
        if kql == failing:
            raise RuntimeError("Forbidden")
        if kql == RULES[0].query:
            return [{"id": "/x/1", "name": "one", "type": "t", "subscriptionId": subscription_id}]
        return []

    monkeypatch.setattr(graph, "query", fake_query)
    findings, result = collect.collect_subscription(None, "run1", {"id": "sub1", "name": "Sub 1"})

    assert result["resourceCount"] == 10
    assert result["findingCount"] == 1 and len(findings) == 1
    assert result["counts"]["Security"]["high"] == 1
    assert [error["ruleId"] for error in result["errors"]] == [RULES[1].id]


def test_build_summary_aggregates_subscriptions():
    results = [
        {
            "subscriptionId": "s1", "name": "One", "resourceCount": 10, "findingCount": 2,
            "topTypes": [{"type": "a/b", "count": 10}],
            "counts": {"Security": {"high": 2}}, "errors": [],
        },
        {
            "subscriptionId": "s2", "name": "Two", "resourceCount": 30, "findingCount": 1,
            "topTypes": [{"type": "a/b", "count": 20}, {"type": "c/d", "count": 10}],
            "counts": {"Reliability": {"medium": 1}}, "errors": [{"ruleId": "X", "error": "boom"}],
        },
    ]
    summary, score_docs = collect.build_summary("run1", "t0", "t1", "manual", results)

    assert summary["subscriptionCount"] == 2
    assert summary["resourceCount"] == 40
    assert summary["findingCount"] == 3
    assert summary["severityTotals"] == {"critical": 0, "high": 2, "medium": 1, "low": 0}
    assert summary["topTypes"][0] == {"type": "a/b", "count": 30}
    assert summary["subscriptions"][0]["id"] == "s1"
    assert summary["errors"] == [{"subscriptionId": "s2", "ruleId": "X", "error": "boom"}]
    assert summary["scores"]["Performance Efficiency"] is None
    assert {doc["id"] for doc in score_docs} == {"run1:s1", "run1:s2"}


def test_subscription_filter_parsing():
    assert graph.parse_subscription_filter("") == set()
    assert graph.parse_subscription_filter(" A-1 ; b-2,, ") == {"a-1", "b-2"}
