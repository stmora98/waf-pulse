from waf_pulse import collect, graph
from waf_pulse.rules import INVENTORY_QUERY, RESOURCE_GROUP_INVENTORY_QUERY, RULES


def rule(rule_id):
    return next(r for r in RULES if r.id == rule_id)


def test_finding_id_is_stable_and_cosmos_safe():
    first_rule = RULES[0]
    row = {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a", "name": "a", "type": "t", "subscriptionId": "s"}
    first = collect.build_finding("run1", first_rule, row)
    second = collect.build_finding("run1", first_rule, dict(row, id=row["id"].upper()))
    assert first["id"] == second["id"]
    assert not any(ch in first["id"] for ch in "/\\?#")
    assert collect.build_finding("run2", first_rule, row)["id"] != first["id"]


def test_finding_key_is_the_same_in_every_run():
    first_rule = RULES[0]
    row = {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a", "name": "a", "type": "t", "subscriptionId": "s"}
    assert collect.build_finding("run1", first_rule, row)["key"] == collect.build_finding("run2", first_rule, row)["key"]
    other = collect.build_finding("run1", RULES[1], row)
    assert other["key"] != collect.build_finding("run1", first_rule, row)["key"]


def test_findings_expire_after_the_retention_period(monkeypatch):
    row = {"id": "/x", "name": "a", "type": "t", "subscriptionId": "s"}
    monkeypatch.delenv("FINDINGS_RETENTION_DAYS", raising=False)
    assert collect.build_finding("r", RULES[0], row)["ttl"] == 90 * 86400
    monkeypatch.setenv("FINDINGS_RETENTION_DAYS", "7")
    assert collect.build_finding("r", RULES[0], row)["ttl"] == 7 * 86400
    monkeypatch.setenv("FINDINGS_RETENTION_DAYS", "0")
    assert "ttl" not in collect.build_finding("r", RULES[0], row)
    monkeypatch.setenv("FINDINGS_RETENTION_DAYS", "not-a-number")
    assert collect.build_finding("r", RULES[0], row)["ttl"] == 90 * 86400


def test_collect_subscription_counts_findings_and_survives_a_failing_rule(monkeypatch):
    failing = rule("SEC-STG-002")

    def fake_query(credential, subscription_id, kql, max_rows=0):
        if kql == INVENTORY_QUERY:
            return [
                {"type": "microsoft.storage/storageaccounts", "count_": 8},
                {"type": "microsoft.sql/servers", "count_": 1},
                {"type": "microsoft.web/sites", "count_": 3},
            ]
        if kql == RESOURCE_GROUP_INVENTORY_QUERY:
            return [{"type": "microsoft.resources/subscriptions/resourcegroups", "count_": 12}]
        if kql == failing.query:
            raise RuntimeError("Forbidden")
        if kql == rule("SEC-SQL-001").query:
            return [{"id": "/x/1", "name": "one", "type": "t", "subscriptionId": subscription_id}]
        return []

    monkeypatch.setattr(graph, "query", fake_query)
    findings, result = collect.collect_subscription(None, "run1", {"id": "sub1", "name": "Sub 1"})

    assert result["resourceCount"] == 12  # resource groups are not resources
    assert result["findingCount"] == 1 and len(findings) == 1
    assert result["counts"]["Security"]["high"] == 1
    assert [error["ruleId"] for error in result["errors"]] == [failing.id]

    stats = {s["ruleId"]: s for s in result["ruleStats"]}
    assert failing.id not in stats  # a rule that could not run is not scored
    assert stats["SEC-SQL-001"]["affected"] == 1 and stats["SEC-SQL-001"]["applicable"] == 1
    assert stats["SEC-STG-001"]["applicable"] == 8
    assert stats["OPS-TAG-001"]["applicable"] == 12


def test_build_summary_aggregates_subscriptions_and_scores_with_rule_stats():
    def stat(rule_id, pillar, severity, affected, applicable):
        return {"ruleId": rule_id, "pillar": pillar, "severity": severity, "affected": affected, "applicable": applicable}

    results = [
        {
            "subscriptionId": "s1", "name": "One", "resourceCount": 10, "findingCount": 2,
            "topTypes": [{"type": "a/b", "count": 10}],
            "counts": {"Security": {"high": 2}},
            "ruleStats": [stat("SEC-SQL-001", "Security", "high", 2, 2)], "errors": [],
        },
        {
            "subscriptionId": "s2", "name": "Two", "resourceCount": 30, "findingCount": 1,
            "topTypes": [{"type": "a/b", "count": 20}, {"type": "c/d", "count": 10}],
            "counts": {"Reliability": {"medium": 1}},
            "ruleStats": [stat("REL-VM-001", "Reliability", "medium", 1, 4)],
            "errors": [{"ruleId": "X", "error": "boom"}],
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
    assert summary["scores"]["Security"] == 0       # every SQL server violates the rule
    assert summary["scores"]["Reliability"] <= 89   # medium finding caps the pillar
    assert summary["scores"]["Performance Efficiency"] is None
    assert {doc["id"] for doc in score_docs} == {"run1:s1", "run1:s2"}


def test_subscription_filter_parsing():
    assert graph.parse_subscription_filter("") == set()
    assert graph.parse_subscription_filter(" A-1 ; b-2,, ") == {"a-1", "b-2"}
