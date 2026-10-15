from waf_pulse import collect, graph
from waf_pulse.rules import INVENTORY_QUERY, RESOURCE_GROUP_INVENTORY_QUERY, RULES


def rule(rule_id):
    return next(r for r in RULES if r.id == rule_id)


def stat(rule_id, pillar, severity, affected, applicable, sub="s1", source="builtin", **extra):
    return {"ruleId": rule_id, "source": source, "pillar": pillar, "severity": severity, "subscriptionId": sub,
            "affected": affected, "applicable": applicable, **extra}


def test_finding_id_is_stable_and_cosmos_safe():
    first_rule = RULES[0]
    row = {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a", "name": "a", "type": "t", "subscriptionId": "s"}
    first = collect.build_finding("run1", first_rule, row)
    second = collect.build_finding("run1", first_rule, dict(row, id=row["id"].upper()))
    assert first["id"] == second["id"]
    assert not any(ch in first["id"] for ch in "/\\?#")
    assert collect.build_finding("run2", first_rule, row)["id"] != first["id"]
    assert first["source"] == "builtin"


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

    def fake_query(credential, subscriptions, kql, max_rows=0):
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
            return [{"id": "/x/1", "name": "one", "type": "t", "subscriptionId": subscriptions}]
        return []

    monkeypatch.setattr(graph, "query", fake_query)
    findings, document = collect.collect_subscription(None, "run1", {"id": "SUB1", "name": "Sub 1"})

    assert len(findings) == 1 and findings[0]["subscriptionId"] == "sub1"
    assert [error["ruleId"] for error in document["errors"]] == [failing.id]
    assert document["inventory"]["sub1"]["microsoft.web/sites"] == 3

    stats = {s["ruleId"]: s for s in document["stats"]}
    assert failing.id not in stats  # a rule that could not run is not scored
    assert stats["SEC-SQL-001"]["affected"] == 1 and stats["SEC-SQL-001"]["applicable"] == 1
    assert stats["SEC-STG-001"]["applicable"] == 8
    assert stats["OPS-TAG-001"]["applicable"] == 12
    assert stats["OPS-TAG-002"]["applicable"] == 12  # "*" counts every resource, not resource groups


def test_build_summary_aggregates_every_source():
    subscriptions = [{"id": "s1", "name": "One"}, {"id": "s2", "name": "Two"}]
    documents = [
        {"stats": [stat("SEC-SQL-001", "Security", "high", 2, 2, "s1")], "errors": [],
         "inventory": {"s1": {"microsoft.sql/servers": 2, "a/b": 8}}},
        {"stats": [stat("REL-VM-001", "Reliability", "medium", 1, 4, "s2")], "errors": [{"ruleId": "X", "error": "boom"}],
         "inventory": {"s2": {"microsoft.compute/virtualmachines": 4, "a/b": 26,
                              "microsoft.resources/subscriptions/resourcegroups": 3}}},
        {"stats": [stat("CHK-1", "Security", "medium", 1, 5, "s1", source="checklist")], "errors": []},
    ]
    summary, score_docs = collect.build_summary("run1", "t0", "t1", "manual", subscriptions, documents)

    assert summary["subscriptionCount"] == 2
    assert summary["resourceCount"] == 40  # resource groups are not resources
    assert summary["findingCount"] == 4
    assert summary["severityTotals"] == {"critical": 0, "high": 2, "medium": 2, "low": 0}
    assert summary["sources"] == {"builtin": {"rules": 2, "findings": 3}, "checklist": {"rules": 1, "findings": 1}}
    assert summary["topTypes"][0] == {"type": "a/b", "count": 34}
    assert summary["subscriptions"][0]["id"] == "s1"
    assert summary["errors"] == [{"ruleId": "X", "error": "boom"}]
    assert summary["scores"]["Security"] < 100 and summary["scores"]["Performance Efficiency"] is None
    assert {doc["id"] for doc in score_docs} == {"run1:s1", "run1:s2"}
    by_sub = {row["id"]: row for row in summary["subscriptions"]}
    assert by_sub["s2"]["scores"]["Reliability"] <= 89 and by_sub["s2"]["scores"]["Security"] is None


def test_applicable_is_taken_from_the_inventory_when_a_source_cannot_count():
    documents = [
        {"stats": [stat("ADV-1", "Reliability", "high", 1, None, "s1", source="advisor",
                        applicableType="microsoft.compute/virtualmachines")], "errors": [],
         "inventory": {"s1": {"microsoft.compute/virtualmachines": 4}}},
    ]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}], documents)
    assert summary["scores"]["Reliability"] == round(100 - 25)  # 1 of 4 VMs, capped at 79 by "high"? 75 < 79


def test_advisor_applicable_never_below_affected():
    documents = [
        {"stats": [stat("ADV-2", "Cost Optimization", "medium", 3, None, "s1", source="advisor",
                        applicableType="unknown/type")], "errors": [], "inventory": {"s1": {}}},
    ]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}], documents)
    assert summary["scores"]["Cost Optimization"] == 0  # 3 of at least 3


def test_defender_and_advisor_datasets_reach_the_summary():
    datasets = [
        {"name": "defender", "data": {
            "secureScores": [{"subscriptionId": "s1", "current": 30, "max": 60, "percentage": 50.0},
                             {"subscriptionId": "s2", "current": 45, "max": 60, "percentage": 75.0}],
            "topControls": [{"control": "Enable MFA", "unhealthy": 2, "healthy": 1}]}},
        {"name": "defender", "data": {"secureScores": [], "topControls": [{"control": "Enable MFA", "unhealthy": 3, "healthy": 0}]}},
        {"name": "advisor", "data": {"savings": {"USD": {"annual": 100.0, "bySubscription": {"s1": 100.0}}}}},
        {"name": "advisor", "data": {"savings": {"USD": {"annual": 50.5, "bySubscription": {}}}}},
    ]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}], [], datasets)
    assert summary["secureScore"]["average"] == 62.5
    assert summary["secureScore"]["subscriptions"][0]["percentage"] == 50.0
    assert summary["secureScore"]["topControls"][0] == {"control": "Enable MFA", "unhealthy": 5, "healthy": 1}
    assert summary["advisorSavings"] == {"USD": 150.5}


def test_summary_without_optional_sources_has_no_defender_or_advisor_keys():
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [], [], [])
    assert "secureScore" not in summary and "advisorSavings" not in summary


def test_subscription_filter_parsing():
    assert graph.parse_subscription_filter("") == set()
    assert graph.parse_subscription_filter(" A-1 ; b-2,, ") == {"a-1", "b-2"}


def test_subscription_chunks():
    assert graph.chunks([], 3) == [[]]
    assert graph.chunks(list("abcdefg"), 3) == [["a", "b", "c"], ["d", "e", "f"], ["g"]]
