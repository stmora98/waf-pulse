from waf_pulse import collect, graph
from waf_pulse.rules import INVENTORY_QUERY, RESOURCE_GROUP_INVENTORY_QUERY, RESOURCE_GROUP_TYPE, RULES


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


def test_every_rule_runs_in_exactly_one_batch():
    batched = [r.id for batch in collect.rule_batches() for r in batch]
    assert sorted(batched) == sorted(r.id for r in RULES)
    assert all(len(batch) <= collect.RULES_PER_ACTIVITY for batch in collect.rule_batches())


# --- tenant wide collection -----------------------------------------------------------------------------

def test_collect_inventory_merges_resources_and_resource_groups_per_subscription(monkeypatch):
    def fake_query(credential, subscriptions, kql, max_rows=0):
        if kql == INVENTORY_QUERY:
            return [{"subscriptionId": "SUB1", "type": "Microsoft.Web/Sites", "count_": 3},
                    {"subscriptionId": "sub2", "type": "microsoft.web/sites", "count_": 1}]
        if kql == RESOURCE_GROUP_INVENTORY_QUERY:
            return [{"subscriptionId": "sub1", "type": RESOURCE_GROUP_TYPE, "count_": 12}]
        return []

    monkeypatch.setattr(graph, "query", fake_query)
    document = collect.collect_inventory(None, ["sub1", "sub2"])
    assert document["inventory"] == {
        "sub1": {"microsoft.web/sites": 3, RESOURCE_GROUP_TYPE: 12},
        "sub2": {"microsoft.web/sites": 1},
    }


def test_collect_rules_counts_per_subscription_and_survives_a_failing_rule(monkeypatch):
    failing, working = rule("SEC-STG-002"), rule("SEC-SQL-001")
    seen = []

    def fake_query(credential, subscriptions, kql, max_rows=0):
        seen.append(list(subscriptions))
        if kql == failing.query:
            raise RuntimeError("Forbidden\nsecond line")
        if kql == working.query:
            return [{"id": "/x/1", "name": "one", "type": "t", "subscriptionId": "SUB1"},
                    {"id": "/x/2", "name": "two", "type": "t", "subscriptionId": "sub1"},
                    {"id": "/x/3", "name": "three", "type": "t", "subscriptionId": "sub2"}]
        return []

    monkeypatch.setattr(graph, "query", fake_query)
    findings, document = collect.collect_rules(None, "run1", ["sub1", "sub2"], [failing, working])

    assert len(findings) == 3 and {f["subscriptionId"] for f in findings} == {"sub1", "sub2"}
    assert document["evaluated"] == [working.id]
    assert document["errors"] == [{"ruleId": failing.id, "error": "Forbidden"}]
    by_sub = {s["subscriptionId"]: s for s in document["stats"]}
    assert by_sub["sub1"]["affected"] == 2 and by_sub["sub2"]["affected"] == 1
    assert by_sub["sub1"]["applicable"] is None and by_sub["sub1"]["applicableTypes"] == list(working.applies_to)
    assert seen[0] == ["sub1", "sub2"]  # one tenant wide query, not one per subscription


def test_findings_per_rule_are_capped_but_counts_are_not(monkeypatch):
    working = rule("SEC-SQL-001")
    rows = [{"id": f"/x/{i}", "name": "n", "type": "t", "subscriptionId": "s1"} for i in range(collect.MAX_FINDINGS_PER_RULE + 30)]
    monkeypatch.setattr(graph, "query", lambda *a, **k: rows)
    findings, document = collect.collect_rules(None, "r", ["s1"], [working])
    assert len(findings) == collect.MAX_FINDINGS_PER_RULE
    assert document["stats"][0]["affected"] == collect.MAX_FINDINGS_PER_RULE + 30


# --- aggregation ----------------------------------------------------------------------------------------

def test_build_summary_aggregates_every_source():
    subscriptions = [{"id": "s1", "name": "One"}, {"id": "s2", "name": "Two"}]
    documents = [
        {"stats": [stat("SEC-SQL-001", "Security", "high", 2, 2, "s1")], "errors": [],
         "inventory": {"s1": {"microsoft.sql/servers": 2, "a/b": 8}}},
        {"stats": [stat("REL-VM-001", "Reliability", "medium", 1, 4, "s2")], "errors": [{"ruleId": "X", "error": "boom"}],
         "inventory": {"s2": {"microsoft.compute/virtualmachines": 4, "a/b": 26, RESOURCE_GROUP_TYPE: 3}}},
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


def test_applicable_comes_from_the_inventory_for_sources_that_cannot_count():
    documents = [
        {"stats": [stat("ADV-1", "Reliability", "high", 1, None, "s1", source="advisor",
                        applicableTypes=["microsoft.compute/virtualmachines"])], "errors": [],
         "inventory": {"s1": {"microsoft.compute/virtualmachines": 4}}},
    ]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}], documents)
    assert summary["scores"]["Reliability"] == 75  # 1 of 4 virtual machines; "high" caps at 79, not reached


def test_applicable_is_never_below_affected():
    documents = [
        {"stats": [stat("ADV-2", "Cost Optimization", "medium", 3, None, "s1", source="advisor",
                        applicableTypes=["unknown/type"])], "errors": [], "inventory": {"s1": {}}},
    ]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}], documents)
    assert summary["scores"]["Cost Optimization"] == 0  # 3 of at least 3


def test_clean_rules_get_zero_rows_so_the_score_reflects_what_passed():
    sql = rule("SEC-SQL-001")
    documents = [
        {"stats": [], "evaluated": [sql.id], "errors": [],
         "inventory": {"s1": {"microsoft.sql/servers": 3}, "s2": {"microsoft.web/sites": 9}}},
        {"stats": [{"ruleId": sql.id, "source": "builtin", "pillar": sql.pillar, "severity": sql.severity,
                    "subscriptionId": "s1", "affected": 1, "applicable": None,
                    "applicableTypes": list(sql.applies_to)}], "evaluated": [], "errors": []},
    ]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}, {"id": "s2", "name": "Two"}], documents)

    by_sub = {row["id"]: row for row in summary["subscriptions"]}
    assert by_sub["s1"]["scores"]["Security"] < 100          # 1 of 3 SQL servers violates the rule
    assert by_sub["s2"]["scores"]["Security"] is None        # no SQL servers: the rule does not apply there
    assert summary["sources"]["builtin"]["rules"] == 1


def test_a_rule_that_failed_to_run_is_not_scored_as_clean():
    documents = [{"stats": [], "evaluated": [], "errors": [{"ruleId": "SEC-SQL-001", "error": "x"}],
                  "inventory": {"s1": {"microsoft.sql/servers": 3}}}]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}], documents)
    assert summary["scores"]["Security"] is None


def test_all_resources_rules_use_the_resource_total_without_resource_groups():
    tags = rule("OPS-TAG-002")
    documents = [{"stats": [], "evaluated": [tags.id], "errors": [],
                  "inventory": {"s1": {"a/b": 8, "c/d": 2, RESOURCE_GROUP_TYPE: 50}}}]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}], documents)
    assert summary["scores"]["Operational Excellence"] == 100  # 0 of 10 resources


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


def test_commitment_options_are_totalled_per_term_not_added_together():
    item = {"subscriptionId": "s1", "resourceType": "virtualmachines", "currency": "USD",
            "terms": {"P1Y": 400.0, "P3Y": 689.0}, "lookbackDays": 30, "solution": "x", "recommendationType": "ri"}
    other = {**item, "subscriptionId": "s2", "terms": {"P1Y": 100.0, "P3Y": 150.0}}
    datasets = [{"name": "advisor", "data": {"commitments": [item]}}, {"name": "advisor", "data": {"commitments": [other]}}]
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [{"id": "s1", "name": "One"}], [], datasets)
    assert summary["commitments"]["totals"] == {"USD": {"P1Y": 500.0, "P3Y": 839.0}}
    assert [i["subscriptionName"] for i in summary["commitments"]["items"]] == ["One", "s2"]

def test_summary_without_optional_sources_has_no_defender_or_advisor_keys():
    summary, _ = collect.build_summary("r", "t0", "t1", "x", [], [], [])
    assert "secureScore" not in summary and "advisorSavings" not in summary


def test_subscription_filter_parsing():
    assert graph.parse_subscription_filter("") == set()
    assert graph.parse_subscription_filter(" A-1 ; b-2,, ") == {"a-1", "b-2"}


def test_subscription_chunks():
    assert graph.chunks([], 3) == [[]]
    assert graph.chunks(list("abcdefg"), 3) == [["a", "b", "c"], ["d", "e", "f"], ["g"]]
