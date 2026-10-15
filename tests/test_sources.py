from waf_pulse import advisor, checklists, defender, graph

SUB = "11111111-1111-1111-1111-111111111111"


def rid(name, sub=SUB):
    return f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}"


# --- checklists -----------------------------------------------------------------------------------------

def test_shipped_checklists_are_loadable_and_automated():
    items = checklists.load_items()
    assert len(items) > 100
    assert all(item["graph"].strip() and item["guid"] for item in items)
    assert len({item["guid"] for item in items}) == len(items)


def test_every_item_is_planned_exactly_once_and_batches_are_small():
    planned = [item["guid"] for batch in checklists.plan_batches() for _, items in batch for item in items]
    assert sorted(planned) == sorted(item["guid"] for item in checklists.load_items())
    assert all(len(batch) <= checklists.BATCH_SIZE for batch in checklists.plan_batches())
    assert checklists.batch_count() == len(checklists.plan_batches())


def test_pillar_and_severity_mapping():
    assert checklists.to_pillar("Operations") == "Operational Excellence"
    assert checklists.to_pillar("cost") == "Cost Optimization"
    assert checklists.to_pillar(None) == "Operational Excellence"
    assert checklists.to_severity("High") == "high" and checklists.to_severity("weird") == "medium"
    assert checklists.is_non_compliant(False) and checklists.is_non_compliant("No") and checklists.is_non_compliant("non-compliant")
    assert not checklists.is_non_compliant(True) and not checklists.is_non_compliant(None)
    # Resource Graph returns the flag as a 0/1 integer for many queries
    assert checklists.is_non_compliant(0) and checklists.is_non_compliant("0") and checklists.is_non_compliant(0.0)
    assert not checklists.is_non_compliant(1) and not checklists.is_non_compliant("1") and not checklists.is_non_compliant("true")


def test_evaluate_builds_findings_and_per_subscription_stats():
    item = {"guid": "g1", "text": "Use private endpoints", "waf": "Security", "severity": "High", "service": "Storage",
            "link": "https://learn.microsoft.com/x", "graph": "q1"}
    other = {"guid": "g2", "text": "Another check", "waf": "Reliability", "severity": "Low", "graph": "q1"}
    batch = [("q1", [item, other]), ("q2", [{"guid": "g3", "text": "t", "graph": "q2"}])]
    rows = [
        [{"id": rid("a", "s1"), "compliant": False}, {"id": rid("b", "s1"), "compliant": True},
         {"id": rid("c", "s2"), "compliant": "false"}, {"id": rid("d", "s2"), "noflag": 1}],
        [],  # q2 returned nothing: the rule does not apply
    ]
    findings, stats = checklists.evaluate("run1", batch, rows)

    assert {f["resourceId"] for f in findings if f["ruleId"] == "CHK-g1"} == {rid("a", "s1"), rid("c", "s2")}
    assert len(findings) == 4  # two shared-query items x two violations
    sample = next(f for f in findings if f["ruleId"] == "CHK-g1")
    assert sample["source"] == "checklist" and sample["severity"] == "high" and sample["pillar"] == "Security"
    assert sample["link"] == "https://learn.microsoft.com/x" and sample["subscriptionId"] in ("s1", "s2")

    g1 = {s["subscriptionId"]: s for s in stats if s["ruleId"] == "CHK-g1"}
    assert (g1["s1"]["affected"], g1["s1"]["applicable"]) == (1, 2)
    assert (g1["s2"]["affected"], g1["s2"]["applicable"]) == (1, 1)  # the row without a flag is not evaluated
    assert not any(s["ruleId"] == "CHK-g3" for s in stats)


def test_evaluate_caps_stored_findings_but_not_the_counts():
    item = {"guid": "g", "text": "t", "waf": "Security", "severity": "High", "graph": "q"}
    rows = [[{"id": rid(f"n{i}"), "compliant": False} for i in range(checklists.MAX_FINDINGS_PER_RULE + 40)]]
    findings, stats = checklists.evaluate("r", [("q", [item])], rows)
    assert len(findings) == checklists.MAX_FINDINGS_PER_RULE
    assert stats[0]["affected"] == checklists.MAX_FINDINGS_PER_RULE + 40


def test_execute_batch_isolates_a_failing_query(monkeypatch):
    def fake_query(credential, subscriptions, kql, max_rows=0):
        if "BAD" in kql:
            raise RuntimeError("unsupported query\nsecond line")
        return [{"id": "row:" + kql.split()[0]}]

    monkeypatch.setattr(graph, "query", fake_query)
    rows, failures = checklists.execute_batch(None, ["s"], ["q0 x", "BAD", "q2 x"])

    assert [len(r) for r in rows] == [1, 0, 1]  # the bad query lost nothing else, order is preserved
    assert rows[2] == [{"id": "row:q2"}]
    assert failures == [None, "unsupported query", None]


def test_execute_batch_makes_one_call_per_query_and_no_union(monkeypatch):
    calls = []

    def fake_query(credential, subscriptions, kql, max_rows=0):
        calls.append(kql)
        return []

    monkeypatch.setattr(graph, "query", fake_query)
    checklists.execute_batch(None, ["s"], ["q0", "q1", "q2"])
    assert sorted(calls) == ["q0", "q1", "q2"]  # Resource Graph rejects union over subqueries


def test_run_batch_reports_failures_as_errors(monkeypatch):
    def fake_query(credential, subscriptions, kql, max_rows=0):
        raise RuntimeError("Forbidden")

    monkeypatch.setattr(graph, "query", fake_query)
    findings, stats, errors = checklists.run_batch(None, "run1", ["s"], 0)
    assert findings == [] and stats == []
    assert len(errors) == len(checklists.plan_batches()[0])
    assert errors[0]["ruleId"].startswith("CHK-") and "Forbidden" in errors[0]["error"]


def test_strip_comments_keeps_the_rest_of_a_flattened_query():
    flat = "resources | extend a = 1 // adjust this | extend compliant = true // check | project id, compliant"
    cleaned = checklists.strip_comments(flat)
    assert "adjust" not in cleaned and "check" not in cleaned
    assert "extend compliant = true" in cleaned and cleaned.endswith("project id, compliant")


def test_strip_comments_leaves_quoted_text_alone():
    query = "resources | where tags['url'] == 'https://learn.microsoft.com/x' | where name == \"a//b\""
    assert checklists.strip_comments(query) == query
    assert checklists.strip_comments("a // c\nb") == "a \nb"


def test_shipped_queries_have_no_comments_left():
    assert all("//" not in item["graph"].replace("://", "") for item in checklists.load_items())


# --- advisor --------------------------------------------------------------------------------------------

def advisor_row(rec="rec1", resource=None, sub="s1", category="Cost", impact="High", saving=None):
    return {"id": f"/subscriptions/{sub}/providers/Microsoft.Advisor/recommendations/{rec}", "subscriptionId": sub,
            "category": category, "impact": impact, "recommendationType": rec,
            "impactedType": "microsoft.compute/virtualmachines", "impactedName": "vm1",
            "problem": "Right-size VM", "solution": "Resize it", "resourceId": resource or rid("x", sub),
            "annualSavings": saving, "currency": "USD" if saving else None}


def test_advisor_groups_by_recommendation_type_and_subscription():
    rows = [advisor_row(resource="/r/1", saving=100), advisor_row(resource="/r/2", saving=50.5),
            advisor_row(resource="/r/2", saving=50.5),  # duplicate of the same resource
            advisor_row(rec="rec2", category="HighAvailability", impact="Low", sub="s2")]
    findings, stats, savings = advisor.evaluate("run1", rows)

    cost = next(s for s in stats if s["ruleId"] == "ADV-rec1")
    assert cost["affected"] == 2 and cost["applicable"] is None and cost["pillar"] == "Cost Optimization"
    assert cost["applicableType"] == "microsoft.compute/virtualmachines" and cost["source"] == "advisor"
    reliability = next(s for s in stats if s["ruleId"] == "ADV-rec2")
    assert reliability["pillar"] == "Reliability" and reliability["severity"] == "low" and reliability["subscriptionId"] == "s2"
    assert findings[0]["source"] == "advisor" and findings[0]["title"] == "Right-size VM"
    assert savings["USD"]["annual"] == 201.0
    assert savings["USD"]["bySubscription"] == {"s1": 201.0}


def test_advisor_category_and_impact_mapping():
    assert advisor.to_pillar("HighAvailability") == "Reliability"
    assert advisor.to_pillar("OperationalExcellence") == "Operational Excellence"
    assert advisor.to_pillar("Performance") == "Performance Efficiency"
    assert advisor.to_pillar("unexpected") == "Operational Excellence"
    assert advisor.to_severity("Medium") == "medium" and advisor.to_severity(None) == "medium"


# --- defender -------------------------------------------------------------------------------------------

def test_secure_score_percentage_accepts_ratio_or_percent_or_missing():
    assert defender.percentage({"percentage": 0.62}) == 62.0
    assert defender.percentage({"percentage": 62.0}) == 62.0
    assert defender.percentage({"percentage": None, "current": 15, "max": 60}) == 25.0
    assert defender.percentage({"percentage": None, "max": None}) is None


def test_defender_builds_stats_findings_and_dataset():
    scores = [{"subscriptionId": "S1", "current": 30, "max": 60, "percentage": 0.5}]
    controls = [{"subscriptionId": "S1", "control": "Enable MFA", "unhealthy": 4, "healthy": 1},
                {"subscriptionId": "S2", "control": "Enable MFA", "unhealthy": 2, "healthy": 0}]
    summary = [{"assessment": "a1", "displayName": "Encrypt disks", "severity": "High", "subscriptionId": "S1",
                "unhealthy": 3, "healthy": 7}]
    unhealthy = [{"assessment": "a1", "subscriptionId": "S1", "resourceId": rid("a", "s1")},
                 {"assessment": "a1", "subscriptionId": "S1", "resourceId": ""},
                 {"assessment": "unknown", "subscriptionId": "S1", "resourceId": rid("b", "s1")}]
    findings, stats, dataset = defender.evaluate("run1", scores, controls, summary, unhealthy)

    assert stats == [{"ruleId": "MDC-a1", "source": "defender", "pillar": "Security", "severity": "high",
                      "subscriptionId": "s1", "affected": 3, "applicable": 10}]
    assert len(findings) == 1 and findings[0]["title"] == "Encrypt disks" and findings[0]["source"] == "defender"
    assert dataset["secureScores"] == [{"subscriptionId": "s1", "current": 30, "max": 60, "percentage": 50.0}]
    assert dataset["topControls"] == [{"control": "Enable MFA", "unhealthy": 6, "healthy": 1}]


def test_defender_failures_are_reported_not_raised(monkeypatch):
    def fake_query(credential, subscriptions, kql, max_rows=0):
        if "securescorecontrols" in kql:
            raise RuntimeError("no access")
        return []

    monkeypatch.setattr(graph, "query", fake_query)
    findings, stats, dataset, errors = defender.collect(None, "run1", ["s1"])
    assert findings == [] and stats == []
    assert [e["ruleId"] for e in errors] == ["defender-controls"]


def test_integer_compliance_flags_produce_findings():
    item = {"guid": "g", "text": "t", "waf": "Security", "severity": "High", "graph": "q"}
    rows = [[{"id": rid("a"), "compliant": 0}, {"id": rid("b"), "compliant": 1}]]
    findings, stats = checklists.evaluate("r", [("q", [item])], rows)
    assert [f["resourceId"] for f in findings] == [rid("a")]
    assert (stats[0]["affected"], stats[0]["applicable"]) == (1, 2)


def test_short_error_drops_the_support_ticket_text():
    error = RuntimeError(
        "(BadRequest) Please provide below info when asking for support: timestamp = x\nCode: BadRequest\n"
        "Message: Please provide below info when asking for support: timestamp = x\n"
        "\tMessage: 'extend' operator: Failed to resolve column named 'principalType'"
    )
    assert checklists._short_error(error).startswith("'extend' operator")