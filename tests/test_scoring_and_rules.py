from waf_pulse import scoring
from waf_pulse.rules import PILLARS, RULES, SEVERITIES


def stat(severity, affected, applicable, pillar="Security", rule_id="R"):
    return {"ruleId": rule_id, "pillar": pillar, "severity": severity, "affected": affected, "applicable": applicable}


def test_nothing_applicable_has_no_score():
    assert scoring.pillar_score([]) is None
    assert scoring.pillar_score([stat("high", 0, 0)]) is None


def test_clean_pillar_scores_100():
    assert scoring.pillar_score([stat("high", 0, 8), stat("medium", 0, 8)]) == 100


def test_everything_violating_scores_zero():
    assert scoring.pillar_score([stat("high", 5, 5)]) == 0


def test_one_high_finding_is_not_hidden_by_a_large_estate():
    # 1 of 1000 resources violates a high rule: the prevalence penalty is ~0, the severity cap still applies.
    assert scoring.pillar_score([stat("high", 1, 1000)]) == 79


def test_severity_caps():
    assert scoring.pillar_score([stat("critical", 1, 1000)]) == 49
    assert scoring.pillar_score([stat("high", 1, 1000)]) == 79
    assert scoring.pillar_score([stat("medium", 1, 1000)]) == 89


def test_low_severity_is_not_capped():
    assert scoring.pillar_score([stat("low", 1, 100)]) == 99


def test_worst_severity_wins_the_cap():
    assert scoring.pillar_score([stat("medium", 1, 1000), stat("critical", 1, 1000)]) == 49


def test_prevalence_is_clamped():
    assert scoring.pillar_score([stat("medium", 50, 5)]) == 0


def test_real_sandbox_case_no_longer_scores_100():
    # 8 storage accounts without findings and 1 of 1 SQL servers public.
    stats = [stat("high", 0, 8, rule_id="STG1"), stat("medium", 0, 8, rule_id="STG2"), stat("high", 1, 1, rule_id="SQL")]
    score = scoring.pillar_score(stats)
    assert score < 100 and score <= 79


def test_score_pillars_marks_uncovered_pillars_as_none():
    scores = scoring.score_pillars([stat("high", 0, 3, pillar="Security")])
    covered = {rule.pillar for rule in RULES}
    assert scores["Security"] == 100
    for pillar in PILLARS:
        if pillar not in covered:
            assert scores[pillar] is None


def test_merge_rule_stats_adds_subscriptions():
    merged = scoring.merge_rule_stats(
        [[stat("high", 1, 4, rule_id="A")], [stat("high", 2, 6, rule_id="A"), stat("low", 0, 1, rule_id="B")]]
    )
    by_id = {item["ruleId"]: item for item in merged}
    assert by_id["A"]["affected"] == 3 and by_id["A"]["applicable"] == 10
    assert by_id["B"]["applicable"] == 1


def test_merge_counts_adds_severities():
    target = {"Security": {"high": 2}}
    scoring.merge_counts(target, {"Security": {"high": 1, "low": 4}, "Reliability": {"medium": 3}})
    assert target == {"Security": {"high": 3, "low": 4}, "Reliability": {"medium": 3}}


def test_rule_catalog_is_valid():
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids))
    for rule in RULES:
        assert rule.pillar in PILLARS
        assert rule.severity in SEVERITIES
        assert "project id, name, type, subscriptionId" in rule.query
        assert rule.applies_to and all(t == t.lower() and "/" in t for t in rule.applies_to)
