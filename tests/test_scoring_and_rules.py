from waf_pulse import scoring
from waf_pulse.rules import PILLARS, RULES, SEVERITIES


def test_no_findings_scores_100():
    assert scoring.pillar_score({}, 50) == 100


def test_heavy_findings_floor_at_zero():
    assert scoring.pillar_score({"critical": 500}, 10) == 0


def test_score_decreases_with_severity():
    medium = scoring.pillar_score({"medium": 5}, 100)
    high = scoring.pillar_score({"high": 5}, 100)
    assert high < medium < 100


def test_empty_tenant_does_not_divide_by_zero():
    assert 0 <= scoring.pillar_score({"low": 3}, 0) <= 100


def test_pillar_without_rules_has_no_score():
    scores = scoring.score_pillars({}, 100)
    covered = {rule.pillar for rule in RULES}
    for pillar in PILLARS:
        assert (scores[pillar] is None) == (pillar not in covered)


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
