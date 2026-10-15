"""Pillar scoring.

For every rule that applies (at least one resource of the types it evaluates):

    prevalence = min(1, affected / applicable)

    penalty = sum(weight[severity] * prevalence) / sum(weight[severity]) * 100     over the pillar's rules
    score   = 100 - penalty

The worst severity found then caps the score, so a single serious finding is never hidden by a
large estate:  critical <= 49,  high <= 79,  medium <= 89.

A pillar with no applicable resources has no score (None) instead of a misleading 100.
"""
from .rules import PILLARS, SEVERITIES

WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
SEVERITY_CAPS = {"critical": 49, "high": 79, "medium": 89}


def pillar_score(rule_stats):
    """rule_stats: iterable of {severity, affected, applicable} for one pillar. None when nothing applies."""
    applicable_rules = [r for r in rule_stats if int(r["applicable"]) > 0]
    if not applicable_rules:
        return None

    total_weight = sum(WEIGHTS[r["severity"]] for r in applicable_rules)
    penalty = sum(
        WEIGHTS[r["severity"]] * min(1.0, int(r["affected"]) / int(r["applicable"])) for r in applicable_rules
    )
    score = 100 - penalty / total_weight * 100

    for severity in SEVERITIES:
        cap = SEVERITY_CAPS.get(severity)
        if cap is not None and any(r["severity"] == severity and int(r["affected"]) > 0 for r in applicable_rules):
            score = min(score, cap)
            break
    return max(0, round(score))


def score_pillars(rule_stats):
    """rule_stats: iterable of {pillar, severity, affected, applicable}. Returns {pillar: score or None}."""
    by_pillar = {pillar: [] for pillar in PILLARS}
    for stat in rule_stats:
        by_pillar[stat["pillar"]].append(stat)
    return {pillar: pillar_score(stats) for pillar, stats in by_pillar.items()}


def merge_rule_stats(per_subscription):
    """Adds affected and applicable counts for the same rule across subscriptions."""
    merged = {}
    for stats in per_subscription:
        for stat in stats:
            current = merged.setdefault(
                stat["ruleId"],
                {"ruleId": stat["ruleId"], "pillar": stat["pillar"], "severity": stat["severity"],
                 "affected": 0, "applicable": 0},
            )
            current["affected"] += int(stat["affected"])
            current["applicable"] += int(stat["applicable"])
    return list(merged.values())


def merge_counts(target, source):
    """Adds {pillar: {severity: count}} from source into target."""
    for pillar, by_severity in source.items():
        bucket = target.setdefault(pillar, {})
        for severity, count in by_severity.items():
            bucket[severity] = bucket.get(severity, 0) + int(count)
    return target
