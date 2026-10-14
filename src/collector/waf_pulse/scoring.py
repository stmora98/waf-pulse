"""Pillar scoring.

penalty = sum(weight[severity] * count) / max(1, resourceCount) * 10, capped at 100
score   = round(100 - penalty)

A pillar without any rule has no score (None) instead of a misleading 100.
"""
from .rules import PILLARS, SEVERITIES, pillars_with_rules

WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}


def pillar_score(severity_counts, resource_count):
    weighted = sum(WEIGHTS[s] * int(severity_counts.get(s, 0)) for s in SEVERITIES)
    penalty = min(100.0, weighted / max(1, int(resource_count)) * 10)
    return max(0, round(100 - penalty))


def score_pillars(counts_by_pillar, resource_count):
    """counts_by_pillar: {pillar: {severity: count}}. Returns {pillar: score or None}."""
    covered = pillars_with_rules()
    scores = {}
    for pillar in PILLARS:
        if pillar not in covered:
            scores[pillar] = None
            continue
        scores[pillar] = pillar_score(counts_by_pillar.get(pillar, {}), resource_count)
    return scores


def merge_counts(target, source):
    """Adds {pillar: {severity: count}} from source into target."""
    for pillar, by_severity in source.items():
        bucket = target.setdefault(pillar, {})
        for severity, count in by_severity.items():
            bucket[severity] = bucket.get(severity, 0) + int(count)
    return target
