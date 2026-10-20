"""What to fix first: the rules ranked by how many points of score fixing them would give, then by how many of the resources face the
internet, then by severity. The impact is calculated with the same scoring as the pillars: the score of the pillar with the rule
solved everywhere, minus the score it has."""
import scoring

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def impacts(stats):
    """{rule id: points the rule's pillar would gain if the rule had no affected resources}, from rows {ruleId, pillar, severity,
    affected, applicable} (several rows of the same rule are added first)."""
    merged = scoring.merge_rule_stats(stats)
    result = {}
    for pillar in scoring.PILLARS:
        rows = [r for r in merged if r["pillar"] == pillar]
        before = scoring.pillar_score(rows)
        if before is None:
            continue
        for row in rows:
            if row["affected"] <= 0:
                continue
            after = scoring.pillar_score([{**r, "affected": 0} if r["ruleId"] == row["ruleId"] else r for r in rows])
            result[row["ruleId"]] = {"points": (after or 0) - before, "pillar": pillar, "before": before}
    return result


def fix_first(stats, rules, findings, exposed=frozenset(), pillar=None, limit=10):
    """rules: the grouped rules (insights.group_rules); findings: the same findings they come from; exposed: lower case ids of
    the resources that face the internet. Returns the top rows: {ruleId, title, severity, pillar, resources, internet, points}."""
    gain = impacts(stats)
    facing = {}
    for finding in findings:
        if str(finding.get("resourceId", "")).lower() in exposed:
            facing.setdefault(finding.get("ruleId"), set()).add(str(finding.get("resourceId", "")).lower())
    rows = []
    for rule in rules:
        info = gain.get(rule["ruleId"])
        if pillar and rule.get("pillar") != pillar:
            continue
        rows.append({"ruleId": rule["ruleId"], "title": rule["title"], "severity": rule["severity"], "pillar": rule.get("pillar", ""), "resources": rule["resources"],
                     "internet": len(facing.get(rule["ruleId"], ())), "points": info["points"] if info else 0})
    rows.sort(key=lambda r: (-r["points"], -r["internet"], RANK.get(r["severity"], 9), -r["resources"], r["title"]))
    return rows[:limit]
