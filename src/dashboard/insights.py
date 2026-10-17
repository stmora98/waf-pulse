"""Aggregations over the findings of one run, for the overview, pillar and recommendation pages. Pure functions."""
import re
from collections import Counter, defaultdict

SEVERITIES = ("critical", "high", "medium", "low")
RANK = {level: index for index, level in enumerate(SEVERITIES)}

# slug -> (pillar, label used in the navigation)
PILLAR_PAGES = {
    "security": ("Security", "Security"),
    "reliability": ("Reliability", "Reliability"),
    "cost": ("Cost Optimization", "Cost"),
    "performance": ("Performance Efficiency", "Performance"),
    "operations": ("Operational Excellence", "Operations"),
}
PILLAR_SLUG = {pillar: slug for slug, (pillar, _) in PILLAR_PAGES.items()}

_NUMBER = re.compile(r"\d+(?:\.\d+)?")


def severity_totals(findings):
    counts = Counter(f.get("severity") for f in findings)
    return {level: counts.get(level, 0) for level in SEVERITIES}


def _generic_title(titles):
    """Findings of one rule can carry measured values ("CPU 3.2%"); the group shows the title without them."""
    unique = set(titles)
    if len(unique) == 1:
        return next(iter(unique))
    most_common = Counter(_NUMBER.sub("N", title) for title in titles).most_common(1)[0][0]
    return most_common.replace("N", "…")


def group_rules(findings):
    """One row per rule, the most severe and widespread first."""
    groups = defaultdict(list)
    for finding in findings:
        groups[finding.get("ruleId") or "unknown"].append(finding)
    rows = []
    for rule, items in groups.items():
        first = items[0]
        rows.append({
            "ruleId": rule, "title": _generic_title([i.get("title", "") for i in items]),
            "severity": min((i.get("severity", "low") for i in items), key=lambda s: RANK.get(s, 9)),
            "pillar": first.get("pillar", ""), "source": first.get("source") or "builtin",
            "recommendation": first.get("recommendation", ""),
            "resources": len({str(i.get("resourceId", "")).lower() for i in items}),
            "subscriptions": len({i.get("subscriptionId", "") for i in items}),
            "link": next((i["link"] for i in items if i.get("link")), None),
        })
    rows.sort(key=lambda row: (RANK.get(row["severity"], 9), -row["resources"], row["title"]))
    return rows


def short_type(resource_type):
    value = str(resource_type or "").lower()
    return value.replace("microsoft.", "", 1) if value else "(no type)"


def top_counts(findings, field, limit=8, transform=None):
    """[(label, count)] largest first. Blank values are skipped."""
    counter = Counter()
    for finding in findings:
        value = finding.get(field)
        if value:
            counter[transform(value) if transform else value] += 1
    return counter.most_common(limit)


def by_pillar(findings, pillars):
    """[(pillar, {severity: count})] in the given order."""
    table = {pillar: Counter() for pillar in pillars}
    for finding in findings:
        if finding.get("pillar") in table:
            table[finding["pillar"]][finding.get("severity")] += 1
    return [(pillar, dict(table[pillar])) for pillar in pillars]


def worst_resources(findings, limit=8):
    """Resources with the most findings: [(name, resourceId, count)]."""
    counter, names = Counter(), {}
    for finding in findings:
        resource = str(finding.get("resourceId", "")).lower()
        if not resource or "/commitments/" in resource:
            continue
        counter[resource] += 1
        names.setdefault(resource, finding.get("resourceName") or resource.rsplit("/", 1)[-1])
    return [(names[resource], resource, count) for resource, count in counter.most_common(limit)]
