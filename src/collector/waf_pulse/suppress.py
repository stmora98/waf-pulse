"""Suppressions: recommendations the visitor accepted or postponed, saved by the dashboard. The collector leaves them out
of the counts so the scores stay honest; the dashboard hides the findings themselves."""
from collections import Counter
from datetime import date


def active(entries, today=None):
    """The suppressions that are still in force: no end date, or an end date that has not passed."""
    today = (today or date.today()).isoformat()
    result = []
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and entry.get("ruleId") and (not entry.get("until") or str(entry["until"]) >= today):
            result.append(entry)
    return result


def matches(entry, rule_id, resource_id):
    """An entry with a resource id hides that resource only; without one it hides the whole rule."""
    if str(entry.get("ruleId", "")).lower() != str(rule_id).lower():
        return False
    target = str(entry.get("resourceId") or "").lower()
    return not target or target == str(resource_id).lower()


def apply(stats_documents, findings, entries, today=None):
    """Lowers `affected` in the statistics by the findings the suppressions hide. findings: [{ruleId, resourceId,
    subscriptionId}] of the run. Returns (documents, hidden count)."""
    live = active(entries, today)
    if not live:
        return stats_documents, 0
    hidden = Counter()
    for finding in findings:
        if any(matches(entry, finding.get("ruleId", ""), finding.get("resourceId", "")) for entry in live):
            hidden[(str(finding.get("ruleId", "")), str(finding.get("subscriptionId", "")).lower())] += 1
    documents = []
    for document in stats_documents:
        rows = []
        for row in document.get("stats", []):
            removed = hidden.get((str(row.get("ruleId", "")), str(row.get("subscriptionId", "")).lower()), 0)
            rows.append({**row, "affected": max(row.get("affected", 0) - removed, 0)} if removed else row)
        documents.append({**document, "stats": rows} if "stats" in document else document)
    return documents, sum(hidden.values())
