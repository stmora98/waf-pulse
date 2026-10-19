"""Suppressions on the dashboard: validation of what the visitor sends and the filter that hides suppressed findings. The
collector has the same matching rules (waf_pulse.suppress) to keep the scores in step."""
import re
import uuid
from datetime import date, datetime, timedelta, timezone

MAX_ENTRIES = 500
MAX_REASON = 200
DURATIONS = {0: "Forever", 30: "30 days", 90: "90 days", 180: "180 days", 365: "1 year"}
RULE_ID = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
RESOURCE_ID = re.compile(r"^/[A-Za-z0-9._()/:@ %'+,=-]{1,600}$")


def clean(entries):
    """The saved list without anything malformed."""
    result = []
    for entry in entries if isinstance(entries, list) else []:
        if (isinstance(entry, dict) and RULE_ID.match(str(entry.get("ruleId", "")))
                and (not entry.get("resourceId") or RESOURCE_ID.match(str(entry["resourceId"])))):
            result.append({"id": str(entry.get("id") or uuid.uuid4()), "ruleId": str(entry["ruleId"]),
                           "resourceId": str(entry.get("resourceId") or ""), "until": str(entry.get("until") or ""),
                           "reason": str(entry.get("reason") or "")[:MAX_REASON], "createdUtc": str(entry.get("createdUtc") or ""),
                           "ruleTitle": str(entry.get("ruleTitle") or "")[:200], "resourceName": str(entry.get("resourceName") or "")[:200]})
    return result[:MAX_ENTRIES]


def active(entries, today=None):
    today = (today or date.today()).isoformat()
    return [e for e in entries if not e["until"] or e["until"] >= today]


def matches(entry, finding):
    if str(entry["ruleId"]).lower() != str(finding.get("ruleId", "")).lower():
        return False
    target = entry["resourceId"].lower()
    return not target or target == str(finding.get("resourceId", "")).lower()


def split(findings, entries, today=None):
    """(visible, hidden): the findings that are not suppressed and the ones that are."""
    live = active(entries, today)
    if not live:
        return list(findings), []
    visible, hidden = [], []
    for finding in findings:
        (hidden if any(matches(entry, finding) for entry in live) else visible).append(finding)
    return visible, hidden


def add(entries, body, now=None):
    """(entries, error): adds or replaces the suppression described by the request body."""
    if not isinstance(body, dict):
        return None, "Send the suppression as an object."
    rule_id, resource_id = str(body.get("ruleId", "")), str(body.get("resourceId") or "")
    if not RULE_ID.match(rule_id):
        return None, "The recommendation is not valid."
    if resource_id and not RESOURCE_ID.match(resource_id):
        return None, "The resource is not valid."
    days = body.get("days", 0)
    if isinstance(days, bool) or days not in DURATIONS:
        return None, "Choose how long to suppress it."
    now = now or datetime.now(timezone.utc)
    kept = [e for e in clean(entries) if not (e["ruleId"].lower() == rule_id.lower() and e["resourceId"].lower() == resource_id.lower())]
    if len(kept) >= MAX_ENTRIES:
        return None, "Too many suppressions: restore some first."
    kept.append({"id": str(uuid.uuid4()), "ruleId": rule_id, "resourceId": resource_id,
                 "until": (now.date() + timedelta(days=days)).isoformat() if days else "",
                 "reason": str(body.get("reason") or "").strip()[:MAX_REASON], "createdUtc": now.isoformat(),
                 "ruleTitle": str(body.get("ruleTitle") or "")[:200], "resourceName": str(body.get("resourceName") or "")[:200]})
    return kept, None


def remove(entries, entry_id):
    return [e for e in clean(entries) if e["id"] != str(entry_id)]
