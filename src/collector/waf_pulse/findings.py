"""Finding documents shared by every source (built-in rules, checklists, Advisor, Defender)."""
import hashlib
import os
import re

DEFAULT_RETENTION_DAYS = 90
_SUBSCRIPTION_IN_ID = re.compile(r"/subscriptions/([^/]+)", re.IGNORECASE)


def retention_seconds():
    """Findings expire after FINDINGS_RETENTION_DAYS (default 90). 0 keeps them forever."""
    try:
        days = int(os.environ.get("FINDINGS_RETENTION_DAYS", DEFAULT_RETENTION_DAYS))
    except ValueError:
        days = DEFAULT_RETENTION_DAYS
    return days * 86400 if days > 0 else None


def finding_key(rule_id, resource_id):
    """Stable across runs, so two runs can be compared finding by finding."""
    return hashlib.sha1(f"{rule_id}|{str(resource_id).lower()}".encode("utf-8")).hexdigest()


def subscription_of(resource_id):
    match = _SUBSCRIPTION_IN_ID.search(str(resource_id or ""))
    return match.group(1).lower() if match else ""


def make_finding(run_id, *, rule_id, source, pillar, severity, title, recommendation, resource_id,
                 resource_name="", resource_type="", subscription_id="", link=None):
    resource_id = str(resource_id or "")
    digest = hashlib.sha1(f"{run_id}|{rule_id}|{resource_id.lower()}".encode("utf-8")).hexdigest()
    finding = {
        "id": digest,
        "key": finding_key(rule_id, resource_id),
        "runId": run_id,
        "subscriptionId": (subscription_id or subscription_of(resource_id)).lower(),
        "ruleId": rule_id,
        "source": source,
        "pillar": pillar,
        "severity": severity,
        "title": title,
        "recommendation": recommendation,
        "resourceId": resource_id,
        "resourceName": resource_name or resource_id.rsplit("/", 1)[-1],
        "resourceType": resource_type,
    }
    if link:
        finding["link"] = link
    ttl = retention_seconds()
    if ttl:
        finding["ttl"] = ttl
    return finding
