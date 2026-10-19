"""Storage accounts without a lifecycle management policy (Reader is enough).

Resource Graph does not index the management policy of a storage account, so each account is asked through ARM. Without a
policy nothing moves old blobs to a cooler tier or deletes them, and the account only grows.
"""
import time
from concurrent.futures import ThreadPoolExecutor

from . import graph, rest
from .findings import make_finding

SCOPE = "https://management.azure.com/.default"
API_VERSION = "2023-01-01"
WORKERS = 6
MAX_ACCOUNTS = 1000
TIME_BUDGET_SECONDS = 180
RULE_ID = "COST-STG-002"
TITLE = "Storage account has no lifecycle management policy"
RECOMMENDATION = ("Add a lifecycle management rule that moves blobs to the Cool or Archive tier and deletes the ones nobody needs, "
                  "so the account does not grow without limit.")

QUERY = """
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where tostring(kind) in~ ('StorageV2', 'BlobStorage', 'BlockBlobStorage')
| project id, name, type, subscriptionId
"""


def check(credential, resource_id):
    """Returns 'yes' (has a policy), 'no', 'denied' or 'error'."""
    token = credential.get_token(SCOPE).token
    response = rest.get(f"https://management.azure.com{resource_id}/managementPolicies/default", token, {"api-version": API_VERSION})
    if response.status_code == 200:
        rules = ((response.json().get("properties") or {}).get("policy") or {}).get("rules") or []
        return "yes" if rules else "no"
    if response.status_code == 404:
        return "no"
    if response.status_code in (401, 403):
        return "denied"
    return "error"


def evaluate(run_id, rows, outcomes):
    """rows: ARG rows; outcomes: {resource id (lower): outcome}. Returns (findings, stats, dataset)."""
    findings, per_sub = [], {}
    skipped = {"denied": 0, "error": 0, "notChecked": 0}
    with_policy = 0
    for row in rows:
        outcome = outcomes.get(str(row["id"]).lower())
        if outcome is None:
            skipped["notChecked"] += 1
            continue
        if outcome not in ("yes", "no"):
            skipped[outcome] += 1
            continue
        sub = str(row.get("subscriptionId", "")).lower()
        entry = per_sub.setdefault(sub, {"affected": 0, "applicable": 0})
        entry["applicable"] += 1
        if outcome == "yes":
            with_policy += 1
            continue
        entry["affected"] += 1
        if len(findings) < 1000:
            findings.append(make_finding(
                run_id, rule_id=RULE_ID, source="lifecycle", pillar="Cost Optimization", severity="low", title=TITLE,
                recommendation=RECOMMENDATION, resource_id=row["id"], resource_name=row.get("name", ""),
                resource_type="microsoft.storage/storageaccounts", subscription_id=sub))
    stats = [{"ruleId": RULE_ID, "source": "lifecycle", "pillar": "Cost Optimization", "severity": "low", "subscriptionId": sub,
              "affected": value["affected"], "applicable": value["applicable"]} for sub, value in per_sub.items()]
    checked = sum(v["applicable"] for v in per_sub.values())
    return findings, stats, {"checked": checked, "withPolicy": with_policy,
                             "percent": round(100 * with_policy / checked, 1) if checked else None, "skipped": skipped}


def collect(credential, run_id, subscription_ids):
    rows, errors = [], []
    try:
        for chunk in graph.chunks(subscription_ids):
            rows.extend(graph.query(credential, chunk, QUERY, max_rows=MAX_ACCOUNTS))
    except Exception as exc:
        errors.append({"ruleId": "lifecycle-list", "error": str(exc).splitlines()[0][:200]})
    rows = rows[:MAX_ACCOUNTS]
    deadline = time.monotonic() + TIME_BUDGET_SECONDS

    def run(row):
        if time.monotonic() > deadline:
            return str(row["id"]).lower(), None
        try:
            return str(row["id"]).lower(), check(credential, row["id"])
        except Exception:
            return str(row["id"]).lower(), "error"

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        outcomes = {key: value for key, value in pool.map(run, rows) if value is not None}
    findings, stats, dataset = evaluate(run_id, rows, outcomes)
    if dataset["skipped"]["notChecked"]:
        errors.append({"ruleId": "lifecycle-budget", "error": f"{dataset['skipped']['notChecked']} accounts were not checked within the time budget"})
    return findings, stats, dataset, errors
