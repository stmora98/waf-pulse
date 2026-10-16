"""Diagnostic settings coverage (Reader is enough).

Resource Graph lists the resources that can emit logs and the ARM diagnostic settings API tells whether anything
receives them. A resource with no setting, or with settings that send nothing anywhere, leaves no trail to
investigate an incident or an audit question.
"""
import time
from concurrent.futures import ThreadPoolExecutor

from . import graph, rest
from .findings import make_finding

SCOPE = "https://management.azure.com/.default"
API_VERSION = "2021-05-01-preview"
WORKERS = 6
MAX_RESOURCES = 1500
TIME_BUDGET_SECONDS = 240
RULE_ID = "OPS-DIAG-001"

# resource type -> label. These are the types where logs matter most for security and operations.
TYPES = {
    "microsoft.keyvault/vaults": "Key Vault",
    "microsoft.network/azurefirewalls": "Azure Firewall",
    "microsoft.network/applicationgateways": "Application Gateway",
    "microsoft.network/networksecuritygroups": "Network security group",
    "microsoft.network/frontdoors": "Front Door",
    "microsoft.cdn/profiles": "Front Door / CDN profile",
    "microsoft.web/sites": "App Service or Function app",
    "microsoft.containerservice/managedclusters": "AKS cluster",
    "microsoft.documentdb/databaseaccounts": "Cosmos DB account",
    "microsoft.sql/managedinstances": "SQL Managed Instance",
    "microsoft.servicebus/namespaces": "Service Bus namespace",
    "microsoft.eventhub/namespaces": "Event Hubs namespace",
    "microsoft.apimanagement/service": "API Management",
    "microsoft.cache/redis": "Redis cache",
}

QUERY = """
resources
| where type in~ ({types})
| project id, name, type, subscriptionId
""".format(types=", ".join(f"'{name}'" for name in TYPES))

TITLE = "{label} does not send diagnostic logs or metrics anywhere"
RECOMMENDATION = ("Add a diagnostic setting that sends the logs to a Log Analytics workspace, a storage account or an "
                  "event hub. Azure Policy can apply it to every new resource.")


def sends_somewhere(body):
    """True when at least one setting has a destination and something enabled."""
    for setting in (body or {}).get("value", []):
        properties = setting.get("properties", {})
        destination = any(properties.get(key) for key in (
            "workspaceId", "storageAccountId", "eventHubAuthorizationRuleId", "marketplacePartnerId"))
        enabled = any(item.get("enabled") for item in (properties.get("logs") or []) + (properties.get("metrics") or []))
        if destination and enabled:
            return True
    return False


def check(credential, resource_id):
    """Returns 'yes', 'no', 'denied', 'unsupported' or 'error'."""
    token = credential.get_token(SCOPE).token
    response = rest.get(f"https://management.azure.com{resource_id}/providers/microsoft.insights/diagnosticSettings",
                        token, {"api-version": API_VERSION})
    if response.status_code == 200:
        return "yes" if sends_somewhere(response.json()) else "no"
    if response.status_code in (401, 403):
        return "denied"
    if response.status_code in (400, 404):
        return "unsupported"
    return "error"


def evaluate(run_id, rows, outcomes):
    """rows: ARG rows; outcomes: {resource id (lower): outcome}. Returns (findings, stats, dataset)."""
    findings, per_sub, per_type = [], {}, {}
    skipped = {"denied": 0, "error": 0, "unsupported": 0, "notChecked": 0}
    for row in rows:
        outcome = outcomes.get(str(row["id"]).lower())
        if outcome is None:
            skipped["notChecked"] += 1
            continue
        if outcome not in ("yes", "no"):
            skipped[outcome] += 1
            continue
        sub = str(row.get("subscriptionId", "")).lower()
        kind = str(row.get("type", "")).lower()
        entry = per_sub.setdefault(sub, {"affected": 0, "applicable": 0})
        counts = per_type.setdefault(kind, {"checked": 0, "withLogs": 0})
        entry["applicable"] += 1
        counts["checked"] += 1
        if outcome == "yes":
            counts["withLogs"] += 1
            continue
        entry["affected"] += 1
        if len(findings) < 2000:
            findings.append(
                make_finding(
                    run_id, rule_id=RULE_ID, source="diagnostics", pillar="Operational Excellence", severity="medium",
                    title=TITLE.format(label=TYPES.get(kind, "Resource")), recommendation=RECOMMENDATION,
                    resource_id=row["id"], resource_name=row.get("name", ""), resource_type=kind, subscription_id=sub,
                )
            )
    stats = [
        {"ruleId": RULE_ID, "source": "diagnostics", "pillar": "Operational Excellence", "severity": "medium",
         "subscriptionId": sub, "affected": value["affected"], "applicable": value["applicable"]}
        for sub, value in per_sub.items()
    ]
    checked = sum(v["checked"] for v in per_type.values())
    covered = sum(v["withLogs"] for v in per_type.values())
    dataset = {
        "checked": checked,
        "withLogs": covered,
        "percent": round(100 * covered / checked, 1) if checked else None,
        "byType": sorted(
            ({"type": kind, "label": TYPES.get(kind, kind), **value} for kind, value in per_type.items()),
            key=lambda item: item["checked"] - item["withLogs"], reverse=True),
        "skipped": skipped,
    }
    return findings, stats, dataset


def collect(credential, run_id, subscription_ids):
    rows, errors = [], []
    try:
        for chunk in graph.chunks(subscription_ids):
            rows.extend(graph.query(credential, chunk, QUERY, max_rows=MAX_RESOURCES))
    except Exception as exc:
        errors.append({"ruleId": "diagnostics-list", "error": str(exc).splitlines()[0][:200]})
    rows = rows[:MAX_RESOURCES]
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
        errors.append({"ruleId": "diagnostics-budget",
                       "error": f"{dataset['skipped']['notChecked']} resources were not checked within the time budget"})
    return findings, stats, dataset, errors
