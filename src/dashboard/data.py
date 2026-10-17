"""Read access to Cosmos DB and the refresh queue. Both use the managed identity."""
import json
import os

from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.storage.queue import QueueClient, TextBase64EncodePolicy

PILLARS = (
    "Reliability",
    "Security",
    "Cost Optimization",
    "Operational Excellence",
    "Performance Efficiency",
)
SEVERITIES = ("critical", "high", "medium", "low")
SOURCES = ("builtin", "checklist", "advisor", "defender", "governance", "metrics", "finops", "diagnostics", "keyvault", "entra")
SOURCE_LABELS = {
    "builtin": "Built-in rules",
    "checklist": "Review checklists",
    "advisor": "Azure Advisor",
    "defender": "Defender for Cloud",
    "governance": "Governance",
    "metrics": "Azure Monitor metrics",
    "finops": "Cost Management",
    "diagnostics": "Diagnostic settings",
    "keyvault": "Key Vault expirations",
    "entra": "Microsoft Entra",
}
TENANT_PARTITION = "tenant"
QUEUE_NAME = "refresh-requests"

_database = None


def public(document):
    """Removes Cosmos DB system properties (_rid, _self, _etag, ...) before data leaves the service."""
    return {key: value for key, value in document.items() if not key.startswith("_")}


def _credential():
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")
    return ManagedIdentityCredential(client_id=client_id) if client_id else DefaultAzureCredential()


def _db():
    global _database
    if _database is None:
        client = CosmosClient(os.environ["COSMOS_ENDPOINT"], credential=_credential())
        _database = client.get_database_client(os.environ["COSMOS_DATABASE"])
    return _database


def latest_run(completed_only=False):
    where = "WHERE c.status = 'completed'" if completed_only else ""
    items = list(
        _db()
        .get_container_client("runs")
        .query_items(
            f"SELECT TOP 1 * FROM c {where} ORDER BY c.startedUtc DESC",
            partition_key=TENANT_PARTITION,
        )
    )
    return public(items[0]) if items else None


def summary(run_id):
    return public(_db().get_container_client("summaries").read_item(run_id, partition_key=run_id))


def findings(run_id, pillar=None, severity=None, limit=200, source=None):
    """Most severe findings first, without loading more than `limit` documents."""
    container = _db().get_container_client("findings")
    severities = [severity] if severity in SEVERITIES else list(SEVERITIES)
    results = []
    for level in severities:
        remaining = limit - len(results)
        if remaining <= 0:
            break
        query = "SELECT * FROM c WHERE c.runId = @run AND c.severity = @sev"
        parameters = [{"name": "@run", "value": run_id}, {"name": "@sev", "value": level}]
        if pillar in PILLARS:
            query += " AND c.pillar = @pillar"
            parameters.append({"name": "@pillar", "value": pillar})
        if source in SOURCES:
            query += " AND c.source = @source"
            parameters.append({"name": "@source", "value": source})
        query += " OFFSET 0 LIMIT @limit"
        parameters.append({"name": "@limit", "value": remaining})
        results.extend(public(item) for item in container.query_items(query, parameters=parameters, partition_key=run_id))
    return results


FINDING_FIELDS = ("c.id, c.key, c.ruleId, c.source, c.pillar, c.severity, c.title, c.recommendation, c.resourceId, "
                  "c.resourceName, c.resourceType, c.subscriptionId, c.link")
MAX_FINDINGS = 5000


def all_findings(run_id, pillar=None, rule_id=None, limit=MAX_FINDINGS):
    """Every finding of a run (up to `limit`), optionally for one pillar or one rule, without system fields."""
    query = f"SELECT {FINDING_FIELDS} FROM c WHERE c.runId = @run"
    parameters = [{"name": "@run", "value": run_id}]
    if pillar in PILLARS:
        query += " AND c.pillar = @pillar"
        parameters.append({"name": "@pillar", "value": pillar})
    if rule_id:
        query += " AND c.ruleId = @rule"
        parameters.append({"name": "@rule", "value": rule_id})
    query += " OFFSET 0 LIMIT @limit"
    parameters.append({"name": "@limit", "value": limit})
    items = _db().get_container_client("findings").query_items(query, parameters=parameters, partition_key=run_id)
    return [dict(item) for item in items]


def rule_history(rule_id, run_ids):
    """How many findings a rule had in each of the given runs: {run id: count}. One cheap query per run, each
    inside a single partition."""
    container = _db().get_container_client("findings")
    counts = {}
    for run_id in run_ids:
        result = list(container.query_items(
            "SELECT VALUE COUNT(1) FROM c WHERE c.runId = @run AND c.ruleId = @rule",
            parameters=[{"name": "@run", "value": run_id}, {"name": "@rule", "value": rule_id}],
            partition_key=run_id,
        ))
        if result and result[0]:
            counts[run_id] = result[0]
    return counts

def history(limit=30):
    """Most recent runs first."""
    items = _db().get_container_client("runs").query_items(
        "SELECT * FROM c ORDER BY c.startedUtc DESC OFFSET 0 LIMIT @limit",
        parameters=[{"name": "@limit", "value": limit}],
        partition_key=TENANT_PARTITION,
    )
    return [public(item) for item in items]


def run(run_id):
    return public(_db().get_container_client("runs").read_item(run_id, partition_key=TENANT_PARTITION))


def run_findings(run_id, limit=5000):
    """The fields needed to compare two runs, without the full documents."""
    items = _db().get_container_client("findings").query_items(
        "SELECT c.key, c.ruleId, c.pillar, c.severity, c.title, c.resourceId, c.resourceName "
        "FROM c WHERE c.runId = @run OFFSET 0 LIMIT @limit",
        parameters=[{"name": "@run", "value": run_id}, {"name": "@limit", "value": limit}],
        partition_key=run_id,
    )
    return list(items)


def request_refresh():
    """Queues a refresh request. The collector ignores it if an assessment is already running."""
    queue_url = os.environ["STORAGE_QUEUE_URL"]
    queue = QueueClient(
        account_url=queue_url,
        queue_name=QUEUE_NAME,
        credential=_credential(),
        message_encode_policy=TextBase64EncodePolicy(),
    )
    queue.send_message(json.dumps({"action": "refresh"}))

SETTINGS_PARTITION = "settings"


def get_setting(name):
    """A setting kept by the dashboard (not by a run), or None."""
    from azure.cosmos.exceptions import CosmosResourceNotFoundError

    try:
        item = _db().get_container_client("summaries").read_item(f"setting-{name}", partition_key=SETTINGS_PARTITION)
    except CosmosResourceNotFoundError:
        return None
    return public(item).get("value")


def save_setting(name, value):
    _db().get_container_client("summaries").upsert_item(
        {"id": f"setting-{name}", "runId": SETTINGS_PARTITION, "kind": "setting", "value": value})
