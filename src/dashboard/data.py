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
SOURCES = ("builtin", "checklist", "advisor", "defender", "governance", "metrics", "finops")
SOURCE_LABELS = {
    "builtin": "Built-in rules",
    "checklist": "Review checklists",
    "advisor": "Azure Advisor",
    "defender": "Defender for Cloud",
    "governance": "Governance",
    "metrics": "Azure Monitor metrics",
    "finops": "Cost Management",
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
