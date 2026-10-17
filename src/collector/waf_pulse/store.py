"""Persistence: Cosmos DB for documents, Blob Storage for raw snapshots. Both use the managed identity."""
import json
import os
from concurrent.futures import ThreadPoolExecutor

from azure.cosmos import CosmosClient
from azure.storage.blob import BlobServiceClient

from .credentials import storage_credential
from .findings import retention_seconds

TENANT_PARTITION = "tenant"
_database = None


def database():
    global _database
    if _database is None:
        client = CosmosClient(os.environ["COSMOS_ENDPOINT"], credential=storage_credential())
        _database = client.get_database_client(os.environ["COSMOS_DATABASE"])
    return _database


def container(name):
    return database().get_container_client(name)


def start_run(run_id, started_utc, trigger):
    container("runs").upsert_item(
        {
            "id": run_id,
            "subscriptionId": TENANT_PARTITION,
            "status": "running",
            "trigger": trigger,
            "startedUtc": started_utc,
        }
    )


def save_run(doc):
    container("runs").upsert_item(doc)


def save_findings(findings, workers=8):
    if not findings:
        return
    target = container("findings")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(target.upsert_item, findings))


def save_summary(summary):
    container("summaries").upsert_item(summary)


def save_stats(run_id, key, document):
    """Statistics of one activity. They live in the summaries container (partition = run) next to the summary."""
    _save_run_document(run_id, "stats", key, document)


def save_dataset(run_id, name, data, key="0"):
    _save_run_document(run_id, "dataset", f"{name}:{key}", {"name": name, "data": data})


RESOURCE_CHUNK = 800


def save_resources(run_id, rows, truncated=False):
    """The resource list of a run in documents of RESOURCE_CHUNK rows, apart from the summary so it stays small."""
    for index in range(0, max(len(rows), 1), RESOURCE_CHUNK):
        _save_run_document(run_id, "resources", f"inventory:{index // RESOURCE_CHUNK}",
                           {"rows": rows[index:index + RESOURCE_CHUNK], "truncated": truncated})


def _save_run_document(run_id, kind, key, payload):
    document = {"id": f"{run_id}:{kind}:{key}", "runId": run_id, "kind": kind, **payload}
    ttl = retention_seconds()
    if ttl:
        document["ttl"] = ttl
    container("summaries").upsert_item(document)


def load_run_documents(run_id, kind):
    items = container("summaries").query_items(
        "SELECT * FROM c WHERE c.runId = @run AND c.kind = @kind",
        parameters=[{"name": "@run", "value": run_id}, {"name": "@kind", "value": kind}],
        partition_key=run_id,
    )
    return list(items)


def save_scores(score_docs):
    target = container("scores")
    for doc in score_docs:
        target.upsert_item(doc)


def save_snapshot(run_id, name, payload):
    url = os.environ.get("STORAGE_ACCOUNT_URL")
    if not url:
        return
    service = BlobServiceClient(url, credential=storage_credential())
    blob = service.get_blob_client("snapshots", f"{run_id}/{name}.json")
    blob.upload_blob(json.dumps(payload, indent=2), overwrite=True)
