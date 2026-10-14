"""Persistence: Cosmos DB for documents, Blob Storage for raw snapshots. Both use the managed identity."""
import json
import os
from concurrent.futures import ThreadPoolExecutor

from azure.cosmos import CosmosClient
from azure.storage.blob import BlobServiceClient

from .credentials import storage_credential

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
