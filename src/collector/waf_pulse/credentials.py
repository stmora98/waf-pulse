"""Credentials. The collector uses two identities with different purposes.

* Service principal supplied by the customer: reads the Azure estate (tenant wide).
* User-assigned managed identity of the Function App: reads and writes Cosmos DB, Blob and Queue storage.
"""
import os
from functools import lru_cache

from azure.identity import ClientSecretCredential, DefaultAzureCredential, ManagedIdentityCredential


@lru_cache(maxsize=1)
def collector_credential():
    """One credential per process, so its token cache and the Resource Graph client are reused."""
    return ClientSecretCredential(
        tenant_id=os.environ["COLLECTOR_TENANT_ID"],
        client_id=os.environ["COLLECTOR_CLIENT_ID"],
        client_secret=os.environ["COLLECTOR_CLIENT_SECRET"],
    )


def storage_credential():
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")
    if client_id:
        return ManagedIdentityCredential(client_id=client_id)
    return DefaultAzureCredential()
