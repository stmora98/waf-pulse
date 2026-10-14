"""Azure Resource Graph and subscription discovery."""
import os

from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
from azure.mgmt.subscription import SubscriptionClient

PAGE_SIZE = 1000
MAX_ROWS = 5000


def parse_subscription_filter(value):
    return {item.strip().lower() for item in (value or "").replace(";", ",").split(",") if item.strip()}


def discover_subscriptions(credential):
    """Every enabled subscription the service principal can read, optionally filtered."""
    wanted = parse_subscription_filter(os.environ.get("SUBSCRIPTION_FILTER", ""))
    client = SubscriptionClient(credential)
    subscriptions = []
    for sub in client.subscriptions.list():
        if str(sub.state).lower().endswith("enabled") and (not wanted or sub.subscription_id.lower() in wanted):
            subscriptions.append({"id": sub.subscription_id, "name": sub.display_name})
    return subscriptions


def query(credential, subscription_id, kql, max_rows=MAX_ROWS):
    """Runs a Resource Graph query for one subscription and follows pagination."""
    client = ResourceGraphClient(credential)
    rows, skip_token = [], None
    while len(rows) < max_rows:
        options = QueryRequestOptions(result_format="objectArray", top=PAGE_SIZE, skip_token=skip_token)
        response = client.resources(QueryRequest(subscriptions=[subscription_id], query=kql, options=options))
        rows.extend(response.data or [])
        skip_token = response.skip_token
        if not skip_token:
            break
    return rows[:max_rows]
