"""Azure Resource Graph and subscription discovery."""
import os

from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
from azure.mgmt.subscription import SubscriptionClient

PAGE_SIZE = 1000
MAX_ROWS = 5000
# Resource Graph accepts up to 1000 subscriptions per request. Smaller chunks keep each call fast.
SUBSCRIPTION_CHUNK = 300


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


def chunks(items, size=SUBSCRIPTION_CHUNK):
    items = list(items)
    return [items[i:i + size] for i in range(0, len(items), size)] or [[]]


def query(credential, subscriptions, kql, max_rows=MAX_ROWS):
    """Runs a Resource Graph query over one subscription id or a list of them and follows pagination."""
    scope = [subscriptions] if isinstance(subscriptions, str) else list(subscriptions)
    client = ResourceGraphClient(credential)
    rows, skip_token = [], None
    while len(rows) < max_rows:
        options = QueryRequestOptions(result_format="objectArray", top=PAGE_SIZE, skip_token=skip_token)
        response = client.resources(QueryRequest(subscriptions=scope, query=kql, options=options))
        rows.extend(response.data or [])
        skip_token = response.skip_token
        if not skip_token:
            break
    return rows[:max_rows]
