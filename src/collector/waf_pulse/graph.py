"""Azure Resource Graph access and subscription discovery.

Resource Graph throttles each principal to roughly 15 requests every 5 seconds. Every call goes through a
process wide limiter that stays under that rate, and a throttled call (HTTP 429) waits for the time Azure asks
for and is retried, so a burst of parallel activities slows down instead of losing data.
"""
import os
import random
import threading
import time
from collections import deque

from azure.core.exceptions import HttpResponseError
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions
from azure.mgmt.subscription import SubscriptionClient

PAGE_SIZE = 1000
MAX_ROWS = 5000
# Resource Graph accepts up to 1000 subscriptions per request. Smaller chunks keep each call fast.
SUBSCRIPTION_CHUNK = 300

REQUESTS_PER_WINDOW = 12
WINDOW_SECONDS = 5.0
MAX_ATTEMPTS = 8
DEFAULT_WAIT_SECONDS = 5.0
MAX_WAIT_SECONDS = 60.0

_sleep = time.sleep
_now = time.monotonic


class _Limiter:
    """Sliding window: at most `limit` calls in any `window` seconds, shared by every thread of the process."""

    def __init__(self, limit, window):
        self.limit, self.window = limit, window
        self.calls = deque()
        self.lock = threading.Lock()

    def acquire(self):
        while True:
            with self.lock:
                now = _now()
                while self.calls and now - self.calls[0] >= self.window:
                    self.calls.popleft()
                if len(self.calls) < self.limit:
                    self.calls.append(now)
                    return
                wait = self.window - (now - self.calls[0])
            _sleep(max(wait, 0.05))


_limiter = _Limiter(REQUESTS_PER_WINDOW, WINDOW_SECONDS)
_clients = {}


def is_throttle(exc):
    text = str(exc).lower()
    return getattr(exc, "status_code", None) == 429 or "throttled" in text or "ratelimiting" in text


def retry_after_seconds(exc):
    """Seconds Azure asks us to wait: the quota reset header (hh:mm:ss) or Retry-After."""
    headers = getattr(getattr(exc, "response", None), "headers", None) or {}
    for name in ("x-ms-user-quota-resets-after", "Retry-After"):
        value = headers.get(name)
        if not value:
            continue
        try:
            if ":" in str(value):
                hours, minutes, seconds = (float(part) for part in str(value).split(":")[-3:])
                return min(hours * 3600 + minutes * 60 + seconds, MAX_WAIT_SECONDS)
            return min(float(value), MAX_WAIT_SECONDS)
        except ValueError:
            continue
    return DEFAULT_WAIT_SECONDS


def _client(credential):
    key = id(credential)
    if key not in _clients:
        # 429 is handled here, with the limiter, instead of by the SDK's own short retries.
        _clients[key] = (
            credential,
            ResourceGraphClient(credential, retry_total=3, retry_on_status_codes=[408, 500, 502, 503, 504]),
        )
    return _clients[key][1]


def _execute(client, request):
    for attempt in range(MAX_ATTEMPTS):
        _limiter.acquire()
        try:
            return client.resources(request)
        except HttpResponseError as exc:
            if not is_throttle(exc) or attempt == MAX_ATTEMPTS - 1:
                raise
            _sleep(retry_after_seconds(exc) + random.uniform(0, 1))


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
    client = _client(credential)
    rows, skip_token = [], None
    while len(rows) < max_rows:
        options = QueryRequestOptions(result_format="objectArray", top=PAGE_SIZE, skip_token=skip_token)
        response = _execute(client, QueryRequest(subscriptions=scope, query=kql, options=options))
        rows.extend(response.data or [])
        skip_token = response.skip_token
        if not skip_token:
            break
    return rows[:max_rows]
