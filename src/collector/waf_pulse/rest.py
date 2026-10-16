"""A small HTTP GET with the retries every Azure endpoint needs: throttling (429), server errors and dropped connections."""
import time

import requests

MAX_ATTEMPTS = 5
TIMEOUT = 30

_sleep = time.sleep


def get(url, token, params=None, headers=None):
    """Returns the final response. Only a persistent network failure raises."""
    for attempt in range(MAX_ATTEMPTS):
        last = attempt == MAX_ATTEMPTS - 1
        try:
            response = requests.get(url, params=params, headers={"Authorization": f"Bearer {token}", **(headers or {})},
                                    timeout=TIMEOUT)
        except (requests.ConnectionError, requests.Timeout):
            if last:
                raise
            _sleep(min(2 ** attempt, 20))
            continue
        if response.status_code == 429 and not last:
            _sleep(min(float(response.headers.get("Retry-After", 5)), 60))
            continue
        if response.status_code >= 500 and not last:
            _sleep(min(2 ** attempt, 20))
            continue
        return response
    return response
