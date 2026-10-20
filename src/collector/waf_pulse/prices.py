"""List prices from the Azure Retail Prices API (https://prices.azure.com, no authentication): what a virtual machine size costs per month
in a region, for Linux or Windows, pay as you go. They are list prices: what you pay depends on your agreement, reservations and
savings plans, so they are used to compare sizes with each other, not to tell the bill."""
import time

import requests

URL = "https://prices.azure.com/api/retail/prices"
HOURS_PER_MONTH = 730
REQUEST_TIMEOUT = 30
MAX_ATTEMPTS = 4
MAX_PAGES = 3

_sleep = time.sleep


def _get(url, params=None):
    """The JSON of one call, retrying throttling, server errors and dropped connections; None when it keeps failing."""
    for attempt in range(MAX_ATTEMPTS):
        try:
            response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        except (requests.ConnectionError, requests.Timeout):
            _sleep(min(2 ** attempt, 8))
            continue
        if response.status_code == 429 or response.status_code >= 500:
            _sleep(min(2 ** attempt, 8))
            continue
        return response.json() if response.status_code == 200 else None
    return None


def pick(items, windows):
    """The pay as you go hourly price of a size from the items of the API: Windows or Linux, never spot or low priority."""
    prices = []
    for item in items:
        text = f"{item.get('productName', '')} {item.get('skuName', '')} {item.get('meterName', '')}".lower()
        if "spot" in text or "low priority" in text or item.get("type") != "Consumption":
            continue
        if ("windows" in str(item.get("productName", "")).lower()) != windows:
            continue
        if item.get("retailPrice"):
            prices.append(float(item["retailPrice"]))
    return min(prices) if prices else None


def vm_monthly(region, size, windows=False, currency="USD", cache=None):
    """(monthly price, currency) of a virtual machine size, or (None, currency). `cache` is a dict shared by the caller."""
    key = (str(region).lower(), str(size).lower(), bool(windows), currency)
    if cache is not None and key in cache:
        return cache[key]
    params = {"currencyCode": currency, "$filter": f"serviceName eq 'Virtual Machines' and armRegionName eq '{key[0]}' and armSkuName eq '{size}' and priceType eq 'Consumption'"}
    items, body, pages = [], _get(URL, params), 0
    while body is not None:
        items.extend(body.get("Items", []))
        pages += 1
        if not body.get("NextPageLink") or pages >= MAX_PAGES:
            break
        body = _get(body["NextPageLink"])
    hourly = pick(items, windows)
    result = (round(hourly * HOURS_PER_MONTH, 2) if hourly else None, currency)
    if cache is not None:
        cache[key] = result
    return result
