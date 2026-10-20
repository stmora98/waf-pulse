"""What each virtual machine size offers (vCPUs, memory, disk IOPS) and where it can be deployed, from the Compute
SKUs API (Reader is enough). One call per subscription and region, about 2.5 MB each, so it is only asked for the
regions that have virtual machines."""
import requests

API_VERSION = "2021-07-01"
REQUEST_TIMEOUT = 120
MAX_PAGES = 5


def parse(body):
    """{size name (lower): {name, vcpus, memoryGB, iops, arch, gpus, premium, restricted}} from one page of the SKUs API."""
    sizes = {}
    for item in (body or {}).get("value", []):
        if str(item.get("resourceType", "")).lower() != "virtualmachines":
            continue
        caps = {c.get("name"): c.get("value") for c in item.get("capabilities", [])}
        sizes[str(item.get("name", "")).lower()] = {
            "name": item.get("name", ""), "vcpus": _number(caps.get("vCPUs")), "memoryGB": _number(caps.get("MemoryGB")),
            "iops": _number(caps.get("UncachedDiskIOPS")), "arch": caps.get("CpuArchitectureType") or "x64",
            "gpus": _number(caps.get("GPUs")) or 0, "premium": str(caps.get("PremiumIO", "")).lower() == "true",
            "restricted": any(r.get("reasonCode") for r in item.get("restrictions", [])),
        }
    return sizes


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def fetch(credential, subscription, region):
    """The VM sizes of one region. Empty (not an error) when the call is refused, so right-sizing still works."""
    token = credential.get_token("https://management.azure.com/.default").token
    url = f"https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Compute/skus"
    params = {"api-version": API_VERSION, "$filter": f"location eq '{region}'"}
    sizes = {}
    for _ in range(MAX_PAGES):
        response = requests.get(url, params=params, headers={"Authorization": f"Bearer {token}"}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        body = response.json()
        sizes.update(parse(body))
        url, params = body.get("nextLink"), None
        if not url:
            break
    return sizes
