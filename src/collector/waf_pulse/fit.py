"""Fit score: for a virtual machine that is idle or underutilized, the smaller sizes it could move to, ranked by price.

A size fits when its vCPUs and memory hold the observed peak with headroom: the peak CPU and the memory in use are projected onto the
candidate, and the fit is how close the projected peak is to a comfortable level (70%). Candidates have the same CPU architecture and the
same number of GPUs, are available to the subscription and cost less than the current size. Prices are list prices (see prices.py)."""
from . import prices

TARGET = 70.0           # projected peak utilization that counts as a perfect fit
HEADROOM_CPU = 0.7      # share of a size's CPU the peak may use
HEADROOM_MEMORY = 0.8
MIN_FIT = 40
MAX_CANDIDATES = 6
MAX_ALTERNATIVES = 3
UNKNOWN_MEMORY_SHARE = 0.6  # without a memory reading, a size needs at least this share of the current memory
MAX_MACHINES = 200


def needs(record, size):
    """(vCPUs, memory GB) the machine needs at its peak with headroom, from its record and its current size."""
    vcpus, memory = size["vcpus"], size["memoryGB"]
    peak = record.get("max") if record.get("max") is not None else min((record.get("avg") or 0) * 2, 100)
    need_cpu = vcpus * max(peak, 1) / 100 / HEADROOM_CPU
    need_memory = memory * record["memory"] / 100 / HEADROOM_MEMORY if record.get("memory") is not None else memory * UNKNOWN_MEMORY_SHARE
    return need_cpu, need_memory


def candidates(record, current, catalog):
    """The sizes of the catalog that hold the need and are smaller than the current one, the smallest first."""
    need_cpu, need_memory = needs(record, current)
    found = []
    for name, size in catalog.items():
        if name == str(record.get("detail", "")).lower() or size.get("restricted") or not size.get("vcpus") or not size.get("memoryGB"):
            continue
        if size.get("arch") != current.get("arch") or (size.get("gpus") or 0) != (current.get("gpus") or 0):
            continue
        if current.get("premium") and not size.get("premium"):
            continue
        if size["vcpus"] < need_cpu or size["memoryGB"] < need_memory:
            continue
        if size["vcpus"] > current["vcpus"] or size["memoryGB"] > current["memoryGB"] or (size["vcpus"], size["memoryGB"]) == (current["vcpus"], current["memoryGB"]):
            continue
        found.append(size)
    found.sort(key=lambda s: (s["vcpus"], s["memoryGB"], s["name"]))
    return found


def fit(record, current, size):
    """0-100: how close the peak projected onto `size` is to TARGET percent (the CPU and the memory, whichever is higher)."""
    peak = record.get("max") if record.get("max") is not None else min((record.get("avg") or 0) * 2, 100)
    projected = peak * current["vcpus"] / size["vcpus"]
    if record.get("memory") is not None:
        projected = max(projected, record["memory"] * current["memoryGB"] / size["memoryGB"])
    return max(0, round(100 - 1.5 * abs(TARGET - projected))), round(projected, 1)


def alternatives(record, catalog, windows, region, cache, currency="USD", price=prices.vm_monthly):
    """The best smaller sizes for one record: {currentMonthly, currency, options: [{size, vcpus, memoryGB, monthly, saving, fit, projected}]},
    or None when the record has no size data or nothing fits."""
    current = catalog.get(str(record.get("detail", "")).lower())
    if not current or not current.get("vcpus") or not current.get("memoryGB"):
        return None
    now_price, currency = price(region, current.get("name") or record["detail"], windows, currency, cache)
    if not now_price:
        return None
    options = []
    for size in candidates(record, current, catalog)[:MAX_CANDIDATES]:
        monthly, _ = price(region, size["name"], windows, currency, cache)
        score, projected = fit(record, current, size)
        if monthly and monthly < now_price and score >= MIN_FIT:
            options.append({"size": size["name"], "vcpus": size["vcpus"], "memoryGB": size["memoryGB"], "monthly": monthly, "saving": round(now_price - monthly, 2),
                            "fit": score, "projected": projected})
    options.sort(key=lambda o: (-o["saving"], -o["fit"]))
    return {"currentMonthly": now_price, "currency": currency, "options": options[:MAX_ALTERNATIVES]} if options else None
