from waf_pulse import fit, metrics, prices

SUB = "11111111-1111-1111-1111-111111111111"


def size(name, vcpus, memory, arch="x64", gpus=0, premium=True, restricted=False):
    return {"name": name, "vcpus": vcpus, "memoryGB": memory, "iops": 1000, "arch": arch, "gpus": gpus, "premium": premium, "restricted": restricted}


CATALOG = {s["name"].lower(): s for s in [
    size("Standard_D8s_v5", 8, 32), size("Standard_D4s_v5", 4, 16), size("Standard_D2s_v5", 2, 8), size("Standard_D1s_v5", 1, 4), size("Standard_E2s_v5", 2, 16),
    size("Standard_D2ps_v5", 2, 8, arch="Arm64"), size("Standard_NC4", 4, 28, gpus=1), size("Standard_D2s_nopremium", 2, 8, premium=False), size("Standard_D2_restricted", 2, 8, restricted=True),
    size("Standard_B2s", 2, 4)]}
PRICES = {"Standard_D8s_v5": 280.0, "Standard_D4s_v5": 140.0, "Standard_D2s_v5": 70.0, "Standard_D1s_v5": 35.0, "Standard_E2s_v5": 95.0, "Standard_B2s": 30.0}


def price(region, name, windows=False, currency="USD", cache=None):
    return (PRICES.get(name), currency)


def record(**extra):
    return {"kind": "vm", "id": f"/subscriptions/{SUB}/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1", "name": "vm1", "detail": "Standard_D8s_v5", "avg": 5.0, "max": 10.0,
            "memory": 15.0, "assessment": "under", **extra}


def test_needs_are_the_peak_with_headroom():
    cpu, memory = fit.needs(record(), CATALOG["standard_d8s_v5"])
    assert round(cpu, 2) == round(8 * 10 / 100 / 0.7, 2) and round(memory, 2) == round(32 * 15 / 100 / 0.8, 2)
    cpu, memory = fit.needs(record(max=None, memory=None), CATALOG["standard_d8s_v5"])
    assert round(cpu, 2) == round(8 * 10 / 100 / 0.7, 2) and memory == 32 * fit.UNKNOWN_MEMORY_SHARE  # no peak: twice the average; no memory: a share of what it has


def test_candidates_are_smaller_same_architecture_gpu_and_available_and_hold_the_need():
    names = [c["name"] for c in fit.candidates(record(), CATALOG["standard_d8s_v5"], CATALOG)]
    assert names == ["Standard_D2s_v5", "Standard_E2s_v5", "Standard_D4s_v5"]  # B2s has too little memory for 15% of 32 GB
    assert "Standard_D2ps_v5" not in names and "Standard_NC4" not in names and "Standard_D2s_nopremium" not in names and "Standard_D2_restricted" not in names and "Standard_D8s_v5" not in names
    busy = [c["name"] for c in fit.candidates(record(max=90.0, memory=70.0), CATALOG["standard_d8s_v5"], CATALOG)]
    assert busy == []  # a machine that peaks at 90% has nothing smaller to move to


def test_fit_is_the_closeness_of_the_projected_peak_to_seventy_percent():
    current = CATALOG["standard_d8s_v5"]
    assert fit.fit(record(max=35.0, memory=None), current, CATALOG["standard_d4s_v5"]) == (100, 70.0)
    assert fit.fit(record(max=20.0, memory=None), current, CATALOG["standard_d4s_v5"])[0] == 100 - round(1.5 * 30)  # 40% projected
    score, projected = fit.fit(record(max=20.0, memory=60.0), current, CATALOG["standard_d2s_v5"])
    assert projected == 240.0 and score == 0  # memory would not fit: 60% of 32 GB on 8 GB
    assert fit.fit(record(max=None, avg=10.0, memory=None), current, CATALOG["standard_d4s_v5"])[1] == 40.0


def test_alternatives_are_ranked_by_saving_and_need_a_fit_and_a_lower_price():
    found = fit.alternatives(record(), CATALOG, False, "eastus", {}, price=price)
    assert found["currentMonthly"] == 280.0 and found["currency"] == "USD"
    options = found["options"]
    assert [o["size"] for o in options] == ["Standard_D2s_v5", "Standard_E2s_v5", "Standard_D4s_v5"] and options[0]["saving"] == 210.0 and [o["fit"] for o in options] == [85, 55, 40]
    assert all(o["fit"] >= fit.MIN_FIT and o["monthly"] < 280.0 for o in options) and len(options) <= fit.MAX_ALTERNATIVES
    assert fit.alternatives(record(detail="Unknown_Size"), CATALOG, False, "eastus", {}, price=price) is None
    assert fit.alternatives(record(), CATALOG, False, "eastus", {}, price=lambda *a, **k: (None, "USD")) is None  # no price for the current size
    assert fit.alternatives(record(max=95.0, memory=80.0), CATALOG, False, "eastus", {}, price=price) is None


def test_the_cache_is_shared_between_machines():
    caches = []

    def spy(region, name, windows=False, currency="USD", cache=None):
        caches.append(cache)
        return price(region, name, windows, currency)

    shared = {}
    fit.alternatives(record(), CATALOG, False, "eastus", shared, price=spy)
    fit.alternatives(record(), CATALOG, False, "eastus", shared, price=spy)
    assert caches and all(c is shared for c in caches)


# --- attaching them to the records ---------------------------------------------------------------------------------

def test_alternatives_are_attached_to_idle_and_underutilized_machines_only():
    rows = [{"id": record()["id"], "subscriptionId": SUB, "location": "eastus", "osType": "Linux"}]
    records = [record(), record(id=record()["id"].replace("vm1", "vm2"), assessment="right"), {"kind": "plan", "id": "x", "assessment": "under"}]
    looked = metrics.attach_alternatives(records, rows + [{**rows[0], "id": records[1]["id"]}], {(SUB, "eastus"): CATALOG}, price=price)
    assert looked == 1 and records[0]["alternatives"]["options"][0]["size"] == "Standard_D2s_v5" and "alternatives" not in records[1] and "alternatives" not in records[2]
    assert metrics.attach_alternatives([record()], rows, {}, price=price) == 0  # no size catalog for the region


def test_windows_machines_are_priced_as_windows():
    seen = []

    def spy(region, name, windows=False, currency="USD", cache=None):
        seen.append(windows)
        return price(region, name, windows, currency)

    rows = [{"id": record()["id"], "subscriptionId": SUB, "location": "eastus", "osType": "Windows"}]
    metrics.attach_alternatives([record()], rows, {(SUB, "eastus"): CATALOG}, price=spy)
    assert seen and all(seen)


def test_the_price_time_budget_stops_the_lookups():
    rows = [{"id": record()["id"], "subscriptionId": SUB, "location": "eastus", "osType": "Linux"}]
    ticks = iter([0, 1000])
    assert metrics.attach_alternatives([record()], rows, {(SUB, "eastus"): CATALOG}, price=price, clock=lambda: next(ticks)) == 0


# --- the retail prices API ----------------------------------------------------------------------------------------

ITEMS = [{"productName": "Virtual Machines DASv5 Series", "skuName": "D4as v5", "meterName": "D4as v5", "retailPrice": 0.194, "type": "Consumption"},
         {"productName": "Virtual Machines DASv5 Series Windows", "skuName": "D4as v5", "meterName": "D4as v5", "retailPrice": 0.378, "type": "Consumption"},
         {"productName": "Virtual Machines DASv5 Series", "skuName": "D4as v5 Spot", "meterName": "D4as v5 Spot", "retailPrice": 0.02, "type": "Consumption"},
         {"productName": "Virtual Machines DASv5 Series", "skuName": "D4as v5 Low Priority", "meterName": "x", "retailPrice": 0.03, "type": "Consumption"},
         {"productName": "Virtual Machines DASv5 Series", "skuName": "D4as v5", "meterName": "D4as v5", "retailPrice": 0.1, "type": "Reservation"}]


def test_pick_chooses_pay_as_you_go_prices_for_the_operating_system():
    assert prices.pick(ITEMS, False) == 0.194 and prices.pick(ITEMS, True) == 0.378 and prices.pick([], False) is None and prices.pick([{"productName": "x", "retailPrice": 0, "type": "Consumption"}], False) is None


def test_vm_monthly_asks_the_api_once_per_size_and_follows_pages(monkeypatch):
    calls = []

    def fake(url, params=None):
        calls.append((url, params))
        if len(calls) == 1:
            return {"Items": ITEMS[:1], "NextPageLink": "https://prices.azure.com/api/retail/prices?$skip=100"}
        return {"Items": ITEMS[1:2], "NextPageLink": None}

    monkeypatch.setattr(prices, "_get", fake)
    cache = {}
    assert prices.vm_monthly("EastUS", "Standard_D4as_v5", False, "USD", cache) == (round(0.194 * 730, 2), "USD")
    assert prices.vm_monthly("eastus", "standard_d4as_v5", False, "USD", cache) == (round(0.194 * 730, 2), "USD") and len(calls) == 2
    assert "armRegionName eq 'eastus'" in calls[0][1]["$filter"] and "armSkuName eq 'Standard_D4as_v5'" in calls[0][1]["$filter"] and calls[1][0].endswith("$skip=100")
    assert prices.vm_monthly("eastus", "Standard_D4as_v5", True, "USD", cache)[0] == round(0.378 * 730, 2)  # Windows is another cache entry


def test_a_failing_api_gives_no_price(monkeypatch):
    monkeypatch.setattr(prices, "_get", lambda url, params=None: None)
    assert prices.vm_monthly("eastus", "Standard_X", False, "USD", {}) == (None, "USD")


def test_get_retries_throttling_and_gives_up(monkeypatch):
    answers = iter([type("R", (), {"status_code": 429})(), type("R", (), {"status_code": 200, "json": lambda self: {"Items": []}})()])
    monkeypatch.setattr(prices.requests, "get", lambda *a, **k: next(answers))
    monkeypatch.setattr(prices, "_sleep", lambda s: None)
    assert prices._get(prices.URL, {}) == {"Items": []}
    monkeypatch.setattr(prices.requests, "get", lambda *a, **k: type("R", (), {"status_code": 500})())
    assert prices._get(prices.URL, {}) is None
    monkeypatch.setattr(prices.requests, "get", lambda *a, **k: type("R", (), {"status_code": 404})())
    assert prices._get(prices.URL, {}) is None
