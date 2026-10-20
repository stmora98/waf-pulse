from datetime import datetime, timezone

import pytest

import app as dashboard_app
import data
from waf_pulse import graph, metrics, skus

SUB = "11111111-1111-1111-1111-111111111111"
NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


def points(field, *values):
    return [{"timeStamp": f"2026-10-{i + 1:02d}T00:00:00Z", field: value} for i, value in enumerate(values)]


def rid(kind, name, sub=SUB):
    return f"/subscriptions/{sub}/resourceGroups/rg/providers/{kind}/{name}"


def row(kind, name, sub=SUB, region="eastus"):
    return {"id": rid(kind, name, sub), "name": name, "subscriptionId": sub, "location": region, "detail": "size"}


# --- aggregation and classification ---------------------------------------------------------------------

def test_summarize_ignores_missing_points():
    data_points = points("average", 10, None, 20)
    assert metrics.summarize(data_points, "average") == 15
    assert metrics.summarize(points("maximum", 3, 9, None), "maximum") == 9
    assert metrics.summarize(points("total", 0, 5, 7), "total") == 12
    assert metrics.summarize([{"timeStamp": "t"}], "average") is None
    assert metrics.summarize([], "total") is None


def test_parse_batch_keys_resources_by_lowercase_id():
    body = {"values": [{"resourceid": "/Subscriptions/S/X", "value": [
        {"name": {"value": "Percentage CPU"}, "timeseries": [{"data": points("average", 1)}]},
        {"name": {"value": "Empty"}, "timeseries": []}]}]}
    parsed = metrics.parse_batch(body)
    assert list(parsed) == ["/subscriptions/s/x"]
    assert parsed["/subscriptions/s/x"]["Percentage CPU"] == points("average", 1)
    assert parsed["/subscriptions/s/x"]["Empty"] == []
    assert metrics.parse_batch(None) == {}


@pytest.mark.parametrize("average,expected", [(2, "MET-VM-001"), (4.9, "MET-VM-001"), (5, "MET-VM-002"), (14.9, "MET-VM-002"),
                                              (15, None), (79, None), (80, "MET-VM-003"), (99, "MET-VM-003")])
def test_vm_thresholds(average, expected):
    rule, value = metrics.classify("vm", {"Percentage CPU": points("average", average)})
    assert rule == expected and value == average


def test_resources_without_data_are_not_classified():
    assert metrics.classify("vm", {"Percentage CPU": []}) == (None, None)
    assert metrics.classify("storage", {"Transactions": []}) == (None, None)
    assert metrics.classify("unknown", {}) == (None, None)


def test_sql_uses_dtu_or_cpu_depending_on_the_model():
    assert metrics.classify("sql_dtu", {"dtu_consumption_percent": points("average", 4)})[0] == "MET-SQL-001"
    assert metrics.classify("sql_dtu", {"cpu_percent": points("average", 4)}) == (None, None)  # wrong metric for DTU
    assert metrics.classify("sql_vcore", {"cpu_percent": points("average", 90)})[0] == "MET-SQL-002"
    assert metrics.classify("sql_vcore", {"cpu_percent": points("average", 40)})[0] is None


def test_app_service_plan_cpu_and_memory():
    assert metrics.classify("plan", {"CpuPercentage": points("average", 10)})[0] == "MET-APP-001"
    assert metrics.classify("plan", {"CpuPercentage": points("average", 85)})[0] == "MET-APP-002"
    busy_memory = {"CpuPercentage": points("average", 30), "MemoryPercentage": points("average", 90)}
    assert metrics.classify("plan", busy_memory) == ("MET-APP-002", 90)
    assert metrics.classify("plan", {"CpuPercentage": points("average", 50)})[0] is None


def test_storage_with_no_transactions():
    assert metrics.classify("storage", {"Transactions": points("total", 0, 0, 0)}) == ("MET-STG-001", 0)
    assert metrics.classify("storage", {"Transactions": points("total", 0, 12)})[0] is None


# --- evaluation -----------------------------------------------------------------------------------------

def test_evaluate_builds_findings_stats_and_dataset():
    resources = {"vm": [row("Microsoft.Compute/virtualMachines", "idle"), row("Microsoft.Compute/virtualMachines", "busy"),
                        row("Microsoft.Compute/virtualMachines", "fine"), row("Microsoft.Compute/virtualMachines", "nodata")],
                 "sql_dtu": [row("Microsoft.Sql/servers/databases", "db1")],
                 "sql_vcore": [row("Microsoft.Sql/servers/databases", "db2")]}
    measurements = {
        rid("Microsoft.Compute/virtualMachines", "idle").lower(): {"Percentage CPU": points("average", 1, 2)},
        rid("Microsoft.Compute/virtualMachines", "busy").lower(): {"Percentage CPU": points("average", 95)},
        rid("Microsoft.Compute/virtualMachines", "fine").lower(): {"Percentage CPU": points("average", 40)},
        rid("Microsoft.Sql/servers/databases", "db1").lower(): {"dtu_consumption_percent": points("average", 5)},
        rid("Microsoft.Sql/servers/databases", "db2").lower(): {"cpu_percent": points("average", 50)},
    }
    findings, stats, dataset = metrics.evaluate("run1", resources, measurements)

    assert {f["ruleId"] for f in findings} == {"MET-VM-001", "MET-VM-003", "MET-SQL-001"}
    idle = next(f for f in findings if f["ruleId"] == "MET-VM-001")
    assert idle["source"] == "metrics" and idle["pillar"] == "Cost Optimization" and "1.5%" in idle["title"]
    by_rule = {s["ruleId"]: s for s in stats}
    assert (by_rule["MET-VM-001"]["affected"], by_rule["MET-VM-001"]["applicable"]) == (1, 3)  # "nodata" is not measured
    assert (by_rule["MET-VM-003"]["affected"], by_rule["MET-VM-003"]["applicable"]) == (1, 3)
    assert (by_rule["MET-SQL-001"]["affected"], by_rule["MET-SQL-001"]["applicable"]) == (1, 2)  # dtu + vcore merged
    assert dataset["measured"]["vm"] == 3 and dataset["listed"]["vm"] == 4
    assert [i["name"] for i in dataset["topUnderutilized"]] == ["idle", "db1"]
    assert [i["name"] for i in dataset["topSaturated"]] == ["busy"]


def test_evaluate_keeps_every_measured_resource_with_its_cpu_and_assessment():
    vm = "Microsoft.Compute/virtualMachines"
    resources = {"vm": [row(vm, "idle"), row(vm, "busy"), row(vm, "fine"), row(vm, "nodata")],
                 "plan": [row("Microsoft.Web/serverfarms", "plan1")]}
    measurements = {
        rid(vm, "idle").lower(): {"Percentage CPU": points("average", 1, 2)},
        rid(vm, "busy").lower(): {"Percentage CPU": [{"average": 90, "maximum": 99}, {"average": 95, "maximum": 100}]},
        rid(vm, "fine").lower(): {"Percentage CPU": [{"average": 40, "maximum": 70}]},
        rid("Microsoft.Web/serverfarms", "plan1").lower(): {"CpuPercentage": points("average", 10), "MemoryPercentage": points("average", 55)},
    }
    _, _, dataset = metrics.evaluate("run1", resources, measurements)

    assert dataset["distribution"]["vm"] == {"idle": 1, "under": 0, "right": 1, "saturated": 1, "nodata": 1}
    assert dataset["distribution"]["plan"]["under"] == 1
    by_name = {r["name"]: r for r in dataset["resources"]}
    assert by_name["busy"]["assessment"] == "saturated" and by_name["busy"]["avg"] == 92.5 and by_name["busy"]["max"] == 100
    assert by_name["fine"]["assessment"] == "right" and by_name["idle"]["detail"] == "size"
    assert by_name["idle"]["resourceGroup"] == "rg" and "max" not in by_name["idle"]  # no daily maximum was reported
    assert by_name["plan1"]["memory"] == 55.0 and "nodata" not in by_name
    # idle first, then underutilized, saturated and right-sized
    assert [r["assessment"] for r in dataset["resources"]] == ["idle", "under", "saturated", "right"]


def test_the_inventory_is_capped(monkeypatch):
    monkeypatch.setattr(metrics, "MAX_INVENTORY", 2)
    vm = "Microsoft.Compute/virtualMachines"
    resources = {"vm": [row(vm, f"v{i}") for i in range(4)]}
    measurements = {rid(vm, f"v{i}").lower(): {"Percentage CPU": points("average", 1)} for i in range(4)}
    _, _, dataset = metrics.evaluate("r", resources, measurements)
    assert len(dataset["resources"]) == 2 and dataset["distribution"]["vm"]["idle"] == 4

def test_evaluate_with_nothing_measured():
    findings, stats, dataset = metrics.evaluate("r", {"vm": [row("x/y", "a")]}, {})
    assert findings == [] and stats == [] and dataset["measured"]["vm"] == 0


# --- requests -------------------------------------------------------------------------------------------

def test_requests_are_grouped_by_subscription_region_and_kind_in_chunks_of_fifty():
    many = [row("Microsoft.Compute/virtualMachines", f"vm{i}") for i in range(120)]
    resources = {"vm": many + [row("Microsoft.Compute/virtualMachines", "west", region="westus2")],
                 "storage": [row("Microsoft.Storage/storageAccounts", "st")]}
    plan = metrics.plan_requests(resources)
    sizes = sorted(len(ids) for kind, _, region, ids in plan if kind == "vm" and region == "eastus")
    assert sizes == [20, 50, 50]
    assert {(kind, region) for kind, _, region, _ in plan} == {("vm", "eastus"), ("vm", "westus2"), ("storage", "eastus")}


class FakeResponse:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_post_retries_when_throttled(monkeypatch):
    responses = [FakeResponse(429, headers={"Retry-After": "3"}), FakeResponse(200, {"values": []})]
    slept = []
    monkeypatch.setattr(metrics.requests, "post", lambda *a, **k: responses.pop(0))
    monkeypatch.setattr(metrics, "_sleep", slept.append)
    assert metrics._post("u", {}, "t", ["id"]) == {"values": []}
    assert slept == [3.0]


def test_post_raises_other_errors(monkeypatch):
    monkeypatch.setattr(metrics.requests, "post", lambda *a, **k: FakeResponse(400))
    with pytest.raises(RuntimeError):
        metrics._post("u", {}, "t", ["id"])


def test_post_retries_dropped_connections_and_then_gives_up(monkeypatch):
    attempts = {"n": 0}

    def flaky(*args, **kwargs):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise metrics.requests.ConnectionError("Remote end closed connection")
        return FakeResponse(200, {"values": []})

    slept = []
    monkeypatch.setattr(metrics.requests, "post", flaky)
    monkeypatch.setattr(metrics, "_sleep", slept.append)
    assert metrics._post("u", {}, "t", ["id"]) == {"values": []}
    assert attempts["n"] == 3 and slept == [1, 2]

    monkeypatch.setattr(metrics.requests, "post", lambda *a, **k: (_ for _ in ()).throw(metrics.requests.Timeout("slow")))
    with pytest.raises(metrics.requests.Timeout):
        metrics._post("u", {}, "t", ["id"])


def test_fetch_batch_calls_the_regional_endpoint(monkeypatch):
    captured = {}

    def fake_post(url, params, token, ids):
        captured.update(url=url, params=params, token=token, ids=ids)
        return {"values": [{"resourceid": ids[0], "value": [
            {"name": {"value": "Percentage CPU"}, "timeseries": [{"data": points("average", 3)}]}]}]}

    class Credential:
        def get_token(self, scope):
            captured["scope"] = scope
            return type("T", (), {"token": "secret-token"})()

    monkeypatch.setattr(metrics, "_post", fake_post)
    result = metrics.fetch_batch(Credential(), "vm", SUB, "westus2", ["/x/Y"], now=NOW)
    assert captured["url"] == f"https://westus2.metrics.monitor.azure.com/subscriptions/{SUB}/metrics:getBatch"
    assert captured["params"]["metricnamespace"] == "Microsoft.Compute/virtualMachines"
    assert captured["params"]["metricnames"].startswith("Percentage CPU,Available Memory Bytes") and captured["params"]["interval"] == "P1D"
    assert captured["params"]["endtime"] == "2026-10-15T00:00:00Z" and captured["params"]["starttime"] == "2026-09-15T00:00:00Z"
    assert captured["scope"] == metrics.SCOPE and captured["token"] == "secret-token"
    assert result == {"/x/y": {"Percentage CPU": points("average", 3)}}


REAL_FETCH_HOURLY = metrics.fetch_hourly


@pytest.fixture(autouse=True)
def no_hourly_calls(monkeypatch):
    monkeypatch.setattr(metrics, "fetch_hourly", lambda *a, **k: {})


def test_collect_reports_failures_without_losing_the_rest(monkeypatch):
    vm = row("Microsoft.Compute/virtualMachines", "idle")

    def fake_query(credential, subscriptions, kql, max_rows=0):
        if "virtualmachines'" in kql:
            return [vm]
        if "serverfarms" in kql:
            raise RuntimeError("Forbidden\nsecond line")
        return []

    def fake_fetch(credential, kind, sub, region, ids, now=None):
        return {vm["id"].lower(): {"Percentage CPU": points("average", 1)}}

    monkeypatch.setattr(graph, "query", fake_query)
    monkeypatch.setattr(metrics, "fetch_batch", fake_fetch)
    monkeypatch.setattr(skus, "fetch", lambda credential, sub, region: {})
    findings, stats, dataset, errors = metrics.collect(None, "r", [SUB])
    assert [f["ruleId"] for f in findings] == ["MET-VM-001"]
    assert errors == [{"ruleId": "metrics-plan", "error": "Forbidden"}]


def test_a_failing_metrics_request_is_reported(monkeypatch):
    vm = row("Microsoft.Compute/virtualMachines", "a")
    monkeypatch.setattr(graph, "query", lambda c, s, kql, max_rows=0: [vm] if "virtualmachines'" in kql else [])

    def boom(*args, **kwargs):
        raise RuntimeError("HTTP 400")

    monkeypatch.setattr(metrics, "fetch_batch", boom)
    monkeypatch.setattr(skus, "fetch", lambda credential, sub, region: {})
    findings, stats, dataset, errors = metrics.collect(None, "r", [SUB])
    assert findings == [] and errors[0]["ruleId"] == "metrics-vm-eastus"


def test_every_target_has_rules_and_a_query():
    for kind, target in metrics.TARGETS.items():
        assert target["query"].strip() and target["namespace"] and target["metrics"]
        assert all(rule in metrics.RULES for rule in metrics.APPLICABLE[kind])


# --- dashboard ------------------------------------------------------------------------------------------

def test_pillar_pages_render_the_right_sizing_panel(monkeypatch):
    dashboard_app.app.config.update(TESTING=True)
    client = dashboard_app.app.test_client()
    summary = {
        "runId": "r1", "completedUtc": "t", "subscriptionCount": 1, "resourceCount": 5, "findingCount": 1,
        "scores": {"Security": 80, "Reliability": 80, "Cost Optimization": 80, "Operational Excellence": 80,
                   "Performance Efficiency": 80},
        "severityTotals": {"critical": 0, "high": 0, "medium": 1, "low": 0}, "sources": {"metrics": {"rules": 3, "findings": 1}},
        "subscriptions": [], "errors": [],
        "metrics": {"lookbackDays": 30, "measured": {"vm": 4, "storage": 2},
                    "topUnderutilized": [{"name": "<i>idle-vm</i>", "detail": "Standard_D2", "rule": "MET-VM-001", "value": 1.5}],
                    "topSaturated": [{"name": "busy-vm", "detail": "B2", "rule": "MET-VM-003", "value": 92.0}]},
    }
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: summary)
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])
    html = client.get("/pillar/performance").get_data(as_text=True)
    assert "Right-sizing" in html and "VMs 4" in html and "busy-vm" in html
    assert "<i>idle-vm</i>" not in html and "&lt;i&gt;idle-vm&lt;/i&gt;" in html
    assert "Right-sizing" in client.get("/pillar/cost").get_data(as_text=True)


# --- memory, disk and network of virtual machines ------------------------------------------------------------

GIB = 1024 ** 3
SIZE = {"vcpus": 4, "memoryGB": 16, "iops": 1000, "restricted": False}


def test_sizes_are_read_from_the_skus_api():
    body = {"value": [
        {"resourceType": "virtualMachines", "name": "Standard_D4as_v5", "capabilities": [
            {"name": "vCPUs", "value": "4"}, {"name": "MemoryGB", "value": "16"}, {"name": "UncachedDiskIOPS", "value": "6400"}], "restrictions": []},
        {"resourceType": "virtualMachines", "name": "Standard_X", "capabilities": [], "restrictions": [{"reasonCode": "NotAvailableForSubscription"}]},
        {"resourceType": "disks", "name": "Premium_LRS", "capabilities": []}]}
    sizes = skus.parse(body)
    assert sizes["standard_d4as_v5"] == {"vcpus": 4, "memoryGB": 16, "iops": 6400, "restricted": False}
    assert sizes["standard_x"]["restricted"] is True and sizes["standard_x"]["vcpus"] is None and "premium_lrs" not in sizes
    assert skus.parse(None) == {}


def test_skus_follow_the_next_link(monkeypatch):
    pages = [{"value": [{"resourceType": "virtualMachines", "name": "A", "capabilities": []}], "nextLink": "https://next"},
             {"value": [{"resourceType": "virtualMachines", "name": "B", "capabilities": []}]}]
    calls = []

    class Response:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self.body

    def fake_get(url, params=None, headers=None, timeout=0):
        calls.append((url, params))
        return Response(pages[len(calls) - 1])

    class Credential:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    monkeypatch.setattr(skus.requests, "get", fake_get)
    assert set(skus.fetch(Credential(), SUB, "eastus")) == {"a", "b"}
    assert calls[0][1]["$filter"] == "location eq 'eastus'" and calls[1] == ("https://next", None)


def test_enrich_derives_memory_disk_and_network():
    raw = {"Available Memory Bytes": points("average", 4 * GIB),
           "Disk Read Operations/Sec": points("average", 100) , "Disk Write Operations/Sec": points("average", 150),
           "Network In Total": points("average", 7_500_000), "Network Out Total": points("average", 7_500_000)}
    raw["Disk Read Operations/Sec"][0]["maximum"] = 300
    raw["Disk Write Operations/Sec"][0]["maximum"] = 200
    out = metrics.enrich_vm(raw, SIZE)
    assert out["Memory used %"][0]["average"] == 75.0
    assert out["Disk IOPS %"][0]["average"] == 25.0 and out["Disk IOPS %"][0]["maximum"] == 50.0
    assert out["Network Mbps"][0]["average"] == 2.0
    assert metrics.enrich_vm(raw, None).keys() >= {"Network Mbps"} and "Memory used %" not in metrics.enrich_vm(raw, None)


def test_a_vm_with_low_cpu_but_busy_memory_is_not_idle():
    cpu = {"Percentage CPU": points("average", 3)}
    assert metrics.classify("vm", {**cpu, "Memory used %": points("average", 40)})[0] == "MET-VM-001"
    assert metrics.classify("vm", {**cpu, "Memory used %": points("average", 75)}) == (None, 3)
    assert metrics.classify("vm", {**cpu, "Memory used %": points("average", 93)}) == ("MET-VM-004", 93)
    assert metrics.classify("vm", {"Percentage CPU": points("average", 90), "Memory used %": points("average", 95)})[0] == "MET-VM-003"


def test_evaluate_adds_vm_details_and_the_daily_series():
    vm = {**row("Microsoft.Compute/virtualMachines", "big"), "detail": "Standard_D4as_v5"}
    raw = {"Percentage CPU": points("average", 3, 5), "Available Memory Bytes": points("average", 8 * GIB, 8 * GIB),
           "Network In Total": points("average", 0, 0), "Network Out Total": points("average", 0, 0)}
    raw["Percentage CPU"][0]["maximum"] = 40
    findings, stats, dataset = metrics.evaluate("r", {"vm": [vm]}, {vm["id"].lower(): raw}, {(SUB, "eastus"): {"standard_d4as_v5": SIZE}})
    record = dataset["resources"][0]
    assert record["memory"] == 50.0 and record["vcpus"] == 4 and record["memoryGB"] == 16 and record["net"] == 0.0
    assert "note" not in record and record["assessment"] == "idle"
    assert dataset["series"] == [{"id": vm["id"].lower(), "from": "2026-10-01", "cpu": [3, 5], "cpuMax": [40, None], "mem": [50.0, 50.0]}]
    busy = {**raw, "Available Memory Bytes": points("average", 4 * GIB, 4 * GIB)}
    _, _, dataset = metrics.evaluate("r", {"vm": [vm]}, {vm["id"].lower(): busy}, {(SUB, "eastus"): {"standard_d4as_v5": SIZE}})
    assert dataset["resources"][0]["note"] == "memory-bound" and dataset["resources"][0]["assessment"] == "right"


def test_a_failing_sizes_call_is_reported_and_right_sizing_goes_on(monkeypatch):
    vm = row("Microsoft.Compute/virtualMachines", "a")
    monkeypatch.setattr(graph, "query", lambda c, s, kql, max_rows=0: [vm] if "virtualmachines'" in kql else [])
    monkeypatch.setattr(metrics, "fetch_batch", lambda *a, **k: {vm["id"].lower(): {"Percentage CPU": points("average", 1)}})

    def refuse(credential, sub, region):
        raise RuntimeError("AuthorizationFailed\nmore")

    monkeypatch.setattr(skus, "fetch", refuse)
    findings, _, _, errors = metrics.collect(None, "r", [SUB])
    assert [f["ruleId"] for f in findings] == ["MET-VM-001"] and errors == [{"ruleId": "metrics-sizes-eastus", "error": "AuthorizationFailed"}]

# ---- more resource kinds

def test_new_kinds_have_queries_rules_and_thresholds():
    for kind in ("sql_mi", "aks", "cosmos", "redis"):
        assert kind in metrics.TARGETS and all(rule in metrics.RULES for rule in metrics.APPLICABLE[kind])
    assert "provisioned" in metrics.TARGETS["cosmos"]["query"] and "EnableServerless" in metrics.TARGETS["cosmos"]["query"]


def test_aks_is_underutilized_only_when_memory_is_low_too():
    low = {"node_cpu_usage_percentage": points("average", 8)}
    assert metrics.classify("aks", {**low, "node_memory_working_set_percentage": points("average", 30)}) == ("MET-AKS-001", 8)
    assert metrics.classify("aks", {**low, "node_memory_working_set_percentage": points("average", 65)}) == (None, 8)
    assert metrics.classify("aks", {**low, "node_memory_working_set_percentage": points("average", 90)}) == ("MET-AKS-002", 90)
    assert metrics.classify("aks", {"node_cpu_usage_percentage": points("average", 85)})[0] == "MET-AKS-002"


def test_cosmos_redis_and_managed_instance_classification():
    assert metrics.classify("cosmos", {"NormalizedRUConsumption": points("average", 4)}) == ("MET-COS-001", 4)
    assert metrics.classify("cosmos", {"NormalizedRUConsumption": points("average", 95)})[0] == "MET-COS-002"
    assert metrics.classify("cosmos", {"NormalizedRUConsumption": points("average", 40)}) == (None, 40)
    assert metrics.classify("redis", {"percentProcessorTime": points("average", 3), "usedmemorypercentage": points("average", 20)})[0] == "MET-RED-001"
    assert metrics.classify("redis", {"percentProcessorTime": points("average", 3), "usedmemorypercentage": points("average", 95)})[0] == "MET-RED-002"
    assert metrics.classify("sql_mi", {"avg_cpu_percent": points("average", 2)})[0] == "MET-MI-001"
    assert metrics.classify("sql_mi", {"avg_cpu_percent": points("average", 90)})[0] == "MET-MI-002"
    assert metrics.classify("aks", {}) == (None, None)


def test_vm_records_carry_environment_and_availability():
    vm = {**row("Microsoft.Compute/virtualMachines", "p"), "environment": "Production", "availability": "none"}
    _, _, dataset = metrics.evaluate("r", {"vm": [vm]}, {vm["id"].lower(): {"Percentage CPU": points("average", 30)}})
    assert dataset["resources"][0]["env"] == "Production" and dataset["resources"][0]["ha"] == "none"


def test_aks_records_keep_their_memory_and_the_dashboard_agrees_with_the_collector():
    import rightsizing
    cluster = row("Microsoft.ContainerService/managedClusters", "k")
    raw = {"node_cpu_usage_percentage": points("average", 8), "node_memory_working_set_percentage": points("average", 30)}
    _, _, dataset = metrics.evaluate("r", {"aks": [cluster]}, {cluster["id"].lower(): raw})
    record = dataset["resources"][0]
    assert record["memory"] == 30 and record["assessment"] == "under"
    assert rightsizing.assess(record, rightsizing.DEFAULT_THRESHOLDS) == "under"
    assert rightsizing.assess({**record, "memory": 90}, rightsizing.DEFAULT_THRESHOLDS) == "saturated"
    assert rightsizing.assess({**record, "memory": 65}, rightsizing.DEFAULT_THRESHOLDS) == "right"
    assert "aks" in rightsizing.KINDS and rightsizing.kind_labels("cosmos")["under"].startswith("Mostly unused")

# ---- office-hours virtual machines

def hourly_points(busy_hours, level=40, base=2, days=7, start="2026-10-05"):
    """168 hourly points: `level` percent in the given UTC hours Monday to Friday, `base` otherwise."""
    from datetime import datetime, timedelta
    first = datetime.fromisoformat(start)
    out = []
    for i in range(24 * days):
        moment = first + timedelta(hours=i)
        busy = moment.weekday() < 5 and moment.hour in busy_hours
        out.append({"timeStamp": moment.strftime("%Y-%m-%dT%H:00:00Z"), "average": level if busy else base})
    return out


def test_schedule_finds_the_office_hours_window_and_the_quiet_weekend():
    schedule = metrics.schedule_of(hourly_points(range(8, 18)))
    assert schedule["window"] == 10 and schedule["start"] == 8 and schedule["weekend"] is True and schedule["hours"] == 50
    assert schedule["saving"] == round(1 - 50 / 168, 2)


def test_schedule_of_a_machine_that_is_always_busy_or_idle():
    assert metrics.schedule_of(hourly_points(range(24)))["window"] > metrics.SCHEDULE_MAX_WINDOW
    assert metrics.schedule_of(hourly_points(range(8, 18), level=3, base=1)) is None  # never above the minimum peak
    assert metrics.schedule_of(hourly_points(range(8, 18))[:20]) is None  # too little data
    assert metrics.schedule_of(None) is None


def test_schedule_window_can_wrap_midnight():
    schedule = metrics.schedule_of(hourly_points([22, 23, 0, 1, 2, 3]))
    assert schedule["window"] == 6 and schedule["start"] == 22


def test_a_vm_used_in_office_hours_gets_a_finding_and_a_schedule():
    vm = row("Microsoft.Compute/virtualMachines", "office")
    daily = {"Percentage CPU": points("average", 20, 20)}
    hourly = {vm["id"].lower(): {"Percentage CPU": hourly_points(range(8, 18))}}
    findings, stats, dataset = metrics.evaluate("r", {"vm": [vm]}, {vm["id"].lower(): daily}, hourly=hourly)
    assert [f["ruleId"] for f in findings] == ["MET-VM-005"] and "10 hours a day" in findings[0]["title"]
    assert dataset["resources"][0]["scheduleCandidate"] is True and dataset["resources"][0]["schedule"]["window"] == 10
    always = {vm["id"].lower(): {"Percentage CPU": hourly_points(range(24))}}
    findings, _, dataset = metrics.evaluate("r", {"vm": [vm]}, {vm["id"].lower(): daily}, hourly=always)
    assert findings == [] and "scheduleCandidate" not in dataset["resources"][0]


def test_hourly_cpu_is_requested_for_the_measured_vms_and_failures_are_reported(monkeypatch):
    vm = row("Microsoft.Compute/virtualMachines", "a")
    monkeypatch.setattr(graph, "query", lambda c, s, kql, max_rows=0: [vm] if "virtualmachines'" in kql else [])
    monkeypatch.setattr(metrics, "fetch_batch", lambda *a, **k: {vm["id"].lower(): {"Percentage CPU": points("average", 20)}})
    monkeypatch.setattr(skus, "fetch", lambda credential, sub, region: {})
    seen = []

    def hourly(credential, sub, region, ids, now=None):
        seen.append((sub, region, ids))
        raise RuntimeError("HTTP 429\nmore")

    monkeypatch.setattr(metrics, "fetch_hourly", hourly)
    _, _, _, errors = metrics.collect(None, "r", [SUB])
    assert seen == [(SUB, "eastus", [vm["id"]])] and errors == [{"ruleId": "metrics-schedule-eastus", "error": "HTTP 429"}]


def test_fetch_hourly_asks_for_seven_days_of_hourly_cpu(monkeypatch):
    captured = {}
    monkeypatch.setattr(metrics, "_post", lambda url, params, token, ids: captured.update(params=params) or {"values": []})

    class Credential:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    REAL_FETCH_HOURLY(Credential(), SUB, "eastus", ["/x"], now=NOW)
    assert captured["params"]["interval"] == "PT1H" and captured["params"]["metricnames"] == "Percentage CPU"
    assert captured["params"]["starttime"] == "2026-10-08T00:00:00Z"

def test_no_query_uses_mv_apply_which_resource_graph_rejects():
    from waf_pulse import aoe_rules, security, security_rules
    queries = [t["query"] for t in metrics.TARGETS.values()] + [r.query for r in aoe_rules.RULES_EXTRA] + [r.query for r in security_rules.RULES_SECURITY] + list(security.QUERIES.values())
    assert not [q for q in queries if "mv-apply" in q]
