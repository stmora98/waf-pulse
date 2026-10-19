"""Right-sizing from Azure Monitor metrics (Reader is enough).

Resources are listed with Resource Graph and their last 30 days are read with the Azure Monitor metrics batch
API: up to 50 resources per call, grouped by subscription, region and resource type. Every measured resource is
classified as idle, underutilized or saturated, and the classification feeds the Cost and Performance pillars.
"""
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import requests

from . import graph, skus
from .findings import make_finding

BATCH_SIZE = 50
LOOKBACK_DAYS = 30
MAX_RESOURCES = 5000
REQUEST_TIMEOUT = 60
MAX_ATTEMPTS = 5
SCOPE = "https://metrics.monitor.azure.com/.default"
API_VERSION = "2023-10-01"
WORKERS = 4

TARGETS = {
    "vm": {
        "namespace": "Microsoft.Compute/virtualMachines",
        "metrics": "Percentage CPU,Available Memory Bytes,Disk Read Operations/Sec,Disk Write Operations/Sec,Network In Total,Network Out Total",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where tostring(properties.extended.instanceView.powerState.code) =~ 'PowerState/running'
| extend environment = tostring(coalesce(tags['environment'], tags['Environment'], tags['env'], tags['Env'], tags['ENVIRONMENT']))
| extend availability = iff(isnotempty(tostring(properties.availabilitySet.id)), 'set', iff(array_length(zones) > 0, 'zone', 'none'))
| project id, name, subscriptionId, location, detail = tostring(properties.hardwareProfile.vmSize), environment, availability
""",
    },
    "sql_dtu": {
        "namespace": "Microsoft.Sql/servers/databases",
        "metrics": "dtu_consumption_percent",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.sql/servers/databases' and name != 'master'
| where tostring(sku.tier) in~ ('Basic', 'Standard', 'Premium')
| project id, name, subscriptionId, location, detail = strcat(tostring(sku.tier), ' ', tostring(sku.name))
""",
    },
    "sql_vcore": {
        "namespace": "Microsoft.Sql/servers/databases",
        "metrics": "cpu_percent",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.sql/servers/databases' and name != 'master'
| where tostring(sku.tier) !in~ ('Basic', 'Standard', 'Premium', 'DataWarehouse', '')
| project id, name, subscriptionId, location, detail = strcat(tostring(sku.tier), ' ', tostring(sku.name))
""",
    },
    "plan": {
        "namespace": "Microsoft.Web/serverfarms",
        "metrics": "CpuPercentage,MemoryPercentage",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.web/serverfarms'
| where tostring(sku.tier) !in~ ('Free', 'Shared', 'Dynamic', 'FlexConsumption', 'ElasticPremium', '')
| project id, name, subscriptionId, location, detail = strcat(tostring(sku.name), ' x', tostring(sku.capacity))
""",
    },
    "sql_mi": {
        "namespace": "Microsoft.Sql/managedInstances",
        "metrics": "avg_cpu_percent",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.sql/managedinstances'
| project id, name, subscriptionId, location, detail = strcat(tostring(sku.name), ' ', tostring(properties.vCores), ' vCores')
""",
    },
    "vmss": {
        "namespace": "Microsoft.Compute/virtualMachineScaleSets",
        "metrics": "Percentage CPU",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.compute/virtualmachinescalesets'
| where toint(sku.capacity) > 0
| project id, name, subscriptionId, location, detail = strcat(tostring(sku.name), ' x', tostring(sku.capacity))
""",
    },
    "disk": {
        "namespace": "Microsoft.Compute/disks",
        "metrics": "Composite Disk Read Operations/sec,Composite Disk Write Operations/sec",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.compute/disks'
| where tostring(sku.name) startswith 'Premium' and tostring(properties.diskState) !~ 'Unattached'
| where toint(properties.diskIOPSReadWrite) > 0
| project id, name, subscriptionId, location, detail = strcat(tostring(sku.name), ' ', tostring(properties.diskSizeGB), ' GB'),
    iops = toint(properties.diskIOPSReadWrite)
""",
    },
    "aks": {
        "namespace": "Microsoft.ContainerService/managedClusters",
        "metrics": "node_cpu_usage_percentage,node_memory_working_set_percentage",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.containerservice/managedclusters'
| mv-apply pool = properties.agentPoolProfiles on (summarize nodes = sum(toint(pool['count'])), sizes = make_set(tostring(pool['vmSize'])))
| project id, name, subscriptionId, location, detail = strcat(tostring(nodes), ' nodes · ', strcat_array(sizes, ', '))
""",
    },
    "cosmos": {
        "namespace": "Microsoft.DocumentDB/databaseAccounts",
        "metrics": "NormalizedRUConsumption",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.documentdb/databaseaccounts'
| where tostring(properties.capabilities) !contains 'EnableServerless'
| project id, name, subscriptionId, location, detail = strcat('provisioned · ', tostring(properties.databaseAccountOfferType))
""",
    },
    "redis": {
        "namespace": "Microsoft.Cache/redis",
        "metrics": "percentProcessorTime,usedmemorypercentage",
        "aggregation": "Average,Maximum",
        "query": """
resources
| where type =~ 'microsoft.cache/redis'
| project id, name, subscriptionId, location, detail = strcat(tostring(sku.name), ' ', tostring(sku.family), tostring(sku.capacity))
""",
    },
    "storage": {
        "namespace": "Microsoft.Storage/storageAccounts",
        "metrics": "Transactions",
        "aggregation": "Total",
        "query": """
resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id, name, subscriptionId, location, detail = tostring(sku.name)
""",
    },
}

# rule id -> (pillar, severity, title template, recommendation)
RULES = {
    "MET-VM-001": ("Cost Optimization", "high", "Virtual machine is idle: average CPU {value:.1f}% over {days} days",
                   "Shut down or delete the virtual machine, or move the workload to a much smaller size."),
    "MET-VM-002": ("Cost Optimization", "medium", "Virtual machine is underutilized: average CPU {value:.1f}% over {days} days",
                   "Resize the virtual machine to a smaller size."),
    "MET-VM-003": ("Performance Efficiency", "high", "Virtual machine is saturated: average CPU {value:.1f}% over {days} days",
                   "Resize to a larger size or scale out the workload."),
    "MET-VM-004": ("Performance Efficiency", "high", "Virtual machine is short on memory: average memory use {value:.1f}% over {days} days",
                   "Resize to a size with more memory or find what is holding it."),
    "MET-VM-005": ("Cost Optimization", "medium", "Virtual machine is only busy about {value:.0f} hours a day: schedule an automatic shutdown",
                   "Turn on auto-shutdown or start and stop the virtual machine on a schedule (Azure Automation, a Logic App or Start/Stop v2)."),
    "MET-SQL-001": ("Cost Optimization", "medium", "SQL database is oversized: average utilization {value:.1f}% over {days} days",
                    "Move the database to a smaller service objective."),
    "MET-SQL-002": ("Performance Efficiency", "high", "SQL database is saturated: average utilization {value:.1f}% over {days} days",
                    "Move the database to a larger service objective."),
    "MET-MI-001": ("Cost Optimization", "medium", "SQL managed instance is oversized: average CPU {value:.1f}% over {days} days",
                   "Move the instance to fewer vCores."),
    "MET-MI-002": ("Performance Efficiency", "high", "SQL managed instance is saturated: average CPU {value:.1f}% over {days} days",
                   "Move the instance to more vCores."),
    "MET-VMSS-001": ("Cost Optimization", "medium", "Virtual machine scale set is underutilized: average CPU {value:.1f}% over {days} days",
                     "Lower the minimum instance count or move to a smaller size, and let autoscale add instances when needed."),
    "MET-VMSS-002": ("Performance Efficiency", "high", "Virtual machine scale set is saturated: average CPU {value:.1f}% over {days} days",
                     "Raise the maximum instance count, tune the autoscale rules or move to a larger size."),
    "MET-DSK-001": ("Cost Optimization", "low", "Premium SSD disk is barely used: average {value:.1f}% of its IOPS over {days} days",
                    "Move the disk to Standard SSD, or to a smaller Premium size, if the latency allows it."),
    "MET-DSK-002": ("Performance Efficiency", "high", "Disk is close to its IOPS limit: {value:.1f}% over {days} days",
                    "Move to a larger disk size or a higher tier before requests are throttled."),
    "MET-AKS-001": ("Cost Optimization", "medium", "AKS cluster is underutilized: average node CPU {value:.1f}% over {days} days",
                    "Use fewer or smaller nodes and turn on the cluster autoscaler."),
    "MET-AKS-002": ("Performance Efficiency", "high", "AKS cluster is saturated: node CPU or memory at {value:.1f}% over {days} days",
                    "Add nodes or use larger nodes, and check the pod resource requests."),
    "MET-COS-001": ("Cost Optimization", "medium", "Cosmos DB throughput is mostly unused: average normalized RU consumption {value:.1f}% over {days} days",
                    "Lower the provisioned RU/s, or move to autoscale or serverless."),
    "MET-COS-002": ("Performance Efficiency", "high", "Cosmos DB is close to its provisioned throughput: normalized RU consumption {value:.1f}% over {days} days",
                    "Raise the RU/s or autoscale maximum before requests are throttled."),
    "MET-RED-001": ("Cost Optimization", "medium", "Redis cache is underutilized: average CPU {value:.1f}% over {days} days",
                    "Move to a smaller cache size or tier."),
    "MET-RED-002": ("Performance Efficiency", "high", "Redis cache is saturated: CPU or memory at {value:.1f}% over {days} days",
                    "Scale up or add shards before it evicts keys."),
    "MET-APP-001": ("Cost Optimization", "medium", "App Service plan is underutilized: average CPU {value:.1f}% over {days} days",
                    "Move to a smaller plan or consolidate apps onto fewer plans."),
    "MET-APP-002": ("Performance Efficiency", "high", "App Service plan is saturated: CPU {value:.1f}% over {days} days",
                    "Scale up or out, or move busy apps to their own plan."),
    "MET-STG-001": ("Cost Optimization", "low", "Storage account had no transactions in {days} days",
                    "Delete the storage account if it is no longer used."),
}
APPLICABLE = {
    "vm": ["MET-VM-001", "MET-VM-002", "MET-VM-003", "MET-VM-004", "MET-VM-005"],
    "sql_dtu": ["MET-SQL-001", "MET-SQL-002"],
    "sql_vcore": ["MET-SQL-001", "MET-SQL-002"],
    "plan": ["MET-APP-001", "MET-APP-002"],
    "sql_mi": ["MET-MI-001", "MET-MI-002"],
    "aks": ["MET-AKS-001", "MET-AKS-002"],
    "vmss": ["MET-VMSS-001", "MET-VMSS-002"],
    "disk": ["MET-DSK-001", "MET-DSK-002"],
    "cosmos": ["MET-COS-001", "MET-COS-002"],
    "redis": ["MET-RED-001", "MET-RED-002"],
    "storage": ["MET-STG-001"],
}
SQL_OVERSIZED, SQL_SATURATED = 10, 80
VM_IDLE, VM_UNDER, VM_SATURATED = 5, 15, 80
SCHEDULE_DAYS = 7
SCHEDULE_MAX_VMS = 500
SCHEDULE_MIN_PEAK = 5          # a machine that never goes above this is idle, not scheduled
SCHEDULE_ACTIVE_SHARE = 0.4    # an hour is "in use" from this share of the machine's own peak hour
SCHEDULE_COVER = 0.95          # the usage window holds this share of the busy hours
SCHEDULE_MAX_WINDOW = 12       # hours a day: longer than this is not worth scheduling
VM_MEMORY_BOUND, VM_MEMORY_SATURATED = 70, 90  # low CPU with this much memory in use is a memory-bound machine, not an idle one
PLAN_UNDER, PLAN_SATURATED_CPU, PLAN_SATURATED_MEMORY = 20, 80, 85

# What the visitor can change on the dashboard (percent of average utilization); the memory limits stay fixed.
DEFAULT_THRESHOLDS = {"vm": {"idle": VM_IDLE, "under": VM_UNDER, "saturated": VM_SATURATED},
                      "sql": {"under": SQL_OVERSIZED, "saturated": SQL_SATURATED},
                      "plan": {"under": PLAN_UNDER, "saturated": PLAN_SATURATED_CPU},
                      "aks": {"under": 20, "saturated": 80}, "cosmos": {"under": 10, "saturated": 80},
                      "redis": {"under": 10, "saturated": 80}, "vmss": {"under": 15, "saturated": 80},
                      "disk": {"under": 5, "saturated": 90}}

# kinds judged by one main metric and, for some, a second one that holds back "underutilized" and flags "saturated"
# kind -> (threshold group, main metric, second metric, second metric saturates from, second metric blocks "under" from, rules)
GENERIC = {
    "sql_mi": ("sql", "avg_cpu_percent", None, None, None, ("MET-MI-001", "MET-MI-002")),
    "aks": ("aks", "node_cpu_usage_percentage", "node_memory_working_set_percentage", 85, 60, ("MET-AKS-001", "MET-AKS-002")),
    "cosmos": ("cosmos", "NormalizedRUConsumption", None, None, None, ("MET-COS-001", "MET-COS-002")),
    "redis": ("redis", "percentProcessorTime", "usedmemorypercentage", 90, 50, ("MET-RED-001", "MET-RED-002")),
    "vmss": ("vmss", "Percentage CPU", None, None, None, ("MET-VMSS-001", "MET-VMSS-002")),
    "disk": ("disk", "Disk IOPS %", None, None, None, ("MET-DSK-001", "MET-DSK-002")),
}
SECOND_METRIC = {"plan": "MemoryPercentage", "aks": "node_memory_working_set_percentage", "redis": "usedmemorypercentage"}


def resolve_thresholds(saved):
    """The defaults with the visitor's saved values on top; anything out of range or out of order falls back."""
    result = {group: dict(values) for group, values in DEFAULT_THRESHOLDS.items()}
    for group, values in (saved or {}).items() if isinstance(saved, dict) else []:
        if group not in result or not isinstance(values, dict):
            continue
        merged = dict(result[group])
        for name in merged:
            number = values.get(name)
            if isinstance(number, (int, float)) and not isinstance(number, bool) and 0 < number <= 100:
                merged[name] = number
        order = [merged[name] for name in ("idle", "under", "saturated") if name in merged]
        if order == sorted(set(order)):
            result[group] = merged
    return result

_sleep = time.sleep


def summarize(points, field):
    """Mean of the daily `average`, max of the daily `maximum` or the sum of the daily `total`. None without data."""
    values = [p[field] for p in points if p.get(field) is not None]
    if not values:
        return None
    if field == "average":
        return sum(values) / len(values)
    return sum(values) if field == "total" else max(values)


def parse_batch(body):
    """{resourceid (lower): {metric name: points}} from a metrics:getBatch response."""
    result = {}
    for item in (body or {}).get("values", []):
        metrics = {}
        for metric in item.get("value", []):
            series = (metric.get("timeseries") or [{}])[0].get("data", [])
            metrics[metric.get("name", {}).get("value", "")] = series
        result[str(item.get("resourceid", "")).lower()] = metrics
    return result


def classify(kind, metrics, thresholds=None):
    """Returns (rule id, value) for a measured resource, or (None, value) when it is healthy or has no data."""
    limits = resolve_thresholds(thresholds)
    vm_idle, vm_under, vm_saturated = limits["vm"]["idle"], limits["vm"]["under"], limits["vm"]["saturated"]
    if kind == "vm":
        value = summarize(metrics.get("Percentage CPU", []), "average")
        if value is None:
            return None, None
        if value >= vm_saturated:
            return "MET-VM-003", value
        memory = summarize(metrics.get("Memory used %", []), "average")
        if memory is not None and memory >= VM_MEMORY_SATURATED:
            return "MET-VM-004", memory
        if memory is not None and memory >= VM_MEMORY_BOUND:
            return None, value
        if value < vm_idle:
            return "MET-VM-001", value
        return ("MET-VM-002", value) if value < vm_under else (None, value)
    if kind in ("sql_dtu", "sql_vcore"):
        name = "dtu_consumption_percent" if kind == "sql_dtu" else "cpu_percent"
        value = summarize(metrics.get(name, []), "average")
        if value is None:
            return None, None
        if value < limits["sql"]["under"]:
            return "MET-SQL-001", value
        return ("MET-SQL-002", value) if value >= limits["sql"]["saturated"] else (None, value)
    if kind in GENERIC:
        group, main, second, saturates, blocks, (low, high) = GENERIC[kind]
        value = summarize(metrics.get(main, []), "average")
        if value is None:
            return None, None
        other = summarize(metrics.get(second, []), "average") if second else None
        if value >= limits[group]["saturated"]:
            return high, value
        if other is not None and other >= saturates:
            return high, other
        if other is not None and other >= blocks:
            return None, value
        return (low, value) if value < limits[group]["under"] else (None, value)
    if kind == "plan":
        cpu = summarize(metrics.get("CpuPercentage", []), "average")
        memory = summarize(metrics.get("MemoryPercentage", []), "average")
        if cpu is None:
            return None, None
        if cpu >= limits["plan"]["saturated"]:
            return "MET-APP-002", cpu
        if memory is not None and memory >= PLAN_SATURATED_MEMORY:
            return "MET-APP-002", memory
        return ("MET-APP-001", cpu) if cpu < limits["plan"]["under"] else (None, cpu)
    if kind == "storage":
        points = metrics.get("Transactions", [])
        if not points:
            return None, None
        total = summarize(points, "total")
        return ("MET-STG-001", total or 0) if (total or 0) == 0 else (None, total)
    return None, None


ASSESSMENT = {
    "MET-VM-001": "idle", "MET-VM-002": "under", "MET-VM-003": "saturated", "MET-VM-004": "saturated",
    "MET-SQL-001": "under", "MET-SQL-002": "saturated",
    "MET-APP-001": "under", "MET-APP-002": "saturated",
    "MET-MI-001": "under", "MET-MI-002": "saturated", "MET-AKS-001": "under", "MET-AKS-002": "saturated",
    "MET-COS-001": "under", "MET-COS-002": "saturated", "MET-RED-001": "under", "MET-RED-002": "saturated",
    "MET-VMSS-001": "under", "MET-VMSS-002": "saturated", "MET-DSK-001": "under", "MET-DSK-002": "saturated",
    "MET-STG-001": "idle",
}
ASSESSMENT_ORDER = {"idle": 0, "under": 1, "saturated": 2, "right": 3}
MAX_INVENTORY = 1500
PEAK_METRIC = {"vm": "Percentage CPU", "sql_dtu": "dtu_consumption_percent", "sql_vcore": "cpu_percent", "plan": "CpuPercentage",
               "sql_mi": "avg_cpu_percent", "aks": "node_cpu_usage_percentage", "cosmos": "NormalizedRUConsumption", "redis": "percentProcessorTime",
               "vmss": "Percentage CPU", "disk": "Disk IOPS %"}


def peak(kind, metrics):
    """Highest daily maximum of the main metric (CPU or DTU), or None."""
    name = PEAK_METRIC.get(kind)
    return summarize(metrics.get(name, []), "maximum") if name else None


def _by_day(points):
    return {p.get("timeStamp"): p for p in points or []}


def _pair(first, second, field, scale):
    values = [v for v in (first.get(field), second.get(field)) if v is not None]
    return round(sum(values) * scale, 2) if values else None


def enrich_vm(metrics, size):
    """Adds what the size of a virtual machine lets us read from its raw metrics: memory in use (%), disk IOPS (% of what
    the size allows) and network traffic (Mbps). `size` is the entry of skus.parse; without it only the network is derived."""
    extra = {}
    memory_gb = (size or {}).get("memoryGB")
    if memory_gb and metrics.get("Available Memory Bytes"):
        total = memory_gb * 1024 ** 3
        extra["Memory used %"] = [
            {"timeStamp": p.get("timeStamp"), "average": None if p.get("average") is None else round(min(max(100 - p["average"] / total * 100, 0), 100), 2)}
            for p in metrics["Available Memory Bytes"]]
    reads, writes = _by_day(metrics.get("Disk Read Operations/Sec")), _by_day(metrics.get("Disk Write Operations/Sec"))
    cap = (size or {}).get("iops")
    if cap and (reads or writes):
        extra["Disk IOPS %"] = [
            {"timeStamp": day, "average": _pair(reads.get(day, {}), writes.get(day, {}), "average", 100 / cap),
             "maximum": _pair(reads.get(day, {}), writes.get(day, {}), "maximum", 100 / cap)}
            for day in sorted(set(reads) | set(writes))]
    ins, outs = _by_day(metrics.get("Network In Total")), _by_day(metrics.get("Network Out Total"))
    if ins or outs:
        # the daily average of a per-minute total, so bytes per minute -> megabits per second
        scale = 8 / 60 / 1e6
        extra["Network Mbps"] = [
            {"timeStamp": day, "average": _pair(ins.get(day, {}), outs.get(day, {}), "average", scale),
             "maximum": _pair(ins.get(day, {}), outs.get(day, {}), "maximum", scale)}
            for day in sorted(set(ins) | set(outs))]
    return {**metrics, **extra}


def schedule_of(points):
    """When a virtual machine is in use, from its hourly average CPU (UTC): {hours, window, start, weekend, saving} or None.
    hours = busy hours in the period, window = hours a day that hold most of them, start = first hour of that window,
    weekend = it is quiet on Saturday and Sunday, saving = share of its hours an automatic shutdown could switch off."""
    values = []
    for point in points or []:
        value = point.get("average")
        try:
            moment = datetime.strptime(str(point.get("timeStamp"))[:13], "%Y-%m-%dT%H")
        except ValueError:
            continue
        if value is not None:
            values.append((moment, value))
    if len(values) < 24 * 3:
        return None
    peak = max(v for _, v in values)
    if peak < SCHEDULE_MIN_PEAK:
        return None
    busy = [m for m, v in values if v >= peak * SCHEDULE_ACTIVE_SHARE and v >= SCHEDULE_MIN_PEAK]
    if not busy:
        return None
    by_hour = [0] * 24
    for moment in busy:
        by_hour[moment.hour] += 1
    total = sum(by_hour)
    best = None
    for length in range(1, 25):
        for start in range(24):
            covered = sum(by_hour[(start + i) % 24] for i in range(length))
            if covered >= SCHEDULE_COVER * total:
                best = (length, start)
                break
        if best:
            break
    length, start = best
    weekend = sum(1 for m in busy if m.weekday() >= 5) <= 0.1 * len(busy)
    on = length * (5 if weekend else 7)
    return {"hours": len(busy), "window": length, "start": start, "weekend": weekend, "saving": round(max(1 - on / 168, 0), 2)}


def enrich_disk(metrics, iops):
    """The share of the IOPS a disk's size allows that it really uses, from its read and write operations per second."""
    reads, writes = _by_day(metrics.get("Composite Disk Read Operations/sec")), _by_day(metrics.get("Composite Disk Write Operations/sec"))
    if not iops or not (reads or writes):
        return metrics
    return {**metrics, "Disk IOPS %": [
        {"timeStamp": day, "average": _pair(reads.get(day, {}), writes.get(day, {}), "average", 100 / iops),
         "maximum": _pair(reads.get(day, {}), writes.get(day, {}), "maximum", 100 / iops)} for day in sorted(set(reads) | set(writes))]}


def series_of(kind, metrics):
    """The daily curve of a resource for its chart: {from, cpu, cpuMax, mem}, one value per day (None where there is no
    data), or None when there is nothing to draw."""
    name = PEAK_METRIC.get(kind)
    points = metrics.get(name, []) if name else []
    if not points:
        return None
    memory_name = {"vm": "Memory used %", **SECOND_METRIC}.get(kind)
    memory = _by_day(metrics.get(memory_name))

    def one(value):
        return None if value is None else round(value, 1)

    days = [p.get("timeStamp") for p in points]
    result = {"from": str(days[0])[:10], "cpu": [one(p.get("average")) for p in points], "cpuMax": [one(p.get("maximum")) for p in points]}
    if memory:
        result["mem"] = [one(memory.get(day, {}).get("average")) for day in days]
    return result


def resource_group_of(resource_id):
    parts = str(resource_id).split("/")
    lowered = [p.lower() for p in parts]
    return parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered[:-1] else ""

def evaluate(run_id, resources, measurements, sizes=None, thresholds=None, hourly=None):
    """resources: {kind: [ARG rows]}; measurements: {resourceid (lower): {metric: points}}; sizes: {(subscription, region):
    {size: skus.parse entry}}. Returns (findings, stats, dataset); dataset["series"] has the daily curves."""
    findings, counts, measured_totals = [], {}, {}
    inventory, distribution, series = [], {}, []
    top = {"idle": [], "saturated": []}
    for kind, rows in resources.items():
        for row in rows:
            metrics = measurements.get(str(row["id"]).lower())
            if metrics is None:
                continue
            size = None
            if kind == "vm":
                size = ((sizes or {}).get((str(row.get("subscriptionId", "")).lower(), str(row.get("location", "")).lower())) or {}).get(
                    str(row.get("detail", "")).lower())
                metrics = enrich_vm(metrics, size)
            if kind == "disk":
                metrics = enrich_disk(metrics, row.get("iops"))
            rule, value = classify(kind, metrics, thresholds)
            if value is None:
                continue
            sub = str(row.get("subscriptionId", "")).lower()
            measured_totals[(kind, sub)] = measured_totals.get((kind, sub), 0) + 1
            assessment = ASSESSMENT.get(rule, "right")
            distribution.setdefault(kind, {"idle": 0, "under": 0, "right": 0, "saturated": 0})[assessment] += 1
            record = {"kind": kind, "id": row["id"], "name": row.get("name", ""), "subscriptionId": sub,
                      "resourceGroup": resource_group_of(row["id"]), "detail": row.get("detail", ""),
                      "avg": round(value, 2), "assessment": assessment}
            top_value = peak(kind, metrics)
            if top_value is not None:
                record["max"] = round(top_value, 2)
            if kind in SECOND_METRIC:
                memory = summarize(metrics.get(SECOND_METRIC[kind], []), "average")
                if memory is not None:
                    record["memory"] = round(memory, 1)
            if kind == "vm":
                for field, name, aggregate in (("memory", "Memory used %", "average"), ("iops", "Disk IOPS %", "average"),
                                               ("iopsMax", "Disk IOPS %", "maximum"), ("net", "Network Mbps", "average"),
                                               ("netMax", "Network Mbps", "maximum")):
                    number = summarize(metrics.get(name, []), aggregate)
                    if number is not None:
                        record[field] = round(number, 1)
                if size:
                    record["vcpus"], record["memoryGB"] = size.get("vcpus"), size.get("memoryGB")
                if row.get("environment"):
                    record["env"] = str(row["environment"])[:30]
                if row.get("availability"):
                    record["ha"] = row["availability"]
                if rule is None and value is not None and value < resolve_thresholds(thresholds)["vm"]["under"] and record.get("memory", 0) >= VM_MEMORY_BOUND:
                    record["note"] = "memory-bound"
            if kind == "vm":
                schedule = schedule_of((hourly or {}).get(str(row["id"]).lower(), {}).get("Percentage CPU"))
                if schedule:
                    record["schedule"] = schedule
                    if schedule["window"] <= SCHEDULE_MAX_WINDOW and schedule["saving"] >= 0.3 and rule in (None, "MET-VM-002"):
                        pillar, severity, title, recommendation = RULES["MET-VM-005"]
                        counts[("MET-VM-005", kind, sub)] = counts.get(("MET-VM-005", kind, sub), 0) + 1
                        record["scheduleCandidate"] = True
                        if len(findings) < 3000:
                            findings.append(make_finding(
                                run_id, rule_id="MET-VM-005", source="metrics", pillar=pillar, severity=severity,
                                title=title.format(value=schedule["window"]), recommendation=recommendation,
                                resource_id=row["id"], resource_name=row.get("name", ""), subscription_id=sub))
            curve = series_of(kind, metrics)
            if curve:
                series.append({"id": str(row["id"]).lower(), **curve})
            inventory.append(record)
            if rule is None:
                continue
            pillar, severity, title, recommendation = RULES[rule]
            counts[(rule, kind, sub)] = counts.get((rule, kind, sub), 0) + 1
            if len(findings) < 3000:
                findings.append(
                    make_finding(
                        run_id, rule_id=rule, source="metrics", pillar=pillar, severity=severity,
                        title=title.format(value=value, days=LOOKBACK_DAYS), recommendation=recommendation,
                        resource_id=row["id"], resource_name=row.get("name", ""), subscription_id=sub,
                    )
                )
            entry = {"name": row.get("name", ""), "detail": row.get("detail", ""), "rule": rule, "value": round(value, 1)}
            bucket = "saturated" if pillar == "Performance Efficiency" else "idle"
            if len(top[bucket]) < 10:
                top[bucket].append(entry)

    stats = []
    for (kind, sub), measured in measured_totals.items():
        for rule in APPLICABLE[kind]:
            pillar, severity = RULES[rule][0], RULES[rule][1]
            affected = sum(count for (r, k, s), count in counts.items() if r == rule and k == kind and s == sub)
            stats.append({"ruleId": rule, "source": "metrics", "pillar": pillar, "severity": severity,
                          "subscriptionId": sub, "affected": affected, "applicable": measured})
    # sql_dtu and sql_vcore share rules: merge their rows so each rule has one row per subscription.
    merged = {}
    for item in stats:
        key = (item["ruleId"], item["subscriptionId"])
        if key in merged:
            merged[key]["affected"] += item["affected"]
            merged[key]["applicable"] += item["applicable"]
        else:
            merged[key] = dict(item)
    dataset = {
        "lookbackDays": LOOKBACK_DAYS,
        "measured": {kind: sum(n for (k, _), n in measured_totals.items() if k == kind) for kind in resources},
        "listed": {kind: len(rows) for kind, rows in resources.items()},
        "topUnderutilized": top["idle"],
        "topSaturated": top["saturated"],
        "distribution": {kind: {**distribution.get(kind, {"idle": 0, "under": 0, "right": 0, "saturated": 0}),
                                "nodata": max(len(rows) - sum(distribution.get(kind, {}).values()), 0)}
                         for kind, rows in resources.items()},
        "resources": sorted(inventory, key=lambda r: (ASSESSMENT_ORDER[r["assessment"]], r["avg"]))[:MAX_INVENTORY],
        "series": series[:MAX_INVENTORY],
    }
    return findings, list(merged.values()), dataset


def _post(url, params, token, resource_ids):
    for attempt in range(MAX_ATTEMPTS):
        last = attempt == MAX_ATTEMPTS - 1
        try:
            response = requests.post(url, params=params, headers={"Authorization": f"Bearer {token}"},
                                     json={"resourceids": resource_ids}, timeout=REQUEST_TIMEOUT)
        except (requests.ConnectionError, requests.Timeout):
            if last:
                raise
            _sleep(min(2 ** attempt, 30))
            continue
        if response.status_code == 429 and not last:
            _sleep(min(float(response.headers.get("Retry-After", 5)), 60))
            continue
        response.raise_for_status()
        return response.json()


def _fetch(credential, namespace, names, aggregation, interval, days, subscription, region, resource_ids, now=None):
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "api-version": API_VERSION, "metricnamespace": namespace, "metricnames": names, "aggregation": aggregation, "interval": interval,
        "starttime": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "endtime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    token = credential.get_token(SCOPE).token
    url = f"https://{region}.metrics.monitor.azure.com/subscriptions/{subscription}/metrics:getBatch"
    return parse_batch(_post(url, params, token, resource_ids))


def fetch_batch(credential, kind, subscription, region, resource_ids, now=None):
    target = TARGETS[kind]
    return _fetch(credential, target["namespace"], target["metrics"], target["aggregation"], "P1D", LOOKBACK_DAYS,
                  subscription, region, resource_ids, now)


def fetch_hourly(credential, subscription, region, resource_ids, now=None):
    """The hourly CPU of the last SCHEDULE_DAYS days of virtual machines, to see when they are in use."""
    return _fetch(credential, TARGETS["vm"]["namespace"], "Percentage CPU", "Average", "PT1H", SCHEDULE_DAYS,
                  subscription, region, resource_ids, now)


def plan_requests(resources):
    """One request per (kind, subscription, region) chunk of at most BATCH_SIZE resources."""
    groups = {}
    for kind, rows in resources.items():
        for row in rows:
            key = (kind, str(row["subscriptionId"]).lower(), str(row["location"]).lower())
            groups.setdefault(key, []).append(row["id"])
    return [
        (kind, sub, region, ids[i:i + BATCH_SIZE])
        for (kind, sub, region), ids in groups.items()
        for i in range(0, len(ids), BATCH_SIZE)
    ]


def collect(credential, run_id, subscription_ids, thresholds=None):
    resources, errors = {}, []
    for kind, target in TARGETS.items():
        rows = []
        try:
            for chunk in graph.chunks(subscription_ids):
                rows.extend(graph.query(credential, chunk, target["query"], max_rows=MAX_RESOURCES))
        except Exception as exc:
            errors.append({"ruleId": f"metrics-{kind}", "error": str(exc).splitlines()[0][:200]})
        resources[kind] = rows[:MAX_RESOURCES]

    def run(request):
        kind, sub, region, ids = request
        try:
            return fetch_batch(credential, kind, sub, region, ids), None
        except Exception as exc:
            return {}, {"ruleId": f"metrics-{kind}-{region}", "error": str(exc).splitlines()[0][:200]}

    measurements = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for result, error in pool.map(run, plan_requests(resources)):
            measurements.update(result)
            if error:
                errors.append(error)
    sizes = {}
    for sub_id, region in sorted({(str(r["subscriptionId"]).lower(), str(r["location"]).lower()) for r in resources.get("vm", [])}):
        try:
            sizes[(sub_id, region)] = skus.fetch(credential, sub_id, region)
        except Exception as exc:
            errors.append({"ruleId": f"metrics-sizes-{region}", "error": str(exc).splitlines()[0][:200]})
    hourly = {}
    vms = [r for r in resources.get("vm", []) if str(r["id"]).lower() in measurements][:SCHEDULE_MAX_VMS]
    groups = {}
    for r in vms:
        groups.setdefault((str(r["subscriptionId"]).lower(), str(r["location"]).lower()), []).append(r["id"])
    for (sub_id, region), ids in groups.items():
        for index in range(0, len(ids), BATCH_SIZE):
            try:
                hourly.update(fetch_hourly(credential, sub_id, region, ids[index:index + BATCH_SIZE]))
            except Exception as exc:
                errors.append({"ruleId": f"metrics-schedule-{region}", "error": str(exc).splitlines()[0][:200]})
    findings, stats, dataset = evaluate(run_id, resources, measurements, sizes, thresholds, hourly)
    dataset["thresholds"] = resolve_thresholds(thresholds)
    return findings, stats, dataset, errors
