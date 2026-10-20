"""Quota usage (Reader is enough): how close each subscription is to its compute and network quotas in the regions it uses. A quota that
is almost used stops the next deployment or the next scale-out, so it is a reliability risk long before it is an outage.

The regions come from where the subscription has resources. One call per subscription, region and service."""
import time
from concurrent.futures import ThreadPoolExecutor

from . import graph, rest
from .findings import make_finding

SCOPE = "https://management.azure.com/.default"
SERVICES = {
    "compute": ("Microsoft.Compute", "2024-03-01"),
    "network": ("Microsoft.Network", "2023-11-01"),
}
WORKERS = 6
MAX_REGIONS_PER_SUBSCRIPTION = 15
TIME_BUDGET_SECONDS = 200
WARN_PERCENT = 80.0
HIGH_PERCENT = 95.0
MIN_LIMIT = 4          # a quota of 1 to 3 is a switch (a dedicated host, a gateway), not a pool that runs out
MAX_ROWS = 40
RULES = {"REL-QUOTA-001": ("medium", "{name} is at {percent:g}% of its quota in {region} ({current:g} of {limit:g})"),
         "REL-QUOTA-002": ("high", "{name} is at {percent:g}% of its quota in {region} ({current:g} of {limit:g})")}
RECOMMENDATION = "Request a quota increase before the next deployment or scale-out needs it, or free some of the quota that is in use."

REGIONS_QUERY = """
resources
| where tolower(location) !in ('global', '')
| summarize resources = count() by subscriptionId, location = tolower(location)
| order by resources desc
"""


def parse_usages(body, service, subscription, region):
    """[{service, subscriptionId, region, name, current, limit, percent}] of the quotas that are in use, from a usages response."""
    rows = []
    for item in (body or {}).get("value", []):
        limit, current = item.get("limit"), item.get("currentValue")
        if not isinstance(limit, (int, float)) or not isinstance(current, (int, float)) or limit < MIN_LIMIT or current <= 0:
            continue
        name = item.get("name") or {}
        rows.append({"service": service, "subscriptionId": subscription, "region": region, "key": name.get("value", ""),
                     "name": name.get("localizedValue") or name.get("value", ""), "current": current, "limit": limit,
                     "percent": round(100 * current / limit, 1)})
    return rows


def evaluate(run_id, rows):
    """(findings, stats, dataset) from the quotas that are in use."""
    findings, per_sub = [], {}
    for row in rows:
        entry = per_sub.setdefault(row["subscriptionId"], {"affected": 0, "applicable": 0})
        entry["applicable"] += 1
        if row["percent"] < WARN_PERCENT:
            continue
        entry["affected"] += 1
        rule = "REL-QUOTA-002" if row["percent"] >= HIGH_PERCENT else "REL-QUOTA-001"
        severity, title = RULES[rule]
        findings.append(make_finding(
            run_id, rule_id=rule, source="quotas", pillar="Reliability", severity=severity, title=title.format(**row), recommendation=RECOMMENDATION,
            resource_id=f"/subscriptions/{row['subscriptionId']}/providers/microsoft.{row['service']}/locations/{row['region']}/usages/{row['key']}",
            resource_name=f"{row['name']} · {row['region']}", resource_type=f"microsoft.{row['service']}/locations/usages", subscription_id=row["subscriptionId"]))
    stats = [{"ruleId": rule, "source": "quotas", "pillar": "Reliability", "severity": RULES[rule][0], "subscriptionId": sub,
              "affected": sum(1 for f in findings if f["ruleId"] == rule and f["subscriptionId"] == sub), "applicable": value["applicable"]}
             for sub, value in per_sub.items() for rule in RULES]
    ranked = sorted(rows, key=lambda r: (-r["percent"], r["name"]))
    dataset = {"checked": len(rows), "atRisk": sum(1 for r in rows if r["percent"] >= WARN_PERCENT),
               "rows": [{k: r[k] for k in ("service", "subscriptionId", "region", "name", "current", "limit", "percent")} for r in ranked[:MAX_ROWS]]}
    return findings, stats, dataset


def collect(credential, run_id, subscription_ids):
    """Returns (findings, stats, dataset, errors)."""
    errors, regions = [], {}
    try:
        for chunk in graph.chunks(subscription_ids):
            for row in graph.query(credential, chunk, REGIONS_QUERY, max_rows=2000):
                regions.setdefault(str(row["subscriptionId"]).lower(), []).append(str(row["location"]).lower())
    except Exception as exc:
        errors.append({"ruleId": "quotas-regions", "error": str(exc).splitlines()[0][:200]})
    jobs = [(sub, region, service) for sub, found in regions.items() for region in found[:MAX_REGIONS_PER_SUBSCRIPTION] for service in SERVICES]
    token = credential.get_token(SCOPE).token
    deadline = time.monotonic() + TIME_BUDGET_SECONDS
    denied = {"count": 0}

    def run(job):
        sub, region, service = job
        if time.monotonic() > deadline:
            return []
        provider, version = SERVICES[service]
        try:
            response = rest.get(f"https://management.azure.com/subscriptions/{sub}/providers/{provider}/locations/{region}/usages", token, {"api-version": version})
        except Exception:
            return []
        if response.status_code in (401, 403):
            denied["count"] += 1
            return []
        return parse_usages(response.json(), service, sub, region) if response.status_code == 200 else []

    rows = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for found in pool.map(run, jobs):
            rows.extend(found)
    if denied["count"]:
        errors.append({"ruleId": "quotas-permission", "error": f"{denied['count']} quota read(s) were refused: grant Reader on the subscriptions."})
    findings, stats, dataset = evaluate(run_id, rows)
    dataset["regionsRead"] = len(jobs) // len(SERVICES)
    return findings, stats, dataset, errors
