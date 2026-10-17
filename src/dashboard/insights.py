"""Aggregations over the findings of one run, for the overview, pillar and recommendation pages. Pure functions."""
import re
from collections import Counter, defaultdict

SEVERITIES = ("critical", "high", "medium", "low")
RANK = {level: index for index, level in enumerate(SEVERITIES)}

# slug -> (pillar, label used in the navigation)
PILLAR_PAGES = {
    "security": ("Security", "Security"),
    "reliability": ("Reliability", "Reliability"),
    "cost": ("Cost Optimization", "Cost"),
    "performance": ("Performance Efficiency", "Performance"),
    "operations": ("Operational Excellence", "Operations"),
}
PILLAR_SLUG = {pillar: slug for slug, (pillar, _) in PILLAR_PAGES.items()}

_NUMBER = re.compile(r"\d+(?:\.\d+)?")


def severity_totals(findings):
    counts = Counter(f.get("severity") for f in findings)
    return {level: counts.get(level, 0) for level in SEVERITIES}


def _generic_title(titles):
    """Findings of one rule can carry measured values ("CPU 3.2%"); the group shows the title without them."""
    unique = set(titles)
    if len(unique) == 1:
        return next(iter(unique))
    most_common = Counter(_NUMBER.sub("N", title) for title in titles).most_common(1)[0][0]
    return most_common.replace("N", "…")


def group_rules(findings):
    """One row per rule, the most severe and widespread first."""
    groups = defaultdict(list)
    for finding in findings:
        groups[finding.get("ruleId") or "unknown"].append(finding)
    rows = []
    for rule, items in groups.items():
        first = items[0]
        rows.append({
            "ruleId": rule, "title": _generic_title([i.get("title", "") for i in items]),
            "severity": min((i.get("severity", "low") for i in items), key=lambda s: RANK.get(s, 9)),
            "pillar": first.get("pillar", ""), "source": first.get("source") or "builtin",
            "recommendation": first.get("recommendation", ""),
            "resources": len({str(i.get("resourceId", "")).lower() for i in items}),
            "subscriptions": len({i.get("subscriptionId", "") for i in items}),
            "link": next((i["link"] for i in items if i.get("link")), None),
        })
    rows.sort(key=lambda row: (RANK.get(row["severity"], 9), -row["resources"], row["title"]))
    return rows


def short_type(resource_type):
    value = str(resource_type or "").lower()
    return value.replace("microsoft.", "", 1) if value else "(no type)"


def top_counts(findings, field, limit=8, transform=None):
    """[(label, count)] largest first. Blank values are skipped."""
    counter = Counter()
    for finding in findings:
        value = finding.get(field)
        if value:
            counter[transform(value) if transform else value] += 1
    return counter.most_common(limit)


def by_pillar(findings, pillars):
    """[(pillar, {severity: count})] in the given order."""
    table = {pillar: Counter() for pillar in pillars}
    for finding in findings:
        if finding.get("pillar") in table:
            table[finding["pillar"]][finding.get("severity")] += 1
    return [(pillar, dict(table[pillar])) for pillar in pillars]


def worst_resources(findings, limit=8):
    """Resources with the most findings: [(name, resourceId, count)]."""
    counter, names = Counter(), {}
    for finding in findings:
        resource = str(finding.get("resourceId", "")).lower()
        if not resource or "/commitments/" in resource:
            continue
        counter[resource] += 1
        names.setdefault(resource, finding.get("resourceName") or resource.rsplit("/", 1)[-1])
    return [(names[resource], resource, count) for resource, count in counter.most_common(limit)]


FRIENDLY_TYPES = {
    "microsoft.compute/virtualmachines": "Virtual machines", "microsoft.compute/disks": "Managed disks",
    "microsoft.compute/snapshots": "Disk snapshots", "microsoft.storage/storageaccounts": "Storage accounts",
    "microsoft.sql/servers": "SQL servers", "microsoft.sql/servers/databases": "SQL databases",
    "microsoft.web/sites": "App Service and Function apps", "microsoft.web/serverfarms": "App Service plans",
    "microsoft.keyvault/vaults": "Key Vaults", "microsoft.network/networksecuritygroups": "Network security groups",
    "microsoft.network/virtualnetworks": "Virtual networks", "microsoft.network/publicipaddresses": "Public IP addresses",
    "microsoft.network/networkinterfaces": "Network interfaces", "microsoft.network/loadbalancers": "Load balancers",
    "microsoft.documentdb/databaseaccounts": "Cosmos DB accounts", "microsoft.containerservice/managedclusters": "AKS clusters",
    "microsoft.operationalinsights/workspaces": "Log Analytics workspaces",
}


def friendly_type(resource_type):
    """A readable name for a resource type: the common ones are spelled out, the rest are shown without the provider."""
    value = str(resource_type or "").lower()
    return FRIENDLY_TYPES.get(value) or short_type(value)


def filter_resources(rows, resource_type=None, subscription=None, group=None, query=None):
    """Narrows the resource list. Every filter is optional; the text matches name, type, group, location and details."""
    needle = str(query or "").strip().lower()
    result = []
    for row in rows:
        if resource_type and row.get("type") != resource_type:
            continue
        if subscription and row.get("subscriptionId") != subscription:
            continue
        if group and str(row.get("resourceGroup", "")).lower() != group.lower():
            continue
        if needle and needle not in " ".join(str(row.get(k, "")) for k in ("name", "type", "resourceGroup", "location", "detail")).lower():
            continue
        result.append(row)
    return result


def findings_per_resource(findings):
    """{resource id (lower): number of findings}."""
    counts = Counter(str(f.get("resourceId", "")).lower() for f in findings if f.get("resourceId"))
    return dict(counts)


_ARM_ID = re.compile(r"^/subscriptions/[0-9a-fA-F-]{36}(/|$)")
PORTAL = "https://portal.azure.com/"


def portal_url(resource_id, tenant_id=""):
    """Link that opens a resource in the Azure portal, or None for anything that is not an Azure resource (an Entra
    app, a cost anomaly, a commitment option). With the tenant in the link, the portal opens it in the right directory."""
    value = str(resource_id or "")
    if not _ARM_ID.match(value) or "/commitments/" in value.lower() or len(value) > 800:
        return None
    directory = f"@{tenant_id}/" if re.fullmatch(r"[0-9a-fA-F-]{36}", str(tenant_id or "")) else ""
    return f"{PORTAL}#{directory}resource{value}"


def resource_group_of(resource_id):
    parts = str(resource_id or "").split("/")
    lowered = [p.lower() for p in parts]
    return parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered[:-1] else ""


def group_by_resource(findings):
    """One row per affected resource: its worst severity, how many findings it has and their titles."""
    groups = {}
    for finding in findings:
        resource = str(finding.get("resourceId", "")).lower()
        if not resource:
            continue
        item = groups.setdefault(resource, {
            "id": finding.get("resourceId"), "name": finding.get("resourceName") or resource.rsplit("/", 1)[-1],
            "type": str(finding.get("resourceType", "")).lower(), "subscriptionId": finding.get("subscriptionId", ""),
            "severity": "low", "count": 0, "titles": [], "pillars": set(), "sources": set()})
        item["count"] += 1
        if RANK.get(finding.get("severity"), 9) < RANK.get(item["severity"], 9):
            item["severity"] = finding.get("severity")
        title = finding.get("title", "")
        if title and title not in item["titles"]:
            item["titles"].append(title)
        item["pillars"].add(finding.get("pillar", ""))
        item["sources"].add(finding.get("source") or "builtin")
    rows = []
    for item in groups.values():
        rows.append({**item, "resourceGroup": resource_group_of(item["id"]), "pillars": sorted(item["pillars"]),
                     "sources": sorted(item["sources"])})
    rows.sort(key=lambda r: (RANK.get(r["severity"], 9), -r["count"], r["name"].lower()))
    return rows


# Filters of the resource list, like the ones of the Azure portal: a field, "equals" or "does not equal", and values.
RESOURCE_FILTERS = {
    "subscription": ("subscriptionId", "Subscription"),
    "group": ("resourceGroup", "Resource group"),
    "type": ("type", "Resource type"),
    "location": ("location", "Location"),
}
FINDING_FILTER = {"with": "With findings", "without": "Without findings"}
MAX_FILTER_VALUES = 60
MAX_FILTER_TEXT = 150


def parse_filters(args, facets, lowercase=(), radios=None, texts=("name",)):
    """Reads filters from a query string (a `MultiDict`): {field: {op, values}}. A facet field takes several values
    (any of them) and `field_op=ne` turns it into "does not equal"; a radio field takes one of its choices; a text
    field is "contains"."""
    filters = {}
    for field in facets:
        values = []
        for value in args.getlist(field):
            value = value.strip()[:MAX_FILTER_TEXT]
            if value and value.lower() not in {v.lower() for v in values}:
                values.append(value.lower() if field in lowercase else value)
        if values:
            op = "ne" if args.get(f"{field}_op") == "ne" else "eq"
            filters[field] = {"op": op, "values": values[:MAX_FILTER_VALUES]}
    for field, choices in (radios or {}).items():
        if args.get(field, "") in choices:
            filters[field] = {"op": "eq", "values": [args.get(field)]}
    for field in texts:
        text = args.get(field, "").strip()[:MAX_FILTER_TEXT]
        if text:
            filters[field] = {"op": "contains", "values": [text]}
    return filters


def parse_resource_filters(args):
    """The filters of the resource list: the four fields, `findings` (with or without) and `name` (contains)."""
    return parse_filters(args, RESOURCE_FILTERS, ("subscription", "type"), {"findings": FINDING_FILTER})


def apply_resource_filters(rows, filters, query="", counts=None, skip=None):
    """The rows that satisfy every filter (except `skip`, to count the choices of that filter) and the free text."""
    counts = counts or {}
    needle = str(query or "").strip().lower()
    result = []
    for row in rows:
        keep = True
        for field, spec in filters.items():
            if field == skip:
                continue
            if field in RESOURCE_FILTERS:
                value = str(row.get(RESOURCE_FILTERS[field][0], "")).lower()
                hit = value in {v.lower() for v in spec["values"]}
                keep = hit if spec["op"] == "eq" else not hit
            elif field == "findings":
                has = bool(counts.get(str(row.get("id", "")).lower()))
                keep = has if spec["values"][0] == "with" else not has
            elif field == "name":
                keep = spec["values"][0].lower() in str(row.get("name", "")).lower()
            if not keep:
                break
        if not keep:
            continue
        if needle and needle not in " ".join(str(row.get(k, "")) for k in ("name", "type", "resourceGroup", "location", "detail")).lower():
            continue
        result.append(row)
    return result


def filter_choices(rows, filters, query="", counts=None, names=None, limit=300):
    """For each of the four fields, the values to offer with how many resources each would give, counted with all the
    other filters applied, like the faceted filters of the Azure portal. Returns {field: [[value, label, count]]}."""
    names = names or {}
    choices = {}
    for field, (key, _) in RESOURCE_FILTERS.items():
        counter = Counter(str(r.get(key, "")) for r in apply_resource_filters(rows, filters, query, counts, skip=field) if r.get(key))
        selected = {v.lower() for v in filters.get(field, {}).get("values", [])}
        for value in selected:  # a chosen value stays on the list even when nothing matches it any more
            if not any(v.lower() == value for v in counter):
                counter[value] = 0
        entries = []
        for value, count in counter.items():
            label = names.get(value.lower(), value) if field == "subscription" else friendly_type(value) if field == "type" else value
            entries.append([value, label, count])
        entries.sort(key=lambda e: (-e[2], str(e[1]).lower()))
        choices[field] = entries[:limit]
    return choices
