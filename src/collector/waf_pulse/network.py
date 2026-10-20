"""Network topology and network insights (Resource Graph, Reader is enough): virtual networks with their subnets and peerings, the
devices around them (firewalls, gateways, Bastion, application gateways, load balancers, NAT gateways, private endpoints, public IPs,
route tables, security groups, private DNS zones, flow logs) and the findings that only show when the pieces are read together:
subnets with no security group, spokes that do not send traffic through the firewall, peerings that are broken or one sided,
address spaces that overlap inside a connected group, retired Basic SKUs, gateways that are not zone redundant.

The rows kept for the dashboard are small: the page draws the topology from them."""
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor

from . import graph
from .findings import make_finding

SOURCE = "network"
RESERVED_SUBNETS = {"gatewaysubnet", "azurefirewallsubnet", "azurefirewallmanagementsubnet", "azurebastionsubnet", "routeserversubnet"}
WORKERS = 4
MAX_ROWS = {"vnet": 800, "device": 2500}
MAX_KIND_ROWS = 600     # per device kind, the biggest ones first (private endpoints and public IPs can be thousands)
# What the page keeps first when there are more devices than MAX_ROWS["device"]: the edge and the exposure, then the plumbing.
KEEP_ORDER = ("firewall", "gateway", "bastion", "appgw", "lb", "natgw", "paas", "nsg", "routetable", "pe", "pip", "dns")
INTERNET_SOURCES = {"*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "/0"}

RULES = {
    "SEC-NET-001": ("Security", "medium", "Virtual network has subnets without a network security group",
                    "Associate a network security group with every subnet that holds workloads, so traffic between tiers is filtered by default."),
    "SEC-NET-002": ("Security", "medium", "Subnets next to an Azure Firewall do not send their traffic through it",
                    "Associate a route table with a 0.0.0.0/0 route whose next hop is the firewall's private IP address, so traffic cannot bypass it."),
    "SEC-NET-003": ("Security", "medium", "Application Gateway that faces the internet has no web application firewall",
                    "Use the WAF tier (WAF_v2) or attach a WAF policy so web attacks are filtered before they reach the application."),
    "SEC-NET-004": ("Security", "medium", "Azure Firewall threat intelligence is off",
                    "Turn on threat intelligence (alert, or alert and deny) so traffic to and from known malicious addresses is flagged."),
    "REL-NET-002": ("Reliability", "high", "Virtual network peering is disconnected or exists on one side only",
                    "Recreate the peering on both networks, or delete the leftover one. Traffic does not flow until both sides are connected."),
    "REL-NET-003": ("Reliability", "medium", "Address space overlaps with another network in the same connected group",
                    "Renumber one of the networks: peered or routed networks cannot share addresses, and the overlap blocks new peerings and VPN routes."),
    "REL-NET-004": ("Reliability", "high", "Basic SKU public IP address or load balancer (retired by Microsoft)",
                    "Upgrade to the Standard SKU, which is zone redundant and has an SLA. Basic public IPs and load balancers were retired on 30 September 2025."),
    "REL-NET-005": ("Reliability", "low", "VPN or ExpressRoute gateway is not zone redundant",
                    "Use a zone redundant gateway SKU (the ones that end in AZ) in regions with availability zones."),
    "OPS-NET-004": ("Operational Excellence", "low", "Virtual network has no flow logs",
                    "Enable virtual network flow logs (or NSG flow logs) so you can investigate traffic and detect threats."),
    "OPS-NET-005": ("Operational Excellence", "low", "Private DNS zone is not linked to any virtual network",
                    "Link the zone to the networks that need to resolve its names, or delete it if nothing uses it."),
}

# KQL per source. Every row has the lower-case id so the pieces can be joined in Python.
QUERIES = {
    "vnets": """
resources | where type =~ 'microsoft.network/virtualnetworks'
| project id, name, subscriptionId, resourceGroup, location, prefixes = properties.addressSpace.addressPrefixes,
    dns = properties.dhcpOptions.dnsServers, ddos = tobool(properties.enableDdosProtection), ddosPlan = tostring(properties.ddosProtectionPlan.id)
""",
    "subnets": """
resources | where type =~ 'microsoft.network/virtualnetworks'
| mv-expand subnet = properties.subnets
| project vnet = id, name = tostring(subnet.name), prefix = tostring(coalesce(subnet.properties.addressPrefix, subnet.properties.addressPrefixes[0])),
    nsg = tostring(subnet.properties.networkSecurityGroup.id), routeTable = tostring(subnet.properties.routeTable.id),
    nat = tostring(subnet.properties.natGateway.id), delegation = tostring(subnet.properties.delegations[0].properties.serviceName),
    used = coalesce(array_length(subnet.properties.ipConfigurations), 0), endpoints = coalesce(array_length(subnet.properties.privateEndpoints), 0),
    serviceEndpoints = coalesce(array_length(subnet.properties.serviceEndpoints), 0)
""",
    "peerings": """
resources | where type =~ 'microsoft.network/virtualnetworks'
| mv-expand peering = properties.virtualNetworkPeerings
| project vnet = id, remote = tostring(peering.properties.remoteVirtualNetwork.id), state = tostring(peering.properties.peeringState),
    forwarded = tobool(peering.properties.allowForwardedTraffic), gatewayTransit = tobool(peering.properties.allowGatewayTransit),
    useRemoteGateways = tobool(peering.properties.useRemoteGateways)
""",
    "firewalls": """
resources | where type =~ 'microsoft.network/azurefirewalls'
| project id, name, subscriptionId, resourceGroup, location, sku = tostring(properties.sku.tier), mode = tostring(properties.sku.name),
    threatIntel = tostring(properties.threatIntelMode), policy = tostring(properties.firewallPolicy.id),
    subnet = tostring(properties.ipConfigurations[0].properties.subnet.id), privateIp = tostring(properties.ipConfigurations[0].properties.privateIPAddress),
    hub = tostring(properties.virtualHub.id)
""",
    "gateways": """
resources | where type =~ 'microsoft.network/virtualnetworkgateways'
| project id, name, subscriptionId, resourceGroup, location, gatewayType = tostring(properties.gatewayType), vpnType = tostring(properties.vpnType),
    sku = tostring(properties.sku.name), activeActive = tobool(properties.activeActive), bgp = tobool(properties.enableBgp),
    subnet = tostring(properties.ipConfigurations[0].properties.subnet.id)
""",
    "connections": """
resources | where type =~ 'microsoft.network/connections'
| project id, name, subscriptionId, resourceGroup, location, connectionType = tostring(properties.connectionType), status = tostring(properties.connectionStatus),
    gateway = tostring(properties.virtualNetworkGateway1.id), remote = tostring(coalesce(properties.localNetworkGateway2.id, properties.peer.id, properties.virtualNetworkGateway2.id))
""",
    "bastions": """
resources | where type =~ 'microsoft.network/bastionhosts'
| project id, name, subscriptionId, resourceGroup, location, sku = tostring(sku.name), subnet = tostring(properties.ipConfigurations[0].properties.subnet.id)
""",
    "appgws": """
resources | where type =~ 'microsoft.network/applicationgateways'
| project id, name, subscriptionId, resourceGroup, location, sku = tostring(properties.sku.name), tier = tostring(properties.sku.tier),
    waf = tobool(properties.webApplicationFirewallConfiguration.enabled) or isnotempty(tostring(properties.firewallPolicy.id)),
    public = tostring(properties.frontendIPConfigurations) contains 'publicIPAddress',
    subnet = tostring(properties.gatewayIPConfigurations[0].properties.subnet.id)
""",
    "lbs": """
resources | where type =~ 'microsoft.network/loadbalancers'
| project id, name, subscriptionId, resourceGroup, location, sku = tostring(sku.name),
    public = tostring(properties.frontendIPConfigurations) contains 'publicIPAddress'
""",
    "natgws": """
resources | where type =~ 'microsoft.network/natgateways'
| project id, name, subscriptionId, resourceGroup, location, sku = tostring(sku.name), subnets = coalesce(array_length(properties.subnets), 0)
""",
    "pes": """
resources | where type =~ 'microsoft.network/privateendpoints'
| project id, name, subscriptionId, resourceGroup, location, subnet = tostring(properties.subnet.id),
    target = tostring(coalesce(properties.privateLinkServiceConnections[0].properties.privateLinkServiceId, properties.manualPrivateLinkServiceConnections[0].properties.privateLinkServiceId)),
    group = tostring(coalesce(properties.privateLinkServiceConnections[0].properties.groupIds[0], properties.manualPrivateLinkServiceConnections[0].properties.groupIds[0]))
""",
    "pips": """
resources | where type =~ 'microsoft.network/publicipaddresses'
| project id, name, subscriptionId, resourceGroup, location, sku = tostring(sku.name), ip = tostring(properties.ipAddress),
    attached = tostring(coalesce(properties.ipConfiguration.id, properties.natGateway.id)), ddos = tostring(properties.ddosSettings.protectionMode)
""",
    "routetables": """
resources | where type =~ 'microsoft.network/routetables'
| project id, name, subscriptionId, resourceGroup, location, routes = properties.routes, subnets = coalesce(array_length(properties.subnets), 0)
""",
    "nsgs": """
resources | where type =~ 'microsoft.network/networksecuritygroups'
| project id, name, subscriptionId, resourceGroup, location, subnets = coalesce(array_length(properties.subnets), 0),
    nics = coalesce(array_length(properties.networkInterfaces), 0), rules = coalesce(array_length(properties.securityRules), 0)
""",
    "nsgrules": """
resources | where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| where tostring(rule.properties.access) =~ 'Allow' and tostring(rule.properties.direction) =~ 'Inbound'
| extend sources = array_concat(pack_array(tostring(rule.properties.sourceAddressPrefix)),
    iff(isnull(rule.properties.sourceAddressPrefixes), dynamic([]), rule.properties.sourceAddressPrefixes))
| mv-expand source = sources to typeof(string)
| where source in~ ('*', 'internet', 'any', '0.0.0.0/0', '0.0.0.0', '/0')
| extend ports = array_concat(pack_array(tostring(rule.properties.destinationPortRange)),
    iff(isnull(rule.properties.destinationPortRanges), dynamic([]), rule.properties.destinationPortRanges))
| mv-expand port = ports to typeof(string)
| project nsg = id, rule = tostring(rule.name), port
""",
    "dnszones": """
resources | where type =~ 'microsoft.network/privatednszones'
| project id, name, subscriptionId, resourceGroup, location, links = toint(properties.numberOfVirtualNetworkLinks), records = toint(properties.numberOfRecordSets)
""",
    "flowlogs": """
resources | where type =~ 'microsoft.network/networkwatchers/flowlogs'
| project id, target = tostring(properties.targetResourceId), enabled = tobool(properties.enabled)
""",
    "paas": """
resources
| where type in~ ('microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.sql/servers', 'microsoft.documentdb/databaseaccounts', 'microsoft.containerregistry/registries')
| extend access = tostring(properties.publicNetworkAccess), acl = tostring(coalesce(properties.networkAcls.defaultAction, properties.networkRuleSet.defaultAction)),
    filtered = tobool(properties.isVirtualNetworkFilterEnabled)
| project id, name, type = tolower(type), subscriptionId, resourceGroup, location, access, acl, filtered,
    endpoints = coalesce(array_length(properties.privateEndpointConnections), 0)
""",
}
LIMITS = {"vnets": 2000, "subnets": 8000, "peerings": 8000, "nsgrules": 8000, "pes": 4000, "pips": 4000, "paas": 4000}


def lower(value):
    return str(value or "").lower()


def short(resource_id):
    return str(resource_id or "").rstrip("/").rsplit("/", 1)[-1]


def owner(resource_id):
    """The resource a child id belongs to: the NIC behind .../networkInterfaces/nic/ipConfigurations/x, the firewall behind its IP configuration."""
    parts = str(resource_id or "").split("/")
    lowered = [p.lower() for p in parts]
    if "providers" in lowered:
        index = len(lowered) - 1 - lowered[::-1].index("providers")
        if len(parts) > index + 3:
            return parts[index + 3]
    return short(resource_id)


def vnet_of(subnet_id):
    """The virtual network id (lower case) inside a subnet id."""
    parts = lower(subnet_id).split("/subnets/")
    return parts[0] if len(parts) > 1 else ""


def fetch(credential, subscription_ids):
    """({name: rows or None}, errors). A query that fails for every chunk of subscriptions gives None, and the rules that need it are skipped."""
    rows, failed, errors = {name: [] for name in QUERIES}, {}, []

    def run(job):
        name, chunk = job
        try:
            return name, graph.query(credential, chunk, QUERIES[name], max_rows=LIMITS.get(name, 2000)), None
        except Exception as exc:
            logging.warning("Network query %s failed: %s", name, str(exc).splitlines()[0][:200])
            return name, None, str(exc).splitlines()[0][:200]

    chunks = list(graph.chunks(subscription_ids))
    jobs = [(name, chunk) for name in QUERIES for chunk in chunks]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for name, found, error in pool.map(run, jobs):
            if found is None:
                failed[name] = failed.get(name, 0) + 1
                errors.append({"ruleId": f"network-{name}", "error": error})
            else:
                rows[name].extend(found)
    raw = {name: (None if failed.get(name, 0) >= len(chunks) else found) for name, found in rows.items()}
    return raw, errors


def _networks(prefixes):
    found = []
    for prefix in prefixes or []:
        try:
            found.append(ipaddress.ip_network(str(prefix), strict=False))
        except ValueError:
            continue
    return found


def _components(vnets):
    """Groups of virtual networks joined by peerings (union find). {id: group id}."""
    parent = {vid: vid for vid in vnets}

    def find(item):
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for vid, vnet in vnets.items():
        for peering in vnet["peerings"]:
            if peering["remote"] in vnets and peering["state"].lower() == "connected":
                parent[find(vid)] = find(peering["remote"])
    return {vid: find(vid) for vid in vnets}


def build(raw):
    """The virtual networks of the raw rows, each with its subnets and peerings, and the lookups the rules need."""
    vnets = {}
    for row in raw.get("vnets") or []:
        vid = lower(row["id"])
        vnets[vid] = {"t": "vnet", "id": row["id"], "name": row["name"], "sub": lower(row["subscriptionId"]), "rg": row["resourceGroup"], "loc": row["location"],
                      "prefixes": list(row.get("prefixes") or []), "dns": list(row.get("dns") or []), "ddos": bool(row.get("ddos")) or bool(row.get("ddosPlan")),
                      "subnets": [], "peerings": []}
    names = {lower(row["id"]): row["name"] for key in ("routetables", "nsgs", "natgws") for row in raw.get(key) or []}
    for row in raw.get("subnets") or []:
        vnet = vnets.get(lower(row["vnet"]))
        if vnet is None or not row.get("name"):
            continue
        prefix = row.get("prefix") or ""
        networks = _networks([prefix])
        capacity = max(networks[0].num_addresses - 5, 0) if networks else 0
        vnet["subnets"].append({"name": row["name"], "prefix": prefix, "nsg": lower(row.get("nsg")), "nsgName": names.get(lower(row.get("nsg")), short(row.get("nsg"))),
                                "routeTable": lower(row.get("routeTable")), "routeTableName": names.get(lower(row.get("routeTable")), short(row.get("routeTable"))),
                                "nat": bool(row.get("nat")), "delegation": row.get("delegation") or "", "used": int(row.get("used") or 0) + int(row.get("endpoints") or 0),
                                "capacity": capacity, "reserved": lower(row["name"]) in RESERVED_SUBNETS})
    for row in raw.get("peerings") or []:
        vnet = vnets.get(lower(row["vnet"]))
        if vnet is None:
            continue
        remote = lower(row.get("remote"))
        vnet["peerings"].append({"remote": remote, "name": vnets[remote]["name"] if remote in vnets else short(remote), "known": remote in vnets,
                                 "state": row.get("state") or "", "forwarded": bool(row.get("forwarded")), "gatewayTransit": bool(row.get("gatewayTransit")),
                                 "useRemoteGateways": bool(row.get("useRemoteGateways"))})
    for vnet in vnets.values():
        for peering in vnet["peerings"]:
            remote = vnets.get(peering["remote"])
            peering["oneSided"] = bool(remote) and not any(p["remote"] == lower(vnet["id"]) for p in remote["peerings"])
    return vnets


def _finding(run_id, rule, resource_id, name, resource_type, subscription_id):
    pillar, severity, title, recommendation = RULES[rule]
    return make_finding(run_id, rule_id=rule, source=SOURCE, pillar=pillar, severity=severity, title=title, recommendation=recommendation,
                        resource_id=resource_id, resource_name=name, resource_type=resource_type, subscription_id=subscription_id)


def _has_default_route(route_table):
    for route in (route_table or {}).get("routes") or []:
        props = route.get("properties", route)
        if str(props.get("addressPrefix", "")).strip() == "0.0.0.0/0" and str(props.get("nextHopType", "")).lower() in ("virtualappliance", "virtualnetworkgateway"):
            return True
    return False


def evaluate(run_id, raw):
    """(findings, stats, summary, rows): findings and statistics like any other source, a small summary and the rows the page draws."""
    vnets = build(raw)
    flagged = {rule: {} for rule in RULES}       # rule -> {resource id: (name, type, subscription)}
    applicable = {rule: {} for rule in RULES}    # rule -> {resource id: subscription}

    def judge(rule, resource_id, name, resource_type, subscription, bad):
        applicable[rule][lower(resource_id)] = lower(subscription)
        if bad:
            flagged[rule][lower(resource_id)] = (resource_id, name, resource_type, lower(subscription))

    route_tables = {lower(row["id"]): row for row in raw.get("routetables") or []}
    groups = _components(vnets)
    firewall_vnets = {}
    for row in raw.get("firewalls") or []:
        vid = vnet_of(row.get("subnet"))
        if vid in vnets:
            firewall_vnets.setdefault(vid, []).append(row)

    missing_side = {p["remote"] for v in vnets.values() for p in v["peerings"] if p["oneSided"]}   # the network that lacks the peering back
    for vid, vnet in vnets.items():
        workloads = [s for s in vnet["subnets"] if not s["reserved"]]
        if raw.get("subnets") is not None and workloads:
            judge("SEC-NET-001", vnet["id"], vnet["name"], "microsoft.network/virtualnetworks", vnet["sub"], any(not s["nsg"] for s in workloads))
        if raw.get("peerings") is not None and (vnet["peerings"] or vid in missing_side):
            judge("REL-NET-002", vnet["id"], vnet["name"], "microsoft.network/virtualnetworks", vnet["sub"],
                  vid in missing_side or any(p["state"].lower() != "connected" or p["oneSided"] for p in vnet["peerings"]))

    if raw.get("firewalls") is not None and firewall_vnets and raw.get("routetables") is not None:
        covered = set(firewall_vnets)
        for vid in firewall_vnets:
            covered.update(p["remote"] for p in vnets[vid]["peerings"] if p["remote"] in vnets)
        for vid in covered:
            vnet = vnets[vid]
            subnets = [s for s in vnet["subnets"] if not s["reserved"] and not s["delegation"]]
            if subnets:
                judge("SEC-NET-002", vnet["id"], vnet["name"], "microsoft.network/virtualnetworks", vnet["sub"],
                      any(not _has_default_route(route_tables.get(s["routeTable"])) for s in subnets))

    members = {}
    for vid, group in groups.items():
        members.setdefault(group, []).append(vid)
    for group, ids in members.items():
        if len(ids) < 2:
            continue
        networks = {vid: _networks(vnets[vid]["prefixes"]) for vid in ids}
        overlapping = set()
        for index, first in enumerate(ids):
            for second in ids[index + 1:]:
                if any(a.overlaps(b) for a in networks[first] for b in networks[second]):
                    overlapping.update((first, second))
        for vid in ids:
            judge("REL-NET-003", vnets[vid]["id"], vnets[vid]["name"], "microsoft.network/virtualnetworks", vnets[vid]["sub"], vid in overlapping)

    if raw.get("flowlogs") is not None:
        targets = {lower(row["target"]) for row in raw["flowlogs"] if row.get("enabled")}
        for vid, vnet in vnets.items():
            covered = vid in targets or any(s["nsg"] and s["nsg"] in targets for s in vnet["subnets"]) \
                or any(f"{vid}/subnets/{lower(s['name'])}" in targets for s in vnet["subnets"])
            judge("OPS-NET-004", vnet["id"], vnet["name"], "microsoft.network/virtualnetworks", vnet["sub"], not covered)

    for row in raw.get("firewalls") or []:
        if not row.get("hub") and not row.get("policy") and row.get("threatIntel"):
            judge("SEC-NET-004", row["id"], row["name"], "microsoft.network/azurefirewalls", row["subscriptionId"], lower(row["threatIntel"]) == "off")
    for row in raw.get("appgws") or []:
        if row.get("public"):
            judge("SEC-NET-003", row["id"], row["name"], "microsoft.network/applicationgateways", row["subscriptionId"], not row.get("waf"))
    for row in raw.get("pips") or []:
        judge("REL-NET-004", row["id"], row["name"], "microsoft.network/publicipaddresses", row["subscriptionId"], lower(row.get("sku")) == "basic")
    for row in raw.get("lbs") or []:
        judge("REL-NET-004", row["id"], row["name"], "microsoft.network/loadbalancers", row["subscriptionId"], lower(row.get("sku")) == "basic")
    for row in raw.get("gateways") or []:
        if lower(row.get("gatewayType")) in ("vpn", "expressroute"):
            judge("REL-NET-005", row["id"], row["name"], "microsoft.network/virtualnetworkgateways", row["subscriptionId"], not lower(row.get("sku")).endswith("az"))
    for row in raw.get("dnszones") or []:
        judge("OPS-NET-005", row["id"], row["name"], "microsoft.network/privatednszones", row["subscriptionId"], int(row.get("links") or 0) == 0)

    findings = [_finding(run_id, rule, *entry) for rule, items in flagged.items() for entry in items.values()]
    stats = []
    for rule, (pillar, severity, _, _) in RULES.items():
        per_sub = {}
        for rid, sub in applicable[rule].items():
            entry = per_sub.setdefault(sub, {"affected": 0, "applicable": 0})
            entry["applicable"] += 1
            entry["affected"] += 1 if rid in flagged[rule] else 0
        stats.extend({"ruleId": rule, "source": SOURCE, "pillar": pillar, "severity": severity, "subscriptionId": sub, **value} for sub, value in per_sub.items())
    rows, truncated = rows_for_page(vnets, raw)
    return findings, stats, {**summarize(vnets, raw, findings), "truncated": truncated}, rows


def _exposure(raw):
    """{nsg id: [ports]} of the inbound allow rules that accept the internet."""
    result = {}
    for row in raw.get("nsgrules") or []:
        result.setdefault(lower(row["nsg"]), set()).add(row["port"] or "*")
    return {nsg: sorted(ports, key=lambda p: (p != "*", p)) for nsg, ports in result.items()}


def _device(kind, row, **extra):
    return {"t": "device", "kind": kind, "id": row["id"], "name": row["name"], "sub": lower(row["subscriptionId"]), "rg": row["resourceGroup"], "loc": row["location"], **extra}


def rows_for_page(vnets, raw):
    """The rows the dashboard keeps: virtual networks, then devices (each kind limited to its biggest)."""
    exposure = _exposure(raw)
    rows = list(vnets.values())[:MAX_ROWS["vnet"]]
    devices = []
    for row in raw.get("firewalls") or []:
        devices.append(_device("firewall", row, vnet=vnet_of(row.get("subnet")) or lower(row.get("hub")), sku=row.get("sku") or "", threatIntel=row.get("threatIntel") or "",
                               policy=bool(row.get("policy")), privateIp=row.get("privateIp") or "", managed=bool(row.get("hub"))))
    connections = {}
    for row in raw.get("connections") or []:
        connections.setdefault(lower(row.get("gateway")), []).append({"kind": row.get("connectionType") or "", "status": row.get("status") or ""})
    for row in raw.get("gateways") or []:
        devices.append(_device("gateway", row, vnet=vnet_of(row.get("subnet")), gatewayType=row.get("gatewayType") or "", sku=row.get("sku") or "", activeActive=bool(row.get("activeActive")),
                               bgp=bool(row.get("bgp")), connections=connections.get(lower(row["id"]), [])[:6]))
    for row in raw.get("bastions") or []:
        devices.append(_device("bastion", row, vnet=vnet_of(row.get("subnet")), sku=row.get("sku") or ""))
    for row in raw.get("appgws") or []:
        devices.append(_device("appgw", row, vnet=vnet_of(row.get("subnet")), sku=row.get("sku") or "", waf=bool(row.get("waf")), public=bool(row.get("public"))))
    for row in raw.get("lbs") or []:
        devices.append(_device("lb", row, sku=row.get("sku") or "", public=bool(row.get("public"))))
    for row in raw.get("natgws") or []:
        devices.append(_device("natgw", row, sku=row.get("sku") or "", subnets=int(row.get("subnets") or 0)))
    for row in raw.get("routetables") or []:
        routes = []
        for route in row.get("routes") or []:
            props = route.get("properties", route)
            routes.append({"prefix": props.get("addressPrefix", ""), "hop": props.get("nextHopType", ""), "ip": props.get("nextHopIpAddress", "")})
        devices.append(_device("routetable", row, subnets=int(row.get("subnets") or 0), routes=routes[:20], default=_has_default_route(row)))
    for row in raw.get("nsgs") or []:
        devices.append(_device("nsg", row, subnets=int(row.get("subnets") or 0), nics=int(row.get("nics") or 0), rules=int(row.get("rules") or 0), internetPorts=exposure.get(lower(row["id"]), [])[:12]))
    for row in raw.get("dnszones") or []:
        devices.append(_device("dns", row, links=int(row.get("links") or 0), records=int(row.get("records") or 0)))
    kept = []
    for row in sorted(raw.get("pes") or [], key=lambda r: lower(r["name"]))[:MAX_KIND_ROWS]:
        devices.append(_device("pe", row, vnet=vnet_of(row.get("subnet")), target=lower(row.get("target")), targetName=short(row.get("target")), group=row.get("group") or ""))
    for row in sorted(raw.get("pips") or [], key=lambda r: (lower(r.get("attached")) != "", lower(r["name"])))[:MAX_KIND_ROWS]:
        devices.append(_device("pip", row, sku=row.get("sku") or "", ip=row.get("ip") or "", attached=lower(row.get("attached")), attachedName=owner(row.get("attached")),
                               ddos=row.get("ddos") or ""))
    for row in raw.get("paas") or []:
        public = lower(row.get("access")) != "disabled" and lower(row.get("acl")) != "deny" and not row.get("filtered")
        if public and int(row.get("endpoints") or 0) == 0:
            kept.append(_device("paas", row, type=lower(row["type"])))
    devices.extend(kept[:MAX_KIND_ROWS])
    devices.sort(key=lambda d: (KEEP_ORDER.index(d["kind"]) if d["kind"] in KEEP_ORDER else len(KEEP_ORDER), 0 if d.get("internetPorts") else 1))
    truncated = (len(vnets) > MAX_ROWS["vnet"] or len(devices) > MAX_ROWS["device"] or len(raw.get("pes") or []) > MAX_KIND_ROWS
                 or len(raw.get("pips") or []) > MAX_KIND_ROWS or len(kept) > MAX_KIND_ROWS)
    return rows + devices[:MAX_ROWS["device"]], truncated


def summarize(vnets, raw, findings):
    """Counts for the Network page header and the data source table."""
    def count(key):
        return len(raw.get(key) or [])

    subnets = [s for v in vnets.values() for s in v["subnets"]]
    peerings = sum(len(v["peerings"]) for v in vnets.values())
    return {"vnets": len(vnets), "subnets": len(subnets), "subnetsWithoutNsg": sum(1 for s in subnets if not s["reserved"] and not s["nsg"]),
            "peerings": peerings // 2 if peerings else 0, "firewalls": count("firewalls"), "gateways": count("gateways"), "bastions": count("bastions"),
            "appGateways": count("appgws"), "loadBalancers": count("lbs"), "natGateways": count("natgws"), "privateEndpoints": count("pes"),
            "publicIps": count("pips"), "publicIpsUnattached": sum(1 for r in raw.get("pips") or [] if not r.get("attached")), "nsgs": count("nsgs"),
            "routeTables": count("routetables"), "privateDnsZones": count("dnszones"), "findings": len(findings)}


def collect(credential, run_id, subscription_ids):
    """Returns (findings, stats, summary, rows, errors)."""
    raw, errors = fetch(credential, subscription_ids)
    findings, stats, summary, rows = evaluate(run_id, raw)
    return findings, stats, summary, rows, errors
