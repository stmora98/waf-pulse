"""The Network page: a topology of the virtual networks the collector found (hubs, spokes, peerings, on-premises links), the facts of each
network and the network insights. Everything is drawn from the rows the collector kept (`netrows`); the layout is a pure function so it
can be tested without a browser."""
import ipaddress
from collections import Counter, defaultdict

NODE_W, NODE_H = 236, 108
GAP_X, GAP_Y, GAP_GROUP, MARGIN = 36, 96, 70, 24
ONPREM_W, ONPREM_H = 150, 54
BAND_MAX = 1500
PER_ROW = 6
MAX_DRAWN = 18        # networks drawn around one hub (or in the not peered list); the rest folds into one "more" node
MAX_EDGE_LABELS = 12  # with more peerings than this, the "gateway transit" labels would hide the drawing
LABEL_HEIGHT = 26

# Rules whose findings belong on the Network page: the ones of the network source and the older network rules of other sources.
NETWORK_RULES = {
    "SEC-NET-001", "SEC-NET-002", "SEC-NET-003", "SEC-NET-004", "REL-NET-001", "REL-NET-002", "REL-NET-003", "REL-NET-004", "REL-NET-005",
    "OPS-NET-001", "OPS-NET-002", "OPS-NET-003", "OPS-NET-004", "OPS-NET-005", "OPS-NSG-001", "SEC-NSG-001", "SEC-NSG-002", "SEC-NSG-003",
    "SEC-VM-004", "SEC-STG-004", "SEC-KV-002", "SEC-SQL-001", "COST-IP-001", "COST-NSG-001", "COST-NAT-001", "COST-LB-001", "COST-AGW-001",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
KIND_TYPES = {"firewall": "microsoft.network/azurefirewalls", "gateway": "microsoft.network/virtualnetworkgateways", "bastion": "microsoft.network/bastionhosts",
              "appgw": "microsoft.network/applicationgateways", "lb": "microsoft.network/loadbalancers", "natgw": "microsoft.network/natgateways",
              "routetable": "microsoft.network/routetables", "nsg": "microsoft.network/networksecuritygroups", "dns": "microsoft.network/privatednszones",
              "pe": "microsoft.network/privateendpoints", "pip": "microsoft.network/publicipaddresses"}
KIND_LABELS = {"firewall": "Firewall", "gateway": "Gateway", "bastion": "Bastion", "appgw": "App Gateway", "lb": "Load balancer", "natgw": "NAT gateway",
               "routetable": "Route table", "nsg": "Network security group", "dns": "Private DNS zone", "pe": "Private endpoint", "pip": "Public IP", "paas": "Service open to the internet"}
PAAS_LABELS = {"microsoft.storage/storageaccounts": "Storage account", "microsoft.keyvault/vaults": "Key Vault", "microsoft.sql/servers": "SQL server",
               "microsoft.documentdb/databaseaccounts": "Cosmos DB account", "microsoft.containerregistry/registries": "Container registry"}


def split_rows(rows):
    """(virtual networks, devices) of the kept rows."""
    return [r for r in rows if r.get("t") == "vnet"], [r for r in rows if r.get("t") == "device"]


def search(vnets, text):
    """The networks that match a search: part of a name, resource group, region, subnet name or address range, or an IP address that falls
    inside one of the networks (so "10.2.4.7" finds the network that holds it)."""
    text = str(text or "").strip().lower()
    if not text:
        return vnets
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        address = None
    found = []
    for vnet in vnets:
        if address is not None:
            hit = any(address in net for prefix in vnet.get("prefixes", []) for net in _networks_of(prefix))
        else:
            haystack = [vnet["name"], vnet.get("rg", ""), vnet.get("loc", ""), *vnet.get("prefixes", []), *(s["name"] for s in vnet.get("subnets", [])),
                        *(s["prefix"] for s in vnet.get("subnets", []))]
            hit = any(text in str(item).lower() for item in haystack)
        if hit:
            found.append(vnet)
    return found


def _networks_of(prefix):
    try:
        return [ipaddress.ip_network(str(prefix), strict=False)]
    except ValueError:
        return []


def probe(row):
    """What the dashboard filters ask about a row, in the shape of an inventory row."""
    kind = row.get("kind")
    kind_type = row.get("type") if kind == "paas" else KIND_TYPES.get(kind, "microsoft.network/virtualnetworks")
    return {"id": row["id"], "subscriptionId": row.get("sub", ""), "type": kind_type, "location": row.get("loc", ""), "resourceGroup": row.get("rg", "")}


def worst(severities):
    return min(severities, key=lambda s: SEVERITY_ORDER.get(s, 9), default="")


def findings_by_resource(findings):
    """{resource id (lower): [findings]} of the network findings."""
    result = defaultdict(list)
    for finding in findings:
        if finding.get("ruleId") in NETWORK_RULES:
            result[str(finding.get("resourceId", "")).lower()].append(finding)
    return result


def devices_by_vnet(devices):
    result = defaultdict(list)
    for device in devices:
        if device.get("vnet"):
            result[device["vnet"]].append(device)
    return result


def edges_of(vnets):
    """[{a, b, ok, transit}] one per pair of visible networks that are peered."""
    ids = {str(v["id"]).lower(): v for v in vnets}
    pairs = {}
    for vid, vnet in ids.items():
        for peering in vnet.get("peerings", []):
            remote = peering["remote"]
            if remote not in ids:
                continue
            key = tuple(sorted((vid, remote)))
            entry = pairs.setdefault(key, {"a": key[0], "b": key[1], "ok": True, "transit": False})
            entry["ok"] = entry["ok"] and peering["state"].lower() == "connected" and not peering.get("oneSided")
            entry["transit"] = entry["transit"] or peering.get("gatewayTransit") or peering.get("useRemoteGateways")
    return list(pairs.values())


def _components(ids, edges):
    parent = {i: i for i in ids}

    def find(item):
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for edge in edges:
        parent[find(edge["a"])] = find(edge["b"])
    groups = defaultdict(list)
    for i in ids:
        groups[find(i)].append(i)
    return list(groups.values())


def clip(text, limit):
    text = str(text or "")
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _badges(vnet, devices):
    kinds = Counter()
    for device in devices:
        if device["kind"] == "gateway":
            kinds[device.get("gatewayType") or "Gateway"] += 1
        elif device["kind"] == "pe":
            kinds["Private endpoints"] += 1
        elif device["kind"] in ("firewall", "bastion", "appgw"):
            kinds[KIND_LABELS[device["kind"]]] += 1
    labels = [f"{name} ×{count}" if count > 1 else name for name, count in kinds.items()]
    out, x = [], 12
    for label in labels[:4]:
        width = int(len(label) * 6.4 + 14)
        if x + width > NODE_W - 8:
            break
        out.append({"x": x, "w": width, "text": label})
        x += width + 6
    return out


def layout(vnets, devices, findings_for, selected="", expand=False, limit=MAX_DRAWN):
    """Positions for the topology: connected groups of networks (hubs on top, spokes below), then the networks that are not peered.
    A group with more than `limit` spokes (or more than `limit` networks without peering) draws the ones with the most findings and
    folds the rest into a "+N more networks" node, unless `expand`. The selected network is always drawn.
    Returns {width, height, nodes, edges, bands, folded}; every coordinate is absolute."""
    attached = devices_by_vnet(devices)
    by_id = {str(v["id"]).lower(): v for v in vnets}
    edges = edges_of(vnets)
    degree = Counter()
    for edge in edges:
        degree[edge["a"]] += 1
        degree[edge["b"]] += 1
    core = {vid: any(d["kind"] in ("firewall", "gateway") for d in attached.get(vid, [])) for vid in by_id}
    groups = [g for g in _components(sorted(by_id, key=lambda i: by_id[i]["name"].lower()), edges) if len(g) > 1]
    alone = [i for i in sorted(by_id, key=lambda i: by_id[i]["name"].lower()) if degree[i] == 0]
    groups.sort(key=lambda g: (-len(g), by_id[g[0]]["name"].lower()))

    placed = {}     # vnet id -> (x, y) relative to its group
    onprem, plans, folded, more = {}, [], 0, {}   # more: node key -> {hub, count}
    trunks = {}     # (hub, spoke) -> x of the trunk the spoke hangs from

    def keep(ids, slots):
        """The `slots` networks to draw out of `ids` when they are too many: the selected one, then the most findings; and how many fold."""
        if expand or len(ids) <= limit:
            return ids, 0
        ranked = sorted(ids, key=lambda v: (v != selected, -len(findings_for.get(v, [])), by_id[v]["name"].lower()))
        return ranked[:slots - 1], len(ids) - (slots - 1)

    for group in groups:
        hubs = [v for v in group if core[v] or degree[v] >= 2]
        if not hubs:
            hubs = [max(group, key=lambda v: (degree[v], by_id[v]["name"].lower()))]
        hubs.sort(key=lambda v: (not core[v], -degree[v], by_id[v]["name"].lower()))
        spokes, hidden = keep([v for v in group if v not in hubs], limit)
        if hidden:
            key = f"more:{hubs[0]}"
            spokes = spokes + [key]
            more[key] = {"hub": hubs[0], "count": hidden}
            folded += hidden
        gateways = {h: [d for d in attached.get(h, []) if d["kind"] == "gateway"] for h in hubs}
        has_onprem = any(gateways.values())
        hub_rows = [hubs[i:i + PER_ROW] for i in range(0, len(hubs), PER_ROW)]
        spoke_rows = [spokes[i:i + PER_ROW] for i in range(0, len(spokes), PER_ROW)]
        columns = max([len(r) for r in hub_rows + spoke_rows] or [1])
        width = columns * (NODE_W + GAP_X) - GAP_X
        top = (ONPREM_H + GAP_Y // 2) if has_onprem else 0
        tree = len(spoke_rows) > 1 and len(hub_rows) == 1   # many spokes: they hang from one trunk that runs down the gap between the middle columns
        positions, y = {}, top
        for number, row in enumerate(hub_rows + spoke_rows):
            row_w = len(row) * (NODE_W + GAP_X) - GAP_X
            aligned = tree and number >= len(hub_rows)
            for index, vid in enumerate(row):
                positions[vid] = ((0 if aligned else (width - row_w) // 2) + index * (NODE_W + GAP_X), y)
            y += NODE_H + GAP_Y
        height = y - GAP_Y
        plans.append({"width": width, "height": height, "positions": positions, "onprem": {h: g for h, g in gateways.items() if g}, "title": by_id[hubs[0]]["name"], "count": len(group),
                      "tree": {"hub": hubs[0], "x": width // 2, "spokes": set(spokes)} if tree else None})
    if alone:
        alone, hidden = keep(alone, limit)
        if hidden:
            alone = alone + ["more:alone"]
            more["more:alone"] = {"hub": "", "count": hidden}
            folded += hidden
        per_row = max(min(len(alone), PER_ROW), 1)
        width = per_row * (NODE_W + GAP_X) - GAP_X
        positions = {vid: ((i % per_row) * (NODE_W + GAP_X), (i // per_row) * (NODE_H + GAP_Y // 2)) for i, vid in enumerate(alone)}
        height = ((len(alone) - 1) // per_row + 1) * (NODE_H + GAP_Y // 2) - GAP_Y // 2
        plans.append({"width": width, "height": height, "positions": positions, "onprem": {}, "title": "Not peered", "count": len(alone), "alone": True})

    nodes, lines, bands = [], [], []
    cursor_x = cursor_y = MARGIN
    band_h, total_w = 0, 0
    for plan in plans:
        if cursor_x > MARGIN and cursor_x + plan["width"] > BAND_MAX:
            cursor_x, cursor_y, band_h = MARGIN, cursor_y + band_h + GAP_GROUP, 0
        label_y = cursor_y
        bands.append({"x": cursor_x, "y": label_y + 14, "text": "Not peered" if plan.get("alone") else f"{plan['title']} and {plan['count'] - 1} connected" if plan["count"] > 1 else plan["title"]})
        for vid, (x, y) in plan["positions"].items():
            placed[vid] = (cursor_x + x, cursor_y + LABEL_HEIGHT + y)
        if plan.get("tree"):
            trunks.update({(plan["tree"]["hub"], spoke): cursor_x + plan["tree"]["x"] for spoke in plan["tree"]["spokes"]})
        for hub, gateways in plan["onprem"].items():
            hx, hy = placed[hub]
            kinds = sorted({g.get("gatewayType") or "Gateway" for g in gateways})
            statuses = [c["status"] for g in gateways for c in g.get("connections", []) if c.get("status")]
            onprem[hub] = {"x": hx + (NODE_W - ONPREM_W) // 2, "y": hy - ONPREM_H - GAP_Y // 2, "kinds": kinds, "status": ("Connected" if statuses and all(s.lower() == "connected" for s in statuses) else statuses[0] if statuses else "")}
        band_h = max(band_h, LABEL_HEIGHT + plan["height"])
        cursor_x += plan["width"] + GAP_GROUP
        total_w = max(total_w, cursor_x - GAP_GROUP + MARGIN)
    height = cursor_y + band_h + MARGIN

    for vid, (x, y) in placed.items():
        if vid in more:
            nodes.append({"id": "", "key": vid, "x": x, "y": y, "w": NODE_W, "h": NODE_H, "name": f"+{more[vid]['count']} more network(s)", "full": "More networks", "address": "Show all",
                          "meta": "folded to keep the drawing readable", "badges": [], "severity": "", "findings": 0, "selected": False, "more": True})
            continue
        vnet = by_id[vid]
        found = findings_for.get(vid, [])
        prefixes = vnet.get("prefixes") or []
        nodes.append({"id": vnet["id"], "key": vid, "x": x, "y": y, "w": NODE_W, "h": NODE_H, "name": clip(vnet["name"], 28), "full": vnet["name"],
                      "address": clip(prefixes[0] + (f" +{len(prefixes) - 1}" if len(prefixes) > 1 else ""), 30) if prefixes else "no address space",
                      "meta": f"{vnet.get('loc', '')} · {len(vnet.get('subnets', []))} subnet(s)", "badges": _badges(vnet, attached.get(vid, [])),
                      "severity": worst([f["severity"] for f in found]), "findings": len(found), "selected": vid == selected})
    for hub, spec in onprem.items():
        hx, hy = placed[hub]
        nodes.append({"id": "", "key": f"onprem:{hub}", "x": spec["x"], "y": spec["y"], "w": ONPREM_W, "h": ONPREM_H, "name": "On-premises", "full": "On-premises", "address": " + ".join(spec["kinds"]),
                      "meta": spec["status"], "badges": [], "severity": "", "findings": 0, "selected": False, "onprem": True})
        lines.append({"d": f"M {spec['x'] + ONPREM_W // 2} {spec['y'] + ONPREM_H} L {hx + NODE_W // 2} {hy}", "cls": "onprem", "label": "", "lx": 0, "ly": 0})
    drawn = [e for e in edges if e["a"] in placed and e["b"] in placed]
    drawn += [{"a": more[key]["hub"], "b": key, "ok": True, "transit": False, "more": True} for key in more if more[key]["hub"]]
    for edge in drawn:
        (ax, ay), (bx, by) = placed[edge["a"]], placed[edge["b"]]
        trunk = trunks.get((edge["a"], edge["b"]), trunks.get((edge["b"], edge["a"])))
        if trunk is not None:
            (hx_, hy_), (sx_, sy_) = ((ax, ay), (bx, by)) if (edge["a"], edge["b"]) in trunks else ((bx, by), (ax, ay))
            bus = sy_ - GAP_Y // 2
            d, lx, ly = f"M {trunk} {hy_ + NODE_H} V {bus} H {sx_ + NODE_W // 2} V {sy_}", sx_ + NODE_W // 2, bus - 4
        elif ay == by:
            left, right = sorted(((ax, ay), (bx, by)))
            if right[0] - left[0] <= NODE_W + GAP_X + 1:
                d, lx, ly = f"M {left[0] + NODE_W} {ay + NODE_H // 2} L {right[0]} {by + NODE_H // 2}", (left[0] + NODE_W + right[0]) // 2, ay + NODE_H // 2 - 6
            else:
                cx = (left[0] + right[0] + NODE_W) // 2
                d, lx, ly = f"M {left[0] + NODE_W // 2} {ay} Q {cx} {ay - 46} {right[0] + NODE_W // 2} {by}", cx, ay - 28
        else:
            (ux, uy), (lx_, ly_) = ((ax, ay), (bx, by)) if ay < by else ((bx, by), (ax, ay))
            x1, y1, x2, y2 = ux + NODE_W // 2, uy + NODE_H, lx_ + NODE_W // 2, ly_
            mid = (y1 + y2) // 2
            d, lx, ly = f"M {x1} {y1} C {x1} {mid} {x2} {mid} {x2} {y2}", (x1 + x2) // 2, mid - 4
        label = "gateway transit" if edge["transit"] and len(drawn) <= MAX_EDGE_LABELS else ""
        lines.append({"d": d, "cls": "onprem" if edge.get("more") else "ok" if edge["ok"] else "broken", "label": label, "lx": lx, "ly": ly})
    return {"width": max(total_w, 320), "height": max(height, 120), "nodes": nodes, "edges": lines, "bands": bands, "folded": folded}


def subnet_rows(vnet):
    """The subnets of a network with how full each one is."""
    rows = []
    for subnet in vnet.get("subnets", []):
        capacity = subnet.get("capacity") or 0
        percent = round(100 * subnet["used"] / capacity) if capacity else None
        rows.append({**subnet, "percent": percent, "missingNsg": not subnet["nsg"] and not subnet["reserved"]})
    return rows


def vnet_rows(vnets, findings_for, names):
    """One row per virtual network for the table."""
    rows = []
    for vnet in vnets:
        found = findings_for.get(str(vnet["id"]).lower(), [])
        subnets = subnet_rows(vnet)
        rows.append({"id": vnet["id"], "name": vnet["name"], "sub": names.get(vnet["sub"], vnet["sub"]), "rg": vnet["rg"], "loc": vnet.get("loc", ""),
                     "address": ", ".join(vnet.get("prefixes") or []), "subnets": len(subnets), "noNsg": sum(1 for s in subnets if s["missingNsg"]),
                     "peerings": len(vnet.get("peerings", [])), "dns": ", ".join(vnet.get("dns") or []) or "Azure default", "findings": len(found),
                     "severity": worst([f["severity"] for f in found]), "subnetRows": subnets})
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9), r["name"].lower()))
    return rows


def facts(vnets, devices):
    """Numbers for the header cards, counted over what the filters leave."""
    kinds = Counter(d["kind"] for d in devices)
    subnets = [s for v in vnets for s in v.get("subnets", [])]
    pairs = len(edges_of(vnets))
    pips = [d for d in devices if d["kind"] == "pip"]
    exposed = [d for d in devices if d["kind"] == "nsg" and d.get("internetPorts")]
    return {"vnets": len(vnets), "subnets": len(subnets), "noNsg": sum(1 for s in subnets if not s["nsg"] and not s["reserved"]), "peerings": pairs,
            "firewalls": kinds["firewall"], "gateways": kinds["gateway"], "bastions": kinds["bastion"], "appgws": kinds["appgw"], "privateEndpoints": kinds["pe"],
            "publicIps": len(pips), "publicIpsFree": sum(1 for d in pips if not d.get("attached")), "nsgs": kinds["nsg"], "nsgExposed": len(exposed),
            "paasOpen": kinds["paas"]}


def security_tables(vnets, devices, names):
    """The tables of the Security tab: security groups open to the internet, public IPs, firewalls, gateways of web traffic and services without a private endpoint."""
    vnet_names = {str(v["id"]).lower(): v["name"] for v in vnets}
    nsgs = sorted((d for d in devices if d["kind"] == "nsg" and d.get("internetPorts")), key=lambda d: (("*" not in d["internetPorts"]), d["name"].lower()))
    pips = sorted((d for d in devices if d["kind"] == "pip"), key=lambda d: (bool(d.get("attached")), d["name"].lower()))
    firewalls = [{**d, "vnetName": vnet_names.get(d.get("vnet", ""), "")} for d in sorted((d for d in devices if d["kind"] == "firewall"), key=lambda d: d["name"].lower())]
    appgws = sorted((d for d in devices if d["kind"] == "appgw"), key=lambda d: (d.get("waf", False), d["name"].lower()))
    paas = sorted((d for d in devices if d["kind"] == "paas"), key=lambda d: (PAAS_LABELS.get(d.get("type"), ""), d["name"].lower()))
    for d in paas:
        d["label"] = PAAS_LABELS.get(d.get("type"), d.get("type", ""))
    endpoints = Counter(d.get("targetName") and d.get("group") or "other" for d in devices if d["kind"] == "pe")
    return {"nsgs": nsgs, "pips": pips, "firewalls": firewalls, "appgws": appgws, "paas": paas, "endpointGroups": endpoints.most_common(8), "names": names}


def insight_groups(findings):
    """The network findings grouped by recommendation: [{ruleId, title, severity, pillar, count, resources: [names]}], the worst first."""
    groups = {}
    for finding in findings:
        if finding.get("ruleId") not in NETWORK_RULES:
            continue
        entry = groups.setdefault(finding["ruleId"], {"ruleId": finding["ruleId"], "title": finding["title"], "severity": finding["severity"], "pillar": finding["pillar"],
                                                      "count": 0, "resources": []})
        entry["count"] += 1
        if len(entry["resources"]) < 4:
            entry["resources"].append(finding.get("resourceName") or finding.get("resourceId", ""))
    return sorted(groups.values(), key=lambda g: (SEVERITY_ORDER.get(g["severity"], 9), -g["count"], g["ruleId"]))
