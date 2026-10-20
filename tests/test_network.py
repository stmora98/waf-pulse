from waf_pulse import network

SUB = "11111111-1111-1111-1111-111111111111"
BASE = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network"


def vid(name):
    return f"{BASE}/virtualNetworks/{name}"


def vnet(name, prefix):
    return {"id": vid(name), "name": name, "subscriptionId": SUB, "resourceGroup": "rg", "location": "westeurope", "prefixes": [prefix], "dns": [], "ddos": False, "ddosPlan": ""}


def subnet(v, name, prefix="10.0.0.0/24", nsg="", rt="", delegation="", used=0):
    return {"vnet": vid(v), "name": name, "prefix": prefix, "nsg": nsg, "routeTable": rt, "nat": "", "delegation": delegation, "used": used, "endpoints": 0, "serviceEndpoints": 0}


def peering(v, remote, state="Connected"):
    return {"vnet": vid(v), "remote": vid(remote), "state": state, "forwarded": True, "gatewayTransit": False, "useRemoteGateways": False}


def run(raw):
    full = {name: [] for name in network.QUERIES}
    full.update(raw)
    return network.evaluate("r1", full)


def rules(findings):
    return {(f["ruleId"], f["resourceName"]) for f in findings}


def test_subnet_without_nsg_ignores_reserved_subnets():
    findings, stats, _, _ = run({"vnets": [vnet("a", "10.0.0.0/16"), vnet("b", "10.1.0.0/16")],
                                 "subnets": [subnet("a", "web", nsg="nsg1"), subnet("a", "GatewaySubnet"), subnet("b", "app"), subnet("b", "AzureFirewallSubnet")]})
    assert {x for x in rules(findings) if x[0] == "SEC-NET-001"} == {("SEC-NET-001", "b")}
    entry = next(s for s in stats if s["ruleId"] == "SEC-NET-001")
    assert (entry["affected"], entry["applicable"], entry["source"], entry["pillar"]) == (1, 2, "network", "Security")


def test_peering_one_sided_and_disconnected():
    findings, _, summary, rows = run({"vnets": [vnet("a", "10.0.0.0/16"), vnet("b", "10.1.0.0/16"), vnet("c", "10.2.0.0/16")],
                                      "peerings": [peering("a", "b"), peering("c", "a", "Disconnected"), peering("a", "c", "Disconnected")]})
    assert {f["resourceName"] for f in findings if f["ruleId"] == "REL-NET-002"} == {"a", "b", "c"}
    a = next(r for r in rows if r["t"] == "vnet" and r["name"] == "a")
    assert next(p for p in a["peerings"] if p["name"] == "b")["oneSided"] is True
    assert summary["peerings"] == 1 or summary["peerings"] == 2


def test_peering_to_a_network_outside_the_scan_is_not_an_issue():
    findings, _, _, _ = run({"vnets": [vnet("a", "10.0.0.0/16")], "peerings": [{**peering("a", "x"), "remote": "/subscriptions/other/resourceGroups/r/providers/Microsoft.Network/virtualNetworks/x"}]})
    assert not [f for f in findings if f["ruleId"] == "REL-NET-002"]


def test_overlap_only_inside_a_connected_group():
    findings, _, _, _ = run({"vnets": [vnet("a", "10.0.0.0/16"), vnet("b", "10.0.128.0/17"), vnet("c", "10.0.0.0/16"), vnet("d", "192.168.0.0/16")],
                             "peerings": [peering("a", "b"), peering("b", "a"), peering("c", "d"), peering("d", "c")]})
    assert {f["resourceName"] for f in findings if f["ruleId"] == "REL-NET-003"} == {"a", "b"}


def test_firewall_default_route():
    rt_ok = {"id": f"{BASE}/routeTables/rt", "name": "rt", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "subnets": 1,
             "routes": [{"properties": {"addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance", "nextHopIpAddress": "10.0.3.4"}}]}
    rt_other = {**rt_ok, "id": f"{BASE}/routeTables/rt2", "name": "rt2", "routes": [{"properties": {"addressPrefix": "10.9.0.0/16", "nextHopType": "VnetLocal"}}]}
    firewall = {"id": f"{BASE}/azureFirewalls/fw", "name": "fw", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Standard", "threatIntel": "Alert",
                "policy": "", "subnet": f"{vid('hub')}/subnets/AzureFirewallSubnet", "privateIp": "10.0.3.4", "hub": ""}
    findings, stats, _, rows = run({
        "vnets": [vnet("hub", "10.0.0.0/16"), vnet("good", "10.1.0.0/16"), vnet("bad", "10.2.0.0/16"), vnet("far", "10.3.0.0/16"), vnet("sqlmi", "10.4.0.0/16")],
        "subnets": [subnet("hub", "AzureFirewallSubnet"), subnet("good", "s", nsg="n", rt=rt_ok["id"]), subnet("bad", "s", nsg="n", rt=rt_other["id"]),
                    subnet("far", "s", nsg="n"), subnet("sqlmi", "mi", nsg="n", delegation="Microsoft.Sql/managedInstances")],
        "peerings": [peering("hub", n) for n in ("good", "bad", "sqlmi")] + [peering(n, "hub") for n in ("good", "bad", "sqlmi")],
        "firewalls": [firewall], "routetables": [rt_ok, rt_other]})
    assert {f["resourceName"] for f in findings if f["ruleId"] == "SEC-NET-002"} == {"bad"}  # hub only has the reserved subnet, far is not behind the firewall
    entry = next(s for s in stats if s["ruleId"] == "SEC-NET-002")
    assert entry["applicable"] == 2 and entry["affected"] == 1
    assert next(r for r in rows if r.get("kind") == "firewall")["vnet"] == vid("hub").lower()


def test_without_firewall_or_route_tables_the_default_route_rule_is_skipped():
    _, stats, _, _ = run({"vnets": [vnet("a", "10.0.0.0/16")], "subnets": [subnet("a", "s")]})
    assert not [s for s in stats if s["ruleId"] == "SEC-NET-002"]


def test_flow_logs_cover_a_network_directly_or_through_a_subnet_nsg():
    nsg = f"{BASE}/networkSecurityGroups/n1"
    findings, _, _, _ = run({"vnets": [vnet("a", "10.0.0.0/16"), vnet("b", "10.1.0.0/16"), vnet("c", "10.2.0.0/16"), vnet("d", "10.3.0.0/16")],
                             "subnets": [subnet("b", "s", nsg=nsg), subnet("d", "s")],
                             "flowlogs": [{"id": "f1", "target": vid("a").upper(), "enabled": True}, {"id": "f2", "target": nsg, "enabled": True}, {"id": "f3", "target": vid("c"), "enabled": False}]})
    assert {f["resourceName"] for f in findings if f["ruleId"] == "OPS-NET-004"} == {"c", "d"}


def test_failed_query_skips_its_rules():
    _, stats, _, _ = run({"vnets": [vnet("a", "10.0.0.0/16")], "flowlogs": None})
    assert not [s for s in stats if s["ruleId"] == "OPS-NET-004"]


def test_devices_rules():
    findings, _, summary, rows = run({
        "appgws": [{"id": f"{BASE}/applicationGateways/ag1", "name": "ag1", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Standard_v2", "tier": "Standard_v2", "waf": False, "public": True, "subnet": ""},
                   {"id": f"{BASE}/applicationGateways/ag2", "name": "ag2", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "WAF_v2", "tier": "WAF_v2", "waf": True, "public": True, "subnet": ""},
                   {"id": f"{BASE}/applicationGateways/ag3", "name": "ag3", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Standard_v2", "tier": "Standard_v2", "waf": False, "public": False, "subnet": ""}],
        "pips": [{"id": f"{BASE}/publicIPAddresses/p1", "name": "p1", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Basic", "ip": "1.1.1.1", "attached": f"{BASE}/networkInterfaces/nic1/ipConfigurations/ipconfig1", "ddos": ""}],
        "lbs": [{"id": f"{BASE}/loadBalancers/lb1", "name": "lb1", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Basic", "public": False}],
        "gateways": [{"id": f"{BASE}/virtualNetworkGateways/g1", "name": "g1", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "gatewayType": "Vpn", "vpnType": "RouteBased", "sku": "VpnGw1", "activeActive": False, "bgp": False, "subnet": ""},
                     {"id": f"{BASE}/virtualNetworkGateways/g2", "name": "g2", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "gatewayType": "Vpn", "vpnType": "RouteBased", "sku": "VpnGw2AZ", "activeActive": True, "bgp": True, "subnet": ""}],
        "firewalls": [{"id": f"{BASE}/azureFirewalls/f1", "name": "f1", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Standard", "threatIntel": "Off", "policy": "", "subnet": "", "privateIp": "", "hub": ""},
                      {"id": f"{BASE}/azureFirewalls/f2", "name": "f2", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Standard", "threatIntel": "Off", "policy": "/p", "subnet": "", "privateIp": "", "hub": ""}],
        "dnszones": [{"id": f"{BASE}/privateDnsZones/z1", "name": "z1", "subscriptionId": SUB, "resourceGroup": "rg", "location": "global", "links": 0, "records": 2},
                     {"id": f"{BASE}/privateDnsZones/z2", "name": "z2", "subscriptionId": SUB, "resourceGroup": "rg", "location": "global", "links": 1, "records": 2}]})
    assert rules(findings) == {("SEC-NET-003", "ag1"), ("REL-NET-004", "p1"), ("REL-NET-004", "lb1"), ("REL-NET-005", "g1"), ("SEC-NET-004", "f1"), ("OPS-NET-005", "z1")}
    pip = next(r for r in rows if r.get("kind") == "pip")
    assert pip["attachedName"] == "nic1"
    assert summary["firewalls"] == 2 and summary["publicIps"] == 1 and summary["findings"] == 6


def test_nsg_internet_ports_and_public_paas_rows():
    nsg = f"{BASE}/networkSecurityGroups/n1"
    _, _, _, rows = run({"nsgs": [{"id": nsg, "name": "n1", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "subnets": 1, "nics": 0, "rules": 3}],
                         "nsgrules": [{"nsg": nsg, "rule": "ssh", "port": "22"}, {"nsg": nsg, "rule": "any", "port": "*"}, {"nsg": nsg, "rule": "ssh2", "port": "22"}],
                         "paas": [{"id": "/subscriptions/x/storage/open", "name": "open", "type": "Microsoft.Storage/storageAccounts", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "access": "Enabled", "acl": "Allow", "filtered": None, "endpoints": 0},
                                  {"id": "/subscriptions/x/storage/closed", "name": "closed", "type": "Microsoft.Storage/storageAccounts", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "access": "Enabled", "acl": "Deny", "filtered": None, "endpoints": 0},
                                  {"id": "/subscriptions/x/storage/pe", "name": "pe", "type": "Microsoft.Storage/storageAccounts", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "access": "Enabled", "acl": "Allow", "filtered": None, "endpoints": 1}]})
    assert next(r for r in rows if r.get("kind") == "nsg")["internetPorts"] == ["*", "22"]
    assert [r["name"] for r in rows if r.get("kind") == "paas"] == ["open"]


def test_kql_alias_names_do_not_use_the_reserved_kind_column():
    for name, query in network.QUERIES.items():
        assert " kind = " not in query and "kind = tostring" not in query, name
