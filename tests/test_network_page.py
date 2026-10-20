import pytest

import app as dashboard_app
import data
import network_view

SUB_A, SUB_B = "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"


def vid(sub, name):
    return f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/{name}"


def vnet(name, sub=SUB_A, prefix="10.0.0.0/16", peers=(), subnets=None):
    return {"t": "vnet", "id": vid(sub, name), "name": name, "sub": sub, "rg": "rg", "loc": "westeurope", "prefixes": [prefix], "dns": [], "ddos": False,
            "subnets": subnets if subnets is not None else [{"name": "app", "prefix": "10.0.0.0/24", "nsg": "", "nsgName": "", "routeTable": "", "routeTableName": "", "nat": False,
                                                              "delegation": "", "used": 10, "capacity": 251, "reserved": False}],
            "peerings": [{"remote": vid(sub, p).lower(), "name": p, "known": True, "state": "Connected", "forwarded": True, "gatewayTransit": False, "useRemoteGateways": False,
                          "oneSided": False} for p in peers]}


def device(kind, name, v=None, **extra):
    return {"t": "device", "kind": kind, "id": f"/subscriptions/{SUB_A}/resourceGroups/rg/providers/x/{kind}/{name}", "name": name, "sub": SUB_A, "rg": "rg", "loc": "westeurope",
            "vnet": vid(SUB_A, v).lower() if v else "", **extra}


HUB = vnet("hub", peers=("s1", "s2"), prefix="10.0.0.0/16")
HUB["peerings"].append({**HUB["peerings"][0], "remote": vid(SUB_B, "s3").lower(), "name": "s3"})
ROWS = [HUB, vnet("s1", prefix="10.1.0.0/16", peers=("hub",)), vnet("s2", prefix="10.2.0.0/16", peers=("hub",)), {**vnet("s3", sub=SUB_B, prefix="10.3.0.0/16"), "peerings": [{**HUB["peerings"][0], "remote": HUB["id"].lower(), "name": "hub"}]},
        vnet("lonely", prefix="10.9.0.0/16"),
        device("firewall", "fw", "hub", sku="Premium", threatIntel="Alert", policy=True, privateIp="10.0.3.4", managed=False),
        device("gateway", "gw", "hub", gatewayType="Vpn", sku="VpnGw1AZ", connections=[{"kind": "IPsec", "status": "Connected"}]),
        device("nsg", "open-nsg", subnets=1, nics=0, rules=4, internetPorts=["*", "22"]), device("nsg", "closed-nsg", subnets=1, nics=2, rules=1, internetPorts=[]),
        device("pip", "pip1", sku="Basic", ip="1.2.3.4", attached="", attachedName=""), device("pe", "pe1", "s1", targetName="stor", group="blob", target="x"),
        {**device("paas", "stopen"), "type": "microsoft.storage/storageaccounts"}]
FINDING = {"id": "1", "ruleId": "SEC-NET-001", "severity": "medium", "pillar": "Security", "title": "Virtual network has subnets without a network security group", "source": "network",
           "resourceId": vid(SUB_A, "s1"), "resourceName": "s1", "subscriptionId": SUB_A}


def test_layout_puts_hub_above_spokes_and_lists_unpeered_apart():
    vnets, devices = network_view.split_rows(ROWS)
    d = network_view.layout(vnets, devices, network_view.findings_by_resource([FINDING]))
    nodes = {n["full"]: n for n in d["nodes"] if not n.get("onprem")}
    assert set(nodes) == {"hub", "s1", "s2", "s3", "lonely"}
    assert all(nodes["hub"]["y"] < nodes[s]["y"] for s in ("s1", "s2", "s3"))
    assert nodes["lonely"]["x"] > nodes["s3"]["x"] or nodes["lonely"]["y"] > nodes["s1"]["y"]
    assert len([e for e in d["edges"] if e["cls"] == "ok"]) == 3
    assert any(n.get("onprem") and n["address"] == "Vpn" for n in d["nodes"])
    assert nodes["s1"]["severity"] == "medium" and nodes["s1"]["findings"] == 1
    assert [b["text"] for b in d["bands"]] == ["hub and 3 connected", "Not peered"]
    badges = {b["text"] for b in nodes["hub"]["badges"]}
    assert "Firewall" in badges and "Vpn" in badges
    assert any(b["text"] == "Private endpoints" for b in nodes["s1"]["badges"])


def test_layout_has_no_overlapping_nodes_and_stays_inside_the_canvas():
    vnets = [vnet(f"n{i}", prefix=f"10.{i}.0.0/16", peers=("n0",) if i else tuple(f"n{j}" for j in range(1, 13))) for i in range(13)]
    d = network_view.layout(vnets, [], {})
    boxes = [(n["x"], n["y"], n["x"] + n["w"], n["y"] + n["h"]) for n in d["nodes"]]
    for i, a in enumerate(boxes):
        assert a[2] <= d["width"] and a[3] <= d["height"] and a[0] >= 0 and a[1] >= 0
        for b in boxes[i + 1:]:
            assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1]


def test_broken_peering_is_drawn_dashed_and_transit_is_labelled():
    a, b = vnet("a", peers=("b",)), vnet("b", prefix="10.1.0.0/16")
    a["peerings"][0]["gatewayTransit"] = True
    a["peerings"][0]["oneSided"] = True
    d = network_view.layout([a, b], [], {})
    assert d["edges"][0]["cls"] == "broken" and d["edges"][0]["label"] == "gateway transit"
    b["peerings"] = [{**a["peerings"][0], "remote": a["id"].lower(), "oneSided": False}]
    a["peerings"][0]["oneSided"] = False
    assert network_view.layout([a, b], [], {})["edges"][0]["cls"] == "ok"


def test_empty_and_filtered_layouts():
    d = network_view.layout([], [], {})
    assert d["nodes"] == [] and d["width"] >= 320
    only = network_view.layout([vnet("solo")], [], {})
    assert len(only["nodes"]) == 1 and only["edges"] == []


def test_facts_and_tables():
    vnets, devices = network_view.split_rows(ROWS)
    facts = network_view.facts(vnets, devices)
    assert facts["vnets"] == 5 and facts["peerings"] == 3 and facts["noNsg"] == 5 and facts["nsgExposed"] == 1 and facts["publicIpsFree"] == 1 and facts["paasOpen"] == 1
    tables = network_view.security_tables(vnets, devices, {})
    assert [d["name"] for d in tables["nsgs"]] == ["open-nsg"] and tables["paas"][0]["label"] == "Storage account"
    assert network_view.vnet_rows(vnets, network_view.findings_by_resource([FINDING]), {SUB_A: "Prod"})[0]["name"] == "s1"
    groups = network_view.insight_groups([FINDING, {**FINDING, "id": "2", "resourceName": "s2"}, {**FINDING, "ruleId": "REL-VM-001"}])
    assert len(groups) == 1 and groups[0]["count"] == 2


@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, network=True, rows=ROWS, findings=(FINDING,)):
    summary = {"runId": "r1", "subscriptions": [{"id": SUB_A, "name": "Prod"}, {"id": SUB_B, "name": "Dev"}]}
    if network:
        summary["network"] = {"vnets": 5}
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: summary)
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: list(findings))
    monkeypatch.setattr(data, "resources", lambda run_id: ([], False))
    monkeypatch.setattr(data, "get_setting", lambda name: None)
    kinds = {"netrows": rows, "rulestats": []}
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: kinds.get(kind, []))


def test_topology_page_draws_nodes_and_details(client, monkeypatch):
    serve(monkeypatch)
    html = client.get("/network").get_data(as_text=True)
    assert "<svg class=\"net\"" in html and "hub and 3 connected" in html and "Not peered" in html and "On-premises" in html
    assert 'aria-current="page">Topology' in html and 'href="/network"' in html
    detail = client.get("/network?vnet=" + vid(SUB_A, "s1")).get_data(as_text=True)
    assert 'id="detail"' in detail and "Subnets" in detail and "Peerings" in detail and "Virtual network has subnets without" in detail and "stor" in detail


def test_networks_security_and_insights_tabs(client, monkeypatch):
    serve(monkeypatch)
    assert "lonely" in client.get("/network?tab=networks").get_data(as_text=True)
    security = client.get("/network?tab=security").get_data(as_text=True)
    assert "open-nsg" in security and "any port" in security and "closed-nsg" not in security and "Basic (retired)" in security and "Storage account" in security
    insights = client.get("/network?tab=insights").get_data(as_text=True)
    assert "SEC-NET-001" in insights and "chip medium" in insights


def test_subscription_filter_applies(client, monkeypatch):
    serve(monkeypatch)
    client.set_cookie("waf_scope", '[{"f":"sub","op":"eq","v":["%s"]}]' % SUB_B)
    html = client.get("/network?tab=networks").get_data(as_text=True)
    assert "s3" in html and "lonely" not in html and "hub" not in html


def test_page_without_network_data_and_names_are_escaped(client, monkeypatch):
    serve(monkeypatch, network=False)
    assert "no network data in this run yet" in client.get("/network").get_data(as_text=True)
    evil = vnet("<b>x</b>")
    serve(monkeypatch, rows=[evil])
    html = client.get("/network").get_data(as_text=True)
    assert "<b>x</b>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html or "&lt;b&gt;" in html


def test_nav_and_data_source_row(client, monkeypatch):
    serve(monkeypatch)
    assert 'href="/network"' in client.get("/network").get_data(as_text=True)
    sources = dashboard_app._data_sources({"network": {"vnets": 1}, "errors": [{"ruleId": "network-pes", "error": "x"}], "sources": {}})
    assert next(s for s in sources if s["name"] == "Network topology")["status"] == "partial"
