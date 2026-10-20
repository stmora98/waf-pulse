import json

import pytest

import network_view as nv
from waf_pulse import network, store

SUB = "aaaaaaaa-0000-0000-0000-000000000001"


def vid(name):
    return f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/{name}"


def subnet(i, prefix=None):
    return {"name": f"snet-{i}", "prefix": prefix or f"10.0.{i}.0/24", "nsg": "n", "nsgName": "n", "routeTable": "", "routeTableName": "", "nat": False,
            "delegation": "", "used": 1, "capacity": 251, "reserved": False}


def peer(name, **extra):
    return {"remote": vid(name).lower(), "name": name, "known": True, "state": "Connected", "forwarded": True, "gatewayTransit": True,
            "useRemoteGateways": False, "oneSided": False, **extra}


def vnet(name, prefix, peers=(), subnets=1):
    return {"t": "vnet", "id": vid(name), "name": name, "sub": SUB, "rg": "rg", "loc": "westeurope", "prefixes": [prefix], "dns": [],
            "ddos": False, "subnets": [subnet(i) for i in range(subnets)], "peerings": [peer(p) for p in peers]}


def hub_and_spokes(count):
    names = [f"spoke-{i:03d}" for i in range(count)]
    return [vnet("hub", "10.0.0.0/16", names)] + [vnet(n, f"10.{i + 1}.0.0/16", ["hub"]) for i, n in enumerate(names)]


def boxes(d):
    return [(n["x"], n["y"], n["x"] + n["w"], n["y"] + n["h"]) for n in d["nodes"]]


def test_a_hub_with_100_spokes_folds_into_a_readable_drawing():
    vnets = hub_and_spokes(100)
    findings = {vid("spoke-077").lower(): [{"severity": "high"}], vid("spoke-042").lower(): [{"severity": "low"}, {"severity": "low"}]}
    d = nv.layout(vnets, [], findings)
    names = [n["full"] for n in d["nodes"]]
    assert len(d["nodes"]) == nv.MAX_DRAWN + 1 and d["folded"] == 100 - (nv.MAX_DRAWN - 1)     # the hub, 17 spokes and the "more" box
    assert "hub" in names and "spoke-042" in names and "spoke-077" in names       # the ones with findings stay
    assert sum(1 for n in d["nodes"] if n.get("more")) == 1
    assert next(n for n in d["nodes"] if n.get("more"))["name"] == f"+{d['folded']} more network(s)"
    assert d["height"] < 1800 and len(d["edges"]) == nv.MAX_DRAWN
    assert not any(e["label"] for e in d["edges"])                                   # 18 labels would hide the drawing
    for i, a in enumerate(boxes(d)):
        for b in boxes(d)[i + 1:]:
            assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1]


def test_expand_draws_everything_and_the_selected_network_is_never_folded():
    vnets = hub_and_spokes(100)
    full = nv.layout(vnets, [], {}, expand=True)
    assert len(full["nodes"]) == 101 and full["folded"] == 0 and len(full["edges"]) == 100
    chosen = vid("spoke-099").lower()
    d = nv.layout(vnets, [], {}, selected=chosen)
    assert any(n["key"] == chosen and n["selected"] for n in d["nodes"])


def test_many_unpeered_networks_fold_too():
    vnets = [vnet(f"alone-{i:03d}", f"10.{i}.0.0/16") for i in range(60)]
    d = nv.layout(vnets, [], {})
    assert len(d["nodes"]) == nv.MAX_DRAWN and d["folded"] == 60 - (nv.MAX_DRAWN - 1) and d["edges"] == []


def test_few_networks_are_not_folded_and_keep_their_labels():
    d = nv.layout(hub_and_spokes(5), [], {})
    assert d["folded"] == 0 and len(d["nodes"]) == 6 and all(e["label"] == "gateway transit" for e in d["edges"])


def test_search_by_name_group_subnet_and_ip():
    vnets = hub_and_spokes(20)
    assert [v["name"] for v in nv.search(vnets, "SPOKE-01")] == [f"spoke-01{i}" for i in range(10)]
    assert len(nv.search(vnets, "westeurope")) == 21 and nv.search(vnets, "") == vnets
    assert [v["name"] for v in nv.search(vnets, "snet-0")] == [v["name"] for v in vnets]
    assert [v["name"] for v in nv.search(vnets, "10.3.44.9")] == ["spoke-002"]
    assert nv.search(vnets, "192.168.1.1") == [] and nv.search(vnets, "no such thing") == []


def test_rows_are_split_by_size_so_a_document_stays_under_the_cosmos_limit():
    rows = [{"name": f"vnet-{i}", "blob": "x" * 60_000} for i in range(40)]      # 2.4 MB in total
    groups = store.split_rows(rows, chunk=150)
    assert sum(len(g) for g in groups) == 40 and len(groups) >= 3
    assert all(len(json.dumps(g)) < store.MAX_DOCUMENT_BYTES + 100 for g in groups)
    assert [r["name"] for g in groups for r in g] == [r["name"] for r in rows]       # order kept
    assert store.split_rows([], 150) == [[]]                                           # an empty list still writes one document
    assert [len(g) for g in store.split_rows([{"a": 1}] * 400, chunk=150)] == [150, 150, 100]
    assert len(store.split_rows([{"t": "é" * 400_000}] * 3, 150)) == 3                  # bytes, not characters


def test_save_rows_writes_one_document_per_group(monkeypatch):
    saved = []
    monkeypatch.setattr(store, "_save_run_document", lambda run, kind, key, payload: saved.append((kind, key, len(payload["rows"]))))
    store.save_rows("r1", "netrows", [{"blob": "x" * 60_000}] * 40, chunk=150)
    assert len(saved) >= 3 and [s[1] for s in saved] == [f"netrows:{i}" for i in range(len(saved))] and sum(s[2] for s in saved) == 40


def raw_for(devices_count, pes=0):
    pip = [{"id": f"/s/{SUB}/pip/p{i}", "name": f"p{i}", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Standard", "ip": "1.1.1.1", "attached": "", "ddos": ""} for i in range(devices_count)]
    raw = {name: [] for name in network.QUERIES}
    raw["pips"] = pip
    return raw


def test_the_run_says_when_the_page_keeps_less_than_the_tenant_has():
    _, _, summary, rows = network.evaluate("r1", raw_for(10))
    assert summary["truncated"] is False
    _, _, summary, rows = network.evaluate("r1", raw_for(network.MAX_KIND_ROWS + 5))
    assert summary["truncated"] is True and len(rows) == network.MAX_KIND_ROWS


def test_when_devices_are_cut_the_edge_and_the_exposure_stay(monkeypatch):
    monkeypatch.setitem(network.MAX_ROWS, "device", 6)
    raw = raw_for(0)
    raw["dnszones"] = [{"id": f"/z{i}", "name": f"z{i}", "subscriptionId": SUB, "resourceGroup": "rg", "location": "g", "links": 1, "records": 1} for i in range(5)]
    raw["firewalls"] = [{"id": "/fw", "name": "fw", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "sku": "Std", "threatIntel": "Alert", "policy": "", "subnet": "", "privateIp": "", "hub": ""}]
    raw["paas"] = [{"id": f"/p{i}", "name": f"p{i}", "type": "Microsoft.Storage/storageAccounts", "subscriptionId": SUB, "resourceGroup": "rg", "location": "x", "access": "Enabled", "acl": "Allow", "filtered": None, "endpoints": 0} for i in range(3)]
    _, _, summary, rows = network.evaluate("r1", raw)
    kinds = [r["kind"] for r in rows]
    assert summary["truncated"] is True and kinds.count("firewall") == 1 and kinds.count("paas") == 3 and kinds.count("dns") == 2


def test_spokes_hang_from_a_trunk_that_does_not_cross_other_networks():
    import re
    d = nv.layout(hub_and_spokes(30), [], {}, expand=True)
    hub = next(n for n in d["nodes"] if n["full"] == "hub")
    trunks = set()
    for edge in d["edges"]:
        m = re.fullmatch(r"M (\d+) (\d+) V (\d+) H (\d+) V (\d+)", edge["d"])
        assert m, edge["d"]
        x, top, bus, target, bottom = map(int, m.groups())
        trunks.add(x)
        assert top == hub["y"] + hub["h"] and top < bus < bottom
        for n in d["nodes"]:     # the vertical and horizontal runs stay out of every node
            if n is hub:
                continue
            inside_x, inside_y = n["x"] < x < n["x"] + n["w"], n["y"] < bus < n["y"] + n["h"]
            assert not (inside_x and top < n["y"] + n["h"] and n["y"] < bottom) and not inside_y
    assert len(trunks) == 1 and abs(trunks.pop() - (hub["x"] + hub["w"] // 2)) <= 1
