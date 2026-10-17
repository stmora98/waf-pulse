import landing_zone as lz


def group(name, display, parent=None, subs=()):
    return {"name": name, "displayName": display, "parent": parent, "subscriptions": list(subs)}


def test_roles_are_recognized_by_words_not_exact_names():
    assert lz.role_of("Landing Zones") == "landingzones" and lz.role_of("alz-landingzones") == "landingzones"
    assert lz.role_of("Contoso Platform") == "platform" and lz.role_of("Sandboxes") == "sandbox"
    assert lz.role_of("Decommissioned") == "decommissioned" and lz.role_of("Connectivity") == "connectivity"
    assert lz.role_of("Corp") == "corp" and lz.role_of("github-team") == "" and lz.role_of("Tenant Root Group") == ""


def tree():
    return [{"name": "root", "displayName": "Tenant Root Group", "subscriptions": ["s9"], "children": [
        {"name": "p", "displayName": "Platform", "subscriptions": [], "children": [
            {"name": "c", "displayName": "Connectivity", "subscriptions": ["s1", "s2", "s3", "s4", "s5"], "children": []},
            {"name": "i", "displayName": "Identity", "subscriptions": ["s1"], "children": []}]},
        {"name": "l", "displayName": "Landing Zones", "subscriptions": [], "children": []}]}]


NAMES = {f"s{i}": f"Subscription {i}" for i in range(10)}


def test_the_diagram_places_children_under_their_parent_with_connectors():
    diagram = lz.actual(tree(), [], NAMES, [])
    by_label = {n["label"]: n for n in diagram["nodes"]}
    assert set(by_label) == {"Tenant Root Group", "Platform", "Connectivity", "Identity", "Landing Zones"}
    assert by_label["Tenant Root Group"]["y"] < by_label["Platform"]["y"] < by_label["Connectivity"]["y"]
    assert by_label["Platform"]["y"] == by_label["Landing Zones"]["y"]  # same level, same row
    centre = lambda n: n["x"] + n["width"] / 2
    assert min(centre(by_label["Connectivity"]), centre(by_label["Identity"])) < centre(by_label["Platform"]) < max(
        centre(by_label["Connectivity"]), centre(by_label["Identity"]))
    boxes = sorted((n["x"], n["x"] + n["width"]) for n in diagram["nodes"] if n["y"] == by_label["Connectivity"]["y"])
    assert all(a_end <= b_start for (_, a_end), (b_start, _) in zip(boxes, boxes[1:]))  # siblings never overlap
    assert len(diagram["links"]) == 6 and diagram["width"] > 0 and diagram["height"] > by_label["Connectivity"]["y"]


def test_subscriptions_show_as_chips_and_overflow_is_counted():
    by_label = {n["label"]: n for n in lz.actual(tree(), [], NAMES, [])["nodes"]}
    connectivity = by_label["Connectivity"]
    assert [c["label"] for c in connectivity["chips"]] == ["Subscription 1", "Subscription 2", "Subscription 3"]
    assert connectivity["more"]["label"] == "+2 more" and by_label["Identity"]["subscriptions"] == 1
    assert by_label["Platform"]["role"] == "platform" and by_label["Landing Zones"]["role"] == "landingzones"


def test_subscriptions_without_a_group_get_their_own_box():
    diagram = lz.actual([], [], NAMES, [{"id": "s1", "name": "Loose"}])
    assert [n["label"] for n in diagram["nodes"]] == ["No visible management group"]
    assert diagram["nodes"][0]["chips"][0]["label"] == "Loose"
    assert lz.actual([], [], {}, [])["nodes"] == []


def test_the_reference_marks_what_the_tenant_has():
    roles = lz.present_roles(tree())
    assert roles == {"platform", "connectivity", "identity", "landingzones"}
    reference = lz.reference(roles, True)
    status = {n["label"]: n["status"] for n in reference["nodes"]}
    assert status["Platform"] == status["Connectivity"] == status["Workload landing zones"] == "present"
    assert status["Sandbox"] == status["Security"] == "missing" and len(reference["nodes"]) == 13
    assert lz.reference(set(), False)["nodes"][1]["status"] == "missing"  # no hierarchy: no intermediate root either
    found = dict(lz.alignment(roles))
    assert found["Platform"] and not found["Sandbox"] and len(found) == 11
