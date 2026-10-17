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
    _, found = lz.classify(tree())
    assert set(found) == {"platform", "connectivity", "identity", "landingzones"}
    status = {n["label"]: n["status"] for n in lz.reference(found, True)["nodes"]}
    assert status["Platform"] == status["Connectivity"] == status["Workload landing zones"] == "present"
    assert status["Sandbox"] == status["Security"] == "missing" and len(status) == 13
    assert lz.reference({}, False)["nodes"][1]["status"] == "missing"  # no hierarchy: no intermediate root either
    rows = {label: (ok, matches) for label, ok, matches in lz.alignment(found)}
    assert rows["Platform"] == (True, ["Platform (name)"]) and rows["Sandbox"] == (False, []) and len(rows) == 11


def node(name, display, subs=(), children=()):
    return {"name": name, "displayName": display, "subscriptions": list(subs), "children": list(children)}


def test_names_in_spanish_and_portuguese_are_recognized_without_accents():
    for text, role in [("Plataforma", "platform"), ("Conectividad", "connectivity"), ("Identidad", "identity"),
                       ("Seguridad", "security"), ("Gestión", "management"), ("Zonas de aterrizaje", "landingzones"),
                       ("Corporativo", "corp"), ("Pruebas", "sandbox"), ("Dado de baja", "decommissioned"),
                       ("Conectividade", "connectivity"), ("Segurança", "security")]:
        assert lz.role_of(text) == role, text
    assert lz.role_of("Ventas") == "" and lz.role_of("Marketing 2025") == ""


def test_policy_assignments_identify_a_group_whose_name_says_nothing():
    tree_ = [node("root", "Tenant Root Group", children=[node("mg-a1", "Grupo A1"), node("mg-b2", "Grupo B2"), node("mg-c3", "Grupo C3")])]
    policies = {"mg-a1": ["Enforce-ALZ-Sandbox"], "mg-b2": ["Enforce-ALZ-Decomm"], "mg-c3": ["Deny-IP-Forwarding", "Deny-Storage-http"]}
    classification, found = lz.classify(tree_, policies)
    assert classification["mg-a1"] == {"role": "sandbox", "how": "policy"}
    assert classification["mg-b2"]["role"] == "decommissioned" and classification["mg-c3"]["role"] == "landingzones"
    assert found["sandbox"] == [{"label": "Grupo A1", "how": "policy"}]


def test_the_contents_of_platform_subscriptions_identify_the_platform_groups():
    tree_ = [node("root", "Root", children=[node("plat", "Plataforma", children=[
        node("g1", "Alfa", ["s1"]), node("g2", "Beta", ["s2"]), node("g3", "Gamma", ["s3"]), node("g4", "Delta", ["s4"])])])]
    signals = {"s1": {"microsoft.network/azurefirewalls": 1}, "s2": {"microsoft.operationalinsights/workspaces": 2},
               "s3": {"microsoft.aad/domainservices": 1}, "s4": {}}
    classification, _ = lz.classify(tree_, {}, signals)
    assert classification["g1"] == {"role": "connectivity", "how": "content"}
    assert classification["g2"]["role"] == "management" and classification["g3"]["role"] == "identity"
    assert classification["g4"]["role"] == ""  # nothing to go on
    # The same contents outside a platform group say nothing: a workload subscription often has a workspace.
    other = [node("root", "Root", children=[node("apps", "Ventas", children=[node("g2", "Beta", ["s2"])])])]
    assert lz.classify(other, {}, signals)[0]["g2"]["role"] == ""


def test_a_manual_mapping_wins_over_everything_else():
    tree_ = [node("root", "Root", children=[node("mg-1", "Platform"), node("mg-2", "Cosa rara")])]
    override = lz.parse_override('{"sandbox": ["Cosa Rara"], "connectivity": "MG-1"}')
    classification, found = lz.classify(tree_, {}, {}, override)
    assert classification["mg-1"] == {"role": "connectivity", "how": "manual"}  # not "platform" by name
    assert classification["mg-2"] == {"role": "sandbox", "how": "manual"} and "platform" not in found


def test_a_bad_mapping_is_ignored():
    assert lz.parse_override("") == {} and lz.parse_override("{not json") == {} and lz.parse_override("[1]") == {}
    assert lz.parse_override('{"nonsense": "x", "sandbox": ["a", " "]}') == {"sandbox": {"a"}}


def test_the_diagram_carries_how_each_group_was_matched():
    classification, _ = lz.classify(tree(), {}, {})
    by_label = {n["label"]: n for n in lz.actual(tree(), [], NAMES, [], classification)["nodes"]}
    assert by_label["Platform"]["how"] == "name" and by_label["Tenant Root Group"]["how"] == ""
