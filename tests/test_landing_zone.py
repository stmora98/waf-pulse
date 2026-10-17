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


# --- the editable design ------------------------------------------------------------------------------------

def sub(name, link=""):
    return {"id": name.lower().replace(" ", "-"), "label": name, "kind": "sub", "role": "", "link": link, "children": []}


def group(name, children=(), link="", role=""):
    return {"id": name.lower().replace(" ", "-"), "label": name, "kind": "mg", "role": role, "link": link, "children": list(children)}


def design(*children):
    return {"id": "root", "label": "Tenant root group", "kind": "root", "role": "", "link": "", "children": list(children)}


def test_the_default_design_is_the_reference_architecture():
    base = lz.default_design()
    flat = [node["label"] for node, _ in lz.design_nodes(base)]
    assert flat[0] == "Tenant root group" and len(flat) == 13 and "Sandbox" in flat and "Internal (Corp)" in flat
    assert base["kind"] == "root" and all(n["kind"] == "mg" for n, p in lz.design_nodes(base) if p)
    assert lz.sanitize_design(base) == (base, [])  # what is shown is valid
    platform = next(n for n, _ in lz.design_nodes(base) if n["id"] == "platform")
    assert platform["role"] == "platform" and [c["id"] for c in platform["children"]] == ["security", "management", "identity", "connectivity"]


def test_a_box_can_be_a_subscription_and_a_group_can_gain_levels_and_subscriptions():
    mine = design(group("Contoso", [group("Platform", [group("Hub", [group("Spoke A", [sub("Spoke A prod"), sub("Spoke A dev")])])]),
                                    sub("Shared services")]))
    cleaned, errors = lz.sanitize_design(mine)
    assert errors == [] and cleaned == mine
    kinds = [(n["label"], n["kind"]) for n, _ in lz.design_nodes(cleaned)]
    assert ("Shared services", "sub") in kinds and ("Spoke A", "mg") in kinds
    diagram, facts, counts = lz.design_diagram(cleaned, {}, True)
    assert {n["label"]: n["kind"] for n in diagram["nodes"]}["Spoke A prod"] == "sub" and counts["subscriptions"] == 3
    by_level = {}
    for n in diagram["nodes"]:
        by_level.setdefault(n["y"], []).append(n["label"])
    assert len(by_level) == 6  # root, Contoso, Platform and the subscription, Hub, Spoke A, its subscriptions


def test_a_subscription_cannot_have_boxes_below_it_and_the_root_cannot_change():
    bad = design(group("A", [{**sub("S"), "children": [group("B")]}]))
    assert lz.sanitize_design(bad)[0] is None and "cannot have boxes below" in lz.sanitize_design(bad)[1][0]
    assert lz.sanitize_design({**design(), "kind": "mg"})[0] is None  # the root cannot become a group or a subscription
    assert lz.sanitize_design({**design(), "kind": "sub"})[0] is None
    assert lz.sanitize_design({**design(), "id": "other"})[0] is None
    assert lz.sanitize_design("text")[0] is None and lz.sanitize_design(None)[1] == ["The diagram needs its root."]


def test_the_design_is_limited_in_size_depth_names_and_identifiers():
    deep = design()
    cursor = deep
    for level in range(10):
        child = group(f"L{level}")
        cursor["children"].append(child)
        cursor = child
    assert "at most 8 levels" in lz.sanitize_design(deep)[1][0]
    wide = design(*[group(f"G{i}") for i in range(151)])
    assert "at most 150 boxes" in lz.sanitize_design(wide)[1][0]
    assert lz.sanitize_design(design(group("A"), group("A")))[0] is None  # the same identifier twice
    assert lz.sanitize_design(design({**group("A"), "id": "bad id!"}))[0] is None
    assert lz.sanitize_design(design({**group("A"), "label": "  "}))[0] is None
    long = lz.sanitize_design(design({**group("A"), "label": "x" * 200}))[0]
    assert len(long["children"][0]["label"]) == 60
    odd = lz.sanitize_design(design({**group("A"), "kind": "folder"}))
    assert odd[0] is None and "unknown type" in odd[1][0]
    assert lz.sanitize_design(design({**group("A"), "role": "nonsense"}))[0]["children"][0]["role"] == ""


def test_a_link_must_be_of_the_right_kind_and_exist_in_the_tenant():
    groups, subs = {"mg-hub", "hub"}, {"hub sub", "s1"}
    ok = design(group("Hub", link="MG-Hub"), sub("Hub sub", link="Hub Sub"))
    assert lz.sanitize_design(ok, groups, subs)[1] == []
    wrong_group = lz.sanitize_design(design(group("Hub", link="Hub Sub")), groups, subs)
    assert wrong_group[0] is None and "Hub Sub is not a management group of your tenant" in wrong_group[1][0]
    wrong_sub = lz.sanitize_design(design(sub("S", link="mg-hub")), groups, subs)
    assert wrong_sub[0] is None and "mg-hub is not a subscription of your tenant" in wrong_sub[1][0]
    assert lz.sanitize_design(design(group("Hub", link="Anything")))[1] == []  # tenant unknown: nothing to check against
    assert lz.sanitize_design({**design(), "link": "x"}, groups, subs)[0]["link"] == ""  # the root is not linked


def test_boxes_are_found_by_their_link_by_automatic_matching_or_not_at_all():
    found = {"platform": [{"label": "Contoso Platform", "how": "name"}]}
    mine = design(group("Platform", role="platform"), group("Sandbox", role="sandbox"), group("Mine", link="Real MG"),
                  group("Ghost", link="Gone"), sub("Hub", link="Hub Sub"), sub("Empty"), group("Alone"))
    diagram, facts, counts = lz.design_diagram(mine, found, True, {"real mg"}, {"hub sub"})
    assert facts["platform"] == {"status": "present", "matches": ["Contoso Platform (name)"], "how": "name"}
    assert facts["sandbox"]["status"] == "missing" and facts["alone"]["status"] == "missing"
    assert facts["mine"] == {"status": "present", "matches": ["Real MG (manual)"], "how": "manual"}
    assert facts["ghost"]["status"] == "missing"  # linked to something that no longer exists
    assert facts["hub"]["status"] == "present" and facts["empty"]["status"] == "missing"
    assert counts == {"groups": 5, "groupsFound": 2, "subscriptions": 2, "subscriptionsLinked": 1}
    labels = {n["node_id"]: n["label"] for n in diagram["nodes"]}
    assert labels["hub"] == "Hub Sub"  # a linked subscription shows the real name


def test_the_intermediate_root_follows_whether_a_hierarchy_exists():
    base = lz.default_design()
    assert lz.design_diagram(base, {}, True)[1]["intermediate"]["status"] == "present"
    assert lz.design_diagram(base, {}, False)[1]["intermediate"]["status"] == "missing"


def test_subscription_boxes_are_small_leaf_boxes_with_their_own_geometry():
    nodes = {n["node_id"]: n for n in lz.design_diagram(design(group("A", [sub("S1"), sub("S2")])), {}, True)[0]["nodes"]}
    assert nodes["s1"]["height"] < nodes["a"]["height"] and nodes["s1"]["kind"] == "sub" and nodes["s1"]["width"] == lz.SUB_WIDTH
    assert nodes["s1"]["x"] + nodes["s1"]["width"] <= nodes["s2"]["x"]  # siblings do not overlap
    assert nodes["root"]["kind"] == "root" and nodes["root"]["status"] == ""
