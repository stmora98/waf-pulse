"""Landing zone diagram of the management group hierarchy, laid out as a top-down tree with elbow connectors.

A management group is matched to a role of the Azure landing zone reference architecture in this order: a manual
mapping from the deployment configuration, its name (in English, Spanish or Portuguese), the policy assignments made
on it (the reference architecture assigns well known ones) and what its subscriptions contain. Pure functions: the
template draws the returned geometry as SVG, so no script or inline style is needed.
"""
import json
import os
import re
import unicodedata

NODE_HEIGHT = 34
LEVEL_GAP = 46
CHIP_HEIGHT = 22
CHIP_GAP = 4
MAX_CHIPS = 3
H_GAP = 18
CHAR_WIDTH = 7.4
PADDING = 26
MIN_WIDTH = 96

# role -> words that identify a management group. Order matters: the first role with a match wins.
ROLES = (
    ("decommissioned", ("decommission", "decomission", "descomision", "decom", "retirad", "baja", "descontinuad")),
    ("sandbox", ("sandbox", "sandboxes", "laboratorio", "lab", "labs", "pruebas", "playground", "experiment")),
    ("connectivity", ("connectivity", "conectividad", "conectividade", "network", "red", "redes", "rede", "hub", "networking")),
    ("identity", ("identity", "identidad", "identidade", "iam", "directory", "directorio")),
    ("security", ("security", "seguridad", "seguranca", "sec", "secops")),
    ("management", ("management", "mgmt", "gestion", "gerenciamiento", "gerenciamento", "administracion", "monitoring", "operaciones", "operations")),
    ("platform", ("platform", "plataforma", "plataformas", "shared", "compartido", "compartidos", "infrastructure", "infraestructura")),
    ("corp", ("corp", "corporate", "corporativo", "corporativa", "internal", "interno", "interna", "private", "privado")),
    ("online", ("online", "public", "publico", "publica", "internet", "externo", "externa", "dmz")),
    ("local", ("local", "onprem", "edge")),
    ("landingzones", ("landing zone", "landingzone", "landing zones", "zonas de aterrizaje", "workload", "workloads", "cargas", "aplicaciones",
                      "apps", "aterrizaje", "lz", "alz", "produccion", "prod", "spoke")),
)
SHORT_WORDS = {"lz", "alz", "hub", "local", "online", "corp", "red", "sec", "iam", "lab", "baja", "apps", "prod", "dmz", "decom"}

# Well known policy assignments of the reference architecture, by the role of the group they are made on.
POLICY_SIGNS = {
    "sandbox": ("sandbox",),
    "decommissioned": ("decomm",),
    "connectivity": ("ddos",),
    "corp": ("private-dns-zones", "deny-public-endpoints", "privatednszones"),
    "landingzones": ("enforce-gr-keyvault", "deny-ip-forwarding", "enforce-aks-https", "deny-priv-esc", "deny-storage-http"),
}
# Resource types that give away a platform subscription, by role. First role with any resource wins.
CONTENT_SIGNS = (
    ("connectivity", ("microsoft.network/azurefirewalls", "microsoft.network/virtualnetworkgateways",
                      "microsoft.network/expressroutecircuits", "microsoft.network/virtualhubs",
                      "microsoft.network/ddosprotectionplans")),
    ("identity", ("microsoft.aad/domainservices",)),
    ("management", ("microsoft.operationalinsights/workspaces", "microsoft.automation/automationaccounts")),
)
# The reference architecture of the image: (label, role, children)
REFERENCE = (
    "Tenant root group", "root", (
        ("Intermediate root", "intermediate", (
            ("Platform", "platform", (
                ("Security", "security", ()), ("Management", "management", ()),
                ("Identity", "identity", ()), ("Connectivity", "connectivity", ()))),
            ("Workload landing zones", "landingzones", (
                ("Internal (Corp)", "corp", ()), ("Online", "online", ()), ("Local", "local", ()))),
            ("Decommissioned", "decommissioned", ()),
            ("Sandbox", "sandbox", ()),
        )),
    ),
)
ROLE_NAMES = {role for role, _ in ROLES}


def _plain(text):
    """Lower case without accents, with every run of other characters as one space."""
    stripped = unicodedata.normalize("NFKD", str(text).lower()).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", " ", stripped).strip()


def _matches(word, tokens, text):
    word = _plain(word)
    if " " in word:
        return word in text
    if word in SHORT_WORDS:
        return word in tokens
    return any(token.startswith(word) for token in tokens)


def role_of(name):
    """The landing zone role of a management group from its name, or ''. Matching is by words, not exact names."""
    text = _plain(name)
    tokens = text.split()
    for role, words in ROLES:
        if any(_matches(word, tokens, text) for word in words):
            return role
    return ""


def role_from_policies(names):
    """The role that the policy assignments made on a group point to, or ''."""
    joined = " ".join(str(n).lower() for n in names or ())
    for role, signs in POLICY_SIGNS.items():
        if any(sign in joined for sign in signs):
            return role
    return ""


def role_from_content(counts):
    """The role that the resources of a platform subscription point to, or ''."""
    for role, types in CONTENT_SIGNS:
        if any(counts.get(t, 0) for t in types):
            return role
    return ""


def parse_override(text):
    """LANDING_ZONE_MAP: {"connectivity": "mg-conn", "platform": ["Plataforma", "mg-plat"]} -> {role: {lower names}}."""
    if not text:
        return {}
    try:
        raw = json.loads(text)
    except ValueError:
        return {}
    result = {}
    for role, value in (raw.items() if isinstance(raw, dict) else ()):
        if role in ROLE_NAMES:
            items = value if isinstance(value, list) else [value]
            result[role] = {str(item).strip().lower() for item in items if str(item).strip()}
    return result


def override_from_environment():
    return parse_override(os.environ.get("LANDING_ZONE_MAP", ""))


def classify(tree, policies=None, signals=None, override=None):
    """Matches every management group to a role. Returns ({group name: {role, how}}, {role: [labels with how]}).
    policies: {group name: [assignment names]}; signals: {subscription: {resource type: count}}."""
    policies, signals, override = policies or {}, signals or {}, override or {}
    result, found = {}, {}

    def subscriptions_of(node):
        subs = set(node.get("subscriptions", []))
        for child in node.get("children", []):
            subs |= subscriptions_of(child)
        return subs

    def decide(node, parent_role):
        label = node.get("displayName") or node.get("name", "")
        name = str(node.get("name", "")).lower()
        identifiers = {name, str(label).lower()}
        role, how = "", ""
        for candidate, names in override.items():
            if identifiers & names:
                role, how = candidate, "manual"
                break
        if not role:
            role = role_of(label) or role_of(node.get("name", ""))
            how = "name" if role else ""
        if not role:
            role = role_from_policies(policies.get(name))
            how = "policy" if role else ""
        if not role and parent_role == "platform":
            merged = {}
            for sub in subscriptions_of(node):
                for kind, count in (signals.get(sub) or {}).items():
                    merged[kind] = merged.get(kind, 0) + count
            role = role_from_content(merged)
            how = "content" if role else ""
        return role, how

    def walk(node, parent_role=""):
        role, how = decide(node, parent_role)
        result[node.get("name", "")] = {"role": role, "how": how}
        if role:
            found.setdefault(role, []).append({"label": node.get("displayName") or node.get("name", ""), "how": how})
        for child in node.get("children", []):
            walk(child, role)

    for root in tree:
        walk(root)
    return result, found

def _label_width(text):
    return max(MIN_WIDTH, round(len(text) * CHAR_WIDTH + PADDING))


def _short(text, limit):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _measure(node):
    """Width of the space a subtree needs: the widest of its own box and its children side by side."""
    own = max(node["width"], 140 if node["chips"] or node["hidden"] or node["slot"] else 0)
    kids = [_measure(child) for child in node["children"]]
    node["span"] = max(own, sum(kids) + H_GAP * max(len(kids) - 1, 0)) if kids else own
    return node["span"]


def normalize(label, role="", children=(), subs=(), status="", key="", how="", slot=False, kind="mg", node_id="", link=""):
    chips = [_short(s, 24) for s in subs[:MAX_CHIPS]]
    hidden = max(len(subs) - MAX_CHIPS, 0)
    return {"label": label, "role": role, "children": list(children), "chips": chips, "hidden": hidden,
            "status": status, "key": key or label, "width": SUB_WIDTH if kind == "sub" else _label_width(label), "subscriptions": len(subs), "how": how, "slot": slot,
            "kind": kind, "node_id": node_id, "link": link}


def layout(roots):
    """roots: nodes from `normalize`. Returns {width, height, nodes, links}."""
    for root in roots:
        _measure(root)
    nodes, links = [], []
    level_height = {}

    def height_of(node):
        if node["kind"] == "sub":
            return SUB_HEIGHT
        chips = len(node["chips"]) + (1 if node["hidden"] else 0) + (1 if node["slot"] else 0)
        return NODE_HEIGHT + (chips * (CHIP_HEIGHT + CHIP_GAP) + CHIP_GAP if chips else 0)

    def depths(node, depth=0):
        level_height[depth] = max(level_height.get(depth, 0), height_of(node))
        for child in node["children"]:
            depths(child, depth + 1)

    for root in roots:
        depths(root)
    tops, y = {}, 12
    for depth in sorted(level_height):
        tops[depth] = y
        y += level_height[depth] + LEVEL_GAP

    def place(node, left, depth):
        cx = left + node["span"] / 2
        top = tops[depth]
        entry = {**{k: node[k] for k in ("label", "role", "status", "key", "hidden", "subscriptions", "how", "kind", "node_id", "link")},
                 "x": round(cx - node["width"] / 2, 1), "y": top, "width": node["width"],
                 "height": SUB_HEIGHT if node["kind"] == "sub" else NODE_HEIGHT,
                 "cx": round(cx, 1), "chips": []}
        for index, chip in enumerate(node["chips"]):
            entry["chips"].append({"label": chip, "x": round(cx - 70, 1), "width": 140,
                                   "y": top + NODE_HEIGHT + CHIP_GAP + index * (CHIP_HEIGHT + CHIP_GAP)})
        if node["hidden"]:
            entry["more"] = {"label": f"+{node['hidden']} more", "x": round(cx - 70, 1), "width": 140,
                             "y": top + NODE_HEIGHT + CHIP_GAP + len(node["chips"]) * (CHIP_HEIGHT + CHIP_GAP)}
        if node["slot"]:
            rows = len(node["chips"]) + (1 if node["hidden"] else 0)
            entry["add"] = {"label": "+ Subscription", "x": round(cx - 70, 1), "width": 140,
                            "y": top + NODE_HEIGHT + CHIP_GAP + rows * (CHIP_HEIGHT + CHIP_GAP)}
        nodes.append(entry)
        if node["children"]:
            total = sum(c["span"] for c in node["children"]) + H_GAP * (len(node["children"]) - 1)
            cursor = cx - total / 2
            child_top = tops[depth + 1]
            bar_y = child_top - LEVEL_GAP / 2
            starts = []
            for child in node["children"]:
                starts.append(place(child, cursor, depth + 1))
                cursor += child["span"] + H_GAP
            bottom = top + height_of(node)
            xs = [s for s in starts]
            links.append({"d": f"M{cx:.1f},{bottom} V{bar_y:.1f} M{min(xs):.1f},{bar_y:.1f} H{max(xs):.1f}"})
            for sx in starts:
                links.append({"d": f"M{sx:.1f},{bar_y:.1f} V{child_top}"})
        return cx

    cursor = 12
    for root in roots:
        place(root, cursor, 0)
        cursor += root["span"] + H_GAP * 3
    width = max(cursor - H_GAP * 3 + 12, 240)
    return {"width": round(width), "height": round(y - LEVEL_GAP + 12), "nodes": nodes, "links": links}


def actual(tree, subscriptions, names, outside, classification=None):
    """The tenant's own hierarchy. tree: roots from governance_view.build_tree."""
    classification = classification or {}

    def convert(node):
        subs = [names.get(s, s) for s in node.get("subscriptions", [])]
        label = node.get("displayName") or node.get("name", "")
        match = classification.get(node.get("name", ""), {})
        role = match.get("role", "") if classification else role_of(label)
        return normalize(label, role, [convert(c) for c in node.get("children", [])], sorted(subs),
                         key=node.get("name", ""), how=match.get("how", ""))

    roots = [convert(node) for node in tree]
    if outside:
        roots.append(normalize("No visible management group", "", [], sorted(s.get("name") or s["id"] for s in outside),
                               key="outside"))
    return layout(roots)



# ---------------------------------------------------------------------------------------------------------
# The editable design: the tree the visitor draws, starting from the reference architecture.

SUB_HEIGHT = 28
SUB_WIDTH = 160
MAX_NODES = 150
MAX_DEPTH = 8
MAX_LABEL = 60
NODE_ID = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
KIND_NAMES = {"mg": "management group", "sub": "subscription"}


def default_design():
    """The reference architecture as an editable tree. Every node: id, label, kind (root, mg or sub), role (the box of
    the reference it started as, used to find it by name, policy or content), link (the name of the real management
    group or subscription it stands for) and children."""
    def convert(item):
        label, role, kids = item
        return {"id": role, "label": label, "kind": "root" if role == "root" else "mg", "role": "" if role == "root" else role,
                "link": "", "children": [convert(kid) for kid in kids]}

    return convert(REFERENCE)


def sanitize_design(raw, group_names=None, subscription_names=None):
    """Checks a design coming from the page. Returns (design or None, [errors]). A subscription is always a leaf, a
    management group may hold anything, the root cannot change kind, and when the names of the tenant are known
    a link must be a management group of the right kind: a subscription is never linked to a group or the other way."""
    errors, seen, count = [], set(), [0]

    def walk(node, depth, is_root):
        if not isinstance(node, dict):
            errors.append("A box is not valid.")
            return None
        count[0] += 1
        if count[0] > MAX_NODES:
            errors.append(f"The diagram can have at most {MAX_NODES} boxes.")
            return None
        if depth > MAX_DEPTH:
            errors.append(f"The diagram can have at most {MAX_DEPTH} levels.")
            return None
        node_id = str(node.get("id", ""))
        kind = "root" if is_root else str(node.get("kind", ""))
        label = " ".join(str(node.get("label", "")).split())[:MAX_LABEL]
        link = " ".join(str(node.get("link", "")).split())[:120]
        role = str(node.get("role", "")) if not is_root else ""
        if not NODE_ID.match(node_id) or node_id in seen:
            errors.append("A box has a missing or repeated identifier.")
            return None
        seen.add(node_id)
        if kind not in ("root", "mg", "sub"):
            errors.append(f"{label or node_id} has an unknown type.")
            return None
        if not label:
            errors.append("Every box needs a name.")
            return None
        if role and role not in ROLE_NAMES and role != "intermediate":
            role = ""
        children = node.get("children") or []
        if not isinstance(children, list):
            children = []
        if kind == "sub":
            role = ""
            if children:
                errors.append(f"{label} is a subscription and cannot have boxes below it.")
                return None
        if link:
            known = group_names if kind == "mg" else subscription_names if kind == "sub" else None
            if kind == "root":
                link = ""
            elif known is not None and link.lower() not in known:
                errors.append(f"{link} is not a {KIND_NAMES[kind]} of your tenant.")
                return None
        built = [walk(child, depth + 1, False) for child in children]
        if any(child is None for child in built):
            return None
        return {"id": node_id, "label": label, "kind": kind, "role": role, "link": link, "children": built}

    if not isinstance(raw, dict) or raw.get("kind") not in (None, "root") or raw.get("id") != "root":
        return None, ["The diagram needs its root."]
    design = walk(raw, 0, True)
    return (design, []) if design and not errors else (None, errors[:3] or ["The diagram is not valid."])


def design_nodes(design):
    """Every node of a design, parents first: [(node, parent or None)]."""
    result = []

    def walk(node, parent):
        result.append((node, parent))
        for child in node.get("children", []):
            walk(child, node)

    walk(design, None)
    return result


def design_diagram(design, found, has_hierarchy, group_names=(), subscription_names=()):
    """Draws a design. `found` is the second value of `classify`. Returns (diagram, facts, summary): facts says, for
    each box id, whether it was found and how, for the editing panel; summary counts what the tenant has."""
    groups, subs = {n.lower() for n in group_names}, {n.lower() for n in subscription_names}
    facts, counts = {}, {"groups": 0, "groupsFound": 0, "subscriptions": 0, "subscriptionsLinked": 0}

    def convert(node):
        kind, link, role = node["kind"], node.get("link", ""), node.get("role", "")
        status, how, matches = "present", "", []
        if kind == "mg":
            counts["groups"] += 1
            if link:
                ok = link.lower() in groups
                status, how, matches = ("present", "manual", [f"{link} (manual)"]) if ok else ("missing", "", [])
            elif role in ("intermediate",):
                status = "present" if has_hierarchy else "missing"
            elif role and found.get(role):
                status, how = "present", found[role][0]["how"]
                matches = [f"{m['label']} ({m['how']})" for m in found[role]]
            else:
                status = "missing"
            counts["groupsFound"] += status == "present"
        elif kind == "sub":
            counts["subscriptions"] += 1
            ok = bool(link) and link.lower() in subs
            status, how = ("present", "manual") if ok else ("missing", "")
            matches = [link] if ok else []
            counts["subscriptionsLinked"] += ok
        facts[node["id"]] = {"status": status, "matches": matches, "how": how}
        label = link if kind == "sub" and link else node["label"]
        return normalize(label, role if kind != "sub" else "", [convert(child) for child in node["children"]],
                         status="" if kind == "root" else status, key=node["id"], how=how, kind=kind,
                         node_id=node["id"], link=link)

    diagram = layout([convert(design)])
    return diagram, facts, counts
