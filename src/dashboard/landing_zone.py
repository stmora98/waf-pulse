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
    own = max(node["width"], 140 if node["chips"] or node["hidden"] else 0)
    kids = [_measure(child) for child in node["children"]]
    node["span"] = max(own, sum(kids) + H_GAP * max(len(kids) - 1, 0)) if kids else own
    return node["span"]


def normalize(label, role="", children=(), subs=(), status="", key="", how=""):
    chips = [_short(s, 24) for s in subs[:MAX_CHIPS]]
    hidden = max(len(subs) - MAX_CHIPS, 0)
    return {"label": label, "role": role, "children": list(children), "chips": chips, "hidden": hidden,
            "status": status, "key": key or label, "width": _label_width(label), "subscriptions": len(subs), "how": how}


def layout(roots):
    """roots: nodes from `normalize`. Returns {width, height, nodes, links}."""
    for root in roots:
        _measure(root)
    nodes, links = [], []
    level_height = {}

    def height_of(node):
        chips = len(node["chips"]) + (1 if node["hidden"] else 0)
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
        entry = {**{k: node[k] for k in ("label", "role", "status", "key", "hidden", "subscriptions", "how")},
                 "x": round(cx - node["width"] / 2, 1), "y": top, "width": node["width"], "height": NODE_HEIGHT,
                 "cx": round(cx, 1), "chips": []}
        for index, chip in enumerate(node["chips"]):
            entry["chips"].append({"label": chip, "x": round(cx - 70, 1), "width": 140,
                                   "y": top + NODE_HEIGHT + CHIP_GAP + index * (CHIP_HEIGHT + CHIP_GAP)})
        if node["hidden"]:
            entry["more"] = {"label": f"+{node['hidden']} more", "x": round(cx - 70, 1), "width": 140,
                             "y": top + NODE_HEIGHT + CHIP_GAP + len(node["chips"]) * (CHIP_HEIGHT + CHIP_GAP)}
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


def reference(found, has_hierarchy):
    """The reference architecture, each box marked present or missing in the tenant. `found` is the second value of
    `classify`. Boxes that only organize the tree (tenant root, intermediate root) are marked present when any
    hierarchy is visible."""
    def convert(item):
        label, role, kids = item
        if role in ("root", "intermediate"):
            status = "present" if has_hierarchy or role == "root" else "missing"
            how = ""
        else:
            status = "present" if found.get(role) else "missing"
            how = found[role][0]["how"] if found.get(role) else ""
        return normalize(label, role, [convert(k) for k in kids], status=status, key=role, how=how)

    return layout([convert(REFERENCE)])


def alignment(found):
    """[(label, present, [matches])] for the boxes of the reference architecture that a tenant is expected to have."""
    expected = []

    def walk(item):
        label, role, kids = item
        if role not in ("root", "intermediate"):
            matches = [f"{m['label']} ({m['how']})" for m in found.get(role, [])]
            expected.append((label, bool(matches), matches))
        for kid in kids:
            walk(kid)

    walk(REFERENCE)
    return expected