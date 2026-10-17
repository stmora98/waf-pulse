"""Landing zone diagram of the management group hierarchy, laid out as a top-down tree with elbow connectors.

Pure functions: the template draws the returned geometry as SVG, so no script or inline style is needed.
"""
import re

NODE_HEIGHT = 34
LEVEL_GAP = 46
CHIP_HEIGHT = 22
CHIP_GAP = 4
MAX_CHIPS = 3
H_GAP = 18
CHAR_WIDTH = 7.4
PADDING = 26
MIN_WIDTH = 96

# role -> words that identify a management group of the Azure landing zone reference architecture
ROLES = (
    ("decommissioned", ("decommission",)),
    ("sandbox", ("sandbox",)),
    ("connectivity", ("connectivity", "network", "hub")),
    ("identity", ("identity",)),
    ("security", ("security",)),
    ("management", ("management", "mgmt")),
    ("platform", ("platform",)),
    ("corp", ("corp", "internal")),
    ("online", ("online",)),
    ("local", ("local",)),
    ("landingzones", ("landing zone", "landingzone", "workload", "lz")),
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


SHORT_WORDS = {"lz", "hub", "local", "online", "corp"}  # too short to match inside other words


def _matches(word, tokens, text):
    if " " in word:
        return word in text
    if word in SHORT_WORDS:
        return word in tokens
    return any(token.startswith(word) for token in tokens)


def role_of(name):
    """The landing zone role of a management group from its names, or ''. Matching is by words, not exact names."""
    text = re.sub(r"[^a-z0-9]+", " ", str(name).lower()).strip()
    tokens = text.split()
    for role, words in ROLES:
        if any(_matches(word, tokens, text) for word in words):
            return role
    return ""

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


def normalize(label, role="", children=(), subs=(), status="", key=""):
    chips = [_short(s, 24) for s in subs[:MAX_CHIPS]]
    hidden = max(len(subs) - MAX_CHIPS, 0)
    return {"label": label, "role": role, "children": list(children), "chips": chips, "hidden": hidden,
            "status": status, "key": key or label, "width": _label_width(label), "subscriptions": len(subs)}


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
        entry = {**{k: node[k] for k in ("label", "role", "status", "key", "hidden", "subscriptions")},
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


def actual(tree, subscriptions, names, outside):
    """The tenant's own hierarchy. tree: roots from governance_view.build_tree."""
    def convert(node):
        subs = [names.get(s, s) for s in node.get("subscriptions", [])]
        label = node.get("displayName") or node.get("name", "")
        return normalize(label, role_of(label), [convert(c) for c in node.get("children", [])], sorted(subs), key=node.get("name", ""))

    roots = [convert(node) for node in tree]
    if outside:
        roots.append(normalize("No visible management group", "", [], sorted(s.get("name") or s["id"] for s in outside),
                               key="outside"))
    return layout(roots)


def present_roles(tree):
    roles = set()

    def walk(node):
        role = role_of(node.get("displayName") or node.get("name", ""))
        if role:
            roles.add(role)
        for child in node.get("children", []):
            walk(child)

    for node in tree:
        walk(node)
    return roles


def reference(found_roles, has_hierarchy):
    """The reference architecture, each box marked present or missing in the tenant. Boxes that only organize the
    tree (tenant root, intermediate root) are marked present when any hierarchy is visible."""
    def convert(item):
        label, role, kids = item
        if role in ("root", "intermediate"):
            status = "present" if has_hierarchy or role == "root" else "missing"
        else:
            status = "present" if role in found_roles else "missing"
        return normalize(label, role, [convert(k) for k in kids], status=status, key=role)

    return layout([convert(REFERENCE)])


def alignment(found_roles):
    """[(label, present)] for the boxes of the reference architecture that a tenant is expected to have."""
    expected = []

    def walk(item):
        label, role, kids = item
        if role not in ("root", "intermediate"):
            expected.append((label, role in found_roles))
        for kid in kids:
            walk(kid)

    walk(REFERENCE)
    return expected
