"""View helpers for the governance page."""


def build_tree(groups, subscriptions):
    """Nests the flat management group list. Returns the root nodes, each with `children` and the names of its
    subscriptions. Groups whose parent is unknown become roots, and a cycle in bad data cannot recurse forever."""
    names = {sub["id"]: sub.get("name") or sub["id"] for sub in subscriptions}
    nodes = {group["name"]: {**group, "children": [], "subscriptionNames": sorted(
        names.get(sub, sub) for sub in group.get("subscriptions", []))} for group in groups}
    roots = []
    for node in nodes.values():
        parent = nodes.get(node.get("parent"))
        if parent is None or parent is node:
            roots.append(node)
        else:
            parent["children"].append(node)

    seen = set()

    def prune(node):
        seen.add(node["name"])
        node["children"] = [child for child in node["children"] if child["name"] not in seen]
        for child in node["children"]:
            prune(child)

    for root in roots:
        prune(root)
    # Groups that only appear inside a cycle are not reachable from a root: show them as roots.
    for node in nodes.values():
        if node["name"] not in seen:
            roots.append(node)
            prune(node)
    return roots


def subscriptions_outside_groups(groups, subscriptions):
    inside = {sub for group in groups for sub in group.get("subscriptions", [])}
    return [sub for sub in subscriptions if sub["id"] not in inside]
