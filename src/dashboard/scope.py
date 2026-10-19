"""Scope: the part of the tenant the visitor looks at: some subscriptions, some management groups (with everything below
them) and some tags. It is kept in a cookie, validated on every read, and applied to the findings, the resources and the
right-sizing rows; the scores of a scope are the scores of its subscriptions, weighted by their number of resources."""
import json
import re

COOKIE = "waf_scope"
MAX_ITEMS = 50
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
MG_NAME = re.compile(r"^[A-Za-z0-9._()\- ]{1,90}$")
TAG = re.compile(r"^[^=\x00-\x1f]{1,64}=[^\x00-\x1f]{0,64}$")


def _unique(values, valid, lower=False):
    result, seen = [], set()
    for value in values if isinstance(values, list) else []:
        if not isinstance(value, str) or not valid.match(value):
            continue
        key = value.lower()
        if key not in seen:
            seen.add(key)
            result.append(key if lower else value)
    return result[:MAX_ITEMS]


def sanitize(body):
    """The scope described by a request or a cookie, with everything malformed dropped."""
    body = body if isinstance(body, dict) else {}
    return {"subs": _unique(body.get("subs"), GUID, lower=True), "mgs": _unique(body.get("mgs"), MG_NAME),
            "tags": _unique(body.get("tags"), TAG)}


def decode(raw):
    try:
        return sanitize(json.loads(raw)) if raw else {"subs": [], "mgs": [], "tags": []}
    except ValueError:
        return {"subs": [], "mgs": [], "tags": []}


def encode(scope):
    return json.dumps(scope, separators=(",", ":"))


def is_active(scope):
    return bool(scope and (scope["subs"] or scope["mgs"] or scope["tags"]))


def label(scope):
    """A short description for the header."""
    parts = []
    for key, singular, plural in (("subs", "subscription", "subscriptions"), ("mgs", "management group", "management groups"), ("tags", "tag", "tags")):
        count = len(scope[key])
        if count:
            parts.append(f"{count} {singular if count == 1 else plural}")
    return " · ".join(parts) if parts else "Everything"


def tag_filters(scope):
    """{key (lower): {values (lower)}}: a resource must carry every key, with one of the values."""
    wanted = {}
    for item in scope["tags"]:
        key, _, value = item.partition("=")
        wanted.setdefault(key.strip().lower(), set()).add(value.strip().lower())
    return wanted


def group_subscriptions(groups, names):
    """Every subscription at or below the management groups named in `names` (the name or the display name)."""
    wanted = {str(n).lower() for n in names}
    by_name = {g.get("name"): g for g in groups}
    children = {}
    for group in groups:
        children.setdefault(group.get("parent"), []).append(group.get("name"))
    result, seen = set(), set()

    def walk(name):
        if name in seen or name not in by_name:
            return
        seen.add(name)
        result.update(str(s).lower() for s in by_name[name].get("subscriptions", []))
        for child in children.get(name, []):
            walk(child)

    for group in groups:
        if str(group.get("name", "")).lower() in wanted or str(group.get("displayName", "")).lower() in wanted:
            walk(group.get("name"))
    return result


def subscription_of(resource_id):
    """The subscription id inside a resource id, lower case, or ''."""
    parts = str(resource_id).lower().split("/")
    return parts[2] if len(parts) > 2 and parts[1] == "subscriptions" else ""


class Resolved:
    """A scope ready to test findings and rows against: `subs` (None = every subscription) and `tagged` (None = no tag
    filter, else the ids of the resources that carry the tags)."""

    def __init__(self, subs=None, tagged=None):
        self.subs, self.tagged = subs, tagged

    @property
    def active(self):
        return self.subs is not None or self.tagged is not None

    def finding_ok(self, finding):
        if self.subs is not None and str(finding.get("subscriptionId", "")).lower() not in self.subs:
            return False
        return self.tagged is None or str(finding.get("resourceId", "")).lower() in self.tagged

    def row_ok(self, row):
        if self.subs is not None and str(row.get("subscriptionId") or subscription_of(row.get("id", ""))).lower() not in self.subs:
            return False
        return self.tagged is None or str(row.get("id", "")).lower() in self.tagged


def matches_tags(row, wanted):
    tags = {str(k).lower(): str(v).lower() for k, v in row.get("tagList") or []}
    return all(key in tags and tags[key] in values for key, values in wanted.items())


def resolve(scope, groups=None, rows=None):
    """`groups`: the management groups of the run; `rows`: the inventory (needed only for tags)."""
    if not is_active(scope):
        return Resolved()
    subs = None
    if scope["subs"] or scope["mgs"]:
        subs = set(scope["subs"]) | group_subscriptions(groups or [], scope["mgs"])
    tagged = None
    if scope["tags"]:
        wanted = tag_filters(scope)
        tagged = {str(r["id"]).lower() for r in rows or [] if matches_tags(r, wanted)}
    return Resolved(subs, tagged)


def apply_summary(summary, resolved, rows=None):
    """A copy of the run summary for the scope: its subscriptions, their resources and the weighted pillar scores. A tag scope
    has no scores (they are calculated per subscription), only counts."""
    if not summary or not resolved.active:
        return summary
    subscriptions = [s for s in summary.get("subscriptions", []) if resolved.subs is None or str(s["id"]).lower() in resolved.subs]
    scoped = {**summary, "subscriptions": subscriptions, "subscriptionCount": len(subscriptions), "scoped": True}
    if resolved.tagged is not None:
        scoped["scores"] = {}
        scoped["resourceCount"] = sum(1 for rid in resolved.tagged if resolved.subs is None or subscription_of(rid) in resolved.subs)
        scoped["scopeNote"] = "Scores are calculated for subscriptions: with a tag in the scope only the findings are shown."
        return scoped
    scoped["resourceCount"] = sum(s.get("resourceCount", 0) for s in subscriptions)
    scores = {}
    for pillar in (summary.get("scores") or {}):
        weighted = [(s["scores"][pillar], max(s.get("resourceCount", 0), 1)) for s in subscriptions
                    if (s.get("scores") or {}).get(pillar) is not None]
        total = sum(weight for _, weight in weighted)
        scores[pillar] = round(sum(score * weight for score, weight in weighted) / total) if total else None
    scoped["scores"] = scores
    scoped["scopeNote"] = "Scores are the scores of the subscriptions in the scope, weighted by their number of resources."
    return scoped


def options(summary, rows=None):
    """What the scope picker offers: subscriptions, management groups and the tags of the inventory."""
    summary = summary or {}
    governance = summary.get("governance") or {}
    groups = [{"name": g.get("name"), "displayName": g.get("displayName") or g.get("name"), "subscriptions": len(g.get("subscriptions", []))}
              for g in governance.get("managementGroups", []) if g.get("name")]
    subscriptions = [{"id": s["id"], "name": s.get("name") or s["id"], "resources": s.get("resourceCount", 0)} for s in summary.get("subscriptions", [])]
    counts = {}
    for row in rows or []:
        for key, value in row.get("tagList") or []:
            counts.setdefault(str(key), {}).setdefault(str(value), 0)
            counts[str(key)][str(value)] += 1
    tags = [{"key": key, "total": sum(values.values()),
             "values": [{"value": v, "count": c} for v, c in sorted(values.items(), key=lambda item: (-item[1], item[0]))[:30]]}
            for key, values in sorted(counts.items(), key=lambda item: (-sum(item[1].values()), item[0]))[:40]]
    return {"subscriptions": sorted(subscriptions, key=lambda s: s["name"].lower()),
            "managementGroups": sorted(groups, key=lambda g: str(g["displayName"]).lower()), "tags": tags,
            "tagsAvailable": any(row.get("tagList") is not None for row in rows or [])}
