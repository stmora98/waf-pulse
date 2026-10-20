"""Filters ("scope"): the part of the tenant the visitor looks at. Each filter is one field (subscription, management group,
resource group, resource type, location or a tag) with "equals" or "does not equal" and its values, like the filters of the
Azure portal; they all have to hold. They live in a cookie, are validated on every read and apply to every page: findings,
resources, right-sizing, and the scores, which are calculated again for the part of the tenant that is left."""
import json
import re
from collections import Counter, defaultdict

import scoring

COOKIE = "waf_scope"
MAX_FILTERS = 12
MAX_VALUES = 50
MAX_COOKIE = 3600

FIELDS = {"sub": "Subscription", "mg": "Management group", "rg": "Resource group", "type": "Resource type", "loc": "Location", "tag": "Tag"}
SUB_FIELDS = ("sub", "mg")
RESOURCE_FIELDS = ("rg", "type", "loc", "tag")

GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
VALUE_PATTERNS = {
    "sub": GUID,
    "mg": re.compile(r"^[A-Za-z0-9._()\- ]{1,90}$"),
    "rg": re.compile(r"^[A-Za-z0-9._()\- ]{1,90}$"),
    "type": re.compile(r"^[A-Za-z0-9._/\-]{1,120}$"),
    "loc": re.compile(r"^[A-Za-z0-9 ._\-]{1,40}$"),
    "tag": re.compile(r"^[^\x00-\x1f]{1,64}$"),
}
TAG_KEY = re.compile(r"^[^=\x00-\x1f]{1,64}$")
NOT_IN_A_SUBSCRIPTION = ("", "tenant", "unknown")
RESOURCE_GROUP_TYPE = "microsoft.resources/subscriptions/resourcegroups"
DIAGNOSTICS_RULE, LIFECYCLE_RULE = "OPS-DIAG-001", "COST-STG-002"


# --- the list of filters ----------------------------------------------------------------------------------------

def _values(field, raw):
    pattern = VALUE_PATTERNS[field]
    result, seen = [], set()
    for value in raw if isinstance(raw, list) else []:
        if isinstance(value, str) and pattern.match(value) and value.lower() not in seen:
            seen.add(value.lower())
            result.append(value.lower() if field in ("sub", "type") else value)
    return result[:MAX_VALUES]


def sanitize(body):
    """The filters in a request or a cookie, with everything malformed dropped: [{f, op, v[, k]}]."""
    items = body.get("filters") if isinstance(body, dict) else body
    result, seen = [], set()
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or item.get("f") not in FIELDS:
            continue
        field = item["f"]
        entry = {"f": field, "op": "ne" if item.get("op") == "ne" else "eq", "v": _values(field, item.get("v"))}
        names = {str(k).lower(): v[:90] for k, v in (item.get("n") or {}).items() if isinstance(v, str) and str(k).lower() in {x.lower() for x in entry["v"]}} \
            if isinstance(item.get("n"), dict) else {}
        if names:
            entry["n"] = names  # what to show instead of an id (a subscription name); cosmetic, never used to filter
        if field == "tag":
            key = item.get("k")
            if not isinstance(key, str) or not TAG_KEY.match(key):
                continue
            entry["k"] = key
        elif not entry["v"]:
            continue
        identity = json.dumps({k: v for k, v in entry.items() if k != "n"}, sort_keys=True).lower()
        if identity not in seen:
            seen.add(identity)
            result.append(entry)
    return result[:MAX_FILTERS]


def from_legacy(body):
    """Cookies written before filters were a list: {subs, mgs, tags}."""
    filters = []
    if body.get("subs"):
        filters.append({"f": "sub", "op": "eq", "v": body["subs"]})
    if body.get("mgs"):
        filters.append({"f": "mg", "op": "eq", "v": body["mgs"]})
    by_key = defaultdict(list)
    for item in body.get("tags") or []:
        key, _, value = str(item).partition("=")
        by_key[key].append(value)
    filters += [{"f": "tag", "k": key, "op": "eq", "v": values} for key, values in by_key.items()]
    return filters


def decode(raw):
    try:
        body = json.loads(raw) if raw else []
    except ValueError:
        return []
    if isinstance(body, dict) and not body.get("filters"):
        body = from_legacy(body)
    return sanitize(body)


def encode(filters):
    return json.dumps(filters, separators=(",", ":"))


def is_active(filters):
    return bool(filters)


def describe(entry, names=None):
    """A readable text for one filter: 'Tag env equals prod, dev'."""
    names = names or {}
    label = f"Tag {entry['k']}" if entry["f"] == "tag" else FIELDS[entry["f"]]
    if entry["f"] == "tag" and not entry["v"]:
        return f"{label} {'is missing' if entry['op'] == 'ne' else 'exists'}"
    names = {**names, **(entry.get("n") or {})}
    shown = [names.get(str(v).lower(), v) for v in entry["v"]]
    return f"{label} {'does not equal' if entry['op'] == 'ne' else 'equals'} {', '.join(shown)}"


def label(filters):
    """A short description for the header."""
    if not filters:
        return "No filters"
    return f"{len(filters)} filter{'' if len(filters) == 1 else 's'}"


# --- tenant structure ---------------------------------------------------------------------------------------------

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


def resource_group_of(resource_id):
    parts = str(resource_id or "").split("/")
    lowered = [p.lower() for p in parts]
    return parts[lowered.index("resourcegroups") + 1] if "resourcegroups" in lowered[:-1] else ""


def _is_resource(resource_id):
    """True for something inside a resource group (or a resource group itself): not a subscription or a tenant object."""
    lowered = str(resource_id).lower()
    return "/resourcegroups/" in lowered and subscription_of(resource_id) != ""


# --- the filters applied -----------------------------------------------------------------------------------------

class Resolved:
    """The filters ready to test findings, rows and statistics against. `inventory` (rows) is needed by the filters that
    look at a resource (location, tags) and to count what a rule evaluates inside the filters."""

    def __init__(self, filters=None, groups=None, inventory=None, truncated=False):
        self.filters = filters or []
        self.inventory = {str(r["id"]).lower(): r for r in inventory or []}
        self.truncated = truncated
        self._mg = {index: group_subscriptions(groups or [], f["v"]) for index, f in enumerate(self.filters) if f["f"] == "mg"}

    @property
    def active(self):
        return bool(self.filters)

    @property
    def resource_level(self):
        return any(f["f"] in RESOURCE_FIELDS for f in self.filters)

    def _hit(self, index, entry, attrs):
        field, values = entry["f"], entry["v"]
        if field == "sub":
            hit = attrs["sub"] in values
        elif field == "mg":
            hit = attrs["sub"] in self._mg[index]
        elif field == "rg":
            hit = str(attrs["rg"]).lower() in {v.lower() for v in values}
        elif field == "type":
            hit = str(attrs["type"]).lower() in values
        elif field == "loc":
            hit = str(attrs["loc"]).lower() in {v.lower() for v in values}
        else:
            found = attrs["tags"].get(entry["k"].lower())
            hit = found is not None and (not values or found.lower() in {v.lower() for v in values})
        return hit if entry["op"] == "eq" else not hit

    def sub_ok(self, sub):
        """Does a subscription pass the subscription and management group filters? Tenant level objects never pass a filter."""
        sub = str(sub or "").lower()
        if not self.filters:
            return True
        if sub in NOT_IN_A_SUBSCRIPTION:
            return False
        attrs = {"sub": sub}
        return all(self._hit(i, f, attrs) for i, f in enumerate(self.filters) if f["f"] in SUB_FIELDS)

    def attributes(self, resource_id, sub="", kind="", row=None):
        """What the filters can ask about a resource, from the inventory when it is there. Location and tags are None when the
        resource is not in the inventory (the filters on them then leave it out)."""
        known = self.inventory.get(str(resource_id).lower()) or row or {}
        tags = {str(k).lower(): str(v) for k, v in known.get("tagList") or []} if "tagList" in known else None
        return {"sub": str(sub or known.get("subscriptionId") or subscription_of(resource_id)).lower(),
                "rg": known.get("resourceGroup") or resource_group_of(resource_id),
                "type": str(known.get("type") or kind or "").lower(), "loc": known.get("location"), "tags": tags}

    def _resource_ok(self, attrs):
        for index, entry in enumerate(self.filters):
            if entry["f"] not in RESOURCE_FIELDS:
                continue
            if (entry["f"] == "loc" and not attrs["loc"]) or (entry["f"] == "tag" and attrs["tags"] is None):
                return False
            if entry["f"] == "type" and not attrs["type"]:
                return False
            if not self._hit(index, entry, attrs):
                return False
        return True

    def finding_ok(self, finding):
        if not self.filters:
            return True
        if not self.sub_ok(finding.get("subscriptionId")):
            return False
        if not self.resource_level:
            return True
        resource_id = finding.get("resourceId", "")
        if not _is_resource(resource_id):
            return False
        kind = finding.get("resourceType") or (RESOURCE_GROUP_TYPE if resource_id.lower().count("/") == 4 else "")
        return self._resource_ok(self.attributes(resource_id, finding.get("subscriptionId"), kind))

    def sub_row_ok(self, row):
        """Rows that belong to a subscription but not to a resource (a compliance control, an installed package): they follow the
        subscription and management group filters and leave a filter on a resource."""
        return self.sub_ok(row.get("subscriptionId")) and not self.resource_level

    def row_ok(self, row):
        """Rows of the inventory, of the right-sizing data, of Advisor's advice and of the costs (all have an id)."""
        if not self.filters:
            return True
        resource_id = row.get("id", "")
        sub = row.get("subscriptionId") or subscription_of(resource_id)
        if not self.sub_ok(sub):
            return False
        if not self.resource_level:
            return True
        return self._resource_ok(self.attributes(resource_id, sub, row.get("type") or "", row))


def resolve(filters, groups=None, inventory=None, truncated=False):
    return Resolved(filters, groups, inventory, truncated)


# --- scores of a part of the tenant -----------------------------------------------------------------------------

def scoped_stats(rulestats, resolved, findings=None):
    """The rule statistics of what the filters leave: [{ruleId, pillar, severity, subscription, affected, applicable}].
    Filters on subscriptions and management groups just keep the rows of those subscriptions. Filters on a resource count
    the resources of the rule that are affected (from the findings) and estimate how many the rule evaluated there: the
    tenant figure scaled by the share of its resource types that the filters keep."""
    rows = [r for r in rulestats or [] if resolved.sub_ok(r["u"])]
    if not resolved.resource_level:
        return [{"ruleId": r["r"], "pillar": r["p"], "severity": r["v"], "subscription": r["u"], "affected": r["a"], "applicable": r["n"]} for r in rows]
    affected = defaultdict(set)
    for finding in findings or []:
        if resolved.finding_ok(finding):
            affected[(finding.get("ruleId"), str(finding.get("subscriptionId", "")).lower())].add(str(finding.get("resourceId", "")).lower())
    total, inside = defaultdict(Counter), defaultdict(Counter)
    for row in resolved.inventory.values():
        sub = str(row.get("subscriptionId", "")).lower()
        kind = str(row.get("type", "")).lower()
        total[sub][kind] += 1
        if resolved.row_ok(row):
            inside[sub][kind] += 1
    result = []
    for r in rows:
        found = len(affected.get((r["r"], r["u"]), ()))
        types = r.get("t")
        if not types or "*" in types:
            whole, kept = sum(total[r["u"]].values()), sum(inside[r["u"]].values())
        else:
            whole, kept = sum(total[r["u"]][t] for t in types), sum(inside[r["u"]][t] for t in types)
        applicable = max(round(r["n"] * kept / whole) if whole else 0, found)
        if applicable:
            result.append({"ruleId": r["r"], "pillar": r["p"], "severity": r["v"], "subscription": r["u"], "affected": found, "applicable": applicable})
    return result


def scores_of(stats):
    return scoring.score_pillars(scoring.merge_rule_stats(stats))


def _rule_total(stats, rule_id):
    rows = [s for s in stats if s["ruleId"] == rule_id]
    return sum(s["affected"] for s in rows), sum(s["applicable"] for s in rows)


def apply_summary(summary, resolved, rulestats=None, findings=None):
    """A copy of the run summary for the filters: the scores calculated again from the rule statistics, the subscriptions that
    are left with their own scores, the resources that are left, and the insights that are kept per subscription."""
    if not summary or not resolved.active:
        return summary
    notes = []
    subscriptions = [s for s in summary.get("subscriptions", []) if resolved.sub_ok(s["id"])]
    scoped = {**summary, "subscriptions": subscriptions, "subscriptionCount": len(subscriptions), "scoped": True}
    if rulestats:
        stats = scoped_stats(rulestats, resolved, findings)
        scoped["scores"] = scores_of(stats)
        by_sub = defaultdict(list)
        for stat in stats:
            by_sub[stat["subscription"]].append(stat)
        findings_by_sub = Counter(str(f.get("subscriptionId", "")).lower() for f in findings or [] if resolved.finding_ok(f))
        scoped["subscriptions"] = [{**s, "scores": scores_of(by_sub.get(s["id"].lower(), [])),
                                    "findingCount": findings_by_sub.get(s["id"].lower(), 0) if resolved.resource_level else s.get("findingCount", 0)}
                                   for s in subscriptions]
        if summary.get("diagnostics"):
            affected, applicable = _rule_total(stats, DIAGNOSTICS_RULE)
            scoped["diagnostics"] = {**summary["diagnostics"], "checked": applicable, "withLogs": applicable - affected, "byType": [],
                                     "percent": round(100 * (applicable - affected) / applicable, 1) if applicable else None}
        if summary.get("lifecycle"):
            affected, applicable = _rule_total(stats, LIFECYCLE_RULE)
            scoped["lifecycle"] = {**summary["lifecycle"], "checked": applicable, "withPolicy": applicable - affected,
                                   "percent": round(100 * (applicable - affected) / applicable, 1) if applicable else None}
    else:
        notes.append("The score statistics of this run are not available: refresh to see scores for the filters.")
        scoped["scores"] = {}
    if resolved.resource_level:
        scoped["resourceCount"] = sum(1 for row in resolved.inventory.values() if resolved.row_ok(row))
    else:
        scoped["resourceCount"] = sum(s.get("resourceCount", 0) for s in subscriptions)
    if resolved.truncated:
        notes.append("The resource list of this run is truncated, so counts by tag, location, resource group or type may be low.")

    # What Azure reports per subscription follows the subscription and management group filters.
    kept = {str(s["id"]).lower() for s in subscriptions}
    secure = summary.get("secureScore")
    if secure:
        entries = [s for s in secure.get("subscriptions", []) if str(s.get("subscriptionId", "")).lower() in kept]
        measured = [s["percentage"] for s in entries if s.get("percentage") is not None]
        scoped["secureScore"] = {**secure, "subscriptions": entries, "average": round(sum(measured) / len(measured), 1) if measured else None,
                                 "controlsTenantWide": True}
    defender = (summary.get("governance") or {}).get("defender")
    if defender and defender.get("detail") is not None:
        detail = [p for p in defender["detail"] if str(p.get("subscriptionId", "")).lower() in kept]
        enabled = sum(1 for p in detail if str(p.get("tier", "")).lower() != "free")
        scoped["governance"] = {**summary["governance"], "defender": {**defender, "detail": detail, "plans": len(detail), "enabled": enabled}}
    if summary.get("advisorSavings") is not None:
        totals = defaultdict(float)
        for sub, currencies in (summary.get("advisorSavingsBySubscription") or {}).items():
            if sub in kept:
                for currency, amount in currencies.items():
                    totals[currency] += amount
        scoped["advisorSavings"] = {currency: round(amount, 2) for currency, amount in totals.items()}
    commitments = summary.get("commitments")
    if commitments:
        items = [i for i in commitments.get("items", []) if str(i.get("subscriptionId", "")).lower() in kept]
        totals = defaultdict(lambda: defaultdict(float))
        for item in items:
            for term, amount in item["terms"].items():
                totals[item["currency"]][term] += amount
        scoped["commitments"] = {"items": items, "totals": {c: {t: round(a, 2) for t, a in terms.items()} for c, terms in totals.items()}} if items else {}
    if resolved.resource_level and (summary.get("secureScore") or commitments or summary.get("advisorSavings")):
        notes.append("Secure Score, Defender plans, commitments and usage savings are reported per subscription: only the subscription and management group filters narrow them.")
    scoped["scopeNotes"] = notes
    return scoped


def options(summary, inventory=None):
    """What the filter menu offers, each with how many resources it has: subscriptions, management groups, resource groups,
    resource types, locations and the tag keys with their values."""
    summary = summary or {}
    rows = inventory or []
    governance = summary.get("governance") or {}
    groups = [{"value": g["name"], "text": g.get("displayName") or g["name"], "count": len(g.get("subscriptions", []))}
              for g in governance.get("managementGroups", []) if g.get("name")]
    subscriptions = [{"value": s["id"], "text": s.get("name") or s["id"], "count": s.get("resourceCount", 0)} for s in summary.get("subscriptions", [])]

    def counted(extract, limit=300):
        counter = Counter(str(extract(r)) for r in rows if extract(r))
        return [{"value": v, "text": v, "count": c} for v, c in sorted(counter.items(), key=lambda item: (-item[1], item[0].lower()))[:limit]]

    tags = defaultdict(Counter)
    for row in rows:
        for key, value in row.get("tagList") or []:
            tags[str(key)][str(value)] += 1
    tag_options = [{"key": key, "count": sum(values.values()),
                    "values": [{"value": v, "count": c} for v, c in sorted(values.items(), key=lambda item: (-item[1], item[0]))[:50]]}
                   for key, values in sorted(tags.items(), key=lambda item: (-sum(item[1].values()), item[0]))[:60]]
    return {
        "fields": {
            "sub": {"label": FIELDS["sub"], "options": sorted(subscriptions, key=lambda o: o["text"].lower())},
            "mg": {"label": FIELDS["mg"], "options": sorted(groups, key=lambda o: str(o["text"]).lower())},
            "rg": {"label": FIELDS["rg"], "options": counted(lambda r: r.get("resourceGroup"))},
            "type": {"label": FIELDS["type"], "options": counted(lambda r: r.get("type"))},
            "loc": {"label": FIELDS["loc"], "options": counted(lambda r: r.get("location"))},
            "tag": {"label": FIELDS["tag"], "keys": tag_options},
        },
        "tagsAvailable": any(row.get("tagList") is not None for row in rows),
    }
