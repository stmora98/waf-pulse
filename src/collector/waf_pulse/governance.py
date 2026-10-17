"""Governance: management group hierarchy, policy, RBAC, locks and Defender plans, from Resource Graph (Reader).

Produces a dataset for the dashboard plus a few checks that feed the pillar scores.
"""
from datetime import datetime, timezone

from . import graph, rest
from .findings import make_finding

OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
MAX_OWNERS = 3
TOP = 10
MAX_ROWS = 20000
TENANT_ROOT = "tenant root group"

QUERIES = {
    "managementGroups": """
resourcecontainers
| where type =~ 'microsoft.management/managementgroups'
| project id, name, displayName = tostring(properties.displayName), parent = tostring(properties.details.parent.name)
""",
    "subscriptions": """
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, name, state = tostring(properties.state), chain = properties.managementGroupAncestorsChain
""",
    "assignments": """
policyresources
| where type =~ 'microsoft.authorization/policyassignments'
| project id, name, subscriptionId, displayName = tostring(properties.displayName),
          enforcement = tostring(properties.enforcementMode), scope = tostring(properties.scope)
""",
    "signals": """
resources
| where type in~ ('microsoft.network/azurefirewalls', 'microsoft.network/virtualnetworkgateways',
                  'microsoft.network/expressroutecircuits', 'microsoft.network/virtualhubs',
                  'microsoft.network/bastionhosts', 'microsoft.network/privatednszones',
                  'microsoft.network/ddosprotectionplans', 'microsoft.operationalinsights/workspaces',
                  'microsoft.automation/automationaccounts', 'microsoft.recoveryservices/vaults',
                  'microsoft.aad/domainservices', 'microsoft.operationsmanagement/solutions')
| summarize n = count() by subscriptionId, type = tolower(type)
""",
    "customDefinitions": """
policyresources
| where type =~ 'microsoft.authorization/policydefinitions'
| where tostring(properties.policyType) =~ 'Custom'
| summarize count_ = count()
""",
    "compliance": """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend assignment = tostring(properties.policyAssignmentId), state = tostring(properties.complianceState)
| summarize nonCompliant = countif(state =~ 'NonCompliant'), total = count() by assignment, subscriptionId
""",
    "exemptions": """
policyresources
| where type =~ 'microsoft.authorization/policyexemptions'
| project id, name, subscriptionId, displayName = tostring(properties.displayName),
          category = tostring(properties.exemptionCategory), expiresOn = tostring(properties.expiresOn)
""",
    "rolesByPrincipal": """
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| summarize count_ = count() by subscriptionId, principalType = tostring(properties.principalType)
""",
    "owners": f"""
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| where tolower(tostring(properties.roleDefinitionId)) endswith '{OWNER_ROLE_ID}'
| where tolower(tostring(properties.scope)) == strcat('/subscriptions/', tolower(subscriptionId))
| summarize owners = count() by subscriptionId
""",
    "customRoles": """
authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| where tostring(properties.type) =~ 'CustomRole'
| summarize count_ = count()
""",
    "locks": """
resources
| where type =~ 'microsoft.authorization/locks'
| summarize locks = count() by subscriptionId
""",
    "defender": """
securityresources
| where type =~ 'microsoft.security/pricings'
| project subscriptionId, plan = name, tier = tostring(properties.pricingTier), subPlan = tostring(properties.subPlan)
""",
}


GROUP_SCOPE = "/providers/microsoft.management/managementgroups/"
MAX_ASSIGNMENTS_PER_GROUP = 60


def policy_by_group(assignments):
    """Names of the policy assignments made at each management group: {group name (lower): [assignment names]}.
    The names are how a landing zone is recognized when its groups are not called what the reference calls them."""
    result = {}
    for item in assignments:
        scope = str(item.get("scope", "")).lower()
        if GROUP_SCOPE not in scope:
            continue
        group = scope.split(GROUP_SCOPE, 1)[1].strip("/").split("/")[0]
        names = result.setdefault(group, [])
        for name in (item.get("name"), item.get("displayName")):
            if name and name not in names and len(names) < MAX_ASSIGNMENTS_PER_GROUP:
                names.append(str(name))
    return result


def subscription_signals(rows):
    """Count of the resource types that hint at what a subscription is for: {subscription: {type: count}}."""
    result = {}
    for row in rows:
        sub = _sub(row)
        if sub:
            result.setdefault(sub, {})[str(row.get("type", "")).lower()] = int(row.get("n", 0))
    return result

def _sub(row):
    return str(row.get("subscriptionId", "")).lower()


def _last(value):
    return str(value or "").rstrip("/").rsplit("/", 1)[-1]


def management_groups(subscription_rows, group_rows):
    """Builds the hierarchy from the ancestors chain of every subscription, plus the groups that are visible."""
    nodes = {}

    def node(name, display=None):
        item = nodes.setdefault(name, {"name": name, "displayName": display or name, "parent": None, "subscriptions": []})
        if display:
            item["displayName"] = display
        return item

    for row in group_rows:
        item = node(row["name"], row.get("displayName"))
        if row.get("parent") and row["parent"] != row["name"]:
            item["parent"] = row["parent"]
            node(row["parent"])

    subscriptions = []
    for row in subscription_rows:
        chain = list(row.get("chain") or [])
        # The chain is ordered from the root to the parent, or the other way round. The tenant root group
        # is recognisable by its display name.
        if chain and str(chain[0].get("displayName", "")).lower() != TENANT_ROOT and str(
            chain[-1].get("displayName", "")
        ).lower() == TENANT_ROOT:
            chain.reverse()
        for parent, child in zip(chain, chain[1:]):
            node(parent["name"], parent.get("displayName"))
            node(child["name"], child.get("displayName"))["parent"] = parent["name"]
        if chain:
            node(chain[-1]["name"], chain[-1].get("displayName"))["subscriptions"].append(_sub(row))
        subscriptions.append(
            {"id": _sub(row), "name": row.get("name", ""), "state": row.get("state", ""),
             "path": [item.get("displayName") or item["name"] for item in chain]}
        )
    return sorted(nodes.values(), key=lambda item: (item["parent"] or "", item["displayName"])), subscriptions


def _expired(expires_on, now):
    try:
        parsed = datetime.fromisoformat(str(expires_on).replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed < now


def evaluate(run_id, results, now=None):
    """results: {query name: rows}. Returns (findings, stats, dataset)."""
    now = now or datetime.now(timezone.utc)
    findings, stats = [], []
    groups, subscriptions = management_groups(results.get("subscriptions", []), results.get("managementGroups", []))
    enabled = [sub for sub in subscriptions if str(sub["state"]).lower() in ("enabled", "")]

    def stat(rule, pillar, severity, sub, affected, applicable):
        stats.append(
            {"ruleId": rule, "source": "governance", "pillar": pillar, "severity": severity, "subscriptionId": sub,
             "affected": affected, "applicable": applicable}
        )

    def finding(rule, pillar, severity, title, recommendation, resource_id, sub, name=""):
        findings.append(
            make_finding(run_id, rule_id=rule, source="governance", pillar=pillar, severity=severity, title=title,
                         recommendation=recommendation, resource_id=resource_id, resource_name=name,
                         subscription_id=sub)
        )

    # Owners: more than MAX_OWNERS owners at subscription scope widens the blast radius of a compromised account.
    owners = {_sub(row): int(row.get("owners", 0)) for row in results.get("owners", [])}
    for sub in enabled:
        count = owners.get(sub["id"], 0)
        stat("GOV-RBAC-001", "Security", "medium", sub["id"], 1 if count > MAX_OWNERS else 0, 1)
        if count > MAX_OWNERS:
            finding("GOV-RBAC-001", "Security", "medium", f"Subscription has {count} owners (more than {MAX_OWNERS})",
                    "Reduce the number of Owner assignments and use more specific roles or Privileged Identity Management.",
                    f"/subscriptions/{sub['id']}", sub["id"], sub["name"])

    # Locks: a subscription without any lock has no protection against accidental deletion.
    locks = {_sub(row): int(row.get("locks", 0)) for row in results.get("locks", [])}
    for sub in enabled:
        missing = locks.get(sub["id"], 0) == 0
        stat("GOV-LOCK-001", "Operational Excellence", "low", sub["id"], 1 if missing else 0, 1)
        if missing:
            finding("GOV-LOCK-001", "Operational Excellence", "low", "Subscription has no resource locks",
                    "Apply CanNotDelete locks to critical resource groups and resources.",
                    f"/subscriptions/{sub['id']}", sub["id"], sub["name"])

    # Policy compliance: one statistics row per subscription, one finding per non-compliant assignment.
    assignments = {str(row.get("id", "")).lower(): row for row in results.get("assignments", [])}
    compliance = results.get("compliance", [])
    per_sub = {}
    for row in compliance:
        bad, total = per_sub.get(_sub(row), (0, 0))
        per_sub[_sub(row)] = (bad + int(row.get("nonCompliant", 0)), total + int(row.get("total", 0)))
    for sub, (bad, total) in per_sub.items():
        stat("GOV-POL-001", "Operational Excellence", "medium", sub, bad, max(total, bad))
    top_non_compliant = []
    for row in sorted(compliance, key=lambda r: int(r.get("nonCompliant", 0)), reverse=True):
        if int(row.get("nonCompliant", 0)) <= 0:
            continue
        assignment = assignments.get(str(row.get("assignment", "")).lower(), {})
        label = assignment.get("displayName") or _last(row.get("assignment"))
        top_non_compliant.append({"assignment": label, "nonCompliant": int(row["nonCompliant"]), "total": int(row["total"]),
                                  "subscriptionId": _sub(row)})
        if len(findings) < 5000:
            finding("GOV-POL-001", "Operational Excellence", "medium",
                    f"Policy '{label}' has {row['nonCompliant']} non-compliant resources",
                    "Review the non-compliant resources and remediate them or adjust the policy.",
                    row.get("assignment", ""), _sub(row), label)

    # Exemptions without an expiry date, or already expired, silently weaken the policy.
    exemptions = results.get("exemptions", [])
    expired = [e for e in exemptions if _expired(e.get("expiresOn", ""), now)]
    no_expiry = [e for e in exemptions if not e.get("expiresOn")]
    by_sub_exemptions = {}
    for item in exemptions:
        by_sub_exemptions.setdefault(_sub(item), []).append(item)
    for sub, items in by_sub_exemptions.items():
        risky = [e for e in items if not e.get("expiresOn") or _expired(e.get("expiresOn", ""), now)]
        stat("GOV-POL-002", "Operational Excellence", "low", sub, len(risky), len(items))
        for item in risky:
            finding("GOV-POL-002", "Operational Excellence", "low",
                    "Policy exemption has expired" if item.get("expiresOn") else "Policy exemption has no expiry date",
                    "Set an expiry date on the exemption, or remove it when it is no longer needed.",
                    item.get("id", ""), sub, item.get("displayName") or item.get("name", ""))

    # Defender for Cloud plans that are not enabled.
    plans = results.get("defender", [])
    plans_by_sub = {}
    for plan in plans:
        plans_by_sub.setdefault(_sub(plan), []).append(plan)
    for sub, items in plans_by_sub.items():
        free = [p for p in items if str(p.get("tier", "")).lower() == "free"]
        stat("GOV-DEF-001", "Security", "medium", sub, len(free), len(items))
        for item in free:
            finding("GOV-DEF-001", "Security", "medium", f"Defender for Cloud plan '{item.get('plan')}' is not enabled",
                    "Enable the Defender plan for the workloads that need protection.",
                    f"/subscriptions/{sub}/providers/Microsoft.Security/pricings/{item.get('plan')}", sub, item.get("plan", ""))

    principal_types = {}
    for row in results.get("rolesByPrincipal", []):
        key = row.get("principalType") or "Unknown"
        principal_types[key] = principal_types.get(key, 0) + int(row.get("count_", 0))

    dataset = {
        "managementGroups": groups,
        "subscriptions": subscriptions,
        "policyByGroup": policy_by_group(assignments.values()),
        "signals": subscription_signals(results.get("signals", [])),
        "policy": {
            "assignments": len(assignments),
            "notEnforced": sum(1 for a in assignments.values() if str(a.get("enforcement", "")).lower() == "donotenforce"),
            "customDefinitions": sum(int(r.get("count_", 0)) for r in results.get("customDefinitions", [])),
            "exemptions": len(exemptions),
            "expiredExemptions": len(expired),
            "exemptionsWithoutExpiry": len(no_expiry),
            "nonCompliantResources": sum(bad for bad, _ in per_sub.values()),
            "topNonCompliant": top_non_compliant[:TOP],
        },
        "rbac": {
            "assignments": sum(principal_types.values()),
            "byPrincipalType": principal_types,
            "customRoles": sum(int(r.get("count_", 0)) for r in results.get("customRoles", [])),
            "owners": [{"subscriptionId": sub, "owners": count} for sub, count in sorted(owners.items(), key=lambda i: -i[1])[:TOP]],
        },
        "locks": {
            "total": sum(locks.values()),
            "subscriptionsWithoutLocks": [sub["id"] for sub in enabled if locks.get(sub["id"], 0) == 0][:50],
        },
        "defender": {
            "plans": len(plans),
            "enabled": sum(1 for p in plans if str(p.get("tier", "")).lower() != "free"),
            "notEnabled": sorted({p.get("plan", "") for p in plans if str(p.get("tier", "")).lower() == "free"}),
            "detail": sorted(
                ({"plan": p.get("plan", ""), "tier": p.get("tier", ""), "subPlan": p.get("subPlan", ""),
                  "subscriptionId": _sub(p)} for p in plans),
                key=lambda p: (str(p["tier"]).lower() == "free", p["plan"], p["subscriptionId"]))[:1500],
        },
    }
    return findings, stats, dataset


PRICING_API = "2024-01-01"
PRICING_WORKERS = 4


def parse_pricings(body, subscription):
    """Defender for Cloud plans from the ARM pricings API: [{subscriptionId, plan, tier, subPlan}]."""
    return [{"subscriptionId": subscription, "plan": item.get("name", ""),
             "tier": (item.get("properties") or {}).get("pricingTier", ""),
             "subPlan": (item.get("properties") or {}).get("subPlan") or ""}
            for item in (body or {}).get("value", [])]


def fetch_pricings(credential, subscription_ids):
    """Resource Graph does not always carry the Defender plans, so they are also read from ARM (Reader is enough).
    Returns (rows, errors); a subscription that cannot be read is reported and skipped."""
    from concurrent.futures import ThreadPoolExecutor

    token = credential.get_token("https://management.azure.com/.default").token
    errors = []

    def read(sub):
        try:
            response = rest.get(f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Security/pricings",
                                token, {"api-version": PRICING_API})
        except Exception:
            return sub, None
        return sub, parse_pricings(response.json(), sub) if response.status_code == 200 else None

    rows = []
    with ThreadPoolExecutor(max_workers=PRICING_WORKERS) as pool:
        for sub, items in pool.map(read, subscription_ids):
            if items is None:
                errors.append({"ruleId": "governance-defender-arm", "error": f"Defender plans of {sub} could not be read."})
            else:
                rows.extend(items)
    return rows, errors[:5]


def collect(credential, run_id, subscription_ids):
    """Runs every governance query over all subscriptions. A query that fails is reported, not raised."""
    results, errors = {}, []
    for name, kql in QUERIES.items():
        rows = []
        try:
            for chunk in graph.chunks(subscription_ids):
                rows.extend(graph.query(credential, chunk, kql, max_rows=MAX_ROWS))
        except Exception as exc:
            errors.append({"ruleId": f"governance-{name}", "error": str(exc).splitlines()[0][:200]})
        results[name] = rows
    if not results.get("defender"):
        try:
            results["defender"], pricing_errors = fetch_pricings(credential, subscription_ids)
            errors.extend(pricing_errors)
        except Exception as exc:
            errors.append({"ruleId": "governance-defender-arm", "error": str(exc).splitlines()[0][:200]})
    findings, stats, dataset = evaluate(run_id, results)
    return findings, stats, dataset, errors
