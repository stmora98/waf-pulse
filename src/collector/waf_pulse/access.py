"""Access and policy posture from Resource Graph (Reader is enough): who has the powerful Azure roles and at what level, custom roles
that allow everything, policy compliance by assignment and the resources that are not compliant, and policy exemptions that
expired. Names of identities are not in Resource Graph (they are in Microsoft Entra), so people and applications show by object id.

Findings go through the normal rule statistics. The rows behind the Access tab are kept apart from the summary."""
from collections import Counter, defaultdict

from . import graph
from .findings import make_finding

SOURCE = "access"
MAX_ROWS = 3000
MAX_RBAC_ROWS = 300
MAX_POLICY_ROWS = 150
MAX_NONCOMPLIANT = 500
MAX_EXEMPTIONS = 100
OWNER_LIMIT = 3

OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
USER_ACCESS_ADMIN = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
RBAC_ADMIN = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
ROLE_NAMES = {OWNER: "Owner", USER_ACCESS_ADMIN: "User Access Administrator", RBAC_ADMIN: "Role Based Access Control Administrator", CONTRIBUTOR: "Contributor"}
CONTROL_ROLES = (OWNER, USER_ACCESS_ADMIN, RBAC_ADMIN)  # roles that can give access to others

# rule id -> (severity, title, recommendation)
RULES = {
    "SEC-RBAC-001": ("high", "{role} is assigned directly to a user at {level} scope", "Assign the role to a group and make the assignment eligible and time-bound with PIM."),
    "SEC-RBAC-002": ("high", "A service principal has {role} at {level} scope", "Give the application a narrower role at the scope it needs, or use a managed identity."),
    "SEC-RBAC-003": ("medium", "Subscription has more than " + str(OWNER_LIMIT) + " owners", "Keep the Owner role for as few identities as possible and use narrower roles."),
    "SEC-RBAC-004": ("high", "Custom role allows every action: {name}", "Narrow the role to the actions its holders need."),
    "SEC-POL-001": ("medium", "Resource is not compliant with policy assignment {name}", "Fix the resource or request an exemption with an expiry date if the deviation is accepted."),
    "SEC-POL-002": ("low", "Policy exemption has expired: {name}", "Remove the exemption or renew it with a new expiry date and a reason."),
}

QUERIES = {
    "rbac": f"""
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend roleId = tolower(tostring(split(tostring(properties.roleDefinitionId), '/')[-1])), scope = tostring(properties.scope),
    principalType = tostring(properties.principalType)
| where roleId in ('{OWNER}', '{USER_ACCESS_ADMIN}', '{RBAC_ADMIN}', '{CONTRIBUTOR}')
| extend level = iff(scope startswith '/providers/microsoft.management', 'management group',
    iff(scope matches regex '^/subscriptions/[^/]+$', 'subscription', iff(scope matches regex '^/subscriptions/[^/]+/resourcegroups/[^/]+$', 'resource group', 'resource')))
| project subscriptionId, roleId, scope, principalType, principalId = tostring(properties.principalId), level, createdOn = tostring(properties.createdOn)
""",
    "customRoles": """
authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| where tostring(properties.type) =~ 'CustomRole'
| mv-expand permission = properties.permissions
| mv-expand action = permission.actions
| where tostring(action) == '*'
| extend scopes = properties.assignableScopes
| project id, name = tostring(properties.roleName), assignable = tostring(scopes[0])
""",
    "policyByAssignment": """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend state = tostring(properties.complianceState)
| summarize nonCompliant = countif(state =~ 'NonCompliant'), compliant = countif(state =~ 'Compliant'), exempt = countif(state =~ 'Exempt')
    by assignment = tostring(properties.policyAssignmentName), initiative = tostring(properties.policySetDefinitionName), subscriptionId
| order by nonCompliant desc
""",
    "nonCompliant": """
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| where tostring(properties.complianceState) =~ 'NonCompliant'
| project id = tostring(properties.resourceId), subscriptionId, assignment = tostring(properties.policyAssignmentName),
    definition = tostring(properties.policyDefinitionName), action = tostring(properties.policyDefinitionAction), type = tolower(tostring(properties.resourceType))
""",
    "exemptions": """
policyresources
| where type =~ 'microsoft.authorization/policyexemptions'
| project id, name, subscriptionId, displayName = tostring(properties.displayName), category = tostring(properties.exemptionCategory),
    expiresOn = tostring(properties.expiresOn), assignment = tostring(properties.policyAssignmentId)
""",
}


def _sub_of_scope(scope):
    parts = str(scope).lower().split("/")
    return parts[2] if len(parts) > 2 and parts[1] == "subscriptions" else ""


def _expired(expires_on, today):
    return bool(expires_on) and str(expires_on)[:10] < today


def evaluate_rbac(run_id, assignments, custom_roles):
    """(findings, stats, rows, dataset) of the powerful role assignments and the custom roles that allow everything."""
    findings, rows, owners = [], [], Counter()
    per_sub = defaultdict(Counter)
    for item in assignments:
        sub = str(item.get("subscriptionId", "")).lower()
        role = ROLE_NAMES.get(str(item.get("roleId", "")).lower(), "Role")
        kind, level, scope = item.get("principalType", ""), item.get("level", ""), item.get("scope", "")
        per_sub[sub]["assignments"] += 1
        if item["roleId"] == OWNER and level == "subscription":
            owners[sub] += 1
        wide = level in ("subscription", "management group")
        rule = None
        if item["roleId"] in CONTROL_ROLES and wide and kind == "User":
            rule = "SEC-RBAC-001"
        elif item["roleId"] in CONTROL_ROLES and wide and kind == "ServicePrincipal":
            rule = "SEC-RBAC-002"
        if len(rows) < MAX_RBAC_ROWS and (rule or item["roleId"] in CONTROL_ROLES):
            rows.append({"t": "rbac", "id": scope, "subscriptionId": sub, "role": role, "principalType": kind, "principalId": item.get("principalId", ""),
                         "level": level, "createdOn": str(item.get("createdOn", ""))[:10], "flag": rule or ""})
        if rule:
            per_sub[sub][rule] += 1
            _, title, recommendation = RULES[rule]
            findings.append(make_finding(
                run_id, rule_id=rule, source=SOURCE, pillar="Security", severity=RULES[rule][0], title=title.format(role=role, level=level), recommendation=recommendation,
                resource_id=f"{scope}/providers/microsoft.authorization/roleassignments/{item.get('principalId', '')}-{item['roleId'][:8]}",
                resource_name=f"{role} · {item.get('principalId', '')}", resource_type="microsoft.authorization/roleassignments", subscription_id=sub))
    for sub, count in owners.items():
        if count > OWNER_LIMIT:
            per_sub[sub]["SEC-RBAC-003"] = 1
            findings.append(make_finding(run_id, rule_id="SEC-RBAC-003", source=SOURCE, pillar="Security", severity=RULES["SEC-RBAC-003"][0],
                                         title=f"Subscription has {count} owners (more than {OWNER_LIMIT})", recommendation=RULES["SEC-RBAC-003"][2],
                                         resource_id=f"/subscriptions/{sub}", resource_name=f"{count} owners", resource_type="microsoft.resources/subscriptions", subscription_id=sub))
    for role in custom_roles:
        sub = _sub_of_scope(role.get("assignable"))
        per_sub[sub or "tenant"]["SEC-RBAC-004"] += 1
        findings.append(make_finding(run_id, rule_id="SEC-RBAC-004", source=SOURCE, pillar="Security", severity=RULES["SEC-RBAC-004"][0],
                                     title=RULES["SEC-RBAC-004"][1].format(name=role.get("name", "")), recommendation=RULES["SEC-RBAC-004"][2], resource_id=role["id"],
                                     resource_name=role.get("name", ""), resource_type="microsoft.authorization/roledefinitions", subscription_id=sub or "tenant"))
    stats = []
    for sub, counts in per_sub.items():
        for rule in ("SEC-RBAC-001", "SEC-RBAC-002"):
            if counts[rule]:
                stats.append({"ruleId": rule, "source": SOURCE, "pillar": "Security", "severity": RULES[rule][0], "subscriptionId": sub,
                              "affected": counts[rule], "applicable": counts["assignments"]})
        if counts["SEC-RBAC-003"]:
            stats.append({"ruleId": "SEC-RBAC-003", "source": SOURCE, "pillar": "Security", "severity": "medium", "subscriptionId": sub, "affected": 1, "applicable": 1})
        if counts["SEC-RBAC-004"]:
            stats.append({"ruleId": "SEC-RBAC-004", "source": SOURCE, "pillar": "Security", "severity": "high", "subscriptionId": sub, "affected": counts["SEC-RBAC-004"],
                          "applicable": counts["SEC-RBAC-004"], "applicableTypes": []})
    dataset = {"powerfulAssignments": len(assignments), "owners": sum(owners.values()), "ownerSubscriptions": sum(1 for c in owners.values() if c > OWNER_LIMIT),
               "usersWithControlRoles": sum(1 for a in assignments if a["roleId"] in CONTROL_ROLES and a.get("principalType") == "User"),
               "servicePrincipalsWithControlRoles": sum(1 for a in assignments if a["roleId"] in CONTROL_ROLES and a.get("principalType") == "ServicePrincipal"),
               "customRolesWithWildcard": len(custom_roles)}
    return findings, stats, rows, dataset


def evaluate_policy(run_id, by_assignment, noncompliant, exemptions, today):
    """(findings, stats, rows, dataset) of the policy compliance and the exemptions that expired."""
    findings, rows = [], []
    per_sub = defaultdict(lambda: Counter())
    for item in by_assignment:
        sub = str(item.get("subscriptionId", "")).lower()
        per_sub[sub]["noncompliant"] += item.get("nonCompliant") or 0
        per_sub[sub]["evaluated"] += (item.get("nonCompliant") or 0) + (item.get("compliant") or 0)
        per_sub[sub]["exempt"] += item.get("exempt") or 0
        if len(rows) < MAX_POLICY_ROWS and (item.get("nonCompliant") or item.get("compliant")):
            rows.append({"t": "policy", "subscriptionId": sub, "assignment": item.get("assignment", ""), "initiative": item.get("initiative") or "",
                         "nonCompliant": item.get("nonCompliant") or 0, "compliant": item.get("compliant") or 0, "exempt": item.get("exempt") or 0})
    seen = set()
    for item in noncompliant:
        key = (str(item.get("id", "")).lower(), item.get("assignment"))
        if not item.get("id") or key in seen or len(findings) >= MAX_NONCOMPLIANT:
            continue
        seen.add(key)
        sub = str(item.get("subscriptionId", "")).lower()
        findings.append(make_finding(
            run_id, rule_id="SEC-POL-001", source=SOURCE, pillar="Security", severity="medium", title=RULES["SEC-POL-001"][1].format(name=item.get("assignment", "")),
            recommendation=RULES["SEC-POL-001"][2], resource_id=item["id"], resource_name=str(item["id"]).rstrip("/").rsplit("/", 1)[-1],
            resource_type=item.get("type") or "", subscription_id=sub))
        rows.append({"t": "noncompliant", "id": item["id"], "subscriptionId": sub, "assignment": item.get("assignment", ""), "definition": item.get("definition", ""),
                     "action": item.get("action", ""), "type": item.get("type", "")})
    expired = [e for e in exemptions if _expired(e.get("expiresOn"), today)]
    no_expiry = [e for e in exemptions if not e.get("expiresOn")]
    for item in exemptions:
        sub = str(item.get("subscriptionId", "")).lower()
        is_expired = _expired(item.get("expiresOn"), today)
        if len([r for r in rows if r["t"] == "exemption"]) < MAX_EXEMPTIONS:
            rows.append({"t": "exemption", "id": item.get("id", ""), "subscriptionId": sub, "name": item.get("displayName") or item.get("name", ""), "category": item.get("category", ""),
                         "expiresOn": str(item.get("expiresOn") or "")[:10], "expired": is_expired})
        if is_expired:
            findings.append(make_finding(run_id, rule_id="SEC-POL-002", source=SOURCE, pillar="Security", severity="low", title=RULES["SEC-POL-002"][1].format(name=item.get("displayName") or item.get("name", "")),
                                         recommendation=RULES["SEC-POL-002"][2], resource_id=item["id"], resource_name=item.get("displayName") or item.get("name", ""),
                                         resource_type="microsoft.authorization/policyexemptions", subscription_id=sub))
    stats = []
    for sub, counts in per_sub.items():
        affected = sum(1 for f in findings if f["ruleId"] == "SEC-POL-001" and str(f.get("subscriptionId", "")).lower() == sub)
        if counts["evaluated"]:
            stats.append({"ruleId": "SEC-POL-001", "source": SOURCE, "pillar": "Security", "severity": "medium", "subscriptionId": sub,
                          "affected": min(affected, counts["evaluated"]), "applicable": counts["evaluated"]})
    exemption_subs = Counter(str(e.get("subscriptionId", "")).lower() for e in exemptions)
    for sub, total in exemption_subs.items():
        stats.append({"ruleId": "SEC-POL-002", "source": SOURCE, "pillar": "Security", "severity": "low", "subscriptionId": sub,
                      "affected": sum(1 for e in expired if str(e.get("subscriptionId", "")).lower() == sub), "applicable": total})
    totals = Counter()
    for counts in per_sub.values():
        totals.update(counts)
    dataset = {"nonCompliant": totals["noncompliant"], "evaluated": totals["evaluated"], "exempt": totals["exempt"], "assignments": len(by_assignment),
               "exemptions": len(exemptions), "expiredExemptions": len(expired), "exemptionsWithoutExpiry": len(no_expiry)}
    return findings, stats, rows, dataset


def collect(credential, run_id, subscription_ids, today):
    """Returns (findings, stats, dataset, rows, errors). `today` is an ISO date."""
    errors, results = [], {}
    for name, kql in QUERIES.items():
        rows = []
        try:
            for chunk in graph.chunks(subscription_ids):
                rows.extend(graph.query(credential, chunk, kql, max_rows=MAX_ROWS))
            results[name] = rows[:MAX_ROWS]
        except Exception as exc:
            errors.append({"ruleId": f"access-{name}", "error": str(exc).splitlines()[0][:200]})
            results[name] = None
    rbac_findings, rbac_stats, rbac_rows, rbac_data = evaluate_rbac(run_id, results["rbac"] or [], results["customRoles"] or [])
    policy_findings, policy_stats, policy_rows, policy_data = evaluate_policy(run_id, results["policyByAssignment"] or [], results["nonCompliant"] or [], results["exemptions"] or [], today)
    dataset = {"rbac": rbac_data, "policy": policy_data, "available": {"rbac": results["rbac"] is not None, "policy": results["policyByAssignment"] is not None}}
    return rbac_findings + policy_findings, rbac_stats + policy_stats, dataset, rbac_rows + policy_rows, errors
