"""Identity posture from Microsoft Graph: Conditional Access, privileged directory roles, MFA registration, risky users and Entra's own
recommendations. Every part needs an optional Graph application permission on the collector's app registration and is reported as "not
available" when it is missing (some also need Entra ID P1 or P2). Only metadata is read.

Permissions: Policy.Read.All (Conditional Access, security defaults), RoleManagement.Read.Directory (role assignments and definitions),
RoleEligibilitySchedule.Read.Directory (PIM), Reports.Read.All and AuditLog.Read.All (MFA registration), IdentityRiskyUser.Read.All (risky users) and
DirectoryRecommendations.Read.All (Entra recommendations)."""
from .findings import make_finding

TENANT = "tenant"
MAX_FINDINGS_PER_RULE = 100
MAX_LIST = 25

PERMISSIONS = {"policies": "Policy.Read.All", "roles": "RoleManagement.Read.Directory", "eligible": "RoleEligibilitySchedule.Read.Directory",
               "mfa": "Reports.Read.All and AuditLog.Read.All", "risky": "IdentityRiskyUser.Read.All", "recommendations": "DirectoryRecommendations.Read.All"}

# rule id -> (severity, title, recommendation)
RULES = {
    "SEC-CA-001": ("high", "No enabled Conditional Access policy requires MFA for all users",
                   "Create a Conditional Access policy that requires multifactor authentication for all users and all cloud apps, with an exclusion only for break-glass accounts."),
    "SEC-CA-002": ("critical", "No enabled Conditional Access policy requires MFA for administrators",
                   "Require multifactor authentication for every directory role with a Conditional Access policy."),
    "SEC-CA-003": ("high", "Legacy authentication is not blocked by Conditional Access",
                   "Block legacy authentication (Exchange ActiveSync and other clients) with a Conditional Access policy: it cannot do MFA."),
    "SEC-CA-004": ("low", "Conditional Access policy is disabled or only reports",
                   "Enable the policy after checking its report-only results, or delete it if it is no longer needed."),
    "SEC-ROLE-001": ("high", "More than {limit} users or groups have Global Administrator", "Keep Global Administrator for as few accounts as possible and use narrower roles."),
    "SEC-ROLE-002": ("high", "Guest account has a privileged directory role: {name}", "Remove the privileged role from the guest, or make the assignment eligible and time-bound with PIM."),
    "SEC-ROLE-003": ("high", "Service principal has a privileged directory role: {name}", "Use a narrower role or a managed identity with the least privilege it needs."),
    "SEC-ROLE-004": ("medium", "Privileged directory roles are assigned permanently and PIM is not used",
                     "Use Privileged Identity Management to make privileged assignments eligible and time-bound."),
    "SEC-MFA-001": ("critical", "Administrator has no multifactor authentication method registered: {name}", "Register an MFA method for the administrator and enforce it with Conditional Access."),
    "SEC-MFA-002": ("medium", "Users have no multifactor authentication method registered", "Ask the users to register MFA and enforce it with a Conditional Access policy or a registration campaign."),
    "SEC-RISK-001": ("high", "User at high risk in Entra ID Protection: {name}", "Investigate the sign-ins, reset the credentials and confirm or dismiss the risk."),
    "SEC-RISK-002": ("medium", "User at medium risk in Entra ID Protection: {name}", "Investigate the sign-ins and confirm or dismiss the risk."),
    "SEC-RISK-003": ("low", "User at low risk in Entra ID Protection: {name}", "Review the risk detections and dismiss them if they are expected."),
    "SEC-ENTRA-001": ("high", "Entra recommendation (high priority): {name}", "Follow the recommendation in the Microsoft Entra admin center."),
    "SEC-ENTRA-002": ("medium", "Entra recommendation (medium priority): {name}", "Follow the recommendation in the Microsoft Entra admin center."),
    "SEC-ENTRA-003": ("low", "Entra recommendation (low priority): {name}", "Follow the recommendation in the Microsoft Entra admin center."),
}
RISK_RULES = {"high": "SEC-RISK-001", "medium": "SEC-RISK-002", "low": "SEC-RISK-003"}
RECOMMENDATION_RULES = {"high": "SEC-ENTRA-001", "medium": "SEC-ENTRA-002", "low": "SEC-ENTRA-003"}
GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10"
GLOBAL_ADMIN_LIMIT = 5

# built-in role template ids that can change who has access or what is protected
PRIVILEGED_ROLES = {
    GLOBAL_ADMINISTRATOR: "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
}
USER, SERVICE_PRINCIPAL, GROUP = "#microsoft.graph.user", "#microsoft.graph.servicePrincipal", "#microsoft.graph.group"


def _finding(run_id, rule, name="", resource_id="", resource_name="", resource_type="microsoft.graph/tenant", link=None, recommendation=None):
    severity, title, default = RULES[rule]
    return make_finding(run_id, rule_id=rule, source="entra", pillar="Security", severity=severity,
                        title=title.format(name=name, limit=GLOBAL_ADMIN_LIMIT), recommendation=recommendation or default,
                        resource_id=resource_id or f"/tenant/identity/{rule.lower()}", resource_name=resource_name or name or "Tenant",
                        resource_type=resource_type, subscription_id=TENANT, link=link)


def _stat(rule, affected, applicable):
    return {"ruleId": rule, "source": "entra", "pillar": "Security", "severity": RULES[rule][0], "subscriptionId": TENANT,
            "affected": affected, "applicable": applicable}


# --- Conditional Access -----------------------------------------------------------------------------------------

def _lower(values):
    return [str(v).lower() for v in values or []]


def evaluate_policies(run_id, policies, security_defaults=False):
    """(findings, stats, dataset) of the Conditional Access policies. With security defaults on, Microsoft already requires MFA and blocks
    legacy authentication, so those checks are skipped."""
    enabled = [p for p in policies if p.get("state") == "enabled"]
    inert = [p for p in policies if p.get("state") in ("disabled", "enabledForReportingButNotEnforced")]

    def controls(policy):
        grant = policy.get("grantControls") or {}
        return _lower(grant.get("builtInControls")), bool(grant.get("authenticationStrength"))

    def users(policy):
        return (policy.get("conditions") or {}).get("users") or {}

    def apps(policy):
        return _lower(((policy.get("conditions") or {}).get("applications") or {}).get("includeApplications"))

    mfa_all = any("all" in _lower(users(p).get("includeUsers")) and "all" in apps(p) and ("mfa" in controls(p)[0] or controls(p)[1]) for p in enabled)
    mfa_admins = any((users(p).get("includeRoles") or []) and ("mfa" in controls(p)[0] or controls(p)[1]) for p in enabled)
    legacy_blocked = any("block" in controls(p)[0] and {"exchangeactivesync", "other"} <= set(_lower((p.get("conditions") or {}).get("clientAppTypes")))
                         and "all" in _lower(users(p).get("includeUsers")) for p in enabled)
    findings, stats = [], []
    if not security_defaults:
        failing = [("SEC-CA-001", not mfa_all), ("SEC-CA-002", not mfa_all and not mfa_admins), ("SEC-CA-003", not legacy_blocked)]
        for rule, bad in failing:
            stats.append(_stat(rule, 1 if bad else 0, 1))
            if bad:
                findings.append(_finding(run_id, rule))
    for policy in inert[:MAX_FINDINGS_PER_RULE]:
        findings.append(_finding(run_id, "SEC-CA-004", name=policy.get("displayName", ""), resource_id=f"/tenant/conditionalaccess/{policy.get('id', '')}",
                                 resource_name=policy.get("displayName", ""), resource_type="microsoft.graph/conditionalaccesspolicy"))
    if policies:
        stats.append(_stat("SEC-CA-004", len(inert), len(policies)))
    dataset = {"total": len(policies), "enabled": len(enabled), "reportOnly": sum(1 for p in inert if p.get("state") == "enabledForReportingButNotEnforced"),
               "disabled": sum(1 for p in inert if p.get("state") == "disabled"), "securityDefaults": security_defaults,
               "mfaAllUsers": mfa_all, "mfaAdmins": mfa_admins, "legacyBlocked": legacy_blocked,
               "policies": [{"name": p.get("displayName", ""), "state": p.get("state", "")} for p in sorted(policies, key=lambda p: (p.get("state") != "enabled", p.get("displayName", "")))][:MAX_LIST]}
    return findings, stats, dataset


# --- directory roles ---------------------------------------------------------------------------------------------

def _principal(assignment):
    principal = assignment.get("principal") or {}
    kind = principal.get("@odata.type", "")
    upn = principal.get("userPrincipalName", "")
    return {"kind": kind, "name": principal.get("displayName") or upn or assignment.get("principalId", ""), "guest": "#ext#" in str(upn).lower(),
            "id": assignment.get("principalId", "")}


def evaluate_roles(run_id, assignments, definitions, eligible=None):
    """(findings, stats, dataset) from the active role assignments, the role names and, when readable, PIM's eligible assignments."""
    names = {d.get("id"): d.get("displayName", "") for d in definitions}
    findings, privileged, global_admins, by_role = [], [], [], {}
    for assignment in assignments:
        role_id = assignment.get("roleDefinitionId")
        if role_id not in PRIVILEGED_ROLES:
            continue
        who = _principal(assignment)
        role = names.get(role_id) or PRIVILEGED_ROLES[role_id]
        entry = {**who, "role": role}
        privileged.append(entry)
        by_role[role] = by_role.get(role, 0) + 1
        if role_id == GLOBAL_ADMINISTRATOR:
            global_admins.append(entry)
        label = f"{who['name']} ({role})"
        if who["kind"] == USER and who["guest"] and len([f for f in findings if f["ruleId"] == "SEC-ROLE-002"]) < MAX_FINDINGS_PER_RULE:
            findings.append(_finding(run_id, "SEC-ROLE-002", name=label, resource_id=f"/tenant/users/{who['id']}", resource_name=who["name"], resource_type="microsoft.graph/users"))
        elif who["kind"] == SERVICE_PRINCIPAL and len([f for f in findings if f["ruleId"] == "SEC-ROLE-003"]) < MAX_FINDINGS_PER_RULE:
            findings.append(_finding(run_id, "SEC-ROLE-003", name=label, resource_id=f"/tenant/serviceprincipals/{who['id']}", resource_name=who["name"],
                                     resource_type="microsoft.graph/serviceprincipals"))
    stats = [_stat("SEC-ROLE-002", sum(1 for f in findings if f["ruleId"] == "SEC-ROLE-002"), max(len(privileged), 1)) if privileged else None,
             _stat("SEC-ROLE-003", sum(1 for f in findings if f["ruleId"] == "SEC-ROLE-003"), max(len(privileged), 1)) if privileged else None]
    if len(global_admins) > GLOBAL_ADMIN_LIMIT:
        findings.append(_finding(run_id, "SEC-ROLE-001", recommendation=None))
    if privileged:
        stats.append(_stat("SEC-ROLE-001", 1 if len(global_admins) > GLOBAL_ADMIN_LIMIT else 0, 1))
    pim_unused = eligible is not None and not eligible and sum(1 for p in privileged if p["kind"] == USER) >= 3
    if pim_unused:
        findings.append(_finding(run_id, "SEC-ROLE-004"))
    if eligible is not None and privileged:
        stats.append(_stat("SEC-ROLE-004", 1 if pim_unused else 0, 1))
    dataset = {"privilegedAssignments": len(privileged), "globalAdministrators": len(global_admins), "byRole": by_role,
               "guests": sum(1 for p in privileged if p["kind"] == USER and p["guest"]), "servicePrincipals": sum(1 for p in privileged if p["kind"] == SERVICE_PRINCIPAL),
               "eligibleAssignments": None if eligible is None else len(eligible), "assignments": sorted(privileged, key=lambda p: (p["role"] != "Global Administrator", p["role"], p["name"]))[:MAX_LIST]}
    return findings, [s for s in stats if s], dataset


# --- MFA registration --------------------------------------------------------------------------------------------

def evaluate_mfa(run_id, users):
    """(findings, stats, dataset) from the user registration details: administrators without MFA are findings one by one, the rest of
    the members are counted in one finding."""
    findings, admins_without, members, without = [], [], 0, []
    for user in users:
        if str(user.get("userType", "member")).lower() == "guest":
            continue
        members += 1
        if user.get("isMfaRegistered"):
            continue
        without.append(user)
        if user.get("isAdmin"):
            admins_without.append(user)
    for user in admins_without[:MAX_FINDINGS_PER_RULE]:
        name = user.get("userDisplayName") or user.get("userPrincipalName", "")
        findings.append(_finding(run_id, "SEC-MFA-001", name=name, resource_id=f"/tenant/users/{user.get('id', '')}", resource_name=name, resource_type="microsoft.graph/users"))
    plain = [u for u in without if not u.get("isAdmin")]
    if plain:
        findings.append(_finding(run_id, "SEC-MFA-002", resource_name=f"{len(plain)} users",
                                 recommendation=f"{len(plain)} of {members} member users have no MFA method registered. " + RULES["SEC-MFA-002"][2]))
    stats = []
    if members:
        admins_total = sum(1 for u in users if u.get("isAdmin") and str(u.get("userType", "member")).lower() != "guest")
        if admins_total:
            stats.append(_stat("SEC-MFA-001", len(admins_without), admins_total))
        stats.append(_stat("SEC-MFA-002", len(plain), max(members - admins_total, 1)))
    dataset = {"members": members, "withoutMfa": len(without), "adminsWithoutMfa": len(admins_without),
               "registeredPercent": round(100 * (members - len(without)) / members, 1) if members else None,
               "adminsWithout": [{"name": u.get("userDisplayName") or u.get("userPrincipalName", ""), "upn": u.get("userPrincipalName", "")} for u in admins_without[:MAX_LIST]]}
    return findings, stats, dataset


# --- risky users and Entra recommendations ----------------------------------------------------------------------

def evaluate_risky(run_id, users):
    findings, by_level = [], {}
    for user in users:
        level = str(user.get("riskLevel", "")).lower()
        if level not in RISK_RULES or str(user.get("riskState", "")).lower() not in ("atrisk", "confirmedcompromised"):
            continue
        by_level[level] = by_level.get(level, 0) + 1
        if len(findings) < MAX_FINDINGS_PER_RULE * 3:
            name = user.get("userDisplayName") or user.get("userPrincipalName", "")
            findings.append(_finding(run_id, RISK_RULES[level], name=name, resource_id=f"/tenant/users/{user.get('id', '')}", resource_name=name,
                                     resource_type="microsoft.graph/users"))
    stats = [{**_stat(rule, by_level.get(level, 0), by_level.get(level, 0)), "applicable": None} for level, rule in RISK_RULES.items() if by_level.get(level)]
    return findings, stats, {"atRisk": sum(by_level.values()), "byLevel": by_level,
                             "users": [{"name": f["resourceName"], "level": f["severity"]} for f in findings[:MAX_LIST]]}


def evaluate_recommendations(run_id, recommendations):
    findings, by_priority = [], {}
    for item in recommendations:
        priority = str(item.get("priority", "")).lower()
        if str(item.get("status", "")).lower() != "active" or priority not in RECOMMENDATION_RULES:
            continue
        by_priority[priority] = by_priority.get(priority, 0) + 1
        name = item.get("displayName", "")
        findings.append(_finding(run_id, RECOMMENDATION_RULES[priority], name=name, resource_id=f"/tenant/recommendations/{item.get('id', '')}", resource_name=name,
                                 resource_type="microsoft.graph/recommendations", recommendation=(item.get("insights") or "").strip()[:300] or None))
    stats = [{**_stat(rule, by_priority.get(priority, 0), by_priority.get(priority, 0)), "applicable": None} for priority, rule in RECOMMENDATION_RULES.items() if by_priority.get(priority)]
    return findings[:MAX_FINDINGS_PER_RULE * 3], stats, {"active": sum(by_priority.values()), "byPriority": by_priority,
                                                         "items": [{"name": f["resourceName"], "priority": f["severity"]} for f in findings[:MAX_LIST]]}
