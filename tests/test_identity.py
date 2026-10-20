from waf_pulse import entra, identity

GA = identity.GLOBAL_ADMINISTRATOR
SEC_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
READER = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"


def policy(name="p", state="enabled", users=("All",), roles=(), apps=("All",), controls=("mfa",), client_types=("all",), strength=False):
    grant = {"operator": "OR", "builtInControls": list(controls)}
    if strength:
        grant["authenticationStrength"] = {"id": "x"}
    return {"id": name, "displayName": name, "state": state, "grantControls": grant,
            "conditions": {"users": {"includeUsers": list(users), "includeRoles": list(roles)}, "applications": {"includeApplications": list(apps)}, "clientAppTypes": list(client_types)}}


# --- Conditional Access ---------------------------------------------------------------------------------------

def rules(findings):
    return sorted(f["ruleId"] for f in findings)


def test_a_tenant_without_policies_fails_the_three_checks():
    findings, stats, dataset = identity.evaluate_policies("r", [])
    assert rules(findings) == ["SEC-CA-001", "SEC-CA-002", "SEC-CA-003"] and findings[0]["subscriptionId"] == "tenant" and findings[0]["source"] == "entra"
    assert {(s["ruleId"], s["affected"], s["applicable"]) for s in stats} == {("SEC-CA-001", 1, 1), ("SEC-CA-002", 1, 1), ("SEC-CA-003", 1, 1)}
    assert dataset["total"] == 0 and dataset["mfaAllUsers"] is False


def test_good_policies_pass_and_the_stats_still_count_the_passes():
    policies = [policy("mfa-all"), policy("block-legacy", users=("All",), controls=("block",), client_types=("exchangeActiveSync", "other"), apps=("All",))]
    findings, stats, dataset = identity.evaluate_policies("r", policies)
    assert findings == [] and {(s["ruleId"], s["affected"]) for s in stats} == {("SEC-CA-001", 0), ("SEC-CA-002", 0), ("SEC-CA-003", 0), ("SEC-CA-004", 0)}
    assert dataset["mfaAllUsers"] and dataset["legacyBlocked"] and dataset["enabled"] == 2


def test_admin_only_mfa_is_critical_free_but_not_enough_for_all_users():
    findings, _, dataset = identity.evaluate_policies("r", [policy("admins", users=("None",), roles=(GA,), controls=("mfa",))])
    assert rules(findings) == ["SEC-CA-001", "SEC-CA-003"] and dataset["mfaAdmins"] is True
    strength, _, data = identity.evaluate_policies("r", [policy("strength", controls=(), strength=True)])
    assert data["mfaAllUsers"] is True and "SEC-CA-001" not in rules(strength)


def test_disabled_and_report_only_policies_are_listed_and_do_not_count_as_protection():
    policies = [policy("mfa-all", state="enabledForReportingButNotEnforced"), policy("off", state="disabled")]
    findings, stats, dataset = identity.evaluate_policies("r", policies)
    assert rules(findings).count("SEC-CA-004") == 2 and "SEC-CA-001" in rules(findings)
    assert dataset["reportOnly"] == 1 and dataset["disabled"] == 1 and [p["name"] for p in dataset["policies"]] == ["mfa-all", "off"]
    assert any(s["ruleId"] == "SEC-CA-004" and s["affected"] == 2 and s["applicable"] == 2 for s in stats)


def test_security_defaults_replace_the_policy_checks():
    findings, stats, dataset = identity.evaluate_policies("r", [], security_defaults=True)
    assert findings == [] and stats == [] and dataset["securityDefaults"] is True


# --- roles ----------------------------------------------------------------------------------------------------------

def assignment(role, kind="#microsoft.graph.user", name="Ana", upn="ana@x.com", pid="1"):
    return {"roleDefinitionId": role, "principalId": pid, "principal": {"@odata.type": kind, "displayName": name, "userPrincipalName": upn}}


DEFINITIONS = [{"id": GA, "displayName": "Global Administrator"}, {"id": SEC_ADMIN, "displayName": "Security Administrator"}, {"id": READER, "displayName": "Global Reader"}]


def test_roles_flag_guests_service_principals_and_too_many_global_administrators():
    assignments = [assignment(GA, pid=str(i), name=f"u{i}", upn=f"u{i}@x.com") for i in range(6)]
    assignments += [assignment(SEC_ADMIN, name="Ext", upn="ext_gmail.com#EXT#@x.onmicrosoft.com", pid="g"), assignment(SEC_ADMIN, kind="#microsoft.graph.servicePrincipal", name="deploy-app", upn="", pid="s"),
                    assignment(READER, name="reader", pid="r")]
    findings, stats, dataset = identity.evaluate_roles("r", assignments, DEFINITIONS, eligible=[{"id": 1}])
    assert rules(findings) == ["SEC-ROLE-001", "SEC-ROLE-002", "SEC-ROLE-003"]
    guest = next(f for f in findings if f["ruleId"] == "SEC-ROLE-002")
    assert "Ext" in guest["title"] and "Security Administrator" in guest["title"] and guest["resourceId"] == "/tenant/users/g"
    assert dataset["globalAdministrators"] == 6 and dataset["privilegedAssignments"] == 8 and dataset["guests"] == 1 and dataset["servicePrincipals"] == 1
    assert dataset["byRole"] == {"Global Administrator": 6, "Security Administrator": 2} and dataset["eligibleAssignments"] == 1 and dataset["assignments"][0]["role"] == "Global Administrator"
    assert {(s["ruleId"], s["affected"]) for s in stats} >= {("SEC-ROLE-001", 1), ("SEC-ROLE-002", 1), ("SEC-ROLE-003", 1)}


def test_five_global_administrators_are_fine_and_pim_unused_is_only_judged_when_readable():
    assignments = [assignment(GA, pid=str(i), name=f"u{i}", upn=f"u{i}@x.com") for i in range(5)]
    findings, stats, dataset = identity.evaluate_roles("r", assignments, DEFINITIONS, eligible=None)
    assert findings == [] and dataset["eligibleAssignments"] is None and ("SEC-ROLE-004" not in {s["ruleId"] for s in stats})
    findings, stats, _ = identity.evaluate_roles("r", assignments, DEFINITIONS, eligible=[])
    assert rules(findings) == ["SEC-ROLE-004"] and any(s["ruleId"] == "SEC-ROLE-004" and s["affected"] == 1 for s in stats)
    assert identity.evaluate_roles("r", [], DEFINITIONS)[0] == [] and identity.evaluate_roles("r", [assignment(READER)], DEFINITIONS)[2]["privilegedAssignments"] == 0


# --- MFA, risky users, recommendations --------------------------------------------------------------------------------

def user(upn, mfa, admin=False, kind="member", name=None):
    return {"id": upn, "userPrincipalName": upn, "userDisplayName": name or upn, "isMfaRegistered": mfa, "isAdmin": admin, "userType": kind}


def test_mfa_admins_are_findings_one_by_one_and_members_are_counted():
    users = [user("a@x", False, admin=True, name="Admin A"), user("b@x", True, admin=True), user("c@x", False), user("d@x", False), user("e@x", True), user("g@x", False, kind="guest")]
    findings, stats, dataset = identity.evaluate_mfa("r", users)
    assert rules(findings) == ["SEC-MFA-001", "SEC-MFA-002"] and "Admin A" in findings[0]["title"] + findings[1]["title"]
    plain = next(f for f in findings if f["ruleId"] == "SEC-MFA-002")
    assert "2 of 5 member users" in plain["recommendation"]
    assert {(s["ruleId"], s["affected"], s["applicable"]) for s in stats} == {("SEC-MFA-001", 1, 2), ("SEC-MFA-002", 2, 3)}
    assert dataset["members"] == 5 and dataset["withoutMfa"] == 3 and dataset["registeredPercent"] == 40.0 and dataset["adminsWithout"] == [{"name": "Admin A", "upn": "a@x"}]
    assert identity.evaluate_mfa("r", []) == ([], [], {"members": 0, "withoutMfa": 0, "adminsWithoutMfa": 0, "registeredPercent": None, "adminsWithout": []})


def test_risky_users_and_recommendations_become_findings_by_level():
    risky = [{"id": "1", "userDisplayName": "R1", "riskLevel": "high", "riskState": "atRisk"}, {"id": "2", "userDisplayName": "R2", "riskLevel": "low", "riskState": "atRisk"},
             {"id": "3", "userDisplayName": "R3", "riskLevel": "high", "riskState": "remediated"}, {"id": "4", "riskLevel": "none", "riskState": "atRisk"}]
    findings, stats, dataset = identity.evaluate_risky("r", risky)
    assert rules(findings) == ["SEC-RISK-001", "SEC-RISK-003"] and dataset["atRisk"] == 2 and dataset["byLevel"] == {"high": 1, "low": 1}
    assert all(s["applicable"] is None for s in stats)
    recs = [{"id": "a", "displayName": "Turn on MFA", "status": "active", "priority": "high", "insights": "5 users have no MFA."}, {"id": "b", "displayName": "Done", "status": "completed", "priority": "high"},
            {"id": "c", "displayName": "Cleanup", "status": "active", "priority": "low"}]
    findings, stats, dataset = identity.evaluate_recommendations("r", recs)
    assert rules(findings) == ["SEC-ENTRA-001", "SEC-ENTRA-003"] and findings[0]["recommendation"] == "5 users have no MFA." and dataset["active"] == 2
    assert dataset["items"] == [{"name": "Turn on MFA", "priority": "high"}, {"name": "Cleanup", "priority": "low"}]


# --- collection -------------------------------------------------------------------------------------------------------

class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


def test_collect_reads_every_identity_part_and_keeps_the_ones_that_are_denied(monkeypatch):
    class Cred:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    def fake_get(url, token, params=None, headers=None):
        if url.endswith("/identity/conditionalAccess/policies"):
            return Resp(200, {"value": [policy("mfa-all")]})
        if url.endswith("identitySecurityDefaultsEnforcementPolicy"):
            return Resp(200, {"isEnabled": False})
        if url.endswith("/roleManagement/directory/roleAssignments"):
            return Resp(200, {"value": [assignment(GA)]})
        if url.endswith("/roleManagement/directory/roleDefinitions"):
            return Resp(200, {"value": DEFINITIONS})
        if url.endswith("/roleEligibilitySchedules"):
            return Resp(403)
        if url.endswith("/userRegistrationDetails"):
            return Resp(200, {"value": [user("a@x", False, admin=True)]})
        if url.endswith("/directory/recommendations"):
            return Resp(200, {"value": [{"id": "a", "displayName": "R", "status": "active", "priority": "medium"}]})
        return Resp(403)

    monkeypatch.setattr(entra.rest, "get", fake_get)
    findings, stats, dataset, errors = entra.collect(Cred(), "r1")
    assert errors == [] and dataset["available"]["policies"] and dataset["available"]["roles"] and dataset["available"]["eligible"] is False
    assert dataset["available"]["mfa"] and dataset["available"]["recommendations"] and dataset["available"]["risky"] is False and dataset["available"]["apps"] is False
    assert {"SEC-MFA-001", "SEC-ENTRA-002", "SEC-CA-003"} <= {f["ruleId"] for f in findings} and "SEC-ROLE-004" not in {f["ruleId"] for f in findings}
    assert dataset["roles"]["eligibleAssignments"] is None and dataset["policies"]["mfaAllUsers"] is True and dataset["permissions"]["mfa"] == "Reports.Read.All and AuditLog.Read.All"
    assert all(set(s) >= {"ruleId", "source", "pillar", "severity", "subscriptionId", "affected", "applicable"} for s in stats)


def test_every_identity_rule_has_a_valid_severity_and_text():
    for rule, (severity, title, recommendation) in identity.RULES.items():
        assert severity in ("critical", "high", "medium", "low") and title and recommendation and rule.startswith("SEC-")
    assert set(identity.PERMISSIONS) == {"policies", "roles", "eligible", "mfa", "risky", "recommendations"}
