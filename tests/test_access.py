from datetime import date

from waf_pulse import access, graph

SUB = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"
TODAY = "2026-10-20"


def assignment(role, kind, level="subscription", scope=None, sub=SUB, pid="p1"):
    return {"subscriptionId": sub, "roleId": role, "scope": scope or f"/subscriptions/{sub}", "principalType": kind, "principalId": pid, "level": level, "createdOn": "2026-01-02T00:00:00Z"}


def rules(findings):
    return sorted(f["ruleId"] for f in findings)


def test_owners_given_to_users_and_applications_at_wide_scope_are_findings():
    items = [assignment(access.OWNER, "User", pid="u1"), assignment(access.USER_ACCESS_ADMIN, "ServicePrincipal", pid="s1"), assignment(access.OWNER, "Group", pid="g1"),
             assignment(access.OWNER, "User", level="resource group", scope=f"/subscriptions/{SUB}/resourcegroups/rg", pid="u2"), assignment(access.CONTRIBUTOR, "User", pid="u3"),
             assignment(access.OWNER, "User", level="management group", scope="/providers/microsoft.management/managementgroups/mg", pid="u4")]
    findings, stats, rows, data = access.evaluate_rbac("r", items, [])
    assert rules(findings) == ["SEC-RBAC-001", "SEC-RBAC-001", "SEC-RBAC-002"]
    first = next(f for f in findings if f["ruleId"] == "SEC-RBAC-001" and "u1" in f["resourceName"])
    assert first["title"] == "Owner is assigned directly to a user at subscription scope" and first["resourceId"].startswith(f"/subscriptions/{SUB}/providers/microsoft.authorization/roleassignments/u1-")
    assert len({f["resourceId"] for f in findings}) == 3
    assert {(s["ruleId"], s["affected"], s["applicable"]) for s in stats} == {("SEC-RBAC-001", 2, 6), ("SEC-RBAC-002", 1, 6)}
    assert data["usersWithControlRoles"] == 3 and data["servicePrincipalsWithControlRoles"] == 1 and data["powerfulAssignments"] == 6
    assert {r["flag"] for r in rows} >= {"SEC-RBAC-001", "SEC-RBAC-002", ""} and all(r["t"] == "rbac" for r in rows)


def test_more_than_three_subscription_owners_is_one_finding_per_subscription():
    items = [assignment(access.OWNER, "Group", pid=f"g{i}") for i in range(4)] + [assignment(access.OWNER, "Group", sub=OTHER, pid="x")]
    findings, stats, rows, data = access.evaluate_rbac("r", items, [])
    assert rules(findings) == ["SEC-RBAC-003"] and findings[0]["resourceId"] == f"/subscriptions/{SUB}" and "4 owners" in findings[0]["title"]
    assert data["owners"] == 5 and data["ownerSubscriptions"] == 1
    assert any(s["ruleId"] == "SEC-RBAC-003" and s["subscriptionId"] == SUB and s["affected"] == 1 for s in stats)


def test_a_custom_role_that_allows_everything_is_a_finding_in_its_subscription():
    roles = [{"id": "/providers/microsoft.authorization/roledefinitions/abc", "name": "Everything", "assignable": f"/subscriptions/{SUB}"},
             {"id": "/providers/microsoft.authorization/roledefinitions/def", "name": "Tenant wide", "assignable": "/"}]
    findings, stats, _, data = access.evaluate_rbac("r", [], roles)
    assert rules(findings) == ["SEC-RBAC-004", "SEC-RBAC-004"] and {f["subscriptionId"] for f in findings} == {SUB, "tenant"} and data["customRolesWithWildcard"] == 2
    assert {s["subscriptionId"] for s in stats} == {SUB, "tenant"}


def test_policy_noncompliance_and_expired_exemptions():
    by_assignment = [{"assignment": "baseline", "initiative": "mcsb", "subscriptionId": SUB, "nonCompliant": 2, "compliant": 6, "exempt": 3},
                     {"assignment": "tags", "initiative": "", "subscriptionId": SUB, "nonCompliant": 0, "compliant": 4, "exempt": 0}]
    noncompliant = [{"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a", "subscriptionId": SUB, "assignment": "baseline", "definition": "d1", "action": "audit",
                     "type": "microsoft.storage/storageaccounts"},
                    {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a", "subscriptionId": SUB, "assignment": "baseline", "definition": "d2", "action": "audit", "type": "microsoft.storage/storageaccounts"},
                    {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/b", "subscriptionId": SUB, "assignment": "baseline", "definition": "d1", "action": "deny", "type": "microsoft.storage/storageaccounts"}]
    exemptions = [{"id": "/e1", "name": "e1", "subscriptionId": SUB, "displayName": "Old waiver", "category": "Waiver", "expiresOn": "2026-01-01T00:00:00Z"},
                  {"id": "/e2", "name": "e2", "subscriptionId": SUB, "displayName": "Open", "category": "Mitigated", "expiresOn": ""},
                  {"id": "/e3", "name": "e3", "subscriptionId": SUB, "displayName": "Future", "category": "Waiver", "expiresOn": "2027-01-01T00:00:00Z"}]
    findings, stats, rows, data = access.evaluate_policy("r", by_assignment, noncompliant, exemptions, TODAY)
    assert rules(findings) == ["SEC-POL-001", "SEC-POL-001", "SEC-POL-002"]  # the same resource and assignment twice is one finding
    assert {(s["ruleId"], s["affected"], s["applicable"]) for s in stats} == {("SEC-POL-001", 2, 12), ("SEC-POL-002", 1, 3)}
    assert data == {"nonCompliant": 2, "evaluated": 12, "exempt": 3, "assignments": 2, "exemptions": 3, "expiredExemptions": 1, "exemptionsWithoutExpiry": 1}
    assert {r["t"] for r in rows} == {"policy", "noncompliant", "exemption"} and next(r for r in rows if r["t"] == "exemption" and r["name"] == "Old waiver")["expired"] is True


def test_collect_reports_failures_and_keeps_the_rest(monkeypatch):
    def fake(credential, subs, kql, max_rows=0):
        if "policyexemptions" in kql:
            raise RuntimeError("Forbidden\nmore")
        if "roleassignments" in kql:
            return [assignment(access.OWNER, "User")]
        return []

    monkeypatch.setattr(graph, "query", fake)
    findings, stats, dataset, rows, errors = access.collect(None, "r", [SUB], TODAY)
    assert rules(findings) == ["SEC-RBAC-001"] and errors == [{"ruleId": "access-exemptions", "error": "Forbidden"}] and dataset["available"] == {"rbac": True, "policy": True}
    assert dataset["rbac"]["owners"] == 1 and rows[0]["t"] == "rbac"


def test_queries_use_resource_graph_features_it_accepts():
    assert not [q for q in access.QUERIES.values() if "mv-apply" in q]
    assert access.OWNER in access.QUERIES["rbac"] and "matches regex" in access.QUERIES["rbac"]
