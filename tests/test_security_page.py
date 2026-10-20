import json

import pytest

import app as dashboard_app
import data
import scope
import security_view

S1, S2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"


def vm(sub, name):
    return f"/subscriptions/{sub}/resourcegroups/rg/providers/microsoft.compute/virtualmachines/{name}"


ROWS = [
    {"t": "alert", "id": vm(S1, "web1"), "subscriptionId": S1, "name": "Suspicious <script>alert(1)</script>", "severity": "high", "status": "Active", "intent": "Execution",
     "started": "2026-10-16T22:35:35", "entity": "web1", "uri": "https://portal.azure.com/alert1", "step": "Contact the owner."},
    {"t": "alert", "id": vm(S2, "db1"), "subscriptionId": S2, "name": "Old one", "severity": "low", "status": "Dismissed", "intent": "", "started": "2026-10-01T00:00:00", "entity": "", "uri": "javascript:alert(1)", "step": ""},
    {"t": "alert", "id": f"/subscriptions/{S1}", "subscriptionId": S1, "name": "Subscription alert", "severity": "informational", "status": "Active", "intent": "", "started": "2026-10-17T00:00:00", "entity": "", "uri": "", "step": ""},
    {"t": "vuln", "id": vm(S1, "web1"), "subscriptionId": S1, "software": 300, "vulnerable": 3, "vulnerabilities": 12, "pastSupport": 1, "worst": "openssl"},
    {"t": "vuln", "id": vm(S2, "db1"), "subscriptionId": S2, "software": 100, "vulnerable": 0, "vulnerabilities": 0, "pastSupport": 2, "worst": ""},
    {"t": "patch", "id": vm(S1, "web1"), "subscriptionId": S1, "critical": 2, "security": 3, "other": 0, "os": "Windows", "assessed": "2026-10-17T00:00:00"},
    {"t": "software", "subscriptionId": S1, "name": "openssl", "machines": 2, "vulnerabilities": 14, "versions": ["3.0.1"]},
    {"t": "software", "subscriptionId": S2, "name": "openssl", "machines": 3, "vulnerabilities": 20, "versions": ["3.0.1", "1.1.1"]},
    {"t": "standard", "subscriptionId": S1, "standard": "MCSB", "state": "Failed", "passed": 40, "failed": 10, "skipped": 1, "unsupported": 2},
    {"t": "standard", "subscriptionId": S2, "standard": "MCSB", "state": "Failed", "passed": 10, "failed": 0, "skipped": 0, "unsupported": 0},
    {"t": "control", "subscriptionId": S1, "standard": "MCSB", "control": "NS-1", "description": "Network security", "failed": 4, "passed": 1},
    {"t": "control", "subscriptionId": S2, "standard": "MCSB", "control": "NS-1", "description": "Network security", "failed": 2, "passed": 3},
    {"t": "exposed", "id": vm(S1, "web1"), "subscriptionId": S1, "ip": "20.1.2.3", "sku": "Standard"},
    {"t": "nsgrule", "id": f"/subscriptions/{S1}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1", "subscriptionId": S1, "nsg": "nsg1", "rule": "ssh", "ports": "22", "source": "*", "priority": 200},
    {"t": "nsgrule", "id": f"/subscriptions/{S1}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1", "subscriptionId": S1, "nsg": "nsg1", "rule": "web", "ports": "443", "source": "Internet", "priority": 300},
    {"t": "nsgrule", "id": f"/subscriptions/{S1}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg2", "subscriptionId": S1, "nsg": "nsg2", "rule": "all", "ports": "*", "source": "*", "priority": 100},
    {"t": "change", "id": vm(S1, "web1"), "subscriptionId": S1, "ts": "2026-10-19T10:00:00", "changeType": "Update", "type": "microsoft.compute/virtualmachines", "by": "a@b.c", "byType": "User", "client": "Portal", "changes": 2},
    {"t": "change", "id": vm(S2, "db1"), "subscriptionId": S2, "ts": "2026-10-18T10:00:00", "changeType": "Create", "type": "microsoft.compute/virtualmachines", "by": "System", "byType": "System", "client": "", "changes": 1},
]
SUMMARY = {"runId": "r1", "scores": {"Security": 40}, "subscriptions": [{"id": S1, "name": "Prod", "resourceCount": 5, "scores": {}}, {"id": S2, "name": "Dev", "resourceCount": 3, "scores": {}}],
           "security": {"available": {"alerts": True, "software": True, "patches": True, "compliance": True, "changes": True}, "machines": {"inventoried": 7}, "exposure": {"publicIps": 4, "attached": 3},
                        "changes": {"days": 14}}}


# --- helpers -------------------------------------------------------------------------------------------------------

def test_port_classes():
    assert security_view.port_class("22") == "management" and security_view.port_class("3380-3400") == "management" and security_view.port_class("1433") == "database"
    assert security_view.port_class("*") == "any" and security_view.port_class("") == "any" and security_view.port_class("80,443") == "" and security_view.port_class("80,3389") == "management"
    assert security_view.port_class("bad") == "" and security_view.port_class("445") == "database"


def test_view_helpers_sort_and_aggregate():
    vuln = security_view.vulnerabilities(ROWS)
    assert [security_view.name_of(r["id"]) for r in vuln["machines"]] == ["web1", "db1"] and vuln["patches"][0]["critical"] == 2
    assert vuln["software"] == [{"name": "openssl", "machines": 5, "vulnerabilities": 20, "versions": ["3.0.1", "1.1.1"]}]
    expo = security_view.exposure(ROWS)
    assert [r["rule"] for r in expo["rules"]] == ["all", "ssh", "web"] and expo["risky"] == 2
    alerts = security_view.alerts(ROWS)
    assert [a["name"] for a in alerts["alerts"]][-1] == "Old one" and alerts["bySeverity"] == {"high": 1, "informational": 1}
    comp = security_view.compliance(ROWS)
    assert comp["standards"] == [{"standard": "MCSB", "passed": 50, "failed": 10, "skipped": 1, "unsupported": 2, "percent": 83.3}]
    assert comp["controls"] == [{"standard": "MCSB", "control": "NS-1", "failed": 6, "passed": 4, "description": "Network security"}]
    chg = security_view.changes(ROWS)
    assert [c["ts"] for c in chg["changes"]][0] == "2026-10-19T10:00:00" and chg["byActor"] == {"User": 1, "System": 1}
    assert security_view.compliance([])["standards"] == [] and security_view.alerts([])["alerts"] == []


# --- the page ------------------------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    dashboard_app.app.config.update(TESTING=True)
    return dashboard_app.app.test_client()


def serve(monkeypatch, rows=None, summary=None):
    monkeypatch.setattr(data, "latest_run", lambda completed_only=False: {"id": "r1", "status": "completed"})
    monkeypatch.setattr(data, "summary", lambda run_id: json.loads(json.dumps(summary or SUMMARY)))
    monkeypatch.setattr(data, "all_findings", lambda *a, **k: [])
    monkeypatch.setattr(data, "resources", lambda run_id: ([], False))
    monkeypatch.setattr(data, "get_setting", lambda name: None)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: list(ROWS if rows is None else rows) if kind == "secrows" else [])
    monkeypatch.setattr(data, "history", lambda limit=30: [])


def page(client, tab):
    return client.get("/pillar/security" + (f"?tab={tab}" if tab else "")).get_data(as_text=True)


def test_the_tabs_are_listed_and_the_default_is_the_posture(client, monkeypatch):
    serve(monkeypatch)
    html = page(client, None)
    for label in ("Posture", "Vulnerabilities", "Exposure", "Alerts", "Compliance", "Changes"):
        assert f">{label}</a>" in html
    assert 'class="tab active" href="/pillar/security" aria-current="page"' in html and "Machines with vulnerable" not in html
    assert 'class="tab active" href="/pillar/security" aria-current="page"' in page(client, "nonsense")  # an unknown tab falls back to the posture


def test_vulnerabilities_tab(client, monkeypatch):
    serve(monkeypatch)
    html = page(client, "vulnerabilities")
    assert "Machines with vulnerable or unsupported software" in html and ">web1<" in html and "openssl" in html and "Pending patches" in html and "Windows" in html
    assert 'class="tab active" href="/pillar/security?tab=vulnerabilities"' in html


def test_exposure_tab_marks_risky_rules(client, monkeypatch):
    serve(monkeypatch)
    html = page(client, "exposure")
    assert "Inbound rules that allow the internet" in html and "Any port" in html and "Management port" in html and "20.1.2.3" in html and "nsg2" in html
    assert "Public IP addresses" in html


def test_alerts_tab_escapes_and_drops_unsafe_links(client, monkeypatch):
    serve(monkeypatch)
    html = page(client, "alerts")
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert 'href="https://portal.azure.com/alert1"' in html and "javascript:alert" not in html and "Contact the owner." in html
    assert html.index("Suspicious") < html.index("Old one")


def test_compliance_and_changes_tabs(client, monkeypatch):
    serve(monkeypatch)
    comp = page(client, "compliance")
    assert "83.3%" in comp and "50 passed" in comp and "NS-1" in comp and "Failed controls" in comp
    chg = page(client, "changes")
    assert "Latest changes" in chg and "a@b.c" in chg and "2026-10-19T10:00:00" in chg


def test_tabs_follow_the_filters(client, monkeypatch):
    serve(monkeypatch)
    client.set_cookie(scope.COOKIE, scope.encode(scope.sanitize([{"f": "sub", "v": [S2]}])), domain="localhost")
    vuln = page(client, "vulnerabilities")
    assert ">db1<" in vuln and ">web1<" not in vuln and "openssl" in vuln
    comp = page(client, "compliance")
    assert "100.0%" in comp and "2 failed" not in comp
    assert "Old one" in page(client, "alerts") and "Suspicious" not in page(client, "alerts")
    client.set_cookie(scope.COOKIE, scope.encode(scope.sanitize([{"f": "rg", "v": ["rg"]}])), domain="localhost")
    assert "MCSB" not in page(client, "compliance")  # a control belongs to a subscription, not to a resource group


def test_empty_tabs_explain_where_the_data_comes_from(client, monkeypatch):
    serve(monkeypatch, rows=[], summary={**SUMMARY, "security": {"available": {}}})
    assert "Defender for Servers" in page(client, "vulnerabilities") and "Update Manager" in page(client, "vulnerabilities")
    assert "No internet-facing rules" in page(client, "exposure") and "No Defender for Cloud alerts" in page(client, "alerts")
    assert "No regulatory compliance data" in page(client, "compliance") and "No security-relevant changes" in page(client, "changes")


def test_a_store_failure_is_reported_on_the_tab(client, monkeypatch):
    serve(monkeypatch)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: (_ for _ in ()).throw(RuntimeError("down")))
    assert "could not be read right now" in page(client, "alerts")

# --- the identity tab ----------------------------------------------------------------------------------------------

ENTRA = {
    "available": {"apps": True, "policies": True, "roles": True, "eligible": False, "mfa": True, "risky": False, "recommendations": True},
    "permissions": {"policies": "Policy.Read.All", "roles": "RoleManagement.Read.Directory", "eligible": "RoleEligibilitySchedule.Read.Directory", "mfa": "Reports.Read.All and AuditLog.Read.All",
                    "risky": "IdentityRiskyUser.Read.All", "recommendations": "DirectoryRecommendations.Read.All"},
    "policies": {"total": 7, "enabled": 5, "reportOnly": 2, "disabled": 0, "securityDefaults": False, "mfaAllUsers": True, "mfaAdmins": False, "legacyBlocked": False,
                 "policies": [{"name": "MFA for partners", "state": "enabled"}, {"name": "Risk sign-in", "state": "enabledForReportingButNotEnforced"}]},
    "roles": {"privilegedAssignments": 16, "globalAdministrators": 15, "byRole": {"Global Administrator": 15, "Exchange Administrator": 1}, "guests": 1, "servicePrincipals": 7, "eligibleAssignments": None,
              "assignments": [{"kind": "#microsoft.graph.user", "name": "Ana", "guest": False, "id": "1", "role": "Global Administrator"},
                              {"kind": "#microsoft.graph.servicePrincipal", "name": "deploy-app", "guest": False, "id": "2", "role": "Global Administrator"}]},
    "mfa": {"members": 100, "withoutMfa": 20, "adminsWithoutMfa": 1, "registeredPercent": 80.0, "adminsWithout": [{"name": "Admin <b>A</b>", "upn": "a@x"}]},
    "recommendations": {"active": 2, "byPriority": {"high": 1, "medium": 1}, "items": [{"name": "Turn on MFA", "priority": "high"}]},
}


def test_identity_tab_shows_what_was_read_and_what_is_missing(client, monkeypatch):
    serve(monkeypatch, summary={**SUMMARY, "entra": ENTRA})
    html = page(client, "identity")
    assert ">Identity</a>" in html and "MFA for partners" in html and "Report-only" in html and "Global Administrators" in html and ">15<" in html
    assert "Missing: legacy authentication blocked" in html and "Covered: MFA for all users" in html
    assert "deploy-app" in html and "Service principal" in html and "1 guest(s)" in html and "PIM eligibility could not be read" in html
    assert "80.0%" in html and "Admin &lt;b&gt;A&lt;/b&gt;" in html and "<b>A</b>" not in html and "Turn on MFA" in html
    assert "Not available. Grant the Microsoft Graph application permission <strong>IdentityRiskyUser.Read.All</strong>" in html and "Microsoft Entra ID P2" in html


def test_identity_tab_without_data_and_with_filters(client, monkeypatch):
    serve(monkeypatch)
    assert "No identity data yet" in page(client, "identity")
    serve(monkeypatch, summary={**SUMMARY, "entra": ENTRA})
    client.set_cookie(scope.COOKIE, scope.encode(scope.sanitize([{"f": "sub", "v": [S1]}])), domain="localhost")
    assert "Identity is about the whole tenant" in page(client, "identity")

# --- the access tab ------------------------------------------------------------------------------------------------

ACCESS_ROWS = [
    {"t": "rbac", "id": f"/subscriptions/{S1}", "subscriptionId": S1, "role": "Owner", "principalType": "User", "principalId": "abc-123", "level": "subscription", "createdOn": "2026-01-02", "flag": "SEC-RBAC-001"},
    {"t": "rbac", "id": f"/subscriptions/{S1}", "subscriptionId": S1, "role": "Contributor", "principalType": "Group", "principalId": "grp-1", "level": "subscription", "createdOn": "2025-05-05", "flag": ""},
    {"t": "rbac", "id": f"/subscriptions/{S2}", "subscriptionId": S2, "role": "User Access Administrator", "principalType": "ServicePrincipal", "principalId": "app-9", "level": "subscription", "createdOn": "2025-06-06", "flag": "SEC-RBAC-002"},
    {"t": "policy", "subscriptionId": S1, "assignment": "baseline", "initiative": "mcsb", "nonCompliant": 2, "compliant": 6, "exempt": 3},
    {"t": "policy", "subscriptionId": S2, "assignment": "baseline", "initiative": "mcsb", "nonCompliant": 1, "compliant": 1, "exempt": 0},
    {"t": "noncompliant", "id": vm(S1, "web1"), "subscriptionId": S1, "assignment": "baseline", "definition": "d", "action": "audit", "type": "microsoft.compute/virtualmachines"},
    {"t": "exemption", "id": f"/subscriptions/{S1}/providers/Microsoft.Authorization/policyExemptions/e1", "subscriptionId": S1, "name": "Old <i>waiver</i>", "category": "Waiver", "expiresOn": "2026-01-01", "expired": True},
    {"t": "exemption", "id": f"/subscriptions/{S1}/providers/Microsoft.Authorization/policyExemptions/e2", "subscriptionId": S1, "name": "Open", "category": "Mitigated", "expiresOn": "", "expired": False},
]


def test_access_view_helper():
    acc = security_view.access(ACCESS_ROWS)
    assert [r["role"] for r in acc["rbac"]][:2] == ["Owner", "User Access Administrator"] and acc["flagged"] == 2 and acc["owners"] == 1
    assert acc["assignments"] == [{"assignment": "baseline", "initiative": "mcsb", "nonCompliant": 3, "compliant": 7, "exempt": 3, "percent": 70.0}]
    assert [e["name"] for e in acc["exemptions"]][0].startswith("Old") and acc["expired"] == 1 and len(acc["noncompliant"]) == 1
    assert security_view.access([]) == {"rbac": [], "flagged": 0, "assignments": [], "noncompliant": [], "exemptions": [], "expired": 0, "owners": 0}


def serve_access(monkeypatch, rows=None):
    serve(monkeypatch)
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: list(ACCESS_ROWS if rows is None else rows) if kind == "accrows" else [])


def test_access_tab(client, monkeypatch):
    serve_access(monkeypatch)
    html = page(client, "access")
    assert ">Access and policy</a>" in html and "Powerful role assignments" in html and "abc-123" in html and "Direct to a user" in html and "Application with control role" in html
    assert "Policy compliance by assignment" in html and "70.0%" in html and ">web1<" in html and "Old &lt;i&gt;waiver&lt;/i&gt;" in html and "<i>waiver</i>" not in html
    assert "expired" in html and "no expiry" in html


def test_access_tab_follows_the_filters_and_handles_no_data(client, monkeypatch):
    serve_access(monkeypatch)
    client.set_cookie(scope.COOKIE, scope.encode(scope.sanitize([{"f": "sub", "v": [S2]}])), domain="localhost")
    html = page(client, "access")
    assert "app-9" in html and "abc-123" not in html and ">web1<" not in html and "50.0%" in html
    serve_access(monkeypatch, rows=[])
    client.set_cookie(scope.COOKIE, "[]", domain="localhost")
    assert "No access or policy data" in page(client, "access")
    monkeypatch.setattr(data, "rows_of", lambda run_id, kind: (_ for _ in ()).throw(RuntimeError("down")))
    assert "could not be read right now" in page(client, "access")
