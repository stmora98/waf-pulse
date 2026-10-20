import json

from waf_pulse import graph, rules, security, security_rules

SUB = "11111111-1111-1111-1111-111111111111"
VM1 = f"/subscriptions/{SUB}/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1"
VM2 = VM1.replace("vm1", "vm2")


def alert(name="Suspicious activity", severity="High", status="Active", **extra):
    return {"id": f"/subscriptions/{SUB}/providers/Microsoft.Security/locations/c/alerts/a", "subscriptionId": SUB.upper(), "name": name, "alertType": "T",
            "severity": severity, "status": status, "intent": "Execution", "started": "2026-10-16T22:35:35.915Z", "entity": "vm1", "uri": "https://portal.azure.com/x",
            "remediation": json.dumps(["1. Contact the owner.", "2. Block it."]), "identifiers": json.dumps([{"Type": "AzureResource", "AzureResourceId": VM1}]), **extra}


# --- alerts -------------------------------------------------------------------------------------------------

def test_alerts_become_rows_with_their_resource_and_first_remediation_step():
    rows = security.alert_rows([alert(), alert(identifiers="not json", uri="javascript:alert(1)", remediation="Plain text")])
    assert rows[0]["id"] == VM1 and rows[0]["subscriptionId"] == SUB and rows[0]["step"] == "1. Contact the owner." and rows[0]["uri"].startswith("https://")
    assert rows[1]["id"] == f"/subscriptions/{SUB}" and rows[1]["uri"] == "" and rows[1]["step"] == "Plain text"


def test_only_active_alerts_of_known_severity_raise_findings_and_the_rest_is_counted():
    rows = security.alert_rows([alert(), alert(severity="Medium"), alert(severity="Informational"), alert(status="Dismissed"), alert(severity="Low", status="InProgress")])
    findings, stats = security.evaluate_alerts("r", rows)
    assert sorted(f["ruleId"] for f in findings) == ["SEC-ALERT-001", "SEC-ALERT-002", "SEC-ALERT-003"]
    high = next(f for f in findings if f["ruleId"] == "SEC-ALERT-001")
    assert high["severity"] == "high" and high["resourceId"] == VM1 and "Suspicious activity" in high["title"] and high["recommendation"] == "1. Contact the owner." and high["source"] == "security"
    assert {(s["ruleId"], s["affected"], s["applicable"]) for s in stats} == {("SEC-ALERT-001", 1, 5), ("SEC-ALERT-002", 1, 5), ("SEC-ALERT-003", 1, 5)}
    assert security.evaluate_alerts("r", []) == ([], [])


# --- machines ---------------------------------------------------------------------------------------------------

def test_machines_with_vulnerable_or_unsupported_software_and_pending_patches():
    software = [{"vm": VM1, "subscriptionId": SUB, "software": 300, "vulnerable": 3, "vulnerabilities": 9, "pastSupport": 0, "worst": "openssl"},
                {"vm": VM2, "subscriptionId": SUB, "software": 200, "vulnerable": 12, "vulnerabilities": 80, "pastSupport": 2, "worst": "kernel"},
                {"vm": VM1.replace("vm1", "vm3"), "subscriptionId": SUB, "software": 5, "vulnerable": 0, "vulnerabilities": 0, "pastSupport": 0}]
    patches = [{"vm": VM1, "subscriptionId": SUB, "critical": 2, "security": 5, "other": 1, "os": "Windows", "assessed": "2026-10-17T00:00:00Z"},
               {"vm": VM2, "subscriptionId": SUB, "critical": 0, "security": 4, "other": 0, "os": "Linux", "assessed": ""},
               {"vm": VM1.replace("vm1", "vm3"), "subscriptionId": SUB, "critical": 0, "security": 0, "other": 3, "os": "Linux", "assessed": ""}]
    findings, stats, rows, totals = security.evaluate_machines("r", software, patches)
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f["ruleId"], []).append(f["resourceName"])
    assert by_rule == {"SEC-VULN-001": ["vm1"], "SEC-VULN-002": ["vm2"], "SEC-EOS-001": ["vm2"], "SEC-PATCH-001": ["vm1"], "SEC-PATCH-002": ["vm2"]}
    assert {(s["ruleId"], s["affected"], s["applicable"]) for s in stats} == {("SEC-VULN-001", 1, 3), ("SEC-VULN-002", 1, 3), ("SEC-EOS-001", 1, 3), ("SEC-PATCH-001", 1, 3), ("SEC-PATCH-002", 1, 3)}
    assert all(s["applicableTypes"] == ["microsoft.compute/virtualmachines"] for s in stats)
    assert totals == {"inventoried": 3, "vulnerable": 2, "pastSupport": 1, "assessedForPatches": 3, "criticalPatches": 1, "securityPatches": 1}
    assert {r["t"] for r in rows} == {"vuln", "patch"} and sum(1 for r in rows if r["t"] == "vuln") == 2 and sum(1 for r in rows if r["t"] == "patch") == 2
    assert security.evaluate_machines("r", [], [])[3]["inventoried"] == 0


# --- the other rows ------------------------------------------------------------------------------------------------

def test_compliance_exposure_and_change_rows():
    standards = [{"subscriptionId": SUB.upper(), "standard": "MCSB", "state": "Failed", "passed": 50, "failed": 7, "skipped": 3, "unsupported": None}]
    controls = [{"subscriptionId": SUB, "standard": "MCSB", "control": "NS-1", "description": "Network", "failedAssessments": 4, "passedAssessments": None}]
    rows = security.compliance_rows(standards, controls)
    assert rows[0] == {"t": "standard", "subscriptionId": SUB, "standard": "MCSB", "state": "Failed", "passed": 50, "failed": 7, "skipped": 3, "unsupported": 0}
    assert rows[1]["control"] == "NS-1" and rows[1]["failed"] == 4 and rows[1]["passed"] == 0
    exposure = security.exposure_rows([{"id": VM1, "subscriptionId": SUB, "ip": "1.2.3.4", "sku": None}],
                                      [{"id": "/nsg", "nsg": "n", "subscriptionId": SUB, "rule": "r", "ports": "", "source": "*", "priority": 100, "protocol": "Tcp"}])
    assert exposure[0]["t"] == "exposed" and exposure[0]["sku"] == "" and exposure[1]["ports"] == "*" and exposure[1]["t"] == "nsgrule"
    changes = [{"ts": "2026-10-19T10:00:00Z", "changeType": "Update", "id": "/x/nsg", "type": "microsoft.network/networksecuritygroups", "by": "a@b.c", "byType": "User", "client": "Portal", "changes": 2, "subscriptionId": SUB},
               {"ts": "2026-10-19T11:00:00Z", "changeType": "Create", "id": "/x/other", "type": "microsoft.insights/components", "by": "System", "byType": "System", "subscriptionId": SUB}]
    assert [c["id"] for c in security.change_rows(changes)] == ["/x/nsg"]
    assert security.summarize_changes(changes) == {"days": 14, "total": 2, "byChangeType": {"Update": 1, "Create": 1}, "byActor": {"User": 1, "System": 1}, "securityRelevant": 1}


def test_caps_keep_the_rows_small():
    many = [alert(name=f"a{i}") for i in range(security.MAX_ALERTS + 50)]
    assert len(security.alert_rows(many)) == security.MAX_ALERTS


# --- collection ---------------------------------------------------------------------------------------------------

def test_collect_builds_findings_a_small_dataset_and_separate_rows(monkeypatch):
    answers = {"securityresources\n| where type =~ 'microsoft.security/locations/alerts'": [alert()],
               "softwareinventories'\n| extend p = properties\n| extend vm = tolower(tostring(p.azureVmId)), vulns = toint(p.numberOfKnownVulnerabilities), eos": [
                   {"vm": VM1, "subscriptionId": SUB, "software": 10, "vulnerable": 2, "vulnerabilities": 4, "pastSupport": 0, "worst": "x"}],
               "publicipaddresses'\n| summarize total": [{"subscriptionId": SUB, "total": 3, "attached": 2}]}

    def fake(credential, subs, kql, max_rows=0):
        for key, rows in answers.items():
            if key in kql:
                return rows
        if "patchassessmentresources" in kql:
            raise RuntimeError("Forbidden\nmore")
        return []

    monkeypatch.setattr(graph, "query", fake)
    findings, stats, dataset, rows, errors = security.collect(None, "r", [SUB])
    assert sorted(f["ruleId"] for f in findings) == ["SEC-ALERT-001", "SEC-VULN-001"]
    assert errors == [{"ruleId": "security-patches", "error": "Forbidden"}] and dataset["queried"]["patches"] is False and dataset["available"]["patches"] is False
    assert dataset["alerts"] == {"total": 1, "active": 1, "bySeverity": {"high": 1}} and dataset["machines"]["vulnerable"] == 1
    assert dataset["exposure"]["publicIps"] == 3 and dataset["exposure"]["attached"] == 2 and "rows" not in dataset
    assert {r["t"] for r in rows} == {"alert", "vuln"}


# --- the exposure rules -----------------------------------------------------------------------------------------

def test_exposure_rules_are_in_the_catalog_and_name_the_ports():
    ids = [r.id for r in rules.RULES]
    assert len(ids) == len(set(ids)) and all(r in rules.RULES for r in security_rules.RULES_SECURITY)
    by_id = {r.id: r for r in security_rules.RULES_SECURITY}
    for port in security_rules.MANAGEMENT_PORTS:
        assert f"low <= {port} and high >= {port}" in by_id["SEC-NSG-001"].query
    for port in security_rules.DATABASE_PORTS:
        assert f"low <= {port} and high >= {port}" in by_id["SEC-NSG-002"].query
    assert "everything" in by_id["SEC-NSG-003"].query and "networkinterfaces" in by_id["SEC-VM-004"].query
    assert by_id["SEC-NSG-001"].severity == "critical" and by_id["SEC-NSG-002"].severity == "high"
    assert "'internet'" in by_id["SEC-NSG-001"].query and "'0.0.0.0/0'" in by_id["SEC-NSG-001"].query
