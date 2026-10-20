"""Security signals from Resource Graph (Reader is enough): Defender for Cloud alerts, installed software with known
vulnerabilities or past its end of support, pending patches (Update Manager), regulatory compliance, public IP exposure and the
recent security-relevant changes. Everything is read in a few queries; what is not available in a tenant (no Defender plan, no
Update Manager) simply returns nothing and is reported as not available.

Findings go through the normal rule statistics, so the scores follow them. The rows behind the Security page are kept apart
from the summary (`rows`), the summary only gets the totals."""
import json
from collections import Counter, defaultdict

from . import graph
from .findings import make_finding

SOURCE = "security"
MAX_ROWS_PER_QUERY = 3000
MAX_ALERTS = 300
MAX_VULNERABLE_VMS = 300
MAX_PATCH_ROWS = 300
MAX_CONTROLS = 200
MAX_EXPOSED = 300
MAX_NSG_RULES = 200
MAX_CHANGES = 150
CHANGE_DAYS = 14
VULNERABLE_HIGH = 10  # installed software with known vulnerabilities from which a machine is a high finding

SEVERITY = {"high": "high", "medium": "medium", "low": "low"}  # Defender's "Informational" alerts are counted, not raised
ALERT_RULES = {"high": "SEC-ALERT-001", "medium": "SEC-ALERT-002", "low": "SEC-ALERT-003"}

# rule id -> (severity, title, recommendation)
RULES = {
    "SEC-ALERT-001": ("high", "Active Defender for Cloud alert (high severity): {name}", "Investigate the alert in Defender for Cloud and follow its remediation steps."),
    "SEC-ALERT-002": ("medium", "Active Defender for Cloud alert (medium severity): {name}", "Investigate the alert in Defender for Cloud and follow its remediation steps."),
    "SEC-ALERT-003": ("low", "Active Defender for Cloud alert (low severity): {name}", "Review the alert in Defender for Cloud and dismiss it if it is expected."),
    "SEC-VULN-001": ("medium", "Virtual machine has installed software with known vulnerabilities",
                     "Update or remove the vulnerable software; Defender for Cloud lists the packages and the fixed versions."),
    "SEC-VULN-002": ("high", "Virtual machine has many installed software packages with known vulnerabilities",
                     "Patch the machine or rebuild it from an updated image; Defender for Cloud lists the packages and the fixed versions."),
    "SEC-EOS-001": ("medium", "Virtual machine runs software that is past or close to its end of support",
                    "Move to a supported version before it stops receiving security fixes."),
    "SEC-PATCH-001": ("high", "Virtual machine has critical patches pending", "Install the pending critical patches, or schedule them with Update Manager."),
    "SEC-PATCH-002": ("medium", "Virtual machine has security patches pending", "Install the pending security patches, or schedule them with Update Manager."),
}

SECURITY_TYPES = (
    "microsoft.network/networksecuritygroups", "microsoft.network/publicipaddresses", "microsoft.network/azurefirewalls",
    "microsoft.keyvault/vaults", "microsoft.authorization/roleassignments", "microsoft.authorization/policyassignments",
    "microsoft.authorization/locks", "microsoft.storage/storageaccounts", "microsoft.sql/servers", "microsoft.network/applicationgateways",
    "microsoft.network/virtualnetworks", "microsoft.compute/virtualmachines", "microsoft.web/sites", "microsoft.containerservice/managedclusters",
)

QUERIES = {
    "alerts": """
securityresources
| where type =~ 'microsoft.security/locations/alerts'
| extend p = properties
| project id, subscriptionId, name = tostring(p.AlertDisplayName), alertType = tostring(p.AlertType), severity = tostring(p.Severity),
    status = tostring(p.Status), intent = tostring(p.Intent), started = tostring(p.StartTimeUtc), entity = tostring(p.CompromisedEntity),
    uri = tostring(p.AlertUri), remediation = tostring(p.RemediationSteps), identifiers = tostring(p.ResourceIdentifiers)
| order by started desc
""",
    "software": """
securityresources
| where type =~ 'microsoft.security/softwareinventories'
| extend p = properties
| extend vm = tolower(tostring(p.azureVmId)), vulns = toint(p.numberOfKnownVulnerabilities), eos = tostring(p.endOfSupportStatus)
| where isnotempty(vm)
| summarize software = count(), vulnerable = countif(vulns > 0), vulnerabilities = sum(vulns),
    pastSupport = countif(eos !in~ ('None', '', 'null')), worst = take_anyif(tostring(p.softwareName), vulns > 0) by vm, subscriptionId
""",
    "topSoftware": """
securityresources
| where type =~ 'microsoft.security/softwareinventories'
| extend p = properties
| extend vm = tolower(tostring(p.azureVmId)), vulns = toint(p.numberOfKnownVulnerabilities)
| where vulns > 0
| summarize machines = dcount(vm), vulnerabilities = max(vulns), versions = make_set(tostring(p.version), 3) by software = tostring(p.softwareName), subscriptionId
| order by machines desc, vulnerabilities desc
""",
    "patches": """
patchassessmentresources
| where type =~ 'microsoft.compute/virtualmachines/patchassessmentresults'
| extend p = properties
| project vm = tolower(tostring(split(id, '/patchAssessmentResults')[0])), subscriptionId,
    critical = toint(p.availablePatchCountByClassification.critical), security = toint(p.availablePatchCountByClassification.security),
    other = toint(p.availablePatchCountByClassification.other), os = tostring(p.osType), assessed = tostring(p.lastModifiedDateTime)
""",
    "standards": """
securityresources
| where type =~ 'microsoft.security/regulatorycompliancestandards'
| extend p = properties
| project subscriptionId, standard = name, state = tostring(p.state), passed = toint(p.passedControls), failed = toint(p.failedControls),
    skipped = toint(p.skippedControls), unsupported = toint(p.unsupportedControls)
""",
    "controls": """
securityresources
| where type =~ 'microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols'
| extend p = properties
| extend standard = tostring(split(id, '/')[6])
| where tostring(p.state) =~ 'Failed'
| project subscriptionId, standard, control = name, description = tostring(p.description), failedAssessments = toint(p.failedAssessments),
    passedAssessments = toint(p.passedAssessments)
| order by failedAssessments desc
""",
    "exposedVms": """
resources
| where type =~ 'microsoft.network/networkinterfaces'
| mv-expand ipc = properties.ipConfigurations
| extend pipId = tolower(tostring(ipc.properties.publicIPAddress.id)), vm = tostring(properties.virtualMachine.id)
| where isnotempty(pipId) and isnotempty(vm)
| join kind=leftouter (resources | where type =~ 'microsoft.network/publicipaddresses'
    | project pipId = tolower(id), ip = tostring(properties.ipAddress), sku = tostring(sku.name)) on pipId
| project id = vm, subscriptionId, ip, sku
""",
    "publicIps": """
resources
| where type =~ 'microsoft.network/publicipaddresses'
| summarize total = count(), attached = countif(isnotnull(properties.ipConfiguration) or isnotnull(properties.natGateway)) by subscriptionId
""",
    "nsgRules": """
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| where tostring(rule.properties.access) =~ 'Allow' and tostring(rule.properties.direction) =~ 'Inbound'
| extend sources = array_concat(pack_array(tostring(rule.properties.sourceAddressPrefix)),
    iff(isnull(rule.properties.sourceAddressPrefixes), dynamic([]), rule.properties.sourceAddressPrefixes))
| mv-expand source = sources to typeof(string)
| where source in~ ('*', 'internet', 'any', '0.0.0.0/0', '0.0.0.0', '/0')
| extend ports = strcat_array(array_concat(pack_array(tostring(rule.properties.destinationPortRange)),
    iff(isnull(rule.properties.destinationPortRanges), dynamic([]), rule.properties.destinationPortRanges)), ',')
| project id, nsg = name, subscriptionId, rule = tostring(rule.name), ports = trim(',', ports), source, priority = toint(rule.properties.priority),
    protocol = tostring(rule.properties.protocol)
| order by priority asc
""",
}
CHANGES_QUERY = """
resourcechanges
| extend p = properties, ts = todatetime(properties.changeAttributes.timestamp)
| where ts > ago({days}d)
| project ts = tostring(ts), changeType = tostring(p.changeType), id = tostring(p.targetResourceId), type = tolower(tostring(p.targetResourceType)),
    by = tostring(p.changeAttributes.changedBy), byType = tostring(p.changeAttributes.changedByType), client = tostring(p.changeAttributes.clientType),
    changes = toint(p.changeAttributes.changesCount), subscriptionId
| order by ts desc
"""


# --- parsing and rules ---------------------------------------------------------------------------------------------

def _first_resource(identifiers):
    """The Azure resource id an alert is about, from its ResourceIdentifiers (a JSON text), or ''."""
    try:
        items = json.loads(identifiers) if isinstance(identifiers, str) else identifiers
    except ValueError:
        return ""
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("AzureResourceId"):
            return str(item["AzureResourceId"])
    return ""


def _first_step(remediation):
    text = str(remediation or "")
    try:
        steps = json.loads(text)
        text = steps[0] if isinstance(steps, list) and steps else text
    except ValueError:
        pass
    return text.strip()[:300]


def alert_rows(rows):
    """Alerts as dashboard rows: {t, id, subscriptionId, name, severity, status, intent, started, entity, uri, step}."""
    result = []
    for row in rows[:MAX_ALERTS]:
        sub = str(row.get("subscriptionId", "")).lower()
        result.append({"t": "alert", "id": _first_resource(row.get("identifiers")) or f"/subscriptions/{sub}", "subscriptionId": sub,
                       "name": row.get("name") or row.get("alertType") or "Alert", "severity": str(row.get("severity", "")).lower(),
                       "status": str(row.get("status", "")), "intent": row.get("intent") or "", "started": str(row.get("started", ""))[:19],
                       "entity": row.get("entity") or "", "uri": row.get("uri") if str(row.get("uri", "")).startswith("https://") else "",
                       "step": _first_step(row.get("remediation"))})
    return result


def evaluate_alerts(run_id, alerts):
    """(findings, stats) of the Defender alerts: one finding per active alert (informational ones are only counted)."""
    findings, per = [], defaultdict(Counter)
    for alert in alerts:
        sub = alert["subscriptionId"]
        per[sub]["total"] += 1
        if alert["status"].lower() not in ("active", "inprogress", "in progress") or alert["severity"] not in SEVERITY:
            continue
        rule = ALERT_RULES[alert["severity"]]
        per[sub][rule] += 1
        _, title, recommendation = RULES[rule]
        findings.append(make_finding(
            run_id, rule_id=rule, source=SOURCE, pillar="Security", severity=SEVERITY[alert["severity"]], title=title.format(name=alert["name"][:120]),
            recommendation=alert["step"] or recommendation, resource_id=alert["id"], resource_name=alert["entity"] or alert["name"][:80],
            subscription_id=sub))
    stats = [{"ruleId": rule, "source": SOURCE, "pillar": "Security", "severity": RULES[rule][0], "subscriptionId": sub,
              "affected": counts[rule], "applicable": counts["total"]}
             for sub, counts in per.items() for rule in ALERT_RULES.values() if counts[rule]]
    return findings, stats


def evaluate_machines(run_id, software, patches):
    """(findings, stats, rows, totals) for the machines: software with known vulnerabilities or past its support, pending patches."""
    findings, rows = [], []
    counts = defaultdict(Counter)

    def finding(rule, row, name):
        severity, title, recommendation = RULES[rule]
        findings.append(make_finding(run_id, rule_id=rule, source=SOURCE, pillar="Security", severity=severity, title=title, recommendation=recommendation,
                                     resource_id=row["vm"], resource_name=name, resource_type="microsoft.compute/virtualmachines",
                                     subscription_id=row["subscriptionId"]))

    for row in software:
        sub = str(row["subscriptionId"]).lower()
        name = str(row["vm"]).rsplit("/", 1)[-1]
        counts[sub]["software"] += 1
        if row.get("vulnerable"):
            counts[sub]["vuln"] += 1
            finding("SEC-VULN-002" if row["vulnerable"] >= VULNERABLE_HIGH else "SEC-VULN-001", row, name)
            counts[sub]["SEC-VULN-002" if row["vulnerable"] >= VULNERABLE_HIGH else "SEC-VULN-001"] += 1
        if row.get("pastSupport"):
            finding("SEC-EOS-001", row, name)
            counts[sub]["SEC-EOS-001"] += 1
        if row.get("vulnerable") or row.get("pastSupport"):
            rows.append({"t": "vuln", "id": row["vm"], "subscriptionId": sub, "software": row.get("software", 0), "vulnerable": row.get("vulnerable", 0),
                         "vulnerabilities": row.get("vulnerabilities", 0), "pastSupport": row.get("pastSupport", 0), "worst": row.get("worst") or ""})
    for row in patches:
        sub = str(row["subscriptionId"]).lower()
        counts[sub]["patched"] += 1
        rule = "SEC-PATCH-001" if (row.get("critical") or 0) > 0 else "SEC-PATCH-002" if (row.get("security") or 0) > 0 else None
        if rule:
            finding(rule, row, str(row["vm"]).rsplit("/", 1)[-1])
            counts[sub][rule] += 1
            rows.append({"t": "patch", "id": row["vm"], "subscriptionId": sub, "critical": row.get("critical") or 0, "security": row.get("security") or 0,
                         "other": row.get("other") or 0, "os": row.get("os") or "", "assessed": str(row.get("assessed") or "")[:19]})
    stats = []
    for sub, count in counts.items():
        for rule in ("SEC-VULN-001", "SEC-VULN-002", "SEC-EOS-001"):
            if count[rule] and count["software"]:
                stats.append({"ruleId": rule, "source": SOURCE, "pillar": "Security", "severity": RULES[rule][0], "subscriptionId": sub,
                              "affected": count[rule], "applicable": count["software"], "applicableTypes": ["microsoft.compute/virtualmachines"]})
        for rule in ("SEC-PATCH-001", "SEC-PATCH-002"):
            if count[rule] and count["patched"]:
                stats.append({"ruleId": rule, "source": SOURCE, "pillar": "Security", "severity": RULES[rule][0], "subscriptionId": sub,
                              "affected": count[rule], "applicable": count["patched"], "applicableTypes": ["microsoft.compute/virtualmachines"]})
    totals = {"inventoried": sum(c["software"] for c in counts.values()), "vulnerable": sum(c["vuln"] for c in counts.values()),
              "pastSupport": sum(c["SEC-EOS-001"] for c in counts.values()), "assessedForPatches": sum(c["patched"] for c in counts.values()),
              "criticalPatches": sum(c["SEC-PATCH-001"] for c in counts.values()), "securityPatches": sum(c["SEC-PATCH-002"] for c in counts.values())}
    return findings, stats, rows, totals


def software_rows(rows):
    return [{"t": "software", "subscriptionId": str(r["subscriptionId"]).lower(), "name": r["software"], "machines": r["machines"],
             "vulnerabilities": r["vulnerabilities"], "versions": r.get("versions") or []} for r in rows[:100]]


def compliance_rows(standards, controls):
    result = [{"t": "standard", "subscriptionId": str(r["subscriptionId"]).lower(), "standard": r["standard"], "state": r["state"], "passed": r["passed"] or 0,
               "failed": r["failed"] or 0, "skipped": r["skipped"] or 0, "unsupported": r["unsupported"] or 0} for r in standards]
    result += [{"t": "control", "subscriptionId": str(r["subscriptionId"]).lower(), "standard": r["standard"], "control": r["control"],
                "description": r["description"], "failed": r["failedAssessments"] or 0, "passed": r["passedAssessments"] or 0} for r in controls[:MAX_CONTROLS]]
    return result


def exposure_rows(vms, rules):
    result = [{"t": "exposed", "id": r["id"], "subscriptionId": str(r["subscriptionId"]).lower(), "ip": r.get("ip") or "", "sku": r.get("sku") or ""} for r in vms[:MAX_EXPOSED]]
    result += [{"t": "nsgrule", "id": r["id"], "subscriptionId": str(r["subscriptionId"]).lower(), "nsg": r["nsg"], "rule": r["rule"], "ports": r["ports"] or "*",
                "source": r["source"], "priority": r.get("priority"), "protocol": r.get("protocol") or ""} for r in rules[:MAX_NSG_RULES]]
    return result


def change_rows(changes):
    relevant = [c for c in changes if c.get("type") in SECURITY_TYPES]
    return [{"t": "change", "id": c["id"], "subscriptionId": str(c.get("subscriptionId", "")).lower(), "ts": str(c.get("ts", ""))[:19], "changeType": c.get("changeType") or "",
             "type": c.get("type") or "", "by": c.get("by") or "", "byType": c.get("byType") or "", "client": c.get("client") or "", "changes": c.get("changes") or 0}
            for c in relevant[:MAX_CHANGES]]


def summarize_changes(changes):
    """Counts of the last CHANGE_DAYS days: by change type, by who (people or the platform) and the share that touched security."""
    kinds = Counter(str(c.get("changeType", "")) for c in changes)
    by_type = Counter(str(c.get("byType", "")) or "Unknown" for c in changes)
    return {"days": CHANGE_DAYS, "total": len(changes), "byChangeType": dict(kinds), "byActor": dict(by_type),
            "securityRelevant": sum(1 for c in changes if c.get("type") in SECURITY_TYPES)}


# --- collection ----------------------------------------------------------------------------------------------------

def _run(credential, subscription_ids, kql, errors, name):
    rows = []
    try:
        for chunk in graph.chunks(subscription_ids):
            rows.extend(graph.query(credential, chunk, kql, max_rows=MAX_ROWS_PER_QUERY))
    except Exception as exc:
        errors.append({"ruleId": f"security-{name}", "error": str(exc).splitlines()[0][:200]})
        return None
    return rows[:MAX_ROWS_PER_QUERY]


def collect(credential, run_id, subscription_ids):
    """Returns (findings, stats, dataset, rows, errors). `dataset` is small and goes into the summary; `rows` are saved apart."""
    errors, available = [], {}
    results = {}
    for name, kql in {**QUERIES, "changes": CHANGES_QUERY.format(days=CHANGE_DAYS)}.items():
        results[name] = _run(credential, subscription_ids, kql, errors, name)
        available[name] = results[name] is not None
    alerts = alert_rows(results["alerts"] or [])
    findings, stats = evaluate_alerts(run_id, alerts)
    machine_findings, machine_stats, machine_rows, machine_totals = evaluate_machines(run_id, results["software"] or [], results["patches"] or [])
    findings += machine_findings
    stats += machine_stats
    rows = alerts + machine_rows + software_rows(results["topSoftware"] or []) + compliance_rows(results["standards"] or [], results["controls"] or []) \
        + exposure_rows(results["exposedVms"] or [], results["nsgRules"] or []) + change_rows(results["changes"] or [])
    ips = results["publicIps"] or []
    dataset = {
        "available": {"alerts": bool(alerts), "software": bool(results["software"]), "patches": bool(results["patches"]), "compliance": bool(results["standards"]),
                      "changes": bool(results["changes"])},
        "queried": available,
        "alerts": {"total": len(alerts), "active": sum(1 for a in alerts if a["status"].lower() in ("active", "inprogress", "in progress")),
                   "bySeverity": dict(Counter(a["severity"] for a in alerts if a["status"].lower() in ("active", "inprogress", "in progress")))},
        "machines": machine_totals,
        "exposure": {"publicIps": sum(i.get("total", 0) for i in ips), "attached": sum(i.get("attached", 0) for i in ips),
                     "exposedMachines": len(results["exposedVms"] or []), "internetRules": len(results["nsgRules"] or [])},
        "changes": summarize_changes(results["changes"] or []),
    }
    return findings, stats, dataset, rows, errors
