"""Security page helpers: the rows the collector kept (alerts, vulnerable machines, exposure, compliance, changes) turned into what
each tab shows. Pure functions over lists of rows."""
from collections import Counter, defaultdict

SECURITY_TABS = (("posture", "Posture"), ("vulnerabilities", "Vulnerabilities"), ("exposure", "Exposure"), ("alerts", "Alerts"),
                 ("compliance", "Compliance"), ("changes", "Changes"))
TAB_KEYS = tuple(key for key, _ in SECURITY_TABS)
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3}
MANAGEMENT_PORTS = (22, 23, 3389, 5985, 5986)
DATABASE_PORTS = (1433, 1521, 3306, 5432, 6379, 27017, 9200, 445)


def by_type(rows, kind):
    return [r for r in rows if r.get("t") == kind]


def name_of(resource_id):
    return str(resource_id).rstrip("/").rsplit("/", 1)[-1]


def port_class(ports):
    """'management', 'database', 'any' or '' for the destination ports of an NSG rule ('22', '1000-2000', '80,443', '*')."""
    found = set()
    for part in str(ports or "*").replace(" ", "").split(","):
        if part in ("*", ""):
            return "any"
        try:
            low, _, high = part.partition("-")
            low, high = int(low), int(high or low)
        except ValueError:
            continue
        if any(low <= p <= high for p in MANAGEMENT_PORTS):
            found.add("management")
        if any(low <= p <= high for p in DATABASE_PORTS):
            found.add("database")
    return "management" if "management" in found else "database" if "database" in found else ""


def vulnerabilities(rows):
    machines = sorted(by_type(rows, "vuln"), key=lambda r: (-(r.get("vulnerabilities") or 0), -(r.get("pastSupport") or 0)))
    patches = sorted(by_type(rows, "patch"), key=lambda r: (-(r.get("critical") or 0), -(r.get("security") or 0)))
    software = defaultdict(lambda: {"machines": 0, "vulnerabilities": 0, "versions": []})
    for r in by_type(rows, "software"):
        item = software[r["name"]]
        item["machines"] += r.get("machines") or 0
        item["vulnerabilities"] = max(item["vulnerabilities"], r.get("vulnerabilities") or 0)
        item["versions"] = (item["versions"] + [v for v in r.get("versions") or [] if v not in item["versions"]])[:3]
    top = sorted(({"name": name, **value} for name, value in software.items()), key=lambda r: (-r["machines"], -r["vulnerabilities"]))
    return {"machines": machines, "patches": patches, "software": top[:25]}


def exposure(rows):
    rules = by_type(rows, "nsgrule")
    for rule in rules:
        rule["class"] = port_class(rule.get("ports"))
    rules.sort(key=lambda r: ({"any": 0, "management": 1, "database": 2, "": 3}[r["class"]], r.get("priority") if r.get("priority") is not None else 99999))
    return {"vms": by_type(rows, "exposed"), "rules": rules, "risky": sum(1 for r in rules if r["class"])}


def alerts(rows):
    items = sorted(by_type(rows, "alert"), key=lambda r: (r.get("status", "").lower() not in ("active", "inprogress", "in progress"),
                                                          SEVERITY_ORDER.get(r.get("severity"), 9), "".join(reversed(r.get("started", "")))))
    active = [a for a in items if a.get("status", "").lower() in ("active", "inprogress", "in progress")]
    return {"alerts": items, "active": active, "bySeverity": Counter(a.get("severity", "") for a in active)}


def compliance(rows):
    standards = defaultdict(lambda: Counter())
    for r in by_type(rows, "standard"):
        for key in ("passed", "failed", "skipped", "unsupported"):
            standards[r["standard"]][key] += r.get(key) or 0
    summary = []
    for name, counts in standards.items():
        judged = counts["passed"] + counts["failed"]
        summary.append({"standard": name, **counts, "percent": round(100 * counts["passed"] / judged, 1) if judged else None})
    summary.sort(key=lambda s: (s["percent"] is None, s["percent"] if s["percent"] is not None else 0))
    controls = defaultdict(lambda: {"failed": 0, "passed": 0, "description": ""})
    for r in by_type(rows, "control"):
        item = controls[(r["standard"], r["control"])]
        item["failed"] += r.get("failed") or 0
        item["passed"] += r.get("passed") or 0
        item["description"] = item["description"] or r.get("description", "")
    failed = sorted(({"standard": s, "control": c, **v} for (s, c), v in controls.items()), key=lambda r: -r["failed"])
    return {"standards": summary, "controls": failed[:60]}


def changes(rows):
    items = sorted(by_type(rows, "change"), key=lambda r: r.get("ts", ""), reverse=True)
    return {"changes": items, "byType": Counter(r.get("type", "") for r in items).most_common(8), "byActor": Counter(r.get("byType") or "Unknown" for r in items),
            "byChange": Counter(r.get("changeType", "") for r in items)}
