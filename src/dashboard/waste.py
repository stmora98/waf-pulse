"""Money behind the findings that ask to remove or shut something down: what each of those resources cost in the last 30 days (amortized),
from the per-resource costs the collector keeps for the most expensive resources. Removing a resource saves at most what it costs, so the
figures are "up to"; resources that are not among the costed ones count as zero."""
from collections import defaultdict

# rule id -> what removing it saves. Only rules whose fix is to delete or shut the resource down: resizing and licensing have their own numbers.
WASTE_RULES = {
    "COST-DISK-001": "Delete or snapshot and delete the unattached disks",
    "COST-IP-001": "Delete the public IP addresses that nothing uses",
    "COST-SNAP-001": "Delete the old snapshots",
    "COST-NAT-001": "Delete the NAT gateways no subnet uses",
    "COST-LB-001": "Delete the load balancers without a backend",
    "COST-AGW-001": "Delete the application gateways without targets",
    "COST-ASP-001": "Delete the App Service plans without apps",
    "COST-SQL-001": "Delete the empty elastic pools",
    "COST-VMSS-001": "Delete the scale sets without instances",
    "COST-VM-002": "Deallocate the stopped virtual machines",
    "MET-VM-001": "Shut down or delete the idle virtual machines",
    "MET-STG-001": "Delete the storage accounts nobody uses",
}
TOP = 5


def savings(findings, costs):
    """findings: the findings in view; costs: [{id (lower), cost}]. Returns {total, costed, rules: [{ruleId, action, resources, costed,
    saves, top: [{id, name, cost}]}], by_rule: {ruleId: saves}} with the rules that save the most first."""
    cost_by_id = {str(c["id"]).lower(): c["cost"] for c in costs or []}
    by_rule = defaultdict(dict)
    for finding in findings:
        rule = finding.get("ruleId")
        if rule in WASTE_RULES:
            by_rule[rule][str(finding.get("resourceId", "")).lower()] = finding.get("resourceName") or str(finding.get("resourceId", "")).rsplit("/", 1)[-1]
    rows = []
    for rule, resources in by_rule.items():
        priced = [(rid, name, cost_by_id[rid]) for rid, name in resources.items() if cost_by_id.get(rid)]
        priced.sort(key=lambda item: -item[2])
        rows.append({"ruleId": rule, "action": WASTE_RULES[rule], "resources": len(resources), "costed": len(priced), "saves": round(sum(p[2] for p in priced), 2),
                     "top": [{"id": rid, "name": name, "cost": round(cost, 2)} for rid, name, cost in priced[:TOP]]})
    rows.sort(key=lambda r: (-r["saves"], -r["resources"], r["ruleId"]))
    return {"total": round(sum(r["saves"] for r in rows), 2), "costed": sum(r["costed"] for r in rows), "resources": sum(r["resources"] for r in rows),
            "rules": rows, "by_rule": {r["ruleId"]: r["saves"] for r in rows}}
