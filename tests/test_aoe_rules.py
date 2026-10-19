from datetime import datetime, timezone

from waf_pulse import aoe_rules, lifecycle, metrics, rest, rules

SUB = "11111111-1111-1111-1111-111111111111"


def points(field, *values):
    return [{"timeStamp": f"2026-10-{i + 1:02d}T00:00:00Z", field: value} for i, value in enumerate(values)]


def test_the_extra_rules_are_part_of_the_catalog_with_unique_ids():
    ids = [rule.id for rule in rules.RULES]
    assert len(ids) == len(set(ids))
    for rule in aoe_rules.RULES_EXTRA:
        assert rule in rules.RULES and rule.query.strip().endswith("project id, name, type, subscriptionId")
        assert rule.pillar in rules.PILLARS and rule.severity in rules.SEVERITIES and rule.applies_to


def test_subnet_rules_leave_out_the_subnets_azure_reserves():
    for rule in aoe_rules.RULES_EXTRA:
        if rule.id in ("OPS-NET-001", "OPS-NET-002", "OPS-NET-003"):
            assert "GatewaySubnet" in rule.query and "AzureBastionSubnet" in rule.query


def test_limit_rules_group_by_subscription_and_use_thresholds_below_the_platform_limit():
    by_id = {rule.id: rule for rule in aoe_rules.RULES_EXTRA}
    assert ">= 3200" in by_id["OPS-LIM-001"].query and "4,000" in by_id["OPS-LIM-001"].title
    assert ">= 800" in by_id["OPS-LIM-002"].query and "980" in by_id["OPS-LIM-002"].title
    assert "authorizationresources" in by_id["OPS-LIM-001"].query


# --- storage lifecycle ----------------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


class Credential:
    def get_token(self, scope):
        return type("T", (), {"token": "t"})()


def test_lifecycle_check_reads_the_management_policy(monkeypatch):
    answers = {}
    monkeypatch.setattr(rest, "get", lambda url, token, params=None, headers=None: answers[url.rsplit("/storageAccounts/", 1)[1].split("/")[0]])
    answers.update(a=FakeResponse(200, {"properties": {"policy": {"rules": [{"name": "x"}]}}}), b=FakeResponse(200, {"properties": {"policy": {"rules": []}}}),
                   c=FakeResponse(404), d=FakeResponse(403), e=FakeResponse(500))
    base = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/"
    assert [lifecycle.check(Credential(), base + name) for name in "abcde"] == ["yes", "no", "no", "denied", "error"]


def test_lifecycle_evaluate_counts_and_reports_skips():
    rows = [{"id": f"/s/{n}", "name": n, "subscriptionId": SUB} for n in "abcd"]
    findings, stats, dataset = lifecycle.evaluate("r", rows, {"/s/a": "yes", "/s/b": "no", "/s/c": "denied"})
    assert [f["resourceName"] for f in findings] == ["b"] and findings[0]["ruleId"] == "COST-STG-002" and findings[0]["source"] == "lifecycle"
    assert stats == [{"ruleId": "COST-STG-002", "source": "lifecycle", "pillar": "Cost Optimization", "severity": "low",
                      "subscriptionId": SUB, "affected": 1, "applicable": 2}]
    assert dataset == {"checked": 2, "withPolicy": 1, "percent": 50.0, "skipped": {"denied": 1, "error": 0, "notChecked": 1}}


def test_lifecycle_collect_reports_listing_failures(monkeypatch):
    from waf_pulse import graph

    def boom(*args, **kwargs):
        raise RuntimeError("Forbidden\nmore")

    monkeypatch.setattr(graph, "query", boom)
    findings, stats, dataset, errors = lifecycle.collect(Credential(), "r", [SUB])
    assert findings == [] and errors == [{"ruleId": "lifecycle-list", "error": "Forbidden"}] and dataset["checked"] == 0


# --- scale sets and premium disks -------------------------------------------------------------------------

def test_scale_sets_are_judged_by_cpu():
    assert metrics.classify("vmss", {"Percentage CPU": points("average", 5)}) == ("MET-VMSS-001", 5)
    assert metrics.classify("vmss", {"Percentage CPU": points("average", 50)}) == (None, 50)
    assert metrics.classify("vmss", {"Percentage CPU": points("average", 90)})[0] == "MET-VMSS-002"


def test_a_premium_disk_is_judged_by_the_share_of_its_iops_it_uses():
    raw = {"Composite Disk Read Operations/sec": points("average", 10, 10), "Composite Disk Write Operations/sec": points("average", 20, 20)}
    raw["Composite Disk Read Operations/sec"][0]["maximum"] = 100
    enriched = metrics.enrich_disk(raw, 1000)
    assert enriched["Disk IOPS %"][0]["average"] == 3.0 and enriched["Disk IOPS %"][0]["maximum"] == 10.0
    assert metrics.classify("disk", enriched) == ("MET-DSK-001", 3.0)
    busy = metrics.enrich_disk({"Composite Disk Read Operations/sec": points("average", 950)}, 1000)
    assert metrics.classify("disk", busy)[0] == "MET-DSK-002"
    assert metrics.enrich_disk(raw, None) is raw and metrics.enrich_disk({}, 1000) == {}


def test_disk_records_use_their_iops_limit_in_evaluate():
    disk = {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Compute/disks/d", "name": "d", "subscriptionId": SUB,
            "location": "eastus", "detail": "Premium_LRS 128 GB", "iops": 500}
    raw = {"Composite Disk Read Operations/sec": points("average", 5), "Composite Disk Write Operations/sec": points("average", 5)}
    findings, _, dataset = metrics.evaluate("r", {"disk": [disk]}, {disk["id"].lower(): raw})
    assert [f["ruleId"] for f in findings] == ["MET-DSK-001"] and dataset["resources"][0]["avg"] == 2.0


def test_the_dashboard_knows_the_new_kinds():
    import rightsizing
    assert "vmss" in rightsizing.KINDS and "disk" in rightsizing.KINDS
    assert rightsizing.kind_labels("disk")["under"].startswith("Barely used")
    record = {"kind": "disk", "avg": 2.0, "assessment": "under"}
    assert rightsizing.assess(record, rightsizing.DEFAULT_THRESHOLDS) == "under"
    assert rightsizing.assess({**record, "avg": 95}, rightsizing.DEFAULT_THRESHOLDS) == "saturated"
    from waf_pulse import metrics as collector
    assert collector.DEFAULT_THRESHOLDS == rightsizing.DEFAULT_THRESHOLDS
