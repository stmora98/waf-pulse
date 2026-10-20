from datetime import datetime, timezone

from waf_pulse import finops, spend

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)


def props(columns, rows):
    return {"columns": [{"name": c} for c in columns], "rows": rows}


def test_parse_grouped_reads_dimensions_by_name_and_normalizes_periods():
    rows = spend.parse_grouped(props(["Cost", "UsageDate", "ServiceName", "Currency"],
                                     [[1.5, 20261005, "Storage", "USD"], [2, "2026-10-06T00:00:00", None, "USD"]]),
                               ("ServiceName",))
    assert rows == [{"ServiceName": "Storage", "cost": 1.5, "currency": "USD", "period": "2026-10-05"},
                    {"ServiceName": "", "cost": 2.0, "currency": "USD", "period": "2026-10-06"}]
    assert spend.parse_grouped(props(["Cost", "ServiceName"], []), ("ResourceLocation",)) == []


def row(period, cost, **dims):
    return {"period": period, "cost": cost, "currency": "USD", **dims}


def test_matrix_keeps_the_largest_series_and_adds_up_the_rest():
    rows = [row("2026-09-01", 10, ServiceName="A"), row("2026-10-01", 20, ServiceName="A"),
            row("2026-09-01", 5, ServiceName="B"), row("2026-09-01", 1, ServiceName="C"),
            row("2026-10-01", 2, ServiceName="D"), row("2026-10-01", 4, ServiceName="")]
    result = spend.matrix(rows, "ServiceName", spend.monthly, top=2)
    assert result["series"] == ["A", "B", "Other"] and result["periods"] == ["2026-09", "2026-10"]
    assert result["values"]["A"] == {"2026-09": 10.0, "2026-10": 20.0}
    assert result["values"]["Other"] == {"2026-09": 1.0, "2026-10": 6.0}  # C, D and the unnamed one
    assert spend.matrix([], "ServiceName", spend.monthly) == {"series": [], "periods": [], "values": {}}


def test_two_dimension_rows_are_totalled_per_dimension():
    rows = [row("2026-10-01", 3, ServiceName="A", ResourceLocation="east"),
            row("2026-10-01", 4, ServiceName="A", ResourceLocation="west"),
            row("2026-10-01", 5, ServiceName="B", ResourceLocation="east")]
    built = spend.build({"serviceLocation": rows}, NOW)
    assert built["byService"]["values"]["A"]["2026-10"] == 7.0 and built["byLocation"]["values"]["east"]["2026-10"] == 8.0
    assert "byResourceGroup" not in built and "dailyByService" not in built


def test_commitment_coverage_counts_reservations_and_savings_plans():
    rows = [row("2026-09-01", 60, PricingModel="OnDemand"), row("2026-09-01", 30, PricingModel="Reservation"),
            row("2026-09-01", 10, PricingModel="SavingsPlan"), row("2026-10-01", 50, PricingModel="OnDemand")]
    coverage = spend.commitment_coverage(rows, NOW)
    assert coverage["lastMonth"] == {"month": "2026-09", "percent": 40.0, "committed": 40.0}
    assert coverage["thisMonth"]["percent"] == 0.0


def test_top_resources_are_ranked_named_and_free_ones_dropped():
    rows = [row("", 5, ResourceId="/s/rg/providers/x/db"), row("", 9, ResourceId="/S/RG/providers/x/VM"),
            row("", 0, ResourceId="/s/free"), row("", 3, ResourceId="")]
    assert spend.top_resources(rows) == [{"id": "/s/rg/providers/x/vm", "name": "vm", "cost": 9.0},
                                         {"id": "/s/rg/providers/x/db", "name": "db", "cost": 5.0}]


def test_collect_adds_scopes_together_and_reports_partial_reads(monkeypatch):
    def fake_fetch(token, scope, name, now):
        if name == "pricing":
            raise RuntimeError("throttled")
        if name == "serviceLocation":
            return [row("2026-10-01", 2 if scope.endswith("a") else 3, ServiceName="A", ResourceLocation="east")]
        return []

    monkeypatch.setattr(spend, "fetch", fake_fetch)
    section, partial = spend.collect("t", ["/subscriptions/a", "/subscriptions/b"], NOW, deadline=1e12, clock=lambda: 0)
    assert section["byService"]["values"]["A"]["2026-10"] == 5.0 and partial is True and "byPricingModel" not in section
    section, partial = spend.collect("t", ["/subscriptions/a"], NOW, deadline=-1, clock=lambda: 0)
    assert section == {} and partial is True  # out of time: nothing was read


def test_finops_collect_stores_the_breakdowns_next_to_the_totals(monkeypatch):
    monkeypatch.setenv("COLLECTOR_TENANT_ID", "tenant-1")
    month = NOW.strftime("%Y-%m")
    monkeypatch.setattr(finops, "fetch_tenant_costs", lambda *a: ("ok", [{"month": month, "service": "S", "cost": 5.0,
                                                                         "currency": "USD", "subscriptionId": "sub1"}]))
    monkeypatch.setattr(finops, "fetch_effective", lambda *a: ("ok", {month: 5.0}))
    monkeypatch.setattr(finops, "fetch_daily", lambda *a: ("ok", []))
    monkeypatch.setattr(finops, "fetch_budgets", lambda *a: ("ok", []))
    seen = {}

    def fake_collect(token, scopes, now, deadline, clock, costs=None, **kwargs):
        seen["scopes"] = scopes
        costs.append({"id": "/s/x", "cost": 4.0})
        return {"byService": {"series": ["S"], "periods": [month], "values": {"S": {month: 5.0}}}}, False

    monkeypatch.setattr(spend, "collect", fake_collect)

    class Cred:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    _, _, dataset, _ = finops.collect(Cred(), "r1", ["SUB1"], now=NOW)
    assert seen["scopes"] == ["/providers/Microsoft.Management/managementGroups/tenant-1"]
    assert dataset["breakdowns"]["byService"]["series"] == ["S"] and dataset["breakdowns"]["partial"] is False
    assert dataset["resourceCosts"] == [{"id": "/s/x", "cost": 4.0}]  # kept apart from the summary by the activity


def test_the_cost_of_each_resource_is_ranked_lowercased_and_capped(monkeypatch):
    rows = [row("", 5, ResourceId="/S/A"), row("", 3, ResourceId="/s/a"), row("", 9, ResourceId="/s/b"),
            row("", 0, ResourceId="/s/free"), row("", 4, ResourceId="")]
    assert spend.resource_costs(rows) == [{"id": "/s/b", "cost": 9.0}, {"id": "/s/a", "cost": 8.0}]
    monkeypatch.setattr(spend, "MAX_COSTS", 1)
    assert spend.resource_costs(rows) == [{"id": "/s/b", "cost": 9.0}]


def test_collect_hands_the_resource_costs_back_only_when_asked(monkeypatch):
    monkeypatch.setattr(spend, "fetch", lambda token, scope, name, now: [row("", 7, ResourceId="/s/a")] if name == "resources" else [])
    costs = []
    spend.collect("t", ["/subscriptions/a"], NOW, deadline=1e12, clock=lambda: 0, costs=costs)
    assert costs == [{"id": "/s/a", "cost": 7.0}]
    assert spend.collect("t", ["/subscriptions/a"], NOW, deadline=1e12, clock=lambda: 0)[1] in (True, False)

# --- commitment utilization --------------------------------------------------------------------------------------

def benefit(month, cost, name="", charge="Usage", currency="USD"):
    return {"period": f"{month}-01", "cost": cost, "BenefitName": name, "ChargeType": charge, "currency": currency}


def test_utilization_of_reservations_and_savings_plans_of_the_last_full_month():
    rows = [benefit("2026-09", 700, "ri-vms"), benefit("2026-09", 300, "ri-vms", "UnusedReservation"),
            benefit("2026-09", 1000, "sp-compute"), benefit("2026-09", 20, "sp-compute", "UnusedSavingsPlan"),
            benefit("2026-09", 5000), benefit("2026-08", 10, "ri-vms", "UnusedReservation"), benefit("2026-10", 99, "ri-vms", "UnusedReservation")]
    items = spend.commitment_utilization(rows, NOW)
    assert [(i["name"], i["kind"], i["percent"], i["unused"], i["used"]) for i in items] == [
        ("ri-vms", "reservation", 70.0, 300.0, 700.0), ("sp-compute", "savingsplan", 98.0, 20.0, 1000.0)]
    assert items[0]["month"] == "2026-09" and items[0]["currency"] == "USD"
    assert spend.commitment_utilization([benefit("2026-09", 5000)], NOW) == []  # no commitments
    assert spend.commitment_utilization([benefit("2026-10", 5, "x", "UnusedReservation")], NOW) == []  # no full month yet
    assert spend.commitment_utilization([], NOW) == []


def test_an_unused_charge_without_a_name_is_still_listed():
    items = spend.commitment_utilization([benefit("2026-09", 80, "", "UnusedReservation")], NOW)
    assert items == [{"name": "(unnamed reservation)", "kind": "reservation", "month": "2026-09", "used": 0.0, "unused": 80.0, "percent": 0.0, "currency": "USD"}]


def test_the_breakdowns_carry_the_utilization():
    built = spend.build({"benefits": [benefit("2026-09", 700, "ri", "Usage"), benefit("2026-09", 300, "ri", "UnusedReservation")]}, NOW)
    assert built["commitmentUtilization"][0]["percent"] == 70.0
    assert "commitmentUtilization" not in spend.build({"benefits": None}, NOW)
    assert "benefits" in spend.QUERIES and spend.QUERIES["benefits"][1] == ("BenefitName", "ChargeType")


def test_under_used_commitments_become_findings_by_how_bad_they_are():
    items = [{"name": "ri-bad", "kind": "reservation", "month": "2026-09", "used": 400, "unused": 600, "percent": 40.0, "currency": "USD"},
             {"name": "sp-meh", "kind": "savingsplan", "month": "2026-09", "used": 700, "unused": 300, "percent": 70.0, "currency": "USD"},
             {"name": "ri-fine", "kind": "reservation", "month": "2026-09", "used": 950, "unused": 50, "percent": 95.0, "currency": "USD"},
             {"name": "ri-tiny", "kind": "reservation", "month": "2026-09", "used": 1, "unused": 10, "percent": 9.1, "currency": "USD"}]
    findings, stats = finops.commitment_findings("r", items)
    assert [(f["resourceName"], f["severity"]) for f in findings] == [("ri-bad", "high"), ("sp-meh", "medium")]
    assert "Reservation 'ri-bad' was used 40% in 2026-09: 600 USD paid for nothing" == findings[0]["title"] and findings[1]["title"].startswith("Savings plan 'sp-meh'")
    assert stats == [{"ruleId": "FIN-COM-001", "source": "finops", "pillar": "Cost Optimization", "severity": "medium", "subscriptionId": "tenant", "affected": 2, "applicable": 4}]
    assert finops.commitment_findings("r", []) == ([], [])
