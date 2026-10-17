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

    def fake_collect(token, scopes, now, deadline, clock):
        seen["scopes"] = scopes
        return {"byService": {"series": ["S"], "periods": [month], "values": {"S": {month: 5.0}}}}, False

    monkeypatch.setattr(spend, "collect", fake_collect)

    class Cred:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()

    _, _, dataset, _ = finops.collect(Cred(), "r1", ["SUB1"], now=NOW)
    assert seen["scopes"] == ["/providers/Microsoft.Management/managementGroups/tenant-1"]
    assert dataset["breakdowns"]["byService"]["series"] == ["S"] and dataset["breakdowns"]["partial"] is False
