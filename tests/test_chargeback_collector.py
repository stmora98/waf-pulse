from waf_pulse import spend

SUB_A = "AAAAAAAA-0000-0000-0000-000000000001"
SUB_B = "bbbbbbbb-0000-0000-0000-000000000002"


def props(columns, rows):
    return {"columns": [{"name": c} for c in columns], "rows": rows}


def test_tag_rows_parse_untagged_as_empty_value():
    page = props(["Cost", "BillingMonth", "TagKey", "TagValue", "SubscriptionId", "Currency"],
                 [[10.0, "2026-09-01T00:00:00", "env", "prod", SUB_A, "USD"], [90.0, "2026-09-01T00:00:00", "env", None, SUB_A, "USD"]])
    rows = spend.parse_grouped(page, spend.TAG_DIMENSIONS)
    assert [r["TagValue"] for r in rows] == ["prod", ""]
    result = spend.tag_rows("env", rows)
    assert {r["value"]: r["months"] for r in result} == {"prod": {"2026-09": 10.0}, "": {"2026-09": 90.0}}
    assert result[0]["sub"] == SUB_A.lower() and result[0]["key"] == "env"


def test_tag_rows_fold_small_values_per_subscription():
    rows = [{"TagValue": f"v{i}", "SubscriptionId": SUB_A, "cost": 100.0 - i, "period": "2026-09-01"} for i in range(spend.MAX_TAG_VALUES + 3)]
    rows.append({"TagValue": "tail", "SubscriptionId": SUB_B, "cost": 0.5, "period": "2026-09-01"})
    result = spend.tag_rows("k", rows)
    values = {(r["value"], r["sub"]) for r in result}
    assert ("v0", SUB_A.lower()) in values
    assert (spend.OTHER_VALUES, SUB_A.lower()) in values and (spend.OTHER_VALUES, SUB_B.lower()) in values
    assert sum(sum(r["months"].values()) for r in result) == round(sum(r["cost"] for r in rows), 2)


def test_chargeback_rows_merge_case_and_drop_zero():
    rows = [{"SubscriptionId": SUB_A, "ResourceGroupName": "Rg-One", "cost": 5.0, "period": "2026-08-01"},
            {"SubscriptionId": SUB_A, "ResourceGroupName": "rg-one", "cost": 7.0, "period": "2026-09-01"},
            {"SubscriptionId": SUB_B, "ResourceGroupName": "", "cost": 50.0, "period": "2026-09-01"},
            {"SubscriptionId": SUB_B, "ResourceGroupName": "empty", "cost": 0.0, "period": "2026-09-01"}]
    result = spend.chargeback_rows(rows)
    assert [r["rg"] for r in result] == ["", "Rg-One"]
    assert result[1]["months"] == {"2026-08": 5.0, "2026-09": 7.0}


def test_discover_tag_keys_override_and_ranking(monkeypatch):
    assert spend.discover_tag_keys(None, [], " CostCenter, Owner ") == ["CostCenter", "Owner"]
    from waf_pulse import graph
    monkeypatch.setattr(graph, "query", lambda *a, **k: [{"k": "created-at", "resources": 99}, {"k": "Environment", "resources": 3}, {"k": "CostCenter", "resources": 1}])
    assert spend.discover_tag_keys(None, [SUB_A]) == ["CostCenter", "Environment", "created-at"]
    monkeypatch.setattr(graph, "query", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no")))
    assert spend.discover_tag_keys(None, [SUB_A]) == []


def test_collect_returns_extras(monkeypatch):
    def fake_fetch(token, scope, name, now):
        if name == "subGroup":
            return [{"SubscriptionId": SUB_A, "ResourceGroupName": "rg", "cost": 3.0, "period": "2026-09-01", "currency": "USD"}]
        if name == "tag:env":
            return [{"TagKey": "env", "TagValue": "", "SubscriptionId": SUB_A, "cost": 3.0, "period": "2026-09-01", "currency": "USD"}]
        return []
    monkeypatch.setattr(spend, "fetch", fake_fetch)
    import datetime
    extras = {}
    section, partial = spend.collect("t", ["/subscriptions/x"], datetime.datetime(2026, 10, 5, tzinfo=datetime.timezone.utc), float("inf"), tag_keys=["env"], extras=extras)
    assert extras["chargeback"][0]["rg"] == "rg" and extras["tagCosts"][0]["key"] == "env"
    assert section["tagKeys"] == ["env"]
