from charts import hbars, sparkline, stacked
import insights


def test_hbars_scale_to_the_largest_value_and_shorten_long_labels():
    chart = hbars([("a" * 60, 10, None), ("b", 5, "/x"), ("c", 0, None)], width=400)
    rows = chart["rows"]
    track = 400 - chart["label_width"] - 44
    assert rows[0]["bar"] == round(track, 1) and rows[1]["bar"] == round(track / 2, 1) and rows[2]["bar"] == 0
    assert rows[0]["label"].endswith("…") and rows[0]["full"] == "a" * 60 and rows[1]["href"] == "/x"
    assert chart["height"] == 3 * 26 and hbars([])["rows"] == []


def test_stacked_bars_lay_segments_side_by_side_in_severity_order():
    chart = stacked([("Security", {"low": 1, "critical": 1}, None), ("Empty", {}, None)])
    first = chart["rows"][0]
    assert [s["level"] for s in first["segments"]] == ["critical", "low"] and first["total"] == 2
    assert first["segments"][1]["x"] > first["segments"][0]["x"] and chart["rows"][1]["segments"] == []


def test_sparkline_needs_points_and_keeps_them_in_the_box():
    assert sparkline([]) is None
    spark = sparkline([("a", 1), ("b", 4), ("c", 2)])
    assert len(spark["dots"]) == 3 and all(0 <= d["y"] <= spark["height"] for d in spark["dots"])
    assert spark["dots"][1]["y"] < spark["dots"][0]["y"]  # larger values are higher


def finding(rule, severity="high", resource="r", title="t", **extra):
    return {"ruleId": rule, "severity": severity, "resourceId": resource, "title": title, "pillar": "Security",
            "source": "builtin", "subscriptionId": "s1", **extra}


def test_group_rules_orders_by_severity_then_reach_and_counts_distinct_resources():
    rows = insights.group_rules([
        finding("A", "low", "r1"), finding("A", "low", "R1"), finding("B", "high", "r1"),
        finding("C", "high", "r1"), finding("C", "high", "r2"), finding("C", "critical", "r3")])
    assert [r["ruleId"] for r in rows] == ["C", "B", "A"]
    assert rows[0]["severity"] == "critical" and rows[0]["resources"] == 3 and rows[2]["resources"] == 1


def test_group_titles_hide_measured_values():
    rows = insights.group_rules([finding("M", title="CPU 3.2% over 30 days", resource="a"),
                                 finding("M", title="CPU 11.8% over 30 days", resource="b")])
    assert rows[0]["title"] == "CPU …% over … days"
    assert insights.group_rules([finding("S", title="Same")])[0]["title"] == "Same"


def test_counts_and_worst_resources_skip_blank_values_and_commitments():
    rows = [finding("A", resourceType="Microsoft.Storage/storageAccounts"), finding("B", resourceType=""),
            finding("C", resource="/s/commitments/vm"), finding("D", resource="/s/x/db", resourceName="db")]
    assert insights.top_counts(rows, "resourceType", transform=insights.short_type) == [("storage/storageaccounts", 1)]
    assert insights.worst_resources(rows) == [("r", "r", 2), ("db", "/s/x/db", 1)]
    assert insights.severity_totals(rows) == {"critical": 0, "high": 4, "medium": 0, "low": 0}
    assert insights.by_pillar(rows, ["Security", "Reliability"])[1] == ("Reliability", {})
