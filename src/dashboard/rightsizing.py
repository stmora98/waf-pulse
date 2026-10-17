"""Right-sizing view helpers: which resources are over or under sized, from the metrics dataset."""

ASSESSMENTS = ("idle", "under", "right", "saturated")

# page kind -> (title, dataset kinds, label of each assessment, columns)
KINDS = {
    "vm": ("Virtual machines", ("vm",),
           {"idle": "Idle (under 5% CPU)", "under": "Underutilized (under 15%)", "right": "Right-sized",
            "saturated": "Saturated (80% or more)"}),
    "sql": ("SQL databases", ("sql_dtu", "sql_vcore"),
            {"idle": "Idle", "under": "Oversized (under 10%)", "right": "Right-sized", "saturated": "Saturated (80% or more)"}),
    "plan": ("App Service plans", ("plan",),
             {"idle": "Idle", "under": "Underutilized (under 20% CPU)", "right": "Right-sized",
              "saturated": "Saturated (80% CPU or 85% memory)"}),
    "storage": ("Storage accounts", ("storage",),
                {"idle": "No transactions", "under": "Underutilized", "right": "In use", "saturated": "Saturated"}),
}
HIDDEN_WHEN_EMPTY = {"storage": ("under", "saturated"), "sql": ("idle",), "plan": ("idle",)}


def counts(metrics, kind):
    """{assessment: count, nodata: count} for a page kind, summing the dataset kinds behind it."""
    distribution = metrics.get("distribution") or {}
    total = {name: 0 for name in (*ASSESSMENTS, "nodata")}
    for source in KINDS[kind][1]:
        for name, value in (distribution.get(source) or {}).items():
            if name in total:
                total[name] += value
    return total


def visible_assessments(kind, totals):
    hidden = HIDDEN_WHEN_EMPTY.get(kind, ())
    return [name for name in ASSESSMENTS if name not in hidden or totals.get(name)]


def resources(metrics, kind, assessment=None, subscription=None):
    """The resources of a page kind, optionally narrowed to one assessment and one subscription."""
    kinds = KINDS[kind][1]
    return [r for r in metrics.get("resources") or []
            if r.get("kind") in kinds and (not assessment or r.get("assessment") == assessment)
            and (not subscription or r.get("subscriptionId") == subscription)]
