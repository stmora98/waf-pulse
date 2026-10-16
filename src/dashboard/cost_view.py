"""View helpers for the cost page: bar chart geometry. Pure functions."""

WIDTH, HEIGHT = 640, 240
PAD_LEFT, PAD_RIGHT, PAD_TOP, PAD_BOTTOM = 56, 16, 16, 34


def _nice_ceiling(value):
    """A round upper bound for the axis: 1, 2, 2.5, 5 or 10 times a power of ten."""
    if value <= 0:
        return 1.0
    magnitude = 1.0
    while magnitude * 10 <= value:
        magnitude *= 10
    while magnitude > value:
        magnitude /= 10
    for factor in (1, 2, 2.5, 5, 10):
        if magnitude * factor >= value:
            return magnitude * factor
    return magnitude * 10


def chart(months):
    """months: [{month, cost, partial}] oldest first. Returns the geometry of a bar chart."""
    top = _nice_ceiling(max((m["cost"] for m in months), default=0))
    plot_w, plot_h = WIDTH - PAD_LEFT - PAD_RIGHT, HEIGHT - PAD_TOP - PAD_BOTTOM
    slot = plot_w / max(len(months), 1)
    width = min(slot * 0.6, 56)
    bars = []
    for index, item in enumerate(months):
        height = plot_h * item["cost"] / top if top else 0
        x = PAD_LEFT + slot * index + (slot - width) / 2
        bars.append(
            {"x": round(x, 1), "y": round(PAD_TOP + plot_h - height, 1), "width": round(width, 1),
             "height": round(max(height, 0.5), 1), "label": item["month"], "label_x": round(x + width / 2, 1),
             "cost": item["cost"], "partial": bool(item.get("partial"))}
        )
    grid = [{"y": round(PAD_TOP + plot_h * (1 - step / 4), 1), "label": f"{top * step / 4:,.0f}"} for step in range(5)]
    return {"width": WIDTH, "height": HEIGHT, "left": PAD_LEFT, "right": WIDTH - PAD_RIGHT, "label_y": HEIGHT - 10,
            "bars": bars, "grid": grid}
