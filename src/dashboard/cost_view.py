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


def _short(label):
    """MM/YY for a month, MM-DD for a day."""
    return f"{label[5:7]}/{label[2:4]}" if len(label) == 7 else label[5:]


def chart(months):
    """months: [{month, cost, partial}] oldest first (`month` may also be a date). Returns bar chart geometry."""
    top = _nice_ceiling(max((m["cost"] for m in months), default=0))
    plot_w, plot_h = WIDTH - PAD_LEFT - PAD_RIGHT, HEIGHT - PAD_TOP - PAD_BOTTOM
    slot = plot_w / max(len(months), 1)
    width = min(slot * 0.6, 56)
    step = 1 if len(months) <= 14 else 10
    bars = []
    for index, item in enumerate(months):
        height = plot_h * item["cost"] / top if top else 0
        x = PAD_LEFT + slot * index + (slot - width) / 2
        bars.append(
            {"x": round(x, 1), "y": round(PAD_TOP + plot_h - height, 1), "width": round(width, 1),
             "height": round(max(height, 0.5), 1), "label": item["month"], "short": _short(item["month"]),
             "show_label": index % step == 0, "label_x": round(x + width / 2, 1),
             "cost": item["cost"], "partial": bool(item.get("partial"))}
        )
    grid = [{"y": round(PAD_TOP + plot_h * (1 - step / 4), 1), "label": f"{top * step / 4:,.0f}"} for step in range(5)]
    return {"width": WIDTH, "height": HEIGHT, "left": PAD_LEFT, "right": WIDTH - PAD_RIGHT, "label_y": HEIGHT - 10,
            "bars": bars, "grid": grid}

def stacked_columns(matrix, partial_from=None):
    """Stacked column chart of {series, periods, values}. Series are numbered so the page can color them."""
    series, periods, values = matrix.get("series", []), matrix.get("periods", []), matrix.get("values", {})
    totals = [sum(values[name].get(period, 0.0) for name in series) for period in periods]
    top = _nice_ceiling(max(totals, default=0))
    plot_w, plot_h = WIDTH - PAD_LEFT - PAD_RIGHT, HEIGHT - PAD_TOP - PAD_BOTTOM
    slot = plot_w / max(len(periods), 1)
    width = min(slot * 0.7, 56)
    step = 1 if len(periods) <= 14 else 10
    bars = []
    for index, (period, total) in enumerate(zip(periods, totals)):
        x = PAD_LEFT + slot * index + (slot - width) / 2
        floor, segments = PAD_TOP + plot_h, []
        for position, name in enumerate(series):
            value = values[name].get(period, 0.0)
            if value <= 0:
                continue
            height = plot_h * value / top if top else 0
            floor -= height
            segments.append({"y": round(floor, 1), "height": round(max(height, 0.4), 1), "name": name,
                             "color": "other" if name == "Other" else position % 8, "value": round(value, 2)})
        bars.append({"x": round(x, 1), "width": round(width, 1), "label": period, "short": _short(period),
                     "show_label": index % step == 0, "label_x": round(x + width / 2, 1), "total": round(total, 2),
                     "segments": segments, "partial": bool(partial_from and period >= partial_from)})
    grid = [{"y": round(PAD_TOP + plot_h * (1 - n / 4), 1), "label": f"{top * n / 4:,.0f}"} for n in range(5)]
    legend = [{"name": name, "color": "other" if name == "Other" else position % 8} for position, name in enumerate(series)]
    return {"width": WIDTH, "height": HEIGHT, "left": PAD_LEFT, "right": WIDTH - PAD_RIGHT, "label_y": HEIGHT - 10,
            "bars": bars, "grid": grid, "legend": legend}


def movers(matrix, last, previous, limit=8):
    """Rows for the table next to a chart: cost in the last full month, the month before and the change."""
    rows = []
    for name in matrix.get("series", []):
        now, before = matrix["values"][name].get(last, 0.0), matrix["values"][name].get(previous, 0.0)
        change = round((now / before - 1) * 100, 1) if before else None
        rows.append({"name": name, "last": round(now, 2), "previous": round(before, 2), "change": change})
    return sorted(rows, key=lambda row: -row["last"])[:limit]


def running_totals(daily, now_month, previous_month):
    """Cumulative spend by day of the month for this month and the previous one, from a daily series."""
    lines = {}
    for month in (previous_month, now_month):
        points, total = [], 0.0
        for point in daily:
            if point["date"][:7] == month:
                total += point["cost"]
                points.append((int(point["date"][8:10]), round(total, 2)))
        lines[month] = points
    return lines


def line_chart(lines):
    """Two cumulative lines by day of the month: {month: [(day, value)]} -> polylines in chart coordinates."""
    top = _nice_ceiling(max((value for points in lines.values() for _, value in points), default=0))
    plot_w, plot_h = WIDTH - PAD_LEFT - PAD_RIGHT, HEIGHT - PAD_TOP - PAD_BOTTOM
    out = []
    for position, (month, points) in enumerate(lines.items()):
        coords = [{"x": round(PAD_LEFT + plot_w * (day - 1) / 30, 1),
                   "y": round(PAD_TOP + plot_h * (1 - value / top), 1), "day": day, "value": value}
                  for day, value in points]
        if coords:
            out.append({"month": month, "current": position == len(lines) - 1, "dots": coords,
                        "line": " ".join(f"{c['x']},{c['y']}" for c in coords)})
    grid = [{"y": round(PAD_TOP + plot_h * (1 - n / 4), 1), "label": f"{top * n / 4:,.0f}"} for n in range(5)]
    days = [{"x": round(PAD_LEFT + plot_w * (day - 1) / 30, 1), "label": str(day)} for day in (1, 5, 10, 15, 20, 25, 30)]
    return {"width": WIDTH, "height": HEIGHT, "left": PAD_LEFT, "right": WIDTH - PAD_RIGHT, "label_y": HEIGHT - 10,
            "lines": out, "grid": grid, "days": days}
