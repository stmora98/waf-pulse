"""Chart geometry for the dashboard. Pure functions: the templates draw SVG from these numbers, so no inline style
or script is needed and the content security policy stays strict."""

from datetime import date, timedelta

SEVERITIES = ("critical", "high", "medium", "low")


def _shorten(text, limit):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def hbars(items, width=520, label_limit=28, row_height=26, label_width=190, value_width=44):
    """Horizontal bars. items: [(label, value, href or None[, css class])], largest first."""
    items = [tuple(item) + (None,) * (4 - len(item)) for item in items]
    top = max((item[1] for item in items), default=0) or 1
    track = max(width - label_width - value_width, 40)
    rows = []
    for index, (label, value, href, css) in enumerate(items):
        rows.append({
            "y": index * row_height, "label": _shorten(label, label_limit), "full": str(label), "value": value,
            "bar": round(max(track * value / top, 2 if value else 0), 1), "href": href, "css": css or "",
        })
    return {"width": width, "height": max(len(rows) * row_height, row_height), "rows": rows,
            "label_width": label_width, "bar_height": row_height - 10, "text_y": row_height / 2 + 4}


def stacked(rows, width=520, label_width=150, row_height=30, value_width=44):
    """Stacked horizontal bars. rows: [(label, {severity: count}, href or None)]."""
    rows = list(rows)
    totals = [sum(parts.get(level, 0) for level in SEVERITIES) for _, parts, _ in rows]
    top = max(totals, default=0) or 1
    track = max(width - label_width - value_width, 40)
    out = []
    for index, ((label, parts, href), total) in enumerate(zip(rows, totals)):
        x, segments = float(label_width), []
        for level in SEVERITIES:
            count = parts.get(level, 0)
            if not count:
                continue
            segment_width = max(track * count / top, 2)
            segments.append({"x": round(x, 1), "width": round(segment_width, 1), "level": level, "count": count})
            x += segment_width
        out.append({"y": index * row_height, "label": _shorten(label, 22), "total": total, "segments": segments,
                    "href": href, "end": round(x + 6, 1)})
    return {"width": width, "height": max(len(out) * row_height, row_height), "rows": out,
            "bar_height": row_height - 12, "text_y": row_height / 2 + 4}


def sparkline(points, width=360, height=90, pad=8):
    """points: [(label, value)] oldest first. Returns the polyline and the dots."""
    points = list(points)
    if not points:
        return None
    top = max(value for _, value in points) or 1
    step = (width - 2 * pad) / max(len(points) - 1, 1)
    coords = []
    for index, (label, value) in enumerate(points):
        x = pad + step * index if len(points) > 1 else width / 2
        y = height - pad - (height - 2 * pad) * value / top
        coords.append({"x": round(x, 1), "y": round(y, 1), "label": label, "value": value})
    return {"width": width, "height": height, "dots": coords, "top": top,
            "line": " ".join(f"{c['x']},{c['y']}" for c in coords)}

def trend(series, width=720, height=220, left=36, right=12, top=10, bottom=26, marks=()):
    """Daily curves on a 0-100 scale. series: {from: 'YYYY-MM-DD', cpu, cpuMax, mem: [value or None, ...]}; marks: [(value,
    label)] horizontal reference lines. Returns the polylines (broken where a day has no data), grid, ticks and the points
    to hover, or None without data."""
    if not series or not any(v is not None for v in series.get("cpu", [])):
        return None
    count = len(series["cpu"])
    try:
        first = date.fromisoformat(series["from"])
    except (KeyError, ValueError):
        first = None
    inner_w, inner_h = width - left - right, height - top - bottom
    step = inner_w / max(count - 1, 1)

    def point(index, value):
        return round(left + step * index, 1), round(top + inner_h * (1 - min(max(value, 0), 100) / 100), 1)

    def lines(values):
        runs, current = [], []
        for index, value in enumerate(values):
            if value is None:
                if current:
                    runs.append(current)
                current = []
            else:
                current.append(point(index, value))
        if current:
            runs.append(current)
        return [" ".join(f"{x},{y}" for x, y in run) if len(run) > 1 else f"{run[0][0] - 2},{run[0][1]} {run[0][0] + 2},{run[0][1]}" for run in runs]

    def day(index):
        return (first + timedelta(days=index)).isoformat() if first else str(index + 1)

    curves = []
    for key, name in (("cpuMax", "Peak CPU"), ("cpu", "Average CPU"), ("mem", "Memory in use")):
        values = series.get(key)
        if values and any(v is not None for v in values):
            curves.append({"key": key, "name": name, "lines": lines(values),
                           "dots": [{"x": point(i, v)[0], "y": point(i, v)[1], "tip": f"{day(i)} · {name} {v:g}%"} for i, v in enumerate(values) if v is not None]})
    ticks = sorted({0, count // 2, count - 1})
    return {
        "width": width, "height": height, "left": left, "right": width - right, "curves": curves,
        "grid": [{"y": point(0, v)[1], "label": f"{v}%"} for v in (0, 25, 50, 75, 100)],
        "marks": [{"y": point(0, v)[1], "label": label} for v, label in marks],
        "ticks": [{"x": point(i, 0)[0], "label": day(i)[5:]} for i in ticks], "label_y": height - 6,
    }
