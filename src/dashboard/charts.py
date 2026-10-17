"""Chart geometry for the dashboard. Pure functions: the templates draw SVG from these numbers, so no inline style
or script is needed and the content security policy stays strict."""

SEVERITIES = ("critical", "high", "medium", "low")


def _shorten(text, limit):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def hbars(items, width=520, label_limit=28, row_height=26, label_width=190, value_width=44):
    """Horizontal bars. items: [(label, value, href or None)], largest first."""
    items = list(items)
    top = max((value for _, value, _ in items), default=0) or 1
    track = max(width - label_width - value_width, 40)
    rows = []
    for index, (label, value, href) in enumerate(items):
        rows.append({
            "y": index * row_height, "label": _shorten(label, label_limit), "full": str(label), "value": value,
            "bar": round(max(track * value / top, 2 if value else 0), 1), "href": href,
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
