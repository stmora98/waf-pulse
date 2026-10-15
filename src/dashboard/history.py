"""Run history: trend chart geometry and run-to-run comparison. Pure functions, no I/O."""
from datetime import datetime

from data import PILLARS, SEVERITIES

CHART_WIDTH = 640
CHART_HEIGHT = 240
PAD_LEFT, PAD_RIGHT, PAD_TOP, PAD_BOTTOM = 40, 16, 16, 36
MAX_LISTED = 200


def slug(pillar):
    return pillar.lower().replace(" ", "-")


def _parse(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def duration_seconds(run):
    started, completed = _parse(run.get("startedUtc")), _parse(run.get("completedUtc"))
    if started and completed:
        return max(0, round((completed - started).total_seconds()))
    return None


def short_time(value):
    parsed = _parse(value)
    return parsed.strftime("%m-%d %H:%M") if parsed else ""


def trend(runs):
    """runs: newest first. Returns the geometry of a score-over-time line chart, oldest run on the left."""
    scored = [run for run in reversed(runs) if run.get("status") == "completed" and run.get("scores")]
    plot_w = CHART_WIDTH - PAD_LEFT - PAD_RIGHT
    plot_h = CHART_HEIGHT - PAD_TOP - PAD_BOTTOM

    def x_at(index):
        if len(scored) == 1:
            return PAD_LEFT + plot_w / 2
        return PAD_LEFT + plot_w * index / (len(scored) - 1)

    def y_at(score):
        return PAD_TOP + plot_h * (100 - score) / 100

    series = []
    for pillar in PILLARS:
        points = [
            (x_at(i), y_at(run["scores"][pillar]))
            for i, run in enumerate(scored)
            if run["scores"].get(pillar) is not None
        ]
        if points:
            series.append(
                {
                    "pillar": pillar,
                    "slug": slug(pillar),
                    "points": " ".join(f"{x:.1f},{y:.1f}" for x, y in points),
                    "dots": [{"x": round(x, 1), "y": round(y, 1)} for x, y in points],
                }
            )

    labels = []
    if scored:
        labels.append({"x": round(x_at(0), 1), "text": short_time(scored[0].get("completedUtc"))})
        if len(scored) > 1:
            labels.append({"x": round(x_at(len(scored) - 1), 1), "text": short_time(scored[-1].get("completedUtc"))})

    return {
        "width": CHART_WIDTH,
        "height": CHART_HEIGHT,
        "left": PAD_LEFT,
        "right": CHART_WIDTH - PAD_RIGHT,
        "label_y": CHART_HEIGHT - 12,
        "grid": [{"y": round(y_at(score), 1), "label": score} for score in (0, 25, 50, 75, 100)],
        "series": series,
        "labels": labels,
        "runs": len(scored),
    }


def _severity_rank(finding):
    try:
        return SEVERITIES.index(finding.get("severity"))
    except ValueError:
        return len(SEVERITIES)


def compare(base_findings, target_findings):
    """Findings are matched by their stable key. new = only in target, resolved = only in base."""
    base = {f["key"]: f for f in base_findings if f.get("key")}
    target = {f["key"]: f for f in target_findings if f.get("key")}
    new = sorted((f for k, f in target.items() if k not in base), key=lambda f: (_severity_rank(f), f.get("title", "")))
    resolved = sorted((f for k, f in base.items() if k not in target), key=lambda f: (_severity_rank(f), f.get("title", "")))
    return {
        "newCount": len(new),
        "resolvedCount": len(resolved),
        "unchangedCount": len(base.keys() & target.keys()),
        "new": new[:MAX_LISTED],
        "resolved": resolved[:MAX_LISTED],
    }


def score_deltas(base_scores, target_scores):
    rows = []
    for pillar in PILLARS:
        before, after = (base_scores or {}).get(pillar), (target_scores or {}).get(pillar)
        delta = after - before if before is not None and after is not None else None
        rows.append({"pillar": pillar, "base": before, "target": after, "delta": delta})
    return rows
