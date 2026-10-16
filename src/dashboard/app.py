"""WAF Pulse dashboard."""
import logging
import re

from azure.cosmos.exceptions import CosmosResourceNotFoundError
from flask import Flask, abort, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

import cost_view
import data
import governance_view
import history

app = Flask(__name__)

REFRESH_HEADER = "X-WAF-Pulse"


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health")
def health():
    # Deliberately independent from Cosmos DB so the platform probe only reflects the web process.
    return jsonify(status="ok")


def _load_dashboard(pillar, severity, source=None):
    """Returns (run, summary, findings, error). Errors are logged, never shown to the user."""
    try:
        latest = data.latest_run()
        completed = latest if latest and latest.get("status") == "completed" else data.latest_run(True)
        if not completed:
            return latest, None, [], None
        summary = data.summary(completed["id"])
        findings = data.findings(completed["id"], pillar, severity, source=source)
        return latest, summary, findings, None
    except Exception:
        logging.exception("Could not load dashboard data")
        return None, None, [], "The data store is not reachable right now."


def _allowed(value, options):
    return value if value in options else None


@app.get("/")
def index():
    pillar = _allowed(request.args.get("pillar"), data.PILLARS)
    severity = _allowed(request.args.get("severity"), data.SEVERITIES)
    source = _allowed(request.args.get("source"), data.SOURCES)
    latest, summary, findings, error = _load_dashboard(pillar, severity, source)
    return render_template(
        "index.html",
        latest=latest,
        summary=summary,
        findings=findings,
        error=error,
        pillars=data.PILLARS,
        severities=data.SEVERITIES,
        sources=data.SOURCES,
        source_labels=data.SOURCE_LABELS,
        selected_pillar=pillar,
        selected_severity=severity,
        selected_source=source,
        user=request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME", ""),
    )


@app.get("/governance")
def governance_page():
    try:
        latest = data.latest_run()
        completed = latest if latest and latest.get("status") == "completed" else data.latest_run(True)
        summary = data.summary(completed["id"]) if completed else None
    except Exception:
        logging.exception("Could not load governance data")
        return render_template("governance.html", error="The data store is not reachable right now.",
                               governance=None, tree=[], unassigned=[]), 503
    governance = (summary or {}).get("governance")
    tree, unassigned = [], []
    if governance:
        tree = governance_view.build_tree(governance.get("managementGroups", []), governance.get("subscriptions", []))
        unassigned = governance_view.subscriptions_outside_groups(
            governance.get("managementGroups", []), governance.get("subscriptions", []))
    return render_template("governance.html", error=None, governance=governance, tree=tree, unassigned=unassigned,
                           summary=summary)


@app.get("/cost")
def cost_page():
    try:
        latest = data.latest_run()
        completed = latest if latest and latest.get("status") == "completed" else data.latest_run(True)
        summary = data.summary(completed["id"]) if completed else None
    except Exception:
        logging.exception("Could not load cost data")
        return render_template("cost.html", error="The data store is not reachable right now.", finops=None,
                               chart=None, summary=None), 503
    finops = (summary or {}).get("finops")
    return render_template("cost.html", error=None, finops=finops, summary=summary,
                           chart=cost_view.chart(finops["months"]) if finops and finops.get("months") else None)


@app.get("/api/summary")
def api_summary():
    latest, summary, _, error = _load_dashboard(None, None)
    if error:
        return jsonify(error=error), 503
    return jsonify(run=latest, summary=summary)


@app.get("/api/findings")
def api_findings():
    latest, summary, findings, error = _load_dashboard(
        request.args.get("pillar"), request.args.get("severity"), request.args.get("source")
    )
    if error:
        return jsonify(error=error), 503
    return jsonify(runId=summary["runId"] if summary else None, findings=findings)


@app.context_processor
def inject_user():
    return {"user": request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME", "")}


RUN_ID = re.compile(r"^[0-9a-fA-F-]{36}$")


def _run_rows(runs):
    rows = [
        {**run, "duration": history.duration_seconds(run), "when": history.short_time(run.get("startedUtc"))}
        for run in runs
    ]
    completed = [row["id"] for row in rows if row.get("status") == "completed"]
    for row in rows:
        if row.get("status") == "completed":
            position = completed.index(row["id"])
            row["previous"] = completed[position + 1] if position + 1 < len(completed) else None
    return rows


@app.get("/history")
def history_page():
    try:
        runs = data.history()
    except Exception:
        logging.exception("Could not load run history")
        return render_template("history.html", error="The data store is not reachable right now.", runs=[],
                               trend=history.trend([]), pillars=data.PILLARS, slug=history.slug)
    return render_template("history.html", error=None, runs=_run_rows(runs), trend=history.trend(runs),
                           pillars=data.PILLARS, slug=history.slug)


@app.get("/api/history")
def api_history():
    try:
        return jsonify(runs=data.history())
    except Exception:
        logging.exception("Could not load run history")
        return jsonify(error="The data store is not reachable right now."), 503


def _select_runs(base_id, target_id):
    """Defaults to the latest completed run against the one before it."""
    runs = data.history()
    completed = [run for run in runs if run.get("status") == "completed"]
    by_id = {run["id"]: run for run in runs}

    def pick(run_id, fallback):
        if not run_id:
            return fallback
        if not RUN_ID.match(run_id):
            abort(400)
        return by_id.get(run_id) or data.run(run_id)

    target = pick(target_id, completed[0] if completed else None)
    base = pick(base_id, completed[1] if len(completed) > 1 else None)
    return runs, base, target


def _compare(base_id, target_id):
    runs, base, target = _select_runs(base_id, target_id)
    if not base or not target:
        return runs, base, target, None
    result = history.compare(data.run_findings(base["id"]), data.run_findings(target["id"]))
    result["scores"] = history.score_deltas(base.get("scores"), target.get("scores"))
    return runs, base, target, result


@app.get("/compare")
def compare_page():
    try:
        runs, base, target, result = _compare(request.args.get("base"), request.args.get("target"))
    except HTTPException:
        raise
    except CosmosResourceNotFoundError:
        abort(404)
    except Exception:
        logging.exception("Could not compare runs")
        return render_template("compare.html", error="The data store is not reachable right now.", runs=[],
                               base=None, target=None, result=None, pillars=data.PILLARS), 503
    options = _run_rows([run for run in runs if run.get("status") == "completed"])
    return render_template("compare.html", error=None, runs=options, base=base, target=target, result=result,
                           pillars=data.PILLARS)


@app.get("/api/compare")
def api_compare():
    try:
        _, base, target, result = _compare(request.args.get("base"), request.args.get("target"))
    except HTTPException:
        raise
    except CosmosResourceNotFoundError:
        abort(404)
    except Exception:
        logging.exception("Could not compare runs")
        return jsonify(error="The data store is not reachable right now."), 503
    if result is None:
        return jsonify(error="At least two completed runs are needed."), 409
    return jsonify(base=base, target=target, **result)


@app.post("/api/refresh")
def api_refresh():
    # A custom header cannot be sent cross-site without a CORS preflight, which blocks CSRF.
    if request.headers.get(REFRESH_HEADER) != "1" or request.headers.get("Sec-Fetch-Site", "same-origin") not in (
        "same-origin",
        "none",
    ):
        return jsonify(error="Forbidden"), 403
    try:
        latest = data.latest_run()
        if latest and latest.get("status") == "running":
            return jsonify(message="A refresh is already running."), 409
        data.request_refresh()
    except Exception:
        logging.exception("Could not queue the refresh request")
        return jsonify(error="The refresh request could not be queued."), 503
    return jsonify(message="Refresh requested. Results appear when the run completes."), 202
