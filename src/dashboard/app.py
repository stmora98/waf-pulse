"""WAF Pulse dashboard."""
import logging

from flask import Flask, jsonify, render_template, request

import data

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


def _load_dashboard(pillar, severity):
    """Returns (run, summary, findings, error). Errors are logged, never shown to the user."""
    try:
        latest = data.latest_run()
        completed = latest if latest and latest.get("status") == "completed" else data.latest_run(True)
        if not completed:
            return latest, None, [], None
        summary = data.summary(completed["id"])
        findings = data.findings(completed["id"], pillar, severity)
        return latest, summary, findings, None
    except Exception:
        logging.exception("Could not load dashboard data")
        return None, None, [], "The data store is not reachable right now."


@app.get("/")
def index():
    pillar = request.args.get("pillar") if request.args.get("pillar") in data.PILLARS else None
    severity = request.args.get("severity") if request.args.get("severity") in data.SEVERITIES else None
    latest, summary, findings, error = _load_dashboard(pillar, severity)
    return render_template(
        "index.html",
        latest=latest,
        summary=summary,
        findings=findings,
        error=error,
        pillars=data.PILLARS,
        severities=data.SEVERITIES,
        selected_pillar=pillar,
        selected_severity=severity,
        user=request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME", ""),
    )


@app.get("/api/summary")
def api_summary():
    latest, summary, _, error = _load_dashboard(None, None)
    if error:
        return jsonify(error=error), 503
    return jsonify(run=latest, summary=summary)


@app.get("/api/findings")
def api_findings():
    pillar = request.args.get("pillar")
    severity = request.args.get("severity")
    latest, summary, findings, error = _load_dashboard(pillar, severity)
    if error:
        return jsonify(error=error), 503
    return jsonify(runId=summary["runId"] if summary else None, findings=findings)


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
