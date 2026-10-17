"""WAF Pulse dashboard."""
import logging
import re
from datetime import datetime, timezone

from azure.cosmos.exceptions import CosmosResourceNotFoundError
from flask import Flask, abort, jsonify, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException

import charts
import cost_view
import data
import governance_view
import history
import insights

app = Flask(__name__)


@app.template_filter("when")
def when(value):
    """A readable UTC timestamp; anything that is not an ISO date is shown as it is."""
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return value
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

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


def _latest():
    """Returns (latest run, summary of the latest completed run or None). Raises when the data store is down."""
    latest = data.latest_run()
    completed = latest if latest and latest.get("status") == "completed" else data.latest_run(True)
    return latest, (data.summary(completed["id"]) if completed else None)


def _all_findings(summary, pillar=None, rule_id=None, limit=data.MAX_FINDINGS):
    return data.all_findings(summary["runId"], pillar, rule_id, limit) if summary else []


@app.get("/")
def index():
    if any(request.args.get(name) for name in ("pillar", "severity", "source")):
        # Links from earlier versions pointed the filters at the overview.
        return redirect(url_for("findings_page", **{k: v for k, v in request.args.items() if k in ("pillar", "severity", "source")}))
    try:
        latest, summary = _latest()
        findings = _all_findings(summary)
    except Exception:
        logging.exception("Could not load dashboard data")
        return render_template("index.html", latest=None, summary=None, error="The data store is not reachable right now.",
                               pillars=data.PILLARS, slugs=insights.PILLAR_SLUG, source_labels=data.SOURCE_LABELS), 503
    rules = insights.group_rules(findings)
    pillar_rows = [
        (pillar, counts, url_for("pillar_page", slug=insights.PILLAR_SLUG[pillar]))
        for pillar, counts in insights.by_pillar(findings, data.PILLARS)
    ]
    return render_template(
        "index.html", latest=latest, summary=summary, error=None, pillars=data.PILLARS, slugs=insights.PILLAR_SLUG,
        source_labels=data.SOURCE_LABELS, partial=len(findings) >= data.MAX_FINDINGS, cap=data.MAX_FINDINGS,
        pillar_chart=charts.stacked(pillar_rows),
        source_chart=charts.hbars(
            [(data.SOURCE_LABELS.get(name, name), count, url_for("findings_page", source=name))
             for name, count in insights.top_counts(findings, "source", 10)]),
        type_chart=charts.hbars([(name, count, None) for name, count in
                                 insights.top_counts(findings, "resourceType", 8, insights.short_type)]),
        resource_chart=charts.hbars([(name, count, None) for name, _, count in insights.worst_resources(findings, 8)]),
        top_rules=rules[:10],
    )


@app.get("/findings")
def findings_page():
    pillar = _allowed(request.args.get("pillar"), data.PILLARS)
    severity = _allowed(request.args.get("severity"), data.SEVERITIES)
    source = _allowed(request.args.get("source"), data.SOURCES)
    latest, summary, findings, error = _load_dashboard(pillar, severity, source)
    return render_template(
        "findings.html", latest=latest, summary=summary, findings=findings, error=error, pillars=data.PILLARS,
        severities=data.SEVERITIES, sources=data.SOURCES, source_labels=data.SOURCE_LABELS,
        selected_pillar=pillar, selected_severity=severity, selected_source=source,
    )


@app.get("/pillar/<slug>")
def pillar_page(slug):
    if slug not in insights.PILLAR_PAGES:
        abort(404)
    pillar = insights.PILLAR_PAGES[slug][0]
    try:
        _, summary = _latest()
        findings = _all_findings(summary, pillar)
    except Exception:
        logging.exception("Could not load the %s page", pillar)
        return render_template("pillar.html", pillar=pillar, slug=slug, summary=None, error="The data store is not reachable right now.",
                               source_labels=data.SOURCE_LABELS), 503
    return render_template(
        "pillar.html", pillar=pillar, slug=slug, summary=summary, error=None, severities=data.SEVERITIES,
        source_labels=data.SOURCE_LABELS, totals=insights.severity_totals(findings), rules=insights.group_rules(findings),
        partial=len(findings) >= data.MAX_FINDINGS, cap=data.MAX_FINDINGS,
        source_chart=charts.hbars([(data.SOURCE_LABELS.get(name, name), count, url_for("findings_page", pillar=pillar, source=name))
                                   for name, count in insights.top_counts(findings, "source", 10)]),
        type_chart=charts.hbars([(name, count, None) for name, count in
                                 insights.top_counts(findings, "resourceType", 8, insights.short_type)]),
    )


RULE_ID = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
MAX_RULE_RESOURCES = 1000


@app.get("/rule/<rule_id>")
def rule_page(rule_id):
    if not RULE_ID.match(rule_id):
        abort(404)
    try:
        _, summary = _latest()
        findings = _all_findings(summary, rule_id=rule_id, limit=MAX_RULE_RESOURCES + 1)
    except Exception:
        logging.exception("Could not load recommendation %s", rule_id)
        return render_template("rule.html", rule=None, error="The data store is not reachable right now.", back=url_for("index"),
                               source_labels=data.SOURCE_LABELS), 503
    rules = insights.group_rules(findings)
    rule = rules[0] if rules else None
    spark = None
    if rule:
        try:
            runs = [run for run in data.history(15) if run.get("status") == "completed"]
            counts = data.rule_history(rule_id, [run["id"] for run in runs])
            spark = charts.sparkline([(history.short_time(run.get("startedUtc")), counts[run["id"]])
                                      for run in reversed(runs) if run["id"] in counts])
        except Exception:
            logging.exception("Could not load the history of %s", rule_id)
    back = url_for("pillar_page", slug=insights.PILLAR_SLUG[rule["pillar"]]) if rule and rule["pillar"] in insights.PILLAR_SLUG else url_for("index")
    return render_template(
        "rule.html", rule=rule, error=None, spark=spark, back=back, source_labels=data.SOURCE_LABELS,
        resources=sorted(findings[:MAX_RULE_RESOURCES], key=lambda f: str(f.get("resourceName", "")).lower()),
        truncated=len(findings) > MAX_RULE_RESOURCES,
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
    months = finops.get("months") if finops else None
    daily = (finops or {}).get("daily") or []
    return render_template(
        "cost.html", error=None, finops=finops, summary=summary,
        chart=cost_view.chart(months) if months else None,
        daily_chart=cost_view.chart([{"month": p["date"], "cost": p["cost"]} for p in daily]) if daily else None,
    )


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
    return {"user": request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME", ""), "nav_pillars": list(insights.PILLAR_PAGES.items())}


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
