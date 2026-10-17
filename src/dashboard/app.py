"""WAF Pulse dashboard."""
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from azure.cosmos.exceptions import CosmosResourceNotFoundError
from flask import Flask, abort, jsonify, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException

import charts
import cost_view
import data
import governance_view
import history
import insights
import landing_zone
import rightsizing

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


def _all_findings(summary, pillar=None, rule_id=None, limit=data.MAX_FINDINGS, resource_id=None):
    if not summary:
        return []
    extra = {"resource_id": resource_id} if resource_id else {}
    return data.all_findings(summary["runId"], pillar, rule_id, limit, **extra)


def _data_sources(summary):
    """What each source could read in the last run, so a missing permission is visible instead of silent.
    Returns [{name, status, records, detail}] with status available, partial, missing or empty."""
    sources = summary.get("sources") or {}
    errors = summary.get("errors") or []

    def records(key):
        return (sources.get(key) or {}).get("findings")

    rows = []

    def add(name, status, count=None, detail=""):
        rows.append({"name": name, "status": status, "records": count, "detail": detail})

    add("Resource Graph inventory and built-in rules", "available" if "builtin" in sources else "empty", records("builtin"),
        f"{summary.get('resourceCount', 0)} resources in {summary.get('subscriptionCount', 0)} subscription(s).")
    failed = sum(1 for e in errors if str(e.get("ruleId", "")).startswith("CHK-"))
    add("Review checklists", "partial" if failed else ("available" if "checklist" in sources else "empty"), records("checklist"),
        f"{failed} check(s) could not run." if failed else "Every check ran.")
    add("Azure Advisor", "available" if "advisor" in sources else "empty", records("advisor"), "Recommendations of the five categories.")
    add("Defender for Cloud", "available" if "defender" in sources or summary.get("secureScore") else "empty",
        records("defender"), "Secure score, controls and assessments." if summary.get("secureScore") else "Needs the Security Reader role.")
    measured = sum(((summary.get("metrics") or {}).get("measured") or {}).values())
    add("Azure Monitor metrics", "available" if measured else "empty", measured or None, "Utilization of the last 30 days.")
    finops = summary.get("finops") or {}
    coverage = finops.get("coverage") or {}
    if finops.get("months"):
        status = "partial" if coverage.get("denied") or coverage.get("error") else "available"
        add("Cost Management", status, coverage.get("ok"),
            f"{coverage.get('denied', 0)} subscription(s) need the Cost Management Reader role." if coverage.get("denied") else "Cost read for every subscription.")
    else:
        add("Cost Management", "missing", None, "Needs the Cost Management Reader role.")
    diagnostics = summary.get("diagnostics")
    add("Diagnostic settings", "available" if diagnostics and diagnostics.get("checked") else "empty",
        (diagnostics or {}).get("checked"), "Resources of the supported types.")
    keyvault = summary.get("keyvault")
    if keyvault:
        denied = keyvault.get("denied", 0)
        add("Key Vault expirations", "partial" if denied else "available", keyvault.get("readable"),
            f"{denied} vault(s) could not be listed (Key Vault Reader role or firewall)." if denied else "Every vault was read.")
    else:
        add("Key Vault expirations", "empty", None, "No vaults found.")
    entra = (summary.get("entra") or {}).get("available") or {}
    labels = {"apps": "app registrations", "guests": "guest users", "incidents": "Defender XDR incidents"}
    missing = [labels[k] for k in labels if k in entra and not entra[k]]
    add("Microsoft Entra", "missing" if entra and len(missing) == len(entra) else "partial" if missing else
        ("available" if entra else "empty"), None,
        ("Needs Graph permissions for " + ", ".join(missing) + ".") if missing else "App credentials, guests and incidents.")
    add("Governance", "available" if summary.get("governance") else "empty", records("governance"), "Policy, access, locks and Defender plans.")
    return rows

@app.get("/")
def index():
    if any(request.args.get(name) for name in ("pillar", "severity", "source")):
        # Links from earlier versions pointed the filters at the overview.
        return redirect(url_for("actions_page", **{k: v for k, v in request.args.items() if k in ("pillar", "severity", "source")}))
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
            [(data.SOURCE_LABELS.get(name, name), count, url_for("actions_page", source=name))
             for name, count in insights.top_counts(findings, "source", 10)]),
        type_chart=charts.hbars(_type_bars(findings)),
        resource_chart=charts.hbars([(name, count, url_for("resource_page", id=resource_id))
                                     for name, resource_id, count in insights.worst_resources(findings, 8)]),
        action_items=len(rules), high_items=sum(1 for r in rules if r["severity"] in ("critical", "high")),
        data_sources=_data_sources(summary or {}),
    )


@app.get("/actions")
def actions_page():
    pillar = _allowed(request.args.get("pillar"), data.PILLARS)
    severity = _allowed(request.args.get("severity"), data.SEVERITIES)
    source = _allowed(request.args.get("source"), data.SOURCES)
    try:
        _, summary = _latest()
        findings = _all_findings(summary, pillar)
    except Exception:
        logging.exception("Could not load the action items")
        return render_template("actions.html", summary=None, error="The data store is not reachable right now."), 503
    findings = [f for f in findings if (not source or f.get("source") == source)]
    rules = insights.group_rules(findings)
    counts = {level: sum(1 for r in rules if r["severity"] == level) for level in data.SEVERITIES}
    shown = [r for r in rules if not severity or r["severity"] == severity]
    return render_template(
        "actions.html", summary=summary, error=None, pillars=data.PILLARS, severities=data.SEVERITIES, sources=data.SOURCES,
        source_labels=data.SOURCE_LABELS, selected_pillar=pillar, selected_severity=severity, selected_source=source,
        rules=shown[:MAX_ACTIONS], total_items=len(shown), counts=counts, cap=data.MAX_FINDINGS,
        total_resources=len({str(f.get("resourceId", "")).lower() for f in findings
                             if not severity or f.get("severity") == severity}),
        partial=len(findings) >= data.MAX_FINDINGS,
    )


@app.get("/findings")
def findings_page():
    # The flat list was replaced by the action items; old links keep working.
    return redirect(url_for("actions_page", **{k: v for k, v in request.args.items() if k in ("pillar", "severity", "source")}))

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
    rules = insights.group_rules(findings)
    spend = _spend_context(summary, rules) if slug == "cost" else {}
    if slug == "security":
        spend = _security_context(summary)
    return render_template(
        "pillar.html", pillar=pillar, slug=slug, summary=summary, error=None, severities=data.SEVERITIES, **spend,
        source_labels=data.SOURCE_LABELS, totals=insights.severity_totals(findings), rules=rules,
        partial=len(findings) >= data.MAX_FINDINGS, cap=data.MAX_FINDINGS,
        source_chart=charts.hbars([(data.SOURCE_LABELS.get(name, name), count, url_for("actions_page", pillar=pillar, source=name))
                                   for name, count in insights.top_counts(findings, "source", 10)]),
        type_chart=charts.hbars(_type_bars(findings)),
    )


BREAKDOWN_PANELS = (("byService", "Service"), ("byResourceGroup", "Resource group"), ("byLocation", "Region"),
                    ("byResourceType", "Resource type"))


def _security_context(summary):
    """Defender plan tiers for the coverage chart, and subscription names for its table."""
    governance = (summary or {}).get("governance") or {}
    detail = (governance.get("defender") or {}).get("detail") or []
    on = sum(1 for p in detail if str(p.get("tier", "")).lower() != "free")
    return {
        "defender_chart": charts.hbars([("Standard (threat protection on)", on, None, "as-right"),
                                        ("Free (recommendations only)", len(detail) - on, None, "as-under")], width=420, label_width=210, label_limit=34),
        "names": {sub["id"].lower(): sub["name"] for sub in (summary or {}).get("subscriptions", [])},
    }


def _type_bars(findings, limit=8):
    """Bars of the resource types with most findings; each one opens the resources of that type."""
    counter = Counter(str(f.get("resourceType", "")).lower() for f in findings if f.get("resourceType"))
    return [(insights.short_type(kind), count, url_for("resources_page", type=kind)) for kind, count in counter.most_common(limit)]


def _walk_groups(tree):
    for node in tree:
        yield node
        yield from _walk_groups(node.get("children", []))


def _spend_context(summary, rules):
    """Everything the Cost page draws, from the finops dataset of the latest run."""
    finops = (summary or {}).get("finops")
    if not finops:
        return {"finops": None}
    months = finops.get("months") or []
    complete = [m["month"] for m in months if not m.get("partial")]
    last, previous = (complete[-1] if complete else None), (complete[-2] if len(complete) > 1 else None)
    current = datetime.now(timezone.utc).strftime("%Y-%m")
    breakdowns = finops.get("breakdowns") or {}
    daily = finops.get("daily") or []
    panels = [{"title": title, "chart": cost_view.stacked_columns(breakdowns[key], partial_from=current),
               "rows": cost_view.movers(breakdowns[key], last, previous)}
              for key, title in BREAKDOWN_PANELS if breakdowns.get(key) and breakdowns[key].get("series")]
    resources = breakdowns.get("topResources") or []
    previous_month = (datetime.strptime(current + "-01", "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m")
    lines = cost_view.running_totals(daily, current, previous_month) if daily else {}
    daily_service = breakdowns.get("dailyByService")
    pricing = breakdowns.get("byPricingModel")
    coverage = (breakdowns.get("commitmentCoverage") or {}).get("lastMonth")
    return {
        "finops": finops,
        "chart": cost_view.chart(months) if months else None,
        "daily_chart": cost_view.chart([{"month": p["date"], "cost": p["cost"]} for p in daily]) if daily else None,
        "daily_service_chart": cost_view.stacked_columns(daily_service) if daily_service and daily_service.get("series") else None,
        "running_chart": cost_view.line_chart(lines) if any(lines.values()) else None,
        "breakdown_panels": panels,
        "resources_chart": charts.hbars([(r["name"], r["cost"], None) for r in resources[:10]]) if resources else None,
        "resource_days": 30,
        "pricing_chart": cost_view.stacked_columns(pricing, partial_from=current) if pricing and pricing.get("series") else None,
        "coverage_last": coverage["percent"] if coverage else None,
    }

SUBSCRIPTION_ID = re.compile(r"^[0-9a-fA-F-]{36}$")
MAX_TABLE_ROWS = 500


RESOURCES_PER_PAGE = 100
TYPE_FILTER = re.compile(r"^[a-z0-9._/-]{1,120}$")
GROUP_FILTER = re.compile(r"^[A-Za-z0-9._()\-]{1,90}$")
RESOURCE_ID = re.compile(r"^/[A-Za-z0-9._()/:@ %'+,=-]{1,600}$")


def _inventory(summary):
    """(rows, truncated) of the latest run; empty when the run predates the list or there is no run."""
    return data.resources(summary["runId"]) if summary else ([], False)


@app.get("/resources")
def resources_page():
    resource_type = request.args.get("type", "").lower()
    resource_type = resource_type if TYPE_FILTER.match(resource_type) else None
    subscription = request.args.get("subscription", "").lower()
    subscription = subscription if SUBSCRIPTION_ID.match(subscription) else None
    group = request.args.get("group", "")
    group = group if GROUP_FILTER.match(group) else None
    query = request.args.get("q", "")[:80]
    try:
        page = max(int(request.args.get("page", "1")), 1)
    except ValueError:
        page = 1
    try:
        _, summary = _latest()
        rows, truncated = _inventory(summary)
        counts = insights.findings_per_resource(_all_findings(summary)) if rows else {}
    except Exception:
        logging.exception("Could not load the resources")
        return render_template("resources.html", error="The data store is not reachable right now.", summary=None), 503
    scoped = insights.filter_resources(rows, None, subscription, group, query)
    chosen = [r for r in scoped if not resource_type or r["type"] == resource_type]
    names = {sub["id"].lower(): sub["name"] for sub in (summary or {}).get("subscriptions", [])}
    type_counts = Counter(r["type"] for r in scoped).most_common(14)
    start = (page - 1) * RESOURCES_PER_PAGE
    shown = [{**r, "findings": counts.get(r["id"].lower(), 0), "subscription": names.get(r["subscriptionId"], r["subscriptionId"])}
             for r in chosen[start:start + RESOURCES_PER_PAGE]]
    return render_template(
        "resources.html", error=None, summary=summary, has_inventory=bool(rows), truncated=truncated, rows=shown,
        total=len(chosen), page=page, pages=max((len(chosen) + RESOURCES_PER_PAGE - 1) // RESOURCES_PER_PAGE, 1),
        resource_type=resource_type, subscription=subscription, group=group, query=query, per_page=RESOURCES_PER_PAGE,
        type_chips=[(t, insights.friendly_type(t), n) for t, n in type_counts], names=names,
        title=insights.friendly_type(resource_type) if resource_type else "Resources", filtered=bool(subscription or group or query),
    )


@app.get("/resource")
def resource_page():
    resource_id = request.args.get("id", "")
    if not RESOURCE_ID.match(resource_id):
        abort(404)
    try:
        _, summary = _latest()
        rows, _ = _inventory(summary)
        findings = _all_findings(summary, resource_id=resource_id, limit=500)
    except Exception:
        logging.exception("Could not load the resource")
        return render_template("resource.html", error="The data store is not reachable right now.", resource=None, summary=None), 503
    row = next((r for r in rows if r["id"].lower() == resource_id.lower()), None)
    if row is None and findings:
        first = findings[0]
        row = {"id": resource_id, "name": first.get("resourceName") or resource_id.rsplit("/", 1)[-1],
               "type": str(first.get("resourceType", "")).lower(), "subscriptionId": first.get("subscriptionId", ""),
               "resourceGroup": "", "location": "", "detail": "", "tags": None}
    names = {sub["id"].lower(): sub["name"] for sub in (summary or {}).get("subscriptions", [])}
    ordered = sorted(findings, key=lambda f: (insights.RANK.get(f.get("severity"), 9), f.get("title", "")))
    return render_template(
        "resource.html", error=None, summary=summary, resource=row, findings=ordered, source_labels=data.SOURCE_LABELS,
        subscription_name=names.get(row["subscriptionId"], row["subscriptionId"]) if row else "",
        friendly=insights.friendly_type(row["type"]) if row else "",
    )




@app.get("/rightsizing")
def rightsizing_page():
    kind = _allowed(request.args.get("kind"), rightsizing.KINDS)
    assessment = _allowed(request.args.get("assessment"), rightsizing.ASSESSMENTS)
    subscription = request.args.get("subscription", "")
    subscription = subscription.lower() if SUBSCRIPTION_ID.match(subscription) else None
    try:
        _, summary = _latest()
    except Exception:
        logging.exception("Could not load right-sizing data")
        return render_template("rightsizing.html", error="The data store is not reachable right now.", metrics=None), 503
    metrics = (summary or {}).get("metrics")
    if not metrics:
        return render_template("rightsizing.html", error=None, metrics=None)
    # Without a choice, open the first resource type that has measurements.
    kind = kind or next((key for key in rightsizing.KINDS if any(rightsizing.counts(metrics, key).values())), "vm")
    cards = []
    for key, (title, _, labels) in rightsizing.KINDS.items():
        totals = rightsizing.counts(metrics, key)
        if not any(totals.values()):
            continue
        bars = [(labels[name], totals[name], url_for("rightsizing_page", kind=key, assessment=name, subscription=subscription) + "#resources",
                 f"as-{name}") for name in rightsizing.visible_assessments(key, totals)]
        cards.append({"key": key, "title": title, "chart": charts.hbars(bars, width=440, label_width=210, label_limit=34),
                      "measured": sum(totals[n] for n in rightsizing.ASSESSMENTS), "nodata": totals["nodata"]})
    rows = rightsizing.resources(metrics, kind, assessment, subscription)
    names = {sub["id"].lower(): sub["name"] for sub in (summary or {}).get("subscriptions", [])}
    return render_template(
        "rightsizing.html", error=None, metrics=metrics, cards=cards, kind=kind, assessment=assessment,
        subscription=subscription, title=rightsizing.KINDS[kind][0], labels=rightsizing.KINDS[kind][2],
        assessments=rightsizing.ASSESSMENTS, rows=rows[:MAX_TABLE_ROWS], total_rows=len(rows), names=names,
        lookback=metrics.get("lookbackDays", 30), kinds=rightsizing.KINDS,
    )

MAX_ACTIONS = 400
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
        return render_template("rule.html", rule=None, error="The data store is not reachable right now.", back=url_for("actions_page"),
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
    back = url_for("actions_page")
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
    diagrams = {}
    if governance:
        names = {sub["id"]: sub.get("name") or sub["id"] for sub in governance.get("subscriptions", [])}
        mapping, sub_mapping, hidden = _landing_zone_settings()
        environment = landing_zone.override_from_environment()
        sub_environment = landing_zone.subscription_override_from_environment()
        classification, found = landing_zone.classify(
            tree, governance.get("policyByGroup"), governance.get("signals"), landing_zone.merge_override(environment, mapping))
        group_names = sorted({name for node in _walk_groups(tree) for name in (node.get("displayName"), node.get("name")) if name})
        subscriptions = governance.get("subscriptions", [])
        sub_found = landing_zone.assign_subscriptions(subscriptions, landing_zone.merge_override(sub_environment, sub_mapping))
        has_hierarchy = any(node.get("children") for node in tree)
        typed = {role: mapping.get(role) or sorted(environment.get(role, ())) for role in {*mapping, *environment}}
        typed_subs = {role: sub_mapping.get(role) or sorted(sub_environment.get(role, ())) for role in {*sub_mapping, *sub_environment}}
        known_groups = {n.lower() for n in group_names}
        known_subs = {str(s.get("name", "")).lower() for s in subscriptions} | {str(s.get("id", "")).lower() for s in subscriptions}
        diagrams = {
            "hierarchy": landing_zone.actual(tree, subscriptions, names, unassigned, classification),
            "reference": landing_zone.reference(found, has_hierarchy, hidden, sub_found, interactive=True),
            "alignment": landing_zone.alignment(found, typed, known_groups, hidden, sub_found, typed_subs, known_subs),
            "removed": landing_zone.removed_boxes(hidden), "has_hierarchy": has_hierarchy,
            "typed": typed, "typed_subscriptions": typed_subs,
            "group_options": group_names, "subscription_options": sorted({s.get("name") for s in subscriptions if s.get("name")}),
        }
    return render_template("governance.html", error=None, governance=governance, tree=tree, unassigned=unassigned,
                           summary=summary, **diagrams)


@app.get("/cost")
def cost_page():
    # Spend and recommendations live on one page.
    return redirect(url_for("pillar_page", slug="cost"))


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


def _cross_site():
    """True when a write did not come from this site: it lacks the custom header or was sent from another origin."""
    return request.headers.get(REFRESH_HEADER) != "1" or request.headers.get("Sec-Fetch-Site", "same-origin") not in (
        "same-origin",
        "none",
    )


MAPPING_SETTING = "landing-zone-map"


def _landing_zone_settings():
    """What was typed in the Governance page: ({role: [management groups]}, {role: [subscriptions]}, [removed roles])."""
    try:
        saved = data.get_setting(MAPPING_SETTING)
    except Exception:
        logging.exception("Could not read the landing zone settings")
        return {}, {}, []
    saved = saved if isinstance(saved, dict) else {}
    return (landing_zone.sanitize_mapping(saved.get("mapping")), landing_zone.sanitize_mapping(saved.get("subscriptions")),
            landing_zone.sanitize_hidden(saved.get("hidden")))


def _tenant_names():
    """(management group names, subscription names and ids), lower case, from the latest run; (None, None) when the
    tenant is not known yet, in which case nothing can be checked."""
    try:
        governance = (_latest()[1] or {}).get("governance")
    except Exception:
        return None, None
    if not governance:
        return None, None
    groups = {str(n).lower() for g in governance.get("managementGroups", []) for n in (g.get("name"), g.get("displayName")) if n}
    subs = {str(n).lower() for s in governance.get("subscriptions", []) for n in (s.get("name"), s.get("id")) if n}
    return groups, subs


@app.post("/api/landing-zone-map")
def api_landing_zone_map():
    """Saves the management groups and subscriptions typed for each landing zone role and the boxes removed from
    the reference. A management group is only accepted for a box and a subscription only under it, never the other
    way around."""
    if _cross_site():
        return jsonify(error="Forbidden"), 403
    body = request.get_json(silent=True)
    body = body if isinstance(body, dict) else {}
    saved = {"mapping": landing_zone.sanitize_mapping(body.get("mapping")),
             "subscriptions": landing_zone.sanitize_mapping(body.get("subscriptions")),
             "hidden": landing_zone.sanitize_hidden(body.get("hidden"))}
    groups, subs = _tenant_names()
    if groups is not None:
        wrong = [f"{name} is not a management group of your tenant" for _, name in landing_zone.rejected_names(saved["mapping"], groups)]
        wrong += [f"{name} is not a subscription of your tenant" for _, name in landing_zone.rejected_names(saved["subscriptions"], subs)]
        if wrong:
            return jsonify(error="; ".join(wrong[:3]) + "."), 422
    try:
        data.save_setting(MAPPING_SETTING, saved)
    except Exception:
        logging.exception("Could not save the landing zone settings")
        return jsonify(error="The settings could not be saved right now."), 503
    return jsonify(**saved)


@app.post("/api/refresh")
def api_refresh():
    # A custom header cannot be sent cross-site without a CORS preflight, which blocks CSRF.
    if _cross_site():
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
