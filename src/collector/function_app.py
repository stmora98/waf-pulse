"""WAF Pulse collector: Azure Durable Functions app.

Triggers
  scheduled_refresh  timer, schedule comes from the REFRESH_CRON app setting
  manual_refresh     storage queue 'refresh-requests', written by the dashboard "Refresh now" button

Both start the same orchestration. It discovers every subscription the service principal can read, then runs
in parallel: the built-in rules (one activity per subscription), the Azure review checklists (batches, tenant
wide), Azure Advisor and Defender for Cloud (tenant wide). Every activity stores its findings and statistics;
the final activity aggregates them into the run summary and the pillar scores.
"""
import logging
from datetime import datetime, timezone

import azure.durable_functions as df
import azure.functions as func

from waf_pulse import (
    advisor, checklists, collect, credentials, defender, diagnostics, entra, finops, governance, graph, keyvault, metrics,
    store,
)

app = df.DFApp()

INSTANCE_ID = "assessment"
ACTIVE_STATES = (
    df.OrchestrationRuntimeStatus.Running,
    df.OrchestrationRuntimeStatus.Pending,
    df.OrchestrationRuntimeStatus.ContinuedAsNew,
)


async def _start_assessment(client, trigger):
    """Only one assessment runs at a time, so repeated refresh requests do not pile up."""
    status = await client.get_status(INSTANCE_ID)
    if status and status.runtime_status in ACTIVE_STATES:
        logging.info("Assessment already running, ignoring %s trigger", trigger)
        return
    await client.start_new("assessment_orchestrator", INSTANCE_ID, {"trigger": trigger})
    logging.info("Assessment started by %s trigger", trigger)


@app.timer_trigger(arg_name="timer", schedule="%REFRESH_CRON%", run_on_startup=False)
@app.durable_client_input(client_name="client")
async def scheduled_refresh(timer: func.TimerRequest, client: df.DurableOrchestrationClient):
    await _start_assessment(client, "schedule")


@app.queue_trigger(arg_name="message", queue_name="refresh-requests", connection="AzureWebJobsStorage")
@app.durable_client_input(client_name="client")
async def manual_refresh(message: func.QueueMessage, client: df.DurableOrchestrationClient):
    await _start_assessment(client, "manual")


@app.orchestration_trigger(context_name="context")
def assessment_orchestrator(context: df.DurableOrchestrationContext):
    params = context.get_input() or {}
    trigger = params.get("trigger", "schedule")
    run_id = str(context.new_uuid())
    started = context.current_utc_datetime.replace(tzinfo=timezone.utc).isoformat()
    try:
        yield context.call_activity("act_start_run", {"runId": run_id, "startedUtc": started, "trigger": trigger})
        subscriptions = yield context.call_activity("act_discover", None)
        subscription_ids = [sub["id"] for sub in subscriptions]

        tasks = []
        if subscription_ids:
            scope = {"runId": run_id, "subscriptions": subscription_ids}
            tasks.append(context.call_activity("act_inventory", scope))
            tasks += [
                context.call_activity("act_rules", {**scope, "batch": index})
                for index in range(len(collect.rule_batches()))
            ]
            tasks += [
                context.call_activity("act_checklist", {**scope, "batch": index})
                for index in range(checklists.batch_count())
            ]
            tasks.append(context.call_activity("act_advisor", scope))
            tasks.append(context.call_activity("act_defender", scope))
            tasks.append(context.call_activity("act_governance", scope))
            tasks.append(context.call_activity("act_metrics", scope))
            tasks.append(context.call_activity("act_finops", scope))
            tasks.append(context.call_activity("act_diagnostics", scope))
            tasks.append(context.call_activity("act_keyvault", scope))
            tasks.append(context.call_activity("act_entra", scope))
        yield context.task_all(tasks)

        summary = yield context.call_activity(
            "act_finalize",
            {"runId": run_id, "startedUtc": started, "trigger": trigger, "subscriptions": subscriptions},
        )
        return summary
    except Exception as exc:
        yield context.call_activity(
            "act_fail", {"runId": run_id, "startedUtc": started, "trigger": trigger, "error": str(exc)[:500]}
        )
        raise


def _record_failure(run_id, key, exc):
    """A failing source must not fail the run: its error is kept with the statistics."""
    logging.exception("Collection step %s failed", key)
    store.save_stats(run_id, key, {"stats": [], "errors": [{"ruleId": key, "error": str(exc)[:300]}]})
    return {"key": key, "error": True}


@app.activity_trigger(input_name="payload")
def act_start_run(payload: dict):
    store.start_run(payload["runId"], payload["startedUtc"], payload["trigger"])


@app.activity_trigger(input_name="payload")
def act_discover(payload):
    subscriptions = graph.discover_subscriptions(credentials.collector_credential())
    logging.info("Discovered %d subscriptions", len(subscriptions))
    return subscriptions


@app.activity_trigger(input_name="payload")
def act_inventory(payload: dict):
    run_id = payload["runId"]
    try:
        store.save_stats(run_id, "inventory", collect.collect_inventory(
            credentials.collector_credential(), payload["subscriptions"]))
    except Exception as exc:
        return _record_failure(run_id, "inventory", exc)
    try:
        rows, truncated = collect.collect_resource_list(credentials.collector_credential(), payload["subscriptions"])
        store.save_resources(run_id, rows, truncated)
    except Exception:
        # The list is a convenience for drilling down: counts still work without it.
        logging.exception("The resource list could not be collected")
    return {"key": "inventory"}


@app.activity_trigger(input_name="payload")
def act_rules(payload: dict):
    run_id, batch = payload["runId"], payload["batch"]
    key = f"rules:{batch}"
    try:
        findings, document = collect.collect_rules(
            credentials.collector_credential(), run_id, payload["subscriptions"], collect.rule_batches()[batch]
        )
        store.save_findings(findings)
        store.save_stats(run_id, key, document)
        return {"key": key, "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, key, exc)


@app.activity_trigger(input_name="payload")
def act_checklist(payload: dict):
    run_id, batch = payload["runId"], payload["batch"]
    key = f"checklist:{batch}"
    try:
        credential = credentials.collector_credential()
        findings, stats, errors = [], [], []
        for chunk in graph.chunks(payload["subscriptions"]):
            chunk_findings, chunk_stats, chunk_errors = checklists.run_batch(credential, run_id, chunk, batch)
            findings += chunk_findings
            stats += chunk_stats
            errors += chunk_errors
        store.save_findings(findings)
        store.save_stats(run_id, key, {"stats": stats, "errors": errors})
        return {"key": key, "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, key, exc)


@app.activity_trigger(input_name="payload")
def act_advisor(payload: dict):
    run_id = payload["runId"]
    try:
        findings, stats, dataset = advisor.collect(
            credentials.collector_credential(), run_id, payload["subscriptions"]
        )
        store.save_findings(findings)
        store.save_stats(run_id, "advisor", {"stats": stats, "errors": []})
        store.save_rows(run_id, "advice", dataset.pop("advice", []))
        store.save_dataset(run_id, "advisor", dataset)
        return {"key": "advisor", "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, "advisor", exc)


@app.activity_trigger(input_name="payload")
def act_defender(payload: dict):
    run_id = payload["runId"]
    try:
        findings, stats, dataset, errors = defender.collect(
            credentials.collector_credential(), run_id, payload["subscriptions"]
        )
        store.save_findings(findings)
        store.save_stats(run_id, "defender", {"stats": stats, "errors": errors})
        store.save_dataset(run_id, "defender", dataset)
        return {"key": "defender", "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, "defender", exc)


@app.activity_trigger(input_name="payload")
def act_governance(payload: dict):
    run_id = payload["runId"]
    try:
        findings, stats, dataset, errors = governance.collect(
            credentials.collector_credential(), run_id, payload["subscriptions"]
        )
        store.save_findings(findings)
        store.save_stats(run_id, "governance", {"stats": stats, "errors": errors})
        store.save_dataset(run_id, "governance", dataset)
        return {"key": "governance", "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, "governance", exc)


@app.activity_trigger(input_name="payload")
def act_metrics(payload: dict):
    run_id = payload["runId"]
    try:
        findings, stats, dataset, errors = metrics.collect(
            credentials.collector_credential(), run_id, payload["subscriptions"]
        )
        store.save_findings(findings)
        store.save_stats(run_id, "metrics", {"stats": stats, "errors": errors})
        store.save_rows(run_id, "series", dataset.pop("series", []), chunk=150)
        store.save_dataset(run_id, "metrics", dataset)
        return {"key": "metrics", "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, "metrics", exc)


@app.activity_trigger(input_name="payload")
def act_finops(payload: dict):
    run_id = payload["runId"]
    try:
        findings, stats, dataset, errors = finops.collect(
            credentials.collector_credential(), run_id, payload["subscriptions"]
        )
        store.save_findings(findings)
        store.save_stats(run_id, "finops", {"stats": stats, "errors": errors})
        store.save_rows(run_id, "costs", dataset.pop("resourceCosts", []))
        store.save_dataset(run_id, "finops", dataset)
        return {"key": "finops", "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, "finops", exc)


@app.activity_trigger(input_name="payload")
def act_diagnostics(payload: dict):
    run_id = payload["runId"]
    try:
        findings, stats, dataset, errors = diagnostics.collect(
            credentials.collector_credential(), run_id, payload["subscriptions"]
        )
        store.save_findings(findings)
        store.save_stats(run_id, "diagnostics", {"stats": stats, "errors": errors})
        store.save_dataset(run_id, "diagnostics", dataset)
        return {"key": "diagnostics", "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, "diagnostics", exc)


@app.activity_trigger(input_name="payload")
def act_keyvault(payload: dict):
    run_id = payload["runId"]
    try:
        findings, stats, dataset, errors = keyvault.collect(
            credentials.collector_credential(), run_id, payload["subscriptions"]
        )
        store.save_findings(findings)
        store.save_stats(run_id, "keyvault", {"stats": stats, "errors": errors})
        store.save_dataset(run_id, "keyvault", dataset)
        return {"key": "keyvault", "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, "keyvault", exc)


@app.activity_trigger(input_name="payload")
def act_entra(payload: dict):
    run_id = payload["runId"]
    try:
        findings, stats, dataset, errors = entra.collect(credentials.collector_credential(), run_id)
        store.save_findings(findings)
        store.save_stats(run_id, "entra", {"stats": stats, "errors": errors})
        store.save_dataset(run_id, "entra", dataset)
        return {"key": "entra", "findings": len(findings)}
    except Exception as exc:
        return _record_failure(run_id, "entra", exc)


@app.activity_trigger(input_name="payload")
def act_finalize(payload: dict):
    run_id = payload["runId"]
    completed = datetime.now(timezone.utc).isoformat()
    summary, score_docs = collect.build_summary(
        run_id,
        payload["startedUtc"],
        completed,
        payload["trigger"],
        payload["subscriptions"],
        store.load_run_documents(run_id, "stats"),
        store.load_run_documents(run_id, "dataset"),
    )
    store.save_summary(summary)
    store.save_scores(score_docs)
    store.save_run(
        {
            "id": run_id,
            "subscriptionId": store.TENANT_PARTITION,
            "status": "completed",
            "trigger": payload["trigger"],
            "startedUtc": payload["startedUtc"],
            "completedUtc": completed,
            "subscriptionCount": summary["subscriptionCount"],
            "resourceCount": summary["resourceCount"],
            "findingCount": summary["findingCount"],
            "scores": summary["scores"],
            "severityTotals": summary["severityTotals"],
        }
    )
    try:
        store.save_snapshot(run_id, "summary", summary)
    except Exception:  # the snapshot is a convenience copy, the run is already complete
        logging.exception("Could not write the summary snapshot")
    return {"runId": run_id, "findingCount": summary["findingCount"]}


@app.activity_trigger(input_name="payload")
def act_fail(payload: dict):
    store.save_run(
        {
            "id": payload["runId"],
            "subscriptionId": store.TENANT_PARTITION,
            "status": "failed",
            "trigger": payload["trigger"],
            "startedUtc": payload["startedUtc"],
            "completedUtc": datetime.now(timezone.utc).isoformat(),
            "error": payload["error"],
        }
    )
