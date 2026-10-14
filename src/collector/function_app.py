"""WAF Pulse collector: Azure Durable Functions app.

Triggers
  scheduled_refresh  timer, schedule comes from the REFRESH_CRON app setting
  manual_refresh     storage queue 'refresh-requests', written by the dashboard "Refresh now" button

Both start the same orchestration, which scans every subscription the service principal can read.
"""
import logging
from datetime import datetime, timezone

import azure.durable_functions as df
import azure.functions as func

from waf_pulse import collect, credentials, graph, store

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
        results = yield context.task_all(
            [context.call_activity("act_collect", {"runId": run_id, "subscription": sub}) for sub in subscriptions]
        )
        summary = yield context.call_activity(
            "act_finalize",
            {"runId": run_id, "startedUtc": started, "trigger": trigger, "results": results},
        )
        return summary
    except Exception as exc:
        yield context.call_activity(
            "act_fail", {"runId": run_id, "startedUtc": started, "trigger": trigger, "error": str(exc)[:500]}
        )
        raise


@app.activity_trigger(input_name="payload")
def act_start_run(payload: dict):
    store.start_run(payload["runId"], payload["startedUtc"], payload["trigger"])


@app.activity_trigger(input_name="payload")
def act_discover(payload):
    subscriptions = graph.discover_subscriptions(credentials.collector_credential())
    logging.info("Discovered %d subscriptions", len(subscriptions))
    return subscriptions


@app.activity_trigger(input_name="payload")
def act_collect(payload: dict):
    findings, result = collect.collect_subscription(
        credentials.collector_credential(), payload["runId"], payload["subscription"]
    )
    store.save_findings(findings)
    return result


@app.activity_trigger(input_name="payload")
def act_finalize(payload: dict):
    completed = datetime.now(timezone.utc).isoformat()
    summary, score_docs = collect.build_summary(
        payload["runId"], payload["startedUtc"], completed, payload["trigger"], payload["results"]
    )
    store.save_summary(summary)
    store.save_scores(score_docs)
    store.save_run(
        {
            "id": payload["runId"],
            "subscriptionId": store.TENANT_PARTITION,
            "status": "completed",
            "trigger": payload["trigger"],
            "startedUtc": payload["startedUtc"],
            "completedUtc": completed,
            "subscriptionCount": summary["subscriptionCount"],
            "resourceCount": summary["resourceCount"],
            "findingCount": summary["findingCount"],
        }
    )
    try:
        store.save_snapshot(payload["runId"], "summary", summary)
    except Exception:  # the snapshot is a convenience copy, the run is already complete
        logging.exception("Could not write the summary snapshot")
    return {"runId": payload["runId"], "findingCount": summary["findingCount"]}


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
