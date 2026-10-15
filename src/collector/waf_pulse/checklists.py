"""Azure review checklists (https://github.com/Azure/review-checklists, MIT).

Every automated checklist item carries a Resource Graph query that returns each evaluated resource with a
`compliant` flag. Items run tenant wide, one query per call over all subscriptions, and the subscription of
each row is read from its resource id.
"""
import json
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

from . import graph
from .findings import make_finding, subscription_of

CHECKLIST_DIR = Path(__file__).resolve().parent / "checklists"
BATCH_SIZE = 8
MAX_ROWS = 20000
MAX_FINDINGS_PER_RULE = 500

# Checklist "waf" values do not match the pillar names 1:1.
PILLAR_MAP = {
    "reliability": "Reliability",
    "security": "Security",
    "cost": "Cost Optimization",
    "operations": "Operational Excellence",
    "performance": "Performance Efficiency",
}
SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def to_pillar(waf):
    return PILLAR_MAP.get(str(waf or "").strip().lower(), "Operational Excellence")


def to_severity(value):
    return SEVERITY_MAP.get(str(value or "").strip().lower(), "medium")


def rule_id(item):
    return f"CHK-{item['guid']}"


def is_non_compliant(value):
    """The `compliant` column arrives as a boolean, a 0/1 integer or text, depending on the query."""
    if value is None:
        return False
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value == 0
    return str(value).strip().lower() in ("false", "0", "non-compliant", "noncompliant", "no")


def strip_comments(kql):
    """Removes `//` comments. Some upstream queries are flattened to one line with a comment in the middle, which
    would swallow the rest of the query, so a comment ends at the end of the line or at the next pipe.
    Text inside quotes is kept."""
    out, i, quote = [], 0, None
    while i < len(kql):
        ch = kql[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(kql):
                out.append(kql[i + 1])
                i += 1
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
        elif kql.startswith("//", i):
            while i < len(kql) and kql[i] not in "|\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out).strip()


@lru_cache(maxsize=1)
def load_items():
    """Every automated item of every shipped checklist, in a stable order.

    The same control appears in several checklists (a service checklist and the general WAF one), so items are
    de-duplicated by guid, keeping the first, which is the more specific checklist.
    """
    items, seen = [], set()
    for path in sorted(CHECKLIST_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("items", []):
            if item["guid"] in seen:
                continue
            seen.add(item["guid"])
            items.append({**item, "graph": strip_comments(item["graph"]), "checklist": data.get("name") or path.stem})
    return items


@lru_cache(maxsize=1)
def plan_batches(batch_size=BATCH_SIZE):
    """Items sharing the same query run once. Returns [[(query, [items...]), ...], ...]."""
    by_query = OrderedDict()
    for item in load_items():
        by_query.setdefault(item["graph"].strip(), []).append(item)
    entries = list(by_query.items())
    return [entries[i:i + batch_size] for i in range(0, len(entries), batch_size)]


def batch_count():
    return len(plan_batches())


def execute_batch(credential, subscriptions, queries, workers=4):
    """Runs each query on its own. Resource Graph does not support `union` over subqueries, so the batch
    only groups queries for one activity. A failing query is reported and does not affect the others.
    Returns (rows per query, errors per query: a short message or None)."""

    def run(query):
        try:
            return graph.query(credential, subscriptions, query, max_rows=MAX_ROWS), None
        except Exception as exc:
            return [], _short_error(exc)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run, queries))
    return [rows for rows, _ in results], [error for _, error in results]


def _short_error(exc):
    """The useful part of a Resource Graph error: the last 'Message:' line, without the support ticket text."""
    lines = [line.strip() for line in str(exc).splitlines()]
    messages = [line[len("Message:"):].strip() for line in lines if line.startswith("Message:")]
    useful = [m for m in messages if "Please provide below info" not in m]
    return (useful[-1] if useful else (lines[0] if lines else "error"))[:200]


def evaluate(run_id, batch, rows_per_query):
    """Turns query results into findings and per rule, per subscription statistics."""
    findings, stats = [], []
    for (_, items), rows in zip(batch, rows_per_query):
        evaluated = [row for row in rows if "compliant" in row]
        if not evaluated:
            continue
        counts = {}
        violations = []
        for row in evaluated:
            sub = subscription_of(row.get("id")) or "unknown"
            affected, applicable = counts.get(sub, (0, 0))
            bad = is_non_compliant(row.get("compliant"))
            counts[sub] = (affected + (1 if bad else 0), applicable + 1)
            if bad:
                violations.append(row)
        for item in items:
            pillar, severity = to_pillar(item.get("waf")), to_severity(item.get("severity"))
            for sub, (affected, applicable) in counts.items():
                stats.append(
                    {
                        "ruleId": rule_id(item), "source": "checklist", "pillar": pillar, "severity": severity,
                        "subscriptionId": sub, "affected": affected, "applicable": applicable,
                    }
                )
            for row in violations[:MAX_FINDINGS_PER_RULE]:
                findings.append(
                    make_finding(
                        run_id, rule_id=rule_id(item), source="checklist", pillar=pillar, severity=severity,
                        title=item.get("text", ""), recommendation=item.get("text", ""),
                        resource_id=row.get("id", ""), resource_type=item.get("service", ""),
                        link=item.get("link"),
                    )
                )
    return findings, stats


def run_batch(credential, run_id, subscriptions, batch_index):
    """Runs one planned batch over the given subscriptions. Returns (findings, stats, errors)."""
    batch = plan_batches()[batch_index]
    rows_per_query, failures = execute_batch(credential, subscriptions, [query for query, _ in batch])
    findings, stats = evaluate(run_id, batch, rows_per_query)
    errors = [
        {"ruleId": rule_id(items[0]), "error": message}
        for (_, items), message in zip(batch, failures)
        if message
    ]
    return findings, stats, errors
