"""Key Vault secrets, keys and certificates that expired, expire soon or never expire.

Only metadata is read, never a secret value. Listing objects is a data plane operation, so the identity needs the
"Key Vault Reader" role on each vault (or list permission in an access policy), and a vault with a firewall must
allow the collector. Vaults that cannot be read are counted and reported, not treated as errors.
"""
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import graph, rest
from .findings import make_finding

SCOPE = "https://vault.azure.net/.default"
API_VERSION = "7.4"
WORKERS = 6
MAX_VAULTS = 300
MAX_OBJECTS_PER_KIND = 5000
TIME_BUDGET_SECONDS = 240
SOON_DAYS = 30
KINDS = ("secrets", "keys", "certificates")
SINGULAR = {"secrets": "secret", "keys": "key", "certificates": "certificate"}

QUERY = """
resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, subscriptionId, vaultUri = tostring(properties.vaultUri)
"""

RULES = {
    "SEC-KVX-001": ("Security", "high", "Key Vault {kind} has expired",
                    "Rotate it or delete it. Anything that still uses an expired {kind} is failing or about to fail."),
    "SEC-KVX-002": ("Security", "medium", "Key Vault {kind} expires in {days} days",
                    "Rotate the {kind} before it expires, ideally with automatic rotation."),
    "OPS-KVX-003": ("Operational Excellence", "low", "Key Vault {kind} has no expiration date",
                    "Set an expiration date so the {kind} is rotated on a schedule."),
}


def parse_objects(items, kind):
    """Normalize a data plane list: [{name, enabled, expires (datetime or None), managed}]."""
    result = []
    for item in items:
        attributes = item.get("attributes", {})
        expires = attributes.get("exp")
        result.append({
            "name": str(item.get("id", "")).rstrip("/").rsplit("/", 1)[-1],
            "enabled": attributes.get("enabled", True) is not False,
            "expires": datetime.fromtimestamp(expires, timezone.utc) if expires else None,
            # A secret that backs a certificate follows the certificate, so it is not judged on its own.
            "managed": bool(item.get("managed")),
            "kind": kind,
        })
    return result


def classify(obj, now):
    """Returns (rule id, days) or (None, None)."""
    if not obj["enabled"]:
        return None, None
    if obj["expires"] is None:
        return (None, None) if obj["managed"] or obj["kind"] == "certificates" else ("OPS-KVX-003", None)
    days = (obj["expires"] - now).days
    if obj["expires"] <= now:
        return "SEC-KVX-001", days
    return ("SEC-KVX-002", days) if days <= SOON_DAYS else (None, days)


def evaluate(run_id, vaults, objects, denied, now):
    """vaults: ARG rows; objects: {vault id: [parsed objects]}; denied: set of vault ids that could not be read."""
    findings, per_sub, upcoming = [], {}, []
    readable = 0
    for vault in vaults:
        if vault["id"] in denied or vault["id"] not in objects:
            continue
        readable += 1
        sub = str(vault.get("subscriptionId", "")).lower()
        for obj in objects[vault["id"]]:
            if not obj["enabled"] or (obj["managed"] and obj["kind"] == "secrets"):
                continue
            counts = per_sub.setdefault(sub, {})
            for rule in RULES:
                counts.setdefault(rule, {"affected": 0, "applicable": 0})["applicable"] += 1
            rule, days = classify(obj, now)
            if obj["expires"] is not None and days is not None and days <= 90:
                upcoming.append({"vault": vault.get("name", ""), "kind": SINGULAR[obj["kind"]], "name": obj["name"],
                                 "expires": obj["expires"].strftime("%Y-%m-%d"), "days": days})
            if not rule:
                continue
            counts[rule]["affected"] += 1
            pillar, severity, title, recommendation = RULES[rule]
            kind = SINGULAR[obj["kind"]]
            if len(findings) < 3000:
                findings.append(
                    make_finding(
                        run_id, rule_id=rule, source="keyvault", pillar=pillar, severity=severity,
                        title=title.format(kind=kind, days=days), recommendation=recommendation.format(kind=kind),
                        resource_id=f"{vault['id']}/{obj['kind']}/{obj['name']}",
                        resource_name=f"{vault.get('name', '')}/{obj['name']}",
                        resource_type=f"microsoft.keyvault/vaults/{obj['kind']}", subscription_id=sub,
                    )
                )
    stats = [
        {"ruleId": rule, "source": "keyvault", "pillar": RULES[rule][0], "severity": RULES[rule][1],
         "subscriptionId": sub, "affected": value["affected"], "applicable": value["applicable"]}
        for sub, rules in per_sub.items() for rule, value in rules.items()
    ]
    upcoming.sort(key=lambda item: item["days"])
    dataset = {
        "vaults": len(vaults), "readable": readable, "denied": len(denied),
        "notChecked": len(vaults) - readable - len(denied),
        "objects": sum(len(items) for items in objects.values()),
        "upcoming": upcoming[:20],
    }
    return findings, stats, dataset


def list_objects(token, vault_uri, kind):
    """Pages through one object type. Returns (items, status): status is 'ok' or 'denied'."""
    items = []
    url, params = f"{vault_uri.rstrip('/')}/{kind}", {"api-version": API_VERSION, "maxresults": 25}
    while url and len(items) < MAX_OBJECTS_PER_KIND:
        response = rest.get(url, token, params)
        if response.status_code in (401, 403):
            return items, "denied"
        response.raise_for_status()
        body = response.json()
        items.extend(body.get("value", []))
        url, params = body.get("nextLink"), None
    return items, "ok"


def collect(credential, run_id, subscription_ids, now=None):
    vaults, errors = [], []
    try:
        for chunk in graph.chunks(subscription_ids):
            vaults.extend(graph.query(credential, chunk, QUERY, max_rows=MAX_VAULTS))
    except Exception as exc:
        errors.append({"ruleId": "keyvault-list", "error": str(exc).splitlines()[0][:200]})
    vaults = [v for v in vaults if v.get("vaultUri")][:MAX_VAULTS]
    deadline = time.monotonic() + TIME_BUDGET_SECONDS
    token = credential.get_token(SCOPE).token if vaults else ""

    def read(vault):
        if time.monotonic() > deadline:
            return vault["id"], None, "skipped"
        parsed = []
        try:
            for kind in KINDS:
                items, status = list_objects(token, vault["vaultUri"], kind)
                if status == "denied":
                    return vault["id"], None, "denied"
                parsed.extend(parse_objects(items, kind))
            return vault["id"], parsed, "ok"
        except Exception:
            # A vault behind a firewall usually refuses the connection or answers 403.
            return vault["id"], None, "denied"

    objects, denied = {}, set()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for vault_id, parsed, status in pool.map(read, vaults):
            if status == "ok":
                objects[vault_id] = parsed
            elif status == "denied":
                denied.add(vault_id)
    now = now or datetime.now(timezone.utc)
    findings, stats, dataset = evaluate(run_id, vaults, objects, denied, now)
    return findings, stats, dataset, errors
