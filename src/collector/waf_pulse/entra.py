"""Microsoft Entra and Defender XDR insights from Microsoft Graph.

Everything here needs optional Graph application permissions on the collector's app registration:
Application.Read.All (app credentials), User.Read.All (guest users) and SecurityIncident.Read.All (Defender XDR
incidents). Each part is independent: a missing permission is reported as "not available" on the dashboard, not as
an error. Only metadata is read, never a secret value.
"""
from datetime import datetime, timedelta, timezone

from . import rest
from .findings import make_finding

SCOPE = "https://graph.microsoft.com/.default"
BASE = "https://graph.microsoft.com/v1.0"
TENANT = "tenant"
SOON_DAYS = 30
LONG_LIVED_DAYS = 730
STALE_INVITE_DAYS = 30
MAX_PAGES = 40
MAX_FINDINGS = 1500

RULES = {
    "SEC-APP-001": ("Security", "medium", "App registration has an expired credential",
                    "Delete the expired credential. If the app still uses it, it is failing right now."),
    "OPS-APP-002": ("Operational Excellence", "high", "App registration credential expires in {days} days",
                    "Create a new credential and switch the app to it before the old one expires."),
    "SEC-APP-003": ("Security", "low", "App registration has a credential valid for more than two years",
                    "Use shorter lived credentials, or better a managed identity or a federated credential."),
    "SEC-GUEST-001": ("Security", "low", "Guest invitation was never accepted",
                      "Remove the guest if the invitation is no longer needed."),
    "SEC-XDR-001": ("Security", "high", "Defender XDR incident is still open: {name}",
                    "Triage the incident in the Defender portal."),
}
INCIDENT_SEVERITY = {"high": "high", "medium": "medium", "low": "low", "informational": "low"}
OPEN_INCIDENT = {"active", "inprogress"}


def fetch_all(token, path, params=None, headers=None):
    """Follows @odata.nextLink. Returns (items, status) with status 'ok', 'denied' or 'error'."""
    items, url = [], f"{BASE}{path}"
    for _ in range(MAX_PAGES):
        response = rest.get(url, token, params, headers)
        if response.status_code in (401, 403):
            return items, "denied"
        if response.status_code >= 400:
            return items, "error"
        body = response.json()
        items.extend(body.get("value", []))
        url, params = body.get("@odata.nextLink"), None
        if not url:
            break
    return items, "ok"


def _moment(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def credentials_of(app):
    """[{kind, start, end}] for the secrets and certificates of an app registration."""
    found = []
    for kind, field in (("secret", "passwordCredentials"), ("certificate", "keyCredentials")):
        for item in app.get(field) or []:
            end = _moment(item.get("endDateTime"))
            if end:
                found.append({"kind": kind, "start": _moment(item.get("startDateTime")), "end": end})
    return found


def evaluate_apps(run_id, apps, now):
    findings, counts = [], {rule: 0 for rule in ("SEC-APP-001", "OPS-APP-002", "SEC-APP-003")}
    soon, with_credentials = [], 0
    for app in apps:
        creds = credentials_of(app)
        if not creds:
            continue
        with_credentials += 1
        name = app.get("displayName") or app.get("appId") or app.get("id", "")
        horizon = now + timedelta(days=SOON_DAYS)
        expired = [c for c in creds if c["end"] <= now]
        valid = [c for c in creds if c["end"] > now]
        outcomes = []
        if expired:
            outcomes.append(("SEC-APP-001", None))
        if valid and not any(c["end"] > horizon for c in valid):
            days = max((min(c["end"] for c in valid) - now).days, 0)
            outcomes.append(("OPS-APP-002", days))
            soon.append({"app": name, "days": days, "kind": valid[0]["kind"]})
        elif not valid and expired:
            soon.append({"app": name, "days": (max(c["end"] for c in expired) - now).days, "kind": expired[0]["kind"]})
        if any(c["start"] and (c["end"] - c["start"]).days > LONG_LIVED_DAYS for c in valid):
            outcomes.append(("SEC-APP-003", None))
        for rule, days in outcomes:
            counts[rule] += 1
            pillar, severity, title, recommendation = RULES[rule]
            if len(findings) < MAX_FINDINGS:
                findings.append(
                    make_finding(
                        run_id, rule_id=rule, source="entra", pillar=pillar, severity=severity,
                        title=title.format(days=days), recommendation=recommendation,
                        resource_id=f"/tenant/applications/{app.get('id', name)}", resource_name=name,
                        resource_type="microsoft.graph/applications", subscription_id=TENANT,
                    )
                )
    stats = [
        {"ruleId": rule, "source": "entra", "pillar": RULES[rule][0], "severity": RULES[rule][1],
         "subscriptionId": TENANT, "affected": count, "applicable": with_credentials}
        for rule, count in counts.items() if with_credentials
    ]
    soon.sort(key=lambda item: item["days"])
    return findings, stats, {"apps": len(apps), "withCredentials": with_credentials,
                             "expiredOrExpiring": soon[:20], "expiredApps": counts["SEC-APP-001"]}


def evaluate_guests(run_id, guests, now):
    stale_before = now - timedelta(days=STALE_INVITE_DAYS)
    findings, pending = [], 0
    for guest in guests:
        created = _moment(guest.get("createdDateTime"))
        if str(guest.get("externalUserState", "")).lower() != "pendingacceptance":
            continue
        pending += 1
        if created and created < stale_before and len(findings) < MAX_FINDINGS:
            pillar, severity, title, recommendation = RULES["SEC-GUEST-001"]
            findings.append(
                make_finding(
                    run_id, rule_id="SEC-GUEST-001", source="entra", pillar=pillar, severity=severity, title=title,
                    recommendation=recommendation, resource_id=f"/tenant/users/{guest.get('id', '')}",
                    resource_name=guest.get("userPrincipalName") or guest.get("displayName", ""),
                    resource_type="microsoft.graph/users", subscription_id=TENANT,
                )
            )
    stats = [{"ruleId": "SEC-GUEST-001", "source": "entra", "pillar": "Security", "severity": "low",
              "subscriptionId": TENANT, "affected": len(findings), "applicable": len(guests)}] if guests else []
    return findings, stats, {"total": len(guests), "pendingInvitations": pending, "staleInvitations": len(findings)}


def evaluate_incidents(run_id, incidents):
    findings, by_severity = [], {}
    for incident in incidents:
        if str(incident.get("status", "")).lower() not in OPEN_INCIDENT:
            continue
        severity = INCIDENT_SEVERITY.get(str(incident.get("severity", "")).lower(), "medium")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        pillar, _, title, recommendation = RULES["SEC-XDR-001"]
        if len(findings) < 200:
            findings.append(
                make_finding(
                    run_id, rule_id="SEC-XDR-001", source="entra", pillar=pillar, severity=severity,
                    title=title.format(name=incident.get("displayName", incident.get("id", ""))),
                    recommendation=recommendation, resource_id=f"/tenant/incidents/{incident.get('id', '')}",
                    resource_name=incident.get("displayName", ""), resource_type="microsoft.graph/incidents",
                    subscription_id=TENANT, link=incident.get("incidentWebUrl"),
                )
            )
    # Every open incident is a finding by itself, so there is no "applicable" population to compare with.
    stats = [{"ruleId": "SEC-XDR-001", "source": "entra", "pillar": "Security", "severity": "high",
              "subscriptionId": TENANT, "affected": len(findings), "applicable": None}] if findings else []
    return findings, stats, {"open": len(findings), "bySeverity": by_severity}


def collect(credential, run_id, subscription_ids=None, now=None):
    """Returns (findings, stats, dataset, errors). dataset['available'] tells which parts could be read."""
    now = now or datetime.now(timezone.utc)
    token = credential.get_token(SCOPE).token
    findings, stats, errors = [], [], []
    dataset = {"available": {}, "permissions": {"apps": "Application.Read.All", "guests": "User.Read.All",
                                                  "incidents": "SecurityIncident.Read.All"}}

    def part(name, path, params, headers, evaluate):
        items, status = fetch_all(token, path, params, headers)
        dataset["available"][name] = status == "ok"
        if status == "error":
            errors.append({"ruleId": f"entra-{name}", "error": "Microsoft Graph returned an error"})
        if status != "ok":
            return
        found, rows, data = evaluate(items)
        findings.extend(found)
        stats.extend(rows)
        dataset[name] = data

    part("apps", "/applications",
         {"$select": "id,appId,displayName,passwordCredentials,keyCredentials", "$top": 999}, None,
         lambda items: evaluate_apps(run_id, items, now))
    part("guests", "/users",
         {"$filter": "userType eq 'Guest'", "$select": "id,displayName,userPrincipalName,createdDateTime,externalUserState",
          "$top": 999, "$count": "true"}, {"ConsistencyLevel": "eventual"},
         lambda items: evaluate_guests(run_id, items, now))
    part("incidents", "/security/incidents", {"$top": 50}, None,
         lambda items: tuple(evaluate_incidents(run_id, items)))
    return findings, stats, dataset, errors
