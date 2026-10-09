"""Turn the lab directory and its event log into categorized alerts."""

from __future__ import annotations

from .policy import is_standing_admin

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_WEIGHT = {"critical": 8, "high": 4, "medium": 2, "low": 1}

SCAN_STEPS = [
    ("Security logs", "Read Security events from every domain controller, not from one console."),
    ("Directory Service logs", "Read replication and directory-change events, including 1925 and 5136."),
    ("Account hygiene", "Lockouts, Guest, the built-in Administrator, stale users, and expired passwords."),
    ("Privileged groups", "Standing Domain Admins membership, Protected Users, and service accounts."),
    ("Replication and FSMO", "Compare last success with the site-link schedule and list FSMO owners."),
    ("Microsoft guidance", "Attach a Learn article and a support note to every finding."),
]


def _alert(
    *,
    id: str,
    severity: str,
    category: str,
    title: str,
    subject: str,
    subject_kind: str,
    guidance: str,
    summary: str,
    evidence: list[str],
    source: str,
) -> dict:
    return {
        "id": id,
        "severity": severity,
        "category": category,
        "title": title,
        "subject": subject,
        "subject_kind": subject_kind,
        "guidance": guidance,
        "summary": summary,
        "evidence": evidence,
        "source": source,
    }


def _by_sam(state: dict) -> dict[str, dict]:
    return {user["sam"]: user for user in state["users"]}


def _events(state: dict, event_id: int, account: str | None = None) -> list[dict]:
    found = []
    for event in state["events"]:
        if event["event_id"] != event_id:
            continue
        if account and event.get("account") != account:
            continue
        found.append(event)
    return found


def _evidence_from(events: list[dict]) -> list[str]:
    lines = []
    for event in events:
        lines.append(
            f"Event {event['event_id']} on {event['computer']} — {event['summary']}"
        )
    return lines


def build_alerts(state: dict) -> list[dict]:
    users = _by_sam(state)
    alerts: list[dict] = []
    closed = set(state.get("closed_incidents", []))

    arjun = users["arjun.patel"]
    if "Domain Admins" in arjun["groups"]:
        alerts.append(
            _alert(
                id="priv-arjun-domain-admins",
                severity="critical",
                category="Privilege assignment",
                title="Intern account is a member of Domain Admins",
                subject="arjun.patel",
                subject_kind="user",
                guidance="privileged-membership",
                summary="Arjun Patel is an IT intern in the people OU, and he is a permanent member of Domain Admins. Helena Voss added him. There is no standing reason for that membership.",
                evidence=_evidence_from(_events(state, 4728, "arjun.patel")),
                source="Privileged-group scan",
            )
        )

    if "audit-log-cleared" not in closed:
        alerts.append(
            _alert(
                id="audit-log-cleared",
                severity="critical",
                category="Audit integrity",
                title="Security log cleared on FAB-DC02",
                subject="FAB-DC02",
                subject_kind="computer",
                guidance="audit-integrity",
                summary="Helena Voss cleared the Security log on FAB-DC02, and the audit policy on that DC changed in the same window. Until a change ticket explains both, this stays critical.",
                evidence=_evidence_from(_events(state, 1102) + _events(state, 4719)),
                source="Security log",
            )
        )

    krbtgt = users["krbtgt"]
    if krbtgt["password_age_days"] > 180:
        alerts.append(
            _alert(
                id="krbtgt-age",
                severity="critical",
                category="Credential hygiene",
                title=f"krbtgt password is {krbtgt['password_age_days']} days old",
                subject="krbtgt",
                subject_kind="user",
                guidance="krbtgt",
                summary="The Kerberos account password has not been rotated twice on the forest-recovery schedule. A single helpdesk reset would not retire the previous key.",
                evidence=[
                    f"pwdLastSet is {krbtgt['password_age_days']} days ago. Microsoft's procedure resets krbtgt twice, waiting longer than the ticket lifetime between resets."
                ],
                source="Credential scan",
            )
        )

    guest = users["guest"]
    if guest["enabled"]:
        alerts.append(
            _alert(
                id="guest-enabled",
                severity="high",
                category="Account hygiene",
                title="Built-in Guest account is enabled",
                subject="guest",
                subject_kind="user",
                guidance="guest-account",
                summary="Guest is enabled in CN=Users. It should stay disabled. Visitors need a named account.",
                evidence=["userAccountControl shows the built-in Guest account enabled."],
                source="Account hygiene scan",
            )
        )

    admin = users["administrator"]
    if admin["enabled"]:
        alerts.append(
            _alert(
                id="builtin-admin-enabled",
                severity="high",
                category="Account hygiene",
                title="Built-in Administrator is enabled",
                subject="administrator",
                subject_kind="user",
                guidance="builtin-administrator",
                summary=f"The shared Administrator account is enabled and its password is {admin['password_age_days']} days old. Named Tier-0 accounts already exist.",
                evidence=[
                    "Administrator is a member of Domain Admins and Enterprise Admins.",
                    f"Password age {admin['password_age_days']} days.",
                ],
                source="Account hygiene scan",
            )
        )

    for link in state["replication"]:
        if link["status"] != "Healthy":
            alerts.append(
                _alert(
                    id=f"repl-{link['dest'].lower()}",
                    severity="high",
                    category="Replication",
                    title=f"Replication to {link['dest']} is failing",
                    subject=link["dest"],
                    subject_kind="computer",
                    guidance="replication",
                    summary=f"{link['source']} to {link['dest']} last succeeded {link['minutes']} minutes ago. The London–Singapore schedule is {link['schedule_minutes']} minutes. Event 1925 reports a DNS lookup failure, so this is not the inter-site schedule.",
                    evidence=_evidence_from(_events(state, 1925))
                    + [link["error"]],
                    source="Replication scan",
                )
            )

    for sam in ("priya.nair", "emma.berg"):
        user = users[sam]
        if not user["locked"]:
            continue
        caller = user["lockout_caller"] or "blank"
        severity = "high" if caller != "blank" else "medium"
        summary = (
            f"{user['display']} is locked after {user['bad_pwd_count']} bad passwords. Caller computer is {caller}."
            if caller != "blank"
            else f"{user['display']} is locked and the 4740 caller computer is blank. That often means a non-domain device or a client that did not supply a name. Correlate 4771 and 4776 on the PDC emulator before you unlock."
        )
        alerts.append(
            _alert(
                id=f"lockout-{sam}",
                severity=severity,
                category="Account lockout",
                title=f"Account locked — {user['display']}",
                subject=sam,
                subject_kind="user",
                guidance="lockout",
                summary=summary,
                evidence=_evidence_from(_events(state, 4740, sam) + _events(state, 4771, sam) + _events(state, 4625, sam)),
                source="Security log",
            )
        )

    for sam in ("svc-sql", "svc-backup"):
        user = users[sam]
        if not (user["password_never_expires"] and user["password_age_days"] > 180):
            continue
        interactive = _events(state, 4624, sam) + _events(state, 4672, sam)
        severity = "high" if interactive else "medium"
        title = (
            f"{sam} signed on interactively and the password is {user['password_age_days']} days old"
            if interactive
            else f"{sam} password never expires and is {user['password_age_days']} days old"
        )
        alerts.append(
            _alert(
                id=f"service-{sam}",
                severity=severity,
                category="Credential hygiene",
                title=title,
                subject=sam,
                subject_kind="user",
                guidance="service-accounts",
                summary="This is a user account acting as a service. Group managed service accounts exist so operators do not keep a permanent password in a script.",
                evidence=_evidence_from(interactive)
                or [f"Password never expires. Age {user['password_age_days']} days. Groups: {', '.join(user['groups'])}."],
                source="Service-account scan",
            )
        )

    liam = users["liam.wright"]
    if liam["password_expired"] or (liam["enabled"] and liam["password_age_days"] > 90 and not liam["password_never_expires"] and not liam["service"]):
        if liam["sam"] and liam["password_expired"]:
            alerts.append(
                _alert(
                    id="password-liam-wright",
                    severity="medium",
                    category="Password hygiene",
                    title="Password expired — Liam Wright",
                    subject="liam.wright",
                    subject_kind="user",
                    guidance="password-hygiene",
                    summary="Liam is a standard account in Sales. Helpdesk can reset this password. It is not a Tier-0 change.",
                    evidence=[f"Password age {liam['password_age_days']} days. Domain maximum age is 90 days."],
                    source="Password scan",
                )
            )

    helena = users["helena.voss"]
    if is_standing_admin(helena) and helena["password_age_days"] > 180:
        alerts.append(
            _alert(
                id="password-helena-voss",
                severity="medium",
                category="Password hygiene",
                title=f"Tier-0 password is {helena['password_age_days']} days old",
                subject="helena.voss",
                subject_kind="user",
                guidance="password-hygiene",
                summary="Helena Voss is in Domain Admins and Schema Admins. Helpdesk must not reset this password. A Tier-0 operator should, and then consider Protected Users.",
                evidence=[f"Password age {helena['password_age_days']} days. Protected Users: {'yes' if helena['protected_users'] else 'no'}."],
                source="Privileged-account scan",
            )
        )

    missing = [user for user in users.values() if is_standing_admin(user) and not user["protected_users"]]
    if missing:
        names = ", ".join(sorted(user["display"] for user in missing))
        alerts.append(
            _alert(
                id="protected-users-gap",
                severity="medium",
                category="Privilege assignment",
                title="Standing admins are missing from Protected Users",
                subject="Domain Admins",
                subject_kind="group",
                guidance="protected-users",
                summary=f"These enabled human Domain Admins are not in Protected Users: {names}. Test one account before you add the rest. The account needs an AES key.",
                evidence=[f"{user['sam']} protected_users=no" for user in missing],
                source="Privileged-group scan",
            )
        )

    tom = users["tom.bauer"]
    if tom["enabled"] and tom["last_logon_days"] is not None and tom["last_logon_days"] > 90:
        alerts.append(
            _alert(
                id="stale-tom-bauer",
                severity="medium",
                category="Stale identity",
                title=f"Tom Bauer has not signed on for {tom['last_logon_days']} days",
                subject="tom.bauer",
                subject_kind="user",
                guidance="stale-accounts",
                summary="The account is still enabled in the warehouse team. Disable it after the manager confirms he has left or changed role.",
                evidence=[f"lastLogonTimestamp is {tom['last_logon_days']} days old."],
                source="Stale-account scan",
            )
        )

    nora = users["nora.hassan"]
    if nora["enabled"] and nora["last_logon_days"] is None and nora["created_days"] > 30:
        alerts.append(
            _alert(
                id="never-nora-hassan",
                severity="low",
                category="Stale identity",
                title="Nora Hassan has never signed on",
                subject="nora.hassan",
                subject_kind="user",
                guidance="stale-accounts",
                summary=f"The account was created {nora['created_days']} days ago and has no logon. Confirm the hire before you leave an enabled unused account in the directory.",
                evidence=["lastLogonTimestamp is unset."],
                source="Stale-account scan",
            )
        )

    for computer in state["computers"]:
        days = computer["last_logon_days"]
        if days is not None and days > 90:
            alerts.append(
                _alert(
                    id=f"stale-computer-{computer['name'].lower()}",
                    severity="low",
                    category="Stale identity",
                    title=f"{computer['name']} has not contacted the domain for {days} days",
                    subject=computer["name"],
                    subject_kind="computer",
                    guidance="stale-accounts",
                    summary=computer["note"] or "The computer account is still enabled.",
                    evidence=[f"Operating system {computer['os']}, site {computer['site']}, last logon {days} days ago."],
                    source="Computer-account scan",
                )
            )

    policy = state["policy"]
    if policy["min_length"] < 14 or not policy["fgpp"]:
        alerts.append(
            _alert(
                id="password-policy-legacy",
                severity="medium",
                category="Group Policy",
                title="Domain password policy is still a short, one-size minimum",
                subject="Default Domain Policy",
                subject_kind="policy",
                guidance="password-policy",
                summary=f"Minimum length is {policy['min_length']}, complexity is {'on' if policy['complexity'] else 'off'}, and passwords expire every {policy['max_age_days']} days. No fine-grained password settings object is defined. A 5136 event shows the policy object was edited.",
                evidence=_evidence_from(_events(state, 5136))
                + [
                    f"Lockout threshold {policy['lockout_threshold']} in {policy['observation_minutes']} minutes, duration {policy['lockout_minutes']} minutes."
                ],
                source="Group Policy scan",
            )
        )

    alerts.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["category"], item["title"]))
    return alerts


def summarize(state: dict, alerts: list[dict]) -> dict:
    by_severity = {name: 0 for name in SEVERITY_ORDER}
    by_category: dict[str, int] = {}
    for alert in alerts:
        by_severity[alert["severity"]] += 1
        by_category[alert["category"]] = by_category.get(alert["category"], 0) + 1
    penalty = sum(SEVERITY_WEIGHT[alert["severity"]] for alert in alerts)
    score = max(0, min(100, 100 - penalty))
    if score >= 80:
        band = "Steady"
    elif score >= 60:
        band = "Watch"
    else:
        band = "Action required"
    critical = by_severity["critical"]
    if critical:
        briefing = (
            f"{critical} critical {'finding' if critical == 1 else 'findings'} need a Tier-0 review "
            "before helpdesk treats today's lockouts as ordinary."
        )
    elif alerts:
        briefing = "No critical findings. Work the high items, then publish another scan."
    else:
        briefing = "This scan published a clean queue."
    healthy_dcs = sum(1 for dc in state["domain_controllers"] if dc["replication"] == "Healthy")
    return {
        "score": score,
        "band": band,
        "total": len(alerts),
        "by_severity": by_severity,
        "by_category": by_category,
        "briefing": briefing,
        "locked": sum(1 for user in state["users"] if user["locked"]),
        "domain_controllers": len(state["domain_controllers"]),
        "healthy_domain_controllers": healthy_dcs,
    }


def scan(state: dict) -> dict:
    alerts = build_alerts(state)
    summary = summarize(state, alerts)
    security = sum(1 for event in state["events"] if event["channel"] == "Security")
    directory = sum(1 for event in state["events"] if event["channel"] == "Directory Service")
    steps = []
    for name, detail in SCAN_STEPS:
        extra = detail
        if name == "Security logs":
            extra = f"{security} Security records in the lab log. {detail}"
        elif name == "Directory Service logs":
            extra = f"{directory} Directory Service records. {detail}"
        elif name == "Microsoft guidance":
            extra = f"{summary['total']} findings categorized. {detail}"
        steps.append({"name": name, "detail": extra})
    return {"alerts": alerts, "summary": summary, "steps": steps}


def drift(state: dict) -> bool:
    published = {alert["id"] for alert in state.get("published_alerts", [])}
    live = {alert["id"] for alert in build_alerts(state)}
    return published != live
