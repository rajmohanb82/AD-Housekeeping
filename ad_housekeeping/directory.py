"""Lab directory for fabrikam.corp.

LabDirectory is the seam a production build would replace with LDAP or ADWS.
The scanner, the role checks, and the web console stay the same.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta
from pathlib import Path

from .policy import (
    OPERATORS,
    Denied,
    assert_allowed,
    assess_password,
    can_close_incident,
    can_disable,
    can_protect,
    can_remove_domain_admin,
    can_reset,
    can_unlock,
    is_privileged,
)
from .scanner import scan

VERSION = 1
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = ROOT / "instance" / "lab_state.json"


def now() -> datetime:
    return datetime.now().astimezone().replace(microsecond=0)


def stamp(**kwargs) -> str:
    return (now() - timedelta(**kwargs)).isoformat()


def _user(**kwargs) -> dict:
    sam = kwargs["sam"]
    record = {
        "sam": sam,
        "upn": f"{sam}@fabrikam.corp",
        "display": kwargs["display"],
        "title": kwargs.get("title", ""),
        "department": kwargs.get("department", ""),
        "ou": kwargs.get("ou", "OU=People,OU=Fabrikam,DC=fabrikam,DC=corp"),
        "ou_label": kwargs.get("ou_label", "People"),
        "enabled": kwargs.get("enabled", True),
        "locked": kwargs.get("locked", False),
        "password_age_days": kwargs.get("password_age_days", 30),
        "password_never_expires": kwargs.get("password_never_expires", False),
        "password_expired": kwargs.get("password_expired", False),
        "must_change": kwargs.get("must_change", False),
        "last_logon_days": kwargs.get("last_logon_days", 1),
        "created_days": kwargs.get("created_days", 400),
        "groups": list(kwargs.get("groups", ["Domain Users"])),
        "service": kwargs.get("service", False),
        "builtin": kwargs.get("builtin", False),
        "protected_users": kwargs.get("protected_users", False),
        "bad_pwd_count": kwargs.get("bad_pwd_count", 0),
        "lockout_caller": kwargs.get("lockout_caller", ""),
    }
    return record


def _event(**kwargs) -> dict:
    return {
        "record": kwargs["record"],
        "event_id": kwargs["event_id"],
        "channel": kwargs.get("channel", "Security"),
        "logged": kwargs["logged"],
        "computer": kwargs["computer"],
        "account": kwargs.get("account", ""),
        "severity": kwargs.get("severity", "info"),
        "category": kwargs["category"],
        "summary": kwargs["summary"],
        "actionable": kwargs.get("actionable", False),
    }


def fresh_state() -> dict:
    users = [
        _user(sam="arjun.patel", display="Arjun Patel", title="IT intern", department="Information Technology", ou_label="People", password_age_days=12, last_logon_days=0, created_days=70, groups=["Domain Users", "IT-Interns", "Domain Admins"]),
        _user(sam="priya.nair", display="Priya Nair", title="Finance controller", department="Finance", ou="OU=Finance,OU=People,OU=Fabrikam,DC=fabrikam,DC=corp", ou_label="Finance", locked=True, password_age_days=2, last_logon_days=0, created_days=2100, groups=["Domain Users", "Finance-Users"], bad_pwd_count=8, lockout_caller="WKS-1042"),
        _user(sam="emma.berg", display="Emma Berg", title="Account executive", department="Sales", ou_label="Sales", locked=True, password_age_days=40, last_logon_days=1, created_days=900, groups=["Domain Users", "Sales-Users"], bad_pwd_count=6, lockout_caller=""),
        _user(sam="liam.wright", display="Liam Wright", title="Account executive", department="Sales", ou_label="Sales", password_age_days=96, password_expired=True, last_logon_days=2, created_days=1400, groups=["Domain Users", "Sales-Users"]),
        _user(sam="tom.bauer", display="Tom Bauer", title="Warehouse supervisor", department="Operations", ou_label="Operations", password_age_days=200, last_logon_days=214, created_days=2600, groups=["Domain Users", "Warehouse-Users"]),
        _user(sam="nora.hassan", display="Nora Hassan", title="New starter", department="People team", ou_label="People", password_age_days=45, last_logon_days=None, created_days=45, groups=["Domain Users"]),
        _user(sam="sarah.chen", display="Sarah Chen", title="IT director", department="Information Technology", ou_label="People", password_age_days=18, last_logon_days=0, created_days=3200, groups=["Domain Users", "IT-Managers"]),
        _user(sam="james.okonkwo", display="James Okonkwo", title="Helpdesk lead", department="Information Technology", ou_label="People", password_age_days=22, last_logon_days=0, created_days=1800, groups=["Domain Users", "Fabrikam-ADHK-Helpdesk"]),
        _user(sam="mina.rahman", display="Mina Rahman", title="Directory auditor", department="Risk", ou_label="People", password_age_days=15, last_logon_days=0, created_days=1500, groups=["Domain Users", "Fabrikam-ADHK-Auditors"]),
        _user(sam="wei.zhang", display="Wei Zhang", title="Engineer", department="Product", ou_label="Product", password_age_days=9, last_logon_days=0, created_days=700, groups=["Domain Users", "Product-Users"]),
        _user(sam="aisha.khan", display="Aisha Khan", title="HR partner", department="People team", ou_label="People", password_age_days=0, must_change=True, last_logon_days=0, created_days=3, groups=["Domain Users", "HR-Users"]),
        _user(sam="olivia.grant", display="Olivia Grant", title="Identity administrator", department="Information Technology", ou="OU=Privileged,OU=Fabrikam,DC=fabrikam,DC=corp", ou_label="Privileged", password_age_days=36, last_logon_days=0, created_days=2800, groups=["Domain Users", "Domain Admins"]),
        _user(sam="helena.voss", display="Helena Voss", title="Directory engineer", department="Information Technology", ou="OU=Privileged,OU=Fabrikam,DC=fabrikam,DC=corp", ou_label="Privileged", password_age_days=210, last_logon_days=0, created_days=4100, groups=["Domain Users", "Domain Admins", "Schema Admins"]),
        _user(sam="svc-sql", display="SQL service", title="Service account", department="Platform", ou="OU=Service Accounts,OU=Fabrikam,DC=fabrikam,DC=corp", ou_label="Service Accounts", password_age_days=410, password_never_expires=True, last_logon_days=0, created_days=2000, groups=["Domain Users"], service=True),
        _user(sam="svc-backup", display="Backup service", title="Service account", department="Platform", ou="OU=Service Accounts,OU=Fabrikam,DC=fabrikam,DC=corp", ou_label="Service Accounts", password_age_days=640, password_never_expires=True, last_logon_days=1, created_days=2400, groups=["Domain Users", "Backup Operators"], service=True),
        _user(sam="guest", display="Guest", title="Built-in guest", department="Built-in", ou="CN=Users,DC=fabrikam,DC=corp", ou_label="Built-in", enabled=True, password_age_days=3000, last_logon_days=None, created_days=4000, groups=["Guests"], builtin=True),
        _user(sam="krbtgt", display="krbtgt", title="Key Distribution Center account", department="Built-in", ou="CN=Users,DC=fabrikam,DC=corp", ou_label="Built-in", password_age_days=418, password_never_expires=True, last_logon_days=None, created_days=4000, groups=["Denied RODC Password Replication Group"], builtin=True),
        _user(sam="administrator", display="Administrator", title="Built-in administrator", department="Built-in", ou="CN=Users,DC=fabrikam,DC=corp", ou_label="Built-in", password_age_days=180, last_logon_days=12, created_days=4000, groups=["Domain Users", "Domain Admins", "Enterprise Admins", "Administrators"], builtin=True),
    ]
    events = [
        _event(record=48120, event_id=4728, logged=stamp(hours=20), computer="FAB-DC01.fabrikam.corp", account="arjun.patel", severity="critical", category="Privilege assignment", actionable=True, summary="Helena Voss added arjun.patel to Domain Admins."),
        _event(record=48155, event_id=5136, logged=stamp(days=2), computer="FAB-DC01.fabrikam.corp", account="helena.voss", severity="medium", category="Group Policy", actionable=True, summary="The Default Domain Policy password-policy object was modified."),
        _event(record=48201, event_id=4719, logged=stamp(hours=9, minutes=20), computer="FAB-DC02.fabrikam.corp", account="helena.voss", severity="critical", category="Audit integrity", actionable=True, summary="System audit policy was changed on FAB-DC02."),
        _event(record=48202, event_id=1102, logged=stamp(hours=9), computer="FAB-DC02.fabrikam.corp", account="helena.voss", severity="critical", category="Audit integrity", actionable=True, summary="The Security audit log was cleared. Subject: helena.voss."),
        _event(record=48220, event_id=1925, logged=stamp(hours=6, minutes=12), computer="FAB-DC04.fabrikam.corp", account="", severity="high", category="Replication", channel="Directory Service", actionable=True, summary="Replication link from FAB-DC02 failed. DNS lookup failure for the partner GUID."),
        _event(record=48240, event_id=4624, logged=stamp(hours=5), computer="FAB-SQL01.fabrikam.corp", account="svc-sql", severity="high", category="Credential hygiene", actionable=True, summary="Interactive logon (type 2) for svc-sql on FAB-SQL01."),
        _event(record=48241, event_id=4672, logged=stamp(hours=5), computer="FAB-SQL01.fabrikam.corp", account="svc-sql", severity="high", category="Credential hygiene", actionable=True, summary="Special privileges were assigned to the new svc-sql logon."),
        _event(record=48260, event_id=4625, logged=stamp(hours=3, minutes=10), computer="FAB-DC01.fabrikam.corp", account="emma.berg", severity="medium", category="Account lockout", actionable=True, summary="Failed logon for emma.berg. Caller computer name is blank."),
        _event(record=48261, event_id=4740, logged=stamp(hours=3), computer="FAB-DC01.fabrikam.corp", account="emma.berg", severity="medium", category="Account lockout", actionable=True, summary="emma.berg was locked out. Caller computer name is blank."),
        _event(record=48280, event_id=4768, logged=stamp(hours=2), computer="FAB-DC01.fabrikam.corp", account="helena.voss", severity="info", category="Informational", summary="Kerberos TGT issued for helena.voss."),
        _event(record=48290, event_id=4624, logged=stamp(hours=1), computer="FAB-DC01.fabrikam.corp", account="james.okonkwo", severity="info", category="Informational", summary="Successful interactive logon for james.okonkwo."),
        _event(record=48310, event_id=4771, logged=stamp(minutes=46), computer="FAB-DC01.fabrikam.corp", account="priya.nair", severity="high", category="Account lockout", actionable=True, summary="Kerberos pre-authentication failed for priya.nair. Client WKS-1042."),
        _event(record=48311, event_id=4740, logged=stamp(minutes=44), computer="FAB-DC01.fabrikam.corp", account="priya.nair", severity="high", category="Account lockout", actionable=True, summary="priya.nair was locked out. Caller computer WKS-1042."),
        _event(record=48320, event_id=4624, logged=stamp(minutes=20), computer="FAB-DC01.fabrikam.corp", account="sarah.chen", severity="info", category="Informational", summary="Successful interactive logon for sarah.chen."),
    ]
    state = {
        "version": VERSION,
        "domain": {
            "dns": "fabrikam.corp",
            "netbios": "FABRIKAM",
            "forest": "fabrikam.corp",
            "functional_level": "Windows Server 2016",
            "dc_os": "Windows Server 2022",
        },
        "policy": {
            "min_length": 8,
            "complexity": True,
            "history": 24,
            "max_age_days": 90,
            "min_age_days": 1,
            "lockout_threshold": 5,
            "lockout_minutes": 30,
            "observation_minutes": 30,
            "fgpp": [],
        },
        "sites": [
            {"name": "London-HQ", "subnet": "172.16.10.0/24", "location": "London"},
            {"name": "Manchester", "subnet": "172.16.20.0/24", "location": "Manchester"},
            {"name": "Singapore", "subnet": "172.16.30.0/24", "location": "Singapore"},
        ],
        "domain_controllers": [
            {"name": "FAB-DC01", "fqdn": "FAB-DC01.fabrikam.corp", "site": "London-HQ", "ip": "172.16.10.11", "os": "Windows Server 2022", "gc": True, "roles": ["PDC emulator", "RID master", "Schema master", "Domain naming master"], "replication": "Healthy"},
            {"name": "FAB-DC02", "fqdn": "FAB-DC02.fabrikam.corp", "site": "London-HQ", "ip": "172.16.10.12", "os": "Windows Server 2022", "gc": True, "roles": ["Infrastructure master"], "replication": "Healthy"},
            {"name": "FAB-DC03", "fqdn": "FAB-DC03.fabrikam.corp", "site": "Manchester", "ip": "172.16.20.11", "os": "Windows Server 2022", "gc": True, "roles": [], "replication": "Healthy"},
            {"name": "FAB-DC04", "fqdn": "FAB-DC04.fabrikam.corp", "site": "Singapore", "ip": "172.16.30.11", "os": "Windows Server 2022", "gc": True, "roles": [], "replication": "Failed"},
        ],
        "replication": [
            {"source": "FAB-DC01", "dest": "FAB-DC02", "site_link": "London-HQ", "minutes": 2, "schedule_minutes": 15, "status": "Healthy", "error": ""},
            {"source": "FAB-DC01", "dest": "FAB-DC03", "site_link": "London-Manchester", "minutes": 16, "schedule_minutes": 15, "status": "Healthy", "error": ""},
            {"source": "FAB-DC02", "dest": "FAB-DC04", "site_link": "London-Singapore", "minutes": 372, "schedule_minutes": 180, "status": "Failed", "error": "Event 1925 — DNS lookup failure for the replication partner GUID under _msdcs.fabrikam.corp."},
        ],
        "computers": [
            {"name": "FAB-FS01", "os": "Windows Server 2022", "site": "London-HQ", "last_logon_days": 1, "owner": "", "note": "File server. Healthy."},
            {"name": "FAB-SQL01", "os": "Windows Server 2022", "site": "London-HQ", "last_logon_days": 0, "owner": "svc-sql", "note": "Interactive logon by the SQL service account was recorded here."},
            {"name": "WKS-1042", "os": "Windows 11", "site": "London-HQ", "last_logon_days": 0, "owner": "priya.nair", "note": "Caller computer for Priya Nair's lockout. Check mapped drives and saved credentials."},
            {"name": "WKS-1880", "os": "Windows 10", "site": "Manchester", "last_logon_days": 190, "owner": "tom.bauer", "note": "Workstation has not contacted the domain. Disable the computer account if it was rebuilt."},
            {"name": "LAP-SARAH", "os": "Windows 11", "site": "London-HQ", "last_logon_days": 0, "owner": "sarah.chen", "note": "Healthy laptop."},
        ],
        "users": users,
        "events": sorted(events, key=lambda item: item["logged"], reverse=True),
        "audit": [],
        "scans": [],
        "published_alerts": [],
        "published_summary": {},
        "closed_incidents": [],
        "next_record": 48400,
        "connection": {
            "mode": "",
            "host": "",
            "port": 389,
            "use_ssl": False,
            "domain": "fabrikam.corp",
            "username": "",
        },
        "managed_servers": [],
    }
    _publish(state, "Scheduled task", "system")
    # The scheduled pass is the one already on the books this morning.
    state["scans"][0]["at"] = stamp(hours=5, minutes=20)
    state["scans"][0]["by"] = "Scheduled task"
    state["scans"][0]["role"] = "system"
    return state


def _publish(state: dict, actor: str, role: str) -> dict:
    result = scan(state)
    state["published_alerts"] = result["alerts"]
    state["published_summary"] = result["summary"]
    state["scans"].insert(
        0,
        {
            "at": now().isoformat(),
            "by": actor,
            "role": role,
            "alerts": result["summary"]["total"],
            "score": result["summary"]["score"],
            "band": result["summary"]["band"],
        },
    )
    return result


def _user_record(state: dict, sam: str) -> dict:
    for user in state["users"]:
        if user["sam"].lower() == sam.lower():
            return user
    raise KeyError(sam)


def _audit(state: dict, *, actor: str, role: str, action: str, target: str, result: str, detail: str) -> None:
    state["audit"].insert(
        0,
        {
            "at": now().isoformat(),
            "actor": actor,
            "role": role,
            "action": action,
            "target": target,
            "result": result,
            "detail": detail,
        },
    )


def _add_event(state: dict, **kwargs) -> None:
    state["next_record"] += 1
    event = _event(record=state["next_record"], logged=now().isoformat(), **kwargs)
    state["events"].insert(0, event)


class LabDirectory:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else DEFAULT_PATH
        self._lock = threading.Lock()
        self.state = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = {}
            if data.get("version") == VERSION and data.get("published_alerts"):
                data.setdefault("managed_servers", [])
                data.setdefault(
                    "connection",
                    {"mode": "", "host": "", "port": 389, "use_ssl": False, "domain": "fabrikam.corp", "username": ""},
                )
                return data
        data = fresh_state()
        self._write(data)
        return data

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def snapshot(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self.state))

    def publish(self, role: str) -> dict:
        actor = OPERATORS.get(role, {}).get("name", role)
        with self._lock:
            result = _publish(self.state, actor, role)
            _audit(self.state, actor=actor, role=role, action="Publish scan", target="fabrikam.corp", result="Allowed", detail=f"Score {result['summary']['score']}, {result['summary']['total']} findings.")
            self._write(self.state)
            return result

    def reset_lab(self) -> None:
        with self._lock:
            self.state = fresh_state()
            self._write(self.state)

    def _mutate(self, role: str, sam: str, action: str, reason: str, apply) -> str:
        actor = OPERATORS[role]["name"]
        reason = reason.strip()
        with self._lock:
            try:
                user = _user_record(self.state, sam)
            except KeyError as exc:
                raise Denied("That account is not in the lab directory.", "stale-accounts") from exc
            try:
                message = apply(user)
            except Denied as denied:
                _audit(self.state, actor=actor, role=role, action=action, target=sam, result="Denied", detail=denied.message)
                self._write(self.state)
                raise
            _audit(self.state, actor=actor, role=role, action=action, target=sam, result="Allowed", detail=f"{message} Reason: {reason}")
            self._write(self.state)
            return message

    def unlock(self, role: str, sam: str, reason: str) -> str:
        def apply(user: dict) -> str:
            blocked = role != "tier0" and (is_privileged(user) or user.get("service") or user.get("builtin"))
            assert_allowed(can_unlock(role, user), "tiered-administration" if blocked or role == "auditor" else "lockout")
            if len(reason.strip()) < 8:
                raise Denied("Enter a short reason (at least 8 characters) so the unlock has an audit trail.", "unlock-and-reset")
            user["locked"] = False
            user["bad_pwd_count"] = 0
            user["lockout_caller"] = ""
            _add_event(
                self.state,
                event_id=4767,
                computer="FAB-DC01.fabrikam.corp",
                account=user["sam"],
                severity="info",
                category="Account lockout",
                summary=f"{user['sam']} was unlocked by {OPERATORS[role]['name']}.",
            )
            return f"Unlocked {user['display']}."

        return self._mutate(role, sam, "Unlock account", reason, apply)

    def reset_password(self, role: str, sam: str, password: str, confirm: str, must_change: bool, reason: str) -> str:
        def apply(user: dict) -> str:
            guidance = "tiered-administration"
            if user["sam"] == "krbtgt":
                guidance = "krbtgt"
            assert_allowed(can_reset(role, user), guidance)
            if len(reason.strip()) < 8:
                raise Denied("Enter a short reason (at least 8 characters) so the reset has an audit trail.", "unlock-and-reset")
            errors = assess_password(password, confirm, user)
            if errors:
                raise Denied(" ".join(errors), "password-hygiene")
            user["password_age_days"] = 0
            user["password_expired"] = False
            user["must_change"] = bool(must_change) and not user["service"]
            user["locked"] = False
            user["bad_pwd_count"] = 0
            user["lockout_caller"] = ""
            _add_event(
                self.state,
                event_id=4724,
                computer="FAB-DC01.fabrikam.corp",
                account=user["sam"],
                severity="info",
                category="Password hygiene",
                summary=f"Password reset for {user['sam']} by {OPERATORS[role]['name']}. The new secret is not stored.",
            )
            follow = " They must change it at next sign-in." if user["must_change"] else ""
            return f"Reset the password for {user['display']}.{follow}"

        return self._mutate(role, sam, "Reset password", reason, apply)

    def disable(self, role: str, sam: str, reason: str) -> str:
        def apply(user: dict) -> str:
            assert_allowed(can_disable(role, user), "tiered-administration")
            if len(reason.strip()) < 8:
                raise Denied("Enter a short reason (at least 8 characters).", "builtin-administrator")
            user["enabled"] = False
            user["locked"] = False
            _add_event(
                self.state,
                event_id=4725,
                computer="FAB-DC01.fabrikam.corp",
                account=user["sam"],
                severity="info",
                category="Account hygiene",
                summary=f"{user['sam']} was disabled by {OPERATORS[role]['name']}.",
            )
            return f"Disabled {user['display']}."

        return self._mutate(role, sam, "Disable account", reason, apply)

    def remove_domain_admin(self, role: str, sam: str, reason: str) -> str:
        def apply(user: dict) -> str:
            assert_allowed(can_remove_domain_admin(role, user), "privileged-membership")
            if len(reason.strip()) < 8:
                raise Denied("Enter the change-ticket reason (at least 8 characters).", "privileged-membership")
            user["groups"] = [group for group in user["groups"] if group != "Domain Admins"]
            _add_event(
                self.state,
                event_id=4729,
                computer="FAB-DC01.fabrikam.corp",
                account=user["sam"],
                severity="info",
                category="Privilege assignment",
                summary=f"{OPERATORS[role]['name']} removed {user['sam']} from Domain Admins.",
            )
            return f"Removed {user['display']} from Domain Admins."

        return self._mutate(role, sam, "Remove Domain Admins", reason, apply)

    def add_protected_user(self, role: str, sam: str, reason: str) -> str:
        def apply(user: dict) -> str:
            assert_allowed(can_protect(role, user), "protected-users")
            if len(reason.strip()) < 8:
                raise Denied("Enter a short reason (at least 8 characters).", "protected-users")
            user["protected_users"] = True
            if "Protected Users" not in user["groups"]:
                user["groups"].append("Protected Users")
            _add_event(
                self.state,
                event_id=4728,
                computer="FAB-DC01.fabrikam.corp",
                account=user["sam"],
                severity="info",
                category="Privilege assignment",
                summary=f"{OPERATORS[role]['name']} added {user['sam']} to Protected Users.",
            )
            return f"Added {user['display']} to Protected Users."

        return self._mutate(role, sam, "Add Protected Users", reason, apply)

    def close_incident(self, role: str, incident_id: str, reason: str) -> str:
        actor = OPERATORS[role]["name"]
        with self._lock:
            try:
                assert_allowed(can_close_incident(role), "audit-integrity")
                if len(reason.strip()) < 8:
                    raise Denied("Record what you found, in at least 8 characters.", "audit-integrity")
                if incident_id in self.state["closed_incidents"]:
                    raise Denied("That incident is already closed.", "audit-integrity")
                self.state["closed_incidents"].append(incident_id)
                _audit(
                    self.state,
                    actor=actor,
                    role=role,
                    action="Close incident",
                    target=incident_id,
                    result="Allowed",
                    detail=reason.strip(),
                )
                self._write(self.state)
            except Denied as denied:
                _audit(self.state, actor=actor, role=role, action="Close incident", target=incident_id, result="Denied", detail=denied.message)
                self._write(self.state)
                raise
        return "Incident recorded as investigated. Publish a scan to clear it from the queue."

    def known_account(self, username: str) -> dict | None:
        needle = username.strip().lower()
        if "@" in needle:
            needle = needle.split("@", 1)[0]
        with self._lock:
            for user in self.state["users"]:
                if user["sam"].lower() == needle or user["upn"].lower() == username.strip().lower():
                    return json.loads(json.dumps(user))
        return None

    def remember_connection(self, profile: dict) -> None:
        """Store the directory target. The password is never part of this profile."""
        public = {
            "mode": profile.get("mode", ""),
            "host": profile.get("host", ""),
            "port": int(profile.get("port") or 389),
            "use_ssl": bool(profile.get("use_ssl")),
            "domain": profile.get("domain", ""),
            "username": profile.get("username", ""),
        }
        with self._lock:
            self.state["connection"] = public
            _audit(
                self.state,
                actor=public["username"] or "operator",
                role=profile.get("role", "helpdesk"),
                action="Directory sign-in",
                target=public["host"] or public["domain"],
                result="Allowed",
                detail=f"{public['mode']} session for {public['username']}. Password was not written to the lab file.",
            )
            self._write(self.state)

    def add_managed_server(self, server: dict) -> None:
        name = server["name"].strip()
        record = {
            "name": name,
            "role": server.get("role", "member-server"),
            "resolved": bool(server.get("resolved")),
            "address": server.get("address", ""),
            "ports": server.get("ports", {}),
            "note": server.get("note", ""),
        }
        with self._lock:
            self.state["managed_servers"] = [
                item for item in self.state.get("managed_servers", []) if item["name"].lower() != name.lower()
            ]
            self.state["managed_servers"].insert(0, record)
            self._write(self.state)
