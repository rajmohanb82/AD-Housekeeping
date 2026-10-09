"""Password rules and the lab role model.

Helpdesk, auditor, and Tier-0 are simulated session roles. They mirror how a
production console would authorize operators from AD groups, without granting
those rights on a real directory.
"""

from __future__ import annotations

PRIVILEGED_GROUPS = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
}

OPERATORS = {
    "auditor": {
        "name": "Mina Rahman",
        "title": "Directory Auditor",
        "group": "Fabrikam-ADHK-Auditors",
    },
    "helpdesk": {
        "name": "James Okonkwo",
        "title": "Helpdesk Operator",
        "group": "Fabrikam-ADHK-Helpdesk",
    },
    "tier0": {
        "name": "Olivia Grant",
        "title": "Tier-0 Administrator",
        "group": "Fabrikam-ADHK-Tier0",
    },
}

BANNED_PASSWORDS = {
    "password",
    "password1",
    "welcome1",
    "fabrikam",
    "fabrikam1",
    "changeme",
    "spring2026",
    "winter2026",
    "admin123",
    "qwertyuiop",
    "letmeinplease",
}


class Denied(Exception):
    def __init__(self, message: str, guidance: str = "tiered-administration"):
        super().__init__(message)
        self.message = message
        self.guidance = guidance


def is_privileged(user: dict) -> bool:
    if user.get("builtin") and user["sam"] in {"administrator", "krbtgt"}:
        return True
    return bool(PRIVILEGED_GROUPS.intersection(user.get("groups", [])))


def is_standing_admin(user: dict) -> bool:
    """Human accounts with standing Domain Admins membership."""
    return (
        user.get("enabled", False)
        and not user.get("service")
        and not user.get("builtin")
        and "Domain Admins" in user.get("groups", [])
    )


def account_flags(user: dict) -> list[dict]:
    flags: list[dict] = []
    if not user["enabled"]:
        flags.append({"label": "Disabled", "tone": "neutral"})
    if user["locked"]:
        flags.append({"label": "Locked", "tone": "bad"})
    if user["sam"] == "arjun.patel" and "Domain Admins" in user["groups"]:
        flags.append({"label": "Domain Admins", "tone": "bad"})
    elif is_privileged(user) and user["sam"] not in {"krbtgt"}:
        flags.append({"label": "Privileged", "tone": "warn"})
    if user["sam"] == "krbtgt":
        flags.append({"label": "krbtgt", "tone": "bad"})
    if user["sam"] == "guest" and user["enabled"]:
        flags.append({"label": "Should be disabled", "tone": "bad"})
    if user["password_expired"]:
        flags.append({"label": "Password expired", "tone": "warn"})
    if user["must_change"]:
        flags.append({"label": "Must change password", "tone": "info"})
    if user["password_never_expires"] and (user["service"] or user["sam"] == "krbtgt"):
        flags.append({"label": "Password never expires", "tone": "warn"})
    if user["last_logon_days"] is None and not user["builtin"] and user["enabled"]:
        flags.append({"label": "Never signed in", "tone": "warn"})
    elif (
        user["enabled"]
        and not user["builtin"]
        and user["last_logon_days"] is not None
        and user["last_logon_days"] > 90
    ):
        flags.append({"label": "Stale", "tone": "warn"})
    if user["protected_users"]:
        flags.append({"label": "Protected Users", "tone": "good"})
    if not flags:
        flags.append({"label": "Healthy", "tone": "good"})
    return flags


def _name_tokens(user: dict) -> set[str]:
    tokens = {user["sam"].lower()}
    for part in user["display"].replace(".", " ").split():
        if len(part) > 3:
            tokens.add(part.lower())
    return tokens


def assess_password(password: str, confirm: str, user: dict) -> list[str]:
    """Lab passphrase bar used by the reset utility.

    The domain policy in the simulation is still the legacy minimum of 8
    characters. Directory Keep asks operators for a longer passphrase anyway.
    """
    errors: list[str] = []
    if password != confirm:
        errors.append("The confirmation does not match.")
    if len(password) < 14:
        errors.append("Use at least 14 characters. A short password is rejected even though the domain minimum is still 8.")
    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1
    if classes < 3:
        errors.append("Use at least three of: lowercase, uppercase, a number, and a symbol.")
    lowered = password.lower()
    if any(token in lowered for token in _name_tokens(user)):
        errors.append("Do not include the account name or the person's name.")
    compact = "".join(ch for ch in lowered if ch.isalnum())
    if compact in BANNED_PASSWORDS or lowered in BANNED_PASSWORDS:
        errors.append("That password is on the lab banned list. Pick a passphrase that is not a common word plus a digit.")
    return errors


def _require_reason(reason: str) -> None:
    if len(reason.strip()) < 8:
        raise Denied("Enter a short reason (at least 8 characters) so the change has an audit trail.", "unlock-and-reset")


def can_unlock(role: str, user: dict) -> tuple[bool, str]:
    if not user["locked"]:
        return False, "This account is not locked."
    if role == "auditor":
        return False, "Directory Auditors can review lockouts. They cannot unlock accounts."
    if role == "helpdesk" and (is_privileged(user) or user["service"] or user["builtin"]):
        return False, "Helpdesk can unlock standard user accounts only. Privileged and service accounts stay with Tier-0."
    return True, ""


def can_reset(role: str, user: dict) -> tuple[bool, str]:
    if user["sam"] == "krbtgt":
        return False, "krbtgt is reset twice, with a full ticket lifetime between the two resets. It is not a helpdesk password change."
    if role == "auditor":
        return False, "Directory Auditors cannot reset passwords."
    if role == "helpdesk" and (is_privileged(user) or user["service"] or user["builtin"]):
        return False, "Helpdesk can reset standard user accounts only. Privileged, built-in, and service accounts stay with Tier-0."
    if not user["enabled"]:
        return False, "Disabled accounts are not reset from this console. Enablement is a separate Tier-0 decision."
    return True, ""


def can_disable(role: str, user: dict) -> tuple[bool, str]:
    if not user["enabled"]:
        return False, "This account is already disabled."
    if user["sam"] == "krbtgt":
        return False, "Do not disable krbtgt. The domain uses it for Kerberos."
    if role != "tier0":
        return False, "Only a Tier-0 administrator can disable accounts in this lab."
    return True, ""


def can_remove_domain_admin(role: str, user: dict) -> tuple[bool, str]:
    if "Domain Admins" not in user.get("groups", []):
        return False, "This account is not a member of Domain Admins."
    if role != "tier0":
        return False, "Removing Domain Admins membership is a Tier-0 change."
    return True, ""


def can_protect(role: str, user: dict) -> tuple[bool, str]:
    if "Domain Admins" not in user.get("groups", []):
        return False, "Protected Users is being demonstrated here for standing Domain Admins."
    if user.get("protected_users"):
        return False, "This account is already in Protected Users."
    if role != "tier0":
        return False, "Membership in Protected Users is a Tier-0 change, and it should be tested before it is applied broadly."
    return True, ""


def can_close_incident(role: str) -> tuple[bool, str]:
    if role != "tier0":
        return False, "Closing an audit incident is a Tier-0 acknowledgement, not a helpdesk action."
    return True, ""


def assert_allowed(check: tuple[bool, str], guidance: str) -> None:
    allowed, message = check
    if not allowed:
        raise Denied(message, guidance)
