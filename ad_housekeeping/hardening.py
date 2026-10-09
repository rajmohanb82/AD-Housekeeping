"""Windows Server hardening recommendations, tied to Microsoft baselines.

Findings are either observed from a port check on this workstation or taken
from the lab baseline. They are recommendations, not a claim that a setting
was read from the server's registry.
"""

from __future__ import annotations

CHECKS = [
    {
        "id": "smb-signing",
        "title": "Require SMB signing",
        "severity": "high",
        "summary": "Unsigned SMB lets a relay sit between a client and a file server. Domain controllers and member servers should require signing.",
        "action": "Set Microsoft network server: Digitally sign communications (always) and the matching client policy. Confirm no legacy appliance still needs unsigned SMB.",
        "doc_title": "SMB security enhancements",
        "doc_url": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security",
    },
    {
        "id": "smbv1",
        "title": "Remove SMBv1",
        "severity": "high",
        "summary": "SMBv1 is an old dialect with known weaknesses. Current Windows Server installs should not still be serving it.",
        "action": "Remove the SMB 1.0/CIFS feature and reboot in a change window. Watch for scanners, NAS devices, and old copiers.",
        "doc_title": "How to detect, enable and disable SMBv1",
        "doc_url": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
    },
    {
        "id": "ldap-channel",
        "title": "LDAP signing and channel binding",
        "severity": "high",
        "summary": "Domain controllers should refuse simple LDAP binds that are not signed or bound to the TLS channel.",
        "action": "Require LDAP signing and enable channel binding. Point management tools at LDAPS (636) before you enforce it.",
        "doc_title": "LDAP signing and channel binding",
        "doc_url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-ldap-signing-and-channel-binding",
    },
    {
        "id": "print-spooler",
        "title": "Stop the Print Spooler on domain controllers",
        "severity": "high",
        "summary": "A domain controller does not need to share printers. The spooler is a standing service that does not belong on a DC.",
        "action": "Disable the Print Spooler service on every domain controller and leave printing on a member server.",
        "doc_title": "Securing domain controllers",
        "doc_url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack",
    },
    {
        "id": "rdp-nla",
        "title": "Remote Desktop requires Network Level Authentication",
        "severity": "medium",
        "summary": "RDP without NLA presents a logon surface before the user is authenticated. Management access should also be limited to admin subnets.",
        "action": "Require NLA, restrict TCP 3389 to the management subnet, and prefer a privileged access workstation.",
        "doc_title": "Remote Desktop security",
        "doc_url": "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access",
    },
    {
        "id": "ldaps",
        "title": "Prefer LDAPS over clear LDAP",
        "severity": "medium",
        "summary": "Port 389 answers, and 636 does not. Binds and searches on clear LDAP can be read on the path.",
        "action": "Install a certificate on the domain controllers and move tools to port 636, then restrict 389 to signing-only clients.",
        "doc_title": "Enable LDAP over SSL",
        "doc_url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-over-ssl-3rd-party-certification-authority",
    },
    {
        "id": "firewall",
        "title": "Windows Firewall is on for every profile",
        "severity": "medium",
        "summary": "Domain, private, and public profiles should all keep the firewall enabled. A server is not hardened because it sits behind another firewall.",
        "action": "Turn the firewall on for all profiles and allow only the roles you intended: directory, file, RDP from management hosts.",
        "doc_title": "Windows Firewall with Advanced Security",
        "doc_url": "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/",
    },
    {
        "id": "llmnr",
        "title": "Turn off LLMNR and NetBIOS name resolution",
        "severity": "medium",
        "summary": "Broadcast name resolution is a common way for a poisoned answer to collect a credential. Domain servers should use DNS only.",
        "action": "Disable LLMNR with Group Policy and disable NetBIOS over TCP/IP on server adapters.",
        "doc_title": "Name resolution overview",
        "doc_url": "https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top",
    },
    {
        "id": "credential-guard",
        "title": "Credential Guard on management servers",
        "severity": "low",
        "summary": "Member servers that admins sign in to should isolate secrets where the hardware supports it.",
        "action": "Enable Credential Guard on Windows Server management hosts after a pilot. Domain controllers have their own protections; do not treat this as a substitute for tiering.",
        "doc_title": "Credential Guard",
        "doc_url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/",
    },
]

_BY_ID = {item["id"]: item for item in CHECKS}

# Lab story: a few controls are already wrong, so the page is worth opening.
_LAB = {
    "FAB-DC01": {"print-spooler": "fail", "ldap-channel": "fail", "smb-signing": "pass", "smbv1": "pass"},
    "FAB-DC02": {"print-spooler": "fail", "ldap-channel": "fail", "smb-signing": "pass", "smbv1": "pass"},
    "FAB-DC03": {"print-spooler": "pass", "ldap-channel": "fail", "smb-signing": "pass", "smbv1": "pass"},
    "FAB-DC04": {"print-spooler": "fail", "ldap-channel": "fail", "smb-signing": "fail", "smbv1": "pass"},
    "FAB-SQL01": {"smbv1": "fail", "rdp-nla": "fail", "smb-signing": "fail", "llmnr": "fail"},
    "FAB-FS01": {"smb-signing": "pass", "smbv1": "pass", "rdp-nla": "fail", "firewall": "pass"},
}


def _row(server: str, role: str, check_id: str, status: str, source: str) -> dict:
    check = _BY_ID[check_id]
    return {
        "server": server,
        "role": role,
        "status": status,
        "source": source,
        **check,
    }


def lab_baseline() -> list[dict]:
    rows = []
    roles = {
        "FAB-DC01": "domain-controller",
        "FAB-DC02": "domain-controller",
        "FAB-DC03": "domain-controller",
        "FAB-DC04": "domain-controller",
        "FAB-SQL01": "member-server",
        "FAB-FS01": "member-server",
    }
    for name, flags in _LAB.items():
        for check_id, status in flags.items():
            rows.append(_row(name, roles[name], check_id, status, "Lab baseline"))
    return rows


def assess_added(name: str, role: str, ports: dict, resolved: bool) -> list[dict]:
    rows = []
    open_3389 = bool(ports.get("3389") or ports.get(3389))
    open_389 = bool(ports.get("389") or ports.get(389))
    open_636 = bool(ports.get("636") or ports.get(636))
    if role == "domain-controller":
        rows.append(_row(name, role, "print-spooler", "review", "Role baseline"))
        rows.append(_row(name, role, "ldap-channel", "review", "Role baseline"))
    rows.append(_row(name, role, "smb-signing", "review", "Role baseline"))
    rows.append(_row(name, role, "smbv1", "review", "Role baseline"))
    rows.append(_row(name, role, "firewall", "review", "Role baseline"))
    if open_3389:
        rows.append(_row(name, role, "rdp-nla", "fail", "Port 3389 answered"))
    if open_389 and not open_636:
        rows.append(_row(name, role, "ldaps", "fail", "Port 389 answered, 636 did not"))
    if not resolved:
        rows.append(
            {
                "id": "resolve",
                "server": name,
                "role": role,
                "status": "review",
                "source": "Name lookup",
                "severity": "medium",
                "title": "This workstation could not resolve the hostname",
                "summary": f"{name} did not resolve from the console. The hardening list is still the role baseline. Run the scan from a host that can see the server's DNS.",
                "action": "Confirm the name in the domain DNS zone, then scan again from a subnet that can reach it.",
                "doc_title": "DNS troubleshooting",
                "doc_url": "https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top",
            }
        )
    return rows


def all_findings(state: dict) -> list[dict]:
    rows = lab_baseline()
    for server in state.get("managed_servers", []):
        rows.extend(
            assess_added(
                server["name"],
                server.get("role", "member-server"),
                server.get("ports") or {},
                bool(server.get("resolved")),
            )
        )
    order = {"fail": 0, "review": 1, "pass": 2}
    rows.sort(key=lambda item: (order.get(item["status"], 9), item["severity"], item["server"]))
    return rows
