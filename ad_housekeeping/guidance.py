"""Recommendations written for this lab, each linked to Microsoft Learn.

The wording here is original. The links point at Microsoft's own documentation
and support articles so an operator can read the source, not a paraphrase.
"""

from __future__ import annotations

CATEGORIES = [
    "Privilege assignment",
    "Audit integrity",
    "Credential hygiene",
    "Account hygiene",
    "Account lockout",
    "Replication",
    "Password hygiene",
    "Stale identity",
    "Group Policy",
]

EVENT_DOCS = {
    1102: {
        "title": "1102(S): The audit log was cleared",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102",
    },
    4624: {
        "title": "4624(S): An account was successfully logged on",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624",
    },
    4625: {
        "title": "4625(F): An account failed to log on",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625",
    },
    4672: {
        "title": "4672(S): Special privileges assigned to new logon",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672",
    },
    4719: {
        "title": "4719(S): System audit policy was changed",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719",
    },
    4724: {
        "title": "4724(S): An attempt was made to reset an account's password",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724",
    },
    4725: {
        "title": "4725(S): A user account was disabled",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4725",
    },
    4728: {
        "title": "4728(S): A member was added to a security-enabled global group",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4728",
    },
    4729: {
        "title": "4729(S): A member was removed from a security-enabled global group",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4729",
    },
    4740: {
        "title": "4740(S): A user account was locked out",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740",
    },
    4767: {
        "title": "4767(S): A user account was unlocked",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4767",
    },
    4768: {
        "title": "4768(S): A Kerberos authentication ticket (TGT) was requested",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768",
    },
    4771: {
        "title": "4771(F): Kerberos pre-authentication failed",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771",
    },
    1925: {
        "title": "Directory Service event 1925: replication link failed",
        "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/active-directory-replication-event-id-1925",
    },
    5136: {
        "title": "5136(S): A directory service object was modified",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136",
    },
}


ARTICLES: dict[str, dict] = {
    "privileged-membership": {
        "title": "Standing membership in Domain Admins",
        "category": "Privilege assignment",
        "summary": "Highly privileged groups should be empty most of the time. Permanent membership is a standing target, and an intern account in Domain Admins is a directory defect, not a convenience.",
        "why": "Microsoft's securing-Active-Directory guidance treats elimination of permanent membership in highly privileged groups as a tactical, preventative control. Group changes such as event 4728 are detective controls: they tell you the membership changed, they do not make the membership safe.",
        "actions": [
            "Confirm the change ticket for the 4728 event. If there is no ticket, remove the member.",
            "Keep day-to-day administration off Domain Admins. Use a separate privileged account that is not the person's email identity.",
            "Grant temporary membership only for the task, then remove it. Do not leave the intern account nested in the group.",
            "Alert on 4728, 4729, and 4732 for Domain Admins, Enterprise Admins, Schema Admins, and Administrators.",
        ],
        "docs": [
            {
                "title": "Best practices for securing Active Directory",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
            },
            {
                "title": "Implementing least-privilege administrative models",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
            },
            {
                "title": "4728(S): A member was added to a security-enabled global group",
                "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4728",
            },
        ],
        "support": "If you cannot tell which console made the change, collect the 4728 event from every domain controller and the Directory Service log. Microsoft support will want the subject account, the member, and whether the log was forwarded off the DC before anyone cleared it.",
        "commands": [
            'Remove-ADGroupMember -Identity "Domain Admins" -Members arjun.patel -Confirm:$false'
        ],
    },
    "audit-integrity": {
        "title": "Cleared security log and audit-policy drift",
        "category": "Audit integrity",
        "summary": "A cleared Security log on a domain controller is a critical housekeeping and security event. Pair it with any 4719 audit-policy change on the same server before you treat the morning as routine.",
        "why": "Event 1102 means the audit log was cleared. Once it is gone from that server, you only have copies that were forwarded elsewhere. Microsoft's audit-policy guidance also says to watch privileged accounts and to collect logs from workstations and servers, not from domain controllers alone.",
        "actions": [
            "Treat 1102 on a domain controller as an incident until the operator and the change ticket are confirmed.",
            "Compare the current advanced audit policy with the last known baseline, because a 4719 landed on the same DC in the same window.",
            "Confirm logs are forwarded off the domain controllers. A local log must not be the only copy.",
            "Review who can clear logs. That right should be rare and alerted.",
        ],
        "docs": [
            {
                "title": "1102(S): The audit log was cleared",
                "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102",
            },
            {
                "title": "System audit policy recommendations",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
            },
            {
                "title": "Advanced security audit policy settings",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration",
            },
        ],
        "support": "Open a support request if you cannot attribute the clear. Include the 1102 and 4719 events, the DC name, and a note on whether a SIEM still has the earlier log. Closing the item in Directory Keep only records your investigation. It does not restore the log.",
        "commands": [],
    },
    "krbtgt": {
        "title": "krbtgt password is past a safe rotation",
        "category": "Credential hygiene",
        "summary": "The krbtgt account password is the key material behind Kerberos tickets. Microsoft's forest-recovery procedure resets it twice, with a wait between the resets. It is not a single helpdesk reset.",
        "why": "The password history on krbtgt keeps the two most recent passwords. One reset leaves the previous key able to authenticate. A second reset, after tickets issued under the old key have expired, retires that key. The default wait is 10 hours because that is the default maximum lifetime for user and service tickets. If you have lengthened those lifetimes, wait longer than the configured value.",
        "actions": [
            "Confirm healthy replication before either reset. A krbtgt reset during a replication outage splits the domain.",
            "Reset the password once. The value you type is not the real secret: the domain controller generates a strong password.",
            "Wait longer than the maximum ticket lifetime (10 hours by default), then reset it a second time.",
            "Do not delete RODC krbtgt accounts (krbtgt_number) as part of a normal rotation.",
            "Use a Tier-0 workstation for the change, and write both times in the change ticket.",
        ],
        "docs": [
            {
                "title": "AD Forest Recovery — reset the krbtgt password",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password",
            },
            {
                "title": "Active Directory forest recovery guide",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide",
            },
        ],
        "support": "If a custom password filter blocks the reset, Microsoft documents that failure under KB 2549833, which the forest-recovery article points to. Do not keep retrying from a helpdesk tool.",
        "commands": [
            "# Active Directory Users and Computers, Advanced Features, Users, krbtgt, Reset Password.",
            "# Repeat once more after the ticket lifetime has elapsed. Do not script this as a single click.",
        ],
    },
    "guest-account": {
        "title": "Built-in Guest is enabled",
        "category": "Account hygiene",
        "summary": "The built-in Guest account should stay disabled. An enabled Guest is an anonymous door into the domain and it shows up in every serious AD review.",
        "why": "Securing Active Directory starts with the built-in identities. Guest is not an account you turn on for contractors. Contractors get a named, expiring account in the correct OU.",
        "actions": [
            "Disable Guest and leave it disabled.",
            "Confirm no one mapped a share or a kiosk to the Guest identity before you disable it.",
            "Give any real visitor a named account with an expiry, in an OU helpdesk can see.",
        ],
        "docs": [
            {
                "title": "Best practices for securing Active Directory",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
            }
        ],
        "support": "Disabling Guest does not require a support case. If an application breaks, that application is depending on an identity Microsoft expects you to keep disabled. Capture the calling computer and give it a named account.",
        "commands": ["Disable-ADAccount -Identity guest"],
    },
    "builtin-administrator": {
        "title": "Built-in Administrator is enabled for daily use",
        "category": "Account hygiene",
        "summary": "The built-in Administrator account should not be the account people use to administer the domain. Keep a separate break-glass account, monitor it, and prefer named Tier-0 accounts for ordinary admin work.",
        "why": "Microsoft recommends monitoring the built-in Administrator for enablement and for changes, and reducing who can modify privileged accounts. A shared, enabled Administrator password cannot be attributed to a person in the audit log.",
        "actions": [
            "Confirm Olivia Grant and Helena Voss are the named Tier-0 accounts, with passwords you can attribute.",
            "Disable the built-in Administrator, or move it to a break-glass process that is disabled until it is needed.",
            "Alert if the account is enabled or if its password is reset.",
        ],
        "docs": [
            {
                "title": "Audit policy recommendations — privileged and built-in accounts",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
            },
            {
                "title": "Best practices for securing Active Directory",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
            },
        ],
        "support": "No support case is required to disable a built-in Administrator you have already replaced with named admin accounts. If you are unsure you have another Enterprise Admin left, do not disable it until you have verified a second path in.",
        "commands": ["Disable-ADAccount -Identity administrator"],
    },
    "replication": {
        "title": "Replication failing between London and Singapore",
        "category": "Replication",
        "summary": "FAB-DC04 has not completed inbound replication from FAB-DC02 for far longer than the site-link schedule, and Directory Service event 1925 reports a DNS lookup failure. That is an outage, not a slow link.",
        "why": "Microsoft's replication troubleshooting guide tells you to start with the Directory Service log and with repadmin /showrepl. Event 1925 with a DNS-shaped failure means the destination could not resolve its partner's GUID CNAME under _msdcs. Lockouts and password changes will also look random while this link is down, because the PDC emulator and the Singapore DC disagree.",
        "actions": [
            "On FAB-DC04, resolve the CNAME <DSA-GUID>._msdcs.fabrikam.corp and confirm the _ldap._tcp records for the London site.",
            "Run repadmin /showrepl and repadmin /replsummary from FAB-DC04 and from FAB-DC02. Fix the error the command prints before you force a sync.",
            "Do not treat the 180-minute London–Singapore schedule as the fault. The last success is measured in hours, and 1925 names DNS.",
            "After DNS is healthy, let the link catch up and then re-check the lockout cases. Some of them may be stale credentials plus stale replication.",
        ],
        "docs": [
            {
                "title": "Troubleshooting Active Directory replication problems",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/troubleshoot/troubleshooting-active-directory-replication-problems",
            },
            {
                "title": "Active Directory replication event ID 1925",
                "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/active-directory-replication-event-id-1925",
            },
        ],
        "support": "If the GUID CNAME is missing and DNS scavenging or a stale zone is involved, open a support case with the output of repadmin /showrepl, dcdiag /test:dns, and the 1925 event. Do not demote FAB-DC04 to 'make the error go away' while it still holds a live copy of the directory.",
        "commands": [
            "repadmin /showrepl FAB-DC04",
            "repadmin /replsummary",
            "dcdiag /test:dns /s:FAB-DC04",
        ],
    },
    "lockout": {
        "title": "Account lockout investigation",
        "category": "Account lockout",
        "summary": "A lockout means the bad-password count reached the domain threshold. Unlocking is the last step, after you know which computer is still presenting the old password.",
        "why": "Event 4740 is written on the domain controller that locked the account and is associated with the PDC emulator. Microsoft recommends correlating it with 4625, 4771, and 4776. A blank caller computer name often means the attempts are not from a domain-joined Windows session: a phone, a personal device, or a non-domain appliance. Mapped drives, scheduled tasks, services, and saved credentials are the usual domain-joined causes.",
        "actions": [
            "Read 4740 for the caller computer. If the caller is blank, read 4771 and 4776 on the PDC emulator for the client name or IP.",
            "On the caller workstation, clear Credential Manager, reconnect mapped drives, and check scheduled tasks and services that use the user's password.",
            "Ask the user about a phone or personal device that still has the old password, especially just after a password change.",
            "Unlock only after the stale credential is gone. Unlocking first produces the same 4740 an hour later.",
            "While FAB-DC04 is failing replication, confirm you are looking at the PDC emulator's view of the lockout and not a stale copy.",
        ],
        "docs": [
            {
                "title": "4740(S): A user account was locked out",
                "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740",
            },
            {
                "title": "4625(F): An account failed to log on",
                "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625",
            },
            {
                "title": "4771(F): Kerberos pre-authentication failed",
                "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771",
            },
        ],
        "support": "Microsoft's account-lockout troubleshooting notes persistent drives, saved passwords, and replication as the first things to rule out. If the caller stays blank after 4771 and 4776, collect those events plus a LockoutStatus view across the DCs before you open a support case. Do not raise the lockout threshold to hide the symptom.",
        "commands": [
            "Unlock-ADAccount -Identity priya.nair",
        ],
    },
    "service-accounts": {
        "title": "User-style service accounts",
        "category": "Credential hygiene",
        "summary": "svc-sql and svc-backup are ordinary user accounts with passwords that never expire. svc-sql has also signed on interactively. Microsoft recommends group managed service accounts for services that support them.",
        "why": "A gMSA gets a long random password rotated by Active Directory, by default every 30 days, without an operator putting that password in a script. A user account with 'password never expires' becomes a permanent credential, and an interactive logon (4624 logon type 2) plus special privileges (4672) means the service identity is being used like a person.",
        "actions": [
            "Move SQL and backup to a gMSA where the service supports it. Restrict that gMSA to the hosts that need it.",
            "Until then, rotate the password, store it in a vault, and turn off interactive logon for the account.",
            "Remove service accounts from Backup Operators and any other privileged group if a narrower right will do.",
            "Alert on interactive logons for every account in the Service Accounts OU.",
        ],
        "docs": [
            {
                "title": "Secure group managed service accounts",
                "url": "https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed",
            },
            {
                "title": "Group Managed Service Accounts overview",
                "url": "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview",
            },
            {
                "title": "4672(S): Special privileges assigned to new logon",
                "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672",
            },
        ],
        "support": "If a vendor service cannot run as a gMSA, record that as a product limit and keep the user account's password in a vault with a rotation date. That is an application conversation, not a lockout-threshold conversation.",
        "commands": [
            "# Prefer a gMSA. A password reset of svc-sql is only a bridge.",
            "Set-ADAccountPassword -Identity svc-sql -Reset -NewPassword (Read-Host -AsSecureString)",
        ],
    },
    "stale-accounts": {
        "title": "Stale users and stale computers",
        "category": "Stale identity",
        "summary": "Enabled accounts that have not signed on in months, and computers that have not contacted the domain, are unused doors. Disable them, then delete them on a schedule after the owner confirms.",
        "why": "Least-privilege administration includes removing access that no longer has an owner. A stale user keeps every group they ever had. A stale computer account can be reused if someone can reset its password. New accounts that never signed on are often leftover starters or duplicated hires.",
        "actions": [
            "Disable the account and remove it from any group that is not Domain Users.",
            "Confirm with the manager before you delete. A mailbox or a home drive may still be the reason it exists.",
            "For a computer that has not logged on, disjoin or disable the object and watch for a helpdesk ticket. Silence usually means it was rebuilt without a cleanup.",
            "Do this from the people OU and the computers OU on a monthly housekeeping pass, which is what this scan is for.",
        ],
        "docs": [
            {
                "title": "Implementing least-privilege administrative models",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
            },
            {
                "title": "Best practices for securing Active Directory",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
            },
        ],
        "support": "Stale-account cleanup does not need Microsoft support. If a disabled account turns out to be a service, you will hear about it from the application owner the same day. That is the signal to convert it to a gMSA rather than to re-enable and forget.",
        "commands": ["Disable-ADAccount -Identity tom.bauer"],
    },
    "password-hygiene": {
        "title": "Expired and aging passwords",
        "category": "Password hygiene",
        "summary": "The domain still expires passwords at 90 days. An expired standard account is a helpdesk reset. An aging privileged password is a Tier-0 problem. Those are different queues.",
        "why": "Microsoft's current password guidance has moved away from forced periodic resets for ordinary users, and toward longer passwords plus a banned-password list. Privileged credentials are still special: they should be unique, long, and changed when people leave or when the credential is exposed. Directory Keep keeps the helpdesk reset for expired standard accounts because that is the live domain policy, and it files a separate finding on the policy itself.",
        "actions": [
            "Reset a standard expired account, require a change at next sign-in, and do not set the password to the user's name.",
            "Do not reset a Domain Admin password from the helpdesk queue.",
            "After the reset, expect a lockout if a phone or a mapped drive still has the old password. Follow the lockout article if 4740 returns.",
        ],
        "docs": [
            {
                "title": "Password technical overview",
                "url": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview",
            },
            {
                "title": "Set-ADAccountPassword",
                "url": "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword",
            },
        ],
        "support": "A single expired password is operational work. A wave of expirations after a policy change is a communication problem. Involve support only if accounts with a recent password are being treated as expired, which points at replication or at a fine-grained policy you did not know was linked.",
        "commands": [
            "Set-ADAccountPassword -Identity liam.wright -Reset -NewPassword (Read-Host -AsSecureString)",
            "Set-ADUser -Identity liam.wright -ChangePasswordAtLogon $true",
        ],
    },
    "protected-users": {
        "title": "Standing admins are not Protected Users",
        "category": "Privilege assignment",
        "summary": "Protected Users applies non-negotiable credential protections: AES Kerberos only, no NTLM, and a four-hour ticket lifetime. None of the standing human admins are in the group.",
        "why": "Microsoft is explicit that you should test first. The account needs an AES key, which means the password was set on Windows Server 2008 or later. Adding every Domain Admin in one change can lock the admins out of the tools they use. The group is still the right destination for high-value admin accounts after that test.",
        "actions": [
            "Reset the admin password if it has not been set on a current domain controller, so an AES key exists.",
            "Add one named Tier-0 account, such as Olivia Grant, and confirm she can still do her work.",
            "Then add the remaining standing admins. Do not add service accounts, and do not add krbtgt.",
            "Keep the four-hour ticket lifetime in mind when you schedule long admin sessions.",
        ],
        "docs": [
            {
                "title": "Protected Users security group",
                "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group",
            },
            {
                "title": "How to configure protected accounts",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts",
            },
        ],
        "support": "If an admin can no longer sign on after joining Protected Users, it is usually NTLM-only tooling or a missing AES key. Microsoft's configuration article covers both. Remove the account from the group to recover access, then fix the client before you add them again.",
        "commands": [
            'Add-ADGroupMember -Identity "Protected Users" -Members olivia.grant'
        ],
    },
    "password-policy": {
        "title": "Legacy domain password policy",
        "category": "Group Policy",
        "summary": "fabrikam.corp still requires 8 characters, complexity, and a 90-day maximum age. There is no fine-grained password policy for privileged or service accounts. A directory change to the policy was logged with event 5136.",
        "why": "Fine-grained password policies, available well before this domain's 2016 functional level, let you give privileged accounts a stricter policy without making every salesperson live with it. Separately, Microsoft Entra Password Protection can ban common passwords for on-premises resets. Deploy that in audit mode first. Forced rotation of ordinary user passwords is no longer the control Microsoft leads with.",
        "actions": [
            "Read the 5136 event and confirm the policy edit was yours.",
            "Create a Password Settings Object for a privileged group, with a longer minimum, and leave ordinary users on a simpler policy.",
            "Plan Microsoft Entra Password Protection in audit mode on the domain controllers before you enforce it.",
            "Raise the domain minimum length when you are ready to retire the 8-character setting. Directory Keep already refuses helpdesk resets shorter than 14 characters.",
        ],
        "docs": [
            {
                "title": "Fine-grained password policies",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies",
            },
            {
                "title": "Deploy on-premises Microsoft Entra Password Protection",
                "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy",
            },
            {
                "title": "5136(S): A directory service object was modified",
                "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136",
            },
        ],
        "support": "A fine-grained policy requires a domain functional level of Windows Server 2012 or higher, which this forest meets. If a password set is rejected after you enforce a banned list, that is the feature working. Use audit-mode events to tune the list before you call support.",
        "commands": [],
    },
    "tiered-administration": {
        "title": "Tier-0 work does not belong on the helpdesk console",
        "category": "Privilege assignment",
        "summary": "Directory Keep is a Tier-1 management application. Helpdesk can unlock and reset people. Domain Admins, krbtgt, service accounts, and audit incidents stay with a Tier-0 operator on a privileged workstation.",
        "why": "Microsoft's privileged-access model separates control of the directory (Tier-0) from control of enterprise servers (Tier-1) and from user workstations (Tier-2). A Tomcat server that helpdesk can sign in to is the wrong place to hold Domain Admin rights. The lab enforces that split in the role switcher so the demo matches the operating model.",
        "actions": [
            "Run this application as a group managed service account that can reset passwords only on the people OU.",
            "Do not put that service account in Domain Admins.",
            "Perform Tier-0 changes from a privileged access workstation, then let the next scan show the result.",
            "Keep auditors in a read-only group.",
        ],
        "docs": [
            {
                "title": "Privileged access model",
                "url": "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model",
            },
            {
                "title": "Implementing least-privilege administrative models",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
            },
            {
                "title": "Management accounts for protected accounts and groups",
                "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/appendix-i--creating-management-accounts-for-protected-accounts-and-groups-in-active-directory",
            },
        ],
        "support": "This is a design choice, not a product fault. If a helpdesk tool you already own uses a Domain Admin service account, plan to replace that delegation with OU-scoped reset and unlock rights. Microsoft support will not recommend putting a web server in Domain Admins to make delegation easier.",
        "commands": [],
    },
    "unlock-and-reset": {
        "title": "Unlock and reset, done in the right order",
        "category": "Account lockout",
        "summary": "Helpdesk unlocks a standard account and resets a standard password. The lab writes the same kind of audit events a domain controller would: 4767 for an unlock, 4724 for a reset.",
        "why": "Unlock-ADAccount clears the lockout. It does not find the caller. Set-ADAccountPassword -Reset is the admin reset, and ChangePasswordAtLogon forces the person to pick their own secret afterwards. Both actions should carry a reason. Directory Keep refuses to store the new password in the journal.",
        "actions": [
            "Identify the caller from 4740 or 4771 before you unlock.",
            "Reset the password only if it is expired, forgotten, or suspected of exposure.",
            "Require a change at next sign-in for a person. Do not do that blindly for a service account that has no one to type the new password.",
            "If the role switcher refuses, you are on the wrong tier. Do not share a Tier-0 session to get around it.",
        ],
        "docs": [
            {
                "title": "Unlock-ADAccount",
                "url": "https://learn.microsoft.com/en-us/powershell/module/activedirectory/unlock-adaccount",
            },
            {
                "title": "Set-ADAccountPassword",
                "url": "https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword",
            },
            {
                "title": "4767(S): A user account was unlocked",
                "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4767",
            },
        ],
        "support": "If the account locks again within minutes, go back to the lockout article. A second unlock is not a different fix.",
        "commands": [
            "Unlock-ADAccount -Identity priya.nair",
            "Set-ADAccountPassword -Identity liam.wright -Reset -NewPassword (Read-Host -AsSecureString)",
            "Set-ADUser -Identity liam.wright -ChangePasswordAtLogon $true",
        ],
    },
}


def article(slug: str) -> dict | None:
    item = ARTICLES.get(slug)
    if not item:
        return None
    return {"slug": slug, **item}
