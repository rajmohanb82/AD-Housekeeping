# Interview demo

Ten minutes. Stay in the browser. Have the overview open before they sit down: [http://127.0.0.1:8765](http://127.0.0.1:8765).

If you have already clicked around, use **Reset lab data** in the sidebar so the morning snapshot is back. Health should read **40 — Action required**.

Say this once, at the start, and do not apologise for it:

> This is Directory Keep, a housekeeping console for a fictional fabrikam.corp. The directory is a lab, so I can show the operating model without writing to a real domain. The recommendations link out to Microsoft Learn.

## 0:00 — Overview

Point at the score, then the sentence under the title. It should say that critical findings need a Tier-0 review before helpdesk treats the lockouts as ordinary.

Name the three critical rows without opening them yet:

- Arjun Patel, an intern, is in Domain Admins.
- The Security log on FAB-DC02 was cleared.
- krbtgt has not been rotated on Microsoft’s two-reset procedure.

Gesture at the four domain controllers. FAB-DC04 is the one with the fault.

## 1:30 — Publish a scan

Open **Housekeeping scan**. Say what the pass actually reads: Security, Directory Service, accounts, privileged groups, replication, then a Learn article on every finding.

Click **Publish scan**. The checklist is the ceremony. The queue at the end is the product.

Then open **Security events** and search `sarah.chen`. Her 4624 is a successful sign-in. It is in the log and it is not an alert. That is the categorization.

## 3:30 — One critical alert

Open **Intern account is a member of Domain Admins**.

Walk the page in this order:

1. Evidence: event 4728, Helena Voss added him, he still lives in the people OU.
2. Why it matters: permanent membership in Domain Admins is the finding, not the fact that a group changed.
3. Microsoft documentation: securing Active Directory, least-privilege administration, and the 4728 article. Click one link so they see it leave the app.
4. The production command is `Remove-ADGroupMember`. Say you will do the lab equivalent in a minute, from Tier-0, not from helpdesk.

## 5:00 — Infrastructure

Open **Infrastructure**. Three sites. Every DC is a global catalog. Say the single-domain sentence out loud: in a single-domain forest the infrastructure master may sit on a global catalog, so that placement is not a defect here.

Then the replication table. London to Manchester is healthy. London to Singapore last succeeded **372 minutes** ago against a **180 minute** schedule, and event **1925** says DNS lookup failure. Do not call it a slow link.

If they ask what you would run: `repadmin /showrepl FAB-DC04` and `dcdiag /test:dns /s:FAB-DC04`. The console does not pretend a button fixes DNS.

## 6:30 — Helpdesk utility

Confirm the header says **Helpdesk** (James Okonkwo).

Open **Accounts**, filter **Locked**, open **Priya Nair**.

- Caller is WKS-1042.
- 4771 then 4740.
- The recommendation is to clear the stale credential on that PC, then unlock.

Unlock her. Reason you can type: `Cleared saved credentials on WKS-1042`.

A banner appears: the directory changed, publish again to refresh the queue. The account itself is already unlocked. That split is deliberate. The queue is scan-based. The directory view is live.

Now open **Helena Voss** and try a reset. The form is not offered. Helpdesk does not reset Domain Admins. If you want the refusal in the journal, the same rule fires on submit from any other path.

## 8:00 — Tier-0

Switch the role to **Tier-0** (Olivia Grant). Open **Arjun Patel**. Remove him from Domain Admins. Reason: `No ticket for the 4728 add`.

Go back to **Housekeeping scan**, publish, and open the queue. The intern finding is gone. The score is higher than 40. krbtgt is still there. Say why you will not one-click it: Microsoft’s forest-recovery procedure is two resets, with a wait longer than the ticket lifetime, and Singapore is already failing replication.

If you have a spare minute, disable **Guest** the same way. It is the cleanest Account hygiene item on the page.

## 9:30 — How it would be deployed

Open **Tomcat deployment**.

The picture is a Tier-1 member server, not a domain controller:

- Apache Tomcat 10.1 serves the `/ad-housekeeping` front door.
- The Python console listens on `127.0.0.1:8765`.
- The service account is the gMSA `svc-adhk$`.
- Delegation is reset and unlock on `OU=People` only.
- The installer prints those `dsacls` commands and does not run them.

Preflight on this laptop shows Python as healthy and domain join as not joined. Say that is the correct result for a demo machine.

## If they ask

**Does this talk to Active Directory?**
Not in the lab. `LabDirectory` is the seam. A production build replaces it with LDAP or ADWS. The scanner, the role checks, and the pages stay.

**Why can helpdesk not reset a Domain Admin?**
The console is Tier-1. Microsoft’s privileged-access model keeps directory control on a privileged workstation. Putting Domain Admin on the Tomcat service account would undo the product.

**Why is the password policy both enforced and flagged?**
The domain still has an 8-character, 90-day policy, so expired accounts are real helpdesk work. Current Microsoft guidance prefers longer passwords, a banned list, and less forced rotation for ordinary users. Both facts are on screen: the reset utility asks for 14 characters, and the Group Policy finding asks for a fine-grained policy plus Entra Password Protection in audit mode.

**What about krbtgt?**
Reset twice. Wait 10 hours, or longer if the ticket lifetime was changed. Do not do it while replication to Singapore is broken. The page links to the forest-recovery article.

**Where is the password stored?**
It is not. The lab records that a reset happened (event 4724) and drops the secret. You can say the tests assert the passphrase never lands in the state file.
