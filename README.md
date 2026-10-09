# Directory Keep

An Active Directory housekeeping console for interviews and lab work. It scans a directory, sorts what it finds, recommends the Microsoft article that fits, and prints a report. A setup wizard collects the domain controller, the username, and the password, then authenticates the scan. The password stays in process memory. It is not written to a text file.

## Open it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m ad_housekeeping
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). Start with **Setup wizard**.

| | |
| --- | --- |
| Lab target | `172.16.10.11` · `fabrikam.corp` |
| Lab account | `james.okonkwo` |
| Password | Any passphrase of 8 or more characters. It is not stored. |
| Fresh lab score | **40 — Action required**, 17 findings |

## What is on the menu

| | Page | What you do there |
| --- | --- | --- |
| 🔑 | Setup wizard | Domain controller IP or hostname, DNS domain, username, password. Choose the Fabrikam lab or a live LDAP bind. |
| 🗂️ | Overview | Health score, categories, and the three critical items. |
| 🔍 | Housekeeping scan | Runs only after sign-in. Security log, directory log, accounts, privilege, replication. |
| 🔔 | Alerts | Each finding has evidence, what to do, a Learn link, and a support note. |
| 📋 | Security events | The full log, including ordinary sign-ins that are not alerts. |
| 👥 | Accounts | Unlock and reset standard people. Domain Admins stay with Tier-0. |
| 🌐 | Infrastructure | Sites, FSMO roles, and the Singapore replication fault. |
| 🖥️ | Windows servers | Add any Windows Server by hostname, not only domain controllers. |
| 🛡️ | Hardening | SMB signing, SMBv1, LDAP channel binding, spooler on DCs, RDP, firewall. |
| 📄 | Reports | On-screen report and a PDF download. The password is left out. |
| 📖 | Microsoft guidance | The recommendation library behind the queue. |
| 📦 | Tomcat deployment | Apache Tomcat 10.1 front door for a member server. |

The header role switch is the lab operating model: **Mina Rahman** reads, **James Okonkwo** is helpdesk, **Olivia Grant** is Tier-0.

## Sign-in, without a password file

1. Open **Setup wizard**.
2. Leave **Fabrikam lab** selected for the interview, or choose **Live directory** for a real domain controller.
3. Enter the controller, the domain, the username, and the password.
4. Choose **Authenticate and continue**.

The lab checks that the username exists. A live connection is an LDAP simple bind to the host you named. After that, **Housekeeping scan** will publish. **Disconnect** drops the password from memory. `instance/lab_state.json` keeps the host and the username so the form can be filled in again. It does not keep the secret. The PDF and the operator journal do not keep it either.

## Servers beyond the domain controllers

**Windows servers → Add and scan** takes a hostname and a role (member server or domain controller). From this workstation the console resolves the name and checks ports 88, 389, 445, 636, 3389, and 5985. Hardening recommendations follow the role. An open 3389 emphasizes Network Level Authentication. LDAP on 389 without 636 emphasizes LDAPS. A name that does not resolve is still listed, with the role baseline and a DNS note.

## Reports

**Reports** shows the pack on screen: score, categorized findings, and open hardening items.

**Download PDF** saves `directory-keep-housekeeping.pdf` — cover, score, finding table, hardening, and the server list.

## A short interview path

1. Sign in through the wizard as `james.okonkwo`.
2. Publish a scan and open the intern in Domain Admins.
3. Show FAB-DC04: 372 minutes since the last success, schedule 180, event 1925.
4. Unlock Priya Nair. The reset for Helena Voss is refused on the helpdesk role.
5. Switch to Tier-0 and remove Arjun Patel from Domain Admins.
6. Add a server hostname and open **Hardening**.
7. Download the PDF.

The speaker notes are in [docs/interview-demo.md](docs/interview-demo.md). How the scan is built is in [docs/architecture.md](docs/architecture.md). The Tomcat installer is in [docs/deployment.md](docs/deployment.md).

Passphrase that passes a helpdesk reset: `Orchid-harbor-7-silver`

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```
