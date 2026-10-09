"""Directory Keep web console."""

from __future__ import annotations

import os
import secrets
import shutil
import sys
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, abort, flash, redirect, render_template, request, session, url_for

from . import __version__
from .bind import bind_ldap, probe_ports, resolve_host
from .directory import DEFAULT_PATH, LabDirectory, ROOT
from .guidance import ARTICLES, CATEGORIES, EVENT_DOCS, article
from .hardening import all_findings
from .reports import build_pdf
from . import vault
from .policy import (
    OPERATORS,
    Denied,
    account_flags,
    can_disable,
    can_protect,
    can_remove_domain_admin,
    can_reset,
    can_unlock,
)
from .scanner import build_alerts, drift

NAV = [
    ("Connect", [
        ("setup", "Setup wizard", "setup", "key"),
    ]),
    ("Directory", [
        ("overview", "Overview", "overview", "grid"),
        ("scan", "Housekeeping scan", "scan", "scan"),
        ("alerts", "Alerts", "alerts", "bell"),
        ("events", "Security events", "events", "list"),
        ("accounts", "Accounts", "accounts", "people"),
    ]),
    ("Servers", [
        ("infrastructure", "Infrastructure", "infrastructure", "nodes"),
        ("servers", "Windows servers", "servers", "server"),
        ("hardening", "Hardening", "hardening", "shield"),
    ]),
    ("Share", [
        ("reports", "Reports", "reports", "file"),
        ("guidance", "Microsoft guidance", "guidance", "book"),
        ("deploy", "Tomcat deployment", "deploy", "box"),
    ]),
]


def create_app(state_path: Path | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.environ.get("ADHK_SECRET", "directory-keep-lab-secret")
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    directory = LabDirectory(state_path or DEFAULT_PATH)

    def csrf_token() -> str:
        token = session.get("csrf")
        if not token:
            session["csrf"] = token = secrets.token_hex(16)
        return token

    def role() -> str:
        chosen = session.get("role", "helpdesk")
        return chosen if chosen in OPERATORS else "helpdesk"

    def vault_id() -> str:
        if not session.get("vault_id"):
            session["vault_id"] = secrets.token_hex(16)
        return session["vault_id"]

    def signed_in() -> bool:
        return vault.contains(session.get("vault_id"))

    def guard() -> None:
        if request.method == "POST":
            if request.form.get("csrf_token") != session.get("csrf"):
                abort(400)

    @app.context_processor
    def inject():
        return {
            "nav": NAV,
            "role": role(),
            "operator": OPERATORS[role()],
            "csrf_token": csrf_token(),
            "version": __version__,
            "product": "Directory Keep",
            "authenticated": signed_in(),
            "connection": directory.snapshot().get("connection") or {},
        }

    @app.template_filter("when")
    def when_filter(value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return value or ""
        return parsed.strftime("%d %b %Y, %H:%M")

    @app.template_filter("ago")
    def ago_filter(days):
        if days is None:
            return "Never"
        if days == 0:
            return "Today"
        if days == 1:
            return "Yesterday"
        return f"{days} days ago"

    def render(template: str, page: str, title: str, **extra):
        state = directory.snapshot()
        return render_template(
            template,
            page=page,
            title=title,
            state=state,
            drift=drift(state),
            **extra,
        )

    @app.get("/health")
    def health():
        return {"status": "ok", "product": "Directory Keep", "mode": "lab", "version": __version__}

    @app.get("/")
    def overview():
        state = directory.snapshot()
        summary = state["published_summary"]
        alerts = state["published_alerts"][:6]
        ring = 326.73 * (1 - summary.get("score", 0) / 100)
        return render(
            "overview.html",
            "overview",
            "Overview",
            summary=summary,
            alerts=alerts,
            ring=f"{ring:.2f}",
            categories=summary.get("by_category", {}),
        )

    @app.post("/role")
    def set_role():
        guard()
        chosen = request.form.get("role", "helpdesk")
        if chosen not in OPERATORS:
            abort(400)
        session["role"] = chosen
        flash(f"Signed in as {OPERATORS[chosen]['name']}, {OPERATORS[chosen]['title']}.", "ok")
        return redirect(request.referrer or url_for("overview"))

    @app.get("/scan", endpoint="scan")
    def scan_page():
        return render("scan.html", "scan", "Housekeeping scan")

    @app.post("/scan")
    def scan_run():
        guard()
        if not signed_in():
            message = "Sign in through the setup wizard before publishing a scan."
            if request.headers.get("X-Requested-With") == "fetch":
                return {"error": message, "redirect": url_for("setup")}, 401
            flash(message, "danger")
            return redirect(url_for("setup"))
        result = directory.publish(role())
        if request.headers.get("X-Requested-With") == "fetch":
            return {
                "steps": result["steps"],
                "summary": result["summary"],
                "redirect": url_for("alerts"),
            }
        flash(
            f"Scan published. Health {result['summary']['score']} · {result['summary']['total']} findings.",
            "ok",
        )
        return redirect(url_for("alerts"))

    @app.get("/alerts")
    def alerts():
        state = directory.snapshot()
        items = list(state["published_alerts"])
        severity = request.args.get("severity", "")
        category = request.args.get("category", "")
        if severity:
            items = [item for item in items if item["severity"] == severity]
        if category:
            items = [item for item in items if item["category"] == category]
        present = []
        seen = set()
        for item in state["published_alerts"]:
            if item["category"] not in seen:
                seen.add(item["category"])
                present.append(item["category"])
        return render(
            "alerts.html",
            "alerts",
            "Alerts",
            alerts=items,
            severity=severity,
            category=category,
            present_categories=present,
            all_categories=CATEGORIES,
        )

    @app.get("/alerts/<alert_id>")
    def alert_detail(alert_id: str):
        state = directory.snapshot()
        found = next((item for item in state["published_alerts"] if item["id"] == alert_id), None)
        if not found:
            abort(404)
        live_ids = {item["id"] for item in build_alerts(state)}
        return render(
            "alert.html",
            "alerts",
            found["title"],
            alert=found,
            article=article(found["guidance"]),
            resolved=found["id"] not in live_ids,
            can_close=found["id"] == "audit-log-cleared" and found["id"] not in state["closed_incidents"],
        )

    @app.post("/alerts/<alert_id>/close")
    def close_alert(alert_id: str):
        guard()
        try:
            message = directory.close_incident(role(), alert_id, request.form.get("reason", ""))
        except Denied as denied:
            flash(denied.message, "danger")
            return redirect(url_for("alert_detail", alert_id=alert_id))
        flash(message, "ok")
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.get("/events")
    def events():
        state = directory.snapshot()
        query = request.args.get("q", "").strip()
        category = request.args.get("category", "")
        items = state["events"]
        if category:
            items = [item for item in items if item["category"] == category]
        if query:
            needle = query.lower()
            items = [
                item
                for item in items
                if needle in str(item["event_id"])
                or needle in item["summary"].lower()
                or needle in item["account"].lower()
                or needle in item["computer"].lower()
            ]
        categories = []
        seen = set()
        for item in state["events"]:
            if item["category"] not in seen:
                seen.add(item["category"])
                categories.append(item["category"])
        return render(
            "events.html",
            "events",
            "Security events",
            events=items,
            query=query,
            category=category,
            categories=categories,
            event_docs=EVENT_DOCS,
        )

    @app.get("/infrastructure")
    def infrastructure():
        return render("infrastructure.html", "infrastructure", "Infrastructure")

    @app.get("/accounts")
    def accounts():
        state = directory.snapshot()
        query = request.args.get("q", "").strip().lower()
        view = request.args.get("view", "all")
        rows = []
        for user in state["users"]:
            if query and query not in user["sam"] and query not in user["display"].lower() and query not in user["department"].lower():
                continue
            flags = account_flags(user)
            labels = {flag["label"] for flag in flags}
            if view == "locked" and not user["locked"]:
                continue
            if view == "password" and not (user["password_expired"] or user["must_change"] or user["password_age_days"] > 90):
                continue
            if view == "stale" and "Stale" not in labels and "Never signed in" not in labels:
                continue
            if view == "privileged" and "Privileged" not in labels and "Domain Admins" not in labels and user["sam"] != "krbtgt":
                continue
            if view == "service" and not user["service"]:
                continue
            rows.append({**user, "flags": flags})
        rows.sort(key=lambda user: (not user["locked"], user["display"].lower()))
        return render("accounts.html", "accounts", "Accounts", accounts=rows, query=request.args.get("q", ""), view=view)

    @app.get("/accounts/<sam>")
    def account(sam: str):
        state = directory.snapshot()
        user = next((item for item in state["users"] if item["sam"].lower() == sam.lower()), None)
        if not user:
            abort(404)
        related = [item for item in state["events"] if item["account"].lower() == user["sam"].lower()][:8]
        journal = [item for item in state["audit"] if item["target"].lower() == user["sam"].lower()][:8]
        current = role()
        return render(
            "account.html",
            "accounts",
            user["display"],
            user=user,
            flags=account_flags(user),
            related=related,
            journal=journal,
            permissions={
                "unlock": can_unlock(current, user),
                "reset": can_reset(current, user),
                "disable": can_disable(current, user),
                "remove_admin": can_remove_domain_admin(current, user),
                "protect": can_protect(current, user),
            },
            event_docs=EVENT_DOCS,
        )

    def _act(sam: str, fn):
        try:
            message = fn()
        except Denied as denied:
            flash(denied.message, "danger")
            return redirect(url_for("account", sam=sam))
        flash(message, "ok")
        return redirect(url_for("account", sam=sam))

    @app.post("/accounts/<sam>/unlock")
    def unlock(sam: str):
        guard()
        return _act(sam, lambda: directory.unlock(role(), sam, request.form.get("reason", "")))

    @app.post("/accounts/<sam>/reset")
    def reset_password(sam: str):
        guard()
        return _act(
            sam,
            lambda: directory.reset_password(
                role(),
                sam,
                request.form.get("password", ""),
                request.form.get("confirm", ""),
                request.form.get("must_change") == "yes",
                request.form.get("reason", ""),
            ),
        )

    @app.post("/accounts/<sam>/disable")
    def disable(sam: str):
        guard()
        return _act(sam, lambda: directory.disable(role(), sam, request.form.get("reason", "")))

    @app.post("/accounts/<sam>/remove-admin")
    def remove_admin(sam: str):
        guard()
        return _act(sam, lambda: directory.remove_domain_admin(role(), sam, request.form.get("reason", "")))

    @app.post("/accounts/<sam>/protect")
    def protect(sam: str):
        guard()
        return _act(sam, lambda: directory.add_protected_user(role(), sam, request.form.get("reason", "")))

    @app.get("/guidance")
    def guidance():
        grouped: dict[str, list] = {}
        for slug, item in ARTICLES.items():
            grouped.setdefault(item["category"], []).append({"slug": slug, **item})
        return render("guidance.html", "guidance", "Microsoft guidance", grouped=grouped)

    @app.get("/guidance/<slug>")
    def guidance_article(slug: str):
        item = article(slug)
        if not item:
            abort(404)
        return render("article.html", "guidance", item["title"], article=item)

    @app.get("/setup", endpoint="setup")
    def setup_page():
        return render("setup.html", "setup", "Setup wizard")

    @app.post("/setup")
    def setup_connect():
        guard()
        mode = request.form.get("mode", "lab")
        host = request.form.get("host", "").strip()
        domain_name = request.form.get("domain", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        use_ssl = request.form.get("use_ssl") == "yes"
        try:
            port = int(request.form.get("port") or (636 if use_ssl else 389))
        except ValueError:
            port = 0
        if mode not in {"lab", "live"} or not host or not domain_name or not username or not (1 <= port <= 65535):
            flash("Enter the domain controller, the DNS domain, and the username.", "danger")
            return redirect(url_for("setup"))
        if len(password) < 8:
            flash("Enter the directory password. It is used for this session only and is not written to a file.", "danger")
            return redirect(url_for("setup"))

        if mode == "lab":
            account = directory.known_account(username)
            if not account:
                flash("That account is not in the Fabrikam lab. Use a lab username such as james.okonkwo, or switch to a live directory.", "danger")
                return redirect(url_for("setup"))
            message = f"Authenticated to the Fabrikam lab as {account['sam']}. The password is in memory for this session only."
        else:
            try:
                result = bind_ldap(host, port, use_ssl, username, password, domain_name)
            except RuntimeError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("setup"))
            if not result["ok"]:
                flash(result["message"], "danger")
                return redirect(url_for("setup"))
            message = result["message"]
            for computer in result.get("computers") or []:
                resolved, address = resolve_host(computer["fqdn"] or computer["name"])
                ports = probe_ports(computer["fqdn"] or computer["name"]) if resolved else {}
                directory.add_managed_server(
                    {
                        "name": computer["name"],
                        "role": "domain-controller" if "dc" in computer["name"].lower() else "member-server",
                        "resolved": resolved,
                        "address": address,
                        "ports": ports,
                        "note": computer.get("os") or "Discovered by LDAP.",
                    }
                )

        vault.store(vault_id(), password)
        directory.remember_connection(
            {
                "mode": mode,
                "host": host,
                "port": port,
                "use_ssl": use_ssl,
                "domain": domain_name,
                "username": username,
                "role": role(),
            }
        )
        flash(message, "ok")
        return redirect(url_for("overview"))

    @app.post("/setup/disconnect")
    def setup_disconnect():
        guard()
        vault.drop(session.get("vault_id"))
        flash("Disconnected. The password has been dropped from memory.", "ok")
        return redirect(url_for("setup"))

    @app.get("/servers", endpoint="servers")
    def servers_page():
        return render("servers.html", "servers", "Windows servers")

    @app.post("/servers")
    def servers_add():
        guard()
        hostname = request.form.get("hostname", "").strip()
        kind = request.form.get("role", "member-server")
        if not hostname or kind not in {"member-server", "domain-controller"}:
            flash("Enter a hostname and a role.", "danger")
            return redirect(url_for("servers"))
        resolved, address = resolve_host(hostname)
        ports = probe_ports(hostname) if resolved else {}
        open_ports = [port for port, open_ in ports.items() if open_]
        if not resolved:
            note = "The name did not resolve from this workstation. Role baseline still applies."
        elif open_ports:
            note = "Answered on " + ", ".join(open_ports) + "."
        else:
            note = "The name resolved, and none of the management ports answered from here."
        directory.add_managed_server(
            {
                "name": hostname,
                "role": kind,
                "resolved": resolved,
                "address": address,
                "ports": ports,
                "note": note,
            }
        )
        flash(f"Added {hostname}. {note}", "ok")
        return redirect(url_for("hardening"))

    @app.get("/hardening", endpoint="hardening")
    def hardening_page():
        status = request.args.get("status", "")
        rows = all_findings(directory.snapshot())
        if status in {"fail", "review", "pass"}:
            rows = [row for row in rows if row["status"] == status]
        elif status != "all":
            rows = [row for row in rows if row["status"] != "pass"]
        return render("hardening.html", "hardening", "Server hardening", rows=rows, status=status)

    @app.get("/reports", endpoint="reports")
    def reports_page():
        rows = all_findings(directory.snapshot())
        return render("report.html", "reports", "Reports", hardening=rows)

    @app.get("/reports/housekeeping.pdf")
    def report_pdf():
        state = directory.snapshot()
        connection = state.get("connection") or {}
        if signed_in() and connection.get("username"):
            label = f"Signed in as {connection['username']} at {connection.get('host', '')}. Password omitted."
        else:
            label = "Preview of the lab dataset. Sign in through the wizard to stamp a live session. Password omitted."
        payload = build_pdf(state, all_findings(state), label)
        return Response(
            payload,
            mimetype="application/pdf",
            headers={"Content-Disposition": "inline; filename=directory-keep-housekeeping.pdf"},
        )

    @app.get("/deploy")
    def deploy():
        return render("deploy.html", "deploy", "Tomcat deployment", preflight=preflight_checks(), preview=bundle_files())

    @app.post("/deploy/stage")
    def deploy_stage():
        guard()
        target = stage_bundle()
        flash(f"Staged the Tomcat webapp at {target}.", "ok")
        return redirect(url_for("deploy"))

    @app.post("/lab/reset")
    def lab_reset():
        guard()
        directory.reset_lab()
        flash("Lab directory restored to this morning's Fabrikam snapshot.", "ok")
        return redirect(url_for("overview"))

    @app.errorhandler(404)
    def missing(_error):
        return render("missing.html", "overview", "Not found"), 404

    @app.errorhandler(400)
    def bad(_error):
        flash("The form expired. Try that action again.", "danger")
        return redirect(url_for("overview"))

    return app


def preflight_checks() -> list[dict]:
    java = shutil.which("java")
    keytab = Path("/etc/krb5.keytab").exists()
    checks = [
        {"name": "Python runtime", "ok": True, "detail": sys.version.split()[0]},
        {"name": "Directory Keep package", "ok": True, "detail": f"Version {__version__}"},
        {
            "name": "Java for Apache Tomcat",
            "ok": bool(java),
            "detail": java or "Not on this workstation. The Windows installer expects Temurin 17 on the member server.",
        },
        {
            "name": "Domain join",
            "ok": False,
            "detail": "This demo host is not a fabrikam.corp member server."
            if not keytab
            else "A Kerberos keytab exists on this host. Confirm the realm before you treat it as the lab domain.",
        },
        {
            "name": "Installer scripts",
            "ok": (ROOT / "installer" / "install.sh").exists() and (ROOT / "installer" / "Install-DirectoryKeep.ps1").exists(),
            "detail": "install.sh for this lab machine, Install-DirectoryKeep.ps1 for a domain member server.",
        },
    ]
    return checks


def bundle_files() -> dict[str, str]:
    webapp = ROOT / "installer" / "webapp"
    files = {}
    for path in sorted(webapp.rglob("*")):
        if path.is_file():
            files[str(path.relative_to(webapp))] = path.read_text(encoding="utf-8")
    return files


def stage_bundle() -> Path:
    source = ROOT / "installer" / "webapp"
    target = ROOT / "dist" / "tomcat" / "webapps" / "ad-housekeeping"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)
    note = ROOT / "dist" / "DEPLOYMENT.txt"
    note.parent.mkdir(parents=True, exist_ok=True)
    note.write_text(
        "\n".join(
            [
                "Directory Keep — staged Tomcat context",
                "",
                "Copy dist/tomcat/webapps/ad-housekeeping to the Tomcat webapps directory.",
                "The Python service listens on 127.0.0.1:8765.",
                "Tomcat serves the front door and links operators to that service.",
                "Do not run the Tomcat process as a Domain Admin.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return target


def main() -> None:
    port = int(os.environ.get("ADHK_PORT", "8765"))
    app = create_app()
    print(f"Directory Keep lab   http://127.0.0.1:{port}")
    if os.environ.get("ADHK_DEBUG") == "1":
        app.run(host="127.0.0.1", port=port, debug=True)
        return
    from waitress import serve

    serve(app, host="127.0.0.1", port=port, threads=8)
