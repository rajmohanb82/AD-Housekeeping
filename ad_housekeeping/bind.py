"""Authenticate to a directory without keeping the password on disk."""

from __future__ import annotations

import socket


def bind_ldap(host: str, port: int, use_ssl: bool, username: str, password: str, domain: str) -> dict:
    """Simple LDAP bind. Returns a public result. The password is not copied into the result."""
    identity = username if "@" in username else f"{username}@{domain}"
    try:
        from ldap3 import ALL, SUBTREE, Connection, Server
        from ldap3.core.exceptions import LDAPException
    except ImportError as exc:
        raise RuntimeError("The ldap3 package is not installed.") from exc

    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=5)
    try:
        connection = Connection(
            server,
            user=identity,
            password=password,
            auto_bind=True,
            receive_timeout=8,
            raise_exceptions=True,
        )
    except LDAPException as exc:
        message = str(exc)
        if password and password in message:
            message = message.replace(password, "********")
        return {"ok": False, "message": f"The directory rejected the sign-in. {message}"}

    base = ""
    try:
        base = server.info.other.get("defaultNamingContext", [""])[0]
    except (AttributeError, IndexError, TypeError):
        base = ""

    computers: list[dict] = []
    people = 0
    if base:
        try:
            connection.search(
                base,
                "(&(objectCategory=computer)(operatingSystem=*Server*))",
                search_scope=SUBTREE,
                attributes=["cn", "dNSHostName", "operatingSystem"],
                size_limit=40,
            )
            for entry in connection.entries:
                computers.append(
                    {
                        "name": str(entry.cn),
                        "fqdn": str(entry.dNSHostName) if entry.dNSHostName else str(entry.cn),
                        "os": str(entry.operatingSystem) if entry.operatingSystem else "Windows Server",
                    }
                )
            connection.search(
                base,
                "(&(objectCategory=person)(objectClass=user))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName"],
                size_limit=5,
            )
            people = len(connection.entries)
        except LDAPException:
            computers = []
    connection.unbind()
    return {
        "ok": True,
        "message": f"Signed in to {host} as {identity}. The password stays in memory for this session only.",
        "identity": identity,
        "naming_context": base,
        "computers": computers,
        "people_sample": people,
    }


def resolve_host(hostname: str) -> tuple[bool, str]:
    try:
        return True, socket.getaddrinfo(hostname, None)[0][4][0]
    except socket.gaierror:
        return False, ""


def probe_ports(hostname: str, ports: tuple[int, ...] = (88, 389, 445, 636, 3389, 5985)) -> dict[str, bool]:
    results: dict[str, bool] = {}
    for port in ports:
        try:
            with socket.create_connection((hostname, port), timeout=0.4):
                results[str(port)] = True
        except OSError:
            results[str(port)] = False
    return results
