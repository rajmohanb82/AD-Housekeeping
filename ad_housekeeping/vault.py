"""Process memory for a directory password.

The password is kept only in this process, keyed by the browser session.
It is never written to lab_state.json, the audit journal, or a report.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_secrets: dict[str, str] = {}


def store(vault_id: str, password: str) -> None:
    with _lock:
        _secrets[vault_id] = password


def contains(vault_id: str | None) -> bool:
    if not vault_id:
        return False
    with _lock:
        return vault_id in _secrets


def peek(vault_id: str | None) -> str | None:
    if not vault_id:
        return None
    with _lock:
        return _secrets.get(vault_id)


def drop(vault_id: str | None) -> None:
    if not vault_id:
        return
    with _lock:
        _secrets.pop(vault_id, None)
