from __future__ import annotations

import threading
from dataclasses import dataclass


_local = threading.local()


@dataclass
class AuditContext:
    user_id: int | None = None
    ip: str | None = None


def set_audit_context(ctx: AuditContext) -> None:
    _local.ctx = ctx


def get_audit_context() -> AuditContext:
    return getattr(_local, "ctx", AuditContext())


def clear_audit_context() -> None:
    if hasattr(_local, "ctx"):
        delattr(_local, "ctx")

