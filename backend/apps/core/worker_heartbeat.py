from __future__ import annotations

from django.utils import timezone


def heartbeat_mark(*, started: bool = False, finished: bool = False, ok: bool = True, error: str = "") -> None:
    """
    Best-effort heartbeat update.

    This must never crash the worker loop (migrations may not be applied yet).
    """

    try:
        from apps.core.models import WorkerHeartbeat

        obj = WorkerHeartbeat.objects.filter(key="default").first()
        if obj is None:
            obj = WorkerHeartbeat.objects.create(key="default")
        now = timezone.now()
        if started:
            obj.last_started_at = now
        if finished:
            obj.last_finished_at = now
        obj.last_ok = bool(ok)
        obj.last_error = (error or "")[:4000]
        obj.save()
    except Exception:
        return

