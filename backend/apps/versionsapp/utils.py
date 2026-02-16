from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime

from django.contrib.contenttypes.models import ContentType


def _as_jsonable(v):
    if v is None:
        return None
    if isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, (date, datetime)):
        return v.isoformat()
    if isinstance(v, (list, tuple)):
        return [_as_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _as_jsonable(val) for k, val in v.items()}
    return str(v)


def serialize_instance(obj) -> dict:
    """
    Serialize a model instance to a JSON-friendly snapshot.

    - Stores concrete model fields (incl. FK ids)
    - Stores declared M2M fields as list of ids
    """

    model = obj.__class__
    ct = ContentType.objects.get_for_model(model)

    fields: dict[str, object] = {}
    for f in model._meta.fields:
        name = f.name
        if name in {"id"}:
            continue
        # Store FK as `<field>_id`
        if getattr(f, "many_to_one", False) and getattr(f, "remote_field", None) is not None:
            fields[f"{name}_id"] = _as_jsonable(getattr(obj, f"{name}_id", None))
        else:
            fields[name] = _as_jsonable(getattr(obj, name, None))

    m2m: dict[str, list[int]] = {}
    for f in model._meta.many_to_many:
        try:
            ids = list(getattr(obj, f.name).values_list("id", flat=True))
        except Exception:
            ids = []
        m2m[f.name] = [int(x) for x in ids if x is not None]

    snap = {
        "model": f"{ct.app_label}.{ct.model}",
        "fields": fields,
        "m2m": m2m,
    }
    return deepcopy(snap)


def _parse_date(s: str) -> date | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        # datetime strings are also acceptable; keep date portion.
        if "T" in s:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
        return date.fromisoformat(s)
    except Exception:
        return None


def _parse_datetime(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def restore_instance_from_snapshot(obj, snapshot: dict) -> None:
    """
    Apply a snapshot onto an existing instance.
    Does not change pk. Organization must be enforced by caller.
    """

    if not isinstance(snapshot, dict):
        return
    fields = snapshot.get("fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    model = obj.__class__
    for f in model._meta.fields:
        name = f.name
        if name in {"id", "organization"}:
            continue

        # Foreign keys are stored as `<field>_id`
        if getattr(f, "many_to_one", False) and getattr(f, "remote_field", None) is not None:
            key = f"{name}_id"
            if key not in fields:
                continue
            setattr(obj, f"{name}_id", fields.get(key) or None)
            continue

        if name not in fields:
            continue
        raw = fields.get(name)

        # Basic coercions for date/datetime fields
        internal = getattr(f, "get_internal_type", lambda: "")()
        if internal == "DateField" and isinstance(raw, str):
            setattr(obj, name, _parse_date(raw))
        elif internal == "DateTimeField" and isinstance(raw, str):
            setattr(obj, name, _parse_datetime(raw))
        else:
            setattr(obj, name, raw)

    obj.save()

    m2m = snapshot.get("m2m") or {}
    if isinstance(m2m, dict):
        for f in model._meta.many_to_many:
            if f.name not in m2m:
                continue
            raw_ids = m2m.get(f.name) or []
            ids = [int(x) for x in raw_ids if str(x).isdigit() or isinstance(x, int)]
            try:
                getattr(obj, f.name).set(ids)
            except Exception:
                pass

