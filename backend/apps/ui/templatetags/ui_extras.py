from __future__ import annotations

import math

from django import template
from django.utils.safestring import mark_safe

register = template.Library()

try:
    from apps.ui.markdown import render_markdown
except Exception:  # pragma: no cover
    render_markdown = None


@register.filter
def get_item(d, key):
    try:
        return d.get(key)
    except Exception:
        return None


@register.filter
def markdown(text):
    """
    Render user-entered markdown as safe HTML.
    """

    if not text:
        return ""
    if render_markdown is None:
        return str(text)
    return mark_safe(render_markdown(str(text)))


@register.filter
def contains(haystack, needle) -> bool:
    try:
        return str(needle) in str(haystack)
    except Exception:
        return False


@register.filter
def human_bytes(v) -> str:
    """
    Format byte counts into a compact human-friendly string (binary units).

    Accepts ints/floats or numeric strings.
    """

    try:
        if v is None:
            return ""
        if isinstance(v, bool):
            return "0 B" if not v else "1 B"
        n = float(str(v).strip())
    except Exception:
        return str(v) if v is not None else ""
    if math.isnan(n) or math.isinf(n):
        return str(v)
    n = max(0.0, n)
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    i = 0
    while n >= 1024.0 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    if i == 0:
        return f"{int(n)} {units[i]}"
    return f"{n:.1f} {units[i]}"


@register.filter
def human_duration_seconds(v) -> str:
    """
    Format seconds into a compact string, e.g. "2d 3h 4m".
    """

    try:
        if v is None:
            return ""
        if isinstance(v, bool):
            return "0s"
        s = int(float(str(v).strip()))
    except Exception:
        return str(v) if v is not None else ""
    if s <= 0:
        return "0s"
    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins and len(parts) < 2:
        parts.append(f"{mins}m")
    if secs and not parts:
        parts.append(f"{secs}s")
    return " ".join(parts[:3]) if parts else "0s"
