from __future__ import annotations

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
