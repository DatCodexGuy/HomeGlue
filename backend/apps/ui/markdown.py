from __future__ import annotations

import html
from typing import Final

import re


# Keep this strict; rendering should never allow arbitrary HTML.
ALLOWED_TAGS: Final[list[str]] = [
    "p",
    "br",
    "hr",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "blockquote",
    "ul",
    "ol",
    "li",
    "strong",
    "em",
    "code",
    "pre",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "a",
]

ALLOWED_ATTRS: Final[dict[str, list[str]]] = {
    "a": ["href", "title", "rel"],
    "th": ["colspan", "rowspan"],
    "td": ["colspan", "rowspan"],
    "code": ["class"],
    "pre": ["class"],
}


# In code blocks we want copy/paste-friendly text. Python-Markdown emits &quot; inside code;
# browsers typically render it fine, but downstream escaping/copy flows can surface the entity.
_CODE_TAG_RE: Final[re.Pattern[str]] = re.compile(r"(<code\b[^>]*>)(.*?)(</code>)", re.IGNORECASE | re.DOTALL)


def _fix_code_entities(html_in: str) -> str:
    """
    Convert quote entities inside <code>...</code> back to literal quotes.

    Important: we do NOT unescape < or &; only quotes, to avoid turning code into HTML.
    """

    def _repl(m: re.Match) -> str:
        head, body, tail = m.group(1), m.group(2), m.group(3)
        body = body or ""
        # linkify() can cause these entities to be double-escaped as &amp;quot; inside <code>.
        body = body.replace("&amp;quot;", '"').replace("&quot;", '"').replace("&amp;#34;", '"').replace("&#34;", '"').replace("&amp;#x22;", '"').replace("&#x22;", '"')
        body = body.replace("&amp;#39;", "'").replace("&#39;", "'").replace("&amp;#x27;", "'").replace("&#x27;", "'")
        return f"{head}{body}{tail}"

    return _CODE_TAG_RE.sub(_repl, html_in or "")


def render_markdown(md: str) -> str:
    """
    Safe Markdown -> HTML renderer (Python-Markdown + bleach sanitization).
    Used for user-entered bodies (Docs, Notes, etc.).
    """

    md = md or ""
    try:
        import markdown as mdlib
        import bleach

        html_out = mdlib.markdown(
            md,
            extensions=[
                "fenced_code",
                "tables",
                "sane_lists",
                "nl2br",
            ],
            output_format="html5",
        )
        cleaned = bleach.clean(
            html_out,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRS,
            protocols=["http", "https", "mailto"],
            strip=True,
        )
        cleaned = bleach.linkify(cleaned, skip_tags=["pre", "code"])
        return _fix_code_entities(cleaned)
    except Exception:
        # Fallback: minimal renderer (headings, bullets, code fences, paragraphs).
        return _fix_code_entities(_render_markdown_minimal(md))


def _render_markdown_minimal(md: str) -> str:
    lines = (md or "").splitlines()

    out: list[str] = []
    in_code = False
    code_lines: list[str] = []
    in_list = False
    paragraph: list[str] = []

    def _close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def _close_code():
        nonlocal in_code, code_lines
        if in_code:
            code = "\n".join(code_lines)
            out.append('<pre class="code"><code>')
            # Keep quotes literal for readability/copy-paste; still escape < and &.
            out.append(html.escape(code, quote=False))
            out.append("</code></pre>")
            in_code = False
            code_lines = []

    def _flush_paragraph():
        nonlocal paragraph
        if not paragraph:
            return
        _close_list()
        text = " ".join([x.strip() for x in paragraph]).strip()
        if text:
            out.append(f"<p>{html.escape(text)}</p>")
        paragraph = []

    for raw in lines:
        line = raw.rstrip("\n")
        if line.strip().startswith("```"):
            _flush_paragraph()
            if in_code:
                _close_code()
            else:
                _close_list()
                in_code = True
                code_lines = []
            continue

        if in_code:
            code_lines.append(line)
            continue

        s = line.strip()
        if not s:
            _flush_paragraph()
            continue

        if s.startswith("#"):
            _flush_paragraph()
            _close_list()
            n = len(s) - len(s.lstrip("#"))
            n = max(1, min(4, n))
            title = s.lstrip("#").strip()
            out.append(f"<h{n}>{html.escape(title)}</h{n}>")
            continue

        if s.startswith("- "):
            _flush_paragraph()
            if not in_list:
                out.append("<ul>")
                in_list = True
            item = s[2:].strip()
            out.append(f"<li>{html.escape(item)}</li>")
            continue

        paragraph.append(line)

    _flush_paragraph()
    _close_list()
    _close_code()
    return "\n".join(out).strip()
