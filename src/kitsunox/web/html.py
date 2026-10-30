"""HTML building blocks for the viewer: escaping, links and the page frame.

Everything that came from a package (names, versions, publishers, reasons, explanations,
snippets, before/after values, URLs) is attacker-controlled and may be crafted to break the
page: `<script>`, a quote to leave an attribute, a `javascript:` link, or bidirectional and
invisible characters that make text read differently from what it is (Trojan Source). So:

- all text goes through `html.escape(quote=True)` after hidden characters (controls, bidi,
  zero-width, variation selectors, private use: `util.text.strip_hidden`) are removed, and a
  visible marker says how many were removed (that alone can be a signal for a reviewer);
- code and evidence go in `<pre>`, escaped the same way, newlines kept;
- links are emitted only for URLs `util.text.safe_url` accepts (plain ASCII `https://` with a
  host name, no user info, no quotes, angle brackets, backslashes, spaces or control
  characters), with `rel="noopener noreferrer nofollow"`; anything else is shown as text.

The page frame carries no inline style or script: the Content-Security-Policy forbids both.
"""

from __future__ import annotations

import html
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final

from kitsunox.util.text import hidden_note, safe_url, strip_hidden

STYLESHEET: Final = "/static/style.css"
MAX_BLOCK_CHARS: Final = 20_000


def removed(count: int) -> str:
    """The visible marker for `count` removed hidden characters, or "" for none."""
    return f'<span class="flag">{hidden_note(count)}</span>' if count else ""


def clean(value: object) -> tuple[str, int]:
    """`value` as text without hidden characters, and how many were removed. Tab and newline
    are kept."""
    return strip_hidden(str(value))


def esc(value: object) -> str:
    """Inline untrusted text: one line, escaped, flagged if characters were removed."""
    stripped, count = clean(value)
    return html.escape(" ".join(stripped.split()), quote=True) + removed(count)


def plain(value: object) -> str:
    """Untrusted text where markup can't go (`<title>`): escaped, no marker."""
    return html.escape(" ".join(clean(value)[0].split()), quote=True)


def block(value: str, *, limit: int = MAX_BLOCK_CHARS) -> str:
    """Untrusted code or evidence in `<pre>`, newlines kept, cut at `limit` characters."""
    stripped, count = clean(value)
    shown = stripped[:limit]
    parts = [f"<pre>{html.escape(shown, quote=True)}</pre>"]
    if len(stripped) > limit:
        parts.append(
            f'<p class="note">Cut at {limit:,} of {len(stripped):,} characters '
            "(all in <code>report.json</code>).</p>"
        )
    if count:
        parts.append(f'<p class="note">{removed(count)}</p>')
    return "".join(parts)


def link(url: str | None, label: object) -> str:
    """An external link, or the URL as text when it isn't safe to link; "n/a" if None."""
    if url is None:
        return "n/a"
    safe = safe_url(url)
    if safe is None:
        return f'<span class="unlinked">{esc(url)}</span> <span class="note">(not linked)</span>'
    return (
        f'<a href="{html.escape(safe, quote=True)}" rel="noopener noreferrer nofollow">'
        f"{esc(label)}</a>"
    )


def internal(href: str, label: str) -> str:
    """A link within the viewer. `href` is built from validated parts; `label` is escaped
    markup (from `esc`)."""
    return f'<a href="{html.escape(href, quote=True)}">{label}</a>'


def when(moment: datetime | None) -> str:
    if moment is None:
        return "unknown"
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def error_box(message: str) -> str:
    """`message` is markup (escape untrusted parts first)."""
    return f'<div class="error" role="alert"><p>{message}</p></div>'


def warning_box(message: str) -> str:
    return f'<div class="warning" role="note"><p>{message}</p></div>'


def page(title: str, body: str, crumbs: Sequence[tuple[str | None, str]] = ()) -> str:
    """A whole document. `title` is plain text (escaped here); `body` and the crumb labels are
    markup; a crumb with an href links there."""
    trail = ""
    if crumbs:
        items = "".join(
            f"<li>{internal(href, label) if href else label}</li>" for href, label in crumbs
        )
        trail = f'<nav aria-label="Breadcrumb"><ol class="crumbs">{items}</ol></nav>'
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f"<title>{plain(title)} - Kitsunox</title>\n"
        f'<link rel="stylesheet" href="{STYLESHEET}">\n'
        "</head>\n"
        "<body>\n"
        '<header><nav aria-label="Main"><a class="brand" href="/">Kitsunox</a> '
        '<a href="/">Review queue</a> <a href="/runs">Runs</a></nav></header>\n'
        f"<main>\n{trail}\n{body}\n</main>\n"
        "<footer><p>Local, read-only viewer. Text from packages is untrusted: it is shown "
        "escaped, with hidden characters removed and only plain https links.</p></footer>\n"
        "</body>\n"
        "</html>\n"
    )
