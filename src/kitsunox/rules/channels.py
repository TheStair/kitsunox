"""Stage 2 artifact rule: a WhatsApp library that follows a fixed channel when it connects.

The owner's policy (decision 0015, addenda of 2026-11-08): a Baileys fork that makes the user's
account follow a channel it chose is **unwanted**, hidden or disclosed; one that follows only
when the user asks is benign. `static.channel-follow` (a file rule) names such code, but file
rules read only the contents an update adds: a follow-on release that ships the same follow
unchanged has no Stage 2 finding at all. `@risacakep/risayap@7.0.0-rc25.7` (live, 2026-11-10,
unwanted, found by the label-blind daily sample) is one: its `lib/Socket/index.js`, unchanged
since rc25.6 (reported), still calls `socket.newsletterFollow('1203...@newsletter')` on every
`connection.update` to `open`.

So this rule reads every JavaScript file of every version (an `ArtifactRule`), narrowly. It
fires when a file

- passes a **hardcoded channel id** (a `\\d{15,22}@newsletter` string, or a variable bound to
  one in the same file: a constant, an environment default, an array iterated with `for ... of`
  or `forEach`) as the first argument of a follow: `newsletterFollow(...)`,
  `followNewsletter(...)`, or a query call that also passes the `FOLLOW` query id
  (`newsletterWMexQuery(jid, QueryIds.FOLLOW)`);
- makes that call itself when the socket connects: inside a `connection.update` listener, a
  `setTimeout`/`setInterval`, or `ev.process`, at most `SETUP_WINDOW` characters before it
  (a follow the library only defines as a method for the user to call is not one);
- and not behind an explicit opt-in (`static.channel-follow`'s `if (... follow ... === true)`,
  `shadowx-baileys`'s `shadowXAutoFollowChannel`, benign by the owner's verdict).

Comments and log or error messages are blanked first (`mask_comments_and_messages`); tests,
examples and documentation directories are skipped. Upstream Baileys and the forks the owner
verdicted benign (follow is an API method only: `aunubaileys`, `@nanazx/baileys`; opt-in:
`shadowx-baileys`, `lexzymods-*`) never pass a hardcoded id to a follow. The tagging form
(`static.channel-tagging`) is not repeated here: the same always-read check would fire on
`aunubaileys` 1.0.53-1.0.58 (benign, a tagging helper the user calls).

MEDIUM, weight 3, like `static.channel-follow`, which fires too when the file changed (two
findings for the same call: the score counts it twice, the decision is the same). Added
2026-11-11, recall round 8 R (`docs/proposals/recall-round8-R.md`).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule
from kitsunox.lang.javascript import language_for, mask_comments_and_messages

SETUP_WINDOW: Final = 1200
OPT_IN_WINDOW: Final = 600
MAX_SHOWN: Final = 3
SNIPPET_RADIUS: Final = 80
_JID: Final = r"[\"'`]\d{15,22}@newsletter[\"'`]"
JID_BYTES: Final = re.compile(rb"\d{15,22}@newsletter")
# A variable bound to a channel id: `const JID = '1203...@newsletter'`, an environment default
# (`process.env.X === undefined ? '1203...@newsletter' : ...`), an array of them.
BOUND: Final = re.compile(r"\b(?:const|let|var)\s+([\w$]+)\s*=[^;]{0,200}?" + _JID)
# A loop variable over a bound array: `for (const jid of CHANNELS)`, `CHANNELS.forEach((jid) =>`.
LOOP: Final = re.compile(
    r"\bfor\s*\(\s*(?:const|let|var)\s+([\w$]+)\s+of\s+([\w$]+)\s*\)"
    r"|\b([\w$]+)\s*\.\s*forEach\s*\(\s*(?:async\s*)?\(?\s*([\w$]+)"
)
_ARG: Final = r"\s*\(\s*(" + _JID + r"|[\w$]+)\s*(?=[,)])"
# The follow call and its first argument.
FOLLOW: Final = re.compile(r"(?<![\w$])(?:newsletterFollow|followNewsletter)" + _ARG)
# A query call given the FOLLOW query id after its first argument.
FOLLOW_QUERY: Final = re.compile(
    r"(?<![\w$])[\w$]*(?:query|Query)[\w$]*" + _ARG + r"\s*,[^;()]{0,120}?\.\s*FOLLOW\b"
)
# An explicit opt-in before the follow (`static.channel-follow`'s test): `if (autoFollow === true)`.
OPT_IN: Final = re.compile(r"if\s*\(\s*[\w$.?]*(?i:follow)[\w$.?]*\s*===\s*true\s*\)")
# The code that runs when the socket connects.
SETUP: Final = re.compile(
    r"connection\.update|\bsetTimeout\s*\(|\bsetInterval\s*\(|\bev\s*\.\s*process\s*\("
)
# Tests, examples and documentation: not what the library runs.
SKIPPED: Final = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|examples?|docs?|demo)/|\.(?:test|spec)\.[cm]?[jt]sx?$",
    re.IGNORECASE,
)


def bound_names(text: str) -> set[str]:
    """The variables in `text` that hold a hardcoded channel id (directly or as a loop
    variable over an array of them)."""
    names = {m.group(1) for m in BOUND.finditer(text)}
    for match in LOOP.finditer(text):
        variable, source = (
            (match.group(1), match.group(2)) if match.group(1) else (match.group(4), match.group(3))
        )
        if source in names:
            names.add(variable)
    return names


def follows_on_connect(text: str) -> list[re.Match[str]]:
    """The follows of a hardcoded channel id that `text` makes when the socket connects, not
    behind an opt-in (module docstring)."""
    if "@newsletter" not in text:
        return []
    names = bound_names(text)
    found = []
    for match in sorted(
        (*FOLLOW.finditer(text), *FOLLOW_QUERY.finditer(text)), key=lambda m: m.start()
    ):
        argument = match.group(1)
        if not (argument[0] in "\"'`" or argument in names):
            continue
        start = match.start()
        if not SETUP.search(text, max(0, start - SETUP_WINDOW), start):
            continue
        if OPT_IN.search(text, max(0, start - OPT_IN_WINDOW), start):
            continue
        found.append(match)
    return found


class ChannelFollowOnConnect(BaseRule):
    """A WhatsApp library follows a hardcoded channel when the socket connects, in any file
    of any version (module docstring)."""

    id = "static.channel-follow-on-connect"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Follows a fixed WhatsApp channel when it connects (unwanted)"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        evidence: list[Evidence] = []
        for path in sorted(files):
            language = language_for(path)
            content = files[path]
            if language is None or b"@newsletter" not in content or SKIPPED.search(path):
                continue
            if not JID_BYTES.search(content):
                continue
            text = mask_comments_and_messages(content, language).decode("utf-8", "replace")
            for match in follows_on_connect(text)[:1]:
                line = text.count("\n", 0, match.start()) + 1
                around = text[max(0, match.start() - SNIPPET_RADIUS) : match.end() + SNIPPET_RADIUS]
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=" ".join(around.split()),
                    )
                )
        if not evidence:
            return ()
        return (
            self.finding(
                "Follows a hardcoded WhatsApp channel with the user's account when the socket "
                "connects (a `connection.update` listener or a timer), not behind an opt-in: "
                "every release that ships it does so, changed or not. Unwanted (account "
                "abuse, decision 0015), not by itself a sign of malware.",
                *evidence[:MAX_SHOWN],
            ),
        )


RULES: Final = (ChannelFollowOnConnect(),)
