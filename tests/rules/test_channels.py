"""`static.channel-follow-on-connect`: a WhatsApp library that follows a hardcoded channel
when the socket connects, in any file of any version.

Fixtures are small, inert snippets in the shape of Baileys forks (made-up channel ids); nothing
here runs or connects anywhere.
"""

from datetime import UTC, datetime

from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.rules.channels import ChannelFollowOnConnect, bound_names, follows_on_connect
from kitsunox.rules.static import RULES
from kitsunox.stages.static import ContentCache, analyse_batch

JID = "120363000000000001@newsletter"
SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="kx-baileys", version="1.0.1"),
    publish=PublishInfo(),
    manifest={},
)
# `@risacakep/risayap` 7.0.0-rc25.7's shape: a constant followed on every connection open.
ON_OPEN = f"""const makeWASocket = (config) => {{
    const socket = makeCommunitiesSocket(config);
    const AUTHOR_JID = '{JID}';
    socket.ev.on('connection.update', async ({{ connection }}) => {{
        if (connection !== 'open')
            return;
        try {{
            await socket.newsletterFollow(AUTHOR_JID);
        }}
        catch (error) {{ }}
    }});
    return socket;
}};
""".encode()
# `elaina-baileys`' shape: the FOLLOW query with a literal id, on a timer.
TIMER_QUERY = f"""    setTimeout(async () => {{
        try {{
            await newsletterWMexQuery("{JID}", Types_1.QueryIds.FOLLOW
            );
        }} catch {{}}
    }}, 90000);
""".encode()
# `@xzvbailss/baileys`' shape: an array of ids iterated on a timer.
TIMER_LOOP = f"""const CHANNELS = [
    "{JID}"
];
setTimeout(async () => {{
    for (const jid of CHANNELS) {{
        await newsletterWMexQuery(jid, QueryIds.FOLLOW);
    }}
}}, 150000);
""".encode()
# Upstream Baileys: the API method, run on the caller's id; nothing follows by itself.
API = b"""const makeNewsletterSocket = (config) => {
    return {
        newsletterFollow: (jid) => {
            return executeWMexQuery({ newsletter_id: jid }, QueryIds.FOLLOW, XWAPaths.join);
        },
    };
};
"""


def fire(files: dict[str, bytes]) -> list[tuple[str | None, int | None]]:
    out = ChannelFollowOnConnect().evaluate_artifact(SNAP, files)
    return [(e.path, e.line_start) for f in out for e in f.evidence]


def test_follows_a_hardcoded_channel_when_it_connects() -> None:
    assert fire({"lib/Socket/index.js": ON_OPEN}) == [("lib/Socket/index.js", 8)]
    assert fire({"lib/Socket/newsletter.js": TIMER_QUERY}) == [("lib/Socket/newsletter.js", 3)]
    assert fire({"lib/Socket/newsletter.js": TIMER_LOOP}) == [("lib/Socket/newsletter.js", 6)]
    (finding,) = ChannelFollowOnConnect().evaluate_artifact(SNAP, {"lib/a.js": ON_OPEN})
    assert (finding.rule_id, finding.severity, finding.weight) == (
        "static.channel-follow-on-connect",
        Severity.MEDIUM,
        3.0,
    )
    assert "newsletterFollow(AUTHOR_JID)" in (finding.evidence[0].snippet or "")


def test_an_environment_default_and_foreach_are_bound_ids() -> None:
    """`gimaa-baileys@1.0.0`: the id is the default of an environment variable."""
    text = (
        "const autoJid = process.env.X === undefined\n"
        f"    ? '{JID}'\n"
        "    : process.env.X.trim();\n"
        f"const LIST = ['{JID}'];\n"
        "LIST.forEach(async (id) => {});\n"
    )
    assert bound_names(text) == {"autoJid", "LIST", "id"}
    gimaa = (
        text + "ev.on('connection.update', ({ connection }) => {\n"
        "    void sock.newsletterFollow(autoJid);\n});\n"
    )
    assert len(follows_on_connect(gimaa)) == 1


def test_not_the_api_an_opt_in_or_a_call_the_user_makes() -> None:
    assert fire({"lib/Socket/newsletter.js": API}) == []
    # `shadowx-baileys` (benign): the follow runs only when the user turns it on.
    opt_in = ON_OPEN.replace(
        b"    socket.ev.on(", b"    if (config.autoFollowChannel === true) socket.ev.on("
    )
    assert fire({"lib/Socket/index.js": opt_in}) == []
    # A helper the user calls, with no connection listener or timer before it.
    helper = f"export const followAuthor = (sock) => sock.newsletterFollow('{JID}');\n".encode()
    assert fire({"lib/helpers.js": helper}) == []
    # A variable that holds no hardcoded id (`aunubaileys`: ids the user passes in).
    loop = (
        b"setTimeout(async () => {\n"
        b"  for (const jid of opts.channels) await sock.newsletterFollow(jid);\n"
        b"}, 1);\n"
    )
    assert fire({"lib/Utils/autojoin.js": loop + f"// e.g. {JID}\n".encode()}) == []


def test_comments_messages_tests_and_docs_do_not_count() -> None:
    commented = (
        b"setTimeout(() => {\n" + f"  // sock.newsletterFollow('{JID}')\n".encode() + b"});\n"
    )
    assert fire({"lib/a.js": commented}) == []
    logged = (
        b"setTimeout(() => {\n" + f"  log.info(\"newsletterFollow('{JID}')\")\n".encode() + b"});\n"
    )
    assert fire({"lib/a.js": logged}) == []
    for path in ("test/socket.test.js", "Example/example.js", "docs/a.js", "README.md"):
        assert fire({path: ON_OPEN}) == []


def _snapshot(version: str) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx-baileys", version=version),
        publish=PublishInfo(published_at=datetime(2026, 11, 10, tzinfo=UTC)),
        manifest={},
        artifact=ArtifactRef(url=f"https://r.test/kx-{version}.tgz", unpacked_size=100),
    )


def test_a_follow_on_release_with_the_file_unchanged_is_still_flagged() -> None:
    """The file rules see only contents an update adds (`static.channel-follow` is silent on
    rc25.7); the artifact rule reads every file of every version."""
    tree = {"lib/index.js": b"module.exports = 1;\n", "lib/Socket/index.js": ON_OPEN}
    trees = {"1.0.0": tree, "1.0.1": tree | {"lib/index.js": b"module.exports = 2;\n"}}
    batch = PackageBatch(
        ecosystem="npm",
        name="kx-baileys",
        base=_snapshot("1.0.0"),
        versions=(Candidate(change=Change(new=_snapshot("1.0.1"), previous=_snapshot("1.0.0"))),),
    )
    result = analyse_batch(
        batch,
        lambda s: trees[s.ref.version],
        ContentCache(None, RULES),
        artifact_rules=NPM_ARTIFACT_RULES,
    )
    (version,) = result.versions
    rules = {f.rule_id for f in version.findings}
    assert "static.channel-follow-on-connect" in rules
    assert "static.channel-follow" not in rules
    assert version.history[-1].forwarded
