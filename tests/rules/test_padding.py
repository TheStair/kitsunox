"""`static.padded-code` and `util.text.collapse_runs` on inert, hand-written lines (they look
like code; nothing here runs)."""

import time

from kitsunox.core.models import Severity
from kitsunox.rules.padding import PaddedCode
from kitsunox.rules.static import RULES
from kitsunox.stages.static import analyse
from kitsunox.util.text import collapse_runs

CODE = "var z='-c';var a=['x','y'];(function(){for(var i=0;i<a.length;i++){f(a[i]);}})();" * 4
HIDDEN = "import fs from 'fs';\n" + "\t" * 266 + CODE + "\n"


def test_code_behind_a_long_run_of_tabs_is_medium() -> None:
    (match,) = PaddedCode().evaluate_text(HIDDEN)
    assert match.severity is Severity.MEDIUM
    assert match.weight == 3.0
    assert match.line == 2
    assert f"266 tabs, then {len(CODE)} characters of code" in match.explanation
    assert match.snippet.startswith("⟨266 tabs⟩var z='-c';")
    assert match.snippet.endswith("...")
    assert any(m.rule_id == PaddedCode.id for m in analyse(HIDDEN.encode()))
    assert any(r.id == PaddedCode.id for r in RULES)


def test_spaces_after_code_on_the_same_line_count() -> None:
    text = "module.exports = {};" + " " * 150 + CODE
    (match,) = PaddedCode().evaluate_text(text)
    assert "150 spaces" in match.explanation
    assert match.snippet.startswith("module.exports = {};⟨150 spaces⟩")


def test_deep_indentation_reached_step_by_step_does_not_count() -> None:
    """`@motir/cli`: compiled JSON-schema validators nest 106 spaces deep, a level at a time."""
    nested = "".join(" " * n + "if (x) {\n" for n in range(0, 106, 2)) + " " * 106 + CODE
    assert PaddedCode().evaluate_text(nested) == []
    jump = " " * 4 + "if (x) {\n\n" + " " * 106 + CODE  # from the margin, past a blank line
    (match,) = PaddedCode().evaluate_text(jump)
    assert match.line == 3


def test_a_string_array_opening_the_payload_counts() -> None:
    """`persona-ai-sdk@1.0.0`: 2,000 spaces, then `const _0x...=["W1hE...","d1wZ...",...`."""
    array = "const _0x38d0=[" + ",".join(f'"W1hEQVwFXFpR{i}"' for i in range(80)) + "];"
    (match,) = PaddedCode().evaluate_text("'use strict';\n" + " " * 2000 + array)
    assert "2000 spaces" in match.explanation


def test_one_finding_per_file() -> None:
    assert len(PaddedCode().evaluate_text(HIDDEN * 3)) == 1


def test_short_runs_short_tails_and_trailing_whitespace_do_not_count() -> None:
    rule = PaddedCode()
    assert rule.evaluate_text(" " * 99 + CODE) == []
    assert rule.evaluate_text(" " * 300 + CODE[:150]) == []
    assert rule.evaluate_text(CODE + " " * 500 + "\n" + CODE) == []


def test_comments_tables_and_markup_do_not_count() -> None:
    rule = PaddedCode()
    for head in ("// ", "/* ", "* ", "# ", "| ", "<td>", "<!-- "):
        assert rule.evaluate_text("x" + " " * 120 + head + CODE) == [], head


def test_padding_inside_a_string_does_not_count() -> None:
    text = 'const banner = "' + " " * 120 + CODE
    assert PaddedCode().evaluate_text(text) == []


def test_prose_without_code_punctuation_does_not_count() -> None:
    words = "the quick brown fox jumps over the lazy dog " * 8
    assert PaddedCode().evaluate_text(" " * 200 + words) == []


def test_many_runs_on_one_long_line_stay_linear() -> None:
    text = ("a" + " " * 120 + "b") * 20_000  # 2.4 MB on one line, no code
    started = time.perf_counter()
    assert PaddedCode().evaluate_text(text) == []
    assert time.perf_counter() - started < 2.0


def test_collapse_runs_counts_each_long_run() -> None:
    assert collapse_runs("a" + "\t" * 266 + "b") == "a⟨266 tabs⟩b"
    assert collapse_runs(" " * 1200 + "x") == "⟨1,200 spaces⟩x"
    assert collapse_runs(" \t" * 30) == "⟨60 spaces and tabs⟩"
    assert collapse_runs(" " * 39 + "x") == " " * 39 + "x"  # ordinary indentation stays
