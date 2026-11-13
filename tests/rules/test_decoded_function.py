"""`static.decoded-function`: a small file that decodes text, compiles text into a function and
hands that function `require`.

Fixtures are short, inert snippets in the shape of `mock-data-sdk@1.0.1`'s loader; the
"decoded" text is never a payload and nothing here runs.
"""

import pytest

from kitsunox.core.models import Severity
from kitsunox.rules.static import RULES, DecodedFunction, FunctionRequire
from kitsunox.stages.static import analyse

DECODE = 'const code = Buffer.from(joined, "base64").toString("utf-8");\n'
# `mock-data-sdk`'s shape: names for the parameters, the compiled function stored, then called.
STORED = DECODE + (
    "const fn = Function(\n  names.Buffer,\n  names.require,\n  names.process,\n  code\n);\n"
    "return fn(Buffer, require, process);\n"
)


def _fire(text: str) -> list[str]:
    return [m.rule_id for m in DecodedFunction().evaluate_text(text)]


@pytest.mark.parametrize(
    "text",
    [
        STORED,
        DECODE + "Function('a', 'b', code)(Buffer, require);\n",
        DECODE + "new Function('m', 'require', code)(module, require);\n",
        DECODE + "const run = new Function(p, code);\nrun.call(null, require);\n",
        DECODE + "let g; g = Function(p, code); g.apply(this, [require]);\n",
        "const s = atob(blob); Function(x, s)(require);\n",
        "const s = zlib.inflateSync(b).toString(); Function(x, s)(require);\n",
        "const n = t.map((c) => String.fromCharCode(c ^ key)).join('');\n"
        "Function(n, body)(require);\n",
        # A module wrapper in a file that fetches what it runs.
        "const code = await (await fetch(atob(u))).text();\n"
        "new Function('module', 'exports', 'require', code)(m, m.exports, require);\n",
    ],
)
def test_fires(text: str) -> None:
    (match,) = DecodedFunction().evaluate_text(text)
    assert match.severity is Severity.MEDIUM and match.weight == 3.0
    assert "require" in match.explanation and "Function" in match.snippet


@pytest.mark.parametrize(
    "text",
    [
        # Nothing decoded in the file.
        "const fn = Function(p, code);\nfn(require);\n",
        # `require` is not handed to the compiled function.
        DECODE + "const fn = Function(p, code);\nfn(Buffer, process);\nrequire('x');\n",
        DECODE + "const fn = Function(p, code);\nother(require);\n",
        # Constant code: the package's own, as written.
        DECODE + "Function('return this')(require);\n",
        DECODE + "Function('a', 'return ' + 'a')(require);\n",
        # `Function("require", ...)`: `static.function-require` reports it.
        DECODE + 'new Function("require", code)(require);\n',
        DECODE + "new Function(\n  'require',\n  code\n)(require);\n",
        # A CommonJS module wrapper (Emscripten, a bundler's output evaluated in place) in a
        # file that fetches nothing.
        DECODE + "new Function('module', 'exports', 'require', code)(m, m.exports, req);\n",
        DECODE + "const w = new Function('g', 'require', 'module', code);\nw(g, require, m);\n",
        # A method or property named Function, and no call at all.
        DECODE + "x.Function(code)(require);\n",
        DECODE + "typeof Function === 'function' && f(require);\n",
    ],
)
def test_does_not_fire(text: str) -> None:
    assert _fire(text) == []


def test_large_files_are_not_read_as_one_loader() -> None:
    padding = "// " + "x" * 120 + "\n"
    big = STORED + padding * (DecodedFunction.MAX_BYTES // len(padding) + 1)
    assert _fire(big) == []


def test_an_unclosed_call_or_string_is_no_match() -> None:
    assert _fire(DECODE + "Function(p, code\n") == []
    assert _fire(DECODE + "Function(p, 'unclosed)(require);\n") == []
    assert _fire(DECODE + "Function(p, " + "(" * 10 + "code" + ")" * 5000 + "(require);") == []
    assert _fire(DECODE + "Function(p, code" + " + x" * 2000 + ")(require);\n") == []
    assert _fire(DECODE + "Function(p, 'it\\'s (', code)(require);\n") == [
        "static.decoded-function"
    ]


def test_one_match_per_file_and_the_function_require_rule_stays_apart() -> None:
    assert _fire(STORED + STORED) == ["static.decoded-function"]
    both = DECODE + 'Function("require", code)(require);\n'
    rules = [m.rule_id for m in analyse(both.encode(), RULES)]
    assert FunctionRequire.id in rules and DecodedFunction.id not in rules
    assert DecodedFunction.id in [m.rule_id for m in analyse(STORED.encode(), RULES)]
