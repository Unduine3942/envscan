"""sh redaction: linear time on hostile input, the length cap and the bare-userinfo bounds.

The hostile inputs are those of the ps hardening test (tests/test_ps_redaction_hardening.py) plus a few
more; the limit is generous (the point is catching quadratic or worse behaviour: 32 KB input that
takes minutes). The same inputs run through gawk (the test harness) and through dash with the
scanner's own es_awk (the awk found on PATH, MSYS awk here).
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from redaction_cases import PH
from sh_helpers import AwkTool, make_awk_tool, msys_path, needs_msys, run_lib
from test_ps_redaction_hardening import HOSTILE as PS_HOSTILE, SIZE

pytestmark = [pytest.mark.integration, needs_msys]

OPS = {"Protect-EsValue": "value", "Protect-EsLine": "line", "Protect-EsText": "text",
       "Protect-EsCommandLine": "cmd", "Protect-EsNamedValue": "named"}
EXTRA = {
    "userinfo_eq_colon": ("Protect-EsValue", "a:=a:=" * (SIZE // 6) + "@"),
    "userinfo_eq_colon_text": ("Protect-EsText", "a:=a:=" * (SIZE // 6) + "@"),
    "userinfo_at_eq": ("Protect-EsValue", "a:@=" * (SIZE // 4)),
    "userinfo_many_matches": ("Protect-EsValue", "u:p@h;" * (SIZE // 6)),
    "userinfo_many_tokens": ("Protect-EsValue", "a:b@c " * (SIZE // 6)),
    "userinfo_many_tokens_line": ("Protect-EsLine", "a:b@c " * (SIZE // 6)),
    "userinfo_separators": ("Protect-EsValue", "a:" + ",(|;=" * (SIZE // 6) + "@h"),
    "option_words_pass": ("Protect-EsCommandLine", " --" + "pass" * 8000),
    "authorization_repeat_13": ("Protect-EsValue", "authorization" * 2500),
    "authorization_repeat_13_cmd": ("Protect-EsCommandLine", "authorization" * 2500),
    # review 2026-11-15: pair keys and key/value pairs found once, never per match over the rest
    "pairkeys_many_quoted": ("Protect-EsValue", 'Pwd="x";' * (SIZE // 8)),
    "pairs_many_runs": ("Protect-EsValue", "pwd=a " * (SIZE // 6)),
    "pairkeys_in_open_attribute": ("Protect-EsValue", '<password a="' + "<password>" * (SIZE // 10)),
}
HOSTILE = {**PS_HOSTILE, **EXTRA}
LIMIT_SECONDS = 5.0
CAP = 131072
TOO_LONG = "<redacted: too long>"


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


@pytest.fixture(scope="module")
def awk_tool(lib: Path, tmp_path_factory: pytest.TempPathFactory) -> AwkTool:
    return make_awk_tool(lib, tmp_path_factory.mktemp("sh-hard"))


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_input_runs_in_linear_time_gawk(awk_tool: AwkTool, tmp_path: Path, name: str) -> None:
    fn, text = HOSTILE[name]
    start = time.perf_counter()
    out = awk_tool.cases([(OPS[fn], text)], tmp_path)
    elapsed = time.perf_counter() - start
    assert len(out) == 1
    assert elapsed < LIMIT_SECONDS, f"{name}: {elapsed:.1f} s for {len(text)} chars"
    if len(text) > CAP:
        assert out[0] == TOO_LONG


def dash_run(lib: Path, work: Path, text: str, mode: str) -> float:
    src = work / "in.txt"
    src.write_bytes((text + "\n").encode("utf-8"))
    script = ('ES_TMP=$1; es_awk_program >"$ES_TMP/json.awk"; ES_REDACT=1; '
              'es_awk "$3" "$2" >"$ES_TMP/out.txt"; echo "rc=$?"')
    start = time.perf_counter()
    proc = run_lib(lib, script, msys_path(work), msys_path(src), mode, timeout=120)
    elapsed = time.perf_counter() - start
    assert proc.stdout.strip() == "rc=0", proc.stderr
    return elapsed


@pytest.fixture(scope="module")
def dash_baseline(lib: Path, tmp_path_factory: pytest.TempPathFactory) -> float:
    """Start-up of dash, the library and awk (slow under MSYS), measured on a trivial line."""
    return dash_run(lib, tmp_path_factory.mktemp("dash-base"), "plain", "text")


@pytest.mark.parametrize("name", ["userinfo_eq_colon", "userinfo_at_eq", "userinfo_many_matches", "userinfo_many_tokens",
                                  "option_words_pass", "authorization_repeat_13", "at_signs", "long_userinfo_tokens"])
def test_hostile_input_runs_in_linear_time_dash(lib: Path, tmp_path: Path, dash_baseline: float, name: str) -> None:
    fn, text = HOSTILE[name]
    elapsed = dash_run(lib, tmp_path, text, "log" if fn == "Protect-EsCommandLine" else "text") - dash_baseline
    assert elapsed < LIMIT_SECONDS, f"{name}: {elapsed:.1f} s above the start-up time"


@pytest.mark.parametrize("op, text", [
    ("value", "authorization " + "a" * CAP), ("line", "key=" + "a:=" * 100000 + "@"),
    ("cmd", "--password " + "a b " * 100000), ("text", "x" * (CAP + 1)), ("named", "OTHER")],
    ids=["value", "line", "cmd", "text", "named"])
def test_over_the_cap_fails_closed(awk_tool: AwkTool, tmp_path: Path, op: str, text: str) -> None:
    if op == "named":
        out = awk_tool.cases([("named", "PATHISH", "y" * (CAP + 1))], tmp_path)[0]
    else:
        out = awk_tool.cases([(op, text)], tmp_path)[0]
    assert out == TOO_LONG
    again = awk_tool.cases([(op if op != "named" else "value", out)], tmp_path)[0]
    assert again == TOO_LONG


def test_exactly_the_cap_is_scanned(awk_tool: AwkTool, tmp_path: Path) -> None:
    text = "a" * (CAP - len("password=") - 1)
    out = awk_tool.cases([("value", "password=" + text), ("value", "a" * CAP)], tmp_path)
    assert out[0] == f"password={PH}" and out[1] == "a" * CAP


@pytest.mark.parametrize("text, expected", [
    # the user is 1-128 characters, the password 1-256 (bare userinfo)
    ("via " + "u" * 128 + ":pw@host.corp end", f"via {'u' * 128}:{PH}@host.corp end"),
    ("via " + "u" * 129 + ":pw@host.corp end", f"via {PH} end"),
    ("via bob:" + "p" * 256 + "@host end", f"via bob:{PH}@host end"),
    ("via bob:" + "p" * 257 + "@host end", f"via {PH} end"),
    ("via bob:@host end", "via bob:@host end"),
    # a token start follows = ; , ( |: the user never holds them
    ("http=u:a@p:80;https=u:b@p:80", f"http=u:{PH}@p:80;https=u:{PH}@p:80"),
    ("(bob:pw1@h)", f"(bob:{PH}@h)"),
    # not userinfo
    ("git@github.com:org/repo.git", "git@github.com:org/repo.git"),
    ("image:tag@sha256:" + "a" * 64 + " x", "image:tag@sha256:" + "a" * 64 + " x"),
    # a long token without any "@" stays
    ("x:" + "p" * 400, "x:" + "p" * 400),
])
def test_bare_userinfo_bounds(awk_tool: AwkTool, tmp_path: Path, text: str, expected: str) -> None:
    once = awk_tool.cases([("value", text)], tmp_path)[0]
    assert once == expected
    assert awk_tool.cases([("value", once)], tmp_path)[0] == once


# Review fix X1i: the xml rule is linear (forward-only cursors, no substr copy of the rest of the
# line per "<"); each hostile line must take well under a second above the awk start-up time.
XML_HOSTILE = {
    "xml_lt_run": ("line", "<" * 100000),
    "xml_lt_run_text": ("text", "<" * 100000),
    "xml_open_run": ("line", "<password" * 10000),
    "xml_open_run_text": ("text", "<password" * 10000),
    "xml_open_quote": ("text", '<password a="' + "<password>" * 10000),
    "xml_open_tags": ("line", "<password>" * 10000),
    "xml_open_tags_text": ("text", "<password>x" * 10000),
    "xml_comments": ("line", "<password>" + "<!--" * 30000),
    "xml_closes": ("line", "<password>" + "</x" * 30000),
    "xml_close_comment_mix": ("text", "<password>\n" + "<!-- </password> -->" * 5000),
    "xml_prefixes": ("line", "<a:b:c:d" * 10000),
}
XML_LIMIT_SECONDS = 1.0


@pytest.mark.parametrize("name", sorted(XML_HOSTILE))
def test_xml_hostile_lines_run_in_linear_time(awk_tool: AwkTool, tmp_path: Path, name: str) -> None:
    mode, text = XML_HOSTILE[name]
    start = time.perf_counter()
    awk_tool.cases([("line", "x")], tmp_path)
    base = time.perf_counter() - start
    start = time.perf_counter()
    out = awk_tool.cases([(mode, text)], tmp_path)
    elapsed = time.perf_counter() - start - base
    assert len(out) == 1
    assert elapsed < XML_LIMIT_SECONDS, f"{name}: {elapsed:.2f} s for {len(text)} chars"


# Review fix X1 a-g, sh-specific extras beyond the shared XML_CASES.
@pytest.mark.parametrize("mode, text, gone, kept", [
    # g: the open quote of a start tag carries over lines; its ">" is the first one outside it
    ("text", '<password a="x\n>y">\nCanaryG1\n</password>\nafter', ("CanaryG1",), ("after", '>y">')),
    # g: a start-tag state ends at a line starting with "<"; that line is read normally
    ("text", "<token\n<password>CanaryG2</password>\nkeep", ("CanaryG2",), ("keep", "<token")),
    # g: what follows the ">" on the closing line of the start tag, closed on that line
    ("text", '<password\n a="1">CanaryG3</password> <token>CanaryG4</token>\nkeep', ("CanaryG3", "CanaryG4"), ("keep",)),
    # d: an unterminated comment hides the rest of its line, also the closing tag
    ("line", "<password>CanaryD1<!-- </password>", ("CanaryD1", "</password>"), ()),
    # f: after the multi-line close a new element left open starts a new multi-line state
    ("text", "<password>\nx\n</password> <token>\nCanaryF1\n</token>\nkeep", ("CanaryF1",), ("keep",)),
    # e: only the first unclosed tag can open (here mid-line: nothing opens)
    ("text", "<x>1</x> <token> <password>\nnext kept", (), ("next kept",)),
    # h: ASCII-only case folding (the Kelvin sign is not "k")
    ("line", "<to\u212aen>keepK</to\u212aen>", (), ("keepK",)),
])
def test_xml_review_rules(awk_tool: AwkTool, tmp_path: Path, mode: str, text: str, gone: tuple, kept: tuple) -> None:
    out = awk_tool.cases([(mode, text)], tmp_path)[0]
    for word in gone:
        assert word not in out, out
    for word in kept:
        assert word in out, out
