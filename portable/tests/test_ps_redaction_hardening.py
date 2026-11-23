"""Security review 2026-11-12 (round 2) of the ps1 redaction rules: quoted values of user options,
the shell idiom 'a'\\''b', odd backslash runs in escaped-quoted values, and run time on hostile input.

The cases run through tests/ps/redaction_cases.ps1 (exact results) and tests/ps/redaction_timing.ps1
(run time), once per language mode. Shared sh/ps cases live in tests/redaction_cases.py.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from conftest import ps_command, ps_quote

pytestmark = pytest.mark.integration

PH = "<redacted>"
NL = chr(10)
TAB = chr(9)
HERE = Path(__file__).resolve().parent
HARNESS = HERE / "ps" / "redaction_cases.ps1"
TIMING = HERE / "ps" / "redaction_timing.ps1"
MODES = ("FullLanguage", "ConstrainedLanguage")
CMD = "Protect-EsCommandLine"

# (name, function, input, expected)
EXACT = (
    # 2: a quoted user:password value
    ("user_single_quoted_password", CMD, "curl --user bob:'pass' http://x", f"curl --user bob:{PH} http://x"),
    ("user_double_quoted_password_space", CMD, 'curl -u bob:"pa ss" http://x', f"curl -u bob:{PH} http://x"),
    ("user_whole_value_quoted", CMD, 'curl --user "bob:pa ss" http://x', f'curl --user "bob:{PH}" http://x'),
    ("user_whole_value_single_quoted", CMD, "curl -u 'bob:pa ss' http://x", f"curl -u 'bob:{PH}' http://x"),
    ("user_doubled_quote_password", CMD, "curl -u bob:'pa''ss tail' http://x", f"curl -u bob:{PH} http://x"),
    ("user_shell_idiom_password", CMD, "curl -u bob:'pa'\\''ss tail' http://x", f"curl -u bob:{PH} http://x"),
    ("user_unquoted_password", CMD, "curl -u bob:pw9Secret http://x", f"curl -u bob:{PH} http://x"),
    ("user_whole_value_unterminated", CMD, 'curl --user "bob:pa ss', f'curl --user "bob:{PH}'),
    # 3: the shell idiom 'a'\''b' is one value
    ("idiom_option_value", CMD, "app --password 'a'\\''b c' --other x", f"app --password {PH} --other x"),
    ("idiom_option_value_attached", CMD, "app --password='a'\\''b c' --other x", f"app --password={PH} --other x"),
    ("idiom_tool_option", CMD, "mysql -p'a'\\''b c' db", f"mysql -p{PH} db"),
    ("idiom_pair_key", "Protect-EsValue", "Pwd='a'\\''b c';Database=y", f"Pwd={PH};Database=y"),
    ("idiom_twice", "Protect-TwiceCommandLine", "app --password 'a'\\''b c' --other x", f"app --password {PH} --other x"),
    ("user_idiom_twice", "Protect-TwiceCommandLine", "curl -u bob:'pa'\\''ss tail' http://x", f"curl -u bob:{PH} http://x"),
    # 4: \\\" inside an escaped-quoted value is content, the delimiter is a single backslash + quote
    ("escaped_odd_run_pair", "Protect-EsValue", '{\\"password\\":\\"pa\\\\\\"ss\\"}', f'{{\\"password\\":\\"{PH}\\"}}'),
    ("escaped_odd_run_pair_after", "Protect-EsValue", '{\\"password\\":\\"pa\\\\\\"ss\\",\\"user\\":\\"bob\\"}',
     f'{{\\"password\\":\\"{PH}\\",\\"user\\":\\"bob\\"}}'),
    ("escaped_odd_run_pairkey", "Protect-EsValue", 'Pwd=\\"a\\\\\\"b c\\";Database=y', f'Pwd=\\"{PH}\\";Database=y'),
    ("escaped_odd_run_option", CMD, 'app --password=\\"a\\\\\\"b c\\" --x', f'app --password=\\"{PH}\\" --x'),
    # long user:password@host beyond the bounds of the bare-userinfo rule: the whole token goes
    ("long_password_userinfo", "Protect-EsValue", "via bob:" + "p" * 300 + "@host.corp:8080 end", f"via {PH} end"),
    ("long_password_userinfo_twice", "Protect-TwiceValue", "via bob:" + "p" * 300 + "@host.corp:8080 end", f"via {PH} end"),
    ("long_password_userinfo_line", "Protect-TwiceLine", "proxy = bob:" + "p" * 300 + "@host.corp:8080", f"proxy = {PH}"),
    ("long_password_userinfo_cmd", "Protect-TwiceCommandLine", "app bob:" + "p" * 300 + "@host.corp x", f"app {PH} x"),
    ("long_user_userinfo", "Protect-EsValue", "via " + "u" * 200 + ":pw9Secret@host.corp end", f"via {PH} end"),
    ("long_password_at_in_password", "Protect-EsValue", "via bob:" + "p" * 150 + "@" + "q" * 150 + "@host end", f"via {PH} end"),
    ("userinfo_bounds_edge_stays_normal", "Protect-EsValue", "via bob:" + "p" * 256 + "@host.corp end", f"via bob:{PH}@host.corp end"),
    ("image_digest_stays", "Protect-EsValue", "image:tag@sha256:" + "a" * 64 + " x", "image:tag@sha256:" + "a" * 64 + " x"),
    ("escaped_odd_run_twice","Protect-TwiceValue", '{\\"password\\":\\"pa\\\\\\"ss\\"}', f'{{\\"password\\":\\"{PH}\\"}}'),
    # Hardening round 2026-11-15: the xml rule (spec/redaction.toml LINE RULES xml, TEXT RULES multi-line)
    ("xml_two_elements", "Protect-EsLine", "<token>a1</token><user>u</user><password>b2</password>",
     f"<token>{PH}</token><user>u</user><password>{PH}</password>"),
    ("xml_dotted_prefix", "Protect-EsLine", '<a.b-c:apiKey x="1">k9</a.b-c:apiKey>', f'<a.b-c:apiKey x="1">{PH}</a.b-c:apiKey>'),
    ("xml_word_suffix_kept", "Protect-EsLine", "<tokenizer>x</tokenizer> <passwords>y</passwords>",
     "<tokenizer>x</tokenizer> <passwords>y</passwords>"),
    ("xml_upper_case_element", "Protect-EsLine", "<PASSWORD>s3</PASSWORD>", f"<PASSWORD>{PH}</PASSWORD>"),
    ("xml_blank_rest_kept", "Protect-EsLine", "<password>   ", "<password>   "),
    ("xml_closed_then_open", "Protect-EsLine", "<token>a</token> x <secret>rest", f"<token>{PH}</token> x <secret>{PH}"),
    ("xml_text_mid_line_open_rest", "Protect-EsText", "x <password>abc" + NL + "next", f"x <password>{PH}" + NL + "next"),
    ("xml_text_mid_line_blank_rest_opens", "Protect-EsText", NL.join(("x <password>", "CanaryM", "</password> y")),
     NL.join(("x <password>", PH, "</password> y"))),
    ("xml_text_first_after_indent", "Protect-EsText", NL.join((TAB + '<ns:token a="b/c">v1', "  v2", "  </NS:TOKEN>", "z")),
     NL.join((TAB + f'<ns:token a="b/c">{PH}', f"  {PH}", "  </NS:TOKEN>", "z"))),
    ("xml_text_self_closing_does_not_open", "Protect-EsText", "<password/>" + NL + "kept", "<password/>" + NL + "kept"),
)


def run(command: str) -> dict[str, Any]:
    proc = ps_command(command, timeout=600)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def run_harness(script: Path, built: Path, work: Path, mode: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    cases_file = work / "cases.json"
    cases_file.write_text(json.dumps(cases), encoding="ascii")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if mode != MODES[0] else ""
    data = run(f"{prefix}& {ps_quote(script)} -Lib {ps_quote(lib)} -Cases {ps_quote(cases_file)}")
    assert data["language_mode"] == mode
    return data


@pytest.fixture(scope="module", params=MODES)
def results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    work = tmp_path_factory.mktemp(f"redact-hard-{request.param}")
    cases = [{"name": n, "fn": fn, "args": [text]} for n, fn, text, _ in EXACT]
    return run_harness(HARNESS, built, work, request.param, cases)


@pytest.mark.parametrize("name,fn,text,expected", EXACT, ids=[c[0] for c in EXACT])
def test_exact(results: dict[str, Any], name: str, fn: str, text: str, expected: str) -> None:
    assert results[name] == expected


# ---------------------------------------------------------------- run time on hostile input

SIZE = 32000
HOSTILE = {
    "option_words": ("Protect-EsCommandLine", " --" + "pass" * (SIZE // 4)),
    "option_words_16k": ("Protect-EsCommandLine", " --" + "pass" * 4000),
    "pair_equals": ("Protect-EsCommandLine", "a=" * (SIZE // 2)),
    "pair_equals_16k": ("Protect-EsCommandLine", "a=" * 8000),
    "pair_equals_text": ("Protect-EsText", "a=" * (SIZE // 2)),
    "words": ("Protect-EsCommandLine", "word " * (SIZE // 5)),
    "words_text": ("Protect-EsText", "word " * (SIZE // 5)),
    "authorization": ("Protect-EsValue", "authorization " + "a" * SIZE),
    "authorization_repeat": ("Protect-EsValue", "authorization:" * (SIZE // 14)),
    "authorization_text": ("Protect-EsText", "Authorization: " + "a\\" * (SIZE // 2)),
    "dashes": ("Protect-EsCommandLine", " -" * (SIZE // 2)),
    "user_options": ("Protect-EsCommandLine", " -u a" * (SIZE // 5)),
    "quotes": ("Protect-EsCommandLine", "password='" + "'a" * (SIZE // 2)),
    "escaped_quotes": ("Protect-EsValue", 'password=\\"' + 'a\\\\' * (SIZE // 3)),
    "password_keys": ("Protect-EsText", "password=x " * (SIZE // 11)),
    "tool_options": ("Protect-EsCommandLine", "mysql" + " -p" * (SIZE // 3)),
    "userinfo": ("Protect-EsValue", "a:" * (SIZE // 2) + "@"),
    "at_signs": ("Protect-EsValue", "u:p@" * (SIZE // 4)),
    "tokens": ("Protect-EsValue", "ghp_" * (SIZE // 4)),
    "userinfo_boundaries": ("Protect-EsValue", "a:=" * (SIZE // 3) + "@"),
    "userinfo_boundaries_text": ("Protect-EsText", "a:=" * (SIZE // 3) + "@"),
    "pairs_with_hint": ("Protect-EsValue", "a=" * (SIZE // 2 - 6) + "pwd=1"),
    "hint_keys": ("Protect-EsValue", "pass_" * (SIZE // 5)),
    "escaped_pairs": ("Protect-EsValue", '\\"password\\":\\"' + 'a\\\\\\"' * (SIZE // 6)),
    "long_userinfo_tokens": ("Protect-EsValue", ("a:" + "p" * 300 + "@h ") * (SIZE // 303)),
    "long_userinfo_no_at": ("Protect-EsValue", ("a:" + "p" * 300 + " ") * (SIZE // 302) + "@"),
    "long_token_colons": ("Protect-EsText", "a:" * (SIZE // 2) + "@"),
    "xml_open_no_gt": ("Protect-EsLine", "<password" * (SIZE // 9)),
    "xml_open_no_close": ("Protect-EsLine", "<password>" * (SIZE // 10)),
    "xml_open_no_close_text": ("Protect-EsText", "x <password>" * (SIZE // 12)),
    "xml_prefix_run": ("Protect-EsLine", "<" + "a" * SIZE + " x=1>"),
    "xml_prefix_lts": ("Protect-EsLine", "<a" * (SIZE // 2) + ">"),
    "xml_prefix_colons": ("Protect-EsLine", "<a:" * (SIZE // 3) + ">"),
    "xml_self_closing": ("Protect-EsLine", "<token/>" * (SIZE // 8)),
    "xml_closed": ("Protect-EsLine", "<token>a</token>" * (SIZE // 16)),
    "xml_attributes_no_gt": ("Protect-EsLine", "<token" + " a='/'" * (SIZE // 6)),
    "xml_text_open_lines": ("Protect-EsText", ("<password>" + NL) * (SIZE // 11)),
    "overlong_value":("Protect-EsValue", "authorization " + "a" * 200000),
    "overlong_command_line": ("Protect-EsCommandLine", "--password " + "a b " * 100000),
    "overlong_line": ("Protect-EsLine", "key=" + "a:=" * 100000 + "@"),
}
LIMIT_SECONDS = 2.0


@pytest.fixture(scope="module", params=MODES)
def timings(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    work = tmp_path_factory.mktemp(f"redact-time-{request.param}")
    cases = [{"name": n, "fn": fn, "args": [text]} for n, (fn, text) in HOSTILE.items()]
    return run_harness(TIMING, built, work, request.param, cases)


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_input_runs_in_linear_time(timings: dict[str, Any], name: str) -> None:
    entry = timings[name]
    assert entry["ms"] < LIMIT_SECONDS * 1000, f"{name}: {entry['ms']} ms for {entry['length']} chars"


def test_overlong_values_fail_closed(timings: dict[str, Any]) -> None:
    # A value, command line or line beyond 128 KiB is replaced whole rather than scanned.
    for name in ("overlong_value", "overlong_command_line", "overlong_line"):
        assert timings[name]["result"] == "<redacted: too long>", timings[name]


# ---------------------------------------------------------------- review fixes 2026-11-15 (ps only)
# Kept apart from EXACT and HOSTILE, which tests/test_js_redaction.py imports for the JScript port.

KELVIN = "\u212a"  # KELVIN SIGN: Unicode lower-casing turns it into "k"
PS_XML_EXACT = (
    # X1h: ASCII-only lower-casing; "</to<KELVIN>en>" is not "</token>"
    ("xml_kelvin_does_not_close", "Protect-EsText",
     NL.join(("<token>", "CanaryK1", f"</TO{KELVIN}EN>", "CanaryK2", "</token>", "after")),
     NL.join(("<token>", PH, PH, PH, "</token>", "after"))),
    # X1h: ASCII-only blank tests; a no-break or ideographic space is not blank
    ("xml_nbsp_rest_is_not_blank", "Protect-EsLine", "<password>\u00a0", f"<password>{PH}"),
    ("xml_ideographic_space_rest", "Protect-EsLine", "<token>\u3000", f"<token>{PH}"),
    # X1c: the element's own closing tag ends the content; "</passwords" is another element
    ("xml_text_suffix_close_does_not_end", "Protect-EsText",
     NL.join(("<password>", "CanaryS1", "</passwords>", "CanaryS2", "</password>", "after")),
     NL.join(("<password>", PH, PH, PH, "</password>", "after"))),
    # X1b: <x:token> is "token" with prefix "x"; its closing tag is </x:token>
    ("xml_prefixed_secret_element", "Protect-EsLine", "<x:token>CanaryXt</x:token> <y>1</y>", f"<x:token>{PH}</x:token> <y>1</y>"),
    # key/value exception: "<prefix:" + a secret element name is a qualified name; "<password: x" is a key
    ("xml_qname_close_kept", "Protect-EsLine", "<token:password>CanaryQn</token:password>",
     f"<token:password>{PH}</token:password>"),
    ("xml_key_with_space_after_colon", "Protect-EsLine", "<password: CanarySp", f"<password: {PH}"),
    # X1d: an unterminated comment hides the rest of its line
    ("xml_unterminated_comment_hides_close", "Protect-EsLine", "<password>a<!-- </password> x", f"<password>{PH}"),
    ("xml_comment_after_close_kept", "Protect-EsLine", "<token>a</token><!-- note -->", f"<token>{PH}</token><!-- note -->"),
    # X1g: a quote of the start tag spans lines; the tag ends at the first ">" outside it
    ("xml_text_pending_quote_spans_lines", "Protect-EsText",
     NL.join(('<password a="x', '>y" b="1">CanarySQ', "</password>", "after")),
     NL.join(('<password a="x', f'>y" b="1">{PH}', "</password>", "after"))),
    ("xml_text_pending_tag_closed_on_line", "Protect-EsText", NL.join(("<token", ' a="1">CanaryTc</token> k=v', "after")),
     NL.join(("<token", f' a="1">{PH}</token> k=v', "after"))),
    ("xml_line_pending_tag_left_alone", "Protect-EsLine", '<password a="x <token>CanaryQ</token>', '<password a="x <token>CanaryQ</token>'),
    # X1e/f: after the multi-line close a new element opens again on the same line
    ("xml_text_close_then_open_mid_line", "Protect-EsText",
     NL.join(("<password>", "q", "</password> <token>", "CanaryT2", "</token>", "end")),
     NL.join(("<password>", PH, "</password> <token>", PH, "</token>", "end"))),
    # xml pair rule: key="..secret word.." value="..." and name=... value=...
    ("xml_pair_key_value", "Protect-EsLine", '<add key="db.Password" value="CanaryXp" />', f'<add key="db.Password" value="{PH}" />'),
    ("xml_pair_name_value", "Protect-EsLine", '<setting name="ApiToken" value="CanaryXn"/>', f'<setting name="ApiToken" value="{PH}"/>'),
    ("xml_pair_plain_kept", "Protect-EsLine", '<add key="color" value="blue" />', '<add key="color" value="blue" />'),
)


@pytest.fixture(scope="module", params=MODES)
def ps_xml_results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    work = tmp_path_factory.mktemp(f"redact-xml-{request.param}")
    cases = [{"name": n, "fn": fn, "args": [text]} for n, fn, text, _ in PS_XML_EXACT]
    return run_harness(HARNESS, built, work, request.param, cases)


@pytest.mark.parametrize("name,fn,text,expected", PS_XML_EXACT, ids=[c[0] for c in PS_XML_EXACT])
def test_ps_xml_exact(ps_xml_results: dict[str, Any], name: str, fn: str, text: str, expected: str) -> None:
    assert ps_xml_results[name] == expected


PS_HOSTILE = {
    # ES_XML_PAIR_RE was quadratic on an unterminated key value full of secret words
    "xml_pair_unclosed_key": ("Protect-EsLine", 'key="' + "password" * 16000),
    "xml_pair_unclosed_name": ("Protect-EsLine", 'name="' + "token " * 21000),
    "xml_pair_unclosed_value": ("Protect-EsLine", 'key="password" value="' + "a" * 120000),
    "xml_urlkey_unclosed": ("Protect-EsLine", '<add key="a://' * 8000),
    "xml_attribute_unclosed": ("Protect-EsLine", 'password="' + "token=" * 20000),
    "xml_many_prefixes": ("Protect-EsLine", "".join(f"<a{i}:token>x</b>" for i in range(6000))),
    "xml_closes_many_heads": ("Protect-EsLine", "<password>a</x>" * 8000),
    "xml_comment_runs": ("Protect-EsLine", "<password>" + "<!--" * 30000),
    "xml_comment_closes": ("Protect-EsLine", "<password>a<!-- </password> -->" * 3500),
    "xml_quotes_no_gt": ("Protect-EsLine", '<password a="' + 'x" b="' * 20000),
    "xml_quotes_no_gt_text": ("Protect-EsText", '<password a="' + 'x" b="' * 20000),
    "xml_gt_in_quotes": ("Protect-EsLine", "<token a='" + ">" * 100000 + "'>x</token>"),
    "xml_text_pending_lines": ("Protect-EsText", "<password" + NL + ('a="1"' + NL) * 400),
    "xml_text_until_lines": ("Protect-EsText", "<password>" + NL + ("x</y>" + NL) * 400),
}


@pytest.fixture(scope="module", params=MODES)
def ps_timings(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    work = tmp_path_factory.mktemp(f"redact-time-ps-{request.param}")
    cases = [{"name": n, "fn": fn, "args": [text]} for n, (fn, text) in PS_HOSTILE.items()]
    return run_harness(TIMING, built, work, request.param, cases)


@pytest.mark.parametrize("name", sorted(PS_HOSTILE))
def test_ps_hostile_xml_runs_in_linear_time(ps_timings: dict[str, Any], name: str) -> None:
    entry = ps_timings[name]
    assert entry["ms"] < LIMIT_SECONDS * 1000, f"{name}: {entry['ms']} ms for {entry['length']} chars"
