"""Secret redaction in envscan.sh's awk event writer, against the same case tables as the
PowerShell implementation (tests/test_ps_redaction.py) so that both scripts stay in step.

The awk program is extracted from build/lib/envscan-lib.sh and run with gawk --posix.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sh_helpers import AwkTool, make_awk_tool, needs_msys
from redaction_cases import HEX40, PH, SH_CASES, SHARED_CASES, Case

pytestmark = [pytest.mark.integration, needs_msys]

FUNCTIONS = {
    "Test-EsSecretName": "name",
    "Protect-EsValue": "value",
    "Protect-EsLine": "line",
    "Protect-EsText": "text",
    "Protect-EsCommandLine": "cmd",
    "Protect-EsNamedValue": "named",
}
TWICE = {"Protect-TwiceValue": "value", "Protect-TwiceLine": "line", "Protect-TwiceCommandLine": "cmd"}
FUNCTIONS = {**FUNCTIONS, **{k: v for k, v in TWICE.items()}}
ALL = SHARED_CASES + SH_CASES


@pytest.fixture(scope="module")
def awk_tool(built: Path, tmp_path_factory: pytest.TempPathFactory) -> AwkTool:
    work = tmp_path_factory.mktemp("sh-awk")
    return make_awk_tool(built / "build" / "lib" / "envscan-lib.sh", work)


@pytest.fixture(scope="module")
def results(awk_tool: AwkTool, tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    work = tmp_path_factory.mktemp("sh-redaction")
    rows = [(FUNCTIONS[c.fn], *c.args) for c in ALL]
    out = awk_tool.cases(rows, work)
    twice = [(c, v) for c, v in zip(ALL, out) if c.fn in TWICE]
    second = awk_tool.cases([(TWICE[c.fn], v) for c, v in twice], work)
    again = {c.name: v for (c, _), v in zip(twice, second)}
    return {c.name: again.get(c.name, v) for c, v in zip(ALL, out)}


@pytest.mark.parametrize("case", ALL, ids=lambda c: c.name)
def test_redaction_case(results: dict[str, str], case: Case) -> None:
    actual: Any = results[case.name]
    if case.fn == "Test-EsSecretName":
        actual = actual == "true"
    if case.exact:
        assert actual == case.expected
        return
    for secret in case.gone:
        assert secret not in actual, actual
    for fragment in case.kept:
        assert fragment in actual, actual


def _render(awk_tool: AwkTool, events: list[str], redact: bool = True) -> dict[str, Any]:
    return json.loads(awk_tool.run("json", "\n".join(events) + "\n", redact=redact))


def test_json_safety_net(awk_tool: AwkTool) -> None:
    """Every string in probe data gets the value rules; env-style events get name rules."""
    doc = _render(awk_tool, [
        "{\t-",
        "s\turl\thttps://u:abc123@repo.corp/x",
        "s\topts\tplain value",
        "e\tMY_TOKEN\tzzz999",
        "e\tJAVA_OPTS\t-Dhttp.proxyPassword=key777key -Xmx1g",
        "v\tvalue\tcredential.helper\tstore --file x",
        "c\tcmdline\tapp --token tok555 --verbose",
        "}",
    ])
    flat = json.dumps(doc)
    for secret in ("abc123", "zzz999", "key777key", "tok555"):
        assert secret not in flat, flat
    assert doc["opts"] == "plain value"
    assert doc["MY_TOKEN"] == PH
    assert doc["value"] == PH
    assert "-Xmx1g" in doc["JAVA_OPTS"]


def test_no_redact_keeps_values(awk_tool: AwkTool) -> None:
    doc = _render(awk_tool, ["{\t-", "e\tMY_TOKEN\tzzz999", "}"], redact=False)
    assert doc["MY_TOKEN"] == "zzz999"


def test_config_file_event_redacts_before_filtering(awk_tool: AwkTool, tmp_path: Path) -> None:
    """F events: text rules (blocks) over the whole file, then the lines filter."""
    cfg = tmp_path / "settings.yml"
    cfg.write_text("proxy:\n  host: proxy.corp\nnpmAuthToken: abc123tok\ngithub-oauth:\n  proxy.corp: "
                   + HEX40 + "\nother: x\n", encoding="ascii")
    doc = _render(awk_tool, ["{\t-", f"F\tlines\t{cfg.as_posix()}\t65536\tlines\tproxy|Token", "}"])
    flat = json.dumps(doc)
    assert HEX40 not in flat and "abc123tok" not in flat, flat
    assert "proxy:" in doc["lines"]
    assert doc["truncated"] is False
    assert doc["line_count"] == len(doc["lines"])


def test_config_file_with_private_key(awk_tool: AwkTool, tmp_path: Path) -> None:
    cfg = tmp_path / "key.conf"
    cfg.write_text("proxy=1\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n", encoding="ascii")
    doc = _render(awk_tool, ["{\t-", f"F\tlines\t{cfg.as_posix()}\t65536\tall\t-", "}"])
    assert doc["lines"] == ["<redacted: private key>"]
    assert "MIIabc" not in json.dumps(doc)


def test_log_mode(awk_tool: AwkTool) -> None:
    out = awk_tool.run("log", "run tool --token log444secret\nplain line\n")
    assert "log444secret" not in out
    assert "run tool --token" in out and "plain line" in out


def test_env_event_mode_redacts_and_counts(awk_tool: AwkTool) -> None:
    """envev reads "NAME TAB escaped value" lines (es_env_capture) and writes x events that are
    already redacted, so no unredacted value reaches the scanner's temp directory."""
    capture = ("GH_TOKEN\tabc\nHOME\t/home/u\nMAVEN_OPTS\t-Dhttp.proxyPassword=pw4q7 -Xmx1g\n"
               "ML\tline1\\nKEYFRAG9f3c=x\nPATH\t/bin\n")
    lines = awk_tool.run("envev", capture).rstrip("\n").split("\n")
    assert lines[-2:] == ["}", "n\tredacted\t2"], lines
    events = [line.split("\t", 2) for line in lines[:-2]]
    assert all(e[0] == "x" for e in events), events
    values = {e[1]: e[2] for e in events}
    assert list(values) == ["GH_TOKEN", "HOME", "MAVEN_OPTS", "ML", "PATH"]
    assert values["GH_TOKEN"] == PH
    assert "pw4q7" not in values["MAVEN_OPTS"] and "-Xmx1g" in values["MAVEN_OPTS"]
    assert values["ML"] == "line1\\nKEYFRAG9f3c=x"


def test_config_file_lines_mode_is_case_insensitive(awk_tool: AwkTool, tmp_path: Path) -> None:
    """apt writes Acquire::http::Proxy; the spec's match words are case-insensitive."""
    cfg = tmp_path / "apt.conf"
    cfg.write_text('Acquire::http::Proxy "http://p.corp:3128";\nAPT::Periodic "1";\n', encoding="ascii")
    doc = _render(awk_tool, ["{\t-", f"F\tlines\t{cfg.as_posix()}\t65536\tlines\tproxy|Verify-Peer", "}"])
    assert doc["lines"] == ['Acquire::http::Proxy "http://p.corp:3128";']


def test_config_file_at_the_byte_cap_is_complete(awk_tool: AwkTool, tmp_path: Path) -> None:
    cfg = tmp_path / "small.conf"
    cfg.write_bytes(b"a=1\nb=2")
    doc = _render(awk_tool, ["{\t-", f"F\tlines\t{cfg.as_posix()}\t7\tcontent\t-", "}"])
    assert doc["lines"] == ["a=1", "b=2"] and doc["truncated"] is False
    doc = _render(awk_tool, ["{\t-", f"F\tlines\t{cfg.as_posix()}\t6\tcontent\t-", "}"])
    assert doc["lines"] == ["a=1"] and doc["truncated"] is True


@pytest.mark.parametrize("content", [b"one\ntwo\nthree", b"one\ntwo\nthree\n", b"one\r\ntwo\r\nthree"])
def test_raw_output_keeps_the_last_line(awk_tool: AwkTool, tmp_path: Path, content: bytes) -> None:
    """The renderer caps raw output at the file size; a last line without a line break is kept."""
    raw = tmp_path / "out.txt"
    raw.write_bytes(content)
    doc = _render(awk_tool, ["{\t-", f"f\tout\t{raw.as_posix()}\t{len(content)}", "}"])
    assert doc["out"] == "one\ntwo\nthree"
    doc = _render(awk_tool, ["{\t-", f"f\tout\t{raw.as_posix()}\t9", "}"])
    assert doc["out"] == "one\ntwo\n[... truncated]"


@pytest.mark.parametrize("text, expected", [
    ("password: 'it''s Secr3tNine9' next", "password: '<redacted>' next"),
    ("password='a''b''c' tail", "password=<redacted> tail"),
    ("password: '' next", "password: '<redacted>' next"),
    ("password: 'abc' next", "password: '<redacted>' next"),
])
def test_doubled_single_quote_stays_inside_the_value(awk_tool: AwkTool, tmp_path: Path, text: str, expected: str) -> None:
    once = awk_tool.cases([("value", text)], tmp_path)[0]
    twice = awk_tool.cases([("value", once)], tmp_path)[0]
    assert "Secr3tNine9" not in once and "b'" not in once.replace("'<redacted>'", "")
    assert once == expected
    assert twice == once  # the redaction runs several passes


NEW_ROUND2 = [c for c in ALL if c.name in {
    "curl_user_value_single_quoted", "curl_user_value_double_quoted_space", "curl_user_whole_arg_quoted_space",
    "curl_user_doubled_single_quote", "option_shell_escaped_single_quote", "escaped_json_value_with_escaped_quote"}]


@pytest.mark.parametrize("case", NEW_ROUND2, ids=lambda c: c.name)
def test_round2_cases_are_stable_over_repeated_passes(awk_tool: AwkTool, tmp_path: Path, case: Case) -> None:
    op = FUNCTIONS[case.fn]
    once = awk_tool.cases([(op, *case.args)], tmp_path)[0]
    twice = awk_tool.cases([(op, once)], tmp_path)[0]
    assert twice == once, (once, twice)
    assert PH in once, once
