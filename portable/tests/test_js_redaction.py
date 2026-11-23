"""Secret redaction in the JScript port (src/js/14-redact*.js) under cscript.

Runs every shared redaction case (build/testdata/redaction.json, built from tests/redaction_cases.py:
shared, ps-only and sh-only cases), the ps hardening cases (tests/test_ps_redaction_hardening.py),
the data safety net, the log and the secret canaries of tests/conftest.py, and times the hostile
inputs of the ps hardening test (linear time under cscript).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import SECRET_CANARIES
from js_harness import HAVE_CSCRIPT, build_js, run_js
from shared_cases import redaction_cases
from test_ps_redaction_hardening import EXACT, HOSTILE

import target_js

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe")]

PH = "<redacted>"
CASES = redaction_cases()
OPS = {
    "Test-EsSecretName": "name", "Protect-EsValue": "value", "Protect-EsLine": "line", "Protect-EsText": "text",
    "Protect-EsCommandLine": "cmd", "Protect-EsNamedValue": "named", "Protect-TwiceValue": "twice_value",
    "Protect-TwiceLine": "twice_line", "Protect-TwiceCommandLine": "twice_cmd",
}
# Hostile inputs must finish in a few seconds each under cscript (ps1: 2 s under PowerShell).
LIMIT_MS = 4000

RUNNER = r"""
function jsTestOp(op, args) {
    switch (op) {
        case "name": return testEsSecretName(args[0]);
        case "value": return protectEsValue(args[0]);
        case "line": return protectEsLine(args[0]);
        case "text": return protectEsText(args[0]);
        case "cmd": return protectEsCommandLine(args[0]);
        case "named": return protectEsNamedValue(args[0], args[1]);
        case "twice_value": return protectEsValue(protectEsValue(args[0]));
        case "twice_line": return protectEsLine(protectEsLine(args[0]));
        case "twice_cmd": return protectEsCommandLine(protectEsCommandLine(args[0]));
    }
    throw new Error("unknown op " + op);
}
initializeEsRedaction();
var jsTestOut = {};
for (var jsI = 0; jsI < JS_TEST_CASES.length; jsI++) {
    var jsC = JS_TEST_CASES[jsI];
    try { jsTestOut[jsC.name] = jsTestOp(jsC.op, jsC.args); }
    catch (e) { jsTestOut[jsC.name] = "ERROR " + esErrorText(e); }
}
WScript.Echo(convertToEsJson(jsTestOut));
"""


@pytest.fixture(scope="module")
def lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_js(tmp_path_factory.mktemp("js-redact"))[1]


def run_snippet(lib: Path, snippet: str) -> Any:
    proc = run_js(lib, snippet)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def run_cases(lib: Path, cases: list[dict[str, Any]]) -> dict[str, Any]:
    literal = target_js.js_literal([{"name": c["name"], "op": c["op"], "args": c["args"]} for c in cases])
    return run_snippet(lib, f"var JS_TEST_CASES = {literal};\n{RUNNER}")


@pytest.fixture(scope="module")
def results(lib: Path) -> dict[str, Any]:
    hardening = [{"name": "hard_" + n, "op": OPS[fn], "args": [text]} for n, fn, text, _ in EXACT]
    return run_cases(lib, CASES + hardening)


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_shared_case(results: dict[str, Any], case: dict[str, Any]) -> None:
    actual = results[case["name"]]
    if case["exact"]:
        assert actual == case["expected"]
        return
    assert isinstance(actual, str) and actual and not actual.startswith("ERROR"), actual
    for secret in case["gone"]:
        assert secret not in actual, actual
    for fragment in case["kept"]:
        assert fragment in actual, actual


@pytest.mark.parametrize("name,fn,text,expected", EXACT, ids=[c[0] for c in EXACT])
def test_ps_hardening_case(results: dict[str, Any], name: str, fn: str, text: str, expected: str) -> None:
    assert results["hard_" + name] == expected


def test_every_case_was_run(results: dict[str, Any]) -> None:
    assert len(CASES) > 250
    assert all(c["name"] in results for c in CASES)


# ---------------------------------------------------------------- data, log, canaries

DATA_SNIPPET = r"""
initializeEsRedaction();
var jsOut = {};
jsOut.data_safety_net = protectEsData({
    conn: "Server=x;Password=abc123;",
    opts: ["MAVEN -Dfoo.password=zzz999", "plain value"],
    nested: { header: "X-Api-Key: key777key" },
    n: 5, flag: true, empty: null, when: new Date(0)
});
var jsDeep = "Server=x;Password=deep555;";
for (var jsI = 0; jsI < 35; jsI++) { jsDeep = { next: jsDeep }; }
jsOut.data_too_deep = convertToEsJson(protectEsData(jsDeep));
writeEsLog("run tool --token log444secret");
jsOut.log_line = ES_LOG[ES_LOG.length - 1];
jsOut.canary_env = protectEsTable(JS_CANARIES);
var jsValues = [];
for (var jsK in JS_CANARIES) { jsValues.push(jsK + "=" + JS_CANARIES[jsK]); }
// The safety net applies the value rules (not the name rules: tables go through protectEsTable).
jsOut.canary_data = protectEsData({ env: protectEsTable(JS_CANARIES), lines: jsValues });
jsOut.canary_cmd = protectEsCommandLine("app " + jsValues.join(" "));
jsOut.canary_text = protectEsText(jsValues.join("\n"));
jsOut.untouched = protectEsData({ a: "C:\\Program Files\\x", b: [1, "two"] });
ES_OPT.redact = false;
jsOut.off = protectEsValue("password=offsecret");
WScript.Echo(convertToEsJson(jsOut));
"""


@pytest.fixture(scope="module")
def data_results(lib: Path) -> dict[str, Any]:
    return run_snippet(lib, f"var JS_CANARIES = {target_js.js_literal(SECRET_CANARIES)};\n{DATA_SNIPPET}")


def test_data_safety_net(data_results: dict[str, Any]) -> None:
    data = data_results["data_safety_net"]
    flat = json.dumps(data)
    for secret in ("abc123", "zzz999", "key777key"):
        assert secret not in flat, flat
    assert "plain value" in data["opts"]
    assert data["n"] == 5 and data["flag"] is True and data["empty"] is None
    assert data["when"].startswith("1970-01-01T00:00:00")


def test_data_too_deep_is_redacted(data_results: dict[str, Any]) -> None:
    assert "deep555" not in data_results["data_too_deep"]
    assert PH in data_results["data_too_deep"]


def test_log_is_redacted(data_results: dict[str, Any]) -> None:
    assert "log444secret" not in data_results["log_line"]
    assert "run tool --token" in data_results["log_line"]


@pytest.mark.parametrize("key", ["canary_env", "canary_data", "canary_cmd", "canary_text"])
def test_secret_canaries_never_leak(data_results: dict[str, Any], key: str) -> None:
    from conftest import CANARY_VALUES
    flat = json.dumps(data_results[key])
    for secret in CANARY_VALUES:
        assert secret not in flat, (key, flat)
    assert "proxy.corp.example:8080" in flat


def test_plain_data_is_unchanged_and_redaction_can_be_off(data_results: dict[str, Any]) -> None:
    assert data_results["untouched"] == {"a": "C:\\Program Files\\x", "b": [1, "two"]}
    assert data_results["off"] == "password=offsecret"


# ---------------------------------------------------------------- run time on hostile input

TIMING_RUNNER = r"""
initializeEsRedaction();
var jsTimes = {};
for (var jsI = 0; jsI < JS_TEST_CASES.length; jsI++) {
    var jsC = JS_TEST_CASES[jsI];
    var jsStart = new Date();
    var jsR = String(jsTestOp(jsC.op, jsC.args));
    jsTimes[jsC.name] = { ms: new Date() - jsStart, length: jsC.args[0].length,
        result: jsR.length > 200 ? jsR.substring(0, 200) : jsR, result_length: jsR.length };
}
WScript.Echo(convertToEsJson(jsTimes));
"""


@pytest.fixture(scope="module")
def timings(lib: Path) -> dict[str, Any]:
    cases = [{"name": n, "op": OPS[fn], "args": [text]} for n, (fn, text) in HOSTILE.items()]
    literal = target_js.js_literal(cases)
    runner = RUNNER.split("initializeEsRedaction();")[0]
    return run_snippet(lib, f"var JS_TEST_CASES = {literal};\n{runner}{TIMING_RUNNER}")


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_input_runs_in_linear_time(timings: dict[str, Any], name: str) -> None:
    entry = timings[name]
    assert entry["ms"] < LIMIT_MS, f"{name}: {entry['ms']} ms for {entry['length']} chars"


def test_overlong_values_fail_closed(timings: dict[str, Any]) -> None:
    for name in ("overlong_value", "overlong_command_line", "overlong_line"):
        assert timings[name]["result"] == "<redacted: too long>", timings[name]


# ---------------------------------------------------------------- JScript-only xml cases (review 2026-11-15)

NL = "\n"
# (name, op, input, expected): ASCII-only lower-casing ("\u0130".toLowerCase() is "i" in JScript),
# ASCII-only blank tests, comments, quotes over several lines, the xml attribute pair rules.
JS_XML_EXACT = (
    ("js_xml_dotted_i_not_an_element", "line", "<pr\u0130vatekey>keep</pr\u0130vatekey>",
     "<pr\u0130vatekey>keep</pr\u0130vatekey>"),
    ("js_xml_dotted_i_before_tag", "line", "\u0130\u0130 <password>s3cret</password>", f"\u0130\u0130 <password>{PH}</password>"),
    ("js_xml_kelvin_not_an_element", "line", "<to\u212aen>keep</to\u212aen>", "<to\u212aen>keep</to\u212aen>"),
    ("js_xml_nbsp_rest_is_not_blank", "line", "<password>\u00a0\u3000", f"<password>{PH}"),
    ("js_xml_unterminated_comment_hides_close", "line", "<password>a<!-- </password>", f"<password>{PH}"),
    ("js_xml_comment_then_own_close", "line", "<token>a<!-- x --></b>c</token>z", f"<token>{PH}</token>z"),
    ("js_xml_next_close_when_no_own", "line", "<ns:token>a</other>tail", f"<ns:token>{PH}</other>tail"),
    ("js_xml_qname_with_attributes", "line", "<token:password a='1'>CanaryZ</token:password>",
     f"<token:password a='1'>{PH}</token:password>"),
    ("js_xml_qname_close_tag", "value", "</ns:clientSecret> </NS:ApiKey>", "</ns:clientSecret> </NS:ApiKey>"),
    ("js_xml_qname_local_part_not_secret", "line", "<token:hunter2 a='1'>", f"<token:{PH} a='1'>"),
    ("js_xml_key_colon_space_is_a_key", "value", "<password: s3cret", f"<password: {PH}"),
    # <token:x> is the element token for the xml rule, and "token:x" stays a key/value pair.
    ("js_xml_prefix_fallback_close", "line", "<token:x>a</token:x>", f"<token:{PH}>"),
    ("js_xml_self_closing_after_quoted_gt", "line", '<password a=">"/> tail', '<password a=">"/> tail'),
    ("js_xml_no_gt_line_mode_left_alone", "line", '<password a="x>y', '<password a="x>y'),
    ("js_xml_pair_value", "line", '<add key="db.password" value="s3cret"/>', f'<add key="db.password" value="{PH}"/>'),
    ("js_xml_urlkey_value", "line", '<add key="https://nuget.corp/v3" value="k3y"/>',
     f'<add key="https://nuget.corp/v3" value="{PH}"/>'),
    ("js_xml_text_quote_spans_lines", "text", NL.join(('<password a="x', '>y" b="1">CanaryQS', "</password>", "after")),
     NL.join(('<password a="x', '>y" b="1">' + PH, "</password>", "after"))),
    ("js_xml_text_split_tag_attribute_secret", "text", NL.join(("<token", '  password="CanaryAttr"', "  >", "  CanaryBody", "</token>", "ok")),
     NL.join(("<token", f"  password={PH}", "  >", f"  {PH}", "</token>", "ok"))),
    ("js_xml_text_close_line_rest_rescanned", "text", NL.join(("<token>", "q", "</token> password: CanaryRest")),
     NL.join(("<token>", PH, f"</token> password: {PH}"))),
    ("js_xml_text_nested_open_tag_in_body", "text", NL.join(("<password>", "  <token>", "  CanaryIn", "</password>", "kept")),
     NL.join(("<password>", f"  {PH}", f"  {PH}", "</password>", "kept"))),
)


@pytest.fixture(scope="module")
def js_xml_results(lib: Path) -> dict[str, Any]:
    return run_cases(lib, [{"name": n, "op": op, "args": [text]} for n, op, text, _ in JS_XML_EXACT])


@pytest.mark.parametrize("name,op,text,expected", JS_XML_EXACT, ids=[c[0] for c in JS_XML_EXACT])
def test_js_xml_case(js_xml_results: dict[str, Any], name: str, op: str, text: str, expected: str) -> None:
    assert js_xml_results[name] == expected


# Hostile xml lines (spec LENGTH CAP 131072): each must stay linear (X1i).
XML_SIZE = 120000
JS_XML_HOSTILE = {
    "xml_pair_key_no_quote": ("line", 'key="' + "password" * (XML_SIZE // 8)),
    "xml_pair_many_keys": ("line", '<add key="pass" ' * (XML_SIZE // 16)),
    "xml_urlkey_no_quote": ("line", '<add key="a://' * (XML_SIZE // 14)),
    "xml_attribute_no_quote": ("line", 'password="' * (XML_SIZE // 10)),
    "xml_distinct_prefixes": ("line", "".join(f"<p{i}:token>x</y>" for i in range(XML_SIZE // 18))),
    "xml_quoted_gt_runs": ("line", '<password a="' + '>"' * (XML_SIZE // 2)),
    "xml_open_quote_tags": ("line", '<password a="' * (XML_SIZE // 13)),
    "xml_comments": ("line", "<password>" + "<!-- </password> -->" * (XML_SIZE // 20)),
    "xml_open_comments": ("line", "<token>a" + "<!--" * (XML_SIZE // 4)),
    "xml_text_split_tags": ("text", "<password\n" * (XML_SIZE // 10)),
    "xml_text_quote_lines": ("text", '<password a="\n' + 'x>\n' * (XML_SIZE // 3)),
    "xml_text_close_rescan": ("text", "<token>\n" + "</token><token>\n" * (XML_SIZE // 16)),
}


@pytest.fixture(scope="module")
def js_xml_timings(lib: Path) -> dict[str, Any]:
    cases = [{"name": n, "op": op, "args": [text]} for n, (op, text) in JS_XML_HOSTILE.items()]
    runner = RUNNER.split("initializeEsRedaction();")[0]
    return run_snippet(lib, f"var JS_TEST_CASES = {target_js.js_literal(cases)};\n{runner}{TIMING_RUNNER}")


@pytest.mark.parametrize("name", sorted(JS_XML_HOSTILE))
def test_js_xml_hostile_input_is_linear(js_xml_timings: dict[str, Any], name: str) -> None:
    entry = js_xml_timings[name]
    assert entry["ms"] < LIMIT_MS, f"{name}: {entry['ms']} ms for {entry['length']} chars"


def test_shared_hostile_xml_cases_run_well_under_a_second(lib: Path) -> None:
    cases = [c for c in CASES if c["name"] in ("xml_hostile_lt_run", "xml_hostile_open_run")]
    runner = RUNNER.split("initializeEsRedaction();")[0]
    literal = target_js.js_literal([{"name": c["name"], "op": c["op"], "args": c["args"]} for c in cases])
    timings = run_snippet(lib, f"var JS_TEST_CASES = {literal};\n{runner}{TIMING_RUNNER}")
    assert len(timings) == 2
    for name, entry in timings.items():
        assert entry["ms"] < 1000, (name, entry["ms"])
