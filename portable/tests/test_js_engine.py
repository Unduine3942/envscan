"""Engine of envscan.js (src/js/10-core.js, 12-runner.js): JSON writer parity with the ps1
ConvertTo-EsJson, utilities, time, environment, arguments and the probe runner.

The library is built from the engine modules only (js_harness.engine_only), so these tests do not
depend on the probe, helper and renderer modules.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import HAVE_POWERSHELL, ps_eval
from js_harness import HAVE_CSCRIPT, build_js, engine_only, run_js

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

MARK = "----8<----"


@pytest.fixture(scope="module")
def lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_js(tmp_path_factory.mktemp("jsengine"), engine_only)[1]


def js_eval(lib: Path, snippet: str, *args: str, env: dict[str, str] | None = None) -> str:
    proc = run_js(lib, snippet, *args, env=env)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return proc.stdout.replace("\r\n", "\n")


# ------------------------------------------------------------------ value literals for both languages

class Ordered(dict):
    """A table with __order (emitted first by both writers)."""

    def __init__(self, order: list[str], **items: Any) -> None:
        super().__init__(items)
        self.order = order


def _units(text: str) -> list[str]:
    """UTF-16 code units (surrogate pairs apart), as both scripting languages see the string."""
    data = text.encode("utf-16-le", "surrogatepass")
    return [chr(int.from_bytes(data[i:i + 2], "little")) for i in range(0, len(data), 2)]


def _ps_string(text: str) -> str:
    parts, plain = [], ""
    for ch in _units(text):
        if 0x20 <= ord(ch) <= 0x7E:
            plain += ch.replace("'", "''")
            continue
        if plain:
            parts.append(f"'{plain}'")
            plain = ""
        parts.append(f"[string][char]{ord(ch)}")
    if plain or not parts:
        parts.append(f"'{plain}'")
    return "(" + " + ".join(parts) + ")"


def ps_value(value: Any) -> str:
    if value is None:
        return "$null"
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, int):
        return str(value) if -2**31 <= value < 2**31 else f"[long]{value}"
    if isinstance(value, float):
        return f"[double]{value!r}"
    if isinstance(value, str):
        return _ps_string(value)
    if isinstance(value, dt.datetime):
        return f"([datetime]'{value.strftime('%Y-%m-%dT%H:%M:%SZ')}')"
    if isinstance(value, dict):
        items = [f"{_ps_string(k)} = {ps_value(v)}" for k, v in value.items()]
        if isinstance(value, Ordered):
            items.append("'__order' = " + ps_value(list(value.order)))
        return "@{" + "; ".join(items) + "}"
    if not value:
        return "@()"
    if len(value) == 1:
        return f"@(,{ps_value(value[0])})"
    return "@(" + ", ".join(ps_value(v) for v in value) + ")"


def js_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return "".join(["\"", *(ch if 0x20 <= ord(ch) <= 0x7E and ch not in "\"\\" else f"\\u{ord(ch):04x}"
                                for ch in _units(value)), "\""])
    if isinstance(value, dt.datetime):
        v = value
        return f"new Date(Date.UTC({v.year}, {v.month - 1}, {v.day}, {v.hour}, {v.minute}, {v.second}))"
    if isinstance(value, dict):
        items = [f"{js_value(k)}: {js_value(v)}" for k, v in value.items()]
        if isinstance(value, Ordered):
            items.append("\"__order\": " + js_value(list(value.order)))
        return "{" + ", ".join(items) + "}"
    return "[" + ", ".join(js_value(v) for v in value) + "]"


LONG = "x" * 120
CASES: list[Any] = [
    "plain",
    'quote" back\\ slash',
    "caf\u00e9 \u65e5 \U0001f600",
    "tab\tnl\ncr\r\u0001\u007f",
    None, True, False, 42, -7, 1234567890123, 1.5, 0,
    [], {}, ["only"], [1, 2, 3], [[1, 2], "x"], [{"a": 1}, [1, 2], "x"],
    list(range(1, 41)), [LONG], ["a" * 30, "b" * 30, "c" * 30, "d" * 30],
    list(range(1, 13)), list(range(1, 14)),
    {"list": list(range(1, 41)), "empty": [], "obj": {}, "nested": {"deep": {"deeper": [None, True]}}},
    Ordered(["z", "a", "missing"], m=1, a=2, b=3, z=4),
    Ordered(["status", "data"], status="ok", data={"k": "v\n"}, notes=["n1", "n2"], raw={"label": "t\u00e9xt"}),
    {"key with space": 1, "quote\"key": 2, "nl\nkey": 3},
    [dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)],
    {"when": dt.datetime(2026, 11, 13, 23, 59, 58, tzinfo=dt.timezone.utc)},
]


def test_json_writer_matches_ps(lib: Path, built: Path) -> None:
    if not HAVE_POWERSHELL:
        pytest.skip("needs Windows PowerShell for the reference writer")
    js_lines = [f"WScript.Echo(convertToEsJson({js_value(case)})); WScript.Echo(\"{MARK}\");" for case in CASES]
    js_out = js_eval(lib, "\n".join(js_lines)).split(MARK + "\n")
    ps_expr = "; ".join(f"ConvertTo-EsJson ({ps_value(case)}); '{MARK}'" for case in CASES)
    proc = ps_eval(built / "build" / "lib" / "envscan-lib.ps1", ps_expr)
    assert proc.returncode == 0, proc.stderr
    ps_out = proc.stdout.replace("\r\n", "\n").split(MARK + "\n")
    assert len(js_out) == len(CASES) + 1
    for case, js_text, ps_text in zip(CASES, js_out, ps_out):
        assert js_text == ps_text, f"case {case!r}"


def test_json_round_trips(lib: Path) -> None:
    out = js_eval(lib, "\n".join(f"WScript.Echo(convertToEsJson({js_value(c)})); WScript.Echo(\"{MARK}\");"
                                 for c in CASES)).split(MARK + "\n")
    for case, text in zip(CASES, out):
        text.encode("ascii")
        if isinstance(case, (dict, list)) and not any(isinstance(x, dt.datetime) for x in
                                                      (case.values() if isinstance(case, dict) else case)):
            loaded = json.loads(text)
            expected = {k: v for k, v in case.items()} if isinstance(case, dict) else case
            assert loaded == expected


def test_json_order_and_special_numbers(lib: Path) -> None:
    out = js_eval(lib, 'WScript.Echo(convertToEsJson({b: 0/0, a: 1/0, __order: ["b"]}));')
    assert out == '{\n  "b": null,\n  "a": null\n}\n'


# ------------------------------------------------------------------ utilities and time

def test_utilities(lib: Path) -> None:
    snippet = r"""
var o = [];
o.push(esIndexOf(["a", "b"], "b"), esIndexOf(["a"], "A"), esContains([1, 2], 2), esContainsI(["Path"], "PATH"));
o.push(esKeys({b: 1, a: 2, B: 3}).join("|"), "[" + esTrim("  x y \t") + "]", esStartsWith("abc", "ab"));
o.push(esEndsWithI("File.EXE", ".exe"), esLower("AbC"), esPad2(7), esPad4(26));
o.push(esJoinPath("C:\\", "x"), esJoinPath("C:\\a", "\\b"), esJoinPath("C:\\a\\", "b"));
o.push(esIsDir(getEsEnv("SystemRoot")), esIsFile(getEsEnv("SystemRoot")), esPathExists(getEsEnv("SystemRoot") + "\\System32\\cmd.exe"));
WScript.Echo(o.join(","));
"""
    out = js_eval(lib, snippet).strip()
    assert out == ("1,-1,true,true,B|a|b,[x y],true,true,abc,07,0026,C:\\x,C:\\a\\b,C:\\a\\b,"
                   "true,false,true")


def test_time_functions(lib: Path) -> None:
    snippet = r"""
var d = new Date(Date.UTC(2026, 0, 2, 3, 4, 5));
WScript.Echo(formatEsUtc(d) + "|" + formatEsStamp(d) + "|" + formatEsUtc(null));
WScript.Echo(formatEsUtc(convertFromEsCimDate("20261030023208.500000+540")));
WScript.Echo(formatEsUtc(convertFromEsCimDate("20261030023208.500000-060")));
WScript.Echo(convertFromEsCimDate("garbage") === null ? "null" : "x");
WScript.Echo(getEsElapsedMs(new Date(new Date().getTime() + 100000)));
"""
    lines = js_eval(lib, snippet).splitlines()
    assert lines == ["2026-01-02T03:04:05Z|20260102T030405Z|null", "2026-10-29T17:32:08Z",
                     "2026-10-30T03:32:08Z", "null", "0"]


def test_environment(lib: Path) -> None:
    snippet = r"""
saveEsEnvSnapshot();
var out = [getEsEnv("es_test_one"), getEsEnv("ES_TEST_MISSING") === null];
var spelled = ES_ENV_SNAPSHOT_NAMES["es_test_one"];
out.push(spelled, ES_ENV_SNAPSHOT[spelled]);
ES_CHILD_ENV = {"ES_TEST_ONE": "child", "ES_TEST_GONE": ""};
enterEsChildEnv();
out.push(getEsEnv("ES_TEST_ONE"), getEsEnv("ES_TEST_GONE") === null);
exitEsChildEnv();
out.push(getEsEnv("ES_TEST_ONE"), getEsEnv("ES_TEST_GONE"));
WScript.Echo(out.join(","));
"""
    import os
    env = {**os.environ, "Es_Test_One": "v1", "ES_TEST_GONE": "kept"}
    assert js_eval(lib, snippet, env=env).strip() == "v1,true,Es_Test_One,v1,child,true,v1,kept"


def test_log_and_text_file(lib: Path, tmp_path: Path) -> None:
    target = tmp_path / "out.md"
    snippet = f"""
writeEsLog("hello");
writeEsTextFile({js_value(str(target))}, "a\\nb caf\\u00e9\\r\\nc");
var again = "no";
try {{ writeEsTextFile({js_value(str(target))}, "x"); }} catch (e) {{ again = "refused"; }}
WScript.Echo(ES_LOG.length + " " + /^\\d{{4}}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ hello$/.test(ES_LOG[0]) + " " + again);
"""
    assert js_eval(lib, snippet).strip() == "1 true refused"
    assert target.read_bytes() == b"a\r\nb caf?\r\nc\r\n"
