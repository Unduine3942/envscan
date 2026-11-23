"""tests/schema_check.py and the report helpers in conftest must reject what strict JSON
and a real JSON Schema validator reject, so a broken report can never pass a scan test."""
from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    CANARY_VALUES,
    DASH,
    SCHEMA,
    all_output_text,
    canary_hits,
    load_report,
    ps_quote,
    run_sh,
    schema_errors,
    scrubbed_env,
)
from schema_check import SchemaError, validate
from spec import REGISTRY

pytestmark = pytest.mark.unit

STATUSES = ("ok", "partial", "not_found", "not_applicable", "denied", "timeout", "error", "skipped")


def _report() -> dict[str, Any]:
    """A minimal report that satisfies schema/envscan.schema.json."""
    return {
        "schema": "envscan/1",
        "scanner": {"name": "envscan", "version": "1.0.0", "impl": REGISTRY[0].report_impl, "shell_version": "5.1"},
        "run": {
            "started_utc": "2026-11-11T10:15:00Z", "finished_utc": "2026-11-11T10:16:00Z", "duration_ms": 60000,
            "tiers": ["default"], "flags": [], "cwd": "C:\\", "out_dir": "C:\\out", "exit_code": 0,
            "redaction": True, "counts": {status: 0 for status in STATUSES},
        },
        "host": {"os_family": "windows", "os_name": "Windows 11", "os_version": "10.0", "arch": "x86_64",
                 "hostname": "host"},
        "findings": [],
        "probes": {"os.identity": {"status": "ok", "tier": "default", "scope": "machine", "title": "OS",
                                   "sources": [], "duration_ms": 1, "data": {}}},
    }


def _set(path: tuple[Any, ...], value: Any) -> Callable[[dict[str, Any]], None]:
    def change(report: dict[str, Any]) -> None:
        target = report
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return change


def _delete(path: tuple[Any, ...]) -> Callable[[dict[str, Any]], None]:
    def change(report: dict[str, Any]) -> None:
        target = report
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]
    return change


PROBE = ("probes", "os.identity")
INVALID_REPORTS: dict[str, tuple[Callable[[dict[str, Any]], None], str]] = {
    "missing required key": (_delete(("host",)), "missing required 'host'"),
    "extra property": (_set(("run", "extra"), 1), "unexpected property 'extra'"),
    "wrong enum value": (_set(("host", "arch"), "amd64"), "'amd64' not in"),
    "False as an integer exit code": (_set(("run", "exit_code"), False), "$.run.exit_code: False not in"),
    "True as an integer exit code": (_set(("run", "exit_code"), True), "$.run.exit_code: True not in"),
    "boolean as an integer": (_set(("run", "duration_ms"), True), "expected type integer"),
    "float as an integer": (_set(("run", "duration_ms"), 1.5), "expected type integer"),
    "pattern with a trailing newline": (_set(("scanner", "version"), "1.0.0\n"), "does not match"),
    "non-ASCII digit in a pattern": (_set(("scanner", "version"), "1.0.\u0663"), "does not match"),
    "wrong const": (_set(("schema",), "envscan/2"), "expected 'envscan/1'"),
    "below minimum": (_set(("run", "duration_ms"), -1), "< minimum 0"),
    "probe status through $ref": (_set((*PROBE, "status"), "fine"), "$.probes.os.identity.status"),
    "probe without data through $ref": (_delete((*PROBE, "data")), "missing required 'data'"),
    "raw value that is not a string": (_set((*PROBE, "raw"), {"label": 1}), "$.probes.os.identity.raw.label"),
}


def test_minimal_report_is_valid() -> None:
    assert schema_errors(_report()) == []


@pytest.mark.parametrize("name", sorted(INVALID_REPORTS))
def test_invalid_reports_are_rejected(name: str) -> None:
    change, expected = INVALID_REPORTS[name]
    report = copy.deepcopy(_report())
    change(report)
    errors = schema_errors(report)
    assert any(expected in error for error in errors), errors


# ------------------------------------------------------------------ validator semantics

@pytest.mark.parametrize("schema", [
    {"type": "string", "minLength": 1},
    {"properties": {"unused": {"format": "date-time"}}},
    {"$defs": {"unused": {"oneOf": [{"type": "string"}]}}},
    {"items": [{"type": "string"}]},
    {"type": "text"},
])
def test_unsupported_schema_raises_even_when_unused(schema: dict[str, Any]) -> None:
    with pytest.raises(SchemaError):
        validate({}, schema)


def test_chained_refs_are_followed() -> None:
    schema = {"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"type": "integer", "minimum": 1}}, "$ref": "#/$defs/a"}
    assert validate(3, schema) == []
    assert validate(0, schema) != []
    assert validate("3", schema) != []
    assert validate(True, schema) != []


def test_keywords_next_to_a_ref_apply_too() -> None:
    schema = {"$defs": {"s": {"type": "string"}}, "$ref": "#/$defs/s", "enum": ["y"]}
    assert validate("y", schema) == []
    assert validate("x", schema) != []


def test_missing_definition_and_ref_cycles_raise() -> None:
    with pytest.raises(SchemaError, match="no definition 'nope'"):
        validate(1, {"$ref": "#/$defs/nope"})
    with pytest.raises(SchemaError, match="no definition 'gone'"):
        validate({}, {"properties": {"unused": {"$ref": "#/$defs/gone"}}})
    with pytest.raises(SchemaError, match="cycle"):
        validate(1, {"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}}, "$ref": "#/$defs/a"})
    with pytest.raises(SchemaError, match="unsupported \\$ref"):
        validate(1, {"$ref": "other.json#/x"})


@pytest.mark.parametrize("value, schema", [
    (0, {"const": False}), (False, {"const": 0}), (1, {"const": True}), (True, {"const": 1}),
    (1, {"enum": [True]}), (True, {"enum": [1, 2]}), ([0], {"const": [False]}), ({"a": 1}, {"const": {"a": True}}),
    (None, {"enum": [0, False, ""]}), ("1", {"enum": [1]}),
])
def test_enum_and_const_never_mix_booleans_and_numbers(value: Any, schema: dict[str, Any]) -> None:
    assert validate(value, schema) != []


def test_enum_and_const_compare_numbers_by_value() -> None:
    assert validate(1.0, {"enum": [1]}) == []
    assert validate([1, {"a": False}], {"const": [1.0, {"a": False}]}) == []


@pytest.mark.parametrize("pattern, value, ok", [
    ("^abc$", "abc", True), ("^abc$", "abc\n", False), ("abc$", "xabc\n", False), ("^[$]$", "$", True),
    ("^a\\$$", "a$", True), ("^[0-9]+$", "12", True), ("^\\d+$", "1\u0663", False), ("^(a|b$)", "b\n", False),
])
def test_patterns_use_ecma_anchors(pattern: str, value: str, ok: bool) -> None:
    assert (validate(value, {"type": "string", "pattern": pattern}) == []) is ok


def test_boolean_schemas() -> None:
    assert validate({"a": 1}, {"properties": {"a": True}, "additionalProperties": False}) == []
    assert validate({"a": 1}, {"properties": {"a": False}}) != []
    assert validate({"b": 1}, {"additionalProperties": False}) != []


def test_real_schema_uses_only_supported_keywords() -> None:
    validate(_report(), SCHEMA)  # raises SchemaError otherwise


# ------------------------------------------------------------------ strict report loading

def _write(folder: Path, text: str) -> Path:
    (folder / "envscan.json").write_bytes(text.encode("utf-8"))
    return folder


@pytest.mark.parametrize("text, message", [
    ('{"a": NaN}', "NaN"),
    ('{"a": Infinity}', "Infinity"),
    ('{"a": [-Infinity]}', "-Infinity"),
    ('{"a": 1, "a": 2}', "repeats key"),
    ('{"outer": {"k": 1, "k": 1}}', "repeats key"),
])
def test_load_report_rejects_non_standard_json(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_report(_write(tmp_path, text))


def test_load_report_rejects_non_ascii_and_accepts_plain_json(tmp_path: Path) -> None:
    with pytest.raises(UnicodeDecodeError):
        load_report(_write(tmp_path, '{"a": "caf\u00e9"}'))
    assert load_report(_write(tmp_path, '{"a": [1, 2.5, null, true], "b": "\\u00e9"}')) == {
        "a": [1, 2.5, None, True], "b": "\u00e9"}


# ------------------------------------------------------------------ output text and canaries

def test_output_text_is_decoded_by_bom(tmp_path: Path) -> None:
    canary = CANARY_VALUES[0]
    (tmp_path / "utf16le.md").write_bytes("\ufeff".encode("utf-16-le") + f"x {canary}".encode("utf-16-le"))
    (tmp_path / "utf16be.md").write_bytes("\ufeff".encode("utf-16-be") + "be-text".encode("utf-16-be"))
    (tmp_path / "utf8bom.md").write_bytes(b"\xef\xbb\xbfbom-text")
    text = all_output_text(tmp_path)
    assert canary in text and "be-text" in text and "bom-text" in text and "\ufeff" not in text


@pytest.mark.parametrize("encode", [
    lambda s: s.encode("utf-16-le"), lambda s: s.encode("utf-16-be"), lambda s: s.encode("utf-32-le"),
    lambda s: s.encode("ascii"),
])
def test_canaries_are_found_in_any_encoding_even_without_bom(tmp_path: Path, encode: Callable[[str], bytes]) -> None:
    (tmp_path / "out.log").write_bytes(encode(f"value={CANARY_VALUES[1]};"))
    assert canary_hits([all_output_text(tmp_path)]) == [CANARY_VALUES[1]]


def test_canaries_are_searched_in_every_text() -> None:
    assert canary_hits(["clean", f"stderr: {CANARY_VALUES[2]}"]) == [CANARY_VALUES[2]]
    assert canary_hits(["clean", "also clean"]) == []


# ------------------------------------------------------------------ PowerShell quoting and environment

@pytest.mark.parametrize("text, quoted", [
    ("plain", "'plain'"),
    ("it's", "'it''s'"),
    ("C:\\Users\\O'Brien\\x", "'C:\\Users\\O''Brien\\x'"),
    ("a\u2019b\u2018c", "'a\u2019\u2019b\u2018\u2018c'"),
    ("low\u201aand\u201b", "'low\u201a\u201aand\u201b\u201b'"),
])
def test_ps_quote_doubles_every_quote_powershell_accepts(text: str, quoted: str) -> None:
    assert ps_quote(text) == quoted
    assert ps_quote(Path("C:/a'b")) == ps_quote(str(Path("C:/a'b")))


def test_scrubbed_env_drops_session_secrets_and_keeps_windows() -> None:
    base = {
        "PATH": "C:\\Windows", "SYSTEMROOT": "C:\\Windows", "TEMP": "C:\\t", "USERPROFILE": "C:\\u",
        "PSMODULEPATH": "m", "PROCESSOR_IDENTIFIER": "x", "JAVA_HOME": "C:\\jdk", "KEYBOARD_LAYOUT": "us",
        "HTTPS_PROXY": "http://p:1", "no_proxy": "localhost", "NPM_CONFIG_USERCONFIG": "C:\\npmrc",
        "PIP_INDEX_URL": "https://m/simple", "GIT_CONFIG_GLOBAL": "C:\\g", "GIT_ASKPASS": "x", "GOPROXY": "https://g",
        "GITHUB_TOKEN": "t", "MY_API_KEY": "k", "DB_PASSWORD": "p", "GH_PAT_VALUE": "v", "AWS_SECRET_ACCESS_KEY": "s",
        "NODE_EXTRA_CA_CERTS": "C:\\ca.pem", "ENVSCAN_ROOT": "C:\\fixture",
    }
    kept = scrubbed_env(base)
    assert set(kept) == {"PATH", "SYSTEMROOT", "TEMP", "USERPROFILE", "PSMODULEPATH", "PROCESSOR_IDENTIFIER",
                         "JAVA_HOME", "KEYBOARD_LAYOUT"}
    assert "HTTPS_PROXY" in base  # the input is not modified


# ------------------------------------------------------------------ implementation and platform enums

def test_every_registered_report_impl_is_valid_in_the_schema() -> None:
    reporting = [impl for impl in REGISTRY if impl.report_impl]
    assert {impl.id for impl in reporting} >= {"ps", "sh"}
    for impl in reporting:
        report = _report()
        report["scanner"]["impl"] = impl.report_impl
        assert schema_errors(report) == [], impl.id


@pytest.mark.parametrize("impl", ["jscript", "go"])
def test_schema_accepts_the_script_host_and_binary_impls(impl: str) -> None:
    report = _report()
    report["scanner"]["impl"] = impl
    assert schema_errors(report) == []


@pytest.mark.parametrize("os_family, arch", [("zos", "s390x"), ("os400", "ppc64"), ("aix", "ppc64")])
def test_schema_accepts_mainframe_families_and_arches(os_family: str, arch: str) -> None:
    report = _report()
    report["host"]["os_family"], report["host"]["arch"] = os_family, arch
    assert schema_errors(report) == []


def test_schema_still_rejects_an_unknown_impl_and_family() -> None:
    for path, value in ((("scanner", "impl"), "python"), (("host", "os_family"), "beos")):
        report = _report()
        _set(path, value)(report)
        assert schema_errors(report), value


@pytest.mark.skipif(not DASH.exists(), reason="Git for Windows dash not found")
def test_run_sh_scrubs_session_secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_API_KEY", "canary-sh-1")
    monkeypatch.setenv("HTTP_PROXY", "http://u:canary-sh-2@proxy:1")
    script = tmp_path / "dump.sh"
    script.write_text('printf "%s|%s|%s|%s\\n" "$ENVSCAN_TEST_VALUE" "$MY_API_KEY" "$HTTP_PROXY" "${PATH:+path}"\n',
                      encoding="ascii")
    proc = run_sh(DASH, script, env={"ENVSCAN_TEST_VALUE": "kept"})
    assert proc.returncode == 0, proc.stderr
    # an explicit override survives, session secrets are gone, PATH stays
    assert proc.stdout.strip() == "kept|||path"
