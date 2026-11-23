"""envscan.js entry (src/js/90-main.js, 99-entry.js): options, exit codes and the launcher offset,
--list-probes, and one whole scan validated against the schema.

The whole-scan test uses every module; it passes once every probe function exists (a missing one
is recorded as status error "not implemented", which the test reports by name).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import (CANARY_VALUES, SECRET_CANARIES, all_output_text, canary_hits, expected_probe_listing,
                      find_output, load_report, schema_errors, scrubbed_env)
from js_harness import HAVE_CSCRIPT, PORTABLE, build_js, engine_only, js_registry, run_script
from spec import load_spec

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

SPEC = load_spec(PORTABLE / "spec", js_registry())
VERSION = SPEC.version


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_js(tmp_path_factory.mktemp("jsentry"), engine_only)[0]


@pytest.fixture(scope="module")
def full(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_js(tmp_path_factory.mktemp("jsfull"))[0]


def test_version_help_and_list(engine: Path) -> None:
    version = run_script(engine, "--version")
    assert (version.returncode, version.stdout, version.stderr) == (0, f"envscan {VERSION} (jscript)\n", "")
    usage = run_script(engine, "-h")
    assert usage.returncode == 0 and usage.stdout.startswith("Usage: ") and "--list-probes" in usage.stdout
    listing = run_script(engine, "--list-probes")
    assert listing.returncode == 0 and listing.stderr == ""
    assert listing.stdout.splitlines() == expected_probe_listing(SPEC, "js")


@pytest.mark.parametrize("args, message", [
    (["--net=false"], "option --net takes no value"),
    (["--deep=0"], "option --deep takes no value"),
    (["--no-redact=false"], "option --no-redact takes no value"),
    (["-version=1"], "option --version takes no value"),
    (["--help=yes"], "option --help takes no value"),
    (["--list-probes=1"], "option --list-probes takes no value"),
    (["-h=1"], "option --h takes no value"),
    (["--only", "os.ident[ity"], "--only: invalid pattern 'os.ident[ity' (allowed: letters, digits, . _ - *)"),
    (["--only", "nosuch.*"], "--only: pattern 'nosuch.*' matches no probe"),
    (["--skip=os.identity,bad?"], "--skip: invalid pattern 'bad?' (allowed: letters, digits, . _ - *)"),
    (["--only", "os identity"], "--only: invalid pattern 'os identity' (allowed: letters, digits, . _ - *)"),
    (["--only", ""], "--only needs probe ids"),
    (["--only=,"], "--only needs probe ids"),
    (["--skip", " , "], "--skip needs probe ids"),
    (["--timeout", "0"], "--timeout must be 1-3600 seconds: 0"),
    (["--budget=5"], "--budget must be 10-86400 seconds: 5"),
    (["--timeout"], "missing value for --timeout"),
    (["--frobnicate"], "unknown option: --frobnicate"),
    (["stray"], "unexpected argument: stray"),
])
def test_argument_errors_exit_2(engine: Path, args: list[str], message: str) -> None:
    proc = run_script(engine, *args)
    assert proc.returncode == 2 and proc.stdout == ""
    lines = proc.stderr.splitlines()
    assert lines[0] == "envscan: " + message and "Usage: " in proc.stderr


@pytest.mark.parametrize("value, version_code, error_code", [("100", 100, 102), ("5", 0, 2), ("", 0, 2), ("0100", 0, 2)])
def test_launcher_exit_offset(engine: Path, value: str, version_code: int, error_code: int) -> None:
    env = {**os.environ, "__ES_EXIT_BASE": value}
    assert run_script(engine, "--version", env=env).returncode == version_code
    assert run_script(engine, "--bogus", env=env).returncode == error_code


def test_exit_base_is_removed_before_any_child(engine: Path, tmp_path: Path) -> None:
    text = engine.read_text(encoding="ascii")
    probe = text.replace("WScript.Quit(invokeEsEntry());",
                         "var b = readEsExitBase(); WScript.Echo(b + ' ' + (getEsEnv('__ES_EXIT_BASE') === null));"
                         " var c = ES_SHELL.Exec(getEsSystemTool('cmd.exe') + ' /d /c set __ES_');"
                         " while (c.Status === 0) { WScript.Sleep(20); } WScript.Echo('[' + c.StdOut.ReadAll() + ']');")
    script = tmp_path / "entry-probe.js"
    script.write_bytes(probe.encode("ascii"))
    proc = run_script(script, env={**os.environ, "__ES_EXIT_BASE": "100"})
    assert proc.stdout.splitlines()[:2] == ["100 true", "[]"], proc.stdout + proc.stderr


def test_whole_scan(full: Path, tmp_path: Path) -> None:
    out, temp = tmp_path / "out", tmp_path / "temp"
    out.mkdir()
    temp.mkdir()
    env = {**scrubbed_env(), **SECRET_CANARIES, "TEMP": str(temp), "TMP": str(temp)}
    proc = run_script(full, "--out", str(out), env=env, timeout=900)
    assert proc.returncode in (0, 1), proc.stderr
    folder = find_output(out)
    assert proc.stdout.splitlines() == [str(folder)]
    assert sorted(p.name for p in folder.iterdir()) == ["AGENT_BRIEF.md", "envscan.json", "envscan.log", "envscan.md"]
    report = load_report(folder)
    assert schema_errors(report) == []
    assert report["scanner"]["impl"] == "jscript" and report["host"]["os_family"] == "windows"
    assert list(report["probes"]) == [p["id"] for p in SPEC.probes_for("js")]
    missing = [pid for pid, env_ in report["probes"].items() if env_.get("error") == "not implemented"]
    assert missing == [], f"probe functions not implemented yet: {missing}"
    assert report["run"]["exit_code"] == proc.returncode
    assert "[ 1/" in proc.stderr or "[1/" in proc.stderr
    assert canary_hits([all_output_text(folder)], CANARY_VALUES) == []
    assert [p.name for p in temp.iterdir() if p.name.startswith("envscan-")] == [], "scanner temp folder left behind"
