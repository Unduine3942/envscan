"""The Go engine (src/go engine_*, exec_*, sys_*, main.go): its Go unit tests, the source lint and the
development binary built from the engine files alone (no probes, no redaction or report services yet:
those come from other files of the port and are tested with the full tree)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import go_harness
import target_go
from conftest import PORTABLE
from go_harness import ENGINE_PREFIXES, HAVE_GO

pytestmark = pytest.mark.skipif(not HAVE_GO, reason="needs the go toolchain (ENVSCAN_GO or LOCALAPPDATA/envscan-dev/go)")

DASH = Path(r"C:\Program Files\Git\usr\bin\dash.exe")


@pytest.fixture(scope="module")
def engine_stage(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return go_harness.stage_prefixes(tmp_path_factory.mktemp("go-engine"), *ENGINE_PREFIXES)


@pytest.fixture(scope="module")
def dev_binary(engine_stage: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    return go_harness.build_dev_binary(engine_stage, tmp_path_factory.mktemp("go-bin"))


def test_go_unit_tests_pass(engine_stage: Path) -> None:
    proc = go_harness.go_cmd(engine_stage, "test", *go_harness.DEV_TAGS, "-count=1", ".")
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-2000:]


def test_build_without_dev_tag_never_scans(engine_stage: Path, tmp_path: Path) -> None:
    """Without the envscan_dev tag a non-Linux build has no test hooks and refuses to run (exit 2)."""
    if sys.platform != "win32":
        pytest.skip("the non-Linux build is checked on the Windows dev box")
    out = tmp_path / "envscan-nodev.exe"
    build = go_harness.go_cmd(engine_stage, "build", "-trimpath", "-buildvcs=false", "-o", str(out), ".")
    assert build.returncode == 0, build.stderr[-3000:]
    proc = subprocess.run([str(out), "--version"], env=go_harness.dev_env(go_harness.FIXTURES / "linux-basic"),
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "envscan runs on Linux; this build is for tests only" in proc.stderr


def test_go_vet_linux_and_host(engine_stage: Path) -> None:
    assert target_go.vet(go_harness.GO, engine_stage) == []


def test_go_lint_clean() -> None:
    assert target_go.lint_sources(PORTABLE / "src" / "go") == []


def test_version(dev_binary: Path, tmp_path: Path) -> None:
    proc = go_harness.run_dev(dev_binary, tmp_path, "--version")
    assert proc.returncode == 0
    assert proc.stdout == "envscan 1.0.0 (go)\n"


def test_list_probes_matches_sh_format(dev_binary: Path, tmp_path: Path) -> None:
    proc = go_harness.run_dev(dev_binary, tmp_path, "--list-probes")
    assert proc.returncode == 0
    lines = proc.stdout.splitlines()
    assert lines[0].startswith("os.identity  [default]  ")
    assert all(line.startswith("    - ") or "  [" in line for line in lines)
    if DASH.is_file():
        sh = subprocess.run([str(DASH), str(PORTABLE / "dist" / "envscan.sh"), "--list-probes"],
                            capture_output=True, text=True, timeout=60, check=False)
        sh_heads = [line.split("  [")[0] for line in sh.stdout.splitlines() if not line.startswith("    ")]
        go_heads = [line.split("  [")[0] for line in lines if not line.startswith("    ")]
        assert set(go_heads) <= set(sh_heads)


@pytest.mark.parametrize(("args", "message"), [
    (["--net=false"], "envscan: option --net takes no value"),
    (["--bogus"], "envscan: unknown argument: --bogus"),
    (["--only", "zz.*"], "envscan: --only: pattern 'zz.*' matches no probe"),
    (["--timeout", "0"], "envscan: --timeout needs a positive number of seconds"),
    (["--skip="], "envscan: --skip needs probe ids"),
])
def test_usage_errors(dev_binary: Path, tmp_path: Path, args: list[str], message: str) -> None:
    proc = go_harness.run_dev(dev_binary, tmp_path, *args)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert proc.stderr.startswith(message + "\nusage: envscan [options]")


def test_dev_binary_refuses_without_test_mode(dev_binary: Path, tmp_path: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("the refusal is a property of the non-Linux development build")
    proc = go_harness.run_dev(dev_binary, tmp_path, "--version", env={"ENVSCAN_TEST_OS": ""})
    assert proc.returncode == 2
    assert "ENVSCAN_TEST_OS=linux" in proc.stderr


def test_scan_without_probes_writes_a_report(dev_binary: Path, tmp_path: Path) -> None:
    """Engine files only: no probe is registered (error "probe function ... is missing") and no
    redaction is linked, so the scan runs with --no-redact; findings, Markdown and brief fail softly."""
    proc = go_harness.run_dev(dev_binary, tmp_path, "--no-redact", "--only", "os.identity,os.health")
    assert proc.returncode == 1, proc.stderr
    out = Path(proc.stdout.strip())
    assert proc.stdout.count("\n") == 1 and out.parent == tmp_path
    assert sorted(p.name for p in out.iterdir()) == ["AGENT_BRIEF.md", "envscan.json", "envscan.log", "envscan.md"]
    raw = (out / "envscan.json").read_bytes()
    assert max(raw) < 0x80
    doc = json.loads(raw)
    assert list(doc) == ["schema", "scanner", "run", "host", "findings", "probes"]
    assert doc["scanner"]["impl"] == "go"
    assert doc["run"]["redaction"] is False and doc["run"]["exit_code"] == 1
    assert doc["run"]["test_root"].endswith("linux-basic")
    ident = doc["probes"]["os.identity"]
    assert ident["status"] == "error" and ident["error"] == "probe function probe_os_identity is missing"
    assert doc["probes"]["os.time_locale"]["notes"] == ["not selected by --only"]
    log = (out / "envscan.log").read_text(encoding="utf-8")
    assert log.splitlines()[-1] == "exit code 1"
