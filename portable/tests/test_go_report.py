"""Go port of the findings, envscan.md and AGENT_BRIEF.md (src/go/report_*.go).

Stages the report files (plus the shared api_*/testenv_* files and spec.json) into a pytest tmp
folder and runs their Go tests: the golden findings cases (tests/data/findings_cases.json, the sh
expectations) and the Markdown/brief layout tables. Skipped when no Go toolchain is installed.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import target_go
from conftest import PORTABLE
from spec import load_spec

FINDINGS_CASES = PORTABLE / "tests" / "data" / "findings_cases.json"


@pytest.fixture(scope="module")
def go() -> Path:
    try:
        return target_go.find_go()
    except target_go.GoMissing as exc:
        pytest.skip(str(exc))


@pytest.mark.integration
def test_go_report(go: Path, tmp_path: Path) -> None:
    staged = target_go.stage(load_spec(PORTABLE / "spec"), PORTABLE / "src" / "go", tmp_path / "go-report", ["report_"])
    env = target_go.go_env("", "", {"ENVSCAN_TESTDATA_FINDINGS": str(FINDINGS_CASES)})
    for key in ("GOOS", "GOARCH"):
        env.pop(key)
    proc = subprocess.run([str(go), "test", "-count=1", "-run", "Finding|Render|Brief", "."], cwd=staged, env=env,
                          capture_output=True, text=True, timeout=target_go.BUILD_TIMEOUT, check=False)
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-4000:]
    assert "ok" in proc.stdout


@pytest.mark.unit
def test_go_report_sources_pass_lint() -> None:
    errors = [e for e in target_go.lint_sources(PORTABLE / "src" / "go") if e.startswith("report_")]
    assert errors == []
