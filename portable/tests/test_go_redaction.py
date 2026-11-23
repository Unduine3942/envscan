"""The Go port of redact.awk and proxy.awk (src/go/redact_*.go, proxy_*.go) against the shared
cases: the files are staged into a pytest tmp folder with their test data in ../testdata (written
by tests/shared_cases.py), then `go test -run 'Redact|Proxy|Secret' .` runs there. Skipped when
no go toolchain is found (tools/target_go.find_go).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from conftest import PORTABLE

import shared_cases
import target_go
from spec import load_spec

PREFIXES = ("redact_", "proxy_")
GO_TEST_TIMEOUT = 900


def go_or_skip() -> Path:
    try:
        return target_go.find_go()
    except target_go.GoMissing as exc:
        pytest.skip(f"no go toolchain: {exc}")


def go_test_env(testdata: Path) -> dict[str, str]:
    """The environment of the Phase 4 contract (host GOOS/GOARCH, no proxy, no telemetry)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GO") and k != "CGO_ENABLED"}
    env.update({"GOTOOLCHAIN": "local", "GOFLAGS": "", "CGO_ENABLED": "0", "GOPROXY": "off",
                "GOTELEMETRY": "off", "GOSUMDB": "off", "GOWORK": "off", "ENVSCAN_TESTDATA": str(testdata)})
    return env


def test_go_redaction_and_proxy(tmp_path: Path) -> None:
    go = go_or_skip()
    testdata = tmp_path / "testdata"
    shared_cases.write_testdata(testdata)
    staged = target_go.stage(load_spec(PORTABLE / "spec"), PORTABLE / "src" / "go", tmp_path / "go", PREFIXES)
    proc = subprocess.run([str(go), "test", "-count=1", "-run", "Redact|Proxy|Secret", "."], cwd=staged,
                          env=go_test_env(testdata), capture_output=True, text=True, timeout=GO_TEST_TIMEOUT,
                          check=False)
    assert proc.returncode == 0, proc.stdout[-6000:] + proc.stderr[-3000:]
