"""Secret redaction in the envscan.ps1 library: names, values, lines, multi-line text,
command lines, environment values, the data safety net and the log.

The cases run through tests/ps/redaction_cases.ps1 once per language mode. Each case either
has an exact expected result, or lists secrets that must disappear and fragments that must stay.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from conftest import ps_command, ps_quote
from redaction_cases import PH, PS_ONLY_CASES, SHARED_CASES, Case

pytestmark = pytest.mark.integration

# Every shared case (XML_CASES included) plus the ps-only ones.
ALL_CASES = SHARED_CASES + PS_ONLY_CASES
HARNESS = Path(__file__).resolve().parent / "ps" / "redaction_cases.ps1"
MODES = ("FullLanguage", "ConstrainedLanguage")


@pytest.fixture(scope="module", params=MODES)
def results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    mode = request.param
    work = tmp_path_factory.mktemp(f"redact-{mode}")
    cases_file = work / "cases.json"
    payload = [{"name": c.name, "fn": c.fn, "args": list(c.args)} for c in ALL_CASES]
    cases_file.write_text(json.dumps(payload), encoding="ascii")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if mode != "FullLanguage" else ""
    command = f"{prefix}& {ps_quote(HARNESS)} -Lib {ps_quote(lib)} -Cases {ps_quote(cases_file)}"
    proc = ps_command(command, timeout=300)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    data = json.loads(proc.stdout)
    assert data["language_mode"] == mode
    return data


@pytest.mark.parametrize("case", ALL_CASES, ids=lambda c: c.name)
def test_redaction_case(results: dict[str, Any], case: Case) -> None:
    actual = results[case.name]
    if case.exact:
        assert actual == case.expected
        return
    for secret in case.gone:
        assert secret not in actual, actual
    for fragment in case.kept:
        assert fragment in actual, actual


def test_data_safety_net(results: dict[str, Any]) -> None:
    data = results["data_safety_net"]
    flat = json.dumps(data)
    for secret in ("abc123", "zzz999", "key777key"):
        assert secret not in flat, flat
    assert "plain value" in data["opts"]


def test_data_too_deep_is_redacted(results: dict[str, Any]) -> None:
    assert "deep555" not in results["data_too_deep"]


def test_log_is_redacted(results: dict[str, Any]) -> None:
    assert "log444secret" not in results["log_line"]
    assert "run tool --token" in results["log_line"]
