"""Each implementation against the redaction cases written for the other one.

The ps1 cases (PS_CASES) run through sh, the sh-only cases (SH_CASES) through the ps1. A failure
that is a real divergence is listed in redaction_cases.KNOWN_DIVERGENCES and xfails strictly, so
fixing it turns the test into an XPASS error that reminds to delete the entry.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import ps_command, ps_quote, requires_powershell
from redaction_cases import KNOWN_DIVERGENCES, PS_CASES, SH_CASES, Case
from sh_helpers import AwkTool, make_awk_tool, needs_msys

HARNESS = Path(__file__).resolve().parent / "ps" / "redaction_cases.ps1"
MODES = ("FullLanguage", "ConstrainedLanguage")
SH_FUNCTIONS = {"Test-EsSecretName": "name", "Protect-EsValue": "value", "Protect-EsLine": "line",
                "Protect-EsText": "text", "Protect-EsCommandLine": "cmd", "Protect-EsNamedValue": "named"}
TWICE = {"Protect-TwiceValue": "Protect-EsValue", "Protect-TwiceLine": "Protect-EsLine",
         "Protect-TwiceCommandLine": "Protect-EsCommandLine"}


# Text an implementation prints when a case crashed instead of redacting.
ERROR_MARKERS = ("The term '", "Cannot ", "Exception", "At line:", "awk:", "syntax error", "not found")


def check(case: Case, actual: Any) -> None:
    if case.exact:
        assert actual == case.expected
        return
    # A leak check must not pass because the implementation returned nothing or an error text.
    assert isinstance(actual, str), actual
    original = case.args[0] if case.args else ""
    if isinstance(original, str) and original:
        assert actual, "empty result for a non-empty input"
    for marker in ERROR_MARKERS:
        assert marker not in actual or marker in str(original), actual
    for secret in case.gone:
        assert secret not in actual, actual
    for fragment in case.kept:
        assert fragment in actual, actual


def with_divergence(case: Case, impl: str) -> Any:
    reason = KNOWN_DIVERGENCES.get(case.name, {}).get(impl)
    marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
    return pytest.param(case, id=case.name, marks=marks)


@pytest.fixture(scope="module")
def awk_tool(built: Path, tmp_path_factory: pytest.TempPathFactory) -> AwkTool:
    return make_awk_tool(built / "build" / "lib" / "envscan-lib.sh", tmp_path_factory.mktemp("cross-awk"))


@pytest.fixture(scope="module")
def sh_results(awk_tool: AwkTool, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """PS_CASES through sh; a Protect-Twice case runs the rule a second time on its result."""
    work = tmp_path_factory.mktemp("cross-sh")
    first = awk_tool.cases([(SH_FUNCTIONS[TWICE.get(c.fn, c.fn)], *c.args) for c in PS_CASES], work)
    assert len(first) == len(PS_CASES), (len(first), len(PS_CASES))
    twice = [(c, v) for c, v in zip(PS_CASES, first) if c.fn in TWICE]
    second = awk_tool.cases([(SH_FUNCTIONS[TWICE[c.fn]], v) for c, v in twice], work)
    assert len(second) == len(twice), (len(second), len(twice))
    again = {c.name: v for (c, _), v in zip(twice, second)}
    return {c.name: again.get(c.name, v) for c, v in zip(PS_CASES, first)}


@pytest.mark.integration
@needs_msys
@pytest.mark.parametrize("case", [with_divergence(c, "sh") for c in PS_CASES])
def test_sh_passes_the_ps_cases(sh_results: dict[str, Any], case: Case) -> None:
    check(case, sh_results[case.name])


@pytest.fixture(scope="module", params=MODES)
def ps_results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    work = tmp_path_factory.mktemp(f"cross-ps-{request.param}")
    cases_file = work / "cases.json"
    cases_file.write_text(json.dumps([{"name": c.name, "fn": c.fn, "args": list(c.args)} for c in SH_CASES]),
                          encoding="ascii")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if request.param != MODES[0] else ""
    proc = ps_command(f"{prefix}& {ps_quote(HARNESS)} -Lib {ps_quote(lib)} -Cases {ps_quote(cases_file)}", timeout=300)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.integration
@requires_powershell
@pytest.mark.parametrize("case", [with_divergence(c, "ps") for c in SH_CASES])
def test_ps_passes_the_sh_cases(ps_results: dict[str, Any], case: Case) -> None:
    check(case, ps_results[case.name])
