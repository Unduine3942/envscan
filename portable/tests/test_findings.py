"""Golden findings cases (tests/data/findings_cases.json) against the sh and ps findings code.

Every case lists the facts (minimal probe results) and the finding ids that must result. The sh
rules run in dash from build/lib/envscan-lib.sh, the ps rules from build/lib/envscan-lib.ps1; the
case file is language-neutral so the Go and JScript ports reuse it. See tests/findings_harness.py.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import findings_harness as fh
import pytest
from conftest import PORTABLE, ps_command, ps_quote, requires_powershell
from sh_helpers import msys_path, needs_msys, run_lib

HARNESS = Path(__file__).resolve().parent / "ps" / "findings_cases.ps1"
CASES = fh.load_cases()
IMPLS = ("ps", "sh")
SRC = {"sh": PORTABLE / "src" / "sh" / "30-findings.sh", "ps": PORTABLE / "src" / "ps" / "30-findings.ps1"}
ID_RE = re.compile(r"(?:es_find|New-EsFinding)\s+['\"]?([a-z]+\.[a-z0-9_]+)")
SH_SCRIPT = (
    'ES_TMP=$1; ES_OS=$2; ES_ARCH=x86_64; ES_UNAME_R=\n'
    '. "$3"\n'
    'es_spec_findings >"$ES_TMP/findings.spec" || exit 3\n'
    'es_findings\n'
    'cut -f 1 "$ES_TMP/findings.tsv"\n'
)


def for_impl(impl: str) -> list[Any]:
    out = []
    for case in CASES:
        if impl not in case["impls"]:
            continue
        reason = case.get("xfail", {}).get(impl)
        marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
        out.append(pytest.param(case, id=case["name"], marks=marks))
    return out


def test_case_file_is_well_formed() -> None:
    names = [c["name"].lower() for c in CASES]
    assert len(names) == len(set(names))  # PowerShell hashtable keys ignore case
    raw = fh.DATA.read_bytes()
    raw.decode("ascii")
    assert b"\r" not in raw
    for case in CASES:
        assert set(case["impls"]) <= set(IMPLS) and case["impls"]
        assert set(case.get("xfail", {})) <= set(case["impls"])
        assert set(case.get("expect_by_impl", {})) <= set(case["impls"])
        assert all(case.get("xfail", {}).values())


@pytest.mark.unit
@pytest.mark.parametrize("impl", IMPLS)
def test_every_implemented_finding_has_a_case(impl: str) -> None:
    implemented = set(ID_RE.findall(SRC[impl].read_text(encoding="utf-8")))
    covered = {i for c in CASES if impl in c["impls"] for i in fh.expected(c, impl)}
    assert len(implemented) >= 30
    assert implemented - covered == set(), f"{impl}: findings without a golden case"


@pytest.mark.unit
def test_every_spec_finding_is_implemented_somewhere() -> None:
    spec = set(re.findall(r'^id = "([^"]+)"', (PORTABLE / "spec" / "findings.toml").read_text(encoding="utf-8"), re.M))
    implemented = {i for impl in IMPLS for i in ID_RE.findall(SRC[impl].read_text(encoding="utf-8"))}
    assert spec - implemented == set()


@pytest.mark.unit
def test_absence_guard_cases_exist() -> None:
    guards = [c for c in CASES if c["name"].startswith("guard_")]
    assert len(guards) >= 15
    assert {s for c in guards for s in c.get("probes", {}).values()} >= {"error", "denied", "timeout", "partial", "skipped", "absent"}


@pytest.mark.integration
@needs_msys
@pytest.mark.parametrize("case", for_impl("sh"))
def test_sh_findings(built: Path, tmp_path: Path, case: dict[str, Any]) -> None:
    facts, rows = fh.sh_script_inputs(case)
    (tmp_path / "facts.sh").write_text(facts, encoding="utf-8", newline="\n")
    (tmp_path / "results.tsv").write_text(rows, encoding="ascii", newline="\n")
    lib = built / "build" / "lib" / "envscan-lib.sh"
    proc = run_lib(lib, SH_SCRIPT, msys_path(tmp_path), case.get("sh_os", "linux"), msys_path(tmp_path / "facts.sh"))
    assert proc.returncode == 0, proc.stderr
    assert sorted(proc.stdout.split()) == fh.expected(case, "sh"), proc.stderr


@pytest.fixture(scope="module")
def ps_results(built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, list[str]]:
    cases_file = tmp_path_factory.mktemp("findings-ps") / "cases.json"
    cases_file.write_text(json.dumps([fh.ps_input(c) for c in CASES if "ps" in c["impls"]]), encoding="ascii")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    proc = ps_command(f"& {ps_quote(HARNESS)} -Lib {ps_quote(lib)} -Cases {ps_quote(cases_file)}", timeout=600)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return {k: ([v] if isinstance(v, str) else list(v)) for k, v in json.loads(proc.stdout).items()}


@pytest.mark.integration
@requires_powershell
@pytest.mark.parametrize("case", for_impl("ps"))
def test_ps_findings(ps_results: dict[str, list[str]], case: dict[str, Any]) -> None:
    assert sorted(ps_results[case["name"]]) == fh.expected(case, "ps")


@pytest.mark.unit
def test_harness_holds_no_product_logic() -> None:
    """The adapters pass facts through; classification (public vs internal endpoint, architecture
    mismatch) is the implementations' job, so the golden cases fail when that logic changes."""
    assert not hasattr(fh, "PUBLIC_HOSTS") and not hasattr(fh, "_arch_differs")
    assert all("endpoints" not in c.get("facts", {}) for c in CASES)


@pytest.mark.unit
def test_endpoint_facts_agree_with_the_spec_public_hosts() -> None:
    """The cases say which endpoint is public; check that against spec/configs.toml."""
    from spec import load_spec

    public = load_spec(PORTABLE / "spec").public_hosts

    def is_public(url: str) -> bool:
        host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
        return any(host == h or host.endswith("." + h) for h in public)

    for case in CASES:
        facts = case.get("facts", {})
        assert all(is_public(u) for u in facts.get("endpoints_public", [])), case["name"]
        assert not any(is_public(u) for u in facts.get("endpoints_internal", [])), case["name"]
