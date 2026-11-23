"""Cross-port hardening round of 2026-11-15 in the envscan.ps1 library: the child environment
allowlist (spec/child_env.toml [child_env_keep]) and --net lookups without DNS search-domain
expansion (single-label names skipped, other names looked up in their absolute form).

The XML redaction part of the round is covered by tests/test_ps_redaction.py (shared XML_CASES)
and tests/test_ps_redaction_hardening.py (extra cases and run time on hostile input).

One PowerShell process per language mode evaluates tests/ps/cross_hardening_cases.ps1 and prints
a JSON object (case name -> result).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import PORTABLE, ps_command, ps_quote, requires_powershell

import target_ps
from spec import load_spec

CASES = Path(__file__).resolve().parent / "ps" / "cross_hardening_cases.ps1"
MODES = ("FullLanguage", "ConstrainedLanguage")
SINGLE_LABEL_WHY = "single-label name; DNS search domains could expand it, so it is not looked up"
PLANTED_GONE = ("ENVSCAN_TEST_CHILD_CANARY", "HTTP_PROXY", "GITHUB_TOKEN", "NODE_OPTIONS", "DOCKER_HOST")


@pytest.fixture(scope="module", params=MODES)
def results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    mode = request.param
    scratch = tmp_path_factory.mktemp(f"pscross-{mode}")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if mode != "FullLanguage" else ""
    command = f"{prefix}& {ps_quote(CASES)} -Lib {ps_quote(lib)} -Scratch {ps_quote(scratch)}"
    proc = ps_command(command, timeout=600, cwd=scratch)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    data = json.loads(proc.stdout)
    assert data["language_mode"] == mode
    return data


def case(results: dict[str, Any], name: str) -> Any:
    value = results[name]
    if isinstance(value, dict) and "case_error" in value:
        pytest.fail(f"case {name} failed: {value['case_error']}")
    return value


def upper(names: list[str]) -> set[str]:
    return {name.upper() for name in names}


# ------------------------------------------------------------------ generated lists

def test_generated_block_carries_the_allowlist_from_the_spec() -> None:
    spec = load_spec(PORTABLE / "spec")
    block = target_ps.generate(spec)
    names = target_ps.ps_literal(list(spec.child_env_keep_names))
    prefixes = target_ps.ps_literal(list(spec.child_env_keep_prefixes))
    assert f"$script:ES_CHILD_ENV_KEEP_NAMES = {names}" in block
    assert f"$script:ES_CHILD_ENV_KEEP_PREFIXES = {prefixes}" in block
    assert "PROGRAMFILES(X86)" in spec.child_env_keep_names


def test_generated_block_carries_the_path_vetting_lists_from_the_spec() -> None:
    spec = load_spec(PORTABLE / "spec")
    block = target_ps.generate(spec)
    assert f"$script:ES_CHILD_ENV_HOME_PATHS = {target_ps.ps_literal(list(spec.child_env_home_paths))}" in block
    assert f"$script:ES_CHILD_ENV_PATH_LISTS = {target_ps.ps_literal(list(spec.child_env_path_lists))}" in block
    assert "USERPROFILE" in spec.child_env_home_paths and "PSMODULEPATH" in spec.child_env_path_lists


def test_the_generated_block_has_no_network_fs_rule() -> None:
    # Network file systems are a Unix rule; on Unix the ps1 hands over to envscan.sh.
    block = target_ps.generate(load_spec(PORTABLE / "spec"))
    assert "network_fs" not in block.lower() and "local_fuse" not in block.lower()


# ------------------------------------------------------------------ child environment

@requires_powershell
@pytest.mark.integration
def test_children_get_only_allowlisted_variables(results: dict[str, Any]) -> None:
    env = case(results, "child_env")
    plain = upper(env["plain"])
    for name in PLANTED_GONE:
        assert name not in plain, sorted(plain)
    for name in ("PATH", "SYSTEMROOT", "LC_ENVSCAN_T", "XDG_ENVSCAN_T", "NO_COLOR"):
        assert name in plain, sorted(plain)
    assert env["lc"] == "lc-kept" and env["no_color"] == "1"


@requires_powershell
@pytest.mark.integration
def test_every_child_variable_is_allowlisted_or_set_by_the_scanner(results: dict[str, Any]) -> None:
    spec = load_spec(PORTABLE / "spec")
    # cmd.exe itself adds PROMPT when it is missing.
    allowed = upper(list(spec.child_env_keep_names)) | upper(list(spec.child_env)) | {"PROMPT"}
    prefixes = tuple(p.upper() for p in spec.child_env_keep_prefixes)
    stray = sorted(n for n in upper(case(results, "child_env")["plain"]) if n not in allowed and not n.startswith(prefixes))
    assert stray == []


@requires_powershell
@pytest.mark.integration
def test_per_call_extras_still_reach_the_child(results: dict[str, Any]) -> None:
    env = case(results, "child_env")
    extra = upper(env["extra"])
    assert {"GIT_CEILING_DIRECTORIES", "ENVSCAN_T_EXTRA"} <= extra
    assert env["extra_value"] == "extra-1"
    assert not extra & set(PLANTED_GONE)


@requires_powershell
@pytest.mark.integration
def test_the_scanner_environment_is_restored_after_each_child(results: dict[str, Any]) -> None:
    env = case(results, "child_env")
    assert env["after"] == env["before"]
    assert env["before"]["ENVSCAN_TEST_CHILD_CANARY"] == "canary-child-4d1e"
    assert env["after_extra"] is None and env["after_no_color"] is None


@requires_powershell
@pytest.mark.integration
def test_without_a_snapshot_the_live_environment_is_filtered(results: dict[str, Any]) -> None:
    names = upper(case(results, "child_env_live"))
    assert "PATH" in names and "LC_ENVSCAN_T" in names
    assert not names & set(PLANTED_GONE)


@requires_powershell
@pytest.mark.integration
def test_allowlist_matching_ignores_case(results: dict[str, Any]) -> None:
    keep = case(results, "child_env_keep")
    for name in ("path", "ProgramFiles(x86)", "COMMONPROGRAMFILES(X86)", "lc_all", "XDG_CONFIG_HOME", "SystemRoot"):
        assert keep[name] is True, name
    for name in ("HTTP_PROXY", "GITHUB_TOKEN", "LD_PRELOAD", "BASH_ENV", "ENV", "NODE_OPTIONS", "PATHX", "XPATH", "LC"):
        assert keep[name] is False, name


# ------------------------------------------------------------------ --net names

@requires_powershell
@pytest.mark.integration
def test_single_label_names_are_never_looked_up(results: dict[str, Any]) -> None:
    run = case(results, "single_label")
    targets = {t["host"]: t for t in run["targets"]}
    for host in ("proxy", "proxy.", "localhost"):
        assert targets[host] == {"host": host, "port": 8080, "source": "env HTTP_PROXY", "tcp": "skipped",
                                 "reason": SINGLE_LABEL_WHY}, targets[host]
    assert not [a for a in run["asked"] if a.lower() in ("dns:proxy", "dns:proxy.", "dns:localhost", "dns:localhost.")]


@requires_powershell
@pytest.mark.integration
def test_other_names_are_looked_up_in_their_absolute_form(results: dict[str, Any]) -> None:
    run = case(results, "single_label")
    assert run["asked"] == ["dns:PROXY.CORP.", "dns:proxy.corp.", "dns:nexus.corp.example."]
    targets = {t["host"]: t for t in run["targets"]}
    # The report keeps the name as written; a literal address is never looked up.
    assert targets["PROXY.CORP"]["tcp"] == "ok" and targets["proxy.corp."]["tcp"] == "ok"
    assert targets["10.0.0.5"]["tcp"] == "ok"


@requires_powershell
@pytest.mark.integration
def test_nslookup_gets_the_absolute_name(results: dict[str, Any]) -> None:
    ns = case(results, "nslookup_absolute")
    assert ns["args"] == ["-timeout=2 -retry=1 proxy.corp.", "-timeout=2 -retry=1 proxy.corp."]
    assert ns["answers"] == ["proxy.corp=ok", "proxy.corp.=ok", "proxy=skipped", "proxy.=skipped"]


@requires_powershell
@pytest.mark.integration
def test_children_start_from_a_minimal_scan_environment(results: dict[str, Any]) -> None:
    run = case(results, "child_env_minimal")
    assert run["error"] is None and run["exit_code"] == 0, run
    assert {"PATH", "HOME", "NO_COLOR"} <= upper(run["names"])


# ------------------------------------------------------------------ review fixes: process environment

MALFORMED_WHY = "malformed host name; not looked up"
PUBLIC_V4_WHY = "public IPv4 address; never contacted"


@requires_powershell
@pytest.mark.integration
def test_a_variable_that_cannot_be_removed_stops_the_launch(results: dict[str, Any]) -> None:
    run = case(results, "env_fail_closed")
    assert run["exit_code"] is None and "child-ran" not in run["stdout"], run
    assert run["error"] and "ENVSCAN_T_STICKY" in run["error"], run
    assert run["diff"] == [], run["diff"]


@requires_powershell
@pytest.mark.integration
def test_a_failure_while_setting_restores_everything(results: dict[str, Any]) -> None:
    run = case(results, "env_set_throws")
    assert run["exit_code"] is None and "child-ran" not in run["stdout"], run
    assert run["error"], run
    assert run["diff"] == [], run["diff"]


@requires_powershell
@pytest.mark.integration
def test_the_restore_goes_on_past_a_failing_variable(results: dict[str, Any]) -> None:
    run = case(results, "env_restore_tolerant")
    assert run["threw"] is False
    assert run["keep"] == "keep-1" and run["sticky"] is None


@requires_powershell
@pytest.mark.integration
def test_the_wmi_job_path_restores_and_fails_closed(results: dict[str, Any]) -> None:
    run = case(results, "env_cim_job")
    assert "job refused by test" in run["failed"]
    assert run["closed"] and "ENVSCAN_T_STICKY" in run["closed"], run
    assert run["started"] == 1, run  # only the first call reached Start-Job
    assert run["diff"] == [], run["diff"]


# ------------------------------------------------------------------ review fixes: X2 path vetting

def _folded(table: dict[str, Any]) -> dict[str, Any]:
    return {name.upper(): value for name, value in table.items()}


@requires_powershell
@pytest.mark.integration
def test_refused_home_folders_are_replaced_by_a_private_folder(results: dict[str, Any]) -> None:
    run = case(results, "child_env_paths")
    table, tmp = _folded(run["table"]), run["tmp"]
    for name in ("HOME", "APPDATA", "USERPROFILE", "XDG_CACHE_HOME"):
        assert table[name].lower().startswith(tmp.lower() + "\\"), (name, table[name])
    assert table["TEMP"] == tmp and table["TMP"] == tmp
    assert table["LOCALAPPDATA"] == r"C:\Users\u\AppData\Local"
    assert run["home_exists"] and run["home_empty"]


@requires_powershell
@pytest.mark.integration
def test_refused_path_list_entries_are_dropped(results: dict[str, Any]) -> None:
    table = _folded(case(results, "child_env_paths")["table"])
    assert table["PATH"] == r"C:\Windows\System32;C:\Windows"
    assert table["PSMODULEPATH"] == r"C:\m1"
    assert "LIBPATH" not in table


@requires_powershell
@pytest.mark.integration
def test_other_refused_absolute_paths_are_removed(results: dict[str, Any]) -> None:
    table = _folded(case(results, "child_env_paths")["table"])
    for name in ("JAVA_HOME", "GOROOT", "SSL_CERT_FILE"):
        assert name not in table, name
    assert table["COMSPEC"] == r"C:\Windows\system32\cmd.exe" and table["GOPATH"] == r"C:\go-work"
    assert table["LANG"] == "en_US.UTF-8" and table["OS"] == "Windows_NT"
    # The scanner's own per-call extras are not vetted.
    assert table["GIT_CEILING_DIRECTORIES"] == r"\\srv\ceiling"


@requires_powershell
@pytest.mark.integration
def test_a_child_sees_the_vetted_paths(results: dict[str, Any]) -> None:
    run = case(results, "child_env_paths")
    child = _folded(run["child"])
    assert child["APPDATA"].lower().startswith(run["tmp"].lower() + "\\")
    assert r"\\srv" not in child["PATH"] and "JAVA_HOME" not in child


# ------------------------------------------------------------------ review fixes: X4 names

@requires_powershell
@pytest.mark.integration
def test_malformed_names_and_dotted_ipv4_are_never_looked_up(results: dict[str, Any]) -> None:
    run = case(results, "reach_malformed")
    targets = {t["host"]: t for t in run["targets"]}
    for host in (".proxy.corp", "proxy..corp", ".", "a.b.."):
        assert targets[host]["tcp"] == "skipped" and targets[host]["reason"] == MALFORMED_WHY, targets[host]
    assert targets["10.0.0.1."]["tcp"] == "skipped" and targets["10.0.0.1."]["reason"] == PUBLIC_V4_WHY
    assert targets["10.0.0.5"]["tcp"] == "ok"
    assert run["asked"] == ["dns:ok.corp."]


@requires_powershell
@pytest.mark.integration
def test_skip_reasons_for_malformed_names(results: dict[str, Any]) -> None:
    reasons = case(results, "reach_reasons")
    for name in ("", ".", "..", ".x.corp", "x..corp", "x.corp..", "host.."):
        assert reasons[f"[{name}]"] == MALFORMED_WHY, name
    for name in ("10.0.0.1.", "192.168.1.1.", "8.8.8.8."):
        assert reasons[f"[{name}]"] == PUBLIC_V4_WHY, name
    assert reasons["[proxy.corp.]"] is None and reasons["[proxy.]"] == SINGLE_LABEL_WHY


@requires_powershell
@pytest.mark.integration
def test_ip_literals_and_malformed_names_never_reach_a_resolver(results: dict[str, Any]) -> None:
    run = case(results, "resolve_literal_dot")
    assert run["asked"] == []
    assert run["answers"] == [f"10.0.0.1.=skipped={PUBLIC_V4_WHY}", f"x..corp=skipped={MALFORMED_WHY}",
                              f".x.corp=skipped={MALFORMED_WHY}"]
