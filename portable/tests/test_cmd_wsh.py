"""Integration tests for envscan.cmd --wsh: running envscan.js with Windows Script Host (cscript.exe).

A stub envscan.js next to envscan.cmd records how it was started and exits with STUB_JS_EXIT
(a number, or "throw" for a JScript runtime error, after which cscript.exe exits 0). envscan.js
exits 100 + its result when __ES_EXIT_BASE is 100, so the launcher can tell "envscan.js finished
with n" (100/101/102) from "cscript.exe failed" (anything else, then the cmd.exe fallback runs).
ENVSCAN_TEST_POLICY reaches each reason PowerShell cannot run; ENVSCAN_TEST_WSH stands in for the
Windows Script Host settings of the registry.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import pytest

from conftest import find_output
from test_cmd_launcher import (ALLOW_PROCESS_SCOPE, CMD, CMD32, Run, cmd_script, effective_policy,  # noqa: F401
                               run_cmd)
from test_cmd_security import LAUNCHER_HOSTILE, assert_not_injected, hostile, hostile_env

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name != "nt", reason="envscan.cmd needs cmd.exe"),
]

SYSTEM32 = Path(CMD).parent
HAVE_CSCRIPT = (SYSTEM32 / "cscript.exe").is_file()
needs_cscript = pytest.mark.skipif(not HAVE_CSCRIPT, reason="no cscript.exe in System32")

JS_FOLDER = r"C:\fake\envscan-js-folder"
JS_STUB = r"""// envscan.js test stub: records how envscan.cmd started it, exits with STUB_JS_EXIT.
var sh = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var env = sh.Environment("PROCESS");
var lines = ["argc=" + WScript.Arguments.length];
for (var i = 0; i < WScript.Arguments.length; i++) { lines.push("arg=[" + WScript.Arguments(i) + "]"); }
var names = [];
for (var e = new Enumerator(env); !e.atEnd(); e.moveNext()) {
    var item = String(e.item());
    var name = item.substring(0, item.indexOf("=", 1));
    if (name.toUpperCase().indexOf("__ES_") === 0) { names.push(name); }
}
lines.push("es_vars=" + names.join(","));
lines.push("exit_base=[" + env("__ES_EXIT_BASE") + "]");
lines.push("arch=" + env("PROCESSOR_ARCHITECTURE"));
lines.push("cwd=" + sh.CurrentDirectory);
lines.push("tmp=[" + env("TMP") + "]");
lines.push("systemroot=[" + env("SystemRoot") + "]");
lines.push("systemdrive=[" + env("SystemDrive") + "]");
var here = fso.GetParentFolderName(WScript.ScriptFullName);
var file = fso.CreateTextFile(here + "\\js-record.txt", true);
file.Write(lines.join("\r\n") + "\r\n");
file.Close();
WScript.StdErr.WriteLine("js stub stderr line");
var mode = env("STUB_JS_EXIT");
if (mode === "throw") { throw new Error("js stub runtime failure"); }
WScript.StdOut.WriteLine("C:\\fake\\envscan-js-folder");
WScript.Quit(parseInt(mode, 10));
"""
JS_SYNTAX_ERROR = "// envscan.js stub with a syntax error\r\nvar x = ;\r\n"

LOCAL_POLICY = {"ENVSCAN_TEST_POLICY": "restricted"}
ONLY = ["--only", "session.context"]


def js_record(run: Run) -> str | None:
    path = run.bundle / "js-record.txt"
    return path.read_text(encoding="ascii") if path.exists() else None


def js_args(run: Run) -> list[str]:
    record = js_record(run)
    assert record is not None, f"envscan.js did not run: {run.stderr}"
    return [line[5:-1] for line in record.splitlines() if line.startswith("arg=[")]


def run_wsh(script: Path, root: Path, args: Sequence[str] = (), *, env: Mapping[str, str] | None = None,
            js: str | None = JS_STUB, js_exit: str = "100", **kwargs) -> Run:
    """run_cmd with a stub envscan.js (or none) next to envscan.cmd and STUB_JS_EXIT set."""
    bundle = root / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    if js is not None:
        (bundle / "envscan.js").write_text(js, encoding="ascii")
    return run_cmd(script, root, args, env={"STUB_JS_EXIT": js_exit, **(env or {})}, **kwargs)


def assert_fallback_without_js(run: Run) -> str:
    """envscan.js never ran; the fallback wrote its report. Returns the report."""
    assert js_record(run) is None, "envscan.js must not run"
    assert run.returncode in (0, 1), run.stderr
    assert run.stdout_lines[-1] == str(find_output(run.work))
    assert list(run.temp.iterdir()) == [], "a temporary file was left"
    return run.report


# ------------------------------------------------------------------ WSH runs

@needs_cscript
def test_local_policy_runs_envscan_js_with_the_checked_arguments(cmd_script: Path, tmp_path: Path) -> None:
    out_dir = str(tmp_path / "out dir") + "\\"
    run = run_wsh(cmd_script, tmp_path, ["--wsh", "--deep", "--out", out_dir, "--only", "env.*,os.*"],
                  env=LOCAL_POLICY)
    assert run.returncode == 0, run.stderr
    # --wsh is the launcher's own option; WSH does not unescape \" (the trailing backslash stays).
    assert js_args(run) == ["--deep", "--out", out_dir, "--only", "env.*,os.*"]
    record = js_record(run) or ""
    assert "es_vars=__ES_EXIT_BASE\n" in record, "only __ES_EXIT_BASE may reach envscan.js"
    assert "exit_base=[100]\n" in record
    assert f"cwd={run.work}\n" in record
    assert "arch=x86\n" not in record
    assert run.stdout_lines == [JS_FOLDER], "stdout must be envscan.js's own"
    assert "js stub stderr line" in run.stderr
    assert "Windows Script Host" in run.stderr, "the WSH run is announced on stderr"
    assert run.record is None, "PowerShell must not start"
    assert not list(run.work.glob("envscan-*")), "the fallback must not run after envscan.js finished"
    assert list(run.temp.iterdir()) == []


@needs_cscript
@pytest.mark.parametrize("js_exit,code", [("100", 0), ("101", 1), ("102", 2)])
def test_offset_exit_codes_are_envscan_js_results(cmd_script: Path, tmp_path: Path, js_exit: str, code: int) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", "--net"], env=LOCAL_POLICY, js_exit=js_exit)
    assert run.returncode == code, run.stderr
    assert js_args(run) == ["--net"]
    assert not list(run.work.glob("envscan-*"))


@needs_cscript
def test_caller_exit_base_never_reaches_powershell_or_the_fallback(cmd_script: Path, tmp_path: Path) -> None:
    """The offset is set for envscan.js only: a caller's __ES_EXIT_BASE is removed like every __ES_*."""
    run = run_cmd(cmd_script, tmp_path, ["--wsh", "--net"],
                  env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0", "__ES_EXIT_BASE": "100"})
    assert run.returncode == 0, run.stderr
    assert run.record is not None and "es_vars=\n" in run.record


@needs_cscript
def test_missing_ps1_runs_envscan_js(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", "--net"], stub=False, env=ALLOW_PROCESS_SCOPE, js_exit="101")
    assert run.returncode == 1, run.stderr
    assert js_args(run) == ["--net"]


@needs_cscript
def test_refusal_by_powershell_under_a_local_policy_runs_envscan_js(cmd_script: Path, tmp_path: Path) -> None:
    """PowerShell itself refused the script (the prediction said allowed) and no Group Policy is
    set: the launch after PowerShell gives envscan.js the caller's environment as well."""
    if effective_policy() not in ("Restricted", "AllSigned"):
        pytest.skip(f"needs an execution policy that refuses unsigned scripts, have {effective_policy()!r}")
    out_dir = str(tmp_path / "o&u t") + "\\"
    args = ["--net", "--timeout", "5", "--out", out_dir, "--only", "env.*,os.*", "--no-redact"]
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *args], env={"ENVSCAN_TEST_POLICY": "allowed"})
    assert run.returncode == 0, run.stderr
    assert run.record is None, "the PowerShell stub must not have run"
    record = js_record(run) or ""
    assert "es_vars=__ES_EXIT_BASE\n" in record, record
    # Rebuilt from the restored options after PowerShell: the same options, the flags first.
    assert js_args(run) == ["--net", "--timeout", "5", "--no-redact", "--out", out_dir, "--only", "env.*,os.*"]
    assert run.stdout_lines == [JS_FOLDER]
    assert list(run.temp.iterdir()) == []


@needs_cscript
@pytest.mark.skipif(not Path(CMD32).exists(), reason="no 32-bit cmd.exe on this system")
def test_32bit_cmd_runs_the_64bit_cscript(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", "--net"], env=LOCAL_POLICY, exe=CMD32)
    assert run.returncode == 0, run.stderr
    record = js_record(run) or ""
    assert "arch=" in record and "arch=x86\n" not in record, record
    assert js_args(run) == ["--net"]


def test_wsh_is_not_used_when_powershell_may_run(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", "--net"], env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0"})
    assert run.returncode == 0, run.stderr
    assert run.record is not None and "argc=1" in run.record and "arg=[--net]" in run.record
    assert js_record(run) is None


# ------------------------------------------------------------------ WSH fails: the fallback runs

@needs_cscript
@pytest.mark.parametrize("js_exit,js,shown", [
    ("0", JS_STUB, "0"),                 # envscan.js without the offset (or a //T timeout)
    ("1", JS_STUB, "1"),                 # what cscript.exe returns when WSH is disabled
    ("throw", JS_STUB, "0"),             # a JScript runtime error: cscript.exe exits 0
    ("0", JS_SYNTAX_ERROR, "1"),         # a syntax error: cscript.exe exits 1
], ids=["exit-0", "exit-1", "runtime-error", "syntax-error"])
def test_failed_wsh_runs_the_fallback(cmd_script: Path, tmp_path: Path, js_exit: str, js: str, shown: str) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env=LOCAL_POLICY, js=js, js_exit=js_exit)
    assert run.returncode == 0, run.stderr
    folder = find_output(run.work)
    assert run.stdout_lines[-1] == str(folder)
    report = run.report
    assert f"wsh: envscan.js ran with cscript.exe and ended with exit code {shown}" in report, report
    assert "reason: the PowerShell execution policy is Restricted" in report
    assert "did not finish" in run.stderr and "--wsh" in run.stderr
    # cscript.exe's error output goes to the report, never to stdout.
    assert "js stub stderr line" not in run.stdout and "error" not in run.stdout.lower()
    if js_exit == "throw":
        assert "error output of cscript.exe" in report and "js stub runtime failure" in report
    assert "PowerShell error output" not in report
    assert list(run.temp.iterdir()) == []


# ------------------------------------------------------------------ WSH is never used

@pytest.mark.parametrize("policy,why", [
    ("allsigned-gpo", "wsh: not used: Group Policy enforces the execution policy"),
    ("blocked", "wsh: not used: PowerShell may be blocked by application control"),
])
def test_group_policy_and_application_control_never_use_wsh(cmd_script: Path, tmp_path: Path, policy: str,
                                                            why: str) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env={"ENVSCAN_TEST_POLICY": policy})
    report = assert_fallback_without_js(run)
    assert why in report, report
    assert "bypass" not in (run.stderr + report).lower()
    assert "envscan.cmd --wsh" not in run.stderr, "--wsh must not be offered here"


def test_forced_fallback_never_uses_wsh(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--fallback", "--wsh", *ONLY], env=LOCAL_POLICY)
    report = assert_fallback_without_js(run)
    assert "wsh: not used: --fallback was given" in report


def test_powershell_that_ran_and_failed_never_uses_wsh(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "7"})
    assert run.record is not None, "the PowerShell stub should have run"
    report = assert_fallback_without_js(run)
    assert "exit code 7" in report
    assert "wsh: not used: PowerShell started" in report


@pytest.mark.parametrize("hook,why", [
    ("disabled", "Windows Script Host is disabled - simulated by ENVSCAN_TEST_WSH=disabled"),
    ("signed", "Windows Script Host runs only trusted signed scripts here - simulated by ENVSCAN_TEST_WSH=signed"),
    ("rules", "Software Restriction Policies or AppLocker script rules are configured - simulated by "
              "ENVSCAN_TEST_WSH=rules"),
])
def test_wsh_settings_that_forbid_the_script_are_respected(cmd_script: Path, tmp_path: Path, hook: str,
                                                           why: str) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env={**LOCAL_POLICY, "ENVSCAN_TEST_WSH": hook})
    report = assert_fallback_without_js(run)
    assert f"wsh: not used: {why}" in report, report
    assert f"test_hook: ENVSCAN_TEST_WSH={hook}" in report
    assert f"--wsh was not used: {why}" in run.stderr


def test_missing_envscan_js_falls_back(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env=LOCAL_POLICY, js=None)
    report = assert_fallback_without_js(run)
    assert "wsh: not used: envscan.js is not next to envscan.cmd" in report


@pytest.fixture
def windows_without_cscript(tmp_path: Path) -> Iterator[Path]:
    """A Windows directory whose System32 has reg.exe, findstr.exe and chcp.com but no cscript.exe
    and no WindowsPowerShell folder."""
    root = tmp_path / "fakewin"
    system = root / "System32"
    system.mkdir(parents=True)
    for name in ("reg.exe", "findstr.exe", "chcp.com"):
        shutil.copy2(SYSTEM32 / name, system / name)
    yield root


def test_missing_cscript_falls_back(cmd_script: Path, tmp_path: Path, windows_without_cscript: Path) -> None:
    env = {**LOCAL_POLICY, "SystemRoot": str(windows_without_cscript), "windir": str(windows_without_cscript)}
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env=env)
    report = assert_fallback_without_js(run)
    assert f"wsh: not used: cscript.exe was not found in {windows_without_cscript}\\System32" in report, report


def test_no_private_temporary_folder_never_uses_wsh(cmd_script: Path, tmp_path: Path) -> None:
    env = {**LOCAL_POLICY, "TEMP": "C:\\", "TMP": "C:\\", "LOCALAPPDATA": "C:\\"}
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env=env)
    assert js_record(run) is None
    assert run.returncode == 0, run.stderr
    assert "wsh: not used: no temporary folder of yours" in run.report


# ------------------------------------------------------------------ arguments

@pytest.mark.parametrize("raw", ["--wsh --out //srv/x --only session.context",
                                 "--out //srv/x --wsh --only session.context"], ids=["before", "after"])
def test_out_starting_with_double_slash_is_refused_with_wsh(cmd_script: Path, tmp_path: Path, raw: str) -> None:
    run = run_wsh(cmd_script, tmp_path, raw=raw, env=LOCAL_POLICY)
    assert run.returncode == 2, run.stderr
    assert "envscan: --out cannot start with // together with --wsh" in run.stderr, run.stderr
    assert "Usage: envscan.cmd" in run.stderr
    assert js_record(run) is None and run.record is None
    assert run.stdout == "" and list(run.work.iterdir()) == []
    assert list(run.temp.iterdir()) == []


@pytest.mark.parametrize("raw", [
    r"--wsh --out //T:1 --out C:\x --only session.context",
    r"--wsh --out C:\x --out //T:1 --only session.context",
    r"--out //T:1 --out C:\x --wsh --only session.context",
    r"--out C:\x --out //S --wsh --only session.context",
], ids=["wsh-first-slash-first", "wsh-first-slash-last", "wsh-last-slash-first", "wsh-last-slash-last"])
def test_any_repeated_out_starting_with_double_slash_is_refused_with_wsh(cmd_script: Path, tmp_path: Path,
                                                                         raw: str) -> None:
    """Every --out is forwarded, so every one is checked, not only the last (//S would write the
    WSH settings of HKCU)."""
    run = run_wsh(cmd_script, tmp_path, raw=raw, env=LOCAL_POLICY)
    assert run.returncode == 2, run.stderr
    assert "envscan: --out cannot start with // together with --wsh" in run.stderr, run.stderr
    assert js_record(run) is None and run.record is None
    assert run.stdout == "" and list(run.work.iterdir()) == []
    assert list(run.temp.iterdir()) == []


def test_out_starting_with_double_slash_is_not_refused_without_wsh(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, raw="--out //T:1 --version", env=LOCAL_POLICY)
    assert "cannot start with //" not in run.stderr, run.stderr


def test_wsh_takes_no_value(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, raw="--wsh=1", env=LOCAL_POLICY)
    assert run.returncode == 2 and "option --wsh takes no value" in run.stderr, run.stderr
    assert js_record(run) is None


def test_usage_lists_wsh(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--help"])
    assert run.returncode == 0
    assert "--wsh" in run.stdout and "cscript.exe" in run.stdout


# ------------------------------------------------------------------ guidance

@pytest.mark.parametrize("policy,stub,offered", [
    ("restricted", True, True),
    (None, False, True),                 # envscan.ps1 missing
    ("allsigned-gpo", True, False),
    ("blocked", True, False),
], ids=["local-policy", "noscript", "group-policy", "app-control"])
def test_guidance_offers_wsh_only_where_it_may_be_used(cmd_script: Path, tmp_path: Path, policy: str | None,
                                                      stub: bool, offered: bool) -> None:
    env = {"ENVSCAN_TEST_POLICY": policy} if policy else dict(ALLOW_PROCESS_SCOPE)
    run = run_wsh(cmd_script, tmp_path, ONLY, env=env, stub=stub)
    assert js_record(run) is None, "without --wsh envscan.js never runs"
    assert run.returncode == 0, run.stderr
    assert ("envscan.cmd --wsh" in run.stderr) == offered, run.stderr
    assert "--wsh" not in run.report.replace("wsh:", ""), "the report never offers --wsh"


def test_guidance_does_not_offer_wsh_without_envscan_js(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, ONLY, env=LOCAL_POLICY, js=None)
    assert run.returncode == 0, run.stderr
    assert "--wsh" not in run.stderr


# ------------------------------------------------------------------ the children's SystemRoot

HOSTILE_ROOT = {"SystemRoot": r"C:\nonexistent", "SystemDrive": "Q:"}
PS_ROOT_STUB = r"""# envscan.ps1 test stub: records SystemRoot and SystemDrive as PowerShell sees them.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$lines = @('systemroot=[' + $env:SystemRoot + ']', 'systemdrive=[' + $env:SystemDrive + ']')
Set-Content -LiteralPath (Join-Path $here 'ps-root-record.txt') -Value $lines -Encoding ASCII
Write-Output 'C:\fake\envscan-output-folder'
exit 0
"""


def checked_windows() -> tuple[str, str]:
    """The Windows directory and drive the launcher falls back to from windir (inherited)."""
    windows = str(SYSTEM32.parent)
    return windows, windows[:2]


@needs_cscript
def test_envscan_js_gets_the_checked_system_root(cmd_script: Path, tmp_path: Path) -> None:
    """A SystemRoot without a System32 folder is not used; cscript.exe gets the checked one, never
    the caller's (endlocal would otherwise restore it). A SystemDrive that is a drive letter is kept."""
    run = run_wsh(cmd_script, tmp_path, ["--wsh", "--net"], env={**LOCAL_POLICY, **HOSTILE_ROOT})
    assert run.returncode == 0, run.stderr
    windows, _ = checked_windows()
    record = js_record(run) or ""
    assert f"systemroot=[{windows}]\n" in record, record
    assert "systemdrive=[Q:]\n" in record, record
    assert r"C:\nonexistent" not in record


@needs_cscript
def test_envscan_js_gets_a_system_drive_derived_from_the_checked_root(cmd_script: Path, tmp_path: Path) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", "--net"],
                  env={**LOCAL_POLICY, "SystemRoot": r"C:\nonexistent", "SystemDrive": "nodrive"})
    assert run.returncode == 0, run.stderr
    windows, drive = checked_windows()
    record = js_record(run) or ""
    assert f"systemroot=[{windows}]\n" in record and f"systemdrive=[{drive}]\n" in record, record


def test_powershell_gets_the_checked_system_root(cmd_script: Path, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir(parents=True)
    (bundle / "envscan.ps1").write_text(PS_ROOT_STUB, encoding="ascii")
    run = run_cmd(cmd_script, tmp_path, ["--net"], stub=False,
                  env={**ALLOW_PROCESS_SCOPE, "SystemRoot": r"C:\nonexistent", "SystemDrive": "nodrive"})
    assert run.returncode == 0, run.stderr
    record = (bundle / "ps-root-record.txt").read_text(encoding="ascii")
    windows, drive = checked_windows()
    assert f"systemroot=[{windows}]" in record and f"systemdrive=[{drive}]" in record, record


# ------------------------------------------------------------------ App Control (WDAC) and Smart App Control

@pytest.mark.parametrize("hook,why", [
    ("wdac", "App Control for Business (WDAC) policies are active - simulated by ENVSCAN_TEST_WSH=wdac"),
    ("sac", "Smart App Control is on or in evaluation - simulated by ENVSCAN_TEST_WSH=sac"),
])
def test_code_integrity_policies_refuse_wsh(cmd_script: Path, tmp_path: Path, hook: str, why: str) -> None:
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env={**LOCAL_POLICY, "ENVSCAN_TEST_WSH": hook})
    report = assert_fallback_without_js(run)
    assert f"wsh: not used: {why}" in report, report
    assert f"--wsh was not used: {why}" in run.stderr
    assert "envscan.cmd --wsh" not in run.stderr
    assert "ENVSCAN_TEST_WSH is not one of" not in run.stderr


@pytest.mark.parametrize("hook", ["wdac", "sac"])
def test_code_integrity_policies_suppress_the_wsh_offer(cmd_script: Path, tmp_path: Path, hook: str) -> None:
    run = run_wsh(cmd_script, tmp_path, ONLY, env={**LOCAL_POLICY, "ENVSCAN_TEST_WSH": hook})
    assert js_record(run) is None
    assert run.returncode == 0, run.stderr
    assert "envscan.cmd --wsh" not in run.stderr, run.stderr


@pytest.fixture
def windows_with_ci_policy(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[Path]:
    """A Windows directory with cscript.exe, reg.exe, findstr.exe and chcp.com, no WindowsPowerShell,
    and one code-integrity policy file (the parameter: a path under System32\\CodeIntegrity)."""
    root = tmp_path / "ciwin"
    system = root / "System32"
    system.mkdir(parents=True)
    for name in ("cscript.exe", "reg.exe", "findstr.exe", "chcp.com"):
        shutil.copy2(SYSTEM32 / name, system / name)
    policy = system / "CodeIntegrity" / request.param
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_bytes(b"not a real policy")
    yield root


CI_FILES = ["SiPolicy.p7b"]


@needs_cscript
@pytest.mark.parametrize("windows_with_ci_policy", CI_FILES, indirect=True, ids=["sipolicy"])
def test_active_wdac_policy_file_refuses_wsh(cmd_script: Path, tmp_path: Path, windows_with_ci_policy: Path) -> None:
    env = {**LOCAL_POLICY, "SystemRoot": str(windows_with_ci_policy), "windir": str(windows_with_ci_policy)}
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env=env)
    report = assert_fallback_without_js(run)
    assert "wsh: not used: App Control for Business (WDAC) policies are active" in report, report
    assert "envscan.cmd --wsh" not in run.stderr
    hint = run_wsh(cmd_script, tmp_path / "hint", ONLY, env=env)
    assert hint.returncode == 0, hint.stderr
    assert "envscan.cmd --wsh" not in hint.stderr, hint.stderr


# ------------------------------------------------------------------ hostile values

WSH_HOSTILE = ("COMPUTERNAME", "PATHEXT", "USERPROFILE", "date", "time", "CD", "RANDOM", "ERRORLEVEL",
               "__ES_RELAUNCHED", "__ES_ERR", "__ES_LOCALDRV", "__ES_EXIT_BASE", "__ES_JSFWD", "__ES_WSH_WHY",
               "__ES_WSH_RC", "__ES_JS_RC", "__ES_SV_KIND", "__ES_SV_WSH", "__ES_OPT_WSH", "ENVSCAN_TEST_WSH")


@needs_cscript
def test_hostile_environment_values_never_run_on_the_wsh_path(cmd_script: Path, tmp_path: Path) -> None:
    env = {**hostile_env(tmp_path, WSH_HOSTILE), **LOCAL_POLICY}
    run = run_wsh(cmd_script, tmp_path, ["--wsh", "--net"], env=env)
    assert_not_injected(run, tmp_path)
    assert run.returncode == 0, run.stderr
    record = js_record(run) or ""
    assert "es_vars=__ES_EXIT_BASE\n" in record and "exit_base=[100]\n" in record, record
    assert js_args(run) == ["--net"]
    assert "ENVSCAN_TEST_WSH is not one of" in run.stderr


@needs_cscript
def test_hostile_values_never_run_when_wsh_fails(cmd_script: Path, tmp_path: Path) -> None:
    env = {**hostile_env(tmp_path, WSH_HOSTILE), **LOCAL_POLICY}
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env=env, js_exit="throw")
    assert_not_injected(run, tmp_path)
    assert run.returncode == 0, run.stderr
    report = run.report
    assert "wsh: envscan.js ran with cscript.exe and ended with exit code 0" in report
    assert "note: ENVSCAN_TEST_WSH is not one of" in report


def test_hostile_launcher_values_never_run_with_wsh(cmd_script: Path, tmp_path: Path) -> None:
    """With TEMP, TMP and LOCALAPPDATA refused there is no private temporary folder: no WSH."""
    env = {**hostile_env(tmp_path, LAUNCHER_HOSTILE), **LOCAL_POLICY, "ENVSCAN_TEST_WSH": hostile(tmp_path, "hook")}
    run = run_wsh(cmd_script, tmp_path, ["--wsh", *ONLY], env=env)
    assert_not_injected(run, tmp_path)
    assert js_record(run) is None
    assert run.returncode in (0, 1), run.stderr


def test_wsh_part_launches_cscript_only_once_and_safely() -> None:
    """Source check: one cscript.exe launch, the offset only for it, no //B, no wscript, no FOR /F child."""
    source = "".join(p.read_text(encoding="ascii") for p in sorted((Path(__file__).parents[1] / "src" / "cmd")
                                                                    .glob("05-*.cmd")))
    assert source, "the WSH part 05-wsh.cmd is missing"
    code = [line for line in source.splitlines() if line.strip() and not line.lower().startswith("rem")]
    assert not [line for line in code if "in ('" in line or "//B" in line or "wscript" in line.lower()]
    launch = [line for line in code if "cscript.exe\" //nologo" in line]
    assert len(launch) == 1, launch
    assert '//nologo //E:jscript "%__ES_DIR%envscan.js"%__ES_JSFWD% <nul 2>"%__ES_ERR%"' in launch[0]
    assert 'set "__ES_EXIT_BASE=100" & "%__ES_SYS%\\cscript.exe"' in launch[0]
    assert 'set "__ES_EXIT_BASE=" & ' in launch[0]
