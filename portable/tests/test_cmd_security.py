"""Integration tests for envscan.cmd against hostile values from outside and for its folder rules.

Environment values, arguments and localized text reach a batch file through %expansion%, where a
quote ends the quoted string and the rest runs as commands. Every hostile value below would
create a marker folder if it were ever expanded that way: unquoted (the first mkdir) or inside
quotes (the second mkdir). The run must complete and no marker folder may exist afterwards.
"""
from __future__ import annotations

import datetime as dt
import os
import re
from pathlib import Path

import pytest

from conftest import PORTABLE, find_output
from spec import load_spec
from test_cmd_launcher import (ALLOW_PROCESS_SCOPE, CMD32, FAKE_FOLDER, Run, cmd_probe_ids,  # noqa: F401
                               cmd_script, run_cmd, section)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name != "nt", reason="envscan.cmd needs cmd.exe"),
]

# Read by the fallback collector (paths, names, policy, date and time, cached __ES_* values, the
# dynamic variables). COMSPEC is left alone: cmd.exe itself starts FOR /F commands with it.
FALLBACK_HOSTILE = (
    "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "ProgramData", "ProgramFiles",
    "ProgramFiles(x86)", "PATHEXT", "DOTNET_ROOT", "OneDrive", "OneDriveCommercial", "OneDriveConsumer",
    "COMPUTERNAME", "USERNAME", "USERDOMAIN", "HOMEDRIVE", "HOMEPATH", "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_ARCHITEW6432", "ENVSCAN_TEST_POLICY", "PSExecutionPolicyPreference", "date", "time",
    "SystemRoot", "windir", "SystemDrive", "CD", "RANDOM", "ERRORLEVEL", "__ES_RELAUNCHED",
    "__ES_LOCALDRV", "__ES_ERR", "__ES_PFN", "__ES_OUTDIR", "__ES_CWD_NOTE",
)
# Read by the launcher before PowerShell starts; PowerShell itself needs a sane Windows directory.
LAUNCHER_HOSTILE = ("TEMP", "TMP", "LOCALAPPDATA", "USERPROFILE", "PATHEXT", "COMPUTERNAME", "date", "time",
                    "CD", "RANDOM", "ERRORLEVEL", "__ES_RELAUNCHED", "__ES_ERR", "__ES_LOCALDRV")
SYNTAX_ERRORS = ("was unexpected at this time", "The syntax of the command is incorrect")


def hostile(root: Path, tag: str) -> str:
    """mkdir root/inj-<tag>-1 when %expanded% unquoted, root/inj-<tag>-2 inside quotes."""
    return f'&mkdir "{root}\\inj-{tag}-1"&rem "&mkdir "{root}\\inj-{tag}-2"&rem "'


def hostile_env(root: Path, names: tuple[str, ...]) -> dict[str, str]:
    env = {name: hostile(root, re.sub(r"\W", "_", name)) for name in names}
    env["PATH"] = os.environ.get("PATH", "") + ";" + hostile(root, "PATH")
    return env


def assert_not_injected(run: Run, root: Path) -> None:
    markers = sorted(p.name for p in root.rglob("inj-*") if p.is_dir())
    assert markers == [], f"hostile values ran as commands: {markers}"
    for text in (run.stdout, run.stderr):
        for message in SYNTAX_ERRORS:
            assert message not in text, text


@pytest.mark.slow
def test_hostile_environment_values_never_run_in_the_fallback(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--skip", "pkg.installed"],
                  env=hostile_env(tmp_path, FALLBACK_HOSTILE))
    assert_not_injected(run, tmp_path)
    assert run.returncode in (0, 1), run.stderr
    folder = find_output(run.work)
    assert run.stdout_lines == [str(folder)]
    report = run.report
    assert "=== summary ===" in report and "result: " in report
    for message in SYNTAX_ERRORS:
        assert message not in report
    # Values that are not safe paths or words are reported, never used.
    assert "PATHEXT holds characters other than" in section(report, "tools.inventory")
    assert "TEMP: holds characters a path cannot contain, not tested" in section(report, "fs.locations")
    assert folder.name.startswith("envscan-host-"), folder.name  # COMPUTERNAME refused
    # No usable temporary folder: program output went to envscan-capture.tmp in the output folder.
    assert sorted(p.name for p in folder.iterdir()) == ["envscan-fallback.txt"], "the capture file was left"


def test_hostile_environment_values_never_run_in_the_launcher(cmd_script: Path, tmp_path: Path) -> None:
    env = {**hostile_env(tmp_path, LAUNCHER_HOSTILE), **ALLOW_PROCESS_SCOPE,
           "ENVSCAN_TEST_POLICY": "allowed", "STUB_EXIT": "0"}
    run = run_cmd(cmd_script, tmp_path, ["--net"], env=env)
    assert_not_injected(run, tmp_path)
    assert run.record is not None, run.stderr
    assert "arg=[--net]" in run.record and "es_vars=\n" in run.record
    assert run.returncode == 0, run.stderr
    assert run.stdout_lines == [FAKE_FOLDER]


def test_hostile_policy_values_are_ignored_by_the_prediction(cmd_script: Path, tmp_path: Path) -> None:
    env = hostile_env(tmp_path, ("ENVSCAN_TEST_POLICY", "PSExecutionPolicyPreference"))
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "shell.info"], env=env)
    assert_not_injected(run, tmp_path)
    assert run.returncode in (0, 1), run.stderr
    text = section(run.report, "shell.info")
    assert re.search(r"^predicted_policy: (AllSigned|Bypass|RemoteSigned|Restricted|Unrestricted)$", text, re.M), text
    assert "note: ENVSCAN_TEST_POLICY is not one of" in text


def test_arguments_reach_the_fallback_unchanged_after_powershell(cmd_script: Path, tmp_path: Path) -> None:
    """^ and & in an argument survive the way back from PowerShell (no "call" with the arguments).
    (--out refuses %: see test_cmd_args.test_percent_in_out_is_refused.)"""
    out_dir = tmp_path / "o&u^t d (x)"
    run = run_cmd(cmd_script, tmp_path, ["--only", "session.context", "--out", str(out_dir)],
                  env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "7"})
    assert run.record is not None, run.stderr
    assert f"arg=[{out_dir}]" in run.record
    assert run.returncode == 0, run.stderr
    folder = find_output(out_dir)
    assert run.stdout_lines[-1] == str(folder)
    assert "exit code 7" in (folder / "envscan-fallback.txt").read_text(encoding="utf-8", errors="replace")


def test_unquoted_comma_lists_and_equals_signs(cmd_script: Path, tmp_path: Path, cmd_probe_ids: list[str]) -> None:
    """cmd.exe splits --only a,b into --only a b and --skip=x into --skip x."""
    run = run_cmd(cmd_script, tmp_path, raw="--fallback --only net.proxy,session.context;os.* --skip=net.proxy")
    assert run.returncode in (0, 1), run.stderr
    report = run.report
    ran = {pid for pid in cmd_probe_ids if not section(report, pid).endswith("status: skipped")}
    assert ran == {"session.context", *(p for p in cmd_probe_ids if p.startswith("os."))}
    assert "only: net.proxy,session.context,os.*" in report
    # chcp.com is read by its last number, whatever the language of its text.
    assert re.search(r"^encoding: console code page \d+$", report, re.M)
    assert re.search(r"^console_code_page: \d+$", section(report, "session.context"), re.M)


def test_dates_with_parentheses_give_a_utc_folder_name(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "os.time_locale"],
                  env={"date": "2026/11/11(Wed)", "time": "12:34:56.78"})
    assert run.returncode in (0, 1), run.stderr
    offset = dt.datetime.now().astimezone().utcoffset()
    assert offset is not None
    expected = (dt.datetime(2026, 11, 11, 12, 34, 56) - offset).strftime("%Y%m%dT%H%M%S")
    assert find_output(run.work).name.endswith(f"-{expected}Z")
    text = section(run.report, "os.time_locale")
    assert "local_time: 2026/11/11(Wed) 12:34:56.78" in text
    assert f"utc_time: {expected}Z" in text


def test_default_output_skips_desktop_documents_and_onedrive(cmd_script: Path, tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    synced = tmp_path / "synced"
    places = {"Desktop": profile / "Desktop" / "project", "Documents": profile / "Documents" / "project",
              "OneDrive": synced / "project"}
    for label, cwd in places.items():
        cwd.mkdir(parents=True)
        run = run_cmd(cmd_script, tmp_path / label, ["--fallback", "--only", "session.context"], cwd=cwd,
                      env={"USERPROFILE": str(profile), "OneDrive": str(synced)})
        assert run.returncode == 0, run.stderr
        folder = Path(run.stdout_lines[-1])
        assert folder.parent == profile, (label, folder)
        assert f"output_skipped: current_directory ({label})" in (folder / "envscan-fallback.txt").read_text()
        assert list(cwd.iterdir()) == [], f"wrote into {label}"
    explicit = profile / "Desktop" / "chosen"
    run = run_cmd(cmd_script, tmp_path / "explicit", ["--fallback", "--only", "session.context", "--out", str(explicit)],
                  cwd=places["Desktop"], env={"USERPROFILE": str(profile)})
    assert run.returncode == 0, run.stderr
    assert Path(run.stdout_lines[-1]).parent == explicit, "--out is used as given"


def test_write_tests_skip_personal_synced_and_network_folders(cmd_script: Path, tmp_path: Path) -> None:
    profile = tmp_path / "profile"
    for sub in ("Desktop/pd", "Documents/local", "OneDrive/roaming"):
        (profile / sub).mkdir(parents=True)
    unc = r"\\127.0.0.1\envscan-test-share"
    env = {"USERPROFILE": str(profile), "ProgramData": str(profile / "Desktop" / "pd"),
           "LOCALAPPDATA": str(profile / "Documents" / "local"), "APPDATA": str(profile / "OneDrive" / "roaming"),
           "OneDrive": str(profile / "OneDrive"), "TEMP": unc + r"\temp", "TMP": unc + r"\temp",
           "DOTNET_ROOT": unc + r"\dotnet"}
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", "fs.locations,runtime.dotnet"], env=env)
    assert run.returncode in (0, 1), run.stderr
    text = section(run.report, "fs.locations")
    never = "which is never written to, not tested"
    assert f"TEMP: {unc}\\temp - network location, not tested" in text
    assert f"APPDATA: {profile}\\OneDrive\\roaming - inside OneDrive, {never}" in text
    assert f"LOCALAPPDATA: {profile}\\Documents\\local - inside Documents, {never}" in text
    assert f"ProgramData: {profile}\\Desktop\\pd - inside Desktop, {never}" in text
    assert f"USERPROFILE: {profile} - writable" in text
    assert f"dotnet_root: {unc}\\dotnet - network location, not checked" in section(run.report, "runtime.dotnet")
    assert not [p for p in tmp_path.rglob("envscan-probe-*.tmp")]
    for sub in ("Desktop/pd", "Documents/local", "OneDrive/roaming"):
        assert list((profile / sub).iterdir()) == []


def test_argument_errors_stop_the_fallback(cmd_script: Path, tmp_path: Path) -> None:
    empty = run_cmd(cmd_script, tmp_path / "empty", raw='--fallback "" --only session.context')
    assert empty.returncode == 2 and "an argument is empty" in empty.stderr
    quote = run_cmd(cmd_script, tmp_path / "quote", raw='--fallback --only session.context x"y')
    assert quote.returncode == 2 and "an argument contains a quote character" in quote.stderr
    unknown = run_cmd(cmd_script, tmp_path / "unknown", ["--fallback", "--only", "session.context,nope.nothing"])
    assert unknown.returncode == 2
    assert "--only: pattern 'nope.nothing' matches no probe" in unknown.stderr
    wildcard = run_cmd(cmd_script, tmp_path / "wild", ["--fallback", "--skip", "zz.*"])
    assert wildcard.returncode == 2 and "--skip: pattern 'zz.*' matches no probe" in wildcard.stderr
    for run in (empty, quote, unknown, wildcard):
        assert run.stdout == "" and not list(run.work.iterdir())


# A quote inside an argument, or one that is never closed, used to turn the rest of the command
# line into commands: in "set" while the arguments were read, and in the PowerShell command line,
# which forwarded them as given. Every marker below is created if any part of it runs.
ARGUMENT_INJECTIONS = {
    "inner-quote": 'x"&mkdir "{root}\\inj-inner-1"&rem ',
    "inner-quote-value": '--out x"&mkdir "{root}\\inj-value-1"&rem ',
    "inner-quote-list": '--only os.identity x"&mkdir "{root}\\inj-list-1"&rem ',
    "inner-quote-number": '--timeout 1"&mkdir "{root}\\inj-number-1"&rem ',
    "unterminated": '--deep --out "{root}\\R&mkdir inj-open-1',
    "unterminated-echo": '--out "{root}\\R&echo INJECTED-ECHO',
}


@pytest.mark.parametrize("fallback", [False, True], ids=["launch", "fallback"])
@pytest.mark.parametrize("name", list(ARGUMENT_INJECTIONS))
def test_quotes_in_arguments_never_run_commands(cmd_script: Path, tmp_path: Path, name: str, fallback: bool) -> None:
    raw = ARGUMENT_INJECTIONS[name].format(root=tmp_path)
    run = run_cmd(cmd_script, tmp_path, raw=("--fallback " if fallback else "") + raw,
                  env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0"})
    assert_not_injected(run, tmp_path)
    assert "INJECTED-ECHO" not in run.stdout + run.stderr
    assert run.returncode == 2, run.stderr
    assert "envscan: an argument contains a quote character" in run.stderr
    assert run.record is None, "PowerShell must not start"
    assert list(run.temp.iterdir()) == [], "the temporary error file was left behind"
    assert not list(run.work.iterdir())


def test_full_scan_ids_outside_the_fallback_are_accepted(cmd_script: Path, tmp_path: Path,
                                                         cmd_probe_ids: list[str]) -> None:
    others = [p["id"] for p in load_spec(PORTABLE / "spec").probes if p["id"] not in cmd_probe_ids]
    assert others, "the full scan has probes the fallback does not implement"
    run = run_cmd(cmd_script, tmp_path, ["--fallback", "--only", others[0]])
    assert run.returncode == 0, run.stderr
    assert all(section(run.report, pid).endswith("status: skipped") for pid in cmd_probe_ids)


# The caller's cmd.exe removes the ^ before & | < >, so envscan.cmd receives them bare: a %1 or
# %* expanded outside quotes runs the rest as a command (the launch line used to forward %*, and
# so did the 64-bit relaunch of a 32-bit cmd.exe). Accepted values reach PowerShell in quotes.
CARET_LINE = "INJECTED-CARET"
ESCAPED_SPECIALS = {
    "ampersand-value": (r"--out {root}\R^&echo.INJECTED-CARET", None),
    "ampersand-list": ("--only os.identity^&echo.INJECTED-CARET",
                       "--only: invalid pattern 'os.identity&echo.INJECTED-CARET'"),
    "pipe-value": (r"--out {root}\R^|echo.INJECTED-CARET", "--out needs a directory path without quotes"),
    "redirect-value": (r"--out {root}\R^>{root}\inj-caret-file", "--out needs a directory path without quotes"),
}


def assert_no_caret_injection(run: Run, root: Path) -> None:
    assert_not_injected(run, root)
    lines = [line.strip() for line in (run.stdout + run.stderr).splitlines()]
    assert CARET_LINE not in lines, "an escaped & ran the rest of an argument"
    assert not (root / "inj-caret-file").exists(), "an escaped > redirected output"


@pytest.mark.parametrize("fallback", [False, True], ids=["launch", "fallback"])
@pytest.mark.parametrize("name", list(ESCAPED_SPECIALS))
def test_escaped_specials_in_arguments_never_run_commands(cmd_script: Path, tmp_path: Path, name: str,
                                                          fallback: bool) -> None:
    raw, message = ESCAPED_SPECIALS[name]
    run = run_cmd(cmd_script, tmp_path, raw=("--fallback " if fallback else "") + raw.format(root=tmp_path),
                  env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0"})
    assert_no_caret_injection(run, tmp_path)
    assert list(run.temp.iterdir()) == [], "a temporary file was left behind"
    if message:
        assert run.returncode == 2, run.stderr
        assert f"envscan: {message}" in run.stderr, run.stderr
        assert run.record is None
    elif fallback:
        assert run.returncode in (0, 1), run.stderr
        assert list((tmp_path / f"R&echo.{CARET_LINE}").glob("envscan-*")), "the report folder is missing"
    else:
        assert run.returncode == 0, run.stderr
        assert run.record is not None and f"arg=[{tmp_path / ('R&echo.' + CARET_LINE)}]" in run.record


@pytest.mark.skipif(not Path(CMD32).exists(), reason="no 32-bit cmd.exe on this system")
def test_escaped_specials_survive_the_64bit_relaunch(cmd_script: Path, tmp_path: Path) -> None:
    value = tmp_path / ("R&echo." + CARET_LINE)
    raw = "--net --out " + str(value).replace("&", "^&")
    run = run_cmd(cmd_script, tmp_path, raw=raw, env={**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0"}, exe=CMD32)
    assert_no_caret_injection(run, tmp_path)
    assert run.returncode == 0, run.stderr
    record = run.record or ""
    assert "arch=x86\n" not in record and "arg=[--net]" in record
    assert f"arg=[{value}]" in record
    assert list(run.temp.iterdir()) == []
