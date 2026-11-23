"""Integration tests for the argument handling of envscan.cmd: what PowerShell receives, and which
arguments stop the launcher before anything starts.

PowerShell (CommandLineToArgvW) and cmd.exe quote differently: cmd.exe takes "C:\\x\\" as the
path C:\\x\\, PowerShell reads \\" as a literal quote. The launcher therefore never forwards the
command line it was given; it rebuilds it from the checked values.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from test_cmd_launcher import ALLOW_PROCESS_SCOPE, CMD, CMD32, Run, cmd_script, run_cmd  # noqa: F401

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name != "nt", reason="envscan.cmd needs cmd.exe"),
]

ALLOW = {**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0"}


def stub_args(run: Run) -> list[str]:
    assert run.record is not None, f"the stub did not run: {run.stderr}"
    return [line[5:-1] for line in run.record.splitlines() if line.startswith("arg=[")]


def assert_stopped(run: Run, message: str) -> None:
    """Exit code 2 with the message and the usage on stderr; PowerShell and the fallback never ran."""
    assert run.returncode == 2, run.stderr
    assert f"envscan: {message}" in run.stderr, run.stderr
    assert "Usage: envscan.cmd" in run.stderr
    assert run.record is None, "PowerShell must not start"
    assert run.stdout == ""
    assert list(run.work.iterdir()) == [], "nothing may be written"
    assert list(run.temp.iterdir()) == [], "no temporary file may be left"


def test_trailing_backslash_reaches_powershell_unchanged(cmd_script: Path, tmp_path: Path) -> None:
    spaced = tmp_path / "scan out"
    run = run_cmd(cmd_script, tmp_path / "q", raw=f'--out "{spaced}\\" --deep --only env.* --timeout 30', env=ALLOW)
    assert run.returncode == 0, run.stderr
    assert stub_args(run) == ["--out", f"{spaced}\\", "--deep", "--only", "env.*", "--timeout", "30"]
    plain = tmp_path / "plain"
    run = run_cmd(cmd_script, tmp_path / "p", raw=f"--net --out {plain}\\\\ -deep", env=ALLOW)
    assert run.returncode == 0, run.stderr
    assert stub_args(run) == ["--net", "--out", f"{plain}\\\\", "--deep"]
    assert list(run.temp.iterdir()) == []


def test_comma_lists_and_equals_signs_reach_powershell_as_one_value(cmd_script: Path, tmp_path: Path) -> None:
    run = run_cmd(cmd_script, tmp_path, raw="--only net.proxy,session.context;os.* --skip=net.routes", env=ALLOW)
    assert run.returncode == 0, run.stderr
    assert stub_args(run) == ["--only", "net.proxy,session.context,os.*", "--skip", "net.routes"]


@pytest.mark.parametrize("raw", [
    '--deep --out "{tmp}\\x y',
    'x"y',
    '--net "a"b"',
    '--only "os.identity',
    '--timeout "30',
], ids=["unterminated-value", "inner-quote", "quotes-inside", "unterminated-list", "unterminated-number"])
def test_quote_characters_stop_the_launcher(cmd_script: Path, tmp_path: Path, raw: str) -> None:
    run = run_cmd(cmd_script, tmp_path, raw=raw.format(tmp=tmp_path), env=ALLOW)
    assert_stopped(run, "an argument contains a quote character")


@pytest.mark.parametrize("args, message", [
    (["--net", "--bogus"], "unknown argument: --bogus"),
    (["--out"], "--out needs a directory"),
    (["--timeout", "soon"], "--timeout needs a number of seconds"),
    (["--budget"], "--budget needs a value"),
    (["--help", "--bogus"], "unknown argument: --bogus"),
])
def test_bad_arguments_stop_the_launcher(cmd_script: Path, tmp_path: Path, args: list[str], message: str) -> None:
    assert_stopped(run_cmd(cmd_script, tmp_path, args, env=ALLOW), message)


@pytest.mark.parametrize("raw, name", [
    ("--deep=0", "--deep"),
    ("--net=false", "--net"),
    ("--no-redact=false", "--no-redact"),
    ("-deep=1", "--deep"),
    ("--list-probes=all", "--list-probes"),
    ("--version=1", "--version"),
    ("--help=1", "--help"),
    ("--fallback=yes", "--fallback"),
    ("--deep 0", "--deep"),
])
def test_flags_take_no_value(cmd_script: Path, tmp_path: Path, raw: str, name: str) -> None:
    """cmd.exe splits --deep=0 into --deep and 0: a flag followed by a value is an error, never
    a silently enabled flag."""
    assert_stopped(run_cmd(cmd_script, tmp_path / "launch", raw=raw, env=ALLOW), f"option {name} takes no value")
    fallback = run_cmd(cmd_script, tmp_path / "fallback", raw=f"--fallback {raw}")
    if name == "--fallback":
        return
    assert_stopped(fallback, f"option {name} takes no value")


@pytest.mark.parametrize("raw", ["--timeout 1234567890", "--budget 0000000001"], ids=["timeout", "budget"])
def test_numbers_take_one_to_nine_digits(cmd_script: Path, tmp_path: Path, raw: str) -> None:
    """--timeout and --budget take 1-9 digits, as envscan.ps1 and envscan.sh do."""
    message = f"{raw.split()[0]} needs a number of seconds"
    assert_stopped(run_cmd(cmd_script, tmp_path / "launch", raw=raw, env=ALLOW), message)
    assert_stopped(run_cmd(cmd_script, tmp_path / "fallback", raw=f"--fallback {raw}"), message)
    run = run_cmd(cmd_script, tmp_path / "nine", raw=raw.split()[0] + " 123456789", env=ALLOW)
    assert run.returncode == 0, run.stderr
    assert stub_args(run) == [raw.split()[0], "123456789"]


def assert_help(run: Run) -> None:
    """Usage on stdout and exit code 0; nothing started, written or left behind."""
    assert run.returncode == 0, run.stderr
    assert "Usage: envscan.cmd [options]" in run.stdout, run.stdout + run.stderr
    assert run.record is None, "PowerShell must not start"
    assert list(run.work.iterdir()) == [], "nothing may be written"
    assert list(run.temp.iterdir()) == [], "no temporary file may be left"


@pytest.mark.parametrize("exe", [CMD, CMD32], ids=["cmd64", "cmd32"])
@pytest.mark.parametrize("raw", ["/?", "--net /?", "--deep --only os.identity /?", "--net x/?y"],
                         ids=["alone", "after-flag", "after-list", "inside-argument"])
def test_slash_question_mark_shows_help(cmd_script: Path, tmp_path: Path, raw: str, exe: str) -> None:
    """REM prints its own help instead of the echoed line for an argument with /? in it (its text
    is localized and never read): that argument is a help request, as --help is."""
    if not Path(exe).exists():
        pytest.skip(f"{exe} not found")
    assert_help(run_cmd(cmd_script, tmp_path / "launch", raw=raw, env=ALLOW, exe=exe))
    assert_help(run_cmd(cmd_script, tmp_path / "fallback", raw=f"--fallback {raw}", exe=exe))


@pytest.mark.parametrize("args, message", [
    (["--only", "session.context,nope.nothing"], "--only: pattern 'nope.nothing' matches no probe"),
    (["--skip", "zz.*"], "--skip: pattern 'zz.*' matches no probe"),
    (["--only", "os.id&x"], "--only: invalid pattern 'os.id&x' (allowed: letters, digits, . _ - *)"),
    (["--skip", "net.proxy,a%b"], "--skip: invalid pattern 'a%b' (allowed: letters, digits, . _ - *)"),
])
def test_probe_patterns_are_checked_before_anything_starts(cmd_script: Path, tmp_path: Path, args: list[str],
                                                           message: str) -> None:
    assert_stopped(run_cmd(cmd_script, tmp_path / "launch", args, env=ALLOW), message)
    assert_stopped(run_cmd(cmd_script, tmp_path / "fallback", ["--fallback", *args]), message)


# A cmd.exe command line expands %NAME% once more, with no escape inside quotes: the 64-bit
# relaunch of a 32-bit cmd.exe turned --out C:\x\%COMSPEC% into another path, and a variable
# holding a quote and & ran the rest as commands. --out refuses % whatever the bitness. The
# caller's command line below writes %^NAME%: cmd.exe finds no variable "^NAME", keeps the text and
# drops the caret, so envscan.cmd receives %NAME% itself.
EVIL = 'x" & mkdir "{root}\\inj-pct" & echo INJECTED-PCT & rem "'
PERCENT_OUT = {
    "comspec": "{root}\\x\\%^COMSPEC%",
    "quote-and-ampersand": "{root}\\x\\%^ENVSCAN_EVIL%",
}


def assert_nothing_ran(run: Run, root: Path) -> None:
    assert not (root / "inj-pct").exists(), "a value from the environment ran as a command"
    assert "INJECTED-PCT" not in [line.strip() for line in (run.stdout + run.stderr).splitlines()]


@pytest.mark.parametrize("fallback", [False, True], ids=["launch", "fallback"])
@pytest.mark.parametrize("exe", [CMD, CMD32], ids=["cmd64", "cmd32-relaunch"])
@pytest.mark.parametrize("name", list(PERCENT_OUT))
def test_percent_in_out_is_refused(cmd_script: Path, tmp_path: Path, name: str, exe: str, fallback: bool) -> None:
    if not Path(exe).exists():
        pytest.skip(f"{exe} not found")
    if " " in str(tmp_path):
        pytest.skip("the unquoted %^NAME% argument needs a temporary path without spaces")
    raw = ("--fallback " if fallback else "") + "--out " + PERCENT_OUT[name].format(root=tmp_path) + " --net"
    run = run_cmd(cmd_script, tmp_path, raw=raw, env={**ALLOW, "ENVSCAN_EVIL": EVIL.format(root=tmp_path)}, exe=exe)
    assert_nothing_ran(run, tmp_path)
    assert_stopped(run, "--out needs a directory path without quotes or % < > | * ?")


@pytest.mark.parametrize("exe", [CMD, CMD32], ids=["cmd64", "cmd32-relaunch"])
@pytest.mark.parametrize("raw, message", [
    ("--only os.%^ENVSCAN_EVIL%", "--only: invalid pattern 'os.%ENVSCAN_EVIL%'"),
    ("--skip %^COMSPEC%", "--skip: invalid pattern '%COMSPEC%'"),
    ("--timeout 1%^ENVSCAN_EVIL%", "--timeout needs a number of seconds"),
    ("--budget %^COMSPEC%", "--budget needs a number of seconds"),
], ids=["only", "skip", "timeout", "budget"])
def test_no_other_forwarded_value_holds_percent(cmd_script: Path, tmp_path: Path, raw: str, message: str,
                                                exe: str) -> None:
    """Patterns (letters, digits, . _ - *) and numbers (digits) are the only other values the
    launcher forwards; a percent sign in them stops it before the relaunch."""
    if not Path(exe).exists():
        pytest.skip(f"{exe} not found")
    run = run_cmd(cmd_script, tmp_path, raw=raw + " --net", env={**ALLOW, "ENVSCAN_EVIL": EVIL.format(root=tmp_path)},
                  exe=exe)
    assert_nothing_ran(run, tmp_path)
    assert_stopped(run, message)


@pytest.mark.parametrize("exe", [CMD, CMD32], ids=["cmd64", "cmd32-relaunch"])
def test_percent_in_the_script_path_is_not_expanded(cmd_script: Path, tmp_path: Path, exe: str) -> None:
    """The 64-bit relaunch names the script through a variable that the new cmd.exe expands once,
    so a folder name holding %NAME% is never expanded again."""
    if not Path(exe).exists():
        pytest.skip(f"{exe} not found")
    if " " in str(tmp_path):
        pytest.skip("the unquoted %^NAME% script path needs a temporary path without spaces")
    root = tmp_path / "a%ENVSCAN_EVIL%b"
    invoke = str(root / "bundle" / "envscan.cmd").replace("%ENVSCAN_EVIL%", "%^ENVSCAN_EVIL%")
    run = run_cmd(cmd_script, root, ["--net"], env={**ALLOW, "ENVSCAN_EVIL": EVIL.format(root=tmp_path)}, exe=exe,
                  invoke=invoke)
    assert_nothing_ran(run, tmp_path)
    assert run.returncode == 0, run.stderr
    assert run.record is not None and "arg=[--net]" in run.record, run.stderr
    assert "arch=x86\n" not in run.record
    assert list(run.temp.iterdir()) == []
