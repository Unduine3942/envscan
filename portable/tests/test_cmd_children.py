"""envscan.cmd starts no cmd.exe of its own.

cmd.exe runs the command of FOR /F ('command') in a new "%ComSpec% /c command", without /D, so the
AutoRun commands of HKLM/HKCU\\Software\\Microsoft\\Command Processor would run for every one of
them, with the console as stdin and no time limit. The launcher and the fallback run programs
directly instead, with their output in a temporary file that FOR /F then reads.

ComSpec is replaced by a stand-in that logs its command line and passes it on to cmd.exe, so every
cmd.exe child is counted.
"""
from __future__ import annotations

import ctypes
import os
import subprocess
from pathlib import Path

import pytest

from test_cmd_launcher import ALLOW_PROCESS_SCOPE, CMD, cmd_script, run_cmd  # noqa: F401

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name != "nt", reason="envscan.cmd needs cmd.exe"),
]

_NET = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Microsoft.NET"
CSC = [_NET / "Framework64" / "v4.0.30319" / "csc.exe", _NET / "Framework" / "v4.0.30319" / "csc.exe"]
STAND_IN = r"""
using System;
using System.Diagnostics;
using System.IO;

class ComSpecLogger
{
    static int Main()
    {
        string line = Environment.CommandLine;
        File.AppendAllText(Environment.GetEnvironmentVariable("ENVSCAN_COMSPEC_LOG"), line + "\r\n");
        int i = 0;
        if (line.StartsWith("\"")) { i = line.IndexOf('"', 1); i = i < 0 ? line.Length : i + 1; }
        else { while (i < line.Length && line[i] != ' ' && line[i] != '\t') i++; }
        ProcessStartInfo info = new ProcessStartInfo(Environment.GetEnvironmentVariable("ENVSCAN_COMSPEC_REAL"),
                                                     line.Substring(i).TrimStart());
        info.UseShellExecute = false;
        Process child = Process.Start(info);
        child.WaitForExit();
        return child.ExitCode;
    }
}
"""


@pytest.fixture(scope="session")
def comspec_logger(tmp_path_factory: pytest.TempPathFactory) -> Path:
    csc = next((path for path in CSC if path.is_file()), None)
    if csc is None:
        pytest.skip("needs the .NET Framework C# compiler (csc.exe) to build the ComSpec stand-in")
    folder = tmp_path_factory.mktemp("comspec")
    source = folder / "logger.cs"
    source.write_text(STAND_IN, encoding="ascii")
    exe = folder / "comspec-logger.exe"
    proc = subprocess.run([str(csc), "/nologo", f"/out:{exe}", str(source)], capture_output=True, timeout=300,
                          stdin=subprocess.DEVNULL)
    assert proc.returncode == 0 and exe.is_file(), proc.stdout.decode("oem", "replace")
    return exe


def logged_env(logger: Path, log: Path) -> dict[str, str]:
    return {"ComSpec": str(logger), "ENVSCAN_COMSPEC_LOG": str(log), "ENVSCAN_COMSPEC_REAL": CMD}


def children(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8", errors="replace").splitlines() if log.exists() else []


def test_the_stand_in_counts_for_f_children(comspec_logger: Path, tmp_path: Path) -> None:
    script = tmp_path / "probe.cmd"
    script.write_bytes(b"@echo off\r\nfor /f %%a in ('echo child') do echo got %%a\r\n")
    log = tmp_path / "comspec.log"
    env = {**os.environ, **logged_env(comspec_logger, log)}
    proc = subprocess.run(f'"{CMD}" /d /s /c ""{script}""', capture_output=True, env=env, timeout=120,
                          stdin=subprocess.DEVNULL)
    assert b"got child" in proc.stdout
    assert len(children(log)) == 1


@pytest.mark.parametrize("args, extra", [
    (["--help"], {}),
    (["--fallback", "--version"], {}),
    (["--fallback", "--list-probes"], {}),
    (["--net", "--bogus"], {}),
    (["--net"], {**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0"}),
    (["--only", "session.context"], {"PSExecutionPolicyPreference": "Restricted"}),
    (["--only", "session.context"], {**ALLOW_PROCESS_SCOPE, "STUB_EXIT": "7"}),
], ids=["help", "version", "list-probes", "bad-argument", "launch", "policy-fallback", "failed-launch"])
def test_launcher_starts_no_cmd_child(cmd_script: Path, tmp_path: Path, comspec_logger: Path, args: list[str],
                                      extra: dict[str, str]) -> None:
    log = tmp_path / "comspec.log"
    run = run_cmd(cmd_script, tmp_path, args, env={**logged_env(comspec_logger, log), **extra})
    assert run.returncode in (0, 1, 2, 7), run.stderr
    assert children(log) == []
    assert list(run.temp.iterdir()) == [], "temporary files were left behind"


def unused_drive_letter() -> str:
    """A drive letter no volume, subst or network drive uses (asked without touching any drive)."""
    used = ctypes.windll.kernel32.GetLogicalDrives()
    free = [chr(ord("A") + i) for i in range(25, 3, -1) if not used & (1 << i)]
    if not free:
        pytest.skip("every drive letter is in use")
    return free[0]


def test_temporary_folder_on_another_drive_starts_no_cmd_child(cmd_script: Path, tmp_path: Path,
                                                               comspec_logger: Path) -> None:
    """Whether another drive is local needs the list of local volumes, which needs a capture file:
    a temporary folder on the system drive (here TMP) is taken first, so no FOR /F child runs."""
    log = tmp_path / "comspec.log"
    other = unused_drive_letter()
    env = {**logged_env(comspec_logger, log), **ALLOW_PROCESS_SCOPE, "STUB_EXIT": "0",
           "LOCALAPPDATA": f"{other}:\\local", "TEMP": f"{other}:\\local\\Temp"}
    run = run_cmd(cmd_script, tmp_path, ["--net"], env=env)
    assert run.returncode == 0, run.stderr
    assert children(log) == []
    assert run.record is not None and "--net" in run.record
    assert list(run.temp.iterdir()) == []


@pytest.mark.slow
def test_fallback_starts_no_cmd_child(cmd_script: Path, tmp_path: Path, comspec_logger: Path) -> None:
    log = tmp_path / "comspec.log"
    run = run_cmd(cmd_script, tmp_path, ["--fallback"], env=logged_env(comspec_logger, log))
    assert run.returncode in (0, 1), run.stderr
    assert children(log) == []
    assert list(run.temp.iterdir()) == []
    folder = next(run.work.glob("envscan-*"))
    assert sorted(p.name for p in folder.iterdir()) == ["envscan-fallback.txt"], "the capture file was left"
