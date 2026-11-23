"""The PowerShell-on-Unix shim of envscan.ps1 (src/ps/05-unix-shim.ps1).

Under PowerShell 6+ on Linux/macOS, envscan.ps1 validates its options like on Windows and then
runs `/bin/sh envscan.sh <same arguments>`. Windows cannot be Unix, so the tests use two
test-only hooks: ENVSCAN_TEST_PLATFORM=unix forces the shim branch and ENVSCAN_TEST_SH replaces
/bin/sh (here: Git for Windows' dash). The "sh script" is a stub envscan.sh that records its
argv, its stdin and its working directory, prints a chosen line and exits with a chosen code.

The same cases run in Windows PowerShell 5.1 (FullLanguage and ConstrainedLanguage) and, when it
is installed, in a portable PowerShell 7 (ENVSCAN_PWSH, else %LOCALAPPDATA%\\envscan-dev\\pwsh).
pwsh is always started with POWERSHELL_TELEMETRY_OPTOUT=1 and POWERSHELL_UPDATECHECK=Off.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from conftest import DASH, GIT_USR_BIN, PORTABLE, POWERSHELL, PsResult, requires_powershell, run_ps

pytestmark = [pytest.mark.integration, requires_powershell]

LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
PWSH7 = Path(os.environ.get("ENVSCAN_PWSH") or Path(LOCALAPPDATA) / "envscan-dev" / "pwsh" / "pwsh.exe")
HAVE_PWSH7 = PWSH7.is_file()
HAVE_DASH = DASH.is_file()

NO_PWSH7 = "no portable PowerShell 7 (set ENVSCAN_PWSH or unpack it to %LOCALAPPDATA%\\envscan-dev\\pwsh)"
# (id, executable, ConstrainedLanguage)
RUNNERS = [
    pytest.param(("ps51", POWERSHELL, False), id="ps51-full"),
    pytest.param(("ps51", POWERSHELL, True), id="ps51-clm"),
    pytest.param(("pwsh7", str(PWSH7), False), id="pwsh7-full",
                 marks=pytest.mark.skipif(not HAVE_PWSH7, reason=NO_PWSH7)),
    pytest.param(("pwsh7", str(PWSH7), True), id="pwsh7-clm",
                 marks=pytest.mark.skipif(not HAVE_PWSH7, reason=NO_PWSH7)),
]
needs_dash = pytest.mark.skipif(not HAVE_DASH, reason="needs Git for Windows' dash.exe")

STUB_SH = r"""#!/bin/sh
# Test stub for envscan.sh: records what the shim passed, prints STUB_STDOUT, exits STUB_EXIT.
{
  printf 'argc=%s\n' "$#"
  for a in "$@"; do printf 'arg=[%s]\n' "$a"; done
  printf 'stdin_bytes=%s\n' "$(cat | wc -c | tr -d ' ')"
  printf 'cwd=%s\n' "$(cygpath -w "$(pwd)")"
} > "$STUB_LOG"
[ -n "$STUB_STDERR" ] && printf '%s\n' "$STUB_STDERR" >&2
printf '%s\n' "${STUB_STDOUT:-/out/folder}"
exit "${STUB_EXIT:-0}"
"""


def pwsh_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """pwsh must never contact Microsoft at startup: both opt-outs are set for every run."""
    path = f"{GIT_USR_BIN}{os.pathsep}{os.environ.get('PATH', '')}"
    return {"POWERSHELL_TELEMETRY_OPTOUT": "1", "POWERSHELL_UPDATECHECK": "Off", "PATH": path, **(extra or {})}


@pytest.fixture()
def shim_dir(built: Path, tmp_path: Path) -> Path:
    """A folder with the built envscan.ps1 and a stub envscan.sh next to it."""
    folder = tmp_path / "bin"
    folder.mkdir()
    shutil.copy2(built / "dist" / "envscan.ps1", folder / "envscan.ps1")
    (folder / "envscan.sh").write_bytes(STUB_SH.encode("ascii"))
    return folder


class Shim:
    def __init__(self, folder: Path, work: Path, exe: str, clm: bool) -> None:
        self.folder, self.work, self.exe, self.clm = folder, work, exe, clm
        self.log = work / "stub.log"

    def run(self, args: list[str], *, env: dict[str, str] | None = None, hook: bool = True,
            sh: Path | str | None = None, omit_sh: bool = False) -> PsResult:
        environment = pwsh_env({"STUB_LOG": str(self.log), **(env or {})})
        if hook:
            environment["ENVSCAN_TEST_PLATFORM"] = "unix"
            if not omit_sh:
                environment["ENVSCAN_TEST_SH"] = str(sh if sh is not None else DASH)
        return run_ps(self.folder / "envscan.ps1", args, clm=self.clm, env=environment, cwd=self.work,
                      exe=self.exe, timeout=300)

    def stub_record(self) -> dict[str, list[str]]:
        """The stub's log as {key: [values]}; arg=[x] lines keep order under 'arg'."""
        record: dict[str, list[str]] = {}
        for line in self.log.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key == "arg":
                value = value[1:-1]
            record.setdefault(key, []).append(value)
        return record


@pytest.fixture(params=RUNNERS)
def shim(request: pytest.FixtureRequest, shim_dir: Path, tmp_path: Path) -> Shim:
    _, exe, clm = request.param
    work = tmp_path / "work"
    work.mkdir()
    return Shim(shim_dir, work, exe, clm)


def old_pwsh(shim: Shim) -> bool:
    """Windows PowerShell 5.1 (like pwsh 6.x to 7.2) drops empty arguments and strips embedded
    quotes when it starts a native program, so the shim refuses such arguments there (exit 2)
    instead of forwarding them mangled. pwsh 7.3+ passes argv entries intact."""
    return shim.exe == POWERSHELL


def combined(result: PsResult) -> str:
    return result.stdout + result.stderr


# ------------------------------------------------------------------ forwarding

# The arguments reach sh as argv entries: no joining, no re-parsing.
VERBATIM = [
    ["--deep", "--net"],
    ["--only", "net.*,tls.trust"],
    ["--only", "os.identity", "--out", "C:\\temp\\dir with spaces"],
    ["--out", "it's here"],
    ["--only=os.identity"],
    ["--out", "caf\u00e9 \u65e5\u672c"],
]


@needs_dash
@pytest.mark.parametrize("args", VERBATIM, ids=lambda a: " ".join(a)[:40])
def test_arguments_are_forwarded_verbatim(shim: Shim, args: list[str]) -> None:
    result = shim.run(args)
    # Bad values would exit 2 before sh runs; every case here is a valid command line.
    assert result.returncode == 0, combined(result)
    record = shim.stub_record()
    assert record.get("arg", []) == args  # the stub's $@ excludes the script path itself
    assert record["argc"] == [str(len(args))]


@needs_dash
def test_value_with_embedded_double_quotes_is_one_argument(shim: Shim) -> None:
    value = 'say "hi" there'
    result = shim.run(["--out", value])
    if old_pwsh(shim):
        assert result.returncode == 2, combined(result)
        assert "pwsh 7.3" in combined(result)
        assert not shim.log.exists()
        return
    assert result.returncode == 0, combined(result)
    assert shim.stub_record()["arg"] == ["--out", value]


@needs_dash
def test_empty_string_argument_is_forwarded(shim: Shim) -> None:
    # --only "" is invalid for the scripts (exit 2 "--only needs probe ids"), so the shim itself
    # rejects it; --out "" is not validated by PowerShell and sh decides. It must stay an argument.
    result = shim.run(["--out", ""])
    if old_pwsh(shim):
        assert result.returncode == 2, combined(result)
        assert "pwsh 7.3" in combined(result)
        assert not shim.log.exists()
        return
    assert result.returncode == 0, combined(result)
    assert shim.stub_record()["arg"] == ["--out", ""]


@needs_dash
@pytest.mark.parametrize("code", [0, 1, 2])
def test_exit_code_of_sh_is_passed_through(shim: Shim, code: int) -> None:
    result = shim.run(["--only", "os.identity"], env={"STUB_EXIT": str(code)})
    assert result.returncode == code, combined(result)


@needs_dash
def test_stdout_and_stderr_of_sh_are_passed_through(shim: Shim) -> None:
    result = shim.run(["--deep"], env={"STUB_STDOUT": "/home/u/envscan-host-20261112T000000Z",
                                       "STUB_STDERR": "stub progress line"})
    assert result.returncode == 0, combined(result)
    assert result.stdout.strip().splitlines()[-1] == "/home/u/envscan-host-20261112T000000Z"
    assert "stub progress line" in result.stderr
    assert "stub progress line" not in result.stdout


@needs_dash
def test_sh_gets_empty_stdin_and_the_callers_directory(shim: Shim) -> None:
    result = shim.run(["--deep"])
    assert result.returncode == 0, combined(result)
    record = shim.stub_record()
    assert record["stdin_bytes"] == ["0"]
    assert Path(record["cwd"][0]).resolve() == shim.work.resolve()


@needs_dash
@pytest.mark.parametrize("flag", ["--version", "--help", "--list-probes"])
def test_info_options_are_forwarded_to_sh(shim: Shim, flag: str) -> None:
    result = shim.run([flag], env={"STUB_STDOUT": "stub output of sh"})
    assert result.returncode == 0, combined(result)
    assert result.stdout.strip().splitlines()[-1] == "stub output of sh"
    assert shim.stub_record()["arg"] == [flag]


# ------------------------------------------------------------------ refusals

@needs_dash
@pytest.mark.parametrize("args,message", [
    (["--bogus"], "unknown option: --bogus"),
    (["--net=false"], "option --net takes no value"),
    (["--only", "nosuch.probe"], "pattern 'nosuch.probe' matches no probe"),
    (["--only", ""], "--only needs probe ids"),
    (["--timeout", "0"], "--timeout must be 1-3600 seconds"),
    (["stray"], "unexpected argument: stray"),
])
def test_bad_options_exit_2_without_running_sh(shim: Shim, args: list[str], message: str) -> None:
    result = shim.run(args)
    assert result.returncode == 2, combined(result)
    assert message in combined(result)
    assert not shim.log.exists(), "sh must not run for a bad command line"


@needs_dash
def test_missing_envscan_sh_exits_2(shim: Shim) -> None:
    (shim.folder / "envscan.sh").unlink()
    result = shim.run(["--deep"])
    assert result.returncode == 2, combined(result)
    assert "envscan.sh must be next to envscan.ps1 on Linux/macOS" in combined(result)


@needs_dash
def test_envscan_sh_that_is_a_folder_exits_2(shim: Shim) -> None:
    (shim.folder / "envscan.sh").unlink()
    (shim.folder / "envscan.sh").mkdir()
    result = shim.run(["--deep"])
    assert result.returncode == 2, combined(result)
    assert "envscan.sh must be next to envscan.ps1 on Linux/macOS" in combined(result)


@needs_dash
def test_missing_sh_exits_2(shim: Shim) -> None:
    result = shim.run(["--deep"], sh=shim.work / "sh.exe")
    assert result.returncode == 2, combined(result)
    assert "sh" in combined(result) and "not found" in combined(result)
    assert not shim.log.exists()


# ------------------------------------------------------------------ ENVSCAN_TEST_SH is vetted

@needs_dash
def test_forced_platform_on_windows_requires_the_sh_hook(shim: Shim) -> None:
    result = shim.run(["--deep"], omit_sh=True)
    assert result.returncode == 2, combined(result)
    assert "ENVSCAN_TEST_SH" in combined(result)
    assert not shim.log.exists()


@needs_dash
@pytest.mark.parametrize("bad", [
    r"C:\Windows\System32\cmd.exe",                        # not a shell name
    r"\\localhost\c$\Program Files\Git\usr\bin\sh.exe",    # UNC: never touched
    "sh.exe",                                              # relative
    r"C:\Users\someone\.ssh\sh.exe",                       # credential store
], ids=["leaf", "unc", "relative", "credential"])
def test_unsafe_sh_hook_is_refused(shim: Shim, bad: str) -> None:
    result = shim.run(["--deep"], sh=bad)
    assert result.returncode == 2, combined(result)
    assert "ENVSCAN_TEST_SH" in combined(result)
    assert not shim.log.exists()


@needs_dash
def test_active_hook_is_announced_on_stderr(shim: Shim) -> None:
    result = shim.run(["--deep"])
    assert result.returncode == 0, combined(result)
    assert "ENVSCAN_TEST_PLATFORM" in result.stderr
    # envscan.cmd reads these words on stderr, with exit 1, as a policy refusal.
    for word in ("UnauthorizedAccess", "PSSecurityException"):
        assert word not in result.stderr


# ------------------------------------------------------------------ option spelling

@needs_dash
@pytest.mark.parametrize("given,forwarded", [
    (["-deep"], ["--deep"]),
    (["--DEEP", "-Net"], ["--deep", "--net"]),
    (["-OUT", "Dir"], ["--out", "Dir"]),
    (["--Only=os.identity"], ["--only=os.identity"]),
    (["-NO-REDACT"], ["--no-redact"]),
    (["-H"], ["--help"]),
    (["--out", "--DEEP"], ["--out", "--DEEP"]),     # a value is never touched
], ids=lambda v: " ".join(v)[:30])
def test_option_names_are_forwarded_in_the_spelling_sh_accepts(shim: Shim, given: list[str],
                                                              forwarded: list[str]) -> None:
    # PowerShell reads option names without regard to case, sh only in lower case.
    result = shim.run(given)
    assert result.returncode == 0, combined(result)
    assert shim.stub_record()["arg"] == forwarded


# ------------------------------------------------------------------ the Windows path stays

@needs_dash
def test_without_the_hook_the_windows_path_runs(shim: Shim) -> None:
    result = shim.run(["--version"], hook=False)
    assert result.returncode == 0, combined(result)
    assert result.stdout.strip().endswith("(powershell)")
    assert not shim.log.exists(), "the stub sh must not run on Windows"


@needs_dash
def test_other_platform_hook_value_is_ignored(shim: Shim) -> None:
    result = shim.run(["--version"], hook=False, env={"ENVSCAN_TEST_PLATFORM": "windows",
                                                      "ENVSCAN_TEST_SH": str(DASH)})
    assert result.returncode == 0, combined(result)
    assert result.stdout.strip().endswith("(powershell)")
    assert not shim.log.exists()


@needs_dash
def test_sh_hook_alone_does_not_enable_the_shim(shim: Shim) -> None:
    result = shim.run(["--version"], hook=False, env={"ENVSCAN_TEST_SH": str(DASH)})
    assert result.returncode == 0, combined(result)
    assert result.stdout.strip().endswith("(powershell)")


# ------------------------------------------------------------------ source rules

def test_detection_never_uses_iswindows_or_interop_types(built: Path) -> None:
    text = (built / "dist" / "envscan.ps1").read_text(encoding="utf-8")
    assert "$IsWindows" not in text
    assert "InteropServices" not in text
    assert "PSVersion.Major -ge 6" in text and "'Unix'" in text


# ------------------------------------------------------------------ one real run

@needs_dash
@pytest.mark.skipif(not HAVE_PWSH7, reason=NO_PWSH7)
@pytest.mark.slow
def test_real_scan_through_pwsh7_shim_and_dash(built: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    # The built scripts sit side by side in dist/; the shim finds envscan.sh next to envscan.ps1.
    result = run_ps(built / "dist" / "envscan.ps1", ["--only", "os.identity", "--out", str(out)],
                    env=pwsh_env({"ENVSCAN_TEST_PLATFORM": "unix", "ENVSCAN_TEST_SH": str(DASH)}),
                    cwd=tmp_path, exe=str(PWSH7), timeout=600)
    assert result.returncode in (0, 1), combined(result)
    last = result.stdout.strip().splitlines()[-1]  # dash prints its own form: /c/Users/...
    if len(last) > 2 and last[0] == "/" and last[2] == "/":
        last = f"{last[1].upper()}:{last[2:]}"
    folder = Path(last)
    assert folder.is_dir(), result.stdout
    report = json.loads((folder / "envscan.json").read_text(encoding="utf-8"))
    assert report["scanner"]["impl"] == "posix-sh"
    ran = [pid for pid, probe in report["probes"].items() if probe["status"] != "skipped"]
    assert ran == ["os.identity"]
    assert PORTABLE.exists()
