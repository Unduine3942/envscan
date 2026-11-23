"""envscan.sh preamble on z/OS UNIX and IBM i (src/sh/00-preamble.sh), run under dash with a stub
uname (and od) on PATH. The preamble text is run as a script followed by a few lines that print
what it set; nothing here touches a real z/OS or IBM i system. Unverified on those systems.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from conftest import DASH, PORTABLE
from sh_helpers import msys_path, needs_msys

PREAMBLE = (PORTABLE / "src" / "sh" / "00-preamble.sh").read_text(encoding="ascii")
SHOW = ('printf "%s\\n" "CEE=${_CEE_RUNOPTS-unset}" "AUTOCVT=${_BPXK_AUTOCVT-unset}" "PATH=$PATH" '
        '"PRE=$ES_PATH_PREPENDED" "ORIGCEE=${ES_PRE_CEE_SET-}|${ES_PRE_CEE-}" '
        '"ORIGCVT=${ES_PRE_CVT_SET-}|${ES_PRE_CVT-}" "PREZOS=${ES_PRE_ZOS-}"\n')
OPTIONS = "FILETAG(AUTOCVT,AUTOTAG) POSIX(ON)"


@pytest.fixture
def stubs(tmp_path: Path) -> Path:
    d = tmp_path / "stubs"
    d.mkdir()
    return d


def stub(d: Path, name: str, body: str) -> None:
    (d / name).write_text("#!/bin/sh\n" + body, encoding="ascii", newline="\n")


def run_preamble(tmp_path: Path, stubs: Path, uname: str, *, od: str | None = None,
                 env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    stub(stubs, "uname", f"printf '%s\\n' '{uname}'\n")
    if od is not None:
        stub(stubs, "od", f"printf '%s\\n' '{od}'\n")
    script = tmp_path / "pre.sh"
    script.write_bytes((PREAMBLE + "\n" + SHOW).encode("ascii"))
    import os
    environment = {k: v for k, v in os.environ.items() if k not in ("_CEE_RUNOPTS", "_BPXK_AUTOCVT")}
    environment.update({"PATH": f"{msys_path(stubs)}:/usr/bin:/bin", "ENVSCAN_REEXEC": "x", **(env or {})})
    return subprocess.run([str(DASH), msys_path(script)], capture_output=True, text=True, env=environment,
                          timeout=60, stdin=subprocess.DEVNULL)


def shown(proc: subprocess.CompletedProcess[str]) -> dict[str, str]:
    assert proc.returncode == 0, proc.stderr
    return dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)


pytestmark = [pytest.mark.integration, needs_msys]


def test_zos_sets_autoconversion_and_run_time_options(tmp_path: Path, stubs: Path) -> None:
    got = shown(run_preamble(tmp_path, stubs, "OS/390"))
    assert got["AUTOCVT"] == "ON"
    assert got["CEE"] == OPTIONS


@pytest.mark.parametrize("existing", ["XPLINK(ON)", "HEAP(1M),STACK(128K) ENVAR(\"A=b\")", "FILETAG(NOAUTOCVT)"])
def test_zos_appends_to_existing_run_time_options_never_replaces(tmp_path: Path, stubs: Path, existing: str) -> None:
    got = shown(run_preamble(tmp_path, stubs, "OS/390", env={"_CEE_RUNOPTS": existing}))
    assert got["CEE"] == f"{existing} {OPTIONS}"
    assert got["CEE"].startswith(existing)


def test_zos_keeps_an_existing_autoconversion_value_set_to_on(tmp_path: Path, stubs: Path) -> None:
    got = shown(run_preamble(tmp_path, stubs, "OS/390", env={"_BPXK_AUTOCVT": "OFF"}))
    assert got["AUTOCVT"] == "ON"


@pytest.mark.parametrize("name", ["Linux", "AIX", "SunOS", "Darwin", "OS400"])
def test_other_systems_get_no_zos_settings(tmp_path: Path, stubs: Path, name: str) -> None:
    got = shown(run_preamble(tmp_path, stubs, name))
    assert got["CEE"] == "unset" and got["AUTOCVT"] == "unset"


def test_ibm_i_pase_puts_the_qopensys_directories_first(tmp_path: Path, stubs: Path) -> None:
    got = shown(run_preamble(tmp_path, stubs, "OS400"))  # the real od prints 41 for "A"
    assert got["PATH"].startswith("/QOpenSys/usr/bin:/QOpenSys/usr/sbin:")
    assert got["PRE"] == "/QOpenSys/usr/bin:/QOpenSys/usr/sbin"


@pytest.mark.parametrize("name", ["Linux", "AIX", "OS/390"])
def test_path_is_not_changed_elsewhere(tmp_path: Path, stubs: Path, name: str) -> None:
    got = shown(run_preamble(tmp_path, stubs, name))
    assert "/QOpenSys" not in got["PATH"] and got["PRE"] == ""


@pytest.mark.parametrize("od_out", ["c1", " c1 ", "", "garbage"])
def test_ibm_i_qsh_is_refused_without_a_pase_shell(tmp_path: Path, stubs: Path, od_out: str) -> None:
    """A shell that does not print 41 for the letter A (QSH, or no od: fail closed) stops with exit 2."""
    proc = run_preamble(tmp_path, stubs, "OS400", od=od_out)
    assert proc.returncode == 2
    assert "run envscan.sh from PASE" in proc.stderr
    assert "PATH=" not in proc.stdout


def test_qsh_reexec_marker_prevents_a_loop(tmp_path: Path, stubs: Path) -> None:
    proc = run_preamble(tmp_path, stubs, "OS400", od="c1", env={"ENVSCAN_QSH": "1"})
    assert proc.returncode == 2 and "PASE" in proc.stderr


def test_qsh_reexec_target_is_the_pase_shell() -> None:
    assert re.search(r'exec /QOpenSys/usr/bin/sh "\$0" \$\{1\+"\$@"\}', PREAMBLE)


# ------------------------------------------------------------------ the shell re-exec candidates

@pytest.mark.unit
def test_crlf_repair_never_execs_an_unchecked_shell() -> None:
    assert not re.search(r"^\s*exec /bin/sh", PREAMBLE, re.M)
    loop = re.search(r"for es_sh in (/bin/sh[^;]*); do", PREAMBLE)
    assert loop, "the CRLF repair must pick an existing shell"
    candidates = loop.group(1).split()
    assert "/QOpenSys/usr/bin/sh" in candidates and "/QOpenSys/pkgs/bin/bash" in candidates
    assert re.search(r'if \[ -f "\$es_sh" \] && \[ -x "\$es_sh" \]; then exec "\$es_sh" "\$es_d/envscan.sh"', PREAMBLE)


@pytest.mark.unit
def test_posix_shell_candidates_include_pase() -> None:
    match = re.search(r"for es_sh in (/usr/xpg4/bin/sh[^;]*); do", PREAMBLE)
    assert match
    assert {"/QOpenSys/usr/bin/sh", "/QOpenSys/pkgs/bin/bash"} <= set(match.group(1).split())


@pytest.mark.unit
def test_crlf_repair_removes_its_directory_when_no_shell_exists() -> None:
    assert re.search(r"trap 'rm -rf \"\$es_d\"' 0", PREAMBLE)


@pytest.mark.unit
def test_every_preamble_line_ends_with_the_crlf_marker() -> None:
    lines = PREAMBLE.split("\n")
    assert lines[0] == "#!/bin/sh"
    bad = [(n, line) for n, line in enumerate(lines[1:], 2) if line and not line.endswith(" #")]
    assert bad == [], bad[:3]


@pytest.mark.unit
def test_preamble_avoids_command_substitution_dollar_paren() -> None:
    code = [line for line in PREAMBLE.split("\n") if not line.lstrip().startswith("#")]
    # the POSIX self-test is the one place that has to contain $(...) (it is what is being tested)
    offenders = [line for line in code if "$(" in line and "eval" not in line]
    assert offenders == []


# ------------------------------------------------------------------ fix round

def test_zos_remembers_the_users_original_settings(tmp_path: Path, stubs: Path) -> None:
    got = shown(run_preamble(tmp_path, stubs, "OS/390", env={"_CEE_RUNOPTS": "XPLINK(ON)", "_BPXK_AUTOCVT": "OFF"}))
    assert got["ORIGCEE"] == "x|XPLINK(ON)" and got["ORIGCVT"] == "x|OFF" and got["PREZOS"] == "1"


def test_zos_remembers_that_the_settings_were_unset(tmp_path: Path, stubs: Path) -> None:
    got = shown(run_preamble(tmp_path, stubs, "OS/390"))
    assert got["ORIGCEE"] == "|" and got["ORIGCVT"] == "|" and got["PREZOS"] == "1"


def test_other_systems_remember_nothing(tmp_path: Path, stubs: Path) -> None:
    assert shown(run_preamble(tmp_path, stubs, "Linux"))["PREZOS"] == ""


@pytest.mark.unit
def test_path_prepends_do_not_add_an_empty_entry() -> None:
    assert "${PATH:+:$PATH}" in PREAMBLE
    assert not re.search(r'PATH="[^"]*:\$PATH"', PREAMBLE), "an empty PATH would gain a current-directory entry"


@pytest.mark.unit
def test_pase_od_check_runs_after_the_qopensys_directories_are_on_path() -> None:
    branch = PREAMBLE.split("OS400)", 1)[1]
    assert branch.index("/QOpenSys/usr/bin:/QOpenSys/usr/sbin") < branch.index("od -An -tx1")


@pytest.mark.unit
def test_reexec_candidates_must_be_files_and_executable() -> None:
    assert len(re.findall(r'\[ -f "\$es_sh" \] && \[ -x "\$es_sh" \]', PREAMBLE)) == 2


@pytest.mark.unit
def test_failed_crlf_exec_cannot_leave_the_copy_behind() -> None:
    """exec of a shell that cannot run ends the script: an EXIT trap removes the copy (exec drops traps)."""
    assert re.search(r"trap 'rm -rf \"\$es_d\"' 0", PREAMBLE)
