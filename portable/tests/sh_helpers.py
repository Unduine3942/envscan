"""Helpers for the envscan.sh tests (MSYS dash and bash from Git for Windows).

The shell library build/lib/envscan-lib.sh is sourced into a fresh dash for unit tests; the
awk event writer is extracted from it (es_awk_json) so that the tests exercise exactly the
program the scanner runs. Full scans run dist/envscan.sh under dash and bash --posix.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import pytest

from conftest import BASH, DASH, GIT_USR_BIN

TESTS = Path(__file__).resolve().parent
FIXTURES = TESTS / "fixtures"
STUBS = TESTS / "stubs"
GAWK = GIT_USR_BIN / "gawk.exe"

needs_msys = pytest.mark.skipif(not DASH.exists() or not BASH.exists(),
                                reason="Git for Windows dash/bash not found (set ENVSCAN_GIT_USR_BIN)")

# Calls one redaction function per case line: fn TAB arg [TAB arg2], arguments escaped like
# S events (\\ \n \t \r); prints one escaped result line per case.
REDACTION_HARNESS = r"""
function hx_text(s,   n, P, i, r) {
    if (index(s, pkmarker) > 0) return PKTEXT
    text_reset(); n = split(s, P, "\n"); r = ""
    for (i = 1; i <= n; i++) r = r (i > 1 ? "\n" : "") text_line(P[i])
    return r
}
BEGIN {
    f = ENVIRON["ES_CASES"]
    while ((getline line < f) > 0) {
        n = split(line, A, "\t")
        fn = A[1]; a1 = unesc(A[2]); a2 = (n >= 3) ? unesc(A[3]) : ""
        if (fn == "name") r = secret_name(a1) ? "true" : "false"
        else if (fn == "value") r = redact_value(a1)
        else if (fn == "line") r = redact_line(a1)
        else if (fn == "text") r = hx_text(a1)
        else if (fn == "cmd") r = redact_cmdline(a1)
        else if (fn == "named") r = redact_named(a1, a2)
        else r = "UNKNOWN " fn
        print env_escape(r)
    }
    close(f)
    exit
}
"""


def sh_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")


def sh_unescape(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            d = value[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(d, d))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def msys_path(path: Path) -> str:
    """C:\\x\\y -> /c/x/y (MSYS shells accept both, but scripts compare POSIX forms)."""
    p = str(path.resolve()).replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = "/" + p[0].lower() + p[2:]
    return p


def run_lib(lib: Path, script: str, *args: str, env: Mapping[str, str] | None = None,
            timeout: int = 120, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Source the shell library in dash and run SCRIPT ($1.. are ARGS)."""
    command = f'. "$ES_LIB" || exit 99\n{script}'
    # ENVSCAN_TEST_STUBS=1: the stubs' ES_STUB_* settings pass the child environment allowlist
    environment = {**os.environ, "ES_LIB": msys_path(lib), "ENVSCAN_TEST_STUBS": "1", **(env or {})}
    return subprocess.run(
        [str(DASH), "-c", command, "envscan-test", *args], capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=environment, timeout=timeout, stdin=subprocess.DEVNULL, cwd=cwd,
    )


def extract_awk(lib: Path, dest: Path) -> Path:
    """Write the embedded event writer (exactly as the scanner writes it: the redaction rules
    and the writer as one program) to DEST/json.awk."""
    target = dest / "json.awk"
    proc = run_lib(lib, 'es_awk_program >"$1"', msys_path(target))
    assert proc.returncode == 0, proc.stderr
    assert target.stat().st_size > 1000
    return target


def awk_vars(lib: Path) -> list[str]:
    """The -v assignments es_awk passes (redaction settings from the generated spec block)."""
    names = ("placeholder=ES_REDACT_PLACEHOLDER segs=ES_REDACT_SEGMENTS contains=ES_REDACT_CONTAINS "
             "namesfx=ES_REDACT_NAME_SUFFIXES excepts=ES_REDACT_EXCEPTIONS sfxexc=ES_REDACT_SUFFIX_EXCEPTIONS "
             "prefixes=ES_REDACT_PREFIXES minlen=ES_REDACT_MINLEN pairkeys=ES_REDACT_PAIR_KEYS "
             "optwords=ES_REDACT_OPTION_WORDS hdrwords=ES_REDACT_HEADER_WORDS toolopts=ES_REDACT_TOOL_OPTIONS "
             "xmlel=ES_REDACT_XML_ELEMENTS "
             "xmlat=ES_REDACT_XML_ATTRS pkmarker=ES_REDACT_PKMARKER").split()
    script = "\n".join(f'printf "%s\\n" "{n.split("=")[0]}=${{{n.split("=")[1]}}}"' for n in names)
    proc = run_lib(lib, script)
    assert proc.returncode == 0, proc.stderr
    out: list[str] = []
    for line in proc.stdout.splitlines():
        if line:
            out += ["-v", line]
    return out


@dataclass(frozen=True)
class AwkTool:
    program: Path
    variables: tuple[str, ...]

    def run(self, mode: str, stdin_text: str, *, redact: bool = True, extra: Sequence[str] = ()) -> str:
        args = [str(GAWK), "--posix", "-v", f"mode={mode}", "-v", f"redact={1 if redact else 0}",
                *self.variables, *extra, "-f", str(self.program)]
        proc = subprocess.run(args, input=stdin_text.encode("utf-8"), capture_output=True, timeout=120,
                              env={**os.environ, "LC_ALL": "C"})
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        return proc.stdout.decode("utf-8", "replace")

    def cases(self, cases: Sequence[tuple[str, ...]], work: Path) -> list[str]:
        harness = work / "harness.awk"
        harness.write_text(REDACTION_HARNESS, encoding="ascii")
        case_file = work / "cases.txt"
        case_file.write_bytes(("\n".join("\t".join(sh_escape(a) for a in c) for c in cases) + "\n").encode("utf-8"))
        args = [str(GAWK), "--posix", "-v", "redact=1", *self.variables, "-f", str(self.program), "-f", str(harness)]
        proc = subprocess.run(args, capture_output=True, timeout=300, stdin=subprocess.DEVNULL,
                              env={**os.environ, "LC_ALL": "C", "ES_CASES": str(case_file)})
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        lines = proc.stdout.decode("utf-8", "replace").split("\n")
        return [sh_unescape(x) for x in lines[: len(cases)]]


def make_awk_tool(lib: Path, work: Path) -> AwkTool:
    return AwkTool(extract_awk(lib, work), tuple(awk_vars(lib)))


def run_scan(script: Path, out: Path, args: Sequence[str] = (), *, shell: Path = DASH, posix_flag: bool = False,
             env: Mapping[str, str] | None = None, timeout: int = 900, cwd: Path | None = None
             ) -> subprocess.CompletedProcess:
    """Run envscan.sh with --out OUT under an MSYS shell."""
    cmd = [str(shell)]
    if posix_flag:
        cmd.append("--posix")
    cmd += [str(script), "--out", str(out), *args]
    environment = {**os.environ, "ENVSCAN_TEST_STUBS": "1", **(env or {})}
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env=environment, timeout=timeout, stdin=subprocess.DEVNULL, cwd=cwd or out)


def fake_home(root: Path, canaries: Mapping[str, str]) -> Path:
    """A HOME with package configs holding canary secrets and credential stores that must not be read."""
    home = root / "home"
    (home / ".config" / "pip").mkdir(parents=True)
    pw = canaries["ENVSCAN_CANARY_PASSWORD"]
    tok = canaries["ENVSCAN_CANARY_TOKEN"]
    (home / ".npmrc").write_text(
        "registry=https://npm.corp.example/repository/npm/\n"
        f"//npm.corp.example/repository/npm/:_authToken={tok}\n"
        f"_auth={pw}\n"
        f"https-proxy=http://proxyuser:{pw}@proxy.corp.example:8080\n", encoding="ascii")
    (home / ".config" / "pip" / "pip.conf").write_text(
        "[global]\n"
        f"index-url = https://builder:{pw}@pypi.corp.example/simple\n"
        "trusted-host = pypi.corp.example\n", encoding="ascii")
    (home / ".gitconfig").write_text(
        "[http]\n"
        f"\textraheader = AUTHORIZATION: basic {tok}\n"
        '[url "https://git.corp.example/mirror/"]\n'
        "\tinsteadOf = https://github.com/\n"
        '[credential "https://dev.azure.com"]\n'
        "\tuseHttpPath = true\n", encoding="ascii")
    # Credential stores: the scanner must never open them; their canaries must never appear.
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_rsa").write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{tok}\n", encoding="ascii")
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").write_text(f"[default]\naws_secret_access_key = {pw}\n", encoding="ascii")
    (home / ".netrc").write_text(f"machine corp.example login u password {pw}\n", encoding="ascii")
    (home / ".git-credentials").write_text(f"https://u:{pw}@git.corp.example\n", encoding="ascii")
    (home / ".docker").mkdir()
    (home / ".docker" / "config.json").write_text('{"auths": {"r.example": {"auth": "%s"}}}' % tok, encoding="ascii")
    (home / ".bash_history").write_text(f"curl -u admin:{pw} https://x\n", encoding="ascii")
    return home


def copy_tree(src: Path, dest: Path) -> Path:
    shutil.copytree(src, dest)
    return dest
