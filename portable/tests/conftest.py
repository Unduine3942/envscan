"""Shared pytest fixtures and helpers for envscan.

The dev box is Windows with Windows PowerShell 5.1 and Git for Windows (dash, bash,
gawk under C:\\Program Files\\Git\\usr\\bin). Python is only used to build and test;
the scanner itself never needs it.

PowerShell helpers (run_ps, ps_eval, ps_command) quote every path with ps_quote(), run
with scrubbed_env() (no proxy, package-manager, credential or GIT_* variables from the
developer's session) and decode output in the console code page. run_sh is unchanged.
"""
from __future__ import annotations

import codecs
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

TESTS = Path(__file__).resolve().parent
PORTABLE = TESTS.parent
TOOLS = PORTABLE / "tools"
for extra in (TOOLS, TESTS):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from schema_check import validate  # noqa: E402

import build as build_module  # noqa: E402
from spec import Spec  # noqa: E402

IS_WINDOWS = sys.platform == "win32"
POWERSHELL = shutil.which("powershell.exe") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
POWERSHELL32 = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
CMD32 = r"C:\Windows\SysWOW64\cmd.exe"
GIT_USR_BIN = Path(os.environ.get("ENVSCAN_GIT_USR_BIN", r"C:\Program Files\Git\usr\bin"))
DASH = GIT_USR_BIN / "dash.exe"
BASH = GIT_USR_BIN / "bash.exe"
SCHEMA = json.loads((PORTABLE / "schema" / "envscan.schema.json").read_text(encoding="utf-8"))

HAVE_POWERSHELL = IS_WINDOWS and Path(POWERSHELL).is_file()
requires_powershell = pytest.mark.skipif(not HAVE_POWERSHELL, reason="needs Windows PowerShell (powershell.exe) on Windows")

# AGENT_BRIEF.md section headings, identical in every implementation (docs/DEVELOPING.md).
BRIEF_HEADINGS = ("Platform", "Runtimes and tools", "Package sources and caches", "Blockers and warnings",
                  "Where you can write and execute", "Network, proxy and TLS", "Limits", "Not checked")

# Planted in the environment and in config fixtures; must never appear in any output.
SECRET_CANARIES = {
    "ENVSCAN_CANARY_PASSWORD": "canary-pw-7f3a9c1e",
    "ENVSCAN_CANARY_TOKEN": "canary-tok-5b2d8e44",
    "MY_API_KEY": "canary-key-91c0ffee",
    "HTTP_PROXY": "http://proxyuser:canary-proxy-pw-33aa@proxy.corp.example:8080",
    "GH_PAT_VALUE": "ghp_canaryAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
}
CANARY_VALUES = ("canary-pw-7f3a9c1e", "canary-tok-5b2d8e44", "canary-key-91c0ffee",
                 "canary-proxy-pw-33aa", "ghp_canaryAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")


# ------------------------------------------------------------------ build

@pytest.fixture(scope="session")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build once per test session into a private root (never the shared source tree).

    The root has the same layout as portable/: dist/..., build/lib/..., docs/PROBES.md.
    """
    result = build_module.build(PORTABLE, build_module.script_targets())
    if not result.ok:
        pytest.fail("build failed:\n" + "\n".join(result.errors))
    root = tmp_path_factory.mktemp("built")
    build_module.write_outputs(root, result.files)
    return root


def expected_probe_listing(spec: Spec, impl: str) -> list[str]:
    """The exact `--list-probes` output of one implementation (docs/DEVELOPING.md): no header, per
    probe "<id>  [<tier>]  <title>" then one "    - <footprint line>" per footprint line."""
    lines: list[str] = []
    for probe in spec.probes_for(impl):
        lines.append(f"{probe['id']}  [{probe['tier']}]  {probe['title']}")
        lines.extend(f"    - {line}" for line in probe["footprint"])
    return lines


# ------------------------------------------------------------------ reports and output

def find_output(parent: Path) -> Path:
    folders = sorted(p for p in parent.glob("envscan-*") if p.is_dir())
    assert len(folders) == 1, f"expected one envscan-* folder in {parent}, found {folders}"
    return folders[0]


def _reject_constant(name: str) -> Any:
    raise ValueError(f"envscan.json contains the non-standard JSON constant {name}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    counts = Counter(key for key, _ in pairs)
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    if duplicates:
        raise ValueError(f"envscan.json repeats key(s) {duplicates} in one object")
    return dict(pairs)


def load_report(folder: Path) -> dict[str, Any]:
    """envscan.json as strict JSON: pure ASCII, no NaN/Infinity, no duplicate keys."""
    raw = (folder / "envscan.json").read_bytes()
    raw.decode("ascii")  # the report must be pure ASCII
    return json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_unique_object)


def schema_errors(report: Mapping[str, Any]) -> list[str]:
    return validate(report, SCHEMA)


_BOMS = ((codecs.BOM_UTF32_LE, "utf-32-le"), (codecs.BOM_UTF32_BE, "utf-32-be"), (codecs.BOM_UTF8, "utf-8"),
         (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be"))


def decode_output(data: bytes) -> str:
    """Decode an output file by its BOM (UTF-8, UTF-16/32 LE/BE), else as UTF-8 (lossy)."""
    for bom, codec in _BOMS:
        if data.startswith(bom):
            return data[len(bom):].decode(codec, errors="replace")
    return data.decode("utf-8", errors="replace")


def all_output_text(folder: Path) -> str:
    """Every file under `folder`, decoded with BOM detection."""
    files = sorted(p for p in folder.rglob("*") if p.is_file())
    return "\n".join(decode_output(p.read_bytes()) for p in files)


def canary_hits(texts: Iterable[str], canaries: Iterable[str] = CANARY_VALUES) -> list[str]:
    """Canaries found in any text, plain or NUL-interleaved (UTF-16/32 without a BOM, read as UTF-8)."""
    pool = [form for text in texts for form in (text, text.replace("\x00", ""))]
    return [canary for canary in canaries if any(canary in text for text in pool)]


# ------------------------------------------------------------------ PowerShell

_PS_SINGLE_QUOTES = "'\u2018\u2019\u201a\u201b"  # PowerShell treats all of these as '


def ps_quote(value: str | os.PathLike[str]) -> str:
    """A PowerShell single-quoted literal for any text (every quote character doubled)."""
    text = os.fspath(value)
    return "'" + "".join(ch * 2 if ch in _PS_SINGLE_QUOTES else ch for ch in text) + "'"


# Never scrubbed: what Windows, PowerShell and the scanner's own lookups need.
_WINDOWS_ENV = frozenset({
    "ALLUSERSPROFILE", "APPDATA", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMMONPROGRAMW6432",
    "COMPUTERNAME", "COMSPEC", "DRIVERDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "LOGONSERVER",
    "NUMBER_OF_PROCESSORS", "ONEDRIVE", "OS", "PATH", "PATHEXT", "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432",
    "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "PROGRAMDATA", "PROGRAMFILES",
    "PROGRAMFILES(X86)", "PROGRAMW6432", "PSMODULEPATH", "PUBLIC", "SESSIONNAME", "SYSTEMDRIVE", "SYSTEMROOT",
    "TEMP", "TMP", "USERDOMAIN", "USERDOMAIN_ROAMINGPROFILE", "USERNAME", "USERPROFILE", "WINDIR",
})
_SCRUB_PREFIXES = (
    "GIT_", "ENVSCAN_", "NPM_", "YARN_", "PNPM_", "BUN_", "PIP_", "PIPX_", "UV_", "POETRY_", "CONDA_",
    "CARGO_", "RUSTUP_", "GEM_", "BUNDLE_", "NUGET_", "COMPOSER_", "MAVEN_", "GRADLE_", "HOMEBREW_",
    "DOCKER_", "CONTAINERS_",
)
_SCRUB_NAMES = frozenset({
    "GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOSUMDB", "GOFLAGS", "GOINSECURE",
    "GOTOOLCHAIN", "CONDARC", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "SSL_CERT_FILE",
    "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED",
    "NODE_OPTIONS", "PYTHONHTTPSVERIFY", "OPENSSL_CONF", "OPENSSL_FIPS", "AWS_CA_BUNDLE", "DENO_CERT",
})
_SECRET_SEGMENTS = frozenset({
    "PASSWORD", "PASSWD", "PWD", "PASS", "PW", "SECRET", "SECRETS", "TOKEN", "TOKENS", "APIKEY", "KEY", "KEYS",
    "CREDENTIAL", "CREDENTIALS", "CREDS", "AUTH", "PAT", "COOKIE", "SAS", "SIGNATURE", "PIN", "OTP",
})
_SECRET_PARTS = ("PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY", "ACCESSKEY", "PRIVATEKEY",
                 "CREDENTIAL", "CONNECTIONSTRING")
_NAME_SEPARATORS = re.compile(r"[_\-.:]+")


def _scrubbed(name: str) -> bool:
    upper = name.upper()
    if upper in _WINDOWS_ENV:
        return False
    if "PROXY" in upper or upper.startswith(_SCRUB_PREFIXES) or upper in _SCRUB_NAMES:
        return True
    if set(_NAME_SEPARATORS.split(upper)) & _SECRET_SEGMENTS:
        return True
    compact = _NAME_SEPARATORS.sub("", upper)
    return any(part in compact for part in _SECRET_PARTS)


def scrubbed_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """`base` (default os.environ) without proxy, package-manager, TLS-override, credential-looking,
    GIT_* and ENVSCAN_* variables, so the developer's session never leaks into a scan."""
    source = os.environ if base is None else base
    return {name: value for name, value in source.items() if not _scrubbed(name)}


def _with_overrides(base: Mapping[str, str], overrides: Mapping[str, str] | None) -> dict[str, str]:
    """base + overrides; on Windows an override replaces a variable whatever its case."""
    if not overrides:
        return dict(base)
    fold = str.upper if IS_WINDOWS else str
    replaced = {fold(name) for name in overrides}
    return {**{k: v for k, v in base.items() if fold(k) not in replaced}, **overrides}


def _console_encoding() -> str:
    """PowerShell 5.1 writes redirected output in the console code page (OEM by default)."""
    if not IS_WINDOWS:
        return "utf-8"
    import ctypes  # Windows only

    kernel32 = ctypes.windll.kernel32
    encoding = f"cp{kernel32.GetConsoleOutputCP() or kernel32.GetOEMCP()}"
    try:
        codecs.lookup(encoding)
    except LookupError:
        return "utf-8"
    return encoding


PS_ENCODING = _console_encoding()


class PsResult(subprocess.CompletedProcess):
    """CompletedProcess plus the PowerShell process id, which is $PID inside the script."""

    def __init__(self, args: Any, returncode: int, stdout: str, stderr: str, pid: int) -> None:
        super().__init__(args, returncode, stdout, stderr)
        self.pid = pid


def _clm_prefix(clm: bool) -> str:
    return "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if clm else ""


def ps_command(command: str, *, env: Mapping[str, str] | None = None, cwd: Path | None = None,
               timeout: int = 1200, exe: str = POWERSHELL, base_env: Mapping[str, str] | None = None) -> PsResult:
    """Run one -Command string under Windows PowerShell (process-scoped RemoteSigned policy;
    the dev box is Restricted). The environment is scrubbed_env() (or `base_env`) plus `env`."""
    argv = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", command]
    environment = _with_overrides(scrubbed_env() if base_env is None else base_env, env)
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding=PS_ENCODING, errors="replace", env=environment, cwd=cwd) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        except BaseException:
            process.kill()
            raise
    return PsResult(argv, process.returncode, stdout, stderr, process.pid)


def run_ps(script: Path, args: Sequence[str] = (), *, clm: bool = False, env: Mapping[str, str] | None = None,
           cwd: Path | None = None, timeout: int = 1200, exe: str = POWERSHELL) -> PsResult:
    """Run a .ps1 with arguments. The exit code is the script's `exit` code; a script that
    dies with a terminating error, or cannot start, exits 1 (never 0)."""
    quoted = " ".join(ps_quote(a) for a in args)
    command = (f"{_clm_prefix(clm)}& {ps_quote(script)} {quoted}; $ok = $?; "
               "if ($null -eq $LASTEXITCODE) { exit [int](-not $ok) }; exit $LASTEXITCODE")
    return ps_command(command, env=env, cwd=cwd, timeout=timeout, exe=exe)


def ps_eval(lib: Path, expression: str, *, clm: bool = False, timeout: int = 300,
            env: Mapping[str, str] | None = None, exe: str = POWERSHELL) -> PsResult:
    """Dot-source build/lib/envscan-lib.ps1 and evaluate an expression (for unit tests)."""
    return ps_command(f"{_clm_prefix(clm)}. {ps_quote(lib)}; {expression}", env=env, timeout=timeout, exe=exe)


# ------------------------------------------------------------------ sh

def run_sh(shell: Path, script: Path, args: Sequence[str] = (), *, env: Mapping[str, str] | None = None,
           cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    """Run envscan.sh under an MSYS shell from Git for Windows."""
    environment = _with_overrides(scrubbed_env(), env)
    return subprocess.run(
        [str(shell), str(script), *args], capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=environment, cwd=cwd, timeout=timeout, stdin=subprocess.DEVNULL,
    )
