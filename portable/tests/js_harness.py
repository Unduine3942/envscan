"""Test harness for the Windows Script Host port (envscan.js, JScript 5.8 under cscript.exe).

build_js(dest) assembles dist/envscan.js and build/lib/envscan-lib.js under `dest` straight from
tools/target_js.py, with a registry that includes the "js" implementation, so the JScript code can be
tested before (and independently of) its registration in tools/spec.py REGISTRY.

run_js(lib, snippet) runs the library followed by `snippet` in one cscript process. The snippet prints
with WScript.Echo (stdout); a JScript error goes to stderr with a non-zero exit code.

Snippets that query CIM, read the registry (StdRegProv is checked through the WMI worker) or run
commands need a scanner temp folder and a WMI worker script. The one documented way:

    esInitForTests(<path of the built dist envscan.js>);   // FIRST statement of the snippet
    try { ... } finally { removeEsTemp(); }

esInitForTests (src/js/12-runner.js) serves the request and quits when cscript started the file as a
worker, takes the env snapshot, loads the redaction rules when present and creates the temp folder.
Use js_init_snippet(dist) to get that prelude. A worker never starts another worker (environment
marker), so a snippet without the prelude fails its CIM calls instead of respawning itself.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

PORTABLE = Path(__file__).resolve().parents[1]
TOOLS = PORTABLE / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import target_js  # noqa: E402
from spec import REGISTRY, Impl, load_spec  # noqa: E402

SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))
CSCRIPT = SYSTEM_ROOT / "System32" / "cscript.exe"
HAVE_CSCRIPT = sys.platform == "win32" and CSCRIPT.is_file()
JS_IMPL = Impl("js", "envscan.js (Windows Script Host)", "script", "envscan.js", "js", "jscript")


def js_registry() -> tuple[Impl, ...]:
    """REGISTRY with the js row (once it is registered there, REGISTRY itself)."""
    if any(impl.id == "js" for impl in REGISTRY):
        return tuple(REGISTRY)
    return (*REGISTRY, JS_IMPL)


ENGINE_PREFIXES = ("00-", "10-", "11", "12-", "90-", "99-")


def engine_only(name: str) -> bool:
    """The engine modules (header, core, exec, runner, main, entry): for engine tests that must not
    depend on the probe, helper and renderer modules other agents are still writing."""
    return name.startswith(ENGINE_PREFIXES)


def build_js(dest: Path, include: Callable[[str], bool] | None = None) -> tuple[Path, Path]:
    """(dist script, lib) assembled into dest/dist/envscan.js and dest/build/lib/envscan-lib.js.
    `include` selects modules by file name (e.g. engine_only); None takes every module.
    Raises ValueError with the lint errors when the assembled script is not clean."""
    spec = load_spec(PORTABLE / "spec", js_registry())
    assembled = target_js.assemble(spec, PORTABLE / "src" / "js", include)
    errors = target_js.lint(assembled.dist)
    if errors:
        raise ValueError("envscan.js lint:\n" + "\n".join(errors[:50]))
    dist = dest / "dist" / "envscan.js"
    lib = dest / "build" / "lib" / "envscan-lib.js"
    for path, text in ((dist, assembled.dist), (lib, assembled.lib)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("ascii"))
    return dist, lib


def cscript_command(script: Path, *args: str, timeout_sec: int | None = None) -> list[str]:
    command = [str(CSCRIPT), "//nologo", "//E:jscript"]
    if timeout_sec:
        command.append(f"//T:{timeout_sec}")
    return [*command, str(script), *args]


def _run_capture(command: list[str], env: dict[str, str] | None, cwd: Path | None,
                 timeout: int) -> tuple[int | None, str, str]:
    """(exit code or None after a timeout, stdout, stderr) of one cscript run (see run_script)."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env, cwd=cwd)
        try:
            returncode: int | None = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=30)
            returncode = None
        texts = []
        for handle in (out, err):
            handle.seek(0)
            texts.append(handle.read().decode("ascii", errors="replace").replace("\r\n", "\n"))
    return returncode, texts[0], texts[1]


def run_script(script: Path, *args: str, env: dict[str, str] | None = None, cwd: Path | None = None,
               timeout: int = 600) -> subprocess.CompletedProcess[str]:
    """Run a JScript file with cscript (stdin empty); envscan.js prints ASCII only.

    stdout and stderr go to temporary files, not pipes: a grandchild (a command or WMI worker the
    script started) inherits the handles, and with pipes the wait would last as long as any of them
    lives. The wait is bounded by `timeout` whatever the grandchildren do: on expiry the cscript
    process itself is killed and subprocess.TimeoutExpired is raised (its descendants are not
    touched here; envscan.js stops its own children)."""
    command = cscript_command(script, *args)
    returncode, stdout, stderr = _run_capture(command, env, cwd, timeout)
    if returncode is None:
        raise subprocess.TimeoutExpired(command, timeout, stdout, stderr)
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


# initializeEsTemp names the scanner temp folder it created on stderr when this variable is "1";
# run_js removes those lines and every such folder the snippet left behind (and nothing else).
TEMP_REPORT_VAR = "__ES_TEST_TEMP_REPORT"
_TEMP_REPORT_RE = re.compile("^" + TEMP_REPORT_VAR + r"=(.*)$")
_TEMP_NAME_RE = re.compile(r"^envscan-\d+-\d+$")


def remove_reported_temps(stderr: str) -> str:
    """stderr without the temp-folder report lines; each reported folder that still exists, has the
    scanner's name pattern and its stdin.empty marker is deleted."""
    kept = []
    for line in stderr.split("\n"):
        match = _TEMP_REPORT_RE.match(line.strip())
        if not match:
            kept.append(line)
            continue
        folder = Path(match.group(1).strip())
        if folder.is_absolute() and _TEMP_NAME_RE.match(folder.name) and (folder / "stdin.empty").is_file():
            shutil.rmtree(folder, ignore_errors=True)
    return "\n".join(kept)


def js_init_snippet(dist: Path) -> str:
    """The prelude for snippets that use CIM, the registry or commands (see the module doc); pair it
    with `removeEsTemp()` in a finally."""
    return "esInitForTests(" + target_js.js_string(str(dist)) + ");\r\n"


def run_js(lib: Path, snippet: str, *args: str, env: dict[str, str] | None = None,
           timeout: int = 300) -> subprocess.CompletedProcess[str]:
    """Run `snippet` after the library, in a temporary script next to the library."""
    script = lib.parent / f"snippet-{os.getpid()}-{abs(hash(snippet)) % 10**8}.js"
    body = lib.read_text(encoding="ascii") + "\r\n" + snippet.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n"
    script.write_bytes(body.encode("ascii"))
    run_env = dict(os.environ if env is None else env)
    run_env[TEMP_REPORT_VAR] = "1"
    command = cscript_command(script, *args)
    try:
        returncode, stdout, stderr = _run_capture(command, run_env, None, timeout)
    finally:
        script.unlink(missing_ok=True)
    stderr = remove_reported_temps(stderr)
    if returncode is None:
        raise subprocess.TimeoutExpired(command, timeout, stdout, stderr)
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)
