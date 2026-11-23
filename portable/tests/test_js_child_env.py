"""envscan.js: the child environment allowlist (spec/child_env.toml [child_env_keep]).

Every child (commands, the git child, the WMI worker) sees only the allowlisted scan-start
variables, the [child_env] values and its per-call extras; the scanner's own process environment
is restored exactly after each start, also when the start fails.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from js_harness import HAVE_CSCRIPT, PORTABLE, build_js, js_init_snippet, js_registry, run_js
from spec import load_spec

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
CMD = str(SYSTEM32 / "cmd.exe")
CANARIES = {
    "ENVSCAN_TEST_CHILD_CANARY": "canary-7f3a",
    "HTTP_PROXY": "http://u:pw@p:1",
    "GITHUB_TOKEN": "ghp_canarycanarycanary",
    "NODE_OPTIONS": "--require=evil",
}
KEPT = {
    "LC_ENVSCAN_TEST": "lc-kept",
    "XDG_ENVSCAN_TEST": "xdg-kept",
}
# Empty values must come back exactly (an empty variable is not an unset one).
EMPTY = {"ENVSCAN_TEST_EMPTY_DROPPED": "", "LC_ENVSCAN_EMPTY": ""}


@pytest.fixture(scope="module")
def js(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return build_js(tmp_path_factory.mktemp("jschildenv"))


def _env() -> dict[str, str]:
    base = {k: v for k, v in os.environ.items() if k.upper() not in {n.upper() for n in CANARIES}}
    return {**base, **CANARIES, **KEPT, **EMPTY}


def _run(js: tuple[Path, Path], body: str, extra: dict[str, str] | None = None) -> object:
    dist, lib = js
    snippet = f"{js_init_snippet(dist)}try {{\n{body}\n}} finally {{ removeEsTemp(); }}\n"
    names = {name.upper() for name in extra or {}}
    env = {k: v for k, v in _env().items() if k.upper() not in names}
    proc = run_js(lib, snippet, env={**env, **(extra or {})})
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def _names(stdout: str) -> dict[str, str]:
    pairs = [line.split("=", 1) for line in stdout.split("\n") if "=" in line[1:]]
    return {name.upper(): value for name, value in pairs}


ENV_LIST = "var __envList = function () { var o = []; var e = new Enumerator(ES_PROCESS_ENV); " \
           "for (; !e.atEnd(); e.moveNext()) { o.push(String(e.item())); } return o.join('\\n'); };"


def test_a_command_sees_only_allowlisted_variables(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        ENV_LIST,
        "var before = __envList();",
        f"var r = invokeEsCommand({json.dumps(CMD)}, ['/c', 'set']);",
        "WScript.Echo(convertToEsJson([r, before === __envList(), getEsEnv('GITHUB_TOKEN')]));",
    ])
    result, unchanged, token = _run(js, body)
    seen = _names(result["stdout"])
    for name in CANARIES:
        assert name not in seen, name
    assert "canary-7f3a" not in result["stdout"] and "pw@p" not in result["stdout"]
    for name in ("PATH", "SYSTEMROOT", "COMSPEC", "LC_ENVSCAN_TEST", "XDG_ENVSCAN_TEST"):
        assert name in seen, name
    if os.environ.get("ProgramFiles(x86)"):
        assert "PROGRAMFILES(X86)" in seen
    assert unchanged is True
    assert token == CANARIES["GITHUB_TOKEN"]


def test_per_call_extras_and_child_env_values_reach_the_child(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        "ES_CHILD_ENV = {'ES_CHILD_MARK': 'child-value'};",
        "enterEsChildEnv();",
        f"var r = invokeEsCommandWithEnv({{GIT_CEILING_DIRECTORIES: 'C:\\\\x'}}, "
        f"{{filePath: {json.dumps(CMD)}, args: ['/c', 'set'], timeoutSec: 10}});",
        "exitEsChildEnv();",
        "WScript.Echo(convertToEsJson([r, getEsEnv('GIT_CEILING_DIRECTORIES'), getEsEnv('ES_CHILD_MARK')]));",
    ])
    result, ceiling, mark = _run(js, body)
    seen = _names(result["stdout"])
    assert seen.get("GIT_CEILING_DIRECTORIES") == "C:\\x"
    assert seen.get("ES_CHILD_MARK") == "child-value"
    assert "ENVSCAN_TEST_CHILD_CANARY" not in seen and "HTTP_PROXY" not in seen
    assert ceiling is None and mark is None


def test_environment_is_restored_when_the_start_fails(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        ENV_LIST,
        "var before = __envList();",
        "var failed = false;",
        "try { esStartChild('\"C:\\\\envscan-no-such-dir\\\\none.exe\"', null); } catch (e) { failed = true; }",
        "WScript.Echo(convertToEsJson([failed, before === __envList(), getEsEnv('ENVSCAN_TEST_CHILD_CANARY')]));",
    ])
    failed, unchanged, canary = _run(js, body)
    assert failed is True
    assert unchanged is True
    assert canary == CANARIES["ENVSCAN_TEST_CHILD_CANARY"]


def test_keep_lists_are_generated_from_the_spec(js: tuple[Path, Path]) -> None:
    spec = load_spec(PORTABLE / "spec", js_registry())
    body = "WScript.Echo(convertToEsJson([ES_CHILD_ENV_KEEP_NAMES, ES_CHILD_ENV_KEEP_PREFIXES]));"
    names, prefixes = _run(js, body)
    assert names == list(spec.child_env_keep_names)
    assert prefixes == list(spec.child_env_keep_prefixes)


def test_environment_is_restored_after_a_timeout_and_the_worker_still_runs(js: tuple[Path, Path]) -> None:
    ping = str(SYSTEM32 / "ping.exe")
    body = "\n".join([
        ENV_LIST,
        "var before = __envList();",
        f"var r = invokeEsCommand({json.dumps(CMD)}, ['/c', {json.dumps(ping)}, '-n', '6', '127.0.0.1'], 1);",
        "var os = getEsCimSafe('Win32_OperatingSystem', null, null, ['Caption']);",
        "WScript.Echo(convertToEsJson([r.timed_out, before === __envList(), os.status, os.items.length]));",
    ])
    timed_out, unchanged, status, count = _run(js, body)
    assert timed_out is True
    assert unchanged is True
    assert status == "ok" and count == 1


def test_empty_variables_are_restored_exactly(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        ENV_LIST,
        "var before = __envList();",
        "ES_CHILD_ENV = {'ENVSCAN_TEST_EMPTY_DROPPED': 'set-for-children'};",
        "enterEsChildEnv();",
        f"var r = invokeEsCommand({json.dumps(CMD)}, ['/c', 'set']);",
        "exitEsChildEnv();",
        "WScript.Echo(convertToEsJson([r, before, __envList()]));",
    ])
    result, before, after = _run(js, body)
    assert "ENVSCAN_TEST_EMPTY_DROPPED=" in before.split("\n")
    assert "LC_ENVSCAN_EMPTY=" in before.split("\n")
    assert after == before
    assert _names(result["stdout"]).get("ENVSCAN_TEST_EMPTY_DROPPED") == "set-for-children"


# A remover that fails silently, and one that throws: the child must never start.
SILENT_REMOVE = "function removeEsEnvStrict(name) { /* the variable stays */ }"
FAILING_REMOVE = "function removeEsEnvStrict(name) { throw new Error('remove refused for ' + name); }"


@pytest.mark.parametrize("remover", [SILENT_REMOVE, FAILING_REMOVE], ids=["silent", "throws"])
def test_a_variable_left_behind_stops_the_child(js: tuple[Path, Path], remover: str) -> None:
    body = "\n".join([
        ENV_LIST,
        remover,
        "var before = __envList();",
        f"var r = invokeEsCommand({json.dumps(CMD)}, ['/c', 'echo', 'child-ran']);",
        "WScript.Echo(convertToEsJson([r, before === __envList()]));",
    ])
    result, unchanged = _run(js, body)
    assert unchanged is True
    assert result["exit_code"] is None and "child-ran" not in result["stdout"]
    assert result["error"] and "environment" in result["error"], result["error"]


UNC = r"\\envscan-test-server\share"
SSH_DIR = r"C:\Users\envscan-test\.ssh"
PS_MODULES = r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
# Lists the replacement home folder (APPDATA as the child saw it) from inside the snippet.
HOME_CHECK = (
    r"var home = /(^|\n)APPDATA=([^\r\n]*)/i.exec(r.stdout); home = home ? home[2] : null;"
    "var homeItems = home && ES_FSO.FolderExists(home) ? "
    "ES_FSO.GetFolder(home).Files.Count + ES_FSO.GetFolder(home).SubFolders.Count : -1;"
)


def test_kept_paths_are_vetted_without_touching_them(js: tuple[Path, Path]) -> None:
    # Review 2026-11-15 (X2): home_paths refused -> an empty folder in the scanner temp (TMP ->
    # the temp folder itself); refused path_lists entries dropped; other refused absolute paths
    # removed. Refused: UNC, mapped network drive (ES_NETWORK_DRIVES), credential store.
    extra = {
        "APPDATA": UNC + r"\appdata", "HOME": UNC + r"\home", "TMP": UNC + r"\tmp",
        "XDG_CONFIG_HOME": r"Q:\cfg", "XDG_ENVSCAN_LOCAL": r"C:\Windows",
        "PSMODULEPATH": PS_MODULES + ";" + UNC + r"\mods;Q:\m",
        "PATH": os.environ["PATH"] + ";" + UNC + r"\bin;" + SSH_DIR,
        "XDG_DATA_DIRS": UNC + r"\a;" + UNC + r"\b",
        "JAVA_HOME": UNC + r"\jdk", "GOPATH": SSH_DIR + r"\go", "GOROOT": r"C:\Go",
        "LC_ENVSCAN_DEVICE": r"\\?\UNC\envscan-test-server\x",
    }
    body = "\n".join([
        ENV_LIST,
        "ES_NETWORK_DRIVES = ['Q:'];",
        "var before = __envList();",
        f"var r = invokeEsCommand({json.dumps(CMD)}, ['/c', 'set']);",
        HOME_CHECK,
        "WScript.Echo(convertToEsJson([r, before === __envList(), ES_TMP, getEsEnv('APPDATA'), homeItems]));",
    ])
    result, unchanged, tmp, appdata, home_items = _run(js, body, extra)
    seen = _names(result["stdout"])
    assert unchanged is True and appdata == extra["APPDATA"]
    home = seen["APPDATA"]
    assert home.lower().startswith(tmp.lower() + "\\") and home_items == 0
    assert seen["HOME"] == home and seen["XDG_CONFIG_HOME"] == home
    assert seen["TMP"] == tmp
    assert seen["PSMODULEPATH"] == PS_MODULES
    assert UNC.lower() not in seen["PATH"].lower() and ".ssh" not in seen["PATH"].lower()
    assert "system32" in seen["PATH"].lower()
    for name in ("XDG_DATA_DIRS", "JAVA_HOME", "GOPATH", "LC_ENVSCAN_DEVICE"):
        assert name not in seen, name
    assert seen["GOROOT"] == r"C:\Go" and seen["XDG_ENVSCAN_LOCAL"] == r"C:\Windows"
    assert seen["USERPROFILE"] == os.environ["USERPROFILE"] and seen["TEMP"] == os.environ["TEMP"]


def test_per_call_extras_are_not_vetted(js: tuple[Path, Path]) -> None:
    # The scanner's own values for one child (git's scratch HOME, ...) come after the vetting.
    body = "\n".join([
        rf"var r = invokeEsCommandWithEnv({{HOME: 'C:\\envscan-own-home'}}, "
        f"{{filePath: {json.dumps(CMD)}, args: ['/c', 'set'], timeoutSec: 10}});",
        "WScript.Echo(convertToEsJson([r]));",
    ])
    (result,) = _run(js, body, {"HOME": UNC + r"\home"})
    assert _names(result["stdout"]).get("HOME") == r"C:\envscan-own-home"


def test_home_and_path_lists_are_generated_from_the_spec(js: tuple[Path, Path]) -> None:
    spec = load_spec(PORTABLE / "spec", js_registry())
    body = "WScript.Echo(convertToEsJson([ES_CHILD_ENV_HOME_PATHS, ES_CHILD_ENV_PATH_LISTS]));"
    homes, lists = _run(js, body)
    assert homes == list(spec.child_env_home_paths) and "APPDATA" in homes
    assert lists == list(spec.child_env_path_lists) and "PSMODULEPATH" in lists
