"""envscan.js engine: fixes from the security review.

- M2: the Windows folder (cmd.exe, cscript.exe, the child cwd) comes from Windows, never from the
  SystemRoot/SystemDrive/windir variables; an untrusted Windows folder refuses every command.
- L1: the WMI worker does not trust its request file (namespace, SELECT only, numeric PID whose
  creation time matches the started child).
- L2: a path in or below a credential store is refused by the path guards themselves, so PATH,
  PSModulePath, JAVA_HOME and the cwd pointing into ~/.ssh are never listed, read or written.
- L3: network drives are known before the temp folder is created; a TEMP on one is refused.
- L4: a data key named "hasOwnProperty" does not break a probe (esHas).
- M3: run_js removes the scanner temp folders a snippet leaves behind, and nothing else.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
from typing import Any

import pytest
from js_harness import (HAVE_CSCRIPT, PORTABLE, build_js, engine_only, js_init_snippet, remove_reported_temps,
                        run_js)

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]


def windows_dir() -> str:
    """The Windows folder as Windows reports it (GetWindowsDirectoryW, not the environment)."""
    buffer = ctypes.create_unicode_buffer(260)
    ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, 260)
    return buffer.value


CMD = str(Path(windows_dir()) / "System32" / "cmd.exe")


@pytest.fixture(scope="module")
def engine(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return build_js(tmp_path_factory.mktemp("jsreview-engine"), engine_only)


@pytest.fixture(scope="module")
def full(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return build_js(tmp_path_factory.mktemp("jsreview-full"))


def lit(value: Any) -> str:
    return json.dumps(value)


def run_json(js: tuple[Path, Path], body: str, env: dict[str, str] | None = None, prefix: str = "") -> Any:
    """Runs body with a scanner temp folder (removed afterwards); body sets `out`, printed as JSON."""
    dist, lib = js
    snippet = (f"{prefix}{js_init_snippet(dist)}var out = null;\n"
               f"try {{\n{body}\n}} finally {{ removeEsTemp(); }}\n"
               "WScript.Echo(convertToEsJson(out));\n")
    proc = run_js(lib, snippet, env=env)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


# ------------------------------------------------------------------ M2: trusted Windows folder

def test_system_tool_and_child_cwd_ignore_the_environment(engine: tuple[Path, Path], tmp_path: Path) -> None:
    fake = str(tmp_path / "fakeroot")
    body = "\n".join([
        f"setEsEnvValue('SystemRoot', {lit(fake)}); setEsEnvValue('windir', {lit(fake)}); setEsEnvValue('SystemDrive', 'Q:');",
        "removeEsTemp(); ES_WINDOWS_DIR = null; initializeEsTemp();",
        "var tool = getEsSystemTool('cmd.exe');",
        "var r = invokeEsCommand(tool, ['/d', '/c', 'cd']);",
        "out = { tool: tool, cwd: ES_CHILD_CWD, stdout: r.stdout, exit: r.exit_code, error: r.error, host: getEsWorkerHost() };",
    ])
    out = run_json(engine, body)
    assert out["tool"].lower() == CMD.lower()
    assert out["cwd"].lower() == windows_dir()[:2].lower() + "\\"
    assert out["error"] is None and out["exit"] == 0
    assert out["stdout"].strip().lower() == out["cwd"].lower()
    assert fake.lower() not in out["host"].lower()


@pytest.mark.parametrize("fake", ["\\\\host\\share\\Windows", "C:Windows", "Z:\\Windows", "", "C:\\",
                                  "C:\\Users\\x\\.ssh\\Windows", "C:\\WIN%X%", "\\\\?\\C:\\Windows"])
def test_untrusted_windows_folder_refuses_every_command(engine: tuple[Path, Path], tmp_path: Path, fake: str) -> None:
    batch = tmp_path / "hello.cmd"
    batch.write_text("@echo hi\r\n", encoding="ascii")
    body = "\n".join([
        "var keep = ES_TMP;",
        f"ES_NETWORK_DRIVES = ['Z:']; ES_WINDOWS_DIR = {lit(fake)};",
        f"var direct = invokeEsCommand({lit(CMD)}, ['/c', 'echo', 'x']);",
        f"var viaBatch = invokeEsCommand({lit(str(batch))}, []);",
        "var temp = null; try { initializeEsTemp(); temp = 'created'; } catch (e) { temp = esErrorText(e); }",
        "var host = null; try { host = getEsWorkerHost(); } catch (e2) { host = 'refused'; }",
        "out = { tool: getEsSystemTool('cmd.exe'), direct: direct.error, exit: direct.exit_code, batch: viaBatch.error, temp: temp };",
        "ES_WINDOWS_DIR = null; ES_TMP = keep;",
    ])
    out = run_json(engine, body)
    assert out["tool"] is None
    assert out["exit"] is None and out["direct"].startswith("not run")
    assert out["batch"].startswith("not run")
    assert "Windows folder" in out["temp"]


# ------------------------------------------------------------------ L1: the worker's request file

@pytest.mark.parametrize("lines, problem", [
    (["query", "root/cimv2", "ASSOCIATORS OF {Win32_Process.Handle='0'}", "Name"], "invalid query"),
    (["query", "root/cimv2", "REFERENCES OF {Win32_Process.Handle='0'}", "Name"], "invalid query"),
    (["query", "\\\\host\\root\\cimv2", "SELECT Name FROM Win32_Process", "Name"], "invalid namespace"),
    (["query", "root/cimv2", "SELECT Name FROM Win32_Process", "Name;x"], "invalid prop"),
    (["query", "root/cimv2", "select * from Win32_Process", "Name"], "invalid query"),
    (["tree-stop", "abc", "0", "1"], "invalid request"),
    (["tree-stop", "4"], "invalid request"),
])
def test_worker_refuses_untrusted_requests(engine: tuple[Path, Path], lines: list[str], problem: str) -> None:
    out = run_json(engine, f"var r = invokeEsWorker({lit(lines)}, 30); out = {{ status: r.status, error: r.error }};")
    assert out["status"] == "error" and problem in out["error"], out


def test_worker_runs_a_plain_select(engine: tuple[Path, Path]) -> None:
    lines = ["query", "root/cimv2", "SELECT ProcessId FROM Win32_Process WHERE ProcessId=4", "ProcessId"]
    out = run_json(engine, f"var r = invokeEsWorker({lit(lines)}, 30); out = {{ status: r.status, error: r.error }};")
    assert out == {"status": "ok", "error": None}


def test_tree_stop_never_stops_a_process_with_another_creation_time(engine: tuple[Path, Path]) -> None:
    body = "\n".join([
        "var t0 = new Date().getTime();",
        f"var c = ES_SHELL.Exec({lit(chr(34) + CMD + chr(34) + ' /d /c ping -n 30 127.0.0.1 >nul')});",
        "var t1 = new Date().getTime();",
        "try {",
        "  var wrong = invokeEsWorker(['tree-stop', String(c.ProcessID), '0', String(t0 - 60000)], 20);",
        "  WScript.Sleep(300); var aliveAfterWrong = c.Status === 0;",
        "  var right = invokeEsWorker(['tree-stop', String(c.ProcessID), String(t0 - 500), String(t1 + 500)], 20);",
        "  for (var i = 0; i < 50 && c.Status === 0; i++) { WScript.Sleep(100); }",
        "  out = { wrong: wrong.status, wrongError: wrong.error, aliveAfterWrong: aliveAfterWrong, right: right.status, stopped: c.Status !== 0 };",
        "} finally { if (c.Status === 0) { c.Terminate(); } }",
    ])
    out = run_json(engine, body)
    assert out["wrong"] == "error" and "not the started child" in out["wrongError"]
    assert out["aliveAfterWrong"] is True
    assert out["right"] == "ok" and out["stopped"] is True


def test_cim_dates_keep_milliseconds(engine: tuple[Path, Path]) -> None:
    out = run_json(engine, "out = convertFromEsCimDate('20261113145324.007426+540').getTime() % 1000;")
    assert out == 7


# ------------------------------------------------------------------ L2: credential stores

def make_fake_home(tmp_path: Path) -> Path:
    """A profile-like folder with a .ssh holding a module, a tool, a JDK and a config file."""
    ssh = tmp_path / "home" / ".ssh"
    (ssh / "Modules" / "CanaryModZ" / "1.0").mkdir(parents=True)
    (ssh / "bin").mkdir()
    (ssh / "bin" / "canarytoolz.exe").write_bytes(b"")
    (ssh / "jdk" / "bin").mkdir(parents=True)
    (ssh / "jdk" / "bin" / "java.exe").write_bytes(b"")
    (ssh / "jdk" / "release").write_text('JAVA_VERSION="99.canary"\n', encoding="ascii")
    (ssh / "config").write_text("Host canaryhostz\n", encoding="ascii")
    return ssh


# Every FSO call goes through this spy, which records the first argument (the path).
FSO_SPY = r"""
var FSO_LOG = [];
var REAL_FSO = ES_FSO;
function esSpyMethod(name) {
    return function (a, b, c, d) {
        FSO_LOG.push(name + "|" + a);
        var n = arguments.length;
        if (n === 0) { return REAL_FSO[name](); }
        if (n === 1) { return REAL_FSO[name](a); }
        if (n === 2) { return REAL_FSO[name](a, b); }
        if (n === 3) { return REAL_FSO[name](a, b, c); }
        return REAL_FSO[name](a, b, c, d);
    };
}
var SPY = { Drives: REAL_FSO.Drives };
var SPY_NAMES = ["FileExists", "FolderExists", "GetFolder", "GetFile", "OpenTextFile", "CreateTextFile", "CreateFolder",
    "DeleteFile", "DeleteFolder", "GetAbsolutePathName", "GetParentFolderName", "GetFileVersion", "GetSpecialFolder"];
for (var si = 0; si < SPY_NAMES.length; si++) { SPY[SPY_NAMES[si]] = esSpyMethod(SPY_NAMES[si]); }
ES_FSO = SPY;
"""


def test_credential_store_paths_are_never_listed_read_or_written(full: tuple[Path, Path], tmp_path: Path) -> None:
    ssh = make_fake_home(tmp_path)
    env = dict(os.environ)
    env["PSModulePath"] = str(ssh / "Modules")
    env["PATH"] = str(ssh / "bin") + ";" + env.get("PATH", "")
    env["JAVA_HOME"] = str(ssh / "jdk")
    s = lit(str(ssh))
    body = "\n".join([
        FSO_SPY,
        f"ES_START_CWD = {s}; ES_LINK_CACHE = {{}}; ES_PATH_DIRS = null;",
        f"var config = {s} + '\\\\config';",
        "var listed = newEsResult(); var modules = newEsResult(); var java = null;",
        f"var listable = testEsListableFolder(listed, {s} + '\\\\Modules');",
        "var mods = getEsModulePackages(modules);",
        "try { java = probe_runtime_java(); } catch (e) { java = { error: esErrorText(e) }; }",
        "var candidates = getEsCandidateDirs(); var ids = [];",
        "for (var i = 0; i < candidates.length; i++) { ids.push(candidates[i].id); }",
        "out = {",
        "  refused: getEsRefusedFolder(config), link: getEsPathLinkReason(config),",
        f"  safe: testEsSafePath({s}, 'Container'), read: readEsTextFile(config).error,",
        f"  entries: getEsDirEntries({s}).length, listable: listable, listedNotes: listed.notes,",
        "  mods: mods, moduleNotes: modules.notes, pathDirs: getEsPathDirs(), parents: getEsDefaultOutputParents(),",
        "  ids: ids, java: java, log: FSO_LOG",
        "};",
        "ES_FSO = REAL_FSO;",
    ])
    out = run_json(full, body, env=env)
    assert out["refused"] == {"path": str(ssh), "reason": "credential store"}
    assert out["link"] == "credential store"
    assert out["safe"] is False and out["read"] == "credential store" and out["entries"] == 0
    assert out["listable"] is False and f"{ssh} not read: credential store" in out["listedNotes"]
    assert out["mods"] == [] and f"{ssh} not read: credential store" in out["moduleNotes"]
    assert not [d for d in out["pathDirs"] if ".ssh" in d.lower()]
    assert not [p for p in out["parents"] if ".ssh" in p.lower()]
    assert "cwd" not in out["ids"]
    text = json.dumps(out["java"]).lower()
    assert "canary" not in text
    assert out["log"], "the spy recorded nothing"
    touched = [entry for entry in out["log"] if ".ssh" in entry.lower()]
    assert touched == [], touched


def test_temp_in_a_credential_store_is_refused(engine: tuple[Path, Path], tmp_path: Path) -> None:
    ssh = make_fake_home(tmp_path)
    dist, lib = engine
    env = dict(os.environ)
    env["TEMP"] = str(ssh / "tmp")
    snippet = (f"var msg = 'created'; try {{ {js_init_snippet(dist)} }} catch (e) {{ msg = esErrorText(e); }}\n"
               "WScript.Echo(msg); removeEsTemp();\n")
    proc = run_js(lib, snippet, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "credential store" in proc.stdout
    assert not (ssh / "tmp").exists()


# ------------------------------------------------------------------ L3: drives before temp

def test_drives_are_known_before_temp_and_a_network_temp_is_refused(full: tuple[Path, Path], tmp_path: Path) -> None:
    _dist, lib = full
    main = (PORTABLE / "src" / "js" / "90-main.js").read_text(encoding="ascii")
    temp_drive = os.environ.get("TEMP", "C:\\")[:2].upper()
    results = {}
    for name, drives in (("network", [temp_drive]), ("local", [])):
        out_dir = tmp_path / name
        out_dir.mkdir()
        snippet = main + "\n" + "\n".join([
            "var ORDER = [];",
            f"function initializeEsDrives() {{ ORDER.push(ES_TMP === null ? 'before-temp' : 'after-temp'); ES_NETWORK_DRIVES = {lit(drives)}; }}",
            f"ES_OPT.out = {lit(str(out_dir))};",
            "var folder = esPrepareScan(); var tmp = ES_TMP; removeEsTemp();",
            "WScript.Echo(convertToEsJson({ order: ORDER, folder: folder, tmp: tmp }));",
        ])
        proc = run_js(lib, snippet)
        assert proc.returncode == 0, proc.stderr
        results[name] = (json.loads(proc.stdout), proc.stderr)
    network, stderr = results["network"]
    assert network["order"][0] == "before-temp" and network["folder"] is None and network["tmp"] is None
    assert "no usable TEMP folder" in stderr
    local, _ = results["local"]
    assert local["order"][0] == "before-temp" and local["folder"] and local["tmp"]


# ------------------------------------------------------------------ L4: hasOwnProperty as data

def test_env_var_named_hasownproperty_does_not_break_env_vars(full: tuple[Path, Path]) -> None:
    env = dict(os.environ)
    env["hasOwnProperty"] = "canary-own-value"
    body = "var r = probe_env_vars(); out = { status: r.status, error: r.error, value: r.data.process['hasOwnProperty'], orig: getEsOrigEnv('hasOwnProperty') };"
    out = run_json(full, body, env=env)
    assert out["error"] is None and out["status"] in ("ok", "partial")
    assert out["value"] == "canary-own-value" and out["orig"] == "canary-own-value"


def test_has_own_helper_ignores_a_shadowing_key(engine: tuple[Path, Path]) -> None:
    body = "var o = { hasOwnProperty: 'x', a: 1 }; out = [esHas(o, 'a'), esHas(o, 'b'), esHas(o, 'hasOwnProperty'), esHas(null, 'a')];"
    assert run_json(engine, body) == [True, False, True, False]


# ------------------------------------------------------------------ M3: temp folders of snippets

def test_run_js_removes_a_temp_folder_the_snippet_left(engine: tuple[Path, Path]) -> None:
    dist, lib = engine
    proc = run_js(lib, js_init_snippet(dist) + "WScript.Echo(ES_TMP);\n")
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    folder = Path(proc.stdout.strip())
    assert folder.name.startswith("envscan-") and not folder.exists()


def test_reported_folders_are_removed_only_when_they_are_scanner_temp_folders(tmp_path: Path) -> None:
    good = tmp_path / "envscan-12-34"
    no_marker = tmp_path / "envscan-56-78"
    bad_name = tmp_path / "keep-me"
    for folder in (good, no_marker, bad_name):
        folder.mkdir()
    (good / "stdin.empty").write_bytes(b"")
    (bad_name / "stdin.empty").write_bytes(b"")
    stderr = "\n".join(["first", *(f"__ES_TEST_TEMP_REPORT={f}" for f in (good, no_marker, bad_name)), "last"])
    assert remove_reported_temps(stderr) == "first\nlast"
    assert not good.exists() and no_marker.exists() and bad_name.exists()
