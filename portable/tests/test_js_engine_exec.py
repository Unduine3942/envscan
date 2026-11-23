"""envscan.js engine: external commands (11a-exec.js), the WMI worker (11b-wmi.js) and the registry
(11c-registry.js). Child processes started here are loopback-only (ping 127.0.0.1) or local tools.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from conftest import HAVE_POWERSHELL, ps_eval
from js_harness import HAVE_CSCRIPT, build_js, engine_only, js_init_snippet, run_js, run_script

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
CMD = str(SYSTEM32 / "cmd.exe")


@pytest.fixture(scope="module")
def js(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return build_js(tmp_path_factory.mktemp("jsexec"), engine_only)


def lit(value: str) -> str:
    return json.dumps(value)


def scan_snippet(dist: Path, body: str) -> str:
    """body runs with a scanner temp folder and the dist script as WMI worker; the temp folder is
    removed afterwards (the result line TEMP-GONE says whether it was)."""
    return (f"{js_init_snippet(dist)}var __tmp = ES_TMP;\n"
            f"try {{\n{body}\n}} finally {{ removeEsTemp(); WScript.Echo('TEMP-GONE ' + !ES_FSO.FolderExists(__tmp)); }}\n")


def run_ok(js: tuple[Path, Path], body: str, env: dict[str, str] | None = None) -> list[str]:
    dist, lib = js
    proc = run_js(lib, scan_snippet(dist, body), env=env)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    lines = proc.stdout.replace("\r\n", "\n").splitlines()
    assert lines[-1] == "TEMP-GONE true"
    return lines[:-1]


def echo_json(expr: str) -> str:
    return f"WScript.Echo(convertToEsJson({expr}));"


def parse(lines: list[str]) -> object:
    return json.loads("\n".join(lines))


# ------------------------------------------------------------------ commands

def test_command_output_exit_code_and_cwd(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        f"var a = invokeEsCommand({lit(CMD)}, ['/c', 'echo', 'hello']);",
        f"var b = invokeEsCommand({lit(CMD)}, ['/c', 'exit', '7']);",
        f"var c = invokeEsCommand({lit(CMD)}, ['/c', 'cd']);",
        f"var d = invokeEsCommand({lit(CMD)}, ['/c', 'echo', 'out', '&', 'echo', 'err', '1>&2']);",
        echo_json("[a, b, c, d]"),
    ])
    a, b, c, d = parse(run_ok(js, body))
    assert a["stdout"] == "hello" and a["exit_code"] == 0 and a["stderr"] == "" and a["error"] is None
    assert a["command"] == f"{CMD} /c echo hello" and a["timed_out"] is False
    assert b["exit_code"] == 7
    assert c["stdout"] == (os.environ.get("SystemDrive", "C:") + "\\")
    # "&" is quoted for cmd.exe, so the inner cmd sees one literal argument, not a second command
    assert d["stdout"] == 'out "&" echo err 1>&2' or d["stdout"].startswith("out")
    assert d["stderr"] == ""


def test_arguments_reach_the_program_exactly(js: tuple[Path, Path], tmp_path: Path) -> None:
    # cscript does not undo the CRT doubling of a backslash before a closing quote, so no quoted
    # argument here ends in a backslash.
    echo = tmp_path / "args.js"
    echo.write_text('for (var i = 0; i < WScript.Arguments.length; i++) WScript.Echo("[" + WScript.Arguments(i) + "]");\r\n',
                    encoding="ascii")
    args = ["//nologo", "//E:jscript", str(echo), "a b", "x&y", "p|q", "<in>", "c^d", "tail\\", "!bang!", ""]
    body = f"var r = invokeEsCommand({lit(str(SYSTEM32 / 'cscript.exe'))}, {json.dumps(args)});\n{echo_json('r')}"
    run = parse(run_ok(js, body))
    assert run["exit_code"] == 0, run
    assert run["stdout"].split("\n") == ["[a b]", "[x&y]", "[p|q]", "[<in>]", "[c^d]", "[tail\\]", "[!bang!]", "[]"]


@pytest.mark.parametrize("args, message", [
    (["%PATH%"], "not run: an argument holds a character cmd.exe would expand"),
    (['say "hi"'], "not run: an argument holds a character cmd.exe would expand"),
    (["two\nlines"], "not run: an argument holds a character cmd.exe would expand"),
])
def test_dangerous_arguments_are_refused(js: tuple[Path, Path], args: list[str], message: str) -> None:
    body = f"var r = invokeEsCommand({lit(CMD)}, {json.dumps(args)});\n{echo_json('r')}"
    run = parse(run_ok(js, body))
    assert run["error"].startswith(message) and run["exit_code"] is None


def test_relative_programs_and_batch_metacharacters_are_refused(js: tuple[Path, Path], tmp_path: Path) -> None:
    batch = tmp_path / "tool.cmd"
    batch.write_text("@echo %1\r\n", encoding="ascii")
    body = "\n".join([
        "var a = invokeEsCommand('cmd.exe', ['/c', 'echo']);",
        f"var b = invokeEsCommand({lit(str(batch))}, ['a&b']);",
        f"var c = invokeEsCommand({lit(str(batch))}, ['plain']);",
        echo_json("[a, b, c]"),
    ])
    a, b, c = parse(run_ok(js, body))
    assert a["error"] == "not run: not an absolute path"
    assert b["error"] == "not run: the batch file command line holds a cmd.exe special character"
    assert c["stdout"] == "plain" and c["command"].endswith(f'/d /v:off /s /c ""{batch}" plain"')


def test_stdin_is_empty_and_child_environment_applies(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        "ES_CHILD_ENV = {'ES_CHILD_MARK': 'child-value', 'ES_DROP_ME': ''};",
        "enterEsChildEnv();",
        f"var a = invokeEsCommand({lit(str(SYSTEM32 / 'findstr.exe'))}, ['x'], 10);",
        f"var b = invokeEsCommand({lit(CMD)}, ['/c', 'set', 'ES_']);",
        "exitEsChildEnv();",
        echo_json("[a, b, getEsEnv('ES_DROP_ME')]"),
    ])
    a, b, dropped = parse(run_ok(js, body, env={**os.environ, "ES_DROP_ME": "parent"}))
    assert a["timed_out"] is False and a["exit_code"] == 1 and a["duration_ms"] < 9000
    assert "ES_CHILD_MARK=child-value" in b["stdout"].split("\n")
    assert "ES_DROP_ME" not in b["stdout"]
    assert dropped == "parent"


def _orphans(marker: str) -> list[str]:
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
               "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*" + marker + "*' -and "
               "$_.Name -ne 'powershell.exe' } | ForEach-Object { $_.ProcessId }"]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    return [line for line in proc.stdout.split() if line.strip()]


def test_timeout_stops_the_whole_process_tree(js: tuple[Path, Path]) -> None:
    marker = "-n 37 127.0.0.1"
    body = "\n".join([
        f"var r = invokeEsCommand({lit(CMD)}, ['/c', {lit(str(SYSTEM32 / 'ping.exe'))}, '-n', '37', '127.0.0.1'], 2);",
        echo_json("r"),
    ])
    run = parse(run_ok(js, body))
    assert run["timed_out"] is True and run["exit_code"] is None
    assert 1500 <= run["duration_ms"] < 20000
    if HAVE_POWERSHELL:
        assert _orphans(marker) == [], "ping.exe or cmd.exe survived the tree stop (left running: report it)"


def test_output_decoding(js: tuple[Path, Path], tmp_path: Path) -> None:
    oem = tmp_path / "oem.txt"
    oem.write_bytes(b"caf\x82\r\nline2\r\n")
    utf8 = tmp_path / "utf8.txt"
    utf8.write_bytes("na\u00efve \u65e5\n".encode("utf-8"))
    body = "\n".join([
        "ES_CODEPAGES = {acp: '1252', oemcp: '437'};",
        f"var a = readEsCommandOutput({lit(str(oem))}, 'Oem', 4000);",
        f"var b = readEsCommandOutput({lit(str(utf8))}, 'UTF8', 4000);",
        f"var c = readEsCommandOutput({lit(str(oem))}, 'Oem', 1);",
        "ES_CODEPAGES = {acp: '1252', oemcp: '866'};",
        f"var d = readEsCommandOutput({lit(str(oem))}, 'Oem', 4000);",
        echo_json("[a, b, c, d]"),
    ])
    assert parse(run_ok(js, body)) == ["caf\u00e9\nline2", "na\u00efve \u65e5", "caf\u00e9", "caf?\nline2"]


# ------------------------------------------------------------------ WMI worker

def test_cim_queries_through_the_worker(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        "var os = getEsCimSafe('Win32_OperatingSystem', 'root/cimv2', '', ['Caption', 'MUILanguages', 'LastBootUpTime', 'Primary']);",
        "var again = getEsCimSafe('Win32_OperatingSystem', 'root/cimv2', '', ['Caption', 'MUILanguages', 'LastBootUpTime', 'Primary']);",
        "var bad = getEsCimSafe('Win32_NoSuchClassXyz', 'root/cimv2', '', ['Name']);",
        "var none = getEsCimSafe('Win32_Process', 'root/cimv2', 'ProcessId = 999999999', ['ProcessId']);",
        "var r = newEsResult('ok'); var items = addEsCimItems(r, 'Win32_NoSuchClassXyz', null, '', ['Name']);",
        echo_json("[os, os === again, bad, none, r, items]"),
    ])
    os_info, cached, bad, none, result, items = parse(run_ok(js, body))
    assert os_info["status"] == "ok" and len(os_info["items"]) == 1
    item = os_info["items"][0]
    assert item["Caption"].startswith("Microsoft Windows") and item["Primary"] is True
    assert isinstance(item["MUILanguages"], list) and item["MUILanguages"]
    assert item["LastBootUpTime"][:14].isdigit()
    assert cached is True
    assert bad["status"] == "not_found" and bad["items"] == [] and bad["error"].startswith("Win32_NoSuchClassXyz: ")
    assert none == {"error": None, "items": [], "status": "ok"}
    assert result["status"] == "partial" and result["sources"] == ["CIM Win32_NoSuchClassXyz"] and items == []


def test_worker_time_limit(js: tuple[Path, Path], tmp_path: Path) -> None:
    # A worker that never answers (stands in for a hung WMI provider) is ended by its //T limit.
    hang = tmp_path / "hang.js"
    hang.write_text("while (true) { WScript.Sleep(100); }\r\n", encoding="ascii")
    body = "\n".join([
        f"ES_WORKER_SCRIPT = {lit(str(hang))};",
        "var t0 = new Date().getTime();",
        "var r = getEsCimSafe('Win32_BIOS', 'root/cimv2', '', ['Version'], 2);",
        echo_json("[r, new Date().getTime() - t0]"),
    ])
    result, elapsed = parse(run_ok(js, body))
    assert result == {"error": "Win32_BIOS: WMI query timed out: Win32_BIOS", "items": [], "status": "timeout"}
    assert 1500 <= elapsed < 15000


@pytest.mark.parametrize("paths", [
    [r"C:\x\w1.req", r"C:\x\w1.res"],
    ["{temp}\\envscan-1-2\\w1.req", "{temp}\\envscan-1-2\\w2.res"],
    ["{temp}\\other-1-2\\w1.req", "{temp}\\other-1-2\\w1.res"],
    ["{temp}\\envscan-1-2\\..\\w1.req", "{temp}\\envscan-1-2\\..\\w1.res"],
    ["{temp}\\envscan-1-2\\w1.req"],
])
def test_worker_option_is_refused_outside_the_scanner_temp_folder(js: tuple[Path, Path], paths: list[str]) -> None:
    temp = os.environ["TEMP"]
    args = [p.replace("{temp}", temp) for p in paths]
    proc = run_script(js[0], "--es-wmi-worker", *args)
    assert proc.returncode == 2
    assert "envscan: unknown option: --es-wmi-worker" in proc.stderr
    assert proc.stdout == ""


# ------------------------------------------------------------------ registry

CV = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def test_registry_readers(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        f"var cv = {lit(CV)};",
        "var out = {};",
        "out.product = getEsRegValue(cv, 'ProductName');",
        "out.product_lc = getEsRegValue(cv, 'productname');",
        "out.missing = getEsRegValue(cv, 'NoSuchValueXyz');",
        "out.missing_key = getEsRegValues('HKLM:\\\\SOFTWARE\\\\NoSuchKeyXyz');",
        "out.has_key = testEsRegKey(cv); out.no_key = testEsRegKey('HKLM:\\\\SOFTWARE\\\\NoSuchKeyXyz');",
        "out.subkeys_has_windows = esContains(getEsRegSubkeys('HKLM:\\\\SOFTWARE\\\\Microsoft'), 'Windows');",
        "out.temp = getEsRegValue('HKCU:\\\\Environment', 'TEMP');",
        "out.multi = getEsRegValue('HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\ServiceGroupOrder', 'List');",
        "out.denied_before = ES_DENIED_READS.length;",
        "out.denied_list = getEsRegSubkeys('HKLM:\\\\SECURITY');",
        "out.denied = ES_DENIED_READS;",
        "out.tree = getEsRegTree('HKLM:\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Nls\\\\CodePage', 5);",
        "out.wow = getEsRegValue32('HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion', 'ProgramFilesDir');",
        echo_json("out"),
    ])
    out = parse(run_ok(js, body))
    assert out["product"].startswith("Windows") and out["product_lc"] == out["product"]
    assert out["missing"] is None and out["missing_key"] is None
    assert out["has_key"] is True and out["no_key"] is False and out["subkeys_has_windows"] is True
    assert out["temp"] and "%" not in out["temp"]
    assert isinstance(out["multi"], list) and len(out["multi"]) > 3
    assert out["denied_before"] == 0 and out["denied_list"] == [] and out["denied"] == ["HKLM:\\SECURITY"]
    assert out["tree"]["ACP"] and out["tree"]["OEMCP"]
    assert out["wow"].endswith("(x86)")


def test_registry_values_match_powershell(js: tuple[Path, Path], built: Path) -> None:
    if not HAVE_POWERSHELL:
        pytest.skip("needs Windows PowerShell")
    keys = [CV, r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment", r"HKCU:\Environment",
            r"HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage"]
    body = "\n".join(f"WScript.Echo(convertToEsJson(getEsRegValues({lit(k)}))); WScript.Echo('----');" for k in keys)
    js_out = "\n".join(run_ok(js, body)).split("----")
    expr = "; ".join(f"ConvertTo-EsJson (Get-EsRegValues '{k}'); '----'" for k in keys)
    proc = ps_eval(built / "build" / "lib" / "envscan-lib.ps1", expr)
    assert proc.returncode == 0, proc.stderr
    ps_out = proc.stdout.replace("\r\n", "\n").split("----")
    for key, js_text, ps_text in zip(keys, js_out, ps_out):
        js_values, ps_values = json.loads(js_text), json.loads(ps_text)
        # PowerShell hashtables fold the case of names; JScript keeps the registry's spelling.
        assert {k.lower() for k in js_values} == {k.lower() for k in ps_values}, key
        ps_lower = {k.lower(): v for k, v in ps_values.items()}
        for name, value in js_values.items():
            expected = ps_lower[name.lower()]
            if isinstance(expected, int) and expected > 2**53:
                assert value == str(expected), (key, name)
            else:
                assert value == expected, (key, name)


# ------------------------------------------------------------------ requests from the probe owners

def test_embedded_objects_and_unsigned_numbers(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        "var tasks = getEsCimSafe('MSFT_ScheduledTask', 'root/Microsoft/Windows/TaskScheduler', '',",
        "  ['TaskName', 'Actions.Execute', 'Principal.UserId', 'Principal.NoSuchSub']);",
        "var os = getEsCimSafe('Win32_OperatingSystem', null, '', ['TotalVisibleMemorySize', 'CurrentTimeZone']);",
        "var gpu = getEsCimSafe('Win32_VideoController', null, '', ['AdapterRAM']);",
        echo_json("[tasks, os, gpu]"),
    ])
    tasks, os_info, gpu = parse(run_ok(js, body))
    assert tasks["status"] == "ok" and tasks["items"], tasks["error"]
    with_actions = [t for t in tasks["items"] if isinstance(t.get("Actions"), list) and t["Actions"]]
    assert with_actions and all(set(a) == {"Execute"} for t in with_actions for a in t["Actions"])
    principals = [t["Principal"] for t in tasks["items"] if t.get("Principal") is not None]
    assert principals and all(set(p) == {"UserId", "NoSuchSub"} and p["NoSuchSub"] is None for p in principals)
    memory = os_info["items"][0]["TotalVisibleMemorySize"]
    assert isinstance(memory, int) and memory > 0
    assert isinstance(os_info["items"][0]["CurrentTimeZone"], int)
    assert all(item["AdapterRAM"] is None or item["AdapterRAM"] >= 0 for item in gpu["items"])


def test_registry_binary_bytes(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        f"var a = getEsRegBinary({lit(CV)}, 'DigitalProductId');",
        f"var b = getEsRegBinary({lit(CV)}, 'ProductName');",
        f"var c = getEsRegBinary({lit(CV)}, 'NoSuchValueXyz');",
        f"var d = getEsRegBinary({lit('HKLM:' + chr(92) + 'SECURITY' + chr(92) + 'Policy')}, 'X');",
        echo_json("[a.length > 100, typeof a[0] === 'number', b, c, d, ES_DENIED_READS]"),
    ])
    assert parse(run_ok(js, body)) == [True, True, None, None, None, ["HKLM:\\SECURITY\\Policy"]]


def test_a_worker_never_starts_a_worker(js: tuple[Path, Path]) -> None:
    body = "\n".join([
        "setEsEnvValue(ES_WORKER_MARK, '1');",
        "var r = getEsCimSafe('Win32_BIOS', null, '', ['Version']);",
        "setEsEnvValue(ES_WORKER_MARK, null);",
        echo_json("r"),
    ])
    result = parse(run_ok(js, body))
    assert result["status"] == "error" and "never starts another worker" in result["error"]


def test_worker_needs_a_folder_the_scanner_made(js: tuple[Path, Path]) -> None:
    folder = Path(os.environ["TEMP"]) / f"envscan-{os.getpid()}-424242"
    folder.mkdir()
    try:
        (folder / "w1.req").write_text("reg-check", encoding="utf-16")
        proc = run_script(js[0], "--es-wmi-worker", str(folder / "w1.req"), str(folder / "w1.res"))
        assert proc.returncode == 2 and not (folder / "w1.res").exists()
    finally:
        for item in folder.iterdir():
            item.unlink()
        folder.rmdir()
