"""envscan.js engine: path guards (11d-paths.js) and file readers (11e-files.js).

The text-only guards are compared with the ps1 functions on the same inputs (the cases of
tests/test_ps_hardening.py and more); links are real junctions made with mklink /J.
"""
from __future__ import annotations

import json
import os
import platform
import random
import subprocess
from pathlib import Path

import pytest
from conftest import HAVE_POWERSHELL, ps_eval
from js_harness import HAVE_CSCRIPT, build_js, engine_only, run_js
from test_ps_hardening import CREDENTIAL_STORES, NORMALISED_STORES

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

NOT_STORES = (
    "C:\\Users\\u\\.npmrc", "C:\\x\\config.json", "C:\\x\\sshd\\x", "C:\\x\\my.netrc.bak", "C:\\x\\auth.json.bak",
    "C:\\x\\history", "C:\\x\\.history.bak", "C:\\x\\my.histfile", "C:\\PROGRA~1\\Git\\etc\\gitconfig",
    "\\\\?\\C:\\x\\pip.ini", "C:\\x\\a.b.\\pip.ini", "C:\\jdk\\lib\\security\\cacerts", "C:\\x\\ca-bundle.pem",
    "C:\\x\\cert.pem", "C:\\x\\tls-ca-bundle.pem", "C:\\Users\\u\\.gem\\specs", "C:\\Users\\u\\.cargo\\config.toml",
    "C:\\Users\\u\\.m2\\settings.xml", "C:\\Users\\u\\.config\\gh\\config.yml", "C:\\Users\\u\\keys\\id_rsa.pub",
    "C:\\x\\monkey.txt", "C:\\x\\token", "C:\\x\\keystore.txt", "C:\\Users\\u\\a\\..\\b\\x.txt", "C:\\x\\.\\y\\z.txt",
    "C:\\x\\\\y\\z.txt", "C:\\x\\ca-bundle.pem\\", "C:\\Users\\u\\.docker\\other.json", "C:\\Users\\u\\PROGRA~2\\Tool\\a.txt",
)
PATHS = (*CREDENTIAL_STORES, *NORMALISED_STORES, *NOT_STORES,
         "C:\\x\\NUL", "C:\\x\\nul.txt", "C:\\x\\Con", "C:/x/com1", "C:\\x\\LPT9.log", "C:\\x\\CONIN$", "C:\\x\\conout$",
         "C:\\x\\aux.gitconfig", "C:\\x\\PRN", "C:\\x\\COM0", "C:\\x\\console", "C:\\x\\nul2", "C:\\x\\icon.txt",
         "C:\\x\\COM10", "C:\\x\\nul .txt", "relative\\x", "\\root\\x", "C:drive-relative", "\\\\server\\share\\x",
         "\\\\?\\UNC\\server\\share", "\\\\.\\pipe\\x", "Z:\\mapped\\x", "z:\\lower", "C:", "C:\\", "D:/fwd/slash",
         "C:\\a\\..\\..\\..\\b", "\\\\srv\\share\\..\\..\\x", "C:\\a\\.. .\\b. \\c")


@pytest.fixture(scope="module")
def js(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    return build_js(tmp_path_factory.mktemp("jspaths"), engine_only)


def lit(value: object) -> str:
    return json.dumps(value)


def js_json(js: tuple[Path, Path], body: str, env: dict[str, str] | None = None) -> object:
    proc = run_js(js[1], body, env=env)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def _guards_js(js: tuple[Path, Path]) -> dict[str, list[object]]:
    body = (f"ES_NETWORK_DRIVES = ['Z:']; var paths = {lit(list(PATHS))}; var out = {{}};\n"
            "for (var i = 0; i < paths.length; i++) { var p = paths[i]; out[p] = [testEsCredentialPath(p), "
            "testEsDeviceName(p), convertToEsFlatPath(p, false), convertToEsFlatPath(p, true), testEsLocalPath(p), "
            "getEsNonLocalReason(p), testEsNetworkPath(p)]; }\nWScript.Echo(convertToEsJson(out));")
    return js_json(js, body)  # type: ignore[return-value]


def test_credential_stores_are_recognised(js: tuple[Path, Path]) -> None:
    guards = _guards_js(js)
    assert {p for p in (*CREDENTIAL_STORES, *NORMALISED_STORES, *NOT_STORES) if guards[p][0]} == \
        set(CREDENTIAL_STORES) | set(NORMALISED_STORES)


def test_path_guards_match_powershell(js: tuple[Path, Path], built: Path) -> None:
    if not HAVE_POWERSHELL:
        pytest.skip("needs Windows PowerShell")
    guards = _guards_js(js)
    quoted = ", ".join("'" + p.replace("'", "''") + "'" for p in PATHS)
    expr = ("$script:ES_NETWORK_DRIVES = @('Z:'); $out = @{}; foreach ($p in @(" + quoted + ")) { $out[$p] = @("
            "(Test-EsCredentialPath $p), [bool](Test-EsDeviceName $p), (ConvertTo-EsFlatPath $p $false), "
            "(ConvertTo-EsFlatPath $p $true), (Test-EsLocalPath $p), (Get-EsNonLocalReason $p), (Test-EsNetworkPath $p)) }; "
            "ConvertTo-EsJson $out")
    proc = ps_eval(built / "build" / "lib" / "envscan-lib.ps1", expr)
    assert proc.returncode == 0, proc.stderr
    expected = json.loads(proc.stdout)
    for path in PATHS:
        assert guards[path] == expected[path], path


# ------------------------------------------------------------------ links, globs and folders

def _junction(link: Path, target: Path) -> None:
    proc = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)], capture_output=True,
                          text=True, check=False, stdin=subprocess.DEVNULL)
    if proc.returncode != 0:
        pytest.skip("cannot create a junction here: " + proc.stdout + proc.stderr)


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    (tmp_path / "home" / ".ssh").mkdir(parents=True)
    (tmp_path / "home" / ".ssh" / "config").write_text("Host x", encoding="ascii")
    (tmp_path / "home" / "tool").mkdir()
    (tmp_path / "home" / "tool" / "config").write_text("ok", encoding="ascii")
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "file.txt").write_text("behind the link", encoding="ascii")
    _junction(tmp_path / "home" / "linked", tmp_path / "real")
    return tmp_path


def test_links_are_never_followed(js: tuple[Path, Path], tree: Path) -> None:
    home = str(tree / "home")
    body = "\n".join([
        f"var home = {lit(home)}; var r = newEsResult('ok'); var out = {{}};",
        "out.read = readEsTextFile(home + '\\\\linked\\\\file.txt');",
        "out.read_link = readEsTextFile(home + '\\\\linked');",
        "out.entries = getEsDirEntries(home + '\\\\linked').length;",
        "out.safe = testEsSafePath(home + '\\\\linked\\\\file.txt');",
        "out.glob = expandEsPathPattern(home + '\\\\*\\\\file.txt', r);",
        "out.direct = expandEsPathPattern(home + '\\\\linked\\\\file.txt', r);",
        "out.listable = testEsListableFolder(r, home + '\\\\linked');",
        "out.reason = getEsPathLinkReason(home + '\\\\linked\\\\x\\\\y');",
        "out.result = r;",
        "WScript.Echo(convertToEsJson(out));",
    ])
    out = js_json(js, body)
    link = home + "\\linked"
    assert out["read"]["error"] == "link target unknown" and out["read"]["text"] is None
    assert out["read_link"]["error"] in ("is a directory", "link target unknown")
    assert out["entries"] == 0 and out["safe"] is False and out["listable"] is False
    assert out["glob"] == [] and out["direct"] == []
    assert out["reason"] == "link target unknown"
    assert out["result"]["status"] == "partial"
    assert out["result"]["notes"] == [link + " not read: link target unknown"]


def test_globs_and_env_patterns_skip_credential_stores(js: tuple[Path, Path], tree: Path) -> None:
    home = str(tree / "home")
    env = {**os.environ, "ES_TEST_HOME": home, "ES_TEST_SSH": home + "\\.ssh"}
    body = "\n".join([
        "var r = newEsResult('ok'); var out = {};",
        "out.star = expandEsPathPattern('{env:ES_TEST_HOME}\\\\*\\\\config', r);",
        "out.ssh = expandEsPathPattern('{env:ES_TEST_SSH}\\\\config', r);",
        "out.unset = expandEsPathPattern('{env:ES_TEST_UNSET_XYZ}\\\\config', r);",
        "out.relative = expandEsPathPattern('tool\\\\config', r);",
        "out.device = expandEsPathPattern('{env:ES_TEST_HOME}\\\\NUL.txt', r);",
        "out.entries = []; var e = getEsDirEntries({env}); for (var i = 0; i < e.length; i++) out.entries.push(e[i].Name);".replace(
            "{env}", lit(home)),
        "WScript.Echo(convertToEsJson(out));",
    ])
    out = js_json(js, body, env=env)
    assert out["star"] == [home + "\\tool\\config"]
    assert out["ssh"] == [] and out["unset"] == [] and out["relative"] == [] and out["device"] == []
    assert sorted(out["entries"]) == [".ssh", "linked", "tool"]


# ------------------------------------------------------------------ file contents

def _bytes_cases(tmp: Path) -> dict[str, bytes]:
    rng = random.Random(7)
    cases = {f"r{n}": bytes(rng.randrange(256) for _ in range(n)) for n in (0, 1, 2, 3, 5, 64, 1001, 4096, 5000)}
    cases.update({"bom": b"\xff\xfeA\x00B", "bom_even": b"\xff\xfe\x00\x00", "zeros": b"\x00" * 7,
                  "ascii_odd": b"MZ\x90\x00A", "high_odd": b"MZ\x90\x00\xc3", "crlf": b"a\r\nb\rc\n"})
    for name, data in cases.items():
        (tmp / name).write_bytes(data)
    return cases


def test_bytes_are_read_exactly(js: tuple[Path, Path], tmp_path: Path) -> None:
    cases = _bytes_cases(tmp_path)
    body = (f"var dir = {lit(str(tmp_path))}; var names = {lit(sorted(cases))}; var out = {{}};\n"
            "for (var i = 0; i < names.length; i++) { out[names[i]] = esReadBytesExact(dir + '\\\\' + names[i], 4096); }\n"
            "WScript.Echo(convertToEsJson(out));")
    out = js_json(js, body)
    for name, data in cases.items():
        got = out[name]
        expected = data[:4096]
        if got["exact"]:
            assert bytes(got["bytes"]) == expected, name
        else:
            # only an odd final byte that is not ASCII may stay unknown, and it is left out
            assert bytes(got["bytes"]) == expected[:-1] and expected[-1] >= 0x80, name
        assert got["size"] == len(data)
    assert out["ascii_odd"]["exact"] and out["bom"]["exact"] and out["r4096"]["exact"]


def test_text_files_are_decoded(js: tuple[Path, Path], tmp_path: Path) -> None:
    files = {
        "utf8.txt": "caf\u00e9 \u65e5\u672c \U0001f600\nline2\n".encode("utf-8"),
        "bom8.txt": b"\xef\xbb\xbf" + "na\u00efve\r\n".encode("utf-8"),
        "utf16.txt": "\ufeffwide \u00e9\r\nx".encode("utf-16-le"),
        "ansi.txt": b"caf\xe9\r\n",
        "lines.txt": b"".join(b"%d\n" % i for i in range(5000)),
        "big.txt": b"x" * 40000,
        "empty.txt": b"",
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    (tmp_path / "folder").mkdir()
    names = [*sorted(files), "folder", "missing.txt"]
    body = (f"var dir = {lit(str(tmp_path))}; var names = {lit(names)}; var out = {{}};\n"
            "for (var i = 0; i < names.length; i++) { out[names[i]] = readEsTextFile(dir + '\\\\' + names[i]); }\n"
            "WScript.Echo(convertToEsJson(out));")
    out = js_json(js, body)
    assert out["utf8.txt"]["text"] == "caf\u00e9 \u65e5\u672c \U0001f600\nline2"
    assert out["bom8.txt"]["text"] == "na\u00efve"
    assert out["utf16.txt"]["text"] == "wide \u00e9\nx"
    assert out["ansi.txt"]["text"] in ("caf\u00e9", "caf?")
    assert out["lines.txt"]["text"].count("\n") <= 3999 and out["lines.txt"]["truncated"] is True
    assert out["big.txt"]["truncated"] is True and len(out["big.txt"]["text"]) == 16384
    assert out["empty.txt"]["text"] == "" and out["empty.txt"]["size"] == 0 and out["empty.txt"]["error"] is None
    assert out["folder"]["error"] == "is a directory"
    missing = str(tmp_path / "missing.txt")
    assert out["missing.txt"]["error"] == f"Cannot find path '{missing}' because it does not exist."


def test_pe_machine_and_write_test(js: tuple[Path, Path], tmp_path: Path) -> None:
    script = tmp_path / "s.sh"
    script.write_bytes(b"#!/bin/sh\necho hi\n" + b" " * 64)
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    body = "\n".join([
        f"var out = [getEsPeMachine({lit(str(system32 / 'cmd.exe'))}), getEsPeMachine({lit(str(script))}),",
        f"  getEsPeMachine({lit(str(tmp_path / 'none.exe'))}), testEsWritableDir({lit(str(tmp_path))}),",
        f"  testEsWritableDir({lit(str(tmp_path / 'nope'))}), testEsWritableDir('relative')];",
        "WScript.Echo(convertToEsJson(out));",
    ])
    machine = {"AMD64": "x86_64", "ARM64": "arm64", "x86": "x86"}.get(platform.machine(), platform.machine())
    assert js_json(js, body) == [machine, "script", None, True, None, None]
    assert [p.name for p in tmp_path.iterdir()] == ["s.sh"]
