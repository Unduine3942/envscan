"""envscan.js (JScript) tool probes: tools.inventory, runtime.version_managers, runtime.java,
runtime.dotnet, runtime.python, toolchain.msvc, native.deps (src/js/24-probes-tools.js).

On this machine each probe runs in envscan.js and in the envscan.ps1 library (same scrubbed
environment): the same tools must be found at the same paths with the same versions, and the
runtimes, SDKs and libraries must agree. Fixture cases cover the version parser, the
never-run rules and vswhere's text format.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from test_js_probes_packages import js, js_lib, js_scan, ps_scan, run_snippet  # noqa: F401 (fixture)
from conftest import HAVE_POWERSHELL
from js_harness import HAVE_CSCRIPT

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

TOOL_PROBES = ("tools.inventory", "runtime.version_managers", "runtime.java", "runtime.dotnet", "runtime.python",
               "toolchain.msvc", "native.deps")


@pytest.fixture(scope="module")
def machine_js(js_lib: Path) -> dict[str, Any]:  # noqa: F811
    return js_scan(js_lib, TOOL_PROBES)


@pytest.fixture(scope="module")
def machine_ps(built: Path) -> dict[str, Any]:
    if not HAVE_POWERSHELL:
        pytest.skip("needs Windows PowerShell")
    return ps_scan(built, TOOL_PROBES)


def data(results: dict[str, Any], probe: str) -> dict[str, Any]:
    return results[probe]["data"]


def assert_status(machine_js: dict[str, Any], machine_ps: dict[str, Any], probe: str) -> None:
    """Same status as ps, except that a PATH folder that is a link (never listed in js) makes
    every probe that uses the PATH index partial, with a note naming the folder."""
    got, want = machine_js[probe]["status"], machine_ps[probe]["status"]
    links = data(machine_js, "tools.inventory")["link_dirs"]
    if links and want in ("ok", "not_found", "partial"):
        assert got == "partial", (probe, got)
        for link in links:
            assert any(link in note for note in machine_js[probe]["notes"]), (probe, link)
    else:
        assert got == want, probe


def test_tool_probes_return_valid_statuses(machine_js: dict[str, Any]) -> None:
    for probe in TOOL_PROBES:
        envelope = machine_js[probe]
        assert envelope["status"] in ("ok", "partial", "not_found"), (probe, envelope)
        assert envelope["error"] is None, (probe, envelope["error"])


def behind_reparse(path: str) -> bool:
    """The path or a folder above it is a reparse point (symbolic link, junction, app alias):
    the JScript engine cannot read link targets (FSO), so it never follows, tests or runs them."""
    current = Path(path)
    for candidate in (current, *current.parents):
        try:
            if os.lstat(candidate).st_file_attributes & 0x400:
                return True
        except OSError:
            continue
    return False


def test_tools_inventory_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    got, want = data(machine_js, "tools.inventory"), data(machine_ps, "tools.inventory")
    assert got["searched_count"] == want["searched_count"]
    lost = 0
    for tool_id, expected in want["tools"].items():
        tool = got["tools"][tool_id]
        if not expected["found"]:
            assert tool["found"] is False, tool_id
            continue
        # Paths ps finds behind a link may be missing in js (never through a link it cannot read).
        js_paths = [p.lower() for p in tool.get("paths", [])]
        ps_paths = [p.lower() for p in expected["paths"]]
        assert js_paths == [p for p in ps_paths if p in js_paths], tool_id
        assert all(behind_reparse(p) for p in ps_paths if p not in js_paths), (tool_id, js_paths, ps_paths)
        if not tool["found"]:
            lost += 1
            continue
        if tool["path"].lower() != expected["path"].lower():
            assert behind_reparse(expected["path"]), tool_id
            continue
        if tool["reason"] == "link target unknown; not run":
            # e.g. winget, an app alias ps may run: a reparse point is never run from WSH.
            assert behind_reparse(tool["path"]) and tool["executed"] is False, tool_id
            continue
        assert tool["executed"] == expected["executed"], (tool_id, tool["reason"], expected["reason"])
        assert tool["reason"] == expected["reason"], tool_id
        assert tool["version"] == expected["version"], (tool_id, tool.get("version_line"), expected.get("version_line"))
        assert tool["binary_arch"] == expected["binary_arch"], tool_id
    assert got["found_count"] == want["found_count"] - lost
    assert_status(machine_js, machine_ps, "tools.inventory")


def test_version_managers_match_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    def managers(results: dict[str, Any]) -> list[tuple[str, list[str], list[str]]]:
        return [(m["id"], [d.lower() for d in m["shim_dirs"]], m["versions"])
                for m in data(results, "runtime.version_managers")["managers"]]

    assert managers(machine_js) == managers(machine_ps)
    assert_status(machine_js, machine_ps, "runtime.version_managers")


def test_java_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    def jdks(results: dict[str, Any]) -> list[tuple[Any, ...]]:
        return [(j["path"].lower(), j["source"], j["version"], j["vendor"], j["arch"], j["is_jdk"])
                for j in data(results, "runtime.java")["jdks"]]

    assert jdks(machine_js) == jdks(machine_ps)
    for key in ("java_home", "java_home_valid"):
        assert data(machine_js, "runtime.java")[key] == data(machine_ps, "runtime.java")[key], key
    got_java, want_java = data(machine_js, "runtime.java")["path_java"], data(machine_ps, "runtime.java")["path_java"]
    if want_java and behind_reparse(want_java["path"]):
        # Behind a link folder (javapath): never listed in js; the PATH note says so.
        assert got_java is None or got_java["path"] != want_java["path"]
    else:
        assert got_java == want_java
    assert_status(machine_js, machine_ps, "runtime.java")


def test_dotnet_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    got, want = data(machine_js, "runtime.dotnet"), data(machine_ps, "runtime.dotnet")
    for key in ("framework", "framework_legacy", "sdks", "runtimes"):
        assert got[key] == want[key], key
    assert_status(machine_js, machine_ps, "runtime.dotnet")


def test_python_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    got, want = data(machine_js, "runtime.python"), data(machine_ps, "runtime.python")

    def interpreters(d: dict[str, Any]) -> list[tuple[Any, ...]]:
        return sorted((i["path"].lower(), i["source"], i["store_alias"], i["version"], i["arch"], i["not_run"])
                      for i in d["interpreters"])

    # A candidate behind a reparse point (a link) is never tested in js; Store aliases are listed as in ps.
    kept = {"interpreters": [i for i in want["interpreters"] if i["store_alias"] or not behind_reparse(i["path"])]}
    assert interpreters(got) == interpreters(kept)
    for key in ("launcher", "store_packages"):
        assert got[key] == want[key], key
    real = [i for i in want["interpreters"] if not i["store_alias"] and not i["not_run"] and behind_reparse(i["path"])]
    assert any(i["store_alias"] for i in got["interpreters"]) == any(i["store_alias"] for i in want["interpreters"])
    assert got["real_count"] == want["real_count"] - len(real)
    assert_status(machine_js, machine_ps, "runtime.python")


def test_msvc_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    got, want = data(machine_js, "toolchain.msvc"), data(machine_ps, "toolchain.msvc")
    for key in ("instances", "windows_sdks", "msbuild", "cl_on_path"):
        assert got[key] == want[key], key
    assert_status(machine_js, machine_ps, "toolchain.msvc")


def test_native_deps_match_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    got, want = data(machine_js, "native.deps"), data(machine_ps, "native.deps")
    for key in ("vcredist", "webview2", "odbc_drivers", "oracle_homes", "glibcxx_max", "libssl"):
        assert got[key] == want[key], key
    # FSO GetFileVersion gives the numeric version; .NET FileVersion may add "(WinBuild...)".
    assert got["ucrt"] and want["ucrt"].startswith(got["ucrt"])
    assert got["libc"] == {"kind": "ucrt", "version": got["ucrt"]}
    assert machine_js["native.deps"]["status"] == machine_ps["native.deps"]["status"]


# ------------------------------------------------------------------ fixture cases

@pytest.mark.parametrize("text, version", [
    ("git version 2.47.1.windows.1", "2.47.1.windows.1"),
    ('openjdk version "21.0.1" 2023-10-17', "21.0.1"),
    ("go version go1.22.0 windows/amd64", "1.22.0"),
    ("\nThis is perl 5, version 36, subversion 0 (v5.36.0)", "5.36.0"),
    ("v20.11.0", "20.11.0"),
    ("no version here", None),
    ("Picked up JAVA_TOOL_OPTIONS: -Djdk.tls.client.protocols=TLSv1.2\nPicked up _JAVA_OPTIONS: -Xmx1g -Dv=1.5\n"
     'openjdk version "17.0.2" 2022-01-18\nOpenJDK Runtime Environment (build 17.0.2+8-86)', "17.0.2"),
    ('Picked up JDK_JAVA_OPTIONS: --add-opens=java.base/x=1.2\r\njava version "1.8.0_381"', "1.8.0_381"),
    ("Picked up _JAVA_OPTIONS: -Dhttps.protocols=TLSv1.2", None),
])
def test_version_tokens(js_lib: Path, text: str, version: str | None) -> None:  # noqa: F811
    assert run_snippet(js_lib, f"tOut(getEsVersionToken({js(text)}).version);\n") == version


def test_vswhere_text_and_framework_releases(js_lib: Path) -> None:  # noqa: F811
    text = ("instanceId: abc\r\ninstallationPath: C:\\VS\r\nisComplete: 1\r\nignored: x\r\n"
            "instanceId: def\r\ndisplayName: Build Tools\r\n")
    body = (f"tOut({{ vs: jsTools_parseVswhere({js(text)}), f: [jsTools_frameworkVersion(533325), "
            "jsTools_frameworkVersion(461808), jsTools_frameworkVersion(100), jsTools_frameworkVersion(null)] });\n")
    got = run_snippet(js_lib, body)
    assert got["vs"] == [{"instanceId": "abc", "installationPath": "C:\\VS", "isComplete": "1"},
                         {"instanceId": "def", "displayName": "Build Tools"}]
    assert got["f"] == ["4.8.1", "4.7.2", None, None]


def test_inventory_runs_real_tools_and_never_shims(js_lib: Path, tmp_path: Path) -> None:  # noqa: F811
    bin_dir = tmp_path / "bin"
    shims = tmp_path / ".pyenv" / "pyenv-win" / "shims"
    for folder in (bin_dir, shims):
        folder.mkdir(parents=True)
    (bin_dir / "node.cmd").write_bytes(b"@echo off\r\necho v20.11.0\r\n")
    (bin_dir / "deno.ps1").write_bytes(b"Write-Output 'deno 1.0.0'\r\n")
    (shims / "python.bat").write_bytes(b"@echo off\r\necho Python 3.12.0\r\n")
    snapshot = {"Path": f"{bin_dir};{shims}", "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                "SystemRoot": os.environ.get("SystemRoot", "C:\\Windows")}
    body = f"""tSnap({js(snapshot)});
var r = newEsResult();
var out = {{}};
for (var i = 0; i < ES_TOOLS.length; i++) {{
    if (!esContains(["node", "deno", "python"], ES_TOOLS[i].id)) {{ continue; }}
    // Only PATH (the spec's extra folders would find this machine's real Python).
    var row = {{ id: ES_TOOLS[i].id, name: ES_TOOLS[i].name, cat: ES_TOOLS[i].cat, exe: ES_TOOLS[i].exe, args: ES_TOOLS[i].args, mode: ES_TOOLS[i].mode, dirs: [] }};
    out[row.id] = getEsToolRecord(r, row);
}}
tOut(out);
"""
    tools = run_snippet(js_lib, body)
    assert tools["node"]["executed"] is True and tools["node"]["version"] == "20.11.0"
    assert tools["node"]["path"] == str(bin_dir / "node.cmd") and tools["node"]["on_path"] is True
    assert tools["deno"]["executed"] is False and "PowerShell script shim" in tools["deno"]["reason"]
    assert tools["python"]["executed"] is False and "version-manager shim (pyenv)" in tools["python"]["reason"]
    assert json.dumps(tools).count("3.12.0") == 0


# ------------------------------------------------------------------ links, Store aliases, planted keys

def make_junction(target: Path, link: Path) -> None:
    import _winapi  # Windows only (the module needs cscript)

    _winapi.CreateJunction(str(target), str(link))


def link_note(link: Path) -> str:
    return f"PATH folder {link} is a link whose target cannot be read in the WSH port; tools in it were not checked"


@pytest.fixture()
def link_path(tmp_path: Path) -> Path:
    real = tmp_path / "javapath_target"
    real.mkdir()
    (real / "node.cmd").write_bytes(b"@echo off\r\necho v20.11.0\r\n")
    (real / "java.exe").write_text("x")
    link = tmp_path / "javapath"
    make_junction(real, link)
    return link


def test_tools_in_a_linked_path_folder_are_not_checked_and_the_gap_is_noted(js_lib: Path, link_path: Path) -> None:  # noqa: F811
    snapshot = {"Path": str(link_path), "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                "SystemRoot": os.environ.get("SystemRoot", "C:\\Windows")}
    body = f"""tSnap({js(snapshot)});
ES_TOOLS = [{{ id: "node", name: "Node.js", cat: "runtime", exe: ["node"], args: ["--version"], mode: "version", dirs: [] }}];
var r = probe_tools_inventory();
tOut({{ node: r.data.tools.node, status: r.status, notes: r.notes, link_dirs: r.data.link_dirs }});
"""
    got = run_snippet(js_lib, body)
    assert got["node"] == {"name": "Node.js", "cat": "runtime", "found": False}
    assert got["status"] == "partial"
    assert got["notes"] == [link_note(link_path)]
    assert got["link_dirs"] == [str(link_path)]


def test_java_behind_a_linked_path_folder_is_unknown_not_invented(js_lib: Path, link_path: Path) -> None:  # noqa: F811
    tool = {"name": "Java", "cat": "runtime", "found": False}
    body = f"""tSnap({js({"Path": str(link_path)})});
ES_RESULTS["tools.inventory"] = {{ status: "partial", data: {{ tools: {{ java: {js(tool)} }} }} }};
var r = probe_runtime_java();
tOut({{ path_java: r.data.path_java, notes: r.notes, status: r.status }});
"""
    got = run_snippet(js_lib, body)
    assert got["path_java"] is None
    assert link_note(link_path) in got["notes"]
    assert got["status"] == "partial"


STORE_PYTHON = Path(os.environ.get("LOCALAPPDATA", r"C:\nowhere")) / "Microsoft" / "WindowsApps" / "python.exe"


@pytest.mark.skipif(not os.path.lexists(STORE_PYTHON), reason="no Microsoft Store python alias on this machine")
def test_store_python_alias_is_listed_and_never_run(js_lib: Path) -> None:  # noqa: F811
    snapshot = {"Path": str(STORE_PYTHON.parent), "PATHEXT": ".COM;.EXE;.BAT;.CMD"}
    body = f"""tSnap({js(snapshot)});
var r = newEsResult();
var seen = {{}};
var m = findEsExecutable(["python", "python3"], []);
for (var i = 0; i < m.length; i++) {{ addEsPythonCandidate(seen, m[i].path, "PATH"); }}
var out = [];
var keys = esKeys(seen);
for (var k = 0; k < keys.length; k++) {{ out.push(jsTools_pythonEntry(r, seen[keys[k]], {{ runs: 0 }})); }}
tOut(out);
"""
    entries = run_snippet(js_lib, body)
    alias = [e for e in entries if e["path"].lower() == str(STORE_PYTHON).lower()]
    assert alias, entries
    assert alias[0]["store_alias"] is True and alias[0]["source"] == "PATH" and alias[0]["version"] is None
    assert alias[0]["not_run"] == "app execution alias (WindowsApps); not run"


def test_planted_has_own_property_keys_do_not_throw(js_lib: Path) -> None:  # noqa: F811
    body = """tSnap({});
var values = { hasOwnProperty: "x", Installed: "1" };
ES_RESULTS["tools.inventory"] = { status: "ok", data: { tools: { hasOwnProperty: "x", git: { found: true } } } };
var homes = { hasOwnProperty: "x" };
addEsJavaHome(homes, "C:\\\\nowhere-java", "test");
var seen = { hasOwnProperty: "x" };
addEsPythonCandidate(seen, "C:\\\\nowhere\\\\python.exe", "test");
tOut({ v: jsTools_valueI(values, "installed"), git: getEsTool("git").found, none: getEsTool("ruby") });
"""
    assert run_snippet(js_lib, body) == {"v": "1", "git": True, "none": None}
