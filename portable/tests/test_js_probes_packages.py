"""envscan.js (JScript) package probes and git configuration: pkg.sources, pkg.caches,
pkg.installed, pkg.features (src/js/23-git-config.js, src/js/23-probes-packages.js).

Two kinds of tests:
- this machine: each probe runs in envscan.js and in the envscan.ps1 library (same scrubbed
  environment) and the facts must agree (config files, endpoints, git entries, caches, counts);
- fixtures: the git cases of tests/ps/hardening_cases.ps1 and tests/ps/link_cases.ps1, ported:
  stub git.cmd programs, a fake environment snapshot, faked links and network drives.
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from conftest import HAVE_POWERSHELL, ps_command, ps_quote, requires_powershell, scrubbed_env
from js_harness import HAVE_CSCRIPT, build_js, run_js

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

PKG_PROBES = ("pkg.sources", "pkg.caches", "pkg.installed", "pkg.features")

# After esInitForTests (snapshot, redaction, temp folder; worker hand-over), test helpers:
# tSnap replaces the environment snapshot (as the ps cases set ES_ENV_SNAPSHOT) and the PATH
# caches; tRun runs one probe through the runner (envelope: redacted, as in the report).
JS_PRELUDE = r"""
ES_STARTED = getEsUtc();
function tSnap(o) {
    ES_ENV_SNAPSHOT = {}; ES_ENV_SNAPSHOT_NAMES = {};
    for (var k in o) { if (o.hasOwnProperty(k)) { ES_ENV_SNAPSHOT[k] = o[k]; ES_ENV_SNAPSHOT_NAMES[k.toLowerCase()] = k; } }
    ES_PATH_DIRS = null; ES_PATH_INDEX = null; ES_PATH_RANK = null; ES_PATHEXT = null;
}
function tMeta(id) {
    for (var i = 0; i < ES_PROBES.length; i++) { if (ES_PROBES[i].id === id) { return ES_PROBES[i]; } }
    return { id: id, tier: "default", scope: "user", title: id };
}
function tRun(id) { return invokeEsProbe(tMeta(id)); }
function tOut(value) { WScript.Echo(convertToEsJson(value)); }
function tScan(ids) {
    var out = {};
    enterEsChildEnv();
    initializeEsDrives();
    try { for (var i = 0; i < ids.length; i++) { out[ids[i]] = tRun(ids[i]); } }
    finally { exitEsChildEnv(); }
    return out;
}
"""
JS_EPILOGUE = "\n} finally { removeEsTemp(); }\n"

PS_SCAN = (
    "$script:ES_STARTED = Get-EsUtc; Initialize-EsRedaction; Save-EsEnvSnapshot; Initialize-EsTemp; "
    "Enter-EsChildEnv; Initialize-EsDrives; $out = @{{}}; "
    "foreach ($id in @({ids})) {{ $meta = @($script:ES_PROBES | Where-Object {{ $_.id -eq $id }})[0]; "
    "$out[$id] = Invoke-EsProbe $meta }}; Exit-EsChildEnv; Remove-EsTemp; ConvertTo-EsJson $out"
)


def js(value: Any) -> str:
    """A JScript literal (JSON is valid ES3 for these values; non-ASCII as \\u escapes)."""
    return json.dumps(value)


@pytest.fixture(scope="session")
def js_lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    _, lib = build_js(tmp_path_factory.mktemp("jsprobes-b"))
    return lib


def run_snippet(lib: Path, body: str, env: Mapping[str, str] | None = None, timeout: int = 600) -> Any:
    """Run body after the prelude; body prints one JSON value with tOut()."""
    # esInitForTests first: a snippet started again as a WMI worker must hand over to the
    # worker code before anything else runs (otherwise every worker would start the snippet).
    dist = lib.parents[2] / "dist" / "envscan.js"
    init = f"esInitForTests({js(str(dist))});\n"
    proc = run_js(lib, init + JS_PRELUDE + "try {\n" + body + JS_EPILOGUE, env=dict(env) if env is not None else scrubbed_env(),
                  timeout=timeout)
    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert lines, proc.stderr
    return json.loads("\n".join(lines))


def js_scan(lib: Path, ids: Sequence[str]) -> dict[str, Any]:
    return run_snippet(lib, f"tOut(tScan({js(list(ids))}));\n")


def ps_scan(built: Path, ids: Sequence[str]) -> dict[str, Any]:
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    quoted = ", ".join(ps_quote(i) for i in ids)
    proc = ps_command(f". {ps_quote(lib)}; " + PS_SCAN.format(ids=quoted), timeout=900)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


# ------------------------------------------------------------------ this machine: js against ps

@pytest.fixture(scope="module")
def machine_js(js_lib: Path) -> dict[str, Any]:
    return js_scan(js_lib, PKG_PROBES)


@pytest.fixture(scope="module")
def machine_ps(built: Path) -> dict[str, Any]:
    if not HAVE_POWERSHELL:
        pytest.skip("needs Windows PowerShell")
    return ps_scan(built, PKG_PROBES)


def test_pkg_probes_return_valid_statuses(machine_js: dict[str, Any]) -> None:
    for probe in PKG_PROBES:
        envelope = machine_js[probe]
        assert envelope["status"] in ("ok", "partial", "not_found"), (probe, envelope)
        assert envelope["error"] is None, (probe, envelope["error"])


@requires_powershell
def test_pkg_sources_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    got, want = machine_js["pkg.sources"]["data"], machine_ps["pkg.sources"]["data"]
    assert machine_js["pkg.sources"]["status"] == machine_ps["pkg.sources"]["status"], machine_js["pkg.sources"]["notes"]
    assert [(c["id"], c["path"].lower()) for c in got["configs"]] == [(c["id"], c["path"].lower()) for c in want["configs"]]
    assert [c["urls"] for c in got["configs"]] == [c["urls"] for c in want["configs"]]
    assert got["endpoints"] == want["endpoints"]
    assert got["env"] == want["env"]
    items = lambda data: sorted((i["origin"], i["key"], i["value"]) for i in data["git_config"])  # noqa: E731
    assert items(got) == items(want)
    assert got["proxy_urls"] == want["proxy_urls"]
    assert got["config_count"] == want["config_count"]


@requires_powershell
def test_pkg_caches_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    def caches(envelope: dict[str, Any]) -> list[tuple[str, str, int]]:
        return [(c["id"], c["path"].lower(), c["entries"]) for c in envelope["data"]["caches"]]

    assert machine_js["pkg.caches"]["status"] == machine_ps["pkg.caches"]["status"]
    assert caches(machine_js["pkg.caches"]) == caches(machine_ps["pkg.caches"])


@requires_powershell
def test_pkg_installed_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    got, want = machine_js["pkg.installed"]["data"], machine_ps["pkg.installed"]["data"]
    counts = {m["name"]: m["count"] for m in got["managers"]}
    expected = {m["name"]: m["count"] for m in want["managers"]}
    # Store (Appx) packages have no WSH source: unknown, never 0, and the probe says so.
    assert counts.pop("appx") is None
    expected.pop("appx")
    assert counts == expected
    assert machine_js["pkg.installed"]["status"] == "partial"
    assert any("Appx" in note for note in machine_js["pkg.installed"]["notes"])
    # The engine reads registry strings with RegRead, which ends a value at an embedded NUL
    # (PowerShell keeps "name\x00 "): compare up to the first NUL.
    def names(data: dict[str, Any]) -> list[tuple[str, str, str]]:
        cut = lambda text: (text or "").split("\x00")[0]  # noqa: E731
        return sorted((cut(p["name"]), p["source"], cut(p["version"])) for p in data["packages"] if p["source"] != "appx")

    assert names(got) == names(want)


@requires_powershell
def test_pkg_features_matches_powershell(machine_js: dict[str, Any], machine_ps: dict[str, Any]) -> None:
    got, want = machine_js["pkg.features"], machine_ps["pkg.features"]
    assert got["status"] == want["status"]
    assert sorted(got["data"]["enabled"]) == sorted(want["data"]["enabled"])
    assert got["data"]["powershell_v2_engine"] == want["data"]["powershell_v2_engine"]


# ------------------------------------------------------------------ git: pure helpers

def test_git_quoted_paths_are_decoded(js_lib: Path) -> None:
    body = r"""tOut({
        plain: convertFromEsGitQuoted('C:/Users/u/.gitconfig'),
        escapes: convertFromEsGitQuoted('"C:\\\\a\\tb\\"c\\""'),
        utf8: convertFromEsGitQuoted('"q\\303\\266\\360\\237\\230\\200/x"'),
        origin: getEsGitOriginFile('file:"C:/Users/J\\303\\266rg/.gitconfig"'),
        origin_plain: getEsGitOriginFile('file:C:/Program Files/Git/etc/gitconfig'),
        command_line: getEsGitOriginFile('command line:'),
        bad_utf8: convertFromEsGitQuoted('"q\\377x"'),
        unterminated: convertFromEsGitQuoted('"abc'),
        dangling: convertFromEsGitQuoted('"abc\\"'),
        unknown_escape: convertFromEsGitQuoted('"a\\qb"'),
        upper_escape: convertFromEsGitQuoted('"a\\Tb"'),
        origin_bad: getEsGitOriginFile('file:"C:/x/\\377/.gitconfig"')
    });
"""
    assert run_snippet(js_lib, body) == {
        "plain": "C:/Users/u/.gitconfig",
        "escapes": 'C:\\a\tb"c"',
        "utf8": "q\u00f6\U0001F600/x",
        "origin": "C:\\Users\\J\u00f6rg\\.gitconfig",
        "origin_plain": "C:\\Program Files\\Git\\etc\\gitconfig",
        "command_line": None,
        "bad_utf8": None,
        "unterminated": None,
        "dangling": None,
        "unknown_escape": None,
        "upper_escape": None,
        "origin_bad": None,
    }


def test_git_include_paths_resolve_like_git(js_lib: Path) -> None:
    body = r"""var o = 'C:\\cfg\\.gitconfig';
tOut({
    relative: resolveEsGitIncludePath('sub/x.cfg', o, 'C:\\home'),
    parent: resolveEsGitIncludePath('../x.cfg', o, 'C:\\home'),
    tilde: resolveEsGitIncludePath('~/x.cfg', o, 'C:/home/'),
    tilde_unset: resolveEsGitIncludePath('~/x.cfg', o, ''),
    tilde_user: resolveEsGitIncludePath('~bob/x.cfg', o, 'C:\\home'),
    absolute: resolveEsGitIncludePath('D:/x.cfg', o, 'C:\\home'),
    unc: resolveEsGitIncludePath('//srv/share/x.cfg', o, 'C:\\home'),
    device: resolveEsGitIncludePath('//?/C:/x.cfg', o, 'C:\\home'),
    root_relative: resolveEsGitIncludePath('/etc/x.cfg', o, 'C:\\home'),
    drive_relative: resolveEsGitIncludePath('C:x.cfg', o, 'C:\\home'),
    prefix: resolveEsGitIncludePath('%(prefix)/etc/x.cfg', o, 'C:\\home'),
    no_origin: resolveEsGitIncludePath('x.cfg', '', 'C:\\home')
});
"""
    assert run_snippet(js_lib, body) == {
        "relative": "C:\\cfg\\sub\\x.cfg", "parent": "C:\\cfg\\..\\x.cfg", "tilde": "C:\\home\\x.cfg",
        "tilde_unset": None, "tilde_user": None, "absolute": "D:\\x.cfg", "unc": "\\\\srv\\share\\x.cfg",
        "device": None, "root_relative": None, "drive_relative": None, "prefix": None, "no_origin": None,
    }


def test_git_home_follows_git_for_windows(js_lib: Path, tmp_path: Path) -> None:
    drive, no_drive = str(tmp_path)[:2], str(tmp_path)[2:]
    body = f"""ES_NETWORK_DRIVES = ["H:"];
var out = {{}};
tSnap({{HOMEDRIVE: "H:", HOMEPATH: "\\\\", USERPROFILE: "C:\\\\Users\\\\u"}}); out.network = getEsGitHome();
tSnap({{HOME: "C:\\\\Users\\\\u", HOMEDRIVE: "H:", HOMEPATH: "\\\\"}}); out.explicit = getEsGitHome();
tSnap({{USERPROFILE: "C:\\\\Users\\\\u"}}); out.profile = getEsGitHome();
tSnap({{HOMEDRIVE: {js(os.environ.get("SystemDrive", "C:"))}, HOMEPATH: "\\\\envscan-no-such-home", USERPROFILE: "C:\\\\Users\\\\u"}});
out.missing_local = getEsGitHome();
tSnap({{HOMEDRIVE: {js(drive)}, HOMEPATH: {js(no_drive)}, USERPROFILE: "C:\\\\Users\\\\u"}}); out.existing_local = getEsGitHome();
tOut(out);
"""
    homes = run_snippet(js_lib, body)
    assert homes == {"network": "H:\\", "explicit": "C:\\Users\\u", "profile": "C:\\Users\\u",
                     "missing_local": "C:\\Users\\u", "existing_local": str(tmp_path)}


LINK_CASES = (("home", "C:\\Users\\u"), ("gitconfig", "C:\\Users\\u\\.gitconfig"), ("xdg", "C:\\Users\\u\\.config\\git"),
              ("programdata", "C:\\ProgramData\\Git"), ("clean", "C:\\nothing"), ("unc_programdata", "C:\\nothing"))


@pytest.fixture(scope="module")
def link_locations(js_lib: Path) -> dict[str, Any]:
    # getEsPathLinkReason is faked (a global function may be replaced in JScript).
    body = f"""var tLinked = "";
getEsPathLinkReason = function (path) {{
    return String(path).toLowerCase().indexOf(tLinked.toLowerCase()) === 0 ? "link to a network path" : null;
}};
var out = {{ local: esJoinPath(ES_TMP, "githome") }};
var cases = {js([list(c) for c in LINK_CASES])};
for (var i = 0; i < cases.length; i++) {{
    tSnap({{ HOME: "C:\\\\Users\\\\u", ProgramData: cases[i][0] === "unc_programdata" ? "\\\\\\\\srv\\\\pd" : "C:\\\\ProgramData" }});
    tLinked = cases[i][1];
    var r = newEsResult();
    var env = getEsGitChildEnv(r);
    delete env["GIT_CEILING_DIRECTORIES"];
    out[cases[i][0]] = {{ env: env, status: r.status, notes: r.notes }};
}}
tOut(out);
"""
    return run_snippet(js_lib, body)


@pytest.mark.parametrize("name, variable, path, scope", [
    ("home", "HOME", "C:\\Users\\u", "global"),
    ("gitconfig", "HOME", "C:\\Users\\u\\.gitconfig", "global"),
    ("xdg", "XDG_CONFIG_HOME", "C:\\Users\\u\\.config\\git", "global"),
])
def test_git_locations_behind_links_are_replaced_like_network_ones(link_locations: dict[str, Any], name: str,
                                                                   variable: str, path: str, scope: str) -> None:
    got = link_locations[name]
    assert got["env"] == {variable: link_locations["local"]}
    assert got["status"] == "partial"
    assert len(got["notes"]) == 1 and path in got["notes"][0] and "link to a network path" in got["notes"][0]
    assert f"{scope} git configuration" in got["notes"][0]


@pytest.mark.parametrize("name", ["programdata", "unc_programdata"])
def test_git_system_scope_is_off_when_programdata_is_not_local(link_locations: dict[str, Any], name: str) -> None:
    got = link_locations[name]
    assert got["env"] == {"GIT_CONFIG_NOSYSTEM": "1"}
    assert got["status"] == "partial"
    assert len(got["notes"]) == 1 and "ProgramData" in got["notes"][0] and "system git configuration" in got["notes"][0]


def test_git_locations_without_links_are_kept(link_locations: dict[str, Any]) -> None:
    got = link_locations["clean"]
    assert (got["env"], got["status"], got["notes"]) == ({}, "ok", [])


# ------------------------------------------------------------------ git: stub programs

def git_stub(root: Path, name: str, lines: Sequence[str]) -> Path:
    folder = root / name
    folder.mkdir()
    (folder / "git.cmd").write_bytes(("\r\n".join(["@echo off", *lines]) + "\r\n").encode("ascii"))
    return folder


@pytest.fixture(scope="module")
def git_tree(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """The stub gits and include files of tests/ps/hardening_cases.ps1 (cases 14 and 20)."""
    root = tmp_path_factory.mktemp("jsgit")
    cfg, home = root / "gitcfg", root / "githome-inc"
    quoted = cfg / "q\u00f6"
    for folder in (cfg, home, quoted, home / ".ssh", cfg / "subdir"):
        folder.mkdir(parents=True)
    for file in (cfg / "inc.gitconfig", cfg / "locked.gitconfig", home / "home.gitconfig", quoted / "q.gitconfig",
                 home / ".ssh" / "config", home / ".git-credentials", home / "team.gitconfig"):
        file.write_text("", encoding="ascii")
    origin = "file:" + str(cfg).replace("\\", "/") + "/.gitconfig"
    stubs = {"root": root, "cfg": cfg, "home": home}
    stubs["fake"] = git_stub(root, "fakegit", [
        "echo file:x\tcore.home=%HOME%",
        "echo file:x\thttp.proxy=http://gp:GitPw9@gitproxy.corp:3128",
        "echo file:x\turl.https://gu:GitPw8@git.corp.example/.insteadof=https://github.com/"])
    stubs["inc"] = git_stub(root, "gitinc", [
        'if "%5"=="--file" goto included',
        f"echo {origin}\tuser.name=tester",
        f"echo {origin}\tinclude.path=inc.gitconfig",
        f"echo {origin}\tinclude.path=~/home.gitconfig",
        f"echo {origin}\tinclude.path=//envscan-test-server/share/team.gitconfig",
        f"echo {origin}\tinclude.path=/etc/gitconfig-extra",
        f"echo {origin}\tinclude.path=locked.gitconfig",
        f"echo {origin}\tinclude.path=absent.gitconfig",
        f"echo {origin}\tinclude.path=inc.gitconfig",
        f"echo {origin}\tincludeif.gitdir:~/work/.path=~/work.gitconfig",
        f"echo {origin}\tincludeif.hasconfig:remote.*.url:https://ci:HasPw55@git.corp.example/**.path=~/hc.gitconfig",
        'echo file:"' + str(cfg).replace("\\", "/") + '/q\\303\\266/.gitconfig"\tinclude.path=q.gitconfig',
        "echo command line:\tinclude.path=cl.gitconfig",
        "exit /b 0",
        ":included",
        'if /i "%~nx6"=="inc.gitconfig" goto inc',
        'if /i "%~nx6"=="home.gitconfig" goto home',
        'if /i "%~nx6"=="q.gitconfig" goto quoted',
        "echo fatal: unable to read config file %6 1>&2", "exit /b 128",
        ":inc",
        "echo file:x\thttp.proxy=http://ip:IncPw7@incproxy.corp:3128",
        "echo file:x\tinclude.path=nested.gitconfig",
        "echo file:x\tincludeif.onbranch:main.path=nested2.gitconfig",
        "exit /b 0",
        ":home", "echo file:x\tcore.fromhome=yes", "exit /b 0",
        ":quoted", "echo file:x\tcore.fromquoted=yes", "exit /b 0"])
    stubs["cond"] = git_stub(root, "gitcond", [f"echo {origin}\tincludeif.gitdir:~/work/.path=~/work.gitconfig"])
    stubs["old"] = git_stub(root, "gitold", [
        'set "ARGS=%*"', 'if not "%ARGS:--no-includes=%"=="%ARGS%" goto reject',
        "echo file:x\tcore.editor=vim", f"echo file:x\tinclude.path={str(home).replace(chr(92), '/')}/home.gitconfig",
        "echo file:x\tincludeif.gitdir:~/work/.path=~/work.gitconfig", "exit /b 0",
        ":reject", "echo error: unknown option `no-includes' 1>&2", "echo usage: git config [options] 1>&2",
        "exit /b 129"])
    stubs["ancient"] = git_stub(root, "gitancient", [
        'set "ARGS=%*"', 'if not "%ARGS:--show-origin=%"=="%ARGS%" goto origin',
        'if not "%ARGS:--no-includes=%"=="%ARGS%" goto includes', "echo core.editor=vim", "exit /b 0",
        ":origin", "echo error: unknown option `show-origin' 1>&2", "exit /b 129",
        ":includes", "echo error: unknown option `no-includes' 1>&2", "exit /b 129"])
    stubs["fail"] = git_stub(root, "gitfail", [
        "echo fatal: bad config line 1 in file C:/x/.gitconfig 1>&2", "exit /b 128"])
    stubs["guard"] = git_stub(root, "gitguard", [
        'if "%5"=="--file" goto included',
        f"echo {origin}\tinclude.path=~/.ssh/config",
        f"echo {origin}\tinclude.path=~/.git-credentials",
        f"echo {origin}\tinclude.path=NUL",
        f"echo {origin}\tinclude.path=con.gitconfig",
        f"echo {origin}\tinclude.path=subdir",
        f"echo {origin}\tinclude.path=~/team.gitconfig",
        'echo file:"' + str(cfg).replace("\\", "/") + '/\\377/.gitconfig"\tinclude.path=x.gitconfig',
        "exit /b 0",
        ":included", "echo file:x\tcore.fromteam=yes", "exit /b 0"])
    return stubs


# The git part of pkg.sources as a probe (the envelope is redacted like the report), with a
# spy on the path tests of the engine (esIsFile, esIsDir, esPathExists).
GIT_PROBE = r"""
var tTouched = [];
var tIsFile = esIsFile, tIsDir = esIsDir, tExists = esPathExists;
esIsFile = function (p) { tTouched[tTouched.length] = String(p); return tIsFile(p); };
esIsDir = function (p) { tTouched[tTouched.length] = String(p); return tIsDir(p); };
esPathExists = function (p) { tTouched[tTouched.length] = String(p); return tExists(p); };
function probe_test_gitinc() { var r = newEsResult(); r.data.git = getEsGitConfig(r); return r; }
function tGitProbe(snapshot, drives) {
    tSnap(snapshot);
    ES_NETWORK_DRIVES = drives;
    var envelope;
    try { envelope = invokeEsProbe({ id: "test.gitinc", tier: "default", scope: "user", title: "git includes" }); }
    finally { ES_NETWORK_DRIVES = []; }
    var git = envelope.data.git || { items: [], urls: [], proxy_urls: [] };
    return { status: envelope.status, notes: envelope.notes || [], sources: envelope.sources, items: git.items,
        urls: git.urls, proxy_urls: git.proxy_urls, touched: tTouched };
}
"""


def git_probe(lib: Path, stub: Path, home_vars: Mapping[str, str], drives: Sequence[str] = ()) -> dict[str, Any]:
    snapshot = {"Path": str(stub), "PATHEXT": ".CMD;.EXE", "USERPROFILE": os.environ.get("USERPROFILE", ""), **home_vars}
    return run_snippet(lib, GIT_PROBE + f"tOut(tGitProbe({js(snapshot)}, {js(list(drives))}));\n")


def include_note(reason: str, path: str) -> str:
    return f"git include not read ({reason}): {path}"


@pytest.fixture(scope="module")
def git_includes(js_lib: Path, git_tree: dict[str, Path]) -> dict[str, Any]:
    return git_probe(js_lib, git_tree["inc"], {"HOME": str(git_tree["home"])})


def test_git_endpoints_come_from_raw_values(js_lib: Path, git_tree: dict[str, Path]) -> None:
    run = git_probe(js_lib, git_tree["fake"], {"HOME": os.environ.get("USERPROFILE", "")})
    assert run["urls"] == ["http://gitproxy.corp:3128", "https://git.corp.example", "https://github.com"]
    assert [{"tool": p["tool"], "url": p["url"]} for p in run["proxy_urls"]] == [
        {"tool": "git", "url": "http://gitproxy.corp:3128"}]
    flat = json.dumps(run)
    assert "GitPw9" not in flat and "GitPw8" not in flat
    assert run["status"] == "ok", run["notes"]


def test_git_runs_with_a_local_home_when_home_is_on_the_network(js_lib: Path, git_tree: dict[str, Path]) -> None:
    run = git_probe(js_lib, git_tree["fake"], {"HOMEDRIVE": "H:", "HOMEPATH": "\\envscan-home"}, ["H:"])
    home = {i["key"]: i["value"] for i in run["items"]}["core.home"]
    assert home.lower().endswith("\\githome") and "envscan-home" not in home, home
    assert run["status"] == "partial"
    assert any("network path" in note and "global git" in note for note in run["notes"]), run


def test_git_keeps_a_local_home(js_lib: Path, git_tree: dict[str, Path]) -> None:
    profile = os.environ.get("USERPROFILE", "")
    run = git_probe(js_lib, git_tree["fake"], {"HOME": profile}, ["H:"])
    assert {i["key"]: i["value"] for i in run["items"]}["core.home"] == profile
    assert run["status"] == "ok"


def test_git_reads_local_include_files_one_level(git_includes: dict[str, Any], git_tree: dict[str, Path]) -> None:
    run = git_includes
    cfg, home = git_tree["cfg"], git_tree["home"]
    items = {(item["origin"], item["key"]): item["value"] for item in run["items"]}
    included = f"file:{cfg / 'inc.gitconfig'}"
    quoted = cfg / "q\u00f6" / "q.gitconfig"
    assert items[(included, "http.proxy")] == "http://ip:<redacted>@incproxy.corp:3128"
    assert items[(included, "include.path")] == "nested.gitconfig"
    assert items[(f"file:{home / 'home.gitconfig'}", "core.fromhome")] == "yes"
    assert items[(f"file:{quoted}", "core.fromquoted")] == "yes"
    assert "http://incproxy.corp:3128" in run["urls"]
    assert {"tool": "git", "url": "http://incproxy.corp:3128", "source": included} in run["proxy_urls"]
    runs = [source for source in run["sources"] if source.startswith("run ")]
    assert all("--no-includes" in source for source in runs), runs
    reads = [source for source in runs if " --file " in source]
    assert len(reads) == 4, reads
    assert not [source for source in reads if "absent" in source or "envscan-test-server" in source], reads


def test_git_includes_not_read_are_noted(git_includes: dict[str, Any], git_tree: dict[str, Path]) -> None:
    run = git_includes
    assert run["status"] == "partial"
    assert sorted(run["notes"]) == sorted([
        include_note("network path", "\\\\envscan-test-server\\share\\team.gitconfig"),
        include_note("not a local path", "/etc/gitconfig-extra"),
        include_note("not a local path", "cl.gitconfig"),
        include_note("unreadable", str(git_tree["cfg"] / "locked.gitconfig")),
        include_note("nested include", "nested.gitconfig"),
        include_note("condition gitdir:~/work/", "~/work.gitconfig"),
        include_note("condition onbranch:main", "nested2.gitconfig"),
        include_note("condition hasconfig:remote.*.url:https://ci:<redacted>@git.corp.example/**", "~/hc.gitconfig"),
    ])


def test_git_include_notes_and_entries_are_redacted(git_includes: dict[str, Any]) -> None:
    flat = json.dumps(git_includes)
    assert "HasPw55" not in flat and "IncPw7" not in flat
    keys = {item["key"] for item in git_includes["items"]}
    assert "includeif.hasconfig:remote.*.url:https://ci:<redacted>@git.corp.example/**.path" in keys


def test_conditional_includes_are_noted_without_changing_the_status(js_lib: Path, git_tree: dict[str, Path]) -> None:
    run = git_probe(js_lib, git_tree["cond"], {"HOME": str(git_tree["home"])})
    assert run["status"] == "ok"
    assert run["notes"] == [include_note("condition gitdir:~/work/", "~/work.gitconfig")]


def test_git_without_no_includes_runs_again_without_it(js_lib: Path, git_tree: dict[str, Path]) -> None:
    run = git_probe(js_lib, git_tree["old"], {"HOME": str(git_tree["home"])})
    assert run["status"] == "ok" and run["notes"] == [], run
    assert {"origin": "file:x", "key": "core.editor", "value": "vim"} in run["items"]
    assert len(run["items"]) == 3, run["items"]
    runs = [source for source in run["sources"] if source.startswith("run ")]
    assert len(runs) == 2, runs
    assert "--no-includes" in runs[0] and "--no-includes" not in runs[1] and "--show-origin" in runs[1]


def test_git_without_show_origin_runs_again_without_it(js_lib: Path, git_tree: dict[str, Path]) -> None:
    run = git_probe(js_lib, git_tree["ancient"], {"HOME": str(git_tree["home"])})
    assert run["status"] == "ok" and run["notes"] == [], run
    assert run["items"] == [{"origin": "", "key": "core.editor", "value": "vim"}]
    runs = [source for source in run["sources"] if source.startswith("run ")]
    assert len(runs) == 3, runs
    assert "--show-origin" not in runs[2] and "--no-includes" not in runs[2]


def test_git_include_targets_that_are_never_opened(js_lib: Path, git_tree: dict[str, Path]) -> None:
    run = git_probe(js_lib, git_tree["guard"], {"HOME": str(git_tree["home"])})
    cfg, home = git_tree["cfg"], git_tree["home"]
    assert run["status"] == "partial"
    assert sorted(run["notes"]) == sorted([
        include_note("credential store", str(home / ".ssh" / "config")),
        include_note("credential store", str(home / ".git-credentials")),
        include_note("unreadable", str(cfg / "NUL")),
        include_note("unreadable", str(cfg / "con.gitconfig")),
        include_note("unreadable", str(cfg / "subdir")),
        include_note("not a local path", "x.gitconfig"),
    ])
    reads = [source for source in run["sources"] if " --file " in source]
    assert len(reads) == 1 and "team.gitconfig" in reads[0], reads
    assert {"origin": f"file:{home / 'team.gitconfig'}", "key": "core.fromteam", "value": "yes"} in run["items"]
    touched = [p for p in run["touched"] if re.search(r"\.ssh|git-credentials|\\NUL$|con\.gitconfig", p, re.I)]
    assert touched == [], touched


def test_git_include_under_a_network_home_is_not_read(js_lib: Path, git_tree: dict[str, Path]) -> None:
    run = git_probe(js_lib, git_tree["guard"], {"HOMEDRIVE": "H:", "HOMEPATH": "\\envscan-home"}, ["H:"])
    assert run["status"] == "partial"
    assert include_note("network path", "H:\\envscan-home\\team.gitconfig") in run["notes"]
    assert include_note("credential store", "H:\\envscan-home\\.ssh\\config") in run["notes"]
    assert any(note.startswith("git home folder H:\\envscan-home is on a network path") for note in run["notes"])
    assert not [source for source in run["sources"] if " --file " in source]


def test_a_failing_git_config_makes_the_probe_partial(js_lib: Path, git_tree: dict[str, Path]) -> None:
    run = git_probe(js_lib, git_tree["fail"], {"HOME": str(git_tree["home"])})
    assert run["status"] == "partial"
    assert run["notes"] == ["git config: exit code 128: fatal: bad config line 1 in file C:/x/.gitconfig"]
    assert run["items"] == []


def test_git_child_environment_is_restored(js_lib: Path, git_tree: dict[str, Path]) -> None:
    # The overrides (HOME, GIT_CEILING_DIRECTORIES) are set for the git child only.
    body = GIT_PROBE + f"""var before = getEsEnv("GIT_CEILING_DIRECTORIES");
var run = tGitProbe({js({"Path": str(git_tree["fake"]), "PATHEXT": ".CMD;.EXE", "HOMEDRIVE": "H:",
                          "HOMEPATH": "\\envscan-home"})}, ["H:"]);
tOut({{ before: before, after: getEsEnv("GIT_CEILING_DIRECTORIES"), home: getEsEnv("HOME") }});
"""
    env = {k: v for k, v in scrubbed_env().items() if k.upper() != "HOME"}
    assert run_snippet(js_lib, body, env=env) == {"before": None, "after": None, "home": None}


# ------------------------------------------------------------------ package folders

def test_scoop_and_chocolatey_folders_are_listed(js_lib: Path, tmp_path: Path) -> None:
    choco = tmp_path / "choco"
    (choco / "lib" / "git").mkdir(parents=True)
    (choco / "lib" / "git" / "git.nuspec").write_text(
        '<?xml version="1.0"?><package><metadata><id>git</id><version>2.47.1</version></metadata></package>',
        encoding="ascii")
    scoop = tmp_path / "scoop"
    (scoop / "apps" / "jq" / "current").mkdir(parents=True)
    (scoop / "apps" / "jq" / "current" / "manifest.json").write_text('{\n  "version": "1.7.1",\n  "url": "x"\n}',
                                                                      encoding="ascii")
    body = f"""tSnap({js({"ChocolateyInstall": str(choco), "SCOOP": str(scoop)})});
var r = newEsResult();
tOut({{ choco: getEsFolderPackages(r, [esJoinPath({js(str(choco))}, "lib")], "chocolatey", "<name>.nuspec"),
        scoop: getEsFolderPackages(r, jsPkg_scoopRoots(), "scoop", "current\\\\manifest.json"), status: r.status }});
"""
    got = run_snippet(js_lib, body)
    assert got["choco"] == [{"name": "git", "version": "2.47.1", "publisher": None, "source": "chocolatey"}]
    assert got["scoop"] == [{"name": "jq", "version": "1.7.1", "publisher": None, "source": "scoop"}]
    assert got["status"] == "ok"


def test_config_file_lines_are_redacted_and_endpoints_raw(js_lib: Path, tmp_path: Path) -> None:
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text("registry=https://npm.corp.example/repository/npm/\n"
                     "//npm.corp.example/:_authToken=NpmTok123\n"
                     "# https://commented.example/\n"
                     "proxy=http://pu:ProxPw1@proxy.corp.example:8080\n", encoding="ascii")
    body = f"""var cfg = {{ id: "npmrc.user", tool: "npm", scope: "user", mode: "content", match: [], paths: [], max_bytes: 16384 }};
var e = readEsConfigFile(cfg, {js(str(npmrc))});
tOut(e);
"""
    entry = run_snippet(js_lib, body)
    assert entry["urls"] == ["https://npm.corp.example", "http://proxy.corp.example:8080"]
    assert entry["proxy_urls"] == ["http://proxy.corp.example:8080"]
    assert "//npm.corp.example/:_authToken=<redacted>" in entry["lines"]
    assert "NpmTok123" not in json.dumps(entry["lines"]) and "ProxPw1" not in json.dumps(entry["lines"])
    assert entry["error"] is None and entry["truncated"] is False
