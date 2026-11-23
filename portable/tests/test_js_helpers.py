"""envscan.js shared helpers (src/js/13-helpers.js).

The pure helpers (endpoints, URLs, net-never, SDDL rights, UTF-8 decoding) are compared with the
PowerShell originals on the same inputs. The PATH resolver is checked with the cases of
tests/ps/unit_cases.ps1: PATH and PATHEXT order, network and relative entries dropped, and the
never-run rules (version-manager shims, App Execution Aliases, WSL launchers, .ps1 shims).
The token and ACL helpers have no JScript API: they must report unknown, never a guess.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from conftest import ps_command, ps_quote, requires_powershell
from js_harness import HAVE_CSCRIPT, build_js, run_js
from target_js import js_string

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows Script Host)"),
]

LIB_PREFIXES = ("00-", "10-", "11", "12-", "13-", "14-", "15-")

ENDPOINTS = [
    "http://user:pw@proxy.corp:3128", "https://repo.corp/maven", "proxy:8080", "http://[fd00::1]:8080/x",
    "http://169.254.169.254/latest", "metadata.google.internal", "http://metadata.google.internal./x",
    "http://proxy.corp.:3128", "socks5://s.corp", "foo://x.corp", "foo://x.corp:99", "localhost:80",
    "  'http://Q.CORP:0/' ", "fd00::2", "/path/only", "http://a@b@c.corp:1/", "", "http://[::1]:5",
]
URL_TEXTS = [
    "registry=https://npm.corp.example/repository/npm/\nhttps://Npm.Corp.Example/again",
    "# https://commented.example/\n; https://also.example\n  // https://js.example\nREM http://rem.example",
    '<project xmlns="http://maven.apache.org/POM/4.0.0" xsi:schemaLocation="http://x.example/a.xsd">'
    "<url>https://repo.corp/x</url></project>",
    "credential.https://cred.example.helper=x and xhttps://nope.example and (https://ok.example:8443/p)",
    "http://user:p@ss@host.corp:8080/path?q=1 http://host.corp.:81 http://[fd00::5]:9/ http://bad_host/",
    "http://www.w3.org/2001/XMLSchema https://maven.apache.org/xsd/settings-1.0.0.xsd https://json-schema.org/x",
    "https://a.example/?u=http://b.example/\r\nhttps://c.example:99999/",
    "",
]
NET_NEVER = ["169.254.1.1", "[fe80::1]", "Metadata.Google.Internal.", "metadata", "metadata2", "fd00:ec2::254",
             "10.0.0.1", " instance-data ", ""]
SDDL_RIGHTS = ["0x1200a9/2", "0x1301bf/2", "FA/2", "LC/4", "LC/2", "DC/2", "GR/2", "0x10000000/4", "SDGXGWGR/2",
               "0x40000000/2", "fw/2"]
UTF8 = [[0x63, 0x61, 0x66, 0xC3, 0xA9], [0xE6, 0x97, 0xA5], [0xF0, 0x9F, 0x98, 0x80], [0xC3], [0xFF, 0x41],
        [0xE6, 0x41], [0xF4, 0x90, 0x80, 0x80], []]

# A JScript JSON printer for the snippets, so these tests do not depend on the engine's writer.
JS_JSON = r"""
function T_json(v) {
    if (v === null || v === undefined) { return "null"; }
    if (typeof v === "boolean" || typeof v === "number") { return String(v); }
    if (typeof v === "string") {
        var out = "";
        for (var i = 0; i < v.length; i++) {
            var c = v.charCodeAt(i);
            out += (c < 32 || c > 126 || c === 34 || c === 92) ? "\\u" + ("0000" + c.toString(16)).slice(-4) : v.charAt(i);
        }
        return '"' + out + '"';
    }
    var parts = [];
    if (Object.prototype.toString.call(v) === "[object Array]") {
        for (var j = 0; j < v.length; j++) { parts.push(T_json(v[j])); }
        return "[" + parts.join(",") + "]";
    }
    for (var k in v) { if (v.hasOwnProperty(k)) { parts.push(T_json(k) + ":" + T_json(v[k])); } }
    return "{" + parts.join(",") + "}";
}
"""


@pytest.fixture(scope="module")
def js_lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    _, lib = build_js(tmp_path_factory.mktemp("jshelpers"), lambda name: name.startswith(LIB_PREFIXES))
    return lib


def js_eval(lib: Path, body: str, env: dict[str, str] | None = None) -> Any:
    proc = run_js(lib, JS_JSON + "\n" + body, env=env)
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def js_array(values: list[Any]) -> str:
    return "[" + ", ".join(js_string(v) if isinstance(v, str) else json.dumps(v) for v in values) + "]"


def ps_array(values: list[str]) -> str:
    return "@(" + ", ".join(ps_quote(v) for v in values) + ")"


# ------------------------------------------------------------------ pure helpers vs ps

PS_PURE = r"""
$out = @{ endpoints = @{}; urls = @(); never = @{}; rights = @{}; utf8 = @() }
foreach ($v in $endpoints) {
    $e = ConvertTo-EsEndpoint $v 'src'
    if ($e) { $out.endpoints[$v] = @{ host = $e.host; port = $e.port; source = $e.source } } else { $out.endpoints[$v] = $null }
}
foreach ($t in $texts) { $out.urls += ,@(Get-EsEndpointUrls $t) }
foreach ($n in $never) { $out.never[$n] = (Test-EsNetNever $n) }
foreach ($r in $rights) { $p = $r.Split('/'); $out.rights[$r] = (Test-EsSddlRight $p[0] ([int]$p[1])) }
foreach ($b in $bytes) { $out.utf8 += ,@(@((ConvertFrom-EsUtf8Bytes $b).ToCharArray()) | ForEach-Object { [int]$_ }) }
[Console]::Out.Write((ConvertTo-EsJson $out))
"""

JS_PURE = r"""
var out = {endpoints: {}, urls: [], never: {}, rights: {}, utf8: []};
for (var i = 0; i < endpoints.length; i++) {
    var e = convertToEsEndpoint(endpoints[i], 'src');
    out.endpoints[endpoints[i]] = e ? {host: e.host, port: e.port, source: e.source} : null;
}
for (var t = 0; t < texts.length; t++) { out.urls.push(getEsEndpointUrls(texts[t])); }
for (var n = 0; n < never.length; n++) { out.never[never[n]] = testEsNetNever(never[n]); }
for (var r = 0; r < rights.length; r++) {
    var p = rights[r].split('/');
    out.rights[rights[r]] = testEsSddlRight(p[0], parseInt(p[1], 10));
}
for (var b = 0; b < bytes.length; b++) {
    var s = convertFromEsUtf8Bytes(bytes[b]);
    var codes = [];
    for (var c = 0; c < s.length; c++) { codes.push(s.charCodeAt(c)); }
    out.utf8.push(codes);
}
WScript.Echo(T_json(out));
"""


@pytest.fixture(scope="module")
def pure_js(js_lib: Path) -> dict[str, Any]:
    bytes_js = "[" + ", ".join(js_array(b) for b in UTF8) + "]"
    head = (f"var endpoints = {js_array(ENDPOINTS)}; var texts = {js_array(URL_TEXTS)}; "
            f"var never = {js_array(NET_NEVER)}; var rights = {js_array(SDDL_RIGHTS)}; var bytes = {bytes_js};")
    return js_eval(js_lib, head + JS_PURE)


@pytest.fixture(scope="module")
def pure_ps(built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    texts = "@(" + ", ".join(_ps_text(t) for t in URL_TEXTS) + ")"
    bytes_ps = "@(); " + "; ".join("$bytes += ,@(" + ", ".join(str(x) for x in b) + ")" for b in UTF8)
    script = tmp_path_factory.mktemp("pspure") / "pure.ps1"
    script.write_text("\n".join([
        f". {ps_quote(lib)}", "Initialize-EsRedaction",
        f"$endpoints = {ps_array(ENDPOINTS)}", f"$texts = {texts}", f"$never = {ps_array(NET_NEVER)}",
        f"$rights = {ps_array(SDDL_RIGHTS)}", f"$bytes = {bytes_ps}", PS_PURE]), encoding="ascii")
    proc = ps_command(f"& {ps_quote(script)}", timeout=300)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _ps_text(text: str) -> str:
    return "(" + ps_quote(text).replace("\r", "' + [char]13 + '").replace("\n", "' + [char]10 + '") + ")"


@requires_powershell
@pytest.mark.parametrize("part", ["endpoints", "urls", "never", "rights", "utf8"])
def test_pure_helpers_match_powershell(pure_js: dict[str, Any], pure_ps: dict[str, Any], part: str) -> None:
    assert pure_js[part] == pure_ps[part]


def test_endpoint_cases(pure_js: dict[str, Any]) -> None:
    eps = pure_js["endpoints"]
    assert eps["http://user:pw@proxy.corp:3128"] == {"host": "proxy.corp", "port": 3128, "source": "src"}
    assert eps["https://repo.corp/maven"]["port"] == 443
    assert eps["http://[fd00::1]:8080/x"]["host"] == "fd00::1"
    for never in ("http://169.254.169.254/latest", "metadata.google.internal", "http://metadata.google.internal./x",
                  "foo://x.corp", "localhost:80", "http://[::1]:5", ""):
        assert eps[never] is None, never
    assert eps["foo://x.corp:99"]["port"] == 99
    assert eps["socks5://s.corp"]["port"] == 1080


def test_endpoint_urls(pure_js: dict[str, Any]) -> None:
    urls = pure_js["urls"]
    assert urls[0] == ["https://npm.corp.example"]
    assert urls[1] == []
    assert urls[2] == ["https://repo.corp"]
    assert urls[3] == ["https://ok.example:8443"]
    # Matches do not overlap: the second URL is part of the first one's path.
    assert urls[6] == ["https://a.example", "https://c.example:99999"]
    assert urls[7] == []


def test_sddl_rights(pure_js: dict[str, Any]) -> None:
    expected = {"0x1200a9/2": False, "0x1301bf/2": True, "FA/2": True, "LC/4": True, "LC/2": False, "DC/2": True,
                "GR/2": False, "0x10000000/4": True, "SDGXGWGR/2": True}
    assert {k: pure_js["rights"][k] for k in expected} == expected


# ------------------------------------------------------------------ PATH resolution

@pytest.fixture(scope="module")
def path_case(js_lib: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    scratch = tmp_path_factory.mktemp("jspath")
    a, b, cargo = scratch / "a", scratch / "b", scratch / ".cargo" / "bin"
    for folder in (a, b, cargo):
        folder.mkdir(parents=True)
    for file in (a / "tool.cmd", b / "tool.exe", b / "tool3.exe", b / "only.ps1", b / "TOOL3.bat", cargo / "rustup.exe"):
        file.write_text("x")
    env = {k: v for k, v in os.environ.items() if k.upper() not in ("PATH", "PATHEXT")}
    env["Path"] = f'{a};"{b}\\";relative\\dir;\\\\server\\share;{a}\\;;C:x'
    env["PATHEXT"] = ".EXE;.CMD;bad"
    body = f"""
saveEsEnvSnapshot();
var leaf = function (p) {{ return p.substr(p.lastIndexOf("\\\\") + 1); }};
var two = function (p) {{ var d = getEsParentDir(p); return leaf(d) + "/" + leaf(p); }};
var dirs = getEsPathDirs(); var dl = []; for (var i = 0; i < dirs.length; i++) {{ dl.push(leaf(dirs[i])); }}
var f = findEsExecutable(["tool3", "tool"], []); var fl = []; var onp = [];
for (var j = 0; j < f.length; j++) {{ fl.push(two(f[j].path)); onp.push(f[j].on_path); }}
var p1 = findEsExecutable(["only"]); var pl = []; for (var k = 0; k < p1.length; k++) {{ pl.push(leaf(p1[k].path)); }}
var extra = findEsExecutable(["rustup"], [{js_string(str(cargo))}]);
var tool = {{id: "node", mode: "version"}};
var noRun = {{
  presence: getEsNoRunReason({{id: "sbt", mode: "Presence"}}, "C:\\\\x\\\\sbt.exe"),
  ps1: getEsNoRunReason(tool, "C:\\\\x\\\\node.ps1"),
  alias: getEsNoRunReason(tool, "C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Microsoft\\\\WindowsApps\\\\python.exe"),
  winget: getEsNoRunReason({{id: "winget", mode: "version"}}, "C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Microsoft\\\\WindowsApps\\\\winget.exe"),
  wsl: getEsNoRunReason({{id: "bash", mode: "version"}}, "C:\\\\WINDOWS\\\\System32\\\\Bash.exe"),
  wslhost: getEsNoRunReason({{id: "wsl", mode: "version"}}, "C:\\\\Windows\\\\Sysnative\\\\wslhost.exe"),
  shim: getEsNoRunReason({{id: "cargo", mode: "version"}}, {js_string(str(cargo / "cargo.exe"))}),
  js: getEsNoRunReason(tool, "C:\\\\x\\\\node.js"),
  plain: getEsNoRunReason(tool, "C:\\\\Program Files\\\\nodejs\\\\node.exe"),
  volta: getEsNoRunReason(tool, "C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Volta\\\\bin\\\\node.exe")
}};
WScript.Echo(T_json({{dirs: dl, find: fl, on_path: onp, ps1: pl, ext: getEsPathExt(), extra: extra.length,
  extra_on_path: extra.length ? extra[0].on_path : null, no_run: noRun,
  shim_manager: getEsShimManager({js_string(str(cargo / "cargo.exe"))}),
  no_shim_without_rustup: getEsShimManager("C:\\\\nowhere\\\\.cargo\\\\bin\\\\cargo.exe"),
  tool_path: findEsToolPath("no-such-tool")}}));
"""
    return js_eval(js_lib, body, env=env)


def test_path_dirs_drop_network_relative_and_duplicates(path_case: dict[str, Any]) -> None:
    assert path_case["dirs"] == ["a", "b"]


def test_pathext_is_lower_case_with_ps1(path_case: dict[str, Any]) -> None:
    assert path_case["ext"] == [".exe", ".cmd", ".ps1"]


def test_lookup_order_follows_path_then_pathext(path_case: dict[str, Any]) -> None:
    # tool3 first (first name), then tool: a/tool.cmd (earlier PATH dir) before b/tool.exe.
    # TOOL3.bat is not listed: .bat is not in PATHEXT here. Matching ignores case.
    assert path_case["find"] == ["b/tool3.exe", "a/tool.cmd", "b/tool.exe"]
    assert path_case["on_path"] == [True, True, True]
    assert path_case["ps1"] == ["only.ps1"]


def test_extra_dirs_are_searched_but_not_on_path(path_case: dict[str, Any]) -> None:
    assert path_case["extra"] == 1 and path_case["extra_on_path"] is False


@pytest.mark.parametrize("case, fragment", [
    ("presence", "inventory only"), ("ps1", "PowerShell script shim"), ("alias", "app execution alias"),
    ("wsl", "WSL launcher"), ("wslhost", "WSL launcher"), ("shim", "version-manager shim (rustup)"),
    ("js", "is not run"), ("volta", "version-manager shim (Volta)"),
])
def test_never_run_rules(path_case: dict[str, Any], case: str, fragment: str) -> None:
    assert fragment in path_case["no_run"][case]


def test_runnable_tools_have_no_reason(path_case: dict[str, Any]) -> None:
    assert path_case["no_run"]["plain"] is None
    assert path_case["no_run"]["winget"] is None
    assert path_case["shim_manager"] == "rustup"
    assert path_case["no_shim_without_rustup"] is None
    assert path_case["tool_path"] is None


# ------------------------------------------------------------------ environment, token and ACL

def test_env_subset_and_orig_env(js_lib: Path) -> None:
    env = dict(os.environ)
    env["ES_T_PLAIN"] = "value1"
    env["ES_T_TOKEN"] = "canary-tok-5b2d8e44"
    body = """
saveEsEnvSnapshot();
if (typeof initializeEsRedaction === 'function') { initializeEsRedaction(); }
setEsEnvValue("ES_T_PLAIN", "changed");
var sub = getEsEnvSubset(["ES_T_PLAIN", "es_t_plain", "ES_T_TOKEN", "ES_T_MISSING"]);
WScript.Echo(T_json({orig: getEsOrigEnv("es_t_plain"), none: getEsOrigEnv(""), missing: getEsOrigEnv("ES_T_MISSING"),
  sub: sub}));
"""
    out = js_eval(js_lib, body, env=env)
    assert out["orig"] == "value1" and out["none"] is None and out["missing"] is None
    assert sorted(out["sub"]) == ["ES_T_PLAIN", "ES_T_TOKEN"]
    assert out["sub"]["ES_T_PLAIN"] == "value1"
    assert "canary" not in out["sub"]["ES_T_TOKEN"]


def test_token_and_acl_helpers_report_unknown(js_lib: Path, tmp_path: Path) -> None:
    body = f"""
saveEsEnvSnapshot();
var info = getEsTokenInfo();
var sids = getEsTrusteeSids();
var acc = getEsSddlAccess({js_string(str(tmp_path))});
var rel = getEsSddlAccess("relative\\\\dir");
var thrown = null; try {{ getEsAclSddl({js_string(str(tmp_path))}); }} catch (e) {{ thrown = esErrorText(e); }}
WScript.Echo(T_json({{info: info, sids: sids, acc: acc, rel: rel, thrown: thrown, note: JSHLP_NO_TOKEN_NOTE,
  same: getEsTokenInfo() === info}}));
"""
    out = js_eval(js_lib, body)
    info = out["info"]
    assert info["is_admin"] is None and info["elevation_method"] is None
    assert info["groups_source"] == "assumed"
    assert "S-1-5-32-544" not in info["group_sids"] and "S-1-5-32-545" in info["group_sids"]
    assert info["user_sid"] is None or info["user_sid"].startswith(("S-1-5-21-", "S-1-12-1-"))
    assert "S-1-5-32-544" not in out["sids"]
    assert out["acc"]["create_files"] is None and out["acc"]["create_dirs"] is None and out["acc"]["error"]
    assert out["rel"]["error"] == "not an absolute local path"
    assert out["thrown"] and out["note"] and out["same"] is True


@pytest.mark.parametrize("sddl, sids, expected", [
    ("O:BAG:SYD:(A;OICI;0x1301bf;;;BU)", ["S-1-5-32-545"], (True, True)),
    ("O:BAG:SYD:(A;OICIIO;FA;;;BU)(A;;0x1200a9;;;BU)", ["S-1-5-32-545"], (False, False)),
    ("O:BAG:SYD:(A;;FA;;;S-1-5-21-1-2-3-1001)(D;;DC;;;S-1-5-21-1-2-3-1001)", ["S-1-5-21-1-2-3-1001"], (False, True)),
    ("O:S-1-5-21-9G:SYD:(A;;FA;;;OW)S:(AU;SA;FA;;;WD)", ["S-1-5-21-9"], (True, True)),
    ("O:BAD:(A;;LC;;;AU)", ["S-1-5-11"], (False, True)),
    ("O:BAG:SY", ["S-1-1-0"], None),
])
def test_sddl_parse(js_lib: Path, sddl: str, sids: list[str], expected: tuple[bool, bool] | None) -> None:
    out = js_eval(js_lib, f"WScript.Echo(T_json(jsHlp_sddlAccess({js_string(sddl)}, {js_array(sids)})));")
    if expected is None:
        assert out["error"] == "no DACL"
    else:
        assert (out["create_files"], out["create_dirs"]) == expected and out["error"] is None


# ------------------------------------------------------------------ PATH folders that are links

def make_junction(target: Path, link: Path) -> None:
    """A directory junction (no privilege needed), as javapath folders are links on PATH."""
    import _winapi  # Windows only; the module is skipped elsewhere (HAVE_CSCRIPT)

    _winapi.CreateJunction(str(target), str(link))


def test_path_folder_that_is_a_link_is_never_listed(js_lib: Path, tmp_path: Path) -> None:
    # FSO cannot read the target (it could be a credential store): the folder is never listed and
    # no name inside it is tested; it is kept in ES_PATH_LINK_DIRS so probes can say so.
    real, plain = tmp_path / "real", tmp_path / "plain"
    real.mkdir()
    plain.mkdir()
    (real / "javac.exe").write_text("x")
    (plain / "jq.exe").write_text("x")
    link = tmp_path / "javapath"
    make_junction(real, link)
    env = {k: v for k, v in os.environ.items() if k.upper() not in ("PATH", "PATHEXT")}
    env["Path"] = f"{link};{plain}"
    env["PATHEXT"] = ".EXE"
    body = f"""
var T_seen = [];
var T_wrap = function (fn) {{ return function (p) {{ T_seen.push(String(p)); return fn.apply(null, arguments); }}; }};
jsHlp_listNames = T_wrap(jsHlp_listNames); esIsFile = T_wrap(esIsFile); esIsDir = T_wrap(esIsDir);
esPathExists = T_wrap(esPathExists); getEsDirEntries = T_wrap(getEsDirEntries);
saveEsEnvSnapshot();
var leaf = function (p) {{ return p.substr(p.lastIndexOf("\\\\") + 1); }};
var dirs = getEsPathDirs(); var dl = []; for (var i = 0; i < dirs.length; i++) {{ dl.push(leaf(dirs[i])); }}
var f = findEsExecutable(["javac", "jq"], []);
var r = newEsResult();
addEsPathLinkNotes(r);
var below = [];
var linkLower = {js_string(str(link).lower())} + "\\\\";
for (var s = 0; s < T_seen.length; s++) {{ if (T_seen[s].toLowerCase().indexOf(linkLower) === 0) {{ below.push(T_seen[s]); }} }}
WScript.Echo(T_json({{dirs: dl, links: ES_PATH_LINK_DIRS, found: f.length, below: below, listed: T_seen.length,
  status: r.status, notes: r.notes}}));
"""
    out = js_eval(js_lib, body, env=env)
    assert out["dirs"] == ["plain"]
    assert out["links"] == [str(link)]
    assert out["found"] == 1  # jq in the plain folder only
    assert out["listed"] > 0 and out["below"] == []
    assert out["status"] == "partial"
    assert out["notes"] == [f"PATH folder {link} is a link whose target cannot be read in the WSH port; "
                            "tools in it were not checked"]


def test_planted_has_own_property_keys_do_not_throw(js_lib: Path) -> None:
    body = """
var t = {hasOwnProperty: "x", ProfileImagePath: "p1"};
var idx = {hasOwnProperty: "x", "kjq.exe": ["C:\\\\b\\\\jq.exe"]};
ES_PATH_RANK = {};
WScript.Echo(T_json({get: jsHlp_getI(t, "profileimagepath"), miss: jsHlp_getI(t, "nope"),
  match: jsHlp_pathMatches("jq", idx, [".exe"]).length}));
"""
    out = js_eval(js_lib, body)
    assert out == {"get": "p1", "miss": None, "match": 1}
