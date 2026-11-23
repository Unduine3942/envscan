"""Proxy settings found by the name of the setting in the JScript port (src/js/15-proxy.js), with the
shared cases of tests/proxy_cases.py (build/testdata/proxy.json) that envscan.ps1 and envscan.sh pass.

A configuration case keeps the raw lines Read-EsConfigFile keeps (no comment lines outside "lines"
mode, only matching lines in "lines" mode, no blank lines) and gives them to getEsConfigProxySettings;
a git case feeds git config --list entries to addEsProxyGitLine (one origin).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from js_harness import HAVE_CSCRIPT, build_js, run_js
from shared_cases import proxy_cases

import target_js

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe")]

PH = "<redacted>"
GIT_FILE = "file:C:/h/.gitconfig"
DATA = proxy_cases()
TOOLS = {"npmrc_proxy_keys": "npm", "npmrc_registry_named_proxy": "npm", "pip_userinfo_without_scheme": "pip",
         "go_env_module_proxy": "go"}

RUNNER = r"""
function jsTestRawLines(text, entry) {
    // The raw lines Read-EsConfigFile keeps (src/ps/23-probes-packages.ps1).
    var parts = String(text).split("\n"), out = [];
    for (var i = 0; i < parts.length; i++) {
        var line = parts[i].replace(/\r+$/, "");
        if (entry.mode === "lines") {
            var hit = false;
            for (var j = 0; j < entry.match.length; j++) {
                if (line.toLowerCase().indexOf(String(entry.match[j]).toLowerCase()) >= 0) { hit = true; }
            }
            if (!hit) { continue; }
        } else if (/^[ \t]*[#;]/.test(line)) { continue; }
        if (!/^[ \t]*$/.test(line)) { out.push(line); }
    }
    return out;
}
initializeEsRedaction();
var jsOut = { config: {}, git: {}, settings: {} };
for (var jsI = 0; jsI < JS_PROXY.config.length; jsI++) {
    var jsC = JS_PROXY.config[jsI];
    var jsSettings = getEsConfigProxySettings(jsTestRawLines(jsC.text, jsC.entry));
    jsOut.config[jsC.name] = convertToEsProxyUrls(jsSettings);
    jsOut.settings[jsC.name] = convertToEsProxySettingItems(jsSettings, JS_TOOLS[jsC.name] || "tool", "C:\\cfg");
}
for (jsI = 0; jsI < JS_PROXY.git.length; jsI++) {
    var jsG = JS_PROXY.git[jsI], jsState = newEsProxyState();
    for (var jsJ = 0; jsJ < jsG.entries.length; jsJ++) { addEsProxyGitLine(jsState, jsG.entries[jsJ]); }
    var jsGit = completeEsProxySource(jsState);
    jsOut.git[jsG.name] = convertToEsProxyUrls(jsGit);
    jsOut.settings[jsG.name] = convertToEsProxySettingItems(jsGit, "git", JS_GIT_FILE);
}
jsOut.clean = [getEsProxyClean(" 'a b' x"), getEsProxyClean("v ; comment"), getEsProxyClean("v # c"), getEsProxyClean("v,")];
jsOut.endpoint = [getEsProxyEndpoint("socks5://s.corp"), getEsProxyEndpoint("https://u:p@h.corp/x"), getEsProxyEndpoint("u:p@h.corp:81")];
jsOut.urls_from_lines = getEsConfigProxyUrls(["proxy=http://a.corp:1", "https-proxy=http://a.corp:1"]);
WScript.Echo(convertToEsJson(jsOut));
"""


@pytest.fixture(scope="module")
def results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    lib = build_js(tmp_path_factory.mktemp("js-proxy"))[1]
    head = (f"var JS_PROXY = {target_js.js_literal(DATA)};\nvar JS_TOOLS = {target_js.js_literal(TOOLS)};\n"
            f"var JS_GIT_FILE = {target_js.js_literal(GIT_FILE)};\n")
    proc = run_js(lib, head + RUNNER)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def test_cases_fit_their_byte_caps() -> None:
    # The byte cap of Read-EsConfigFile never cuts these files, so the raw lines above are complete.
    assert all(len(c["text"]) < c["entry"]["max_bytes"] for c in DATA["config"])
    assert len(DATA["config"]) >= 20 and len(DATA["git"]) >= 4


@pytest.mark.parametrize("case", DATA["config"], ids=[c["name"] for c in DATA["config"]])
def test_config_proxy_urls(results: dict[str, Any], case: dict[str, Any]) -> None:
    assert results["config"][case["name"]] == case["expected"]


@pytest.mark.parametrize("case", DATA["git"], ids=[c["name"] for c in DATA["git"]])
def test_git_proxy_urls(results: dict[str, Any], case: dict[str, Any]) -> None:
    assert results["git"][case["name"]] == case["expected"]


def test_proxy_urls_never_hold_credentials(results: dict[str, Any]) -> None:
    flat = json.dumps({"config": results["config"], "git": results["git"]})
    for secret in ("S3cret", "Gem5ecret", "bob", "gemuser", "user:", "@"):
        assert secret not in flat


def settings(results: dict[str, Any], name: str) -> list[tuple[str, str, str]]:
    return [(s["tool"], s["setting"], s["value"]) for s in results["settings"][name]]


def test_net_proxy_lists_settings_by_name_not_lines(results: dict[str, Any]) -> None:
    # The same expectations as tests/test_ps_proxy.py.
    assert settings(results, "npmrc_proxy_keys") == [
        ("npm", "https-proxy", f"http://bob:{PH}@proxy.corp:8080/"), ("npm", "noproxy", ".corp"),
        ("npm", "proxy", "http://proxy.corp:3128")]
    assert settings(results, "npmrc_registry_named_proxy") == []
    assert settings(results, "pip_userinfo_without_scheme") == [
        ("pip", "proxy", f"bob:{PH}@pipproxy.corp:3128"), ("pip", "proxy", f"bob:{PH}@webproxy")]
    assert settings(results, "go_env_module_proxy") == []
    assert settings(results, "git_proxy_keys") == [
        ("git", "http.proxy", "http://gitproxy.corp:3128"),
        ("git", "http.https://internal.corp/.proxy", f"http://user:{PH}@scoped.corp:8080"),
        ("git", "http.proxyauthmethod", "basic"), ("git", "remote.origin.proxy", "socks5://sockproxy.corp")]
    assert {s["file"] for s in results["settings"]["git_proxy_keys"]} == {GIT_FILE}
    for name, items in results["settings"].items():
        for item in items:
            assert set(item) == {"tool", "setting", "value", "file"}, (name, item)


def test_net_proxy_settings_never_hold_secrets(results: dict[str, Any]) -> None:
    flat = json.dumps(results["settings"])
    for secret in ("S3cret", "Gem5ecret", ":pw@", "proxy_password", "proxyPassword", "http_proxy.password"):
        assert secret not in flat, secret


def test_helpers(results: dict[str, Any]) -> None:
    assert results["clean"] == ["a b", "v", "v", "v"]
    assert results["endpoint"] == ["s.corp:1080", "h.corp:443", "h.corp:81"]
    assert results["urls_from_lines"] == ["http://a.corp:1"]
