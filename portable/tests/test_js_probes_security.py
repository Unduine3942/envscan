"""envscan.js security and trust probes (src/js/22-probes-security.js, 22-probes-trust.js, 22-probes-certder.js).

Each probe runs on this machine in cscript and in Windows PowerShell; the facts must be equal.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import ps_command, ps_quote, requires_powershell, scrubbed_env

import js_harness

pytestmark = [pytest.mark.integration, requires_powershell,
              pytest.mark.skipif(not js_harness.HAVE_CSCRIPT, reason="needs cscript.exe")]

PROBES = ("os.identity", "sec.app_control", "sec.crypto", "sec.av", "tls.trust")
JS_INIT = "initializeEsRedaction(); saveEsEnvSnapshot(); initializeEsTemp(); initializeEsDrives();"
PS_INIT = "Initialize-EsRedaction; Save-EsEnvSnapshot; Initialize-EsDrives"
# Until the engine provides getEsRegBinary (all bytes of a REG_BINARY value; getEsRegValue keeps 256),
# a test stand-in reads the value with RegRead. The engine's own function wins when it exists.
REG_BINARY_STANDIN = (
    'if (typeof getEsRegBinary !== "function") { getEsRegBinary = function (path, name) {'
    ' var s = esRegSplit(path); try { return new VBArray(ES_SHELL.RegRead(s.shell + "\\\\" + name)).toArray(); }'
    ' catch (e) { return null; } }; }')


def js_snippet(ids: tuple[str, ...], lib: Path) -> str:
    worker = str(lib.parents[2] / "dist" / "envscan.js").replace("\\", "\\\\")
    calls = "\n".join(f'out["{pid}"] = probe_{pid.replace(".", "_")}();' for pid in ids)
    head = f'ES_WORKER_SCRIPT = "{worker}";'
    return "\n".join([REG_BINARY_STANDIN, head, JS_INIT, "var out = {};", calls, "removeEsTemp();", "WScript.Echo(convertToEsJson(out));"])


@pytest.fixture(scope="module")
def js_lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    _, lib = js_harness.build_js(tmp_path_factory.mktemp("jssec"))
    return lib


@pytest.fixture(scope="module")
def pair(js_lib: Path, built: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    proc = js_harness.run_js(js_lib, js_snippet(PROBES, js_lib), env=scrubbed_env())
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    js = json.loads(proc.stdout)
    names = ", ".join(f"'{pid}'" for pid in PROBES)
    command = (f". {ps_quote(built / 'build' / 'lib' / 'envscan-lib.ps1')}; {PS_INIT}; $out = @{{}}; "
               f"foreach ($id in @({names})) {{ $out[$id] = & ('probe_' + ($id -replace '\\.', '_')) }}; ConvertTo-EsJson $out")
    result = ps_command(command, timeout=600)
    assert result.returncode == 0, result.stderr
    return js, json.loads(result.stdout)


def data(results: dict[str, Any], pid: str) -> dict[str, Any]:
    return results[pid]["data"]


@pytest.mark.parametrize("pid", ["sec.app_control", "sec.crypto", "sec.av"])
def test_same_as_ps(pair: tuple[dict, dict], pid: str) -> None:
    js, ps = pair
    assert js[pid]["status"] == ps[pid]["status"], (js[pid]["notes"], ps[pid]["notes"])
    assert data(js, pid) == data(ps, pid)


def test_tls_trust(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    left, right = data(js, "tls.trust"), data(ps, "tls.trust")
    assert js["tls.trust"]["status"] == ps["tls.trust"]["status"], js["tls.trust"]["notes"]
    assert set(left) == set(right)
    fields = ("thumbprint", "store", "origin", "subject", "issuer", "not_after")
    as_set = lambda roots: sorted(tuple(r[k] for k in fields) for r in roots)  # noqa: E731
    assert as_set(left["roots"]) == as_set(right["roots"])
    for key in ("enterprise_roots", "enterprise_thumbprints", "root_count", "user_root_count", "authroot_count",
                "expired_roots", "intermediate_count", "root_auto_update", "runtime_trust", "java_home_cacerts",
                "bundles", "custom_anchors"):
        assert left[key] == right[key], key


def test_policy_skip_patterns(js_lib: Path) -> None:
    snippet = r"""
var keys = ["\\Exclusions", "\\Exclusions\\Paths", "\\Real-Time Protection\\ASROnlyExclusions", "\\Windows Defender Exploit Guard\\Controlled Folder Access\\AllowedApplications",
  "\\Policy Manager", "\\Microsoft\\Windows\\Installer", "\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "\\Microsoft\\Windows\\IPSec\\Policy",
  "\\winlogon\\x", "\\Spynet", "\\Microsoft\\Windows\\InstallerX", "\\Scan", "\\Policy ManagerX"];
var values = ["ExclusionPath", "ExcludeX", "ASROnlyPerRuleExclusions", "exclusions_paths", "DisableAntiSpyware", "AllowExtension"];
var out = { keys: [], values: [] };
for (var i = 0; i < keys.length; i++) { out.keys.push(ES_POLICY_SKIP_RE.test(keys[i])); }
for (var j = 0; j < values.length; j++) { out.values.push(ES_POLICY_SKIP_VALUE_RE.test(values[j])); }
WScript.Echo(convertToEsJson(out));
"""
    proc = js_harness.run_js(js_lib, snippet, env=scrubbed_env())
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["keys"] == [True] * 9 + [False] * 4
    assert out["values"] == [True, True, True, True, False, False]


def test_policy_tree_never_opens_excluded_keys(js_lib: Path) -> None:
    """getEsRegTree with the skip patterns over a fake registry (the engine's reader functions replaced)."""
    snippet = r"""
var opened = [];
var FAKE = {
  "HKLM:\\P": { values: { A: 1, ExclusionPath: "x" }, subs: ["Exclusions", "Scan", "Policy Manager", "Installer"] },
  "HKLM:\\P\\Scan": { values: { B: 2, ExcludeThis: 3 }, subs: ["Winlogon", "Deep"] },
  "HKLM:\\P\\Scan\\Deep": { values: { C: 4 }, subs: [] }
};
getEsRegValues = function (path, skip) {
  opened.push(path);
  var node = FAKE[path]; if (!node) { return null; }
  var out = {};
  for (var k in node.values) { if (!(skip && skip.test(k))) { out[k] = node.values[k]; } }
  return out;
};
getEsRegSubkeys = function (path) { var node = FAKE[path]; return node ? node.subs : []; };
var tree = getEsRegTree("HKLM:\\P", 50, ES_POLICY_SKIP_RE, ES_POLICY_SKIP_VALUE_RE);
WScript.Echo(convertToEsJson({ tree: tree, opened: opened }));
"""
    proc = js_harness.run_js(js_lib, snippet, env=scrubbed_env())
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert sorted(out["opened"]) == ["HKLM:\\P", "HKLM:\\P\\Scan", "HKLM:\\P\\Scan\\Deep"]
    assert out["tree"] == {"A": 1, "Scan\\B": 2, "Scan\\Deep\\C": 4}


def test_der_quote_and_time(js_lib: Path) -> None:
    snippet = ('WScript.Echo(convertToEsJson([jsDer_quote("Starfield Technologies, Inc."), jsDer_quote("plain"), '
               'jsDer_quote(" lead"), jsDer_quote("say \\"x\\""), jsDer_quote("")]));')
    proc = js_harness.run_js(js_lib, snippet, env=scrubbed_env())
    assert json.loads(proc.stdout) == ['"Starfield Technologies, Inc."', "plain", '" lead"', '"say ""x"""', '""']
