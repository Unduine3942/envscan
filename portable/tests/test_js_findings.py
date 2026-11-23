"""The findings of the JScript port (src/js/30-findings*.js) against the golden cases of
tests/data/findings_cases.json: every case the ps1 findings run (impls "ps") runs through the JScript
findings with the probe results tests/findings_harness.py builds for ps, and must give the same ids.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import findings_harness as fh
import pytest
from conftest import PORTABLE
from js_harness import HAVE_CSCRIPT, build_js, run_js

import target_js

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe")]

CASES = [c for c in fh.load_cases() if "ps" in c["impls"]]
JS_SOURCES = sorted((PORTABLE / "src" / "js").glob("30-findings*.js"))
PS_SOURCE = PORTABLE / "src" / "ps" / "30-findings.ps1"

RUNNER = r"""
// The probe results of each case go into ES_RESULTS as the runner keeps them.
initializeEsRedaction();
var jsOut = { ids: {}, details: {} };
for (var jsI = 0; jsI < JS_CASES.length; jsI++) {
    var jsCase = JS_CASES[jsI];
    ES_RESULTS = {};
    for (var jsId in jsCase.results) {
        if (!jsCase.results.hasOwnProperty(jsId)) { continue; }
        var jsR = jsCase.results[jsId];
        ES_RESULTS[jsId] = { status: jsR.status, data: jsR.data || {}, notes: [] };
    }
    ES_FULL_LANGUAGE = jsCase.full_language;
    ES_LANGUAGE_MODE = jsCase.full_language ? "FullLanguage" : "ConstrainedLanguage";
    var jsFound = getEsFindings(), jsIds = [];
    for (var jsK = 0; jsK < jsFound.length; jsK++) {
        jsIds.push(jsFound[jsK].id);
        jsOut.details[jsCase.name + "|" + jsFound[jsK].id] = jsFound[jsK].detail;
    }
    jsOut.ids[jsCase.name] = jsIds;
}
WScript.Echo(convertToEsJson(jsOut));
"""


@pytest.fixture(scope="module")
def results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    lib = build_js(tmp_path_factory.mktemp("js-findings"))[1]
    cases = target_js.js_literal([fh.ps_input(c) for c in CASES])
    proc = run_js(lib, f"var JS_CASES = {cases};\n{RUNNER}")
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_js_findings(results: dict[str, Any], case: dict[str, Any]) -> None:
    assert sorted(results["ids"][case["name"]]) == fh.expected(case, "ps")


def test_every_ps_finding_is_ported() -> None:
    ps_ids = set(re.findall(r"New-EsFinding\s+'([a-z]+\.[a-z0-9_]+)'", PS_SOURCE.read_text(encoding="utf-8")))
    js_text = "".join(p.read_text(encoding="ascii") for p in JS_SOURCES)
    js_ids = set(re.findall(r'newEsFinding\("([a-z]+\.[a-z0-9_]+)"', js_text))
    assert len(ps_ids) >= 30
    assert js_ids == ps_ids


def test_details_follow_the_ps_wording(results: dict[str, Any]) -> None:
    details = results["details"]
    assert details["enterprise_ca_added|tls.enterprise_ca"] == "1 added root(s): Corp Root CA; no runtime CA variable is set"
    assert details["proxy_configured|net.proxy_configured"] == "proxy.corp.example:8080 (env)"
    assert details["ps_policy_restricted|exec.policy_restricted"] == "Execution policy Restricted (local setting or OS default)"
    assert details["ps_weak_dotnet_tls|crypto.weak_dotnet_tls"] == ".NET Framework 4.5.1 without SchUseStrongCrypto"
    assert details["scan_partial_probe|scan.partial"] == "1 probe(s): hw.gpu"
    assert details["memory_low_available|limits.memory_low"] == "1024 MB available of 4096 MB"
    assert details["locale_non_utf8|locale.non_utf8"] == "ANSI code page 1252, OEM 437, console 437"
    assert details["ps_constrained_language|exec.ps_constrained"] == "Language mode: ConstrainedLanguage"
