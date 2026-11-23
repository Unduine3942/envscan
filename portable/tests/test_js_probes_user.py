"""envscan.js user, environment, PATH and shell probes (src/js/21-probes-user.js, 21-probes-shell.js).

Each probe runs on this machine in cscript and in Windows PowerShell; the stable facts must be equal.
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

PROBES = ("os.identity", "user.identity", "user.profile", "env.vars", "env.path", "shell.info")
JS_INIT = "initializeEsRedaction(); saveEsEnvSnapshot(); initializeEsTemp(); initializeEsDrives();"
PS_INIT = "Initialize-EsRedaction; Save-EsEnvSnapshot; Initialize-EsDrives"
# Variables powershell.exe itself adds to its environment.
PS_OWN_VARS = {"psexecutionpolicypreference", "psmodulepath"}
# Set by tests/js_harness.run_js for its temp-folder cleanup: only the JScript side sees it.
HARNESS_VARS = {"__es_test_temp_report"}


def js_snippet(ids: tuple[str, ...], lib: Path) -> str:
    worker = str(lib.parents[2] / "dist" / "envscan.js").replace("\\", "\\\\")
    calls = "\n".join(f'out["{pid}"] = probe_{pid.replace(".", "_")}();' for pid in ids)
    head = f'ES_WORKER_SCRIPT = "{worker}";'
    return "\n".join([head, JS_INIT, "var out = {};", calls, "removeEsTemp();", "WScript.Echo(convertToEsJson(out));"])


@pytest.fixture(scope="module")
def js_lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    _, lib = js_harness.build_js(tmp_path_factory.mktemp("jsuser"))
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


@pytest.mark.parametrize("pid, extra", [
    ("user.identity", set()), ("user.profile", set()), ("env.vars", set()), ("env.path", set()),
    ("shell.info", {"script_engine", "wsh_settings", "powershell_lockdown_policy"}),
])
def test_keys_match_ps(pair: tuple[dict, dict], pid: str, extra: set[str]) -> None:
    js, ps = pair
    assert set(data(js, pid)) == set(data(ps, pid)) | extra, pid
    assert js[pid]["sources"]


def test_user_identity(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    for key in ("name", "domain", "dns_domain", "logon_server", "local_account", "sid", "home", "shell", "uac",
                "developer_mode", "uid", "gid", "integrity", "passwd_entry"):
        assert data(js, "user.identity")[key] == data(ps, "user.identity")[key], key
    # No token API in WSH: elevation unknown (partial, noted); groups assumed.
    assert data(js, "user.identity")["is_admin"] is None
    assert js["user.identity"]["status"] == "partial"
    assert data(js, "user.identity")["groups_source"] == "assumed"
    assert any("elevation" in note for note in js["user.identity"]["notes"])


def test_user_profile(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    assert js["user.profile"]["status"] == ps["user.profile"]["status"]
    assert data(js, "user.profile") == data(ps, "user.profile")


def test_env_vars(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    left, right = data(js, "env.vars"), data(ps, "env.vars")
    js_names = {n.lower() for n in left["process"]}
    ps_names = {n.lower() for n in right["process"]} - PS_OWN_VARS
    assert js_names - PS_OWN_VARS - HARNESS_VARS == ps_names
    assert left["machine"] == right["machine"]
    assert left["user"] == right["user"]
    assert left["redacted"] == right["redacted"]
    assert js["env.vars"]["status"] == ps["env.vars"]["status"]


def test_env_path(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    left, right = data(js, "env.path"), data(ps, "env.path")
    for key in ("separator", "length", "count", "empty_entries"):
        assert left[key] == right[key], key
    stable = ("path", "scope", "network", "relative", "duplicate", "quoted", "unexpanded", "position")
    assert [tuple(e[k] for k in stable) for e in left["entries"]] == [tuple(e[k] for k in stable) for e in right["entries"]]
    # WSH cannot read link targets: an entry that is (or lies below) a junction is unknown, never "missing".
    for mine, theirs in zip(left["entries"], right["entries"]):
        assert mine["exists"] in (theirs["exists"], None), mine["path"]
    if any(e["exists"] is None and not e["network"] and not e["relative"] for e in left["entries"]):
        assert any("not checked" in note for note in js["env.path"]["notes"])
    for key in ("missing", "duplicate", "relative", "network"):
        assert left["issues"][key] == right["issues"][key], key
    # No ACL API in WSH: writability is unknown and says so.
    assert all(e["writable"] is None for e in left["entries"])
    assert js["env.path"]["status"] == "partial"


def test_shell_info(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    left, right = data(js, "shell.info"), data(ps, "shell.info")
    for key in ("cmd_autorun", "cmd_disabled", "wsh_enabled", "comspec", "powershell_policies",
                "powershell_installed", "policy_from_gpo"):
        assert left[key] == right[key], key
    for scope in ("MachinePolicy", "UserPolicy", "CurrentUser", "LocalMachine"):
        assert left["execution_policy"][scope] == right["execution_policy"][scope], scope
    assert left["current_shell"] == "cscript" and left["host"].lower() == "cscript.exe"
    assert left["script_engine"].startswith("JScript ")
    assert set(left["wsh_settings"]) == {"HKLM", "HKCU"}
    assert set(left["wsh_settings"]["HKLM"]) == {"Enabled", "IgnoreUserSettings", "TrustPolicy", "UseWINSAFER"}
    assert js["shell.info"]["status"] == "ok"


def test_group_names(js_lib: Path) -> None:
    snippet = ('WScript.Echo(convertToEsJson([convertToEsGroupName("S-1-5-32-544"), '
               'convertToEsGroupName("S-1-5-21-1-2-3-512"), convertToEsGroupName("S-1-5-21-1-2-3-1001")]));')
    proc = js_harness.run_js(js_lib, snippet, env=scrubbed_env())
    assert json.loads(proc.stdout) == ["BUILTIN\\Administrators", "Domain Admins (S-1-5-21-1-2-3-512)", "S-1-5-21-1-2-3-1001"]
