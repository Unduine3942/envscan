"""Unit tests of the envscan.ps1 library (build/lib/envscan-lib.ps1).

One PowerShell process per language mode evaluates every case in tests/ps/unit_cases.ps1
and prints a JSON object; the tests below check the results. Running the same cases in
ConstrainedLanguage proves the library only uses what CLM allows.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import ps_command, ps_quote, requires_powershell, run_ps

pytestmark = [pytest.mark.integration, requires_powershell]

CASES = Path(__file__).resolve().parent / "ps" / "unit_cases.ps1"
MODES = ("FullLanguage", "ConstrainedLanguage")


@pytest.fixture(scope="module", params=MODES)
def results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    mode = request.param
    scratch = tmp_path_factory.mktemp(f"psunit-{mode}")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if mode != "FullLanguage" else ""
    command = f"{prefix}& {ps_quote(CASES)} -Lib {ps_quote(lib)} -Scratch {ps_quote(scratch)}"
    proc = ps_command(command, timeout=300)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    data = json.loads(proc.stdout)
    assert data["language_mode"] == mode
    return data


# ------------------------------------------------------------------ JSON writer

def test_json_round_trips_special_characters(results: dict[str, Any]) -> None:
    raw = results["json_tricky"]
    raw.encode("ascii")  # the writer escapes everything outside printable ASCII
    data = json.loads(raw)
    assert data["s"] == 'quote" back\\ slash'
    assert data["u"] == "caf\u00e9 \u65e5"
    assert data["c"] == "tab\tnl\ncr\r\u0001"
    assert data["n"] is None and data["b"] is True and data["f"] is False
    assert data["i"] == 42 and data["l"] == 1234567890123 and data["d"] == 1.5
    assert data["e"] == [] and data["h"] == {}
    assert data["nested"] == [{"a": 1}, [1, 2], "x"]
    assert data["single"] == ["only"]
    assert list(data)[:2] == ["s", "u"]


def test_json_key_order_and_scalars(results: dict[str, Any]) -> None:
    assert list(json.loads(results["json_order"])) == ["z", "a", "b", "m"]
    assert json.loads(results["json_scalar_string"]) == "plain"
    assert json.loads(results["json_long_array"]) == {"list": list(range(1, 41))}


# ------------------------------------------------------------------ redaction

@pytest.mark.parametrize("name, secret", [
    ("GITHUB_TOKEN", True), ("MY_API_KEY", True), ("PASSWORD", True), ("npm_config__authToken", True),
    ("AWS_SECRET_ACCESS_KEY", True), ("GH_PAT_VALUE", True), ("credential.helper", True),
    ("DB_PASSWORD_FILE", False), ("PATH", False), ("PWD", False), ("SSH_AUTH_SOCK", False),
    ("JAVA_HOME", False), ("KEYBOARD_LAYOUT", False), ("PSModulePath", False),
])
def test_secret_names(results: dict[str, Any], name: str, secret: bool) -> None:
    assert results["secret_names"][name] is secret


@pytest.mark.parametrize("case, expected", [
    ("value_url", "https://user:<redacted>@repo.corp.example/simple"),
    ("value_token", "token is <redacted> ok"),
    ("value_bearer", "Authorization: Bearer <redacted>"),
    ("value_key", "<redacted: private key>"),
    ("value_plain", "C:\\Program Files\\nodejs\\node.exe"),
    ("line_password", "password = <redacted>"),
    ("line_npm_token", "//npm.corp.example/:_authToken=<redacted>"),
    ("line_registry", "registry=https://npm.corp.example/repository/npm/"),
    ("line_xml", "<password><redacted></password>"),
    ("line_nuget", '<add key="ClearTextPassword" value="<redacted>" />'),
    ("value_redact_off", "https://user:hunter2@repo.corp.example/simple"),
])
def test_redaction_rules(results: dict[str, Any], case: str, expected: str) -> None:
    assert results[case] == expected


def test_command_line_redaction(results: dict[str, Any]) -> None:
    line = results["cmdline"]
    for secret in ("hunter2", "xyz", "abc"):
        assert secret not in line
    assert "--user bob" in line


def test_nested_data_redaction(results: dict[str, Any]) -> None:
    data = results["data_nested"]
    assert data["a"][0] == "https://u:<redacted>@h.example/x"
    assert data["a"][1] == {"b": "<redacted>"}
    assert data["n"] == 5


# ------------------------------------------------------------------ arguments

def test_argument_quoting(results: dict[str, Any]) -> None:
    assert results["arg_string"] == 'a "b c" "" "x\\"y" trail\\'


def test_argument_errors(results: dict[str, Any]) -> None:
    assert results["args_unknown"] == ["unknown option: --bogus"]
    assert results["args_timeout"] == ["--timeout must be 1-3600 seconds: 0"]
    assert results["args_missing"] == ["missing value for --out"]
    assert results["args_only_errors"] == []
    assert results["args_only"] == ["os.*", "hw.cpu"]
    assert results["args_deep"] is True


# ------------------------------------------------------------------ proxy, endpoints, versions

def test_proxy_blob(results: dict[str, Any]) -> None:
    blob = results["proxy_blob"]
    assert blob["flags"] == 3 and blob["proxy"] == "proxy.corp:8080" and blob["exclusions"] == "<local>"
    direct = results["proxy_blob_direct"]
    assert direct["flags"] == 1 and direct["proxy"] is None


@pytest.mark.parametrize("value, expected", [
    ("http://user:pw@proxy.corp:3128", {"host": "proxy.corp", "port": 3128}),
    ("https://repo.corp/maven", {"host": "repo.corp", "port": 443}),
    ("proxy:8080", {"host": "proxy", "port": 8080}),
    ("http://[fd00::1]:8080/x", {"host": "fd00::1", "port": 8080}),
    ("http://169.254.169.254/latest", None),
    ("metadata.google.internal", None),
    ("http://metadata.google.internal./x", None),
    ("http://proxy.corp.:3128", {"host": "proxy.corp", "port": 3128}),
    # X4c: an IPv4 literal keeps its trailing dot, so net.reachability skips it
    ("http://10.0.0.1.:3128", {"host": "10.0.0.1.", "port": 3128}),
])
def test_endpoints_never_include_metadata(results: dict[str, Any], value: str, expected: dict[str, Any] | None) -> None:
    endpoint = results["endpoints"][value]
    if expected is None:
        assert endpoint is None
    else:
        assert {k: endpoint[k] for k in ("host", "port")} == expected


@pytest.mark.parametrize("text, version", [
    ("git version 2.47.1.windows.1", "2.47.1.windows.1"),
    ('openjdk version "21.0.1" 2023-10-17', "21.0.1"),
    ("go version go1.22.0 windows/amd64", "1.22.0"),
    ("This is perl 5, version 36, subversion 0 (v5.36.0)", "5.36.0"),
    ("v20.11.0", "20.11.0"),
    ("no version here", None),
])
def test_version_tokens(results: dict[str, Any], text: str, version: str | None) -> None:
    assert results["versions"][text] == version


# ------------------------------------------------------------------ ACLs

@pytest.mark.parametrize("key, expected", [
    ("0x1200a9/2", False), ("0x1301bf/2", True), ("FA/2", True), ("LC/4", True), ("LC/2", False),
    ("DC/2", True), ("GR/2", False), ("0x10000000/4", True), ("SDGXGWGR/2", True),
])
def test_sddl_rights(results: dict[str, Any], key: str, expected: bool) -> None:
    assert results["sddl_rights"][key] is expected


def test_sddl_access_on_real_directories(results: dict[str, Any]) -> None:
    assert results["sddl_scratch"]["create_files"] is True
    if results["is_admin"] is not False:
        pytest.skip(f"C:\\Windows may be writable for this token (is_admin = {results['is_admin']!r}); "
                    "the read-only check needs a standard user")
    assert results["sddl_windows"]["create_files"] is False


# ------------------------------------------------------------------ misc helpers

def test_dates_policies_findings_markdown(results: dict[str, Any]) -> None:
    assert results["cim_date"] == "2026-10-29T17:32:08Z"
    assert results["policy_user"] == "RemoteSigned"
    assert results["policy_gpo"] == "AllSigned"
    finding = results["finding_known"]
    assert finding["severity"] == "warning" and finding["evidence"] == ["hw.storage"]
    assert finding["title"] and finding["recommendation"]
    assert results["finding_unknown"] is True
    assert results["md_text"] == "`a<b>_c`"
    assert results["md_plain"] == "plain text"


def test_raw_output_is_capped(results: dict[str, Any]) -> None:
    assert results["raw_limit"]["truncated"] is True
    assert results["raw_limit_length"] <= 65536 + len("\n[truncated]")


# ------------------------------------------------------------------ PATH lookup

def test_path_lookup_order(results: dict[str, Any]) -> None:
    assert results["path_dirs"] == ["a", "b"]
    assert results["find_order"] == ["b/tool3.exe", "a/tool.cmd", "b/tool.exe"]
    assert results["find_ps1"] == ["only.ps1"]


@pytest.mark.parametrize("case, fragment", [
    ("presence", "inventory only"), ("ps1", "PowerShell script shim"), ("alias", "app execution alias"),
    ("wsl", "WSL launcher"), ("shim", "version-manager shim (rustup)"), ("js", "is not run"),
])
def test_never_run_rules(results: dict[str, Any], case: str, fragment: str) -> None:
    assert fragment in results["no_run"][case]


def test_runnable_tools_have_no_reason(results: dict[str, Any]) -> None:
    assert results["no_run"]["plain"] is None
    assert results["no_run"]["winget"] is None


def test_split_probe_helpers(results: dict[str, Any]) -> None:
    assert results["vm_products"] == ["VMware", "VirtualBox", "Google Compute Engine", "", ""]
    assert results["arch_facts"]["arm"]["arch"] == "arm64"
    assert results["arch_facts"]["arm"]["architecture_code"] == 12
    assert results["arch_facts"]["none"]["architecture_code"] is None
    assert results["domain_facts"]["none"] == {"domain": None, "domain_joined": None, "fqdn": None}
    assert results["domain_facts"]["joined"]["fqdn"] == "pc1.corp.example"
    assert results["domain_facts"]["workgroup"] == {"domain": None, "domain_joined": False, "fqdn": None,
                                                    "workgroup": "WORKGROUP"}
    assert all(value == [] for value in results["path_issues"]["empty"].values())
    assert results["path_issues"]["one"]["missing"] == ["C:\\x"]
    assert results["path_issues"]["one"]["writable_before_system32"] == ["C:\\x"]


def test_brief_says_how_much_was_not_checked(results: dict[str, Any]) -> None:
    assert results["brief_findings"]["clean"] == ["- No blockers or warnings."]
    assert results["brief_findings"]["incomplete"] == [
        "- No blockers or warnings found; 4 probes were not fully checked (see Not checked)."]


def test_network_java_home_is_not_read(results: dict[str, Any]) -> None:
    assert results["java_cacerts_unc"] is None


def test_appx_skip_on_powershell_7_is_unknown_not_empty(results: dict[str, Any]) -> None:
    assert results["appx_ps7"] == {"listed": False, "count": 0, "status": "partial"}


def test_default_output_skips_synced_folders(results: dict[str, Any]) -> None:
    # Started inside OneDrive: the report goes to the profile or TEMP instead.
    assert results["output_parents"]["synced_cwd_listed"] is False
    assert results["output_parents"]["count"] >= 1


def test_timeout_stops_the_whole_process_tree(results: dict[str, Any]) -> None:
    # cmd.exe starts powershell.exe, which sleeps; the timeout must stop both.
    assert results["exec_timeout"] == {"timed_out": True, "grandchild_seen": True, "grandchild_alive": False}


# ------------------------------------------------------------------ test harness (conftest.run_ps)

QUOTED_DIR = "it's \u2018quoted\u2019"  # PowerShell treats all three quote characters as '


@pytest.mark.parametrize("body, code", [
    ("exit 3", 3),
    ("Write-Output 'done'", 0),
    ("throw 'boom'", 1),
    ("Get-Item -LiteralPath 'Z:\\no\\such\\path' -ErrorAction Stop", 1),
])
def test_run_ps_exit_code_follows_the_script(tmp_path: Path, body: str, code: int) -> None:
    folder = tmp_path / QUOTED_DIR
    folder.mkdir()
    script = folder / "probe.ps1"
    script.write_text(body + "\r\n", encoding="ascii")
    assert run_ps(script).returncode == code


def test_run_ps_reports_a_missing_script_as_failure(tmp_path: Path) -> None:
    assert run_ps(tmp_path / "missing.ps1").returncode == 1


def test_run_ps_passes_quotes_through_unchanged(tmp_path: Path) -> None:
    script = tmp_path / "echo.ps1"
    script.write_text("param($Value) ([int[]][char[]]$Value) -join ','\r\n", encoding="ascii")
    value = f"{QUOTED_DIR} ''x"
    proc = run_ps(script, (value,))
    assert proc.returncode == 0, proc.stderr
    assert "".join(chr(int(code)) for code in proc.stdout.strip().split(",")) == value
