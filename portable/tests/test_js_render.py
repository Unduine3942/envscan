"""envscan.js renderers (src/js/40-render.js, 41-brief.js) against the PowerShell originals.

The same report and probe results go to ConvertTo-EsMarkdownReport / ConvertTo-EsBrief of the ps
library (build/lib/envscan-lib.ps1) and to convertToEsMarkdownReport / convertToEsBrief of the JScript
library; the texts must be identical. The fixture is written as a PowerShell literal and as a JScript
literal from one Python value, so both see the same data.

Documented differences (see 40-render.js): key and label order is code-unit order in JScript (ps sorts
with the culture's comparer), so fixture keys are lower-case; ES_LANGUAGE_MODE is set to the JScript
value ("WSH") on both sides; doubles print with JScript's String().
"""
from __future__ import annotations

import datetime as dt
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from conftest import BRIEF_HEADINGS, ps_command, ps_quote, requires_powershell
from js_harness import HAVE_CSCRIPT, build_js, run_js
from target_js import js_string

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows Script Host)"),
]

# Modules the renderers need: the engine, helpers, redaction/proxy/findings (joinEsShort,
# getEsPersistentPolicy, getEsInternalHosts) and the renderers themselves.
LIB_PREFIXES = ("00-", "10-", "11", "12-", "13-", "14-", "15-", "30-", "40-", "41-")


@pytest.fixture(scope="module")
def js_lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    _, lib = build_js(tmp_path_factory.mktemp("jsrender"), lambda name: name.startswith(LIB_PREFIXES))
    return lib


# ------------------------------------------------------------------ literals

def ps_literal(value: Any) -> str:
    """A PowerShell expression for a JSON-like Python value (no nested lists)."""
    if value is None:
        return "$null"
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, int):
        return str(value) if abs(value) < 2**31 else f"([long]{value})"
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, dt.datetime):
        return f"([datetime]'{value.strftime('%Y-%m-%dT%H:%M:%SZ')}')"
    if isinstance(value, str):
        return "(" + " + ".join(_ps_string_parts(value)) + ")"
    if isinstance(value, Mapping):
        return "@{" + "; ".join(f"{ps_quote(k)} = {ps_literal(v)}" for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple)):
        assert not any(isinstance(item, (list, tuple)) for item in value), "nested lists are ambiguous in ps"
        return "@(" + ", ".join(ps_literal(item) for item in value) + ")"
    raise TypeError(type(value).__name__)


def _ps_string_parts(text: str) -> list[str]:
    """Control characters as [char] casts; everything else single-quoted."""
    parts: list[str] = []
    current = ""
    for ch in text:
        if ord(ch) < 0x20:
            if current:
                parts.append(ps_quote(current))
                current = ""
            parts.append(f"[string][char]{ord(ch)}")
        else:
            current += ch
    if current or not parts:
        parts.append(ps_quote(current))
    return parts


def js_literal(value: Any) -> str:
    """A JScript expression for the same value (Dates as UTC Date objects)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, dt.datetime):
        return (f"new Date(Date.UTC({value.year}, {value.month - 1}, {value.day}, {value.hour}, "
                f"{value.minute}, {value.second}))")
    if isinstance(value, str):
        return js_string(value)
    if isinstance(value, Mapping):
        return "{" + ", ".join(f"{js_string(k)}: {js_literal(v)}" for k, v in value.items()) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(js_literal(item) for item in value) + "]"
    raise TypeError(type(value).__name__)


# ------------------------------------------------------------------ fixtures

def envelope(title: str, status: str = "ok", data: Mapping[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    env = {"title": title, "status": status, "tier": "default", "scope": "system", "duration_ms": 12,
           "data": dict(data or {}), "raw": {}, "sources": ["registry"], "notes": [], "error": None,
           "truncated": False}
    env.update(extra)
    return env


def rich_results() -> dict[str, Any]:
    long_list = [f"item{i}" for i in range(320)]
    return {
        "os.identity": envelope("OS identity", data={
            "name": "Windows 11 Pro", "display_version": "24H2", "build": "26100", "install_type": "Client",
            "arch": "x86_64", "userland_bits": 64, "process_arch": "x86_64", "domain_joined": False,
            "workgroup": "WORKGROUP", "hostname": "PC1", "directory_joined": None, "product_type": 1,
            "edition_id": "Professional"}),
        "os.health": envelope("OS health", data={"last_boot_utc": "2026-11-10T08:00:00Z", "pending_reboot": False}),
        "hw.cpu": envelope("CPU", data={"model": "Intel(R) Core(TM) i7", "cores": 8, "logical": 16}),
        "hw.memory": envelope("Memory", data={"total_mb": 32000, "available_mb": 12000, "swap_total_mb": 4096,
                                              "commit_limit_mb": 36096}),
        "virt.platform": envelope("Virtualization", data={
            "virtualization": "none", "vm_product": None, "container": {"detected": False, "engine": None},
            "wsl_distros": [{"name": "Ubuntu", "version": 2}, {"name": "Debian", "version": 1}],
            "docker_desktop": True}),
        "session.context": envelope("Session", data={"type": "console", "session_id": 1, "interactive": True,
                                                     "terminal": "Windows Terminal"}),
        "user.identity": envelope("User", data={"domain": "PC1", "name": "dev", "is_admin": None,
                                                "developer_mode": True}),
        "user.profile": envelope("Profile", data={"profile_type": "local", "home": "C:\\Users\\dev"}),
        "shell.info": envelope("Shell", data={"shell_version": "5.1.26100", "edition": "Desktop",
                                              "execution_policy": {"CurrentUser": "RemoteSigned",
                                                                   "LocalMachine": "Undefined"},
                                              "effective_policy": "RemoteSigned", "cmd_disabled": 0}),
        "os.time_locale": envelope("Locale", data={"timezone": "Tokyo Standard Time", "utc_offset": "+09:00",
                                                   "locale": "ja-JP", "codepage_ansi": 932, "codepage_oem": 932,
                                                   "decimal_separator": "."}),
        "tools.inventory": envelope("Tools", data={"tools": {
            "git": {"name": "Git", "cat": "vcs", "found": True, "version": "2.47.1",
                    "path": "C:\\Program Files\\Git\\cmd\\git.exe", "binary_arch": "x86_64"},
            "git-lfs": {"name": "Git LFS", "cat": "vcs", "found": True, "version": None,
                        "path": "C:\\Program Files\\Git\\mingw64\\bin\\git-lfs.exe", "reason": "inventory only"},
            "node": {"name": "Node.js", "cat": "runtime", "found": True, "version": "20.11.0",
                     "path": "C:\\Users\\dev\\.volta\\bin\\node.exe", "reason": "version-manager shim (Volta); not run"},
            "jq": {"name": "jq", "cat": "util", "found": True, "version": "1.7", "path": "C:\\bin\\jq.exe"},
            "ruby": {"name": "Ruby", "cat": "runtime", "found": False, "path": None},
        }}),
        "runtime.java": envelope("Java", data={"jdks": [
            {"version": "21.0.1", "vendor": "Eclipse Adoptium", "arch": "x86_64", "is_jdk": True,
             "path": "C:\\Program Files\\Eclipse Adoptium\\jdk-21"},
            {"version": "1.8.0_392", "vendor": None, "arch": "x86", "is_jdk": False, "path": "C:\\java8"}],
            "java_home": None}),
        "runtime.dotnet": envelope(".NET", data={"framework": {"version": "4.8.1"},
                                                 "sdks": ["8.0.100 [C:\\Program Files\\dotnet\\sdk]"],
                                                 "runtimes": ["Microsoft.NETCore.App 8.0.0 [C:\\x]"]}),
        "runtime.python": envelope("Python", data={"interpreters": [
            {"version": "3.12.1", "path": "C:\\Python312\\python.exe", "store_alias": False},
            {"version": None, "path": "C:\\Users\\dev\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe",
             "store_alias": True}], "store_packages": ["3.11"]}),
        "toolchain.msvc": envelope("MSVC", data={"instances": [{"displayname": "Visual Studio Build Tools 2022",
                                                                "installationversion": "17.9"}],
                                                 "windows_sdks": ["10.0.22621.0", "10.0.19041.0"]}),
        "runtime.version_managers": envelope("Version managers", data={"managers": [
            {"name": "Volta", "versions": ["20.11.0", ".hidden", "18.19.0"]},
            {"name": "pyenv", "versions": []}]}),
        "native.deps": envelope("Native", data={
            "ucrt": "10.0.26100.1", "webview2": "130.0",
            "vcredist": [{"arch": "x64", "version": "14.40"}, {"arch": "x86", "version": "14.40"},
                         {"arch": "x64", "version": "14.40"}],
            "odbc_drivers": [{"name": "SQL Server"}, {"name": "ODBC Driver 18"}, {"name": "SQL Server"}]}),
        "pkg.sources": envelope("Package sources", data={
            "endpoints": ["https://npm.corp.example/repository/npm/", "https://registry.npmjs.org/"],
            "configs": [
                {"tool": "npm", "path": "C:\\Users\\dev\\.npmrc",
                 "lines": ["registry=https://npm.corp.example/repository/npm/", "strict-ssl=false", "save-exact=true"]},
                {"tool": "pip", "path": "C:\\Users\\dev\\AppData\\Roaming\\pip\\pip.ini", "lines": ["[global]", "timeout = 60"]}],
            "env": {"PIP_INDEX_URL": "https://pypi.corp.example/simple", "NPM_CONFIG_REGISTRY": "https://npm.corp.example/"},
            "git_config": [{"key": "http.proxy", "value": "http://proxy.corp:8080"},
                           {"key": "user.name", "value": "dev"},
                           {"key": "core.autocrlf", "value": "true"}]}),
        "pkg.caches": envelope("Caches", data={"caches": [{"tool": "npm", "path": "C:\\Users\\dev\\AppData\\Local\\npm-cache",
                                                           "entries": 1234}]}),
        "fs.locations": envelope("Locations", data={"locations": [
            {"id": "temp", "path": "C:\\Users\\dev\\AppData\\Local\\Temp", "exists": True, "writable": True,
             "free_mb": 100000, "fstype": "NTFS"},
            {"id": "system_drive_root", "path": "C:\\", "exists": True, "writable": False, "can_create_dirs": True,
             "free_mb": 100000, "fstype": "NTFS"},
            {"id": "desktop", "path": "C:\\Users\\dev\\OneDrive\\Desktop", "exists": True, "writable": None,
             "onedrive": True, "free_mb": None},
            {"id": "home_share", "path": "\\\\server\\home", "network": True},
            {"id": "gone", "path": "D:\\nope", "exists": False}]}),
        "sec.app_control": envelope("App control", data={"enforced": []}),
        "env.path": envelope("PATH", data={"count": 42, "length": 3100, "issues": {
            "writable": ["C:\\tools", "C:\\Users\\dev\\bin"], "missing": ["C:\\gone", None]}}),
        "fs.semantics": envelope("FS semantics", data={"symlink": "developer mode", "hardlink": "yes",
                                                       "junction": "yes", "long_paths_enabled": False,
                                                       "case_sensitive": False, "path_max": 260,
                                                       "short_names": "enabled on C:"}),
        "fs.exec_test": envelope("Exec test", data={"results": [
            {"id": "temp", "kind": "cmd", "outcome": "ok", "detail": None},
            {"id": "temp", "kind": "exe", "outcome": "blocked", "detail": "Access is denied <AppLocker>"}]}),
        "net.interfaces": envelope("Interfaces", data={"interfaces": [
            {"name": "Ethernet", "description": "Intel", "addresses": ["192.168.1.10/24", "fe80::1/64"],
             "gateways": ["192.168.1.1"], "dns": ["192.168.1.1"], "mtu": 1500},
            {"name": None, "description": "VPN adapter", "addresses": [], "gateways": [], "dns": None, "mtu": None}]}),
        "net.routes": envelope("Routes", data={"default_gateways": [], "default_route_count": 1}),
        "net.dns": envelope("DNS", data={"search": ["corp.example"], "hosts_entries": []}),
        "net.proxy": envelope("Proxy", data={
            "env": {"HTTPS_PROXY": "http://proxy.corp:8080", "NO_PROXY": "localhost,.corp"},
            "winhttp": {"proxy": "proxy.corp:8080", "exclusions": None},
            "wininet": {"enabled": True, "server": "proxy.corp:8080", "pac_url": "http://wpad.corp/proxy.pac",
                        "auto_detect": True}, "any_proxy": True}),
        "net.firewall": envelope("Firewall", data={"profiles": [
            {"name": "Domain", "enabled": True, "inbound": "Block", "outbound": "Allow"},
            {"name": "Public", "enabled": False, "inbound": None, "outbound": None}]}),
        "net.listening": envelope("Listening", data={"ports": list(range(1000, 1050))}),
        "net.ports": envelope("Ports", data={"excluded_tcp": [{"start": 50000, "end": 50059}],
                                             "ephemeral": {"start": 49152, "end": 65535}, "urlacl_count": 37}),
        "tls.trust": envelope("TLS trust", data={"runtime_trust": {"NODE_EXTRA_CA_CERTS": "C:\\certs\\corp.pem"},
                                                 "enterprise_roots": ["CN=Corp Root CA, O=Corp", "Plain Root"],
                                                 "root_auto_update": True}),
        "sec.crypto": envelope("Crypto", data={"fips": False}),
        "net.reachability": envelope("Reachability", "skipped", data={"targets": [
            {"host": "proxy.corp", "port": 8080, "source": "env", "tcp": "ok", "ms": 3},
            {"host": "npm.corp.example", "port": 443, "source": "npm", "tcp": None, "reason": "net tier off", "ms": None}]},
            notes=["tier net not enabled (--net)"]),
        "hw.storage": envelope("Storage", data={"volumes": [
            {"kind": "local", "mount": "C:\\", "free_mb": 100000, "total_mb": 500000, "fstype": "NTFS"},
            {"kind": "network", "mount": "Z:\\", "free_mb": None}]}),
        "proc.list": envelope("Processes", data={"count": 250}),
        "svc.list": envelope("Services", "partial", data={"running": 120}, notes=["", "access denied to 2 services"]),
        "sched.tasks": envelope("Tasks", "error", data={}, error="query failed: <timeout> | x"),
        "misc.render": envelope("Render cases", data={
            "__order": ["zeta", "alpha"],
            "zeta": "first by __order", "alpha": "a*b_c", "plain": "x", "empty_list": [], "empty_table": {},
            "nothing": None, "flag": True, "number": 1.5, "when": dt.datetime(2026, 1, 2, 3, 4, 5),
            "multi": "line1\nline2", "long": "y" * 310, "tick": "has ` backtick",
            "scalars": long_list[:35], "many": long_list,
            "rows": [{"name": "a", "list": [1, 2], "none": None, "empty": [], "md": "<x>"},
                     {"name": "b", "nested": {"deep": 1}}, "scalar", None],
            "table": {"inner": {"leaf": "v"}, "list": []}},
            raw={"cmd b": "out\r\nline2", "cmd a": "has ``` fence"}, truncated=True,
            sources=["reg <HKLM>", "file"], notes=["note *one*"]),
    }


PROBE_IDS = ["os.identity", "os.health", "hw.cpu", "hw.memory", "virt.platform", "session.context",
             "user.identity", "user.profile", "shell.info", "os.time_locale", "tools.inventory", "runtime.java",
             "runtime.dotnet", "runtime.python", "toolchain.msvc", "runtime.version_managers", "native.deps",
             "pkg.sources", "pkg.caches", "fs.locations", "sec.app_control", "env.path", "fs.semantics",
             "fs.exec_test", "net.interfaces", "net.routes", "net.dns", "net.proxy", "net.firewall",
             "net.listening", "net.ports", "tls.trust", "sec.crypto", "net.reachability", "hw.storage",
             "proc.list", "svc.list", "sched.tasks", "misc.render", "never.ran"]


def make_report(results: Mapping[str, Any], findings: list[dict[str, Any]], redaction: bool = True) -> dict[str, Any]:
    counts = {}
    for env in results.values():
        counts[env["status"]] = counts.get(env["status"], 0) + 1
    probes = {"__order": [pid for pid in PROBE_IDS if pid in results], **results}
    return {
        "scanner": {"name": "envscan", "version": "1.0.0", "impl": "jscript", "shell_version": "5.8"},
        "host": {"hostname": "PC1", "os_name": "Windows 11 Pro", "os_version": "10.0.26100", "arch": "x86_64"},
        "run": {"started_utc": "2026-11-13T01:02:03Z", "duration_ms": 4567, "tiers": ["default", "deep"],
                "exit_code": 1, "redaction": redaction, "counts": counts},
        "findings": findings,
        "probes": probes,
    }


FINDINGS = [
    {"id": "path.writable", "severity": "warning", "title": "Writable PATH entries",
     "detail": "C:\\tools is writable", "recommendation": "Remove it", "evidence": ["env.path"]},
    {"id": "pkg.mirror", "severity": "info", "title": "Internal mirror", "detail": "npm.corp.example",
     "recommendation": "Use it", "evidence": ["pkg.sources", "net.proxy"]},
]


def render_ps(built: Path, tmp: Path, report: Mapping[str, Any], results: Mapping[str, Any]) -> dict[str, str]:
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    script = tmp / "render_case.ps1"
    probes = "@(" + ", ".join(f"@{{ id = {ps_quote(pid)} }}" for pid in PROBE_IDS) + ")"
    body = "\n".join([
        f". {ps_quote(lib)}",
        "Initialize-EsRedaction",
        "$script:ES_NETWORK_DRIVES = @()",
        "$script:ES_LANGUAGE_MODE = 'WSH'",
        f"$script:ES_PROBES = {probes}",
        f"$script:ES_RESULTS = {ps_literal(results)}",
        f"$report = {ps_literal(report)}",
        "$report.probes = $script:ES_RESULTS.Clone()",
        f"$report.probes['__order'] = {ps_literal(report['probes']['__order'])}",
        "$md = ConvertTo-EsMarkdownReport $report",
        "$brief = ConvertTo-EsBrief $report",
        "[Console]::Out.Write((ConvertTo-EsJson @{ md = $md; brief = $brief }))",
    ])
    script.write_text(body, encoding="ascii")
    proc = ps_command(f"& {ps_quote(script)}", timeout=300)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def render_js(lib: Path, report: Mapping[str, Any], results: Mapping[str, Any]) -> dict[str, str]:
    probes = "[" + ", ".join(f"{{\"id\": {js_string(pid)}}}" for pid in PROBE_IDS) + "]"
    snippet = "\n".join([
        "if (typeof initializeEsRedaction === 'function') { initializeEsRedaction(); }",
        "ES_NETWORK_DRIVES = [];",
        f"ES_PROBES = {probes};",
        f"ES_RESULTS = {js_literal(results)};",
        f"var report = {js_literal(report)};",
        "report.probes = ES_RESULTS;",
        f"ES_RESULTS.__order = {js_literal(report['probes']['__order'])};",
        "var md = convertToEsMarkdownReport(report);",
        "var brief = convertToEsBrief(report);",
        "WScript.Echo(convertToEsJson({md: md, brief: brief}));",
    ])
    proc = run_js(lib, snippet)
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def rich(built: Path, js_lib: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, str]]:
    results = rich_results()
    report = make_report(results, FINDINGS)
    return {"ps": render_ps(built, tmp_path_factory.mktemp("psrender"), report, results),
            "js": render_js(js_lib, report, results)}


def _diff(ps: str, js: str) -> str:
    ps_lines, js_lines = ps.split("\n"), js.split("\n")
    for i, (a, b) in enumerate(zip(ps_lines, js_lines)):
        if a != b:
            return f"line {i + 1}:\n ps: {a!r}\n js: {b!r}"
    return f"line count ps {len(ps_lines)} js {len(js_lines)}"


@requires_powershell
def test_markdown_report_matches_powershell(rich: dict[str, dict[str, str]]) -> None:
    assert rich["js"]["md"] == rich["ps"]["md"], _diff(rich["ps"]["md"], rich["js"]["md"])


@requires_powershell
def test_brief_matches_powershell(rich: dict[str, dict[str, str]]) -> None:
    assert rich["js"]["brief"] == rich["ps"]["brief"], _diff(rich["ps"]["brief"], rich["js"]["brief"])


@requires_powershell
def test_brief_layout(rich: dict[str, dict[str, str]]) -> None:
    lines = rich["js"]["brief"].split("\n")
    assert lines[0] == "# Environment brief: PC1"
    assert [line[3:] for line in lines if line.startswith("## ")] == list(BRIEF_HEADINGS)
    assert len(lines) <= 150
    assert "section could not be rendered" not in rich["js"]["brief"]
    assert "- never.ran" not in rich["js"]["brief"]  # no envelope: not listed (as ps)


@requires_powershell
def test_markdown_caps_and_code_spans(rich: dict[str, dict[str, str]]) -> None:
    md = rich["js"]["md"]
    assert "- many: item0, " in md and "(+290 more)" in md  # scalar lists stay inline
    assert "(+5 more)" in md
    assert "- alpha: `a*b_c`" in md
    assert "- tick: `` has ` backtick ``" in md
    assert "- when: 2026-01-02T03:04:05Z" in md
    assert "~~~~text" in md and "_raw output truncated_" in md


@pytest.mark.parametrize("statuses", [{}, {"os.identity": "timeout", "tools.inventory": "skipped",
                                          "net.proxy": "denied", "fs.locations": "error"}])
@requires_powershell
def test_sparse_brief_matches_powershell(built: Path, js_lib: Path, tmp_path: Path, statuses: dict[str, str]) -> None:
    # Probes that did not run or did not complete: every "none" must become "not checked".
    results = {pid: envelope(pid, status, error=("failed" if status == "error" else None))
               for pid, status in statuses.items()}
    report = make_report(results, [], redaction=False)
    ps = render_ps(built, tmp_path, report, results)
    js = render_js(js_lib, report, results)
    assert js["brief"] == ps["brief"], _diff(ps["brief"], js["brief"])
    assert js["md"] == ps["md"], _diff(ps["md"], js["md"])
    assert js["brief"].split("\n")[2].startswith("**REDACTION OFF (--no-redact)")


def test_brief_section_failure_is_contained(js_lib: Path) -> None:
    # A section that throws is reported in place; the other sections are still written.
    snippet = "\n".join([
        "ES_PROBES = [];",
        "ES_RESULTS = {'fs.semantics': {status: 'ok', data: {long_paths_enabled: true}}};",
        "ES_RESULTS['hw.memory'] = {status: 'ok', data: null};",
        "getEsBriefLimits = function () { throw new Error('boom'); };",
        "var report = {scanner: {version: '1', impl: 'jscript'}, host: {hostname: 'h'},",
        "  run: {started_utc: 's', tiers: ['default'], counts: {}, redaction: true}, findings: []};",
        "WScript.Echo(convertToEsBrief(report));",
    ])
    proc = run_js(js_lib, snippet)
    assert proc.returncode == 0, proc.stderr
    text = proc.stdout.replace("\r\n", "\n")
    assert "## Limits\n- (section could not be rendered: boom)\n\n## Not checked" in text
    assert "- Every probe completed." in text


# ------------------------------------------------------------------ WSH: the scanner ran without PowerShell

def wsh_results() -> dict[str, Any]:
    results = rich_results()
    results["shell.info"] = envelope("Shell", data={
        "current_shell": "cscript", "shell_version": "5.812", "script_engine": "JScript 5.8.16384", "edition": None,
        "language_mode": "WSH", "execution_policy": {"CurrentUser": "RemoteSigned", "LocalMachine": "Undefined"},
        "effective_policy": "RemoteSigned", "cmd_disabled": 0})
    return results


def brief_line(brief: str, prefix: str) -> str:
    lines = [line for line in brief.split("\n") if line.startswith(prefix)]
    assert len(lines) == 1, (prefix, lines)
    return lines[0]


def test_wsh_brief_names_the_script_host_not_powershell(js_lib: Path) -> None:
    results = wsh_results()
    brief = render_js(js_lib, make_report(results, FINDINGS), results)["brief"]
    shell = brief_line(brief, "- Shell: ")
    assert shell == ("- Shell: Windows Script Host 5.812, JScript 5.8.16384 (PowerShell not run; execution policy "
                     "RemoteSigned (Windows PowerShell would use: RemoteSigned) read from the registry); "
                     "cmd disabled by policy: no")
    control = brief_line(brief, "- Application control: ")
    assert control == "- Application control: none enforced"
    assert "language mode" not in brief


def test_wsh_brief_without_policy_data(js_lib: Path) -> None:
    results = wsh_results()
    results["shell.info"]["data"].update({"execution_policy": None, "script_engine": None})
    brief = render_js(js_lib, make_report(results, []), results)["brief"]
    assert brief_line(brief, "- Shell: ").startswith(
        "- Shell: Windows Script Host 5.812, unknown (PowerShell not run; execution policy unknown")
