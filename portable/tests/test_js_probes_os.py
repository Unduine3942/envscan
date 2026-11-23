"""envscan.js OS, hardware, session and virtualization probes (src/js/20-probes-os.js, 20-probes-virt.js).

Each probe runs on this machine in cscript (tests/js_harness.py) and in Windows PowerShell
(build/lib/envscan-lib.ps1); the stable facts must be equal and the data keys the same.
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

PROBES = ("os.identity", "os.time_locale", "os.health", "os.updates", "hw.cpu", "hw.memory", "hw.storage",
          "hw.gpu", "session.context", "virt.platform")

JS_INIT = "initializeEsRedaction(); saveEsEnvSnapshot(); initializeEsTemp(); initializeEsDrives();"
PS_INIT = "Initialize-EsRedaction; Save-EsEnvSnapshot; Initialize-EsDrives"


def js_snippet(ids: tuple[str, ...], lib: Path) -> str:
    worker = str(lib.parents[2] / "dist" / "envscan.js").replace("\\", "\\\\")
    calls = "\n".join(f'out["{pid}"] = probe_{pid.replace(".", "_")}();' for pid in ids)
    head = f'ES_WORKER_SCRIPT = "{worker}";'
    return "\n".join([head, JS_INIT, "var out = {};", calls, "removeEsTemp();", "WScript.Echo(convertToEsJson(out));"])


def run_js_probes(lib: Path, ids: tuple[str, ...], env: dict[str, str] | None = None) -> dict[str, Any]:
    proc = js_harness.run_js(lib, js_snippet(ids, lib), env=env or scrubbed_env())
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def run_ps_probes(lib: Path, ids: tuple[str, ...]) -> dict[str, Any]:
    names = ", ".join(f"'{pid}'" for pid in ids)
    command = (f". {ps_quote(lib)}; {PS_INIT}; $out = @{{}}; foreach ($id in @({names})) "
               "{ $out[$id] = & ('probe_' + ($id -replace '\\.', '_')) }; ConvertTo-EsJson $out")
    proc = ps_command(command, timeout=600)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def js_lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    _, lib = js_harness.build_js(tmp_path_factory.mktemp("jsos"))
    return lib


@pytest.fixture(scope="module")
def pair(js_lib: Path, built: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    js = run_js_probes(js_lib, PROBES)
    ps = run_ps_probes(built / "build" / "lib" / "envscan-lib.ps1", PROBES)
    return js, ps


def data(results: dict[str, Any], pid: str) -> dict[str, Any]:
    return results[pid]["data"]


def assert_same_keys(pair: tuple[dict, dict], pid: str, extra: set[str] = frozenset()) -> None:
    js, ps = pair
    assert set(data(js, pid)) - set(extra) == set(data(ps, pid)), pid


def assert_equal_facts(pair: tuple[dict, dict], pid: str, keys: tuple[str, ...]) -> None:
    js, ps = pair
    for key in keys:
        assert data(js, pid)[key] == data(ps, pid)[key], f"{pid}.{key}"


@pytest.mark.parametrize("pid", PROBES)
def test_status_and_keys_match_ps(pair: tuple[dict, dict], pid: str) -> None:
    js, ps = pair
    expected = "partial" if pid == "virt.platform" else ps[pid]["status"]
    assert js[pid]["status"] == expected, (pid, js[pid]["notes"], ps[pid]["notes"])
    assert_same_keys(pair, pid)
    assert js[pid]["sources"], pid


def test_os_identity(pair: tuple[dict, dict]) -> None:
    assert_equal_facts(pair, "os.identity", (
        "family", "name", "version", "build", "display_version", "edition", "install_type", "kernel", "product_type",
        "install_date_utc", "system_root", "arch", "process_arch", "userland_bits", "architecture_code", "wow64_process",
        "hostname", "domain", "domain_joined", "fqdn", "directory_joined", "wsl"))


def test_os_time_locale(pair: tuple[dict, dict]) -> None:
    assert_equal_facts(pair, "os.time_locale", (
        "utc_offset", "timezone", "timezone_display", "locale", "ui_locale", "system_locale", "decimal_separator",
        "thousands_separator", "date_format", "list_separator", "codepage_ansi", "codepage_oem", "codepage_console",
        "utf8_system_codepage", "encoding", "virtual_terminal_level"))


def test_os_health(pair: tuple[dict, dict]) -> None:
    assert_equal_facts(pair, "os.health", ("last_boot_utc", "pending_reboot", "pending_reasons", "load"))
    js, ps = pair
    assert abs(data(js, "os.health")["uptime_seconds"] - data(ps, "os.health")["uptime_seconds"]) < 300


def test_os_updates(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    assert data(js, "os.updates")["count"] == data(ps, "os.updates")["count"]
    assert sorted(h["id"] for h in data(js, "os.updates")["hotfixes"]) == sorted(h["id"] for h in data(ps, "os.updates")["hotfixes"])
    assert data(js, "os.updates")["hotfixes"] == data(ps, "os.updates")["hotfixes"]


def test_hw_cpu(pair: tuple[dict, dict]) -> None:
    assert_equal_facts(pair, "hw.cpu", ("model", "vendor", "sockets", "cores", "logical", "max_clock_mhz",
                                        "architecture_code", "virtualization_firmware_enabled", "l3_cache_kb", "identifier"))


def test_hw_memory(pair: tuple[dict, dict]) -> None:
    assert_equal_facts(pair, "hw.memory", ("total_mb", "commit_limit_mb", "swap_total_mb"))
    js, ps = pair
    assert [p["path"] for p in data(js, "hw.memory")["pagefiles"]] == [p["path"] for p in data(ps, "hw.memory")["pagefiles"]]
    assert abs(data(js, "hw.memory")["available_mb"] - data(ps, "hw.memory")["available_mb"]) < 4096


def test_hw_storage(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    stable = ("mount", "device", "fstype", "label", "kind", "total_mb", "network", "removable")
    left = sorted((tuple(v[k] for k in stable) for v in data(js, "hw.storage")["volumes"]))
    right = sorted((tuple(v[k] for k in stable) for v in data(ps, "hw.storage")["volumes"]))
    assert left == right
    for volume in data(js, "hw.storage")["volumes"]:
        assert set(volume) == {*stable, "free_mb"}


def test_hw_gpu(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    assert data(js, "hw.gpu")["gpus"] == data(ps, "hw.gpu")["gpus"]
    assert js["hw.gpu"]["notes"] == ps["hw.gpu"]["notes"]


def test_session_context(pair: tuple[dict, dict]) -> None:
    assert_equal_facts(pair, "session.context", ("type", "session_name", "session_id", "display", "interactive", "dpi", "tty"))
    js, _ = pair
    assert data(js, "session.context")["host_name"].lower() == "cscript.exe"


def test_virt_platform(pair: tuple[dict, dict]) -> None:
    js, ps = pair
    left = dict(data(js, "virt.platform"))
    right = dict(data(ps, "virt.platform"))
    # FSO cannot test a named pipe: unknown in WSH (partial, noted).
    assert left.pop("docker_socket") == {"path": "\\\\.\\pipe\\docker_engine", "accessible": None}
    right.pop("docker_socket")
    assert left == right
    assert js["virt.platform"]["status"] == "partial"


def test_virt_engine_needs_tools_inventory(js_lib: Path) -> None:
    proc = js_harness.run_js(js_lib, "var r = probe_virt_engine(); WScript.Echo(convertToEsJson(r));", env=scrubbed_env())
    result = json.loads(proc.stdout)
    assert result["status"] == "error" and "tools.inventory" in result["error"]


def test_helpers(js_lib: Path) -> None:
    snippet = r"""
var out = {
  arch: [convertToEsArch("AMD64"), convertToEsArch("x86"), convertToEsArch("ARM64"), convertToEsArch("ARMv7"), convertToEsArch("IA64"), convertToEsArch("MIPS"), convertToEsArch("")],
  vm: [getEsVmProduct("innotek GmbH VirtualBox"), getEsVmProduct("Microsoft Corporation Virtual Machine"), getEsVmProduct("Dell Inc. XPS"), getEsVmProduct("QEMU Standard PC")],
  round: [jsOs_round(2.5), jsOs_round(3.5), jsOs_round(2.4), jsOs_round(2.6)],
  culture: [jsOs_cultureName("en-us"), jsOs_cultureName("zh-hans-cn"), jsOs_cultureName("de")],
  lcid: jsOs_lcidName("00000409"),
  domain: getEsDomainFacts({ PartOfDomain: true, Domain: "Corp.Example", DNSHostName: "PC1", Workgroup: null }),
  workgroup: getEsDomainFacts({ PartOfDomain: false, Domain: "WORKGROUP", DNSHostName: "PC1", Workgroup: "WORKGROUP" }),
  unknown: getEsDomainFacts(null)
};
WScript.Echo(convertToEsJson(out));
"""
    proc = js_harness.run_js(js_lib, snippet, env=scrubbed_env())
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    out = json.loads(proc.stdout)
    assert out["arch"] == ["x86_64", "x86", "arm64", "arm", "ia64", "other", None]
    assert out["vm"] == ["VirtualBox", "Hyper-V", None, "KVM/QEMU"]
    assert out["round"] == [2, 4, 2, 3]
    assert out["culture"] == ["en-US", "zh-Hans-CN", "de"]
    assert out["lcid"] == "en-US"
    assert out["domain"] == {"domain": "Corp.Example", "domain_joined": True, "fqdn": "pc1.corp.example"}
    assert out["workgroup"] == {"domain": None, "domain_joined": False, "fqdn": None, "workgroup": "WORKGROUP"}
    assert out["unknown"] == {"domain": None, "domain_joined": None, "fqdn": None}
