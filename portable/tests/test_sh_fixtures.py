"""envscan.sh parsers against ENVSCAN_ROOT fixture trees (tests/fixtures/<name>/).

With ENVSCAN_ROOT set, the sh scanner reads /etc, /proc, /sys and /run under that root, so the
Linux parsers are exercised on any dev box. Commands (uname, ulimit, date) still describe the
real host, so only file-derived values are asserted here.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from conftest import DASH, find_output, load_report, schema_errors
from sh_helpers import FIXTURES, msys_path, needs_msys, run_scan

pytestmark = [pytest.mark.integration, needs_msys]

LINUX_PROBES = ("os.identity", "os.time_locale", "limits.kernel", "limits.cgroup", "net.ports", "net.interfaces",
                "net.routes", "net.dns", "net.listening", "net.proxy", "net.firewall", "fs.mounts")


@pytest.fixture(scope="module")
def linux(built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """One scan of tests/fixtures/linux-basic. ENVSCAN_ROOT is passed in Windows form, as a
    Windows test runner or CI agent would, which the scanner must accept under MSYS."""
    out = tmp_path_factory.mktemp("sh-fixture-linux")
    root = FIXTURES / "linux-basic"
    proc = run_scan(built / "dist" / "envscan.sh", out, ["--only", ",".join(LINUX_PROBES)],
                    env={"ENVSCAN_ROOT": str(root)}, timeout=600)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    return {"report": load_report(find_output(out)), "root": root}


def data(linux: dict[str, Any], probe: str) -> dict[str, Any]:
    entry = linux["report"]["probes"][probe]
    assert entry["status"] == "ok", (probe, entry.get("notes"), entry.get("error"))
    return entry["data"]


def test_report_records_the_test_root(linux: dict[str, Any]) -> None:
    report = linux["report"]
    assert schema_errors(report) == []
    assert report["run"]["test_root"] == msys_path(linux["root"])


def test_sources_name_real_paths_not_the_fixture(linux: dict[str, Any]) -> None:
    probes = linux["report"]["probes"]
    assert "read /etc/os-release" in probes["os.identity"]["sources"]
    for pid in LINUX_PROBES:
        for source in probes[pid].get("sources") or []:
            assert "fixtures" not in source, (pid, source)


def test_os_identity(linux: dict[str, Any]) -> None:
    d = data(linux, "os.identity")
    assert (d["name"], d["version"], d["distro_id"]) == ("Ubuntu 22.04.4 LTS", "22.04", "ubuntu")
    assert d["kernel"] == "5.15.0-105-generic"
    assert linux["report"]["host"]["os_name"] == "Ubuntu 22.04.4 LTS"


def test_timezone_from_etc_timezone(linux: dict[str, Any]) -> None:
    assert data(linux, "os.time_locale")["timezone"] == "Asia/Tokyo"


def test_kernel_limits(linux: dict[str, Any]) -> None:
    d = data(linux, "limits.kernel")
    assert d["fs.inotify.max_user_watches"] == 8192
    assert d["fs.inotify.max_user_instances"] == 128
    assert d["vm.max_map_count"] == 65530
    assert d["fs.file-max"] == 9223372036854775807
    assert d["transparent_hugepage"] == "madvise"
    assert d["kernel.yama.ptrace_scope"] is None
    # repeated DefaultLimitNOFILE: one key, the last value
    assert d["systemd_default_limits"] == {"system.DefaultLimitNOFILE": "65536", "system.DefaultLimitNPROC": "8192"}


def test_cgroup_v2_limits_take_the_tightest_ancestor(linux: dict[str, Any]) -> None:
    d = data(linux, "limits.cgroup")
    assert d["version"] == 2
    assert d["path"] == "/user.slice/user-1000.slice/session-3.scope"
    assert d["memory_max_bytes"] == 2147483648
    assert d["cpu_quota_cores"] == 1.5
    assert d["pids_max"] == 512


def test_ports(linux: dict[str, Any]) -> None:
    d = data(linux, "net.ports")
    assert d["ephemeral"] == {"start": 32768, "end": 60999}
    assert d["unprivileged_port_start"] == 1024


def test_routes_decoded_with_full_tunnel_vpn(linux: dict[str, Any]) -> None:
    d = data(linux, "net.routes")
    assert d["default_gateways"] == ["10.20.0.1 dev eth0", "(on-link) dev tun0", "fe80:0:0:0:0:0:0:1 dev eth0"]
    assert d["families_checked"] == ["ipv4", "ipv6"]
    assert d["routes"] == ["default via 10.20.0.1 dev eth0 metric 100", "10.20.0.0/16 dev eth0 metric 100",
                           "0.0.0.0/1 dev tun0", "128.0.0.0/1 dev tun0"]
    assert d["default_route"] is True


def test_interfaces_from_proc_net_dev(linux: dict[str, Any]) -> None:
    interfaces = {i["name"]: i for i in data(linux, "net.interfaces")["interfaces"]}
    assert sorted(interfaces) == ["eth0", "lo", "tun0"]
    assert interfaces["eth0"]["gateways"] == ["10.20.0.1"]
    assert interfaces["tun0"]["gateways"] == ["(on-link)"]


def test_dns(linux: dict[str, Any]) -> None:
    d = data(linux, "net.dns")
    assert d["servers"] == ["10.20.0.53", "10.20.0.54"]
    assert d["search"] == ["corp.example", "lab.corp.example"]
    assert d["options"] == ["ndots:2", "timeout:1"]
    assert d["resolver_order"] == "files dns"
    assert d["hosts_entries"] == ["127.0.0.1 localhost", "10.20.1.5 build01.corp.example build01"]


def test_listening_sockets_only_listen_state(linux: dict[str, Any]) -> None:
    tcp = data(linux, "net.listening")["tcp"]
    assert sorted((s["address"], s["port"]) for s in tcp) == [("0.0.0.0", 8080), ("127.0.0.1", 5432),
                                                             ("::1", 631), ("::ffff:10.20.1.5", 9090)]


def test_system_proxy_from_etc_environment(linux: dict[str, Any]) -> None:
    """Proxies are found by setting name (review finding 10): the pypi-proxy index URL in
    /etc/environment is not a proxy; apt's "DIRECT" exception is listed but sets no endpoint."""
    d = data(linux, "net.proxy")
    assert sorted(d["proxy_endpoints"]) == ["apt-cache.corp.example:3142", "proxy.corp.example:3128"]
    assert d["proxy_configured"] is True
    files = d["system"]["files"]
    assert {f["file"] for f in files} == {"/etc/environment", "/etc/apt/apt.conf.d/95proxy"}
    assert not [f for f in files if "pypi-proxy" in f["line"]]


def test_firewall_from_ufw_conf(linux: dict[str, Any]) -> None:
    assert data(linux, "net.firewall")["ufw"] == "enabled"


def test_findings_from_fixture_values(linux: dict[str, Any]) -> None:
    ids = {f["id"] for f in linux["report"]["findings"]}
    assert {"limits.inotify_low", "limits.max_map_count_low", "net.proxy_configured", "net.ports_in_use"} <= ids


def test_mount_points_are_decoded(linux: dict[str, Any]) -> None:
    mounts = {m["mount"]: m for m in data(linux, "fs.mounts")["mounts"]}
    assert "/mnt/data disk" in mounts
    assert r"/mnt/back\slash" in mounts
    assert mounts["/mnt/data disk"]["fstype"] == "ext4"


# ------------------------------------------------------------------ network mounts

def test_network_mounts_are_never_touched(built: Path, tmp_path: Path) -> None:
    """A HOME on an NFS mount (from the ENVSCAN_ROOT mount table): no config file there is read,
    no PATH entry there is searched or run, no write test is made there, and without --out the
    report goes to the next candidate (TMPDIR) instead of the network current directory."""
    marker = tmp_path / "executed.log"
    nethome = tmp_path / "nethome"
    (nethome / "bin").mkdir(parents=True)
    (nethome / ".npmrc").write_text("registry=https://npm.net-mount.example/\n", encoding="ascii")
    stub = f'#!/bin/sh\nprintf "%s\n" "$0 $*" >>"{msys_path(marker)}"\necho "v99.0.0"\n'
    (nethome / "bin" / "node").write_text(stub, encoding="ascii", newline="\n")
    root = tmp_path / "root"
    (root / "proc" / "self").mkdir(parents=True)
    # the same directory as MSYS may name it: /c/... and, under %TEMP%, /tmp/...
    names = {msys_path(nethome)}
    temp = Path(os.environ.get("TEMP", "")).resolve()
    if temp.parts and nethome.resolve().is_relative_to(temp):
        names.add("/tmp/" + nethome.resolve().relative_to(temp).as_posix())
    table = "/dev/sda1 / ext4 rw 0 0\n" + "".join(f"srv:/export/home {n} nfs4 rw,vers=4.2 0 0\n" for n in sorted(names))
    (root / "proc" / "self" / "mounts").write_text(table, encoding="ascii", newline="\n")
    tmpdir = tmp_path / "tmpd"
    tmpdir.mkdir()
    env = {"ENVSCAN_ROOT": str(root), "HOME": msys_path(nethome), "TMPDIR": msys_path(tmpdir),
           "PATH": str(nethome / "bin") + os.pathsep + os.environ.get("PATH", "")}
    probes = "fs.locations,pkg.sources,env.path,tools.inventory"
    proc = subprocess.run([str(DASH), str(built / "dist" / "envscan.sh"), "--only", probes], capture_output=True,
                          text=True, encoding="utf-8", errors="replace", env={**os.environ, **env}, timeout=600,
                          stdin=subprocess.DEVNULL, cwd=nethome)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    assert not marker.exists(), marker.read_text()
    assert not list(nethome.glob("envscan-*")), "the report must not be written to a network directory"
    report = load_report(find_output(tmpdir))
    p = report["probes"]
    home = {loc["id"]: loc for loc in p["fs.locations"]["data"]["locations"]}["home"]
    assert home["network"] is True and home["exists"] is None and "network" in home["note"]
    # skipped locations are unknown, not "not writable": no install-dir blocker from them (finding 7)
    assert "fs.no_writable_install_dir" not in {f["id"] for f in report["findings"]}
    assert not list(nethome.glob(".envscan-*"))
    assert "net-mount.example" not in json.dumps(p["pkg.sources"]["data"])
    assert any("network or autofs" in n for n in p["pkg.sources"].get("notes") or []), p["pkg.sources"].get("notes")
    node = p["tools.inventory"]["data"]["tools"].get("node") or {}
    assert all("nethome" not in path for path in node.get("paths") or []), node
