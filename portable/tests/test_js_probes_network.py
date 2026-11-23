"""The network probes of the Windows Script Host port (src/js/25-probes-*.js).

Each probe runs on this machine through the JScript runner and is compared with the
PowerShell result of the same probe (dist/envscan.ps1 --only <ids>). The pure helpers
(proxy blob, address rules, reachability skip reasons) are compared case by case with the
PowerShell library. Nothing here touches the network: net.reachability is run on fake
net.proxy/pkg.sources data with every command runner replaced by a recorder, and the WSH
port must not run any command or contact anything.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import HAVE_POWERSHELL, find_output, load_report, ps_eval, requires_powershell, run_ps, scrubbed_env
from js_harness import HAVE_CSCRIPT, build_js, run_js

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

NET_IDS = ("net.ports", "net.interfaces", "net.routes", "net.dns", "net.proxy", "net.listening", "net.firewall")
IPV6_WHY = "IPv6 address outside the global and unique-local ranges; never contacted"
PUBLIC_V4_WHY = "public IPv4 address; never contacted"
NET_NEVER_WHY = "cloud metadata or link-local address; never contacted"
PUBLIC_WHY = "public registry; only internal mirrors and proxies are checked"
WSH_WHY = "TCP reachability is not available in the WSH port; never contacted"
SKIPPED_FIELDS = {"host", "port", "source", "tcp", "reason"}

# Initialises the engine like a scan (temp folder, environment snapshot, redaction), runs the
# given probes through the runner in order and prints {id: envelope}; removes the temp folder.
JS_RUN_PROBES = """
var esIds = WScript.Arguments.Item(0).split(",");
var esOut = {};
jsTest_init();
try {
    for (var esI = 0; esI < esIds.length; esI++) { esOut[esIds[esI]] = jsTest_run(esIds[esI]); }
} finally { jsTest_done(); }
WScript.Echo(convertToEsJson(esOut));
"""


def js_prelude() -> str:
    """Test-only engine set-up: the same steps as invokeEnvScan before the probe loop. The library
    has no entry point, so the snippet itself serves as the WMI worker (ES_SCRIPT_PATH is the
    snippet file, which the engine starts with --es-wmi-worker <request> <reply>)."""
    return """
if (WScript.Arguments.length === 3 && WScript.Arguments.Item(0) === ES_WORKER_OPTION) {
    WScript.Quit(invokeEsWmiWorker(WScript.Arguments.Item(1), WScript.Arguments.Item(2)) === 0 ? 0 : 2);
}
function jsTest_init() {
    saveEsEnvSnapshot();
    initializeEsRedaction();
    initializeEsTemp();
    initializeEsDrives();
    enterEsChildEnv();
    ES_OPT.deep = true;
    ES_OPT.net = true;
}
function jsTest_done() { exitEsChildEnv(); removeEsTemp(); }
function jsTest_meta(id) {
    for (var i = 0; i < ES_PROBES.length; i++) { if (ES_PROBES[i].id == id) { return ES_PROBES[i]; } }
    throw new Error("no probe " + id);
}
function jsTest_run(id) { return invokeEsProbe(jsTest_meta(id)); }
function jsTest_fake(id, status, data) { ES_RESULTS[id] = { status: status, data: data, notes: [] }; }
"""


def js_json(lib: Path, snippet: str, *args: str, env: dict[str, str] | None = None) -> Any:
    proc = run_js(lib, js_prelude() + snippet, *args, env=env if env is not None else scrubbed_env())
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def js_probes(lib: Path, ids: tuple[str, ...], cwd_env: dict[str, str] | None = None) -> dict[str, Any]:
    return js_json(lib, JS_RUN_PROBES, ",".join(ids), env=cwd_env)


def ps_probes(built: Path, ids: tuple[str, ...], out: Path, *extra: str) -> dict[str, Any]:
    proc = run_ps(built / "dist" / "envscan.ps1", ["--only", ",".join(ids), "--out", str(out), *extra])
    assert proc.returncode in (0, 1), proc.stderr
    return load_report(find_output(out))["probes"]


@pytest.fixture(scope="module")
def lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_js(tmp_path_factory.mktemp("jsnet"))[1]


@pytest.fixture(scope="module")
def js_net(lib: Path) -> dict[str, Any]:
    return js_probes(lib, NET_IDS)


@pytest.fixture(scope="module")
def ps_net(built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    if not HAVE_POWERSHELL:
        pytest.skip("needs Windows PowerShell")
    return ps_probes(built, NET_IDS, tmp_path_factory.mktemp("psnet"))


# ------------------------------------------------------------------ this machine, compared with ps

@pytest.mark.parametrize("probe_id", NET_IDS)
def test_status_equals_ps(js_net: dict[str, Any], ps_net: dict[str, Any], probe_id: str) -> None:
    assert js_net[probe_id]["status"] == ps_net[probe_id]["status"], (js_net[probe_id], ps_net[probe_id]["notes"])


@pytest.mark.parametrize("probe_id", NET_IDS)
def test_data_keys_equal_ps(js_net: dict[str, Any], ps_net: dict[str, Any], probe_id: str) -> None:
    assert set(js_net[probe_id]["data"]) == set(ps_net[probe_id]["data"])


def test_ports_equal_ps(js_net: dict[str, Any], ps_net: dict[str, Any]) -> None:
    js, ps = js_net["net.ports"]["data"], ps_net["net.ports"]["data"]
    for key in ("excluded_tcp", "ephemeral", "urlacl_count", "urlacl", "common_ports_excluded", "unprivileged_port_start"):
        assert js[key] == ps[key], key


def test_interfaces_equal_ps(js_net: dict[str, Any], ps_net: dict[str, Any]) -> None:
    js = {i["mac"] + i["description"]: i for i in js_net["net.interfaces"]["data"]["interfaces"]}
    ps = {i["mac"] + i["description"]: i for i in ps_net["net.interfaces"]["data"]["interfaces"]}
    assert set(js) == set(ps)
    for key, item in ps.items():
        # The link speed of a wireless adapter changes from one second to the next.
        volatile = ("speed_mbps",) if "wi-fi" in item["description"].lower() or "wireless" in item["description"].lower() else ()
        assert {k: v for k, v in js[key].items() if k not in volatile} == {k: v for k, v in item.items() if k not in volatile}, key


def test_routes_equal_ps(js_net: dict[str, Any], ps_net: dict[str, Any]) -> None:
    js, ps = js_net["net.routes"]["data"], ps_net["net.routes"]["data"]
    assert js["default_gateways"] == ps["default_gateways"]
    assert js["default_route_count"] == ps["default_route_count"]
    # Routes may change between the two runs (DHCP, VPN); most must be the same.
    common = set(js["routes"]) & set(ps["routes"])
    assert len(common) >= 0.9 * max(len(ps["routes"]), 1), (js["routes"], ps["routes"])


def test_dns_equals_ps(js_net: dict[str, Any], ps_net: dict[str, Any]) -> None:
    assert js_net["net.dns"]["data"] == ps_net["net.dns"]["data"]


def test_proxy_equals_ps(js_net: dict[str, Any], ps_net: dict[str, Any]) -> None:
    js, ps = js_net["net.proxy"]["data"], ps_net["net.proxy"]["data"]
    for key in ("env", "winhttp", "wininet", "policy", "package_managers", "any_proxy"):
        assert js[key] == ps[key], key
    assert sorted(map(json.dumps, js["proxy_endpoints"])) == sorted(map(json.dumps, ps["proxy_endpoints"]))
    assert "pkg.sources is " in " | ".join(js_net["net.proxy"]["notes"])


def test_listening_matches_ps(js_net: dict[str, Any], ps_net: dict[str, Any]) -> None:
    js, ps = js_net["net.listening"]["data"], ps_net["net.listening"]["data"]
    assert js["ports"] == sorted(js["ports"])
    common = set(js["ports"]) & set(ps["ports"])
    assert len(common) >= 0.8 * max(len(ps["ports"]), 1), (js["ports"], ps["ports"])
    names = {(t["port"], t["address"]): t["process"] for t in ps["tcp"]}
    same = [t for t in js["tcp"] if names.get((t["port"], t["address"]), t["process"]) == t["process"]]
    assert len(same) >= 0.8 * len(js["tcp"]), js["tcp"]


def test_firewall_equals_ps(js_net: dict[str, Any], ps_net: dict[str, Any]) -> None:
    assert js_net["net.firewall"]["data"] == ps_net["net.firewall"]["data"]


def test_netstat_lists_listening_sockets(lib: Path) -> None:
    got = js_probes(lib, ("net.netstat",))["net.netstat"]
    assert got["status"] == "ok", got
    assert got["data"]["tcp_listening"], got
    assert any(s.endswith("netstat.exe -ano") for s in got["sources"]), got["sources"]
    item = got["data"]["tcp_listening"][0]
    assert set(item) == {"address", "port", "pid"}


# ------------------------------------------------------------------ pure helpers, compared with ps

PROXY_BLOBS = {
    "proxy": [40, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 15, 0, 0, 0, *b"proxy.corp:8080", 7, 0, 0, 0, *b"<local>"],
    "direct": [24, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    "pac": [70, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, *b"http://wpad.corp/p.pac"],
    "short": [1, 2, 3],
    "cut": [40, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 99, 0, 0, 0, *b"abc"],
}
SERVER_VALUES = ("proxy:8080", "http=a.corp:80;https=b.corp:443", " ; ftp=c:21 ;", "")
IPV6_VALUES = ("2001:db8::1", "2000::", "3fff:ffff::1", "1fff::1", "4000::1", "fc00::1", "FDFF::1", "fe00::1",
               "fe80::1", "fd00:ec2::254", "fd00:0ec2::1", "fd00:ec20::1", "fd00::ec2", "::1", "::ffff:10.0.0.1",
               "64:ff9b::a00:1", "ff02::1", "2001:db8::1%3", "[2001:db8::1]", "02001::1", "g001::1", "10.0.0.1")
IPV4_VALUES = ("10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "172.15.0.1", "172.32.0.1",
               "192.168.0.1", "192.169.0.1", "100.64.0.1", "100.127.255.255", "100.63.0.1", "100.128.0.1", "8.8.8.8",
               "127.0.0.1", "0.0.0.0", "255.255.255.255", "010.0.0.1", "10.0.0.256", "10.0.0", "fd00::1")
REACH_HOSTS = ("proxy.corp.example", "registry.npmjs.org", "registry.npmjs.org.", "pypi.org", "files.pythonhosted.org",
               "metadata.google.internal", "169.254.169.254", "::1", "fd00:ec2::7", "4000::1", "fe80::1%4", "8.8.8.8",
               "172.32.0.1", "100.128.0.1", "127.0.0.1", "192.0.0.192", "fd20:ce::254", "2002:c000:204::1",
               "2001:db8::5", "3fff::1", "10.1.2.3", "Registry.NPMJS.org", "nexus.corp.example", "npmjs.org.evil.example",
               "notnpmjs.org", "[fe80::1]", "100.64.0.1")
ADDRESS_LISTS = (["10.0.0.5", "fe80::1%12"], ["8.8.8.8", "2001:db8::10", "10.0.0.7"], ["fe80::1", "4000::1"],
                 ["2001:db8::5", "fd12::1"], [])


def js_list(values: Any) -> str:
    return json.dumps(values)


def ps_list(values: list[Any]) -> str:
    if not values:
        return "@()"
    return "@(" + ", ".join("'" + str(v).replace("'", "''") + "'" if isinstance(v, str) else str(v) for v in values) + ")"


HELPER_SNIPPET_JS = """
var esOut = { blob: {}, servers: {}, v6: {}, v4: {}, skip: {}, select: [] };
var esBlobs = %(blobs)s;
for (var k in esBlobs) { esOut.blob[k] = convertFromEsProxyBlob(esBlobs[k]); }
var esServers = %(servers)s;
for (var i = 0; i < esServers.length; i++) { esOut.servers[esServers[i]] = getEsProxyServers(esServers[i]); }
var esV6 = %(v6)s;
for (var i = 0; i < esV6.length; i++) { esOut.v6[esV6[i]] = testEsIpv6Allowed(esV6[i]); }
var esV4 = %(v4)s;
for (var i = 0; i < esV4.length; i++) { esOut.v4[esV4[i]] = testEsIpv4Allowed(esV4[i]); }
var esHosts = %(hosts)s;
for (var i = 0; i < esHosts.length; i++) { esOut.skip[esHosts[i]] = getEsReachSkipReason(esHosts[i]); }
var esLists = %(lists)s;
for (var i = 0; i < esLists.length; i++) { esOut.select.push(selectEsReachAddress(esLists[i])); }
WScript.Echo(convertToEsJson(esOut));
"""


def helper_ps_expression() -> str:
    blobs = "; ".join(f"$o.blob['{k}'] = ConvertFrom-EsProxyBlob ([byte[]]{ps_list(v)})" for k, v in PROXY_BLOBS.items())
    return (
        "$o = @{ blob = @{}; servers = @{}; v6 = @{}; v4 = @{}; skip = @{}; select = @() }; " + blobs + "; "
        f"foreach ($s in {ps_list(list(SERVER_VALUES))}) {{ $o.servers[$s] = @(Get-EsProxyServers $s) }}; "
        f"foreach ($s in {ps_list(list(IPV6_VALUES))}) {{ $o.v6[$s] = Test-EsIpv6Allowed $s }}; "
        f"foreach ($s in {ps_list(list(IPV4_VALUES))}) {{ $o.v4[$s] = Test-EsIpv4Allowed $s }}; "
        f"foreach ($s in {ps_list(list(REACH_HOSTS))}) {{ $o.skip[$s] = Get-EsReachSkipReason $s }}; "
        + "; ".join(f"$o.select += , (Select-EsReachAddress {ps_list(v)})" for v in ADDRESS_LISTS) + "; "
        "ConvertTo-EsJson $o"
    )


@pytest.fixture(scope="module")
def js_helpers(lib: Path) -> dict[str, Any]:
    snippet = HELPER_SNIPPET_JS % {
        "blobs": js_list(PROXY_BLOBS), "servers": js_list(SERVER_VALUES), "v6": js_list(IPV6_VALUES),
        "v4": js_list(IPV4_VALUES), "hosts": js_list(REACH_HOSTS), "lists": js_list(ADDRESS_LISTS),
    }
    return js_json(lib, snippet)


@pytest.fixture(scope="module")
def ps_helpers(built: Path) -> dict[str, Any]:
    proc = ps_eval(built / "build" / "lib" / "envscan-lib.ps1", helper_ps_expression())
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


@requires_powershell
@pytest.mark.parametrize("part", ["blob", "v6", "v4", "skip", "select"])
def test_helpers_equal_ps(js_helpers: dict[str, Any], ps_helpers: dict[str, Any], part: str) -> None:
    if isinstance(ps_helpers[part], dict):
        # PowerShell tables ignore case: keys differing only by case are one entry there.
        assert {k.lower() for k in js_helpers[part]} == {k.lower() for k in ps_helpers[part]}
        assert {k: js_helpers[part][k] for k in ps_helpers[part]} == ps_helpers[part]
    else:
        assert js_helpers[part] == ps_helpers[part]


@requires_powershell
def test_proxy_servers_equal_ps(js_helpers: dict[str, Any], ps_helpers: dict[str, Any]) -> None:
    # An empty value is a key the PowerShell table keeps too; compare value lists.
    for value in SERVER_VALUES:
        assert js_helpers["servers"][value] == ps_helpers["servers"].get(value, []), value


def test_skip_reasons(js_helpers: dict[str, Any]) -> None:
    skip = js_helpers["skip"]
    assert skip["registry.npmjs.org."] == PUBLIC_WHY and skip["Registry.NPMJS.org"] == PUBLIC_WHY
    assert skip["notnpmjs.org"] is None and skip["npmjs.org.evil.example"] is None
    for host in ("::1", "fd00:ec2::7", "4000::1"):
        assert skip[host] == IPV6_WHY, host
    for host in ("8.8.8.8", "172.32.0.1", "100.128.0.1", "127.0.0.1"):
        assert skip[host] == PUBLIC_V4_WHY, host
    for host in ("fe80::1%4", "192.0.0.192", "fd20:ce::254", "2002:c000:204::1", "169.254.169.254", "[fe80::1]"):
        assert skip[host] == NET_NEVER_WHY, host
    for host in ("2001:db8::5", "3fff::1", "10.1.2.3", "proxy.corp.example", "100.64.0.1"):
        assert skip[host] is None, host


# ------------------------------------------------------------------ net.reachability: nothing is contacted

REACH_SNIPPET = """
var esCalls = [];
function invokeEsCommand(filePath, args) { esCalls.push(String(filePath)); throw new Error("no command may run"); }
function invokeEsTool(result, label, filePath) { esCalls.push(String(filePath)); throw new Error("no command may run"); }
jsTest_init();
var esOut = {};
try {
    %(setup)s
    var esR = probe_net_reachability();
    esOut = { status: esR.status, targets: esR.data.targets, notes: esR.notes, sources: esR.sources, calls: esCalls };
} finally { jsTest_done(); }
WScript.Echo(convertToEsJson(esOut));
"""

REACH_SETUP = """
jsTest_fake("net.proxy", "ok", { proxy_endpoints: [
    { host: "proxy.corp.example", port: 8080, source: "env HTTP_PROXY" },
    { host: "registry.npmjs.org", port: 443, source: "config npm" },
    { host: "metadata.google.internal", port: 80, source: "config x" },
    { host: "169.254.169.254", port: 80, source: "config y" },
    { host: "8.8.8.8", port: 3128, source: "config z" },
    { host: "fe80::1%4", port: 3128, source: "config z" },
    { host: "2001:db8::5", port: 3128, source: "config z" },
    { host: "PROXY.corp.example", port: 8080, source: "env https_proxy" }] });
jsTest_fake("pkg.sources", "ok", { endpoints: ["https://pypi.org", "https://files.pythonhosted.org",
    "https://nexus.corp.example:8443", "https://rebind.corp.example", "http://10.0.0.9:8081/x"] });
"""


def reach(lib: Path, setup: str) -> dict[str, Any]:
    return js_json(lib, REACH_SNIPPET % {"setup": setup})


def test_reachability_contacts_nothing_and_lists_targets(lib: Path) -> None:
    got = reach(lib, REACH_SETUP)
    assert got["calls"] == []
    assert got["status"] == "not_applicable"
    assert "TCP reachability is not available in the WSH port; use envscan.ps1 or envscan.sh" in got["notes"]
    targets = {t["host"]: t for t in got["targets"]}
    expected = {
        "proxy.corp.example": WSH_WHY, "registry.npmjs.org": PUBLIC_WHY, "metadata.google.internal": NET_NEVER_WHY,
        "169.254.169.254": NET_NEVER_WHY, "8.8.8.8": PUBLIC_V4_WHY, "fe80::1%4": NET_NEVER_WHY,
        "2001:db8::5": WSH_WHY, "pypi.org": PUBLIC_WHY, "files.pythonhosted.org": PUBLIC_WHY,
        "nexus.corp.example": WSH_WHY, "rebind.corp.example": WSH_WHY, "10.0.0.9": WSH_WHY,
    }
    assert {host: t["reason"] for host, t in targets.items()} == expected
    for target in got["targets"]:
        assert set(target) == SKIPPED_FIELDS and target["tcp"] == "skipped", target
    # De-duplicated by host:port ignoring case, the first one kept.
    assert len(got["targets"]) == len(expected)
    assert targets["proxy.corp.example"]["source"] == "env HTTP_PROXY"
    assert targets["nexus.corp.example"]["port"] == 8443


def test_reachability_cap_counts_only_checked_targets(lib: Path) -> None:
    endpoints = ", ".join(f'{{ host: "h{i}.corp.example", port: 80, source: "c" }}' for i in range(25))
    setup = (f'jsTest_fake("net.proxy", "ok", {{ proxy_endpoints: [{{ host: "pypi.org", port: 443, source: "c" }}, {endpoints}] }});'
             'jsTest_fake("pkg.sources", "ok", { endpoints: [] });')
    got = reach(lib, setup)
    assert len(got["targets"]) == 21 and got["calls"] == []
    assert "5 more endpoint(s) not checked (at most 20)" in got["notes"]


def test_reachability_without_endpoints_is_not_found(lib: Path) -> None:
    got = reach(lib, 'jsTest_fake("net.proxy", "ok", { proxy_endpoints: [] }); jsTest_fake("pkg.sources", "ok", {});')
    assert (got["status"], got["targets"], got["calls"]) == ("not_found", [], [])
    assert "no proxy or mirror endpoint was found in local configuration" in got["notes"]


def test_reachability_without_inputs_is_partial(lib: Path) -> None:
    got = reach(lib, "")
    assert got["status"] == "partial" and got["calls"] == []
    joined = " | ".join(got["notes"])
    assert "net.proxy is not run" in joined and "pkg.sources is not run" in joined


def test_net_tier_runs_no_command(lib: Path) -> None:
    # net.proxy and net.reachability through the runner with the real command runner: neither
    # starts any command (no nslookup, ping or curl), so nothing can be contacted.
    snippet = """
jsTest_init();
var esOut = {};
try {
    var esIds = ["net.proxy", "net.reachability"];
    for (var i = 0; i < esIds.length; i++) { esOut[esIds[i]] = jsTest_run(esIds[i]).status; }
} finally { jsTest_done(); }
esOut.cmd_seq = ES_CMD_SEQ;
WScript.Echo(convertToEsJson(esOut));
"""
    got = js_json(lib, snippet)
    assert got["cmd_seq"] == 0, got
    assert got["net.reachability"] in ("not_applicable", "not_found", "partial"), got


SINGLE_LABEL_WHY = "single-label name; DNS search domains could expand it, so it is not looked up"


def test_reachability_skips_single_label_names(lib: Path) -> None:
    # "proxy" and "proxy." would be completed with the DNS search list: skipped, never counted.
    endpoints = ", ".join(f'{{ host: "h{i}.corp.example", port: 80, source: "c" }}' for i in range(20))
    setup = ('jsTest_fake("net.proxy", "ok", { proxy_endpoints: ['
             '{ host: "proxy", port: 3128, source: "env HTTP_PROXY" }, { host: "proxy.", port: 8080, source: "c" }, '
             '{ host: "localhost", port: 1, source: "c" }, { host: "proxy.corp", port: 3128, source: "c" }, '
             '{ host: "fd12::1", port: 3128, source: "c" }, '
             f'{endpoints}] }}); jsTest_fake("pkg.sources", "ok", {{ endpoints: [] }});')
    got = reach(lib, setup)
    assert got["calls"] == []
    reasons = {t["host"]: t["reason"] for t in got["targets"]}
    assert reasons["proxy"] == SINGLE_LABEL_WHY
    assert reasons["proxy."] == SINGLE_LABEL_WHY
    assert reasons["localhost"] == SINGLE_LABEL_WHY
    assert reasons["proxy.corp"] == WSH_WHY and reasons["fd12::1"] == WSH_WHY
    # The three skipped names do not count against the cap: 22 lookups wanted, 20 allowed.
    assert "2 more endpoint(s) not checked (at most 20)" in got["notes"]


MALFORMED_WHY = "malformed host name; not looked up"


def test_reachability_skips_malformed_names_and_dotted_ipv4_literals(lib: Path) -> None:
    # Review 2026-11-15 (X4): after one trailing dot is removed, an empty name, a leading "." or
    # ".." is malformed; an IPv4 literal written with a trailing dot is never contacted. None of
    # them counts against the cap.
    hosts = {".": MALFORMED_WHY, "..": MALFORMED_WHY, ".corp.example": MALFORMED_WHY,
             "a..corp.example": MALFORMED_WHY, "a..corp.example.": MALFORMED_WHY, "host..": MALFORMED_WHY, "proxy.corp..": MALFORMED_WHY,
             "10.0.0.1.": PUBLIC_V4_WHY, "192.168.1.1.": PUBLIC_V4_WHY, "8.8.8.8.": PUBLIC_V4_WHY,
             "10.0.0.1": WSH_WHY, "proxy.corp.": WSH_WHY}
    listed = ", ".join(f'{{ host: {json.dumps(h)}, port: 3128, source: "c" }}' for h in hosts)
    endpoints = ", ".join(f'{{ host: "h{i}.corp.example", port: 80, source: "c" }}' for i in range(19))
    setup = (f'jsTest_fake("net.proxy", "ok", {{ proxy_endpoints: [{listed}, {endpoints}] }});'
             'jsTest_fake("pkg.sources", "ok", { endpoints: [] });')
    got = reach(lib, setup)
    assert got["calls"] == []
    reasons = {t["host"]: t["reason"] for t in got["targets"]}
    for host, why in hosts.items():
        assert reasons[host] == why, host
    # 2 + 19 names would be looked up, 20 allowed.
    assert "1 more endpoint(s) not checked (at most 20)" in got["notes"]
