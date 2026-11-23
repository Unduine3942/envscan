"""net.reachability (--net) in envscan.sh: targets that cannot be checked make the probe
partial, and IPv6 addresses are contacted only in the global unicast and unique-local ranges
(second review 2026-11-11, findings D and H). Resolver and TCP client are stubs (tests/stubs/net-abs)
that log every call; the resolver stubs answer only absolute names ("proxy.corp."), so every
test also proves that no DNS search domain can apply (hardening round 2026-11-15).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sh_helpers import STUBS, msys_path, needs_msys, run_lib

pytestmark = [pytest.mark.integration, needs_msys]

V6_WHY = "IPv6 address outside the global and unique-local ranges; never contacted"
PUBLIC_V4_WHY = "public IPv4 address; never contacted"
NEVER_WHY = "cloud metadata or link-local address; never contacted"
LABEL_WHY = "single-label name; DNS search domains could expand it, so it is not looked up"
NET_STUBS = STUBS / "net-abs"


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def _items(events: str) -> dict[str, dict[str, object]]:
    """The targets of the event stream, by host:port (s/n values, z as None, lists)."""
    items: dict[str, dict[str, object]] = {}
    item: dict[str, object] | None = None
    current: list[str] | None = None
    for line in events.splitlines():
        kind, _, rest = line.partition("\t")
        if line == "{\t-":
            item = {}
        elif line == "}" and item is not None:
            items[f"{item['host']}:{item['port']}"] = item
            item = None
        elif item is not None and kind == "[":
            current = []
            item[rest] = current
        elif item is not None and kind == "]":
            current = None
        elif item is not None and current is not None and kind == "s":
            current.append(rest.split("\t", 1)[1])
        elif item is not None and kind in ("s", "n"):
            key, _, value = rest.partition("\t")
            item[key] = value
        elif item is not None and kind == "z":
            item[rest] = None
    return items


def _reach(lib: Path, tmp_path: Path, proxies: list[str], stubs: Path, timeout: int = 10,
           os_name: str = "linux") -> dict[str, object]:
    log, pdir = tmp_path / "stub.log", tmp_path / "p"
    pdir.mkdir()
    (tmp_path / "proxies.txt").write_text("\n".join(proxies) + "\n", encoding="ascii", newline="\n")
    script = (f'ES_P_DIR=$1; ES_TMP=$1; ES_OS={os_name}; ES_TIMEOUT={timeout}; ES_DEADLINE=99999999999999; PATH="$2:/usr/bin"\n'
              'es_pid_init; ES_F_proxy_hosts=$(cat "$3/proxies.txt"); ES_F_endpoints_internal=\n'
              'probe_net_reachability 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"\n'
              'echo "status=$(cat "$ES_P_DIR/status" 2>/dev/null)"; [ ! -f "$ES_P_DIR/notes" ] || sed "s/^/note: /" "$ES_P_DIR/notes"')
    proc = run_lib(lib, script, msys_path(pdir), msys_path(stubs), msys_path(tmp_path),
                   env={"ES_STUB_LOG": msys_path(log)})
    assert proc.returncode == 0, proc.stderr
    calls = log.read_text(encoding="ascii").splitlines() if log.exists() else []
    lines = proc.stdout.splitlines()
    return {
        "items": _items(proc.stdout),
        "calls": calls,
        "connects": sorted(c.split()[-1] for c in calls if c.startswith("curl")),
        "status": next(line[7:] for line in lines if line.startswith("status=")),
        "notes": [line[6:] for line in lines if line.startswith("note: ")],
    }


def test_names_without_a_resolver_are_skipped_and_the_probe_is_partial(lib: Path, tmp_path: Path) -> None:
    """D: with no resolver command a name is skipped (never contacted) and the probe is
    partial; an IP address literal is still vetted and checked."""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    shutil.copy(NET_STUBS / "curl", stubs / "curl")
    r = _reach(lib, tmp_path, ["proxy.corp:3128", "10.0.0.9:3128"], stubs)
    proxy = r["items"]["proxy.corp:3128"]
    assert (proxy["tcp"], proxy["reason"]) == ("skipped", "no resolver available; names are not contacted"), proxy
    assert r["items"]["10.0.0.9:3128"]["tcp"] == "ok"
    assert r["connects"] == ["telnet://10.0.0.9:3128"]
    assert r["status"] == "partial", r


def test_failed_lookups_are_errors_and_only_no_address_is_unresolved(lib: Path, tmp_path: Path) -> None:
    """D: a resolver timeout or error gives tcp "error" with an error text and a partial probe;
    only a definitive "no address" (getent exit status 2) is "unresolved"."""
    r = _reach(lib, tmp_path, ["slow.corp:3128", "broken.corp:3128", "gone.corp:3128"], NET_STUBS, timeout=1)
    items = r["items"]
    assert (items["slow.corp:3128"]["tcp"], items["slow.corp:3128"]["error"]) == ("error", "name lookup timed out")
    assert items["broken.corp:3128"]["tcp"] == "error"
    assert items["broken.corp:3128"]["error"] == "name lookup failed (exit status 3)"
    assert (items["gone.corp:3128"]["tcp"], items["gone.corp:3128"]["error"]) == ("unresolved", "the name has no address")
    assert r["connects"] == []
    assert r["status"] == "partial"
    assert "the name lookup failed for 2 host(s); they were not contacted" in r["notes"]


def test_ipv6_is_contacted_only_in_global_and_unique_local_ranges(lib: Path, tmp_path: Path) -> None:
    """H: resolved and literal IPv6 addresses outside 2000::/3 and fc00::/7, or in
    fd00:ec2::/32, or with a zone id are never contacted (an out-of-range literal is not even
    looked up)."""
    targets = ["ula.corp:3128", "gua.corp:3128", "ll6.corp:3128", "nat64.corp:3128", "mapped.corp:3128",
               "ec2v6.corp:3128", "zone.corp:3128", "[fe90::1]:3128", "[2001:db8::9]:3128", "[::1]:3128"]
    r = _reach(lib, tmp_path, targets, NET_STUBS)
    items = r["items"]
    for target in ("ll6.corp:3128", "nat64.corp:3128", "mapped.corp:3128", "ec2v6.corp:3128", "zone.corp:3128",
                   "fe90::1:3128", "::1:3128"):
        assert (items[target]["tcp"], items[target]["reason"]) == ("skipped", V6_WHY), items[target]
    assert r["connects"] == ["telnet://[2001:db8::5]:3128", "telnet://[2001:db8::9]:3128",
                             "telnet://[fd12:3456::7]:3128"]
    assert not [c for c in r["calls"] if c.startswith("getent") and c.split()[-1] in ("fe90::1", "::1")], r["calls"]


@pytest.mark.parametrize("address,ok", [
    ("2001:db8::1", True), ("3fff:ffff::1", True), ("2000::", True), ("fc00::1", True), ("fdff::1", True),
    ("FD12:3456::7", True), ("fd00::25", True), ("fd00:ec3::1", True),
    ("1fff::1", False), ("4000::1", False), ("fbff::1", False), ("fe00::1", False), ("fe80::1", False),
    ("fe90::1", False), ("febf::1", False), ("ff02::1", False), ("::1", False), ("::", False),
    ("::ffff:10.0.0.5", False), ("64:ff9b::a00:5", False), ("0:0:0:0:0:ffff:a00:5", False),
    ("0000:0000:0000:0000:0000:0000:0000:0001", False), ("fd00:ec2::254", False), ("fd00:0ec2:0::1", False),
    ("fd00:00ec2::1", False), ("2001:db8::1%eth0", False), ("fd00::1%25eth0", False), ("12345::1", False),
])
def test_ip6_ranges(lib: Path, address: str, ok: bool) -> None:
    proc = run_lib(lib, 'es_ip6_ok "$1" && echo ok || echo no', address)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ("ok" if ok else "no")


@pytest.mark.parametrize("value, allowed", [
    ("10.0.0.1", True), ("10.255.255.255", True), ("172.16.0.1", True), ("172.31.255.255", True), ("172.15.0.1", False),
    ("172.32.0.1", False), ("192.168.0.1", True), ("192.169.0.1", False), ("100.64.0.1", True),
    ("100.127.255.255", True), ("100.63.0.1", False), ("100.128.0.1", False), ("8.8.8.8", False), ("127.0.0.1", False),
    ("0.0.0.0", False), ("255.255.255.255", False), ("010.0.0.1", False), ("10.0.0.256", False), ("10.0.0", False),
    ("fd00::1", False),
])
def test_ipv4_contact_rule(lib: Path, value: str, allowed: bool) -> None:
    """Round 3: --net contacts only private IPv4 addresses (parity with ps Test-EsIpv4Allowed)."""
    proc = run_lib(lib, 'es_ip4_ok "$1" && echo ok || echo no', value)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ("ok" if allowed else "no")


def test_reachability_contacts_only_private_ipv4(lib: Path, tmp_path: Path) -> None:
    """Round 3: a public IPv4 address, literal or resolved, is never contacted (skipped with
    the shared reason); a name with a private address among public ones is checked at the
    private one. The new net_never entries are never contacted either."""
    targets = ["public.corp:80", "mixedv4.corp:443", "8.8.8.8:80", "172.32.0.1:80", "100.128.0.1:80", "127.0.0.1:80",
               "100.64.0.1:80", "172.31.255.1:80", "192.0.0.192:80", "[fd20:ce::254]:80", "[2002:c000:204::1]:80"]
    r = _reach(lib, tmp_path, targets, NET_STUBS)
    items = r["items"]
    assert r["connects"] == ["telnet://100.64.0.1:80", "telnet://172.31.255.1:80", "telnet://192.168.1.5:443"]
    for target in ("public.corp:80", "8.8.8.8:80", "172.32.0.1:80", "100.128.0.1:80", "127.0.0.1:80"):
        assert (items[target]["tcp"], items[target]["reason"]) == ("skipped", PUBLIC_V4_WHY), items[target]
    for target in ("192.0.0.192:80", "fd20:ce::254:80", "2002:c000:204::1:80"):
        assert items[target]["reason"] == NEVER_WHY, items[target]
    looked = {c.split()[-1] for c in r["calls"] if c.startswith("getent")}
    assert {"mixedv4.corp.", "public.corp."} <= looked, r["calls"]
    assert not looked & {"8.8.8.8", "172.32.0.1", "100.128.0.1", "127.0.0.1", "192.0.0.192"}, r["calls"]


def test_single_label_names_are_never_looked_up(lib: Path, tmp_path: Path) -> None:
    """Hardening round 2026-11-15: "proxy" and "proxy." (one trailing dot removed) would be
    expanded by the DNS search list; they are skipped and the resolver is never asked. A
    single-label name does not count against the lookup limit and leaves the status alone."""
    r = _reach(lib, tmp_path, ["proxy:3128", "proxy.:8080", "localhost:3128", "proxy.corp:3128"], NET_STUBS)
    items = r["items"]
    for target in ("proxy:3128", "proxy.:8080", "localhost:3128"):
        assert (items[target]["tcp"], items[target]["reason"]) == ("skipped", LABEL_WHY), items[target]
        assert "resolved" not in items[target], items[target]
    assert [c for c in r["calls"] if c.startswith("getent")] == ["getent ahosts proxy.corp."], r["calls"]
    assert items["proxy.corp:3128"]["host"] == "proxy.corp"
    assert items["proxy.corp:3128"]["tcp"] == "ok"
    assert r["connects"] == ["telnet://10.0.0.5:3128"]
    assert r["status"] != "partial", r


def test_names_are_looked_up_in_their_absolute_form(lib: Path, tmp_path: Path) -> None:
    """A name with a trailing dot is asked as written (one dot), any other name with a dot added;
    the report keeps the name as written."""
    r = _reach(lib, tmp_path, ["proxy.corp.:3128", "nexus.corp:8081"], NET_STUBS)
    getent = [c for c in r["calls"] if c.startswith("getent")]
    assert getent == ["getent ahosts proxy.corp.", "getent ahosts nexus.corp."], r["calls"]
    assert not [c for c in r["calls"] if c.startswith("relative")], r["calls"]
    assert set(r["items"]) == {"proxy.corp.:3128", "nexus.corp:8081"}
    assert r["connects"] == ["telnet://10.0.0.5:3128", "telnet://10.0.0.6:8081"]


def test_public_registry_with_a_trailing_dot_is_never_looked_up(lib: Path, tmp_path: Path) -> None:
    r = _reach(lib, tmp_path, ["registry.npmjs.org.:443", "metadata.google.internal.:80"], NET_STUBS)
    assert r["calls"] == [], r["calls"]
    assert r["items"]["registry.npmjs.org.:443"]["tcp"] == "skipped"
    assert r["items"]["metadata.google.internal.:80"]["reason"] == NEVER_WHY


def test_dscacheutil_is_asked_for_the_absolute_name(lib: Path, tmp_path: Path) -> None:
    """macOS without getent: dscacheutil gets "proxy.corp."; "proxy" is never asked."""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name in ("curl", "dscacheutil"):
        shutil.copy(NET_STUBS / name, stubs / name)
    r = _reach(lib, tmp_path, ["proxy.corp:3128", "proxy:3128"], stubs, os_name="darwin")
    assert [c for c in r["calls"] if c.startswith("dscacheutil")] == ["dscacheutil -q host -a name proxy.corp."], r["calls"]
    assert r["items"]["proxy:3128"]["reason"] == LABEL_WHY
    assert r["connects"] == ["telnet://10.0.0.5:3128"]


# Review fixes 2026-11-15 (X4): malformed names, IP literals never handed to a resolver, IPv6
# literals validated.
MALFORMED_WHY = "malformed host name; not looked up"


def test_malformed_names_are_skipped_and_never_looked_up(lib: Path, tmp_path: Path) -> None:
    """X4a: after removing one trailing dot, a name that is empty, starts with "." or contains ".."
    is skipped with the shared reason; the resolver is never asked."""
    targets = ["a..corp:3128", ".corp:3128", ".:3128", "..:3128", "x..:3128", "proxy.corp..:3128", ":3128", "proxy.corp:3128"]
    r = _reach(lib, tmp_path, targets, NET_STUBS)
    items = r["items"]
    for target in targets[:-1]:
        assert (items[target]["tcp"], items[target]["reason"]) == ("skipped", MALFORMED_WHY), items[target]
    assert [c for c in r["calls"] if c.startswith("getent")] == ["getent ahosts proxy.corp."], r["calls"]
    assert r["status"] != "partial", r


def test_ip_literals_are_never_resolved(lib: Path, tmp_path: Path) -> None:
    """X4c/d: literals are vetted and contacted as they are, never passed to a resolver; an IPv4
    literal with a trailing dot is a public IPv4 address."""
    r = _reach(lib, tmp_path, ["10.0.0.9:3128", "[2001:db8::9]:3128", "10.0.0.1.:80"], NET_STUBS)
    items = r["items"]
    assert not [c for c in r["calls"] if c.startswith("getent")], r["calls"]
    assert items["10.0.0.9:3128"]["resolved"] == ["10.0.0.9"]
    assert items["2001:db8::9:3128"]["resolved"] == ["2001:db8::9"]
    assert (items["10.0.0.1.:80"]["tcp"], items["10.0.0.1.:80"]["reason"]) == ("skipped", PUBLIC_V4_WHY)
    assert r["connects"] == ["telnet://10.0.0.9:3128", "telnet://[2001:db8::9]:3128"]


@pytest.mark.parametrize("value, literal", [
    ("10.0.0.1", True), ("2001:db8::1", True), ("::", True), ("::1", True), ("1:2:3:4:5:6:7:8", True),
    ("::ffff:10.0.0.5", True), ("fe80::1:2", True), ("1::", True), ("1:2:3:4:5:6:7::", True),
    ("2001:db8", False), ("1:2:3:4:5:6:7", False), ("1:2:3:4:5:6:7:8:9", False), ("1::2::3", False),
    (":1", False), ("1:", False), ("12345::1", False), (":::", False), ("::ffff:10.0.0", False),
    ("1:2:3:4:5:6:7:8::", False), ("::1.2.3.4:5", False), ("10.0.0", False), ("010.0.0.1", False),
    ("10.0.0.1.", False), ("proxy.corp", False), ("1:2:3:4:5:6:1.2.3.4", True), ("1:2:3:4:5:6:7:1.2.3.4", False),
])
def test_ip_literal_validation(lib: Path, value: str, literal: bool) -> None:
    proc = run_lib(lib, 'es_ip_literal "$1" && echo yes || echo no', value)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ("yes" if literal else "no")


def test_invalid_ipv6_literal_is_not_contacted(lib: Path, tmp_path: Path) -> None:
    """"2001:db8" is not an address: never resolved, never contacted."""
    r = _reach(lib, tmp_path, ["[2001:db8]:3128"], NET_STUBS)
    assert r["calls"] == [], r["calls"]
    assert "not checked (not a plain host name): 2001:db8" in r["notes"], r
