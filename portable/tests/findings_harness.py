"""Golden findings cases (tests/data/findings_cases.json) and the adapters that feed them to the
hand-written findings code of each implementation.

Case fields (all JSON):
  name, impls          ["ps", "sh"]: the implementations that implement the findings under test
  probes               probe id -> status; every probe in DEFAULT_PROBES is "ok" unless listed;
                       "absent" removes the probe from the results
  facts                language-neutral facts (see FACTS); both adapters translate them
  ps_data / sh_facts   implementation-specific raw input: probe id -> data table (ps), ES_F_ name
                       -> value (sh)
  full_language        ps only, default true
  sh_os                ES_OS for sh, default "linux"
  expect               finding ids both implementations must produce (compared as a set)
  expect_by_impl       per-implementation override of `expect`
  xfail                impl -> reason: the implementation does not produce `expect` today

sh facts: a probe that failed, timed out, was denied or skipped publishes no facts ("facts of
probes that did not run are empty" in src/sh/30-findings.sh), so the sh adapter drops the facts
of such a probe. The ps findings read the probe statuses themselves.
"""
from __future__ import annotations

import json
from pathlib import Path
from collections.abc import Callable, Mapping
from typing import Any

DATA = Path(__file__).resolve().parent / "data" / "findings_cases.json"
DEFAULT_PROBES = (
    "os.identity", "os.time_locale", "os.health", "hw.memory", "hw.storage", "sec.app_control", "sec.crypto",
    "tls.trust", "net.routes", "net.listening", "net.ports",
    "tools.inventory", "runtime.python", "runtime.dotnet", "virt.platform", "session.context", "shell.info",
    "fs.semantics", "fs.locations", "fs.mounts", "limits.process", "limits.kernel", "limits.cgroup",
    "user.identity", "user.profile", "native.deps",
)
NO_FACTS = ("error", "timeout", "denied", "skipped", "absent")
Json = Any


def load_cases(path: Path = DATA) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="ascii"))


def statuses(case: Mapping[str, Any]) -> dict[str, str]:
    """Probe id -> status. The probes of DEFAULT_PROBES, the probes that CASE's facts and ps_data
    come from, and those in `probes` (which wins; "absent" removes a probe). pkg.sources,
    pkg.caches and net.proxy are only present when a fact or `probes` names them, so that the
    absence finding pkg.no_source stays out of unrelated cases."""
    merged = {p: "ok" for p in DEFAULT_PROBES}
    merged.update({FACT_PROBE[f]: "ok" for f in case.get("facts", {})})
    merged.update({p: "ok" for p in case.get("ps_data", {})})
    merged.update(case.get("probes", {}))
    return {p: s for p, s in merged.items() if s != "absent"}


def expected(case: Mapping[str, Any], impl: str) -> list[str]:
    return sorted(case.get("expect_by_impl", {}).get(impl, case["expect"]))


# ---------------------------------------------------------------- neutral facts -> ps probe data

def _host_port(item: str) -> dict[str, Any]:
    host, _, port = item.partition(":")
    return {"host": host, "port": int(port or 0), "source": "env"}


def _ps_tools(value: Mapping[str, str]) -> dict[str, Any]:
    return {k: {"found": True, "cat": "runtime", "binary_arch": a} for k, a in value.items()}


PS_FACTS: dict[str, Callable[[Json], dict[str, dict[str, Any]]]] = {
    "app_control_enforced": lambda v: {"sec.app_control": {"enforced": ["AppLocker Exe"] if v else []}},
    "enterprise_roots": lambda v: {"tls.trust": {"enterprise_roots": list(v)}},
    "tls_verify_off_env": lambda v: {"tls.trust": {"runtime_trust": dict(s.split("=", 1) for s in v)}},
    "tls_verify_off_config": lambda v: {"pkg.sources": {"configs": [{"tool": c["tool"], "lines": [c["line"]]} for c in v]}},
    "endpoints_internal": lambda v: {"pkg.sources": {"endpoints": list(v)}},
    "endpoints_public": lambda v: {"pkg.sources": {"endpoints": list(v)}},
    "caches": lambda v: {"pkg.caches": {"caches": [{"tool": t, "entries": 3} for t in v]}},
    "proxy_hosts": lambda v: {"net.proxy": {"any_proxy": bool(v), "proxy_endpoints": [_host_port(h) for h in v]}},
    "default_route": lambda v: {"net.routes": {"default_route_count": 1 if v else 0}},
    "listening_common_ports": lambda v: {"net.listening": {"common_ports_in_use": list(v)}},
    "os_arch": lambda v: {"os.identity": {"arch": v}},
    "runtime_binary_arch": lambda v: {"tools.inventory": {"tools": _ps_tools(v)}},
    "fips": lambda v: {"sec.crypto": {"fips": bool(v)}},
    "pending_reboot": lambda v: {"os.health": {"pending_reboot": bool(v), "pending_reasons": list(v)}},
    "os_identity": lambda v: {"os.identity": dict(v)},
    "container": lambda v: {"virt.platform": {"container": dict(v)}},
    "shim_tools": lambda v: {"tools.inventory": {"tools": {t: {"found": True, "reason": "version-manager shim"} for t in v}}},
    "memory": lambda v: {"hw.memory": dict(v)},
    "disk_free_mb": lambda v: {"hw.storage": {"volumes": [{"mount": "/", "kind": "local", "free_mb": v}]}},
    "symlink": lambda v: {"fs.semantics": {"symlink": v}},
    "case_sensitive": lambda v: {"fs.semantics": {"case_sensitive": v}},
    "install_writable": lambda v: {"fs.locations": {"writable_install_locations": ["C:\\Users\\u\\AppData\\Local"] if v else []}},
    "is_admin": lambda v: {"user.identity": {"is_admin": v}},
    "home_network": lambda v: {"user.profile": {"home_network": v}},
    "locale": lambda v: {"os.time_locale": {"codepage_ansi": "65001" if v["utf8"] else v["codepage_ansi"],
                                            "codepage_oem": "437", "codepage_console": "437"}},
    "decimal_separator": lambda v: {"os.time_locale": {"decimal_separator": v}},
}
# the probe each neutral fact comes from (drives the sh status gating)
FACT_PROBE = {
    "app_control_enforced": "sec.app_control", "enterprise_roots": "tls.trust", "tls_verify_off_env": "tls.trust",
    "tls_verify_off_config": "pkg.sources", "endpoints_internal": "pkg.sources", "endpoints_public": "pkg.sources", "caches": "pkg.caches", "proxy_hosts": "net.proxy",
    "default_route": "net.routes", "listening_common_ports": "net.listening", "os_arch": "os.identity",
    "runtime_binary_arch": "tools.inventory", "fips": "sec.crypto", "pending_reboot": "os.health",
    "os_identity": "os.identity", "container": "virt.platform", "shim_tools": "tools.inventory", "memory": "hw.memory",
    "disk_free_mb": "fs.locations", "symlink": "fs.semantics", "case_sensitive": "fs.semantics",
    "install_writable": "fs.locations", "is_admin": "user.identity", "home_network": "user.profile",
    "locale": "os.time_locale", "decimal_separator": "os.time_locale", "python_found": "runtime.python",
}


def _merge(into: dict[str, dict[str, Any]], part: Mapping[str, Mapping[str, Any]]) -> None:
    for probe, data in part.items():
        target = into.setdefault(probe, {})
        for key, value in data.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                target[key] = {**target[key], **value}
            elif key == "endpoints" and isinstance(target.get(key), list):  # internal + public facts add up
                target[key] = [*target[key], *value]
            else:
                target[key] = value


# What a healthy probe reports; the ps rules read a missing value as "absent" (no route, no folder).
PS_HEALTHY: dict[str, dict[str, Any]] = {
    "fs.locations": {"writable_install_locations": ["/home/u"]},
    "net.routes": {"default_route_count": 1},
}


def ps_input(case: Mapping[str, Any]) -> dict[str, Any]:
    """The probe results (status + data) the ps findings run on, as JSON for the harness."""
    states = statuses(case)
    data: dict[str, dict[str, Any]] = {p: dict(d) for p, d in PS_HEALTHY.items() if p in states}
    facts = dict(case.get("facts", {}))
    if "python_found" in facts and "runtime.python" not in case.get("probes", {}):
        states["runtime.python"] = "ok" if facts["python_found"] else "not_found"
    for name, value in facts.items():
        if name in PS_FACTS:
            _merge(data, PS_FACTS[name](value))
    _merge(data, case.get("ps_data", {}))
    results = {p: {"status": s, "data": data.get(p, {})} for p, s in states.items()}
    return {"name": case["name"], "full_language": case.get("full_language", True), "results": results}


# ---------------------------------------------------------------- neutral facts -> sh ES_F_*

def _host(url: str) -> str:
    """The host the sh probe publishes for an endpoint URL (the probe classifies; the case says how)."""
    return url.split("://", 1)[-1].split("/", 1)[0]


def _lines(items: Any) -> str:
    return "\n".join(str(i) for i in items)


def _sh_os_identity(v: Mapping[str, Any]) -> dict[str, str]:
    keys = {"name": "os_name", "version": "os_version", "distro_id": "distro_id", "kernel": "os_kernel"}
    return {keys[k]: str(x) for k, x in v.items() if k in keys}


def _sh_locale(v: Mapping[str, Any]) -> dict[str, str]:
    return {"encoding_utf8": "true" if v["utf8"] else "false", "encoding": v.get("encoding", "")}


SH_FACTS: dict[str, Callable[[Json], dict[str, str]]] = {
    "app_control_enforced": lambda v: {"fapolicyd": "active"} if v else {},
    "enterprise_roots": lambda v: {"ca_custom": str(len(v)), "ca_subjects": _lines(x.replace("CN=", "") for x in v)},
    "tls_verify_off_env": lambda v: {"tls_disabled_env": _lines(v)},
    "tls_verify_off_config": lambda v: {"tls_disabled_cfg": _lines(f"{c['tool']}: {c['line']}" for c in v)},
    "endpoints_internal": lambda v: {"endpoints_internal": _lines(_host(u) for u in v)},
    "endpoints_public": lambda v: {"endpoints_public": _lines(_host(u) for u in v)},
    "caches": lambda v: {"caches": _lines(v)},
    "proxy_hosts": lambda v: {"proxy": "true" if v else "false", "proxy_hosts": _lines(v)},
    "default_route": lambda v: {"default_route": "true" if v else "false"},
    "listening_common_ports": lambda v: {"listen_ports": " ".join(str(p) for p in v)},
    "os_arch": lambda v: {"os_arch": v},
    "runtime_binary_arch": lambda v: {"arch_mismatch": "; ".join(f"{k} is {a}" for k, a in v.items())},
    "fips": lambda v: {"fips": "true" if v else "false"},
    "pending_reboot": lambda v: {"pending_reboot": "true" if v else "false", "pending_reasons": _lines(v)},
    "os_identity": _sh_os_identity,
    "container": lambda v: {"container": "true" if v["detected"] else "false", "container_engine": v.get("engine", ""),
                            "kubernetes": "true" if v.get("kubernetes") else "false"},
    "python_found": lambda v: {"python_found": "true" if v else "false"},
    "shim_tools": lambda v: {"shims_skipped": str(len(v))},
    "memory": lambda v: {"mem_total_mb": str(v["total_mb"]), **({"mem_avail_mb": str(v["available_mb"])}
                                                                if v.get("available_mb") is not None else {})},
    "disk_free_mb": lambda v: {"free_home_mb": str(v)},
    "symlink": lambda v: {"symlink": v},
    "case_sensitive": lambda v: {"case_sensitive": "true" if v else "false"},
    "install_writable": lambda v: {"install_writable": "true" if v else "false"},
    "is_admin": lambda v: {"is_admin": "true" if v else "false"},
    "home_network": lambda v: {"home_network": "true" if v else "false"},
    "locale": _sh_locale,
    "decimal_separator": lambda v: {"decimal_sep": v},
}


def sh_facts(case: Mapping[str, Any]) -> dict[str, str]:
    """ES_F_<name> -> value for CASE."""
    states = {**statuses(case), **{p: s for p, s in case.get("probes", {}).items() if s == "absent"}}
    out: dict[str, str] = {}
    facts = case.get("facts", {})
    for name, value in facts.items():
        if states.get(FACT_PROBE[name], "absent") in NO_FACTS:
            continue
        out.update(SH_FACTS[name](value))
    out.update({k: str(v) for k, v in case.get("sh_facts", {}).items()})
    out.setdefault("pkg_config_count", "0")
    return out


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def sh_script_inputs(case: Mapping[str, Any]) -> tuple[str, str]:
    """(facts file text, results.tsv text) for the sh findings run."""
    facts = "".join(f"ES_F_{k}={sh_quote(v)}\n" for k, v in sorted(sh_facts(case).items()))
    rows = "".join(f"{i}\t{p}\t{s}\t1\t\n" for i, (p, s) in enumerate(sorted(statuses(case).items()), 1))
    return facts, rows
