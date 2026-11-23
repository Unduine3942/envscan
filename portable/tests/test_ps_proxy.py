"""Proxy settings in package-manager configuration files and in git configuration, found by the
name of the setting (tests/proxy_cases.py), through the envscan.ps1 library in FullLanguage and
in ConstrainedLanguage. tests/test_sh_proxy_parity.py runs the same cases through envscan.sh.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import PORTABLE, ps_command, ps_quote, requires_powershell
from proxy_cases import CONFIG_CASES, GIT_CASES, ConfigCase, GitCase

from spec import load_spec

pytestmark = [pytest.mark.integration, requires_powershell]

HARNESS = Path(__file__).resolve().parent / "ps" / "proxy_cases.ps1"
MODES = ("FullLanguage", "ConstrainedLanguage")
DEFAULT_MAX_BYTES = 16384


def config_entry(config_id: str) -> dict[str, Any]:
    """The spec/configs.toml entry of CONFIG_ID with its defaults (mode, match, max_bytes)."""
    entry = next(c for c in load_spec(PORTABLE / "spec").configs if c["id"] == config_id)
    return {"id": entry["id"], "tool": entry["tool"], "mode": entry.get("mode", "content"),
            "match": list(entry.get("match", [])), "max_bytes": int(entry.get("max_bytes", DEFAULT_MAX_BYTES))}


@pytest.fixture(scope="module", params=MODES)
def results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    mode = request.param
    work = tmp_path_factory.mktemp(f"psproxy-{mode}")
    payload: list[dict[str, Any]] = []
    for index, config_case in enumerate(CONFIG_CASES):
        path = work / f"case{index}.cfg"
        path.write_text(config_case.text, encoding="ascii", newline="\n")
        payload.append({"name": config_case.name, "kind": "config", "config": config_entry(config_case.config_id),
                        "path": str(path)})
    payload += [{"name": git_case.name, "kind": "git", "entries": list(git_case.entries)} for git_case in GIT_CASES]
    cases_file = work / "cases.json"
    cases_file.write_text(json.dumps(payload), encoding="ascii")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if mode != "FullLanguage" else ""
    proc = ps_command(f"{prefix}& {ps_quote(HARNESS)} -Lib {ps_quote(lib)} -Cases {ps_quote(cases_file)}", timeout=300)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    data = json.loads(proc.stdout)
    assert data["language_mode"] == mode
    return data


@pytest.mark.parametrize("config_case", CONFIG_CASES, ids=lambda c: c.name)
def test_config_proxy_urls(results: dict[str, Any], config_case: ConfigCase) -> None:
    assert results[config_case.name]["proxy_urls"] == list(config_case.expected)


@pytest.mark.parametrize("config_case", [c for c in CONFIG_CASES if c.endpoints is not None], ids=lambda c: c.name)
def test_config_endpoints(results: dict[str, Any], config_case: ConfigCase) -> None:
    """A setting that is no proxy (GOPROXY names a module mirror) keeps its URL as an endpoint."""
    assert results[config_case.name]["urls"] == list(config_case.endpoints or ())


@pytest.mark.parametrize("git_case", GIT_CASES, ids=lambda c: c.name)
def test_git_proxy_urls(results: dict[str, Any], git_case: GitCase) -> None:
    assert results[git_case.name]["proxy_urls"] == list(git_case.expected)


def test_proxy_urls_never_hold_credentials(results: dict[str, Any]) -> None:
    flat = json.dumps({name: value for name, value in results.items() if name != "settings"})
    for secret in ("S3cret", "Gem5ecret", "bob", "gemuser", "user:", "@"):
        assert secret not in flat


PH = "<redacted>"
GIT_FILE = "file:C:/h/.gitconfig"


def settings(results: dict[str, Any], name: str) -> list[tuple[str, str, str]]:
    """The (tool, setting, value) of each setting found by name; the file is checked apart."""
    return [(s["tool"], s["setting"], s["value"]) for s in results["settings"][name]]


def test_net_proxy_lists_settings_by_name_not_lines(results: dict[str, Any]) -> None:
    # Second review 2026-11-11: net.proxy package_managers lists the settings found by their
    # names as {tool, setting, value, file}: the key, the value redacted; never a whole line that
    # merely holds "proxy" (a registry URL ".../npm-proxy/" is no proxy setting).
    assert settings(results, "npmrc_proxy_keys") == [
        ("npm", "https-proxy", f"http://bob:{PH}@proxy.corp:8080/"), ("npm", "noproxy", ".corp"),
        ("npm", "proxy", "http://proxy.corp:3128")]
    assert settings(results, "npmrc_registry_named_proxy") == []
    assert settings(results, "pip_userinfo_without_scheme") == [
        ("pip", "proxy", f"bob:{PH}@pipproxy.corp:3128"), ("pip", "proxy", f"bob:{PH}@webproxy")]
    assert settings(results, "go_env_module_proxy") == []
    assert settings(results, "git_proxy_keys") == [
        ("git", "http.proxy", "http://gitproxy.corp:3128"),
        ("git", "http.https://internal.corp/.proxy", f"http://user:{PH}@scoped.corp:8080"),
        ("git", "http.proxyauthmethod", "basic"), ("git", "remote.origin.proxy", "socks5://sockproxy.corp")]
    assert {s["file"] for s in results["settings"]["git_proxy_keys"]} == {GIT_FILE}
    for name, items in results["settings"].items():
        for item in items:
            assert set(item) == {"tool", "setting", "value", "file"}, (name, item)
            assert item["file"], (name, item)


def test_net_proxy_settings_never_hold_secrets(results: dict[str, Any]) -> None:
    flat = json.dumps(results["settings"])
    for secret in ("S3cret", "Gem5ecret", ":pw@", "proxy_password", "proxyPassword", "http_proxy.password"):
        assert secret not in flat, secret
