"""The proxy cases of tests/proxy_cases.py through envscan.sh: a configuration file goes through
the pipeline of a configs entry (es_config_raw, proxy.awk, es_proxy_urls), git entries through
proxy.awk as git_lines.txt holds them. The expected URLs are those tests/test_ps_proxy.py expects
from envscan.ps1, so both implementations report the same proxies.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from conftest import PORTABLE
from proxy_cases import CONFIG_CASES, GIT_CASES, ConfigCase, GitCase
from sh_helpers import msys_path, needs_msys, run_lib

from spec import load_spec

pytestmark = [pytest.mark.integration, needs_msys]

DEFAULT_MAX_BYTES = 16384
CONFIG_SCRIPT = (
    'ES_TMP=$1; ES_P_DIR=$1; es_awk_proxy >"$ES_TMP/proxy.awk" || exit 3\n'
    'es_config_raw "$2" "$3" "$4" "$5"\n'
    'es_proxy_settings "$ES_P_DIR/cfg.cur" | es_proxy_urls | cut -f 2\n'
)
ENDPOINT_SCRIPT = (
    'ES_TMP=$1; ES_P_DIR=$1\n'
    'es_config_raw "$2" "$3" "$4" "$5"\n'
    'es_endpoints "$ES_P_DIR/cfg.cur" | cut -f 2\n'
)
GIT_SCRIPT = (
    'ES_TMP=$1; es_awk_proxy >"$ES_TMP/proxy.awk" || exit 3\n'
    'es_proxy_settings "$2" | es_proxy_urls | cut -f 2\n'
)


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def config_entry(config_id: str) -> dict[str, Any]:
    return next(c for c in load_spec(PORTABLE / "spec").configs if c["id"] == config_id)


def run(lib: Path, script: str, *args: str) -> list[str]:
    proc = run_lib(lib, script, *args)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.splitlines()


def run_config(lib: Path, tmp_path: Path, script: str, config_case: ConfigCase) -> list[str]:
    """SCRIPT over the file of CONFIG_CASE, read as its configs entry reads it (mode, cap, match)."""
    entry = config_entry(config_case.config_id)
    cfg = tmp_path / "cfg"
    cfg.write_text(config_case.text, encoding="ascii", newline="\n")
    match = "|".join(entry.get("match", [])) or "-"
    return run(lib, script, msys_path(tmp_path), msys_path(cfg), entry.get("mode", "content"),
               str(entry.get("max_bytes", DEFAULT_MAX_BYTES)), match)


@pytest.mark.parametrize("config_case", CONFIG_CASES, ids=lambda c: c.name)
def test_config_proxy_urls(lib: Path, tmp_path: Path, config_case: ConfigCase) -> None:
    assert run_config(lib, tmp_path, CONFIG_SCRIPT, config_case) == list(config_case.expected)


@pytest.mark.parametrize("config_case", [c for c in CONFIG_CASES if c.endpoints is not None], ids=lambda c: c.name)
def test_config_endpoints(lib: Path, tmp_path: Path, config_case: ConfigCase) -> None:
    """A setting that is no proxy (GOPROXY names a module mirror) keeps its URL as an endpoint."""
    assert run_config(lib, tmp_path, ENDPOINT_SCRIPT, config_case) == list(config_case.endpoints or ())


@pytest.mark.parametrize("git_case", GIT_CASES, ids=lambda c: c.name)
def test_git_proxy_urls(lib: Path, tmp_path: Path, git_case: GitCase) -> None:
    lines = tmp_path / "git_lines.txt"
    lines.write_text("".join(f"git:file:/h/.gitconfig\t{entry}\n" for entry in git_case.entries),
                     encoding="ascii", newline="\n")
    assert run(lib, GIT_SCRIPT, msys_path(tmp_path), msys_path(lines)) == list(git_case.expected)
