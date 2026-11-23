"""A secret inside a UTF-16LE file (registry export, Windows config with a BOM) must never reach
the output, however the implementation decodes the file.

Fixture: tests/fixtures/utf16le/registry-export.reg (BOM + UTF-16LE, CRLF). The check looks for the
secret as plain text, with NUL bytes / \\u0000 escapes removed (what a byte-wise reader sees),
and in its UTF-16LE form.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import ps_command, ps_quote, requires_powershell
from sh_helpers import AwkTool, make_awk_tool, msys_path, needs_msys, run_lib

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "utf16le" / "registry-export.reg"
SECRET = "CanaryUtf16Pw9"


def leaked(output: str) -> list[str]:
    """The forms of SECRET found in OUTPUT (empty when none)."""
    forms = {"plain": SECRET, "utf16": "\x00".join(SECRET), "escaped": "\\u0000".join(SECRET)}
    stripped = output.replace("\x00", "").replace("\\u0000", "")
    found = [name for name, form in forms.items() if form in output]
    return found + (["after-nul-removal"] if SECRET in stripped and "plain" not in found else [])


def test_fixture_is_utf16le_with_bom() -> None:
    raw = FIXTURE.read_bytes()
    assert raw[:2] == b"\xff\xfe"
    assert SECRET in raw[2:].decode("utf-16-le")
    assert SECRET.encode("ascii") not in raw  # only the UTF-16 form is on disk


def test_leak_detector_sees_every_form() -> None:
    assert leaked(f"x {SECRET}") == ["plain"]
    assert leaked("\x00".join(SECRET)) == ["utf16", "after-nul-removal"]
    assert leaked("\\u0000".join(SECRET)) == ["escaped", "after-nul-removal"]
    assert leaked("<redacted>") == []


@pytest.fixture(scope="module")
def awk_tool(built: Path, tmp_path_factory: pytest.TempPathFactory) -> AwkTool:
    return make_awk_tool(built / "build" / "lib" / "envscan-lib.sh", tmp_path_factory.mktemp("utf16-awk"))


@pytest.mark.integration
@needs_msys
@pytest.mark.parametrize("mode, match", [
    ("content", "-"), ("lines", "proxy|password"), ("list", "-")])
def test_sh_config_event_never_emits_the_secret(awk_tool: AwkTool, mode: str, match: str) -> None:
    events = f"{{\t-\nF\tlines\t{FIXTURE.as_posix()}\t65536\t{mode}\t{match}\n}}\n"
    out = awk_tool.run("json", events)
    assert leaked(out) == [], out


@pytest.mark.integration
@needs_msys
def test_sh_config_pipeline_never_emits_the_secret(built: Path, tmp_path: Path) -> None:
    """es_config_raw, the proxy settings and the endpoint list that feed pkg.sources and net.proxy.

    cfg.cur holds raw lines by design (the event writer redacts what the report gets), so it is
    not printed; everything the pipeline prints is checked, NUL-stripped as well, and must not be
    empty (the proxy server of the fixture has to be found: the file was decoded, not skipped).
    """
    script = ('ES_TMP=$1; ES_P_DIR=$1; es_awk_proxy >"$ES_TMP/proxy.awk" || exit 3\n'
              'es_config_raw "$2" "$3" 65536 "-"\n'
              'es_proxy_settings "$ES_P_DIR/cfg.cur" | es_proxy_urls; es_endpoints "$ES_P_DIR/cfg.cur"\n')
    lib = built / "build" / "lib" / "envscan-lib.sh"
    proc = run_lib(lib, script, msys_path(tmp_path), msys_path(FIXTURE), "content")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip(), "the pipeline printed nothing: the check would be vacuous"
    assert "proxy.corp.example" in proc.stdout
    assert leaked(proc.stdout) == [], proc.stdout


@pytest.fixture(scope="module", params=("FullLanguage", "ConstrainedLanguage"))
def ps_entry(request: pytest.FixtureRequest, built: Path) -> str:
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if request.param != "FullLanguage" else ""
    command = (f"{prefix}. {ps_quote(lib)}; Initialize-EsRedaction; "
               "$c = @{ id = 'canary'; tool = 'reg'; scope = 'user'; mode = 'content'; max_bytes = 65536; match = @() }; "
               f"$e = Read-EsConfigFile $c {ps_quote(FIXTURE)}; ConvertTo-EsJson $e")
    proc = ps_command(command, timeout=300)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.mark.integration
@requires_powershell
def test_ps_config_entry_never_emits_the_secret(ps_entry: str) -> None:
    entry = json.loads(ps_entry)
    assert entry["error"] is None
    assert leaked(ps_entry) == [], ps_entry
    assert any("Mode" in line for line in entry["lines"])  # the file was decoded, not skipped
