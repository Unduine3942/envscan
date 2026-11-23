"""Build pipeline: spec validation, PowerShell generation and lint, docs and checksums."""
from __future__ import annotations

import dataclasses
import hashlib
import math
import re
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
import target_ps
from conftest import BRIEF_HEADINGS, PORTABLE

import build as build_module
import docs
from spec import Spec, SpecError, load_spec, validate_spec

pytestmark = pytest.mark.unit

PS_SRC = PORTABLE / "src" / "ps"
SH_SRC = PORTABLE / "src" / "sh"


@pytest.fixture(scope="module")
def spec() -> Spec:
    return load_spec(PORTABLE / "spec")


@pytest.fixture(scope="module")
def ps_files() -> Mapping[str, bytes]:
    result = build_module.build(PORTABLE, ("ps",))
    assert result.ok, result.errors
    return result.files


def _generated_rows(text: str, name: str) -> list[str]:
    lines = text.splitlines()
    start = lines.index(f"$script:{name} = @(")
    end = lines.index(")", start)
    return lines[start + 1:end]


def _generated_ids(text: str, name: str) -> list[str]:
    return [re.search(r"'id' = '([^']+)'", row).group(1) for row in _generated_rows(text, name)]


# ------------------------------------------------------------------ spec

def test_spec_is_valid(spec: Spec) -> None:
    assert validate_spec(spec) == []


def test_every_probe_is_implemented_somewhere(spec: Spec) -> None:
    implemented = set().union(*(set(lines) for lines in spec.footprints.values()))
    assert [p["id"] for p in spec.probes if p["id"] not in implemented] == []


def test_ps_footprint_matches_probe_functions(spec: Spec) -> None:
    text = "\n".join(p.read_text(encoding="ascii") for p in sorted(PS_SRC.glob("*.ps1")))
    functions = set(re.findall(r"^function probe_(\w+)", text, re.MULTILINE))
    assert functions == {probe_id.replace(".", "_") for probe_id in spec.footprints["ps"]}


def test_sh_footprint_matches_probe_functions(spec: Spec) -> None:
    text = "\n".join(p.read_text(encoding="ascii") for p in sorted(SH_SRC.glob("*.sh")))
    functions = set(re.findall(r"^probe_(\w+)\(\)", text, re.MULTILINE))
    assert functions == {probe_id.replace(".", "_") for probe_id in spec.footprints["sh"]}


def test_every_ps_finding_id_exists_in_spec(spec: Spec) -> None:
    text = (PS_SRC / "30-findings.ps1").read_text(encoding="ascii")
    used = set(re.findall(r"New-EsFinding '([a-z0-9_.]+)'", text))
    assert used, "no findings referenced"
    assert used <= {f["id"] for f in spec.findings}


def _first(entries: tuple[Mapping[str, Any], ...], **changes: Any) -> tuple[Mapping[str, Any], ...]:
    return ({**entries[0], **changes}, *entries[1:])


def _without(entries: tuple[Mapping[str, Any], ...], key: str) -> tuple[Mapping[str, Any], ...]:
    return ({k: v for k, v in entries[0].items() if k != key}, *entries[1:])


Change = Callable[[Spec], Spec]
replace = dataclasses.replace
BAD_SPECS: dict[str, tuple[Change, str]] = {
    "exe given as a string": (lambda s: replace(s, tools=_first(s.tools, exe="git")), "exe: expected a list of strings"),
    "non-string args item": (lambda s: replace(s, tools=_first(s.tools, args=["--version", 3])), "args[1]: expected a string"),
    "missing probe title": (lambda s: replace(s, probes=_without(s.probes, "title")), "missing required key 'title'"),
    "missing tool exe": (lambda s: replace(s, tools=_without(s.tools, "exe")), "missing required key 'exe'"),
    "unknown probe key": (lambda s: replace(s, probes=_first(s.probes, colour="red")), "unknown key 'colour'"),
    "unknown config key": (lambda s: replace(s, configs=_first(s.configs, pathz=["x"])), "unknown key 'pathz'"),
    "cache id format": (lambda s: replace(s, caches=_first(s.caches, id="Bad Id")), "id must match"),
    "cache tool type": (lambda s: replace(s, caches=_first(s.caches, tool=5)), ".tool: expected a string"),
    "boolean max_bytes": (lambda s: replace(s, configs=_first(s.configs, max_bytes=True)), "max_bytes must be a positive"),
    "boolean token_min_length": (lambda s: replace(s, redaction={**s.redaction, "token_min_length": True}),
                                 "token_min_length must be a positive integer"),
    "NaN threshold": (lambda s: replace(s, thresholds={**s.thresholds, "x_min": math.nan}), "finite number"),
    "infinite threshold": (lambda s: replace(s, thresholds={**s.thresholds, "x_min": math.inf}), "finite number"),
    "boolean in a threshold list": (lambda s: replace(s, thresholds={**s.thresholds, "ports": [80, True]}),
                                    "list of integers"),
    "id with a trailing newline": (lambda s: replace(s, findings=_first(s.findings, id="exec.ps_constrained\n")),
                                   "id must match"),
    "version with a trailing newline": (lambda s: replace(s, meta={**s.meta, "version": "1.0.0\n"}), "MAJOR.MINOR.PATCH"),
    "version with a non-ASCII digit": (lambda s: replace(s, meta={**s.meta, "version": "1.0.\u0663"}),
                                       "MAJOR.MINOR.PATCH"),
    "env list given as a string": (lambda s: replace(s, package_env="GOPROXY"), "package_env: expected a list of strings"),
    "non-string env name": (lambda s: replace(s, proxy_env=("HTTP_PROXY", 7)), "proxy_env[1]: expected a string"),
    "non-string CA path": (lambda s: replace(s, ca_bundles=(None,)), "ca_bundles[0]: expected a string"),
    "non-string marker": (lambda s: replace(s, version_managers=_first(s.version_managers, markers=[5])),
                          "markers[0]: expected a string"),
    "non-string redaction word": (lambda s: replace(s, redaction={**s.redaction, "name_segments": [1, "OK"]}),
                                  "name_segments[0]: expected a string"),
    "redaction value of an unknown key": (lambda s: replace(s, redaction={**s.redaction, "future": {"a": 1}}),
                                          "future: expected a string, an integer or a list of strings"),
    "non-string child env value": (lambda s: replace(s, child_env={**s.child_env, "NO_COLOR": 1}),
                                   "child_env.toml NO_COLOR: expected a string"),
    "probe list given as a table": (lambda s: replace(s, probes={"id": "x"}), "expected an array of tables"),
    "footprint lines given as a table": (
        lambda s: replace(s, footprints={**s.footprints, "ps": {**s.footprints["ps"], "os.identity": {"a": 1}}}),
        "'os.identity': expected a list of strings"),
    "public host with a scheme": (lambda s: replace(s, public_hosts=("https://npmjs.org",)),
                                  "public_hosts: 'https://npmjs.org' must be a lower-case domain"),
    "upper-case public host": (lambda s: replace(s, public_hosts=("NuGet.org",)),
                               "public_hosts: 'NuGet.org' must be a lower-case domain"),
    "duplicate public host": (lambda s: replace(s, public_hosts=("npmjs.org", "npmjs.org")), "public_hosts: duplicate"),
    "empty public hosts": (lambda s: replace(s, public_hosts=()), "public_hosts: must not be empty"),
    "net_never given as a string": (lambda s: replace(s, net_never="169.254."), "net_never: expected a list of strings"),
    "net_never entry with a space": (lambda s: replace(s, net_never=("169.254. 1",)), "net_never: '169.254. 1' must be"),
    "empty net_never": (lambda s: replace(s, net_never=()), "net_never: must not be empty"),
}


@pytest.mark.parametrize("name", sorted(BAD_SPECS))
def test_validation_reports_bad_spec_without_crashing(spec: Spec, name: str) -> None:
    change, expected = BAD_SPECS[name]
    errors = validate_spec(change(spec))
    assert any(expected in error for error in errors), errors


def test_redaction_accepts_new_keys(spec: Spec) -> None:
    extended = replace(spec, redaction={**spec.redaction, "future_words": ["a-b", "c|d"], "future_limit": 3})
    assert validate_spec(extended) == []


def test_unknown_top_level_table_is_reported(spec: Spec, tmp_path: Path) -> None:
    copy = tmp_path / "spec"
    shutil.copytree(PORTABLE / "spec", copy)
    tools = copy / "tools.toml"
    tools.write_text(tools.read_text(encoding="utf-8") + "\n[extras]\nx = 1\n", encoding="utf-8")
    assert any("unknown top-level key 'extras'" in error for error in validate_spec(load_spec(copy)))


def test_non_utf8_spec_file_is_a_spec_error(tmp_path: Path) -> None:
    copy = tmp_path / "spec"
    shutil.copytree(PORTABLE / "spec", copy)
    (copy / "child_env.toml").write_bytes(b'[child_env]\nNO_COLOR = "\xff"\n')
    with pytest.raises(SpecError, match="UTF-8"):
        load_spec(copy)


# ------------------------------------------------------------------ PowerShell target

def test_ps_dist_is_ascii_with_crlf(ps_files: Mapping[str, bytes]) -> None:
    data = ps_files["dist/envscan.ps1"]
    data.decode("ascii")
    assert b"\r\n" in data
    assert b"\n" not in data.replace(b"\r\n", b"")


def test_ps_library_excludes_main(ps_files: Mapping[str, bytes]) -> None:
    lib = ps_files["build/lib/envscan-lib.ps1"].decode("ascii")
    assert "function Invoke-EnvScan" not in lib
    assert "function probe_os_identity" in lib


def test_generated_probe_table_follows_catalog_order(spec: Spec, ps_files: Mapping[str, bytes]) -> None:
    ids = _generated_ids(ps_files["dist/envscan.ps1"].decode("ascii"), "ES_PROBES")
    assert ids == [p["id"] for p in spec.probes_for("ps")]


def test_generated_tools_follow_their_os(spec: Spec, ps_files: Mapping[str, bytes]) -> None:
    by_id = {t["id"]: t for t in spec.tools}
    # Known entries of spec/tools.toml: py is windows-only, cc unix-only, strace linux-only, git everywhere.
    assert (by_id["py"]["os"], by_id["cc"]["os"], by_id["strace"]["os"]) == ("windows", "unix", "linux")
    assert "os" not in by_id["git"]
    ids = set(_generated_ids(ps_files["dist/envscan.ps1"].decode("ascii"), "ES_TOOLS"))
    assert {"py", "git"} <= ids
    assert not {"cc", "strace"} & ids


def _generated_block(text: str) -> str:
    return text[text.index(target_ps.GEN_BEGIN):text.index(target_ps.GEN_END)]


def test_windows_tables_drop_unix_absolute_paths(spec: Spec, ps_files: Mapping[str, bytes]) -> None:
    # os = "all" entries list Unix and Windows locations together. On Windows a Unix-absolute path is
    # root-relative ("\usr\local\go\bin" on the current drive), where any user can plant a program.
    windows = target_ps.WINDOWS_OS
    unix_paths = {d for t in spec.tools if t.get("os", "all") in windows for d in t.get("dirs", []) if d.startswith("/")}
    unix_paths |= {p for c in spec.configs if c.get("os", "all") in windows for p in c["paths"] if p.startswith("/")}
    unix_paths |= {p for c in spec.caches for p in c["paths"] if p.startswith("/")}
    assert {"/usr/local/go/bin", "/etc/pip.conf", "/opt/conda/pkgs"} <= unix_paths  # the entries this guards against
    block = _generated_block(ps_files["dist/envscan.ps1"].decode("ascii"))
    assert sorted(p for p in unix_paths if target_ps.ps_literal(p) in block) == []


def test_windows_tables_keep_entries_with_windows_paths(spec: Spec, ps_files: Mapping[str, bytes]) -> None:
    text = ps_files["dist/envscan.ps1"].decode("ascii")
    # pip.global lists /etc paths and {env:ProgramData}/pip/pip.ini; go lists /usr/local/go/bin and Program Files.
    assert "pip.global" in _generated_ids(text, "ES_CONFIGS")
    block = _generated_block(text)
    assert target_ps.ps_literal("{env:ProgramData}/pip/pip.ini") in block
    assert target_ps.ps_literal("{env:ProgramFiles}/Go/bin") in block


def test_generated_network_lists(spec: Spec, ps_files: Mapping[str, bytes]) -> None:
    block = _generated_block(ps_files["dist/envscan.ps1"].decode("ascii"))
    assert f"$script:ES_PUBLIC_HOSTS = {target_ps.ps_literal(list(spec.public_hosts))}" in block
    assert f"$script:ES_NET_NEVER = {target_ps.ps_literal(list(spec.net_never))}" in block
    assert {"nuget.org", "npmjs.org", "github.com"} <= set(spec.public_hosts)
    assert {"169.254.", "fd00:ec2::254", "metadata.google.internal"} <= set(spec.net_never)


def test_sh_network_lists_come_from_the_spec(spec: Spec) -> None:
    result = build_module.build(PORTABLE, ("sh",))
    assert result.ok, result.errors
    text = result.files["dist/envscan.sh"].decode("utf-8")
    assert re.search(r"^ES_PUBLIC_HOSTS='[^']*\bnuget\.org\b", text, re.M)
    assert re.search(r"^ES_NET_NEVER='[^']*169\.254\.", text, re.M)
    # One list only: the module code must not define its own copy.
    assert len(re.findall(r"^ES_PUBLIC_HOSTS=", text, re.M)) == 1


def test_ps_literal_rejects_non_finite_floats() -> None:
    assert target_ps.ps_literal(0.75) == "0.75"
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError):
            target_ps.ps_literal(value)


@pytest.mark.parametrize("snippet, rule", [
    ("$x = [ordered]@{}", "ordered"),
    ("if ($a -in $b) { }", "in-operator"),
    ("if ($a -notin $b) { }", "in-operator"),
    ("$found = $a -in", "in-operator"),
    ("$found = $a -in($b)", "in-operator"),
    ("$found = $a -in:$b", "in-operator"),
    ('Write-Output "x $($a -in $b)"', "in-operator"),
    ("$p = [pscustomobject]@{}", "pscustomobject"),
    ("$list.ForEach({ $_ })", "collection-method"),
    ("$list.Where{ $_ }", "collection-method"),
    ("Get-CimInstance Win32_Process", "cim-cmdlet"),
    ("Get-WmiObject Win32_Process", "wmi-cmdlet"),
    ("$a = New-Object System.Collections.ArrayList", "new-object"),
    ("$x = [IO.Path]::Combine('a', 'b')", "static-method"),
    ("$x = [Math]::Round(1.5)", "static-method"),
    ("$b = [Text.Encoding]::UTF8.GetBytes('x')", "static-method"),
    ("$v = $x ?? 'd'", "ps7-operator"),
    ("$n = $x?.Name", "ps7-operator"),
    ("$n = ${x}?.Name", "ps7-operator"),
    ("Remove-Item x -EA:Ignore", "ea-ignore"),
    ("Remove-Item x -ErrorAction:Ignore", "ea-ignore"),
    ("Remove-Item x -ErrorAction 'Ignore'", "ea-ignore"),
    ("$splat = @{ ErrorAction = 'Ignore' }", "ea-ignore"),
    ("class Probe { }", "class"),
    ("enum Color { Red }", "class"),
    ("$flags.HasFlag($bit)", "hasflag"),
    ("iex $code", "invoke-expression"),
    ("Invoke-Expression $code", "invoke-expression"),
    ("& 'iex' $code", "invoke-expression"),
    ("Get-Content -Raw f.txt", "gc-raw"),
    ("Start-Job { }", "start-job"),
    ("$t = $e.GetType()", "gettype"),
    ("$r = $PSScriptRoot", "psscriptroot"),
    ('Write-Output "$PSItem"', "psitem"),
    ("Get-ChildItem C:\\ -File", "gci-file"),
    ("Get-Content -Encoding:Byte f", "byte-encoding"),
])
def test_lint_rejects_forbidden_constructs(snippet: str, rule: str) -> None:
    errors = target_ps.lint(snippet + "\r\n")
    assert any(f"[{rule}]" in error for error in errors), errors


@pytest.mark.parametrize("snippet", [
    "Get-ChildItem -Include *.txt",
    "$index = 1",
    "$iex = 1",
    "Write-Output 'iex'",
    "$cmd = 'openssl x509 -in f'",
    "$pattern = '*?.txt'",
    "$text = 'a || b'",
    '$text = "a && b -in c"',
    "$x = 1  # -in is PS3+, so is $a ?? $b",
    "<# block comment: -in and ?. #>",
    "$quoted = 'it''s -in'",
    '$quoted = "say `"-in`" and ""-in"""',
    "$e = [Environment]::Is64BitProcess",
    "Get-Item x -ErrorAction SilentlyContinue",
    "$name = 'class Foo'",
    "$m = $line -match '^\\s*[#;]'",
])
def test_lint_accepts_lookalikes_in_names_strings_and_comments(snippet: str) -> None:
    assert target_ps.lint(snippet + "\r\n") == []


def test_lint_sees_through_multiline_strings_and_comments() -> None:
    text = "<#\r\n -in\r\n#>\r\n$h = @'\r\nclass X ?? -in\r\n'@\r\n$a -in $b\r\n"
    errors = target_ps.lint(text)
    assert [e.split(":")[0] for e in errors] == ["line 7"], errors


def test_lint_line_numbers_count_lf_only() -> None:
    # \x0b, \x1c and a lone \r are characters inside a line (str.splitlines would split there).
    text = "$a = 1\r\n$b = 'x\x0by'\r\n$c = [ordered]@{}\r\n$d = 'z\x1cw' \r more\r\n$e = $x ?? 1\r\n# Bypass, bypass\r\n"
    assert target_ps.lint(text) == [
        "line 2: non-ASCII or control character",
        "line 3: forbidden construct [ordered]: $c = [ordered]@{}",
        "line 4: non-ASCII or control character",
        "line 5: forbidden construct [ps7-operator]: $e = $x ?? 1",
        "line 6: suspicious-content keyword 'Bypass' (PowerShell logs such script blocks)",
        "line 6: suspicious-content keyword 'Bypass' (PowerShell logs such script blocks)",
    ]


def test_lint_reports_every_suspicious_occurrence_with_its_line() -> None:
    errors = target_ps.lint("# Marshal\r\n$x = 1\r\n$s = 'marshal'\r\n")
    assert [e for e in errors if "'Marshal'" in e] == [
        "line 1: suspicious-content keyword 'Marshal' (PowerShell logs such script blocks)",
        "line 3: suspicious-content keyword 'Marshal' (PowerShell logs such script blocks)",
    ]


def test_lint_allow_comment_exempts_only_that_rule() -> None:
    assert target_ps.lint("Get-CimInstance x  # lint-allow: cim-cmdlet\r\n") == []
    assert target_ps.lint("Get-CimInstance x  # lint-allow: wmi-cmdlet\r\n") != []
    # Only a comment can exempt a line; the same text inside a string does not.
    assert target_ps.lint("Get-CimInstance x; $s = '# lint-allow: cim-cmdlet'\r\n") != []


@pytest.mark.parametrize("word", ["Add-Type", "Bypass", "IntPtr", "properties", "Emit", "Cryptography", "Marshal"])
def test_lint_rejects_suspicious_keywords_even_in_comments(word: str) -> None:
    errors = target_ps.lint(f"# mentions {word}\r\n")
    assert any("suspicious-content keyword" in error for error in errors)


def test_lint_rejects_non_ascii() -> None:
    assert any("non-ASCII" in error for error in target_ps.lint("$x = 'caf\u00e9'\r\n"))


# ------------------------------------------------------------------ build entry points

def test_build_rejects_unknown_targets_without_raising() -> None:
    result = build_module.build(PORTABLE, ("ps", "zsh"))
    assert not result.ok
    assert "'zsh'" in result.errors[0]


@pytest.mark.parametrize("error", [KeyError("title"), ValueError("bad value"), TypeError("bad type")])
def test_build_reports_generator_exceptions(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def broken(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
        raise error

    monkeypatch.setitem(build_module.BUILDERS, "ps", broken)
    result = build_module.build(PORTABLE, ("ps",))
    assert not result.ok
    assert any(e.startswith("ps: ") and str(error).strip("'") in e for e in result.errors), result.errors


def test_partial_build_has_no_checksums(ps_files: Mapping[str, bytes]) -> None:
    assert "dist/envscan.ps1" in ps_files
    assert "dist/SHA256SUMS" not in ps_files


def test_main_refuses_to_write_a_partial_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    written: list[Path] = []
    monkeypatch.setattr(build_module, "write_outputs", lambda root, files: written.append(root))
    assert build_module.main(["--targets", "ps"]) == 2
    assert build_module.main(["--check", "--targets", "ps"]) == 0
    assert written == []


# ------------------------------------------------------------------ bundle and docs

def test_checksums_cover_and_match_the_bundle(built: Path) -> None:
    dist = built / "dist"
    lines = (dist / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    names = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        names.add(name)
        assert hashlib.sha256((dist / name).read_bytes()).hexdigest() == digest, name
    assert names == set(build_module.DIST_FILES)


def test_readme_title_has_the_version_and_full_footprint(built: Path, spec: Spec) -> None:
    template = (PORTABLE / "docs" / "README.dist.md").read_text(encoding="utf-8")
    title = next(line for line in template.splitlines() if docs.VERSION_MARKER in line)
    assert title.startswith("# ")
    text = (built / "dist" / "README.md").read_text(encoding="utf-8")
    assert docs.MARKER_PREFIX not in text
    assert title.replace(docs.VERSION_MARKER, spec.version) in text.splitlines()
    for probe_id in spec.footprints["ps"]:
        assert f"`{probe_id}`" in text


@pytest.mark.parametrize("template, message", [
    ("# envscan <!-- ENVSCAN:VERSION -->\n", "FOOTPRINT --> exactly once, found 0"),
    ("# envscan <!-- ENVSCAN:VERSION -->\n<!-- ENVSCAN:FOOTPRINT -->\n<!-- ENVSCAN:FOOTPRINT -->\n",
     "FOOTPRINT --> exactly once, found 2"),
    ("# envscan\n<!-- ENVSCAN:FOOTPRINT -->\n", "VERSION --> exactly once, found 0"),
    ("# envscan <!-- ENVSCAN:VERSION --> <!-- ENVSCAN:VERSION -->\n<!-- ENVSCAN:FOOTPRINT -->\n",
     "VERSION --> exactly once, found 2"),
    ("# envscan <!-- ENVSCAN:VERSION -->\n<!-- ENVSCAN:FOOTPRINT -->\n<!-- ENVSCAN:LICENSE -->\n",
     "template line 3: unknown marker '<!-- ENVSCAN:LICENSE -->'"),
    ("# envscan <!-- ENVSCAN:VERSION -->\n<!-- ENVSCAN:FOOTPRINT -->\nv<!-- ENVSCAN:VERSION\n",
     "template line 3: unknown marker '<!-- ENVSCAN:VERSION\\n'"),
])
def test_readme_template_needs_each_marker_once_and_nothing_else(spec: Spec, template: str, message: str) -> None:
    with pytest.raises(ValueError) as caught:
        docs.render_readme(template, spec)
    assert message in str(caught.value)


def test_readme_rendering_fails_when_spec_text_brings_a_marker(spec: Spec) -> None:
    footprints = {**spec.footprints, "ps": {**spec.footprints["ps"], "os.identity": ("read <!-- ENVSCAN:X -->",)}}
    with pytest.raises(ValueError, match="spec text contains"):
        docs.render_readme("<!-- ENVSCAN:VERSION -->\n<!-- ENVSCAN:FOOTPRINT -->\n", replace(spec, footprints=footprints))


def test_footprint_lines_render_literally_in_markdown(spec: Spec) -> None:
    # "<jdk>" is an HTML tag to a Markdown renderer (it vanishes) and "*"/"_" start emphasis.
    lines = ("run <jdk>\\bin\\keytool.exe -list", "list ~/.m2/*, ~/.gradle/*", "environment HTTP_PROXY, _JAVA_OPTIONS_")
    footprints = {**spec.footprints, "ps": {**spec.footprints["ps"], "os.identity": lines}}
    rendered = docs.footprint_section(replace(spec, footprints=footprints)).splitlines()
    for line in lines:
        assert f"  - `{line}`" in rendered


@pytest.mark.parametrize("text, expected", [
    ("plain <x> *y*", "`plain <x> *y*`"),
    ("a`b", "``a`b``"),
    ("`x", "`` `x ``"),
    ("x``y", "`x``y`"),
    (" both ", "`  both  `"),
])
def test_code_span_keeps_text_literal(text: str, expected: str) -> None:
    assert docs.code_span(text) == expected


def test_readme_template_renders_both_markers(spec: Spec) -> None:
    text = docs.render_readme("# envscan <!-- ENVSCAN:VERSION -->\n<!-- ENVSCAN:FOOTPRINT -->\n", spec)
    assert text.startswith(f"# envscan {spec.version}\n")
    assert docs.MARKER_PREFIX not in text and "`os.identity`" in text


def test_probe_docs_list_every_probe(built: Path, spec: Spec) -> None:
    text = (built / "docs" / "PROBES.md").read_text(encoding="utf-8")
    for probe in spec.probes:
        assert f"`{probe['id']}`" in text


def test_developer_doc_brief_headings_match_renderer() -> None:
    renderer = (PS_SRC / "41-brief.ps1").read_text(encoding="ascii")
    doc = (PORTABLE / "docs" / "DEVELOPING.md").read_text(encoding="utf-8")
    for heading in BRIEF_HEADINGS:
        assert f"## {heading}" in doc
        assert f"@('{heading}'" in renderer
