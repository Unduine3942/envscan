"""Unit tests for the envscan.cmd generator (tools/target_cmd.py) and its batch source parts.

Nothing here runs cmd.exe; tests/test_cmd_launcher.py does.
"""
from __future__ import annotations

import copy
import dataclasses
import re
from collections.abc import Callable
from pathlib import Path

import pytest

import target_cmd
from conftest import PORTABLE
from spec import Spec, load_spec, validate_spec

pytestmark = pytest.mark.unit

SOURCE_DIR = PORTABLE / "src" / "cmd"
MAX_PART_LINES = 800
# Characters that change the meaning of a batch line when a spec value is pasted into a
# FOR list, a variable name or a !var:search=replace! expression.
UNSAFE_IN_BATCH = set('=!%"^*?,;&|<>() \t')


@pytest.fixture(scope="module")
def spec() -> Spec:
    loaded = load_spec(PORTABLE / "spec")
    assert validate_spec(loaded) == []
    return loaded


@pytest.fixture(scope="module")
def assembled(spec: Spec) -> str:
    return target_cmd.assemble(spec, SOURCE_DIR)


@pytest.fixture(scope="module")
def source() -> str:
    """The joined parts without their headers, before substitution ("\\n" line endings)."""
    return target_cmd.source_text(SOURCE_DIR)


def test_source_is_split_into_ordered_parts() -> None:
    parts = target_cmd.part_files(SOURCE_DIR)
    assert [p.name for p in parts] == sorted(p.name for p in SOURCE_DIR.iterdir()), "only NN-name.cmd parts"
    assert parts[0].name.startswith("00-") and len(parts) > 1
    for part in parts:
        assert target_cmd.PART_NAME_RE.fullmatch(part.name), part.name
        lines = part.read_bytes().split(b"\r\n")[:-1]
        assert len(lines) <= MAX_PART_LINES, f"{part.name}: {len(lines)} lines"
        assert lines[0].startswith(target_cmd.PART_HEADER.encode()), f"{part.name}: no header"


def test_assembly_is_the_parts_without_headers(spec: Spec, assembled: str, source: str) -> None:
    expected = source
    for key, value in target_cmd.placeholders(spec).items():
        expected = expected.replace(key, value.replace("\r\n", "\n"))
    assert assembled == expected.replace("\n", "\r\n")
    assert target_cmd.PART_HEADER not in assembled
    bodies = []
    for part in target_cmd.part_files(SOURCE_DIR):
        lines = part.read_bytes().decode("ascii").split("\r\n")
        while lines[0].startswith(target_cmd.PART_HEADER):
            lines.pop(0)
        bodies.append("\n".join(lines))
    assert source == "".join(bodies)


def test_build_py_source_path_still_assembles(spec: Spec, assembled: str) -> None:
    """tools/build.py passes the former single file src/cmd/envscan.cmd; its directory is used."""
    assert not (SOURCE_DIR / "envscan.cmd").exists()
    assert target_cmd.assemble(spec, SOURCE_DIR / "envscan.cmd") == assembled


def test_part_checks_name_the_part_and_line(tmp_path: Path, spec: Spec) -> None:
    known = target_cmd.placeholders(spec)
    good = b"rem ## header\r\necho ok\r\n"
    assert target_cmd.check_part("10-good.cmd", good, known) == []
    cases = {
        ("10-a.cmd", b"rem ## h\r\necho a\necho b\r\n"): "10-a.cmd: bare LF",
        ("10-b.cmd", b"rem ## h\r\necho b"): "10-b.cmd: must end with CRLF",
        ("10-c.cmd", b"echo c\r\n"): "10-c.cmd: must start with a 'rem ##' header",
        ("10-d.cmd", b"rem ## only a header\r\n"): "10-d.cmd: has nothing after its header",
        ("10-e.cmd", "rem ## h\r\necho café\r\n".encode("utf-8")): "10-e.cmd line 2: non-ASCII",
        ("10-f.cmd", b"rem ## h\r\necho @@ES_NOPE@@\r\n"): "10-f.cmd line 2: unknown placeholder @@ES_NOPE@@",
        ("10-g.cmd", b"rem ## h\r\nrem see %~1 here\r\n"): "10-g.cmd line 2: %~ in a comment",
        ("10-h.cmd", b"rem ## h\r\nrem @@ES_VERSION@@\r\n"): "10-h.cmd line 2: placeholder in a comment",
        ("envscan.cmd", good): "envscan.cmd: part names look like NN-name.cmd",
    }
    for (name, raw), message in cases.items():
        errors = target_cmd.check_part(name, raw, known)
        assert any(e.startswith(message) for e in errors), (name, errors)
    (tmp_path / "00-first.cmd").write_bytes(good)
    (tmp_path / "10-bad.cmd").write_bytes(b"echo no header\r\n")
    with pytest.raises(ValueError, match="10-bad.cmd: must start with a 'rem ##' header"):
        target_cmd.assemble(spec, tmp_path)
    (tmp_path / "00-first.cmd").unlink()
    with pytest.raises(FileNotFoundError):
        target_cmd.part_files(tmp_path)


def test_redaction_placeholders_follow_the_spec(spec: Spec) -> None:
    values = target_cmd.placeholders(spec)
    red = spec.redaction
    assert values["@@ES_REDACT_SEGMENTS@@"].split() == red["name_segments"]
    assert values["@@ES_REDACT_CONTAINS@@"].split() == red["name_contains"]
    assert values["@@ES_REDACT_EXCEPT@@"].split() == red["exact_exceptions"]
    assert values["@@ES_REDACT_SUFFIXES@@"].split() == red["suffix_exceptions"]
    assert values["@@ES_REDACT_PREFIXES@@"].split() == red["token_prefixes"]
    assert values["@@ES_REDACT_PLACEHOLDER@@"] == red["placeholder"]
    assert values["@@ES_REDACT_PKMARKER@@"] == red["private_key_marker"]
    assert values["@@ES_REDACT_MINLEN@@"] == str(red["token_min_length"])
    assert values["@@ES_REDACT_NAME_SUFFIXES@@"].split() == red["name_suffixes"]
    assert values["@@ES_REDACT_PAIRS@@"].split() == red["pair_keys"]
    assert values["@@ES_REDACT_OPTIONS@@"].split() == red["option_words"]
    assert values["@@ES_REDACT_HEADERS@@"].split() == red["header_words"]
    assert values["@@ES_REDACT_TOOL_OPTIONS@@"].split() == red["tool_options"]
    names = values["@@ES_REDACT_TOOL_NAMES@@"].split()
    assert names == sorted(set(names), key=names.index), "tool names must not repeat"
    assert set(names) == {token.split(":", 1)[0] for token in red["tool_options"]}
    combined = values["@@ES_REDACT_WORDS@@"].split()
    assert set(combined) == set(red["name_segments"]) | set(red["name_contains"])


def test_trigger_words_cover_every_secret_name_word(spec: Spec) -> None:
    """The cheap test before a value is scanned must never skip a value with a secret key."""
    red = spec.redaction
    triggers = target_cmd.placeholders(spec)["@@ES_REDACT_TRIGGERS@@"].split()
    words = [w.upper() for key in ("name_segments", "name_contains", "name_suffixes", "pair_keys") for w in red[key]]
    for word in words:
        assert any(trigger in word for trigger in triggers), f"no trigger word inside {word}"
    for trigger in triggers:
        assert trigger in words
        assert not any(other != trigger and other in trigger for other in triggers), f"{trigger} is redundant"


def test_tool_and_proxy_placeholders_follow_the_spec(spec: Spec) -> None:
    values = target_cmd.placeholders(spec)
    windows_tools = [t for t in spec.tools if t.get("os", "all") in ("all", "windows")]
    quoted = re.findall(r'"([^"]+)"', values["@@ES_TOOLS_QUOTED@@"])
    assert quoted == values["@@ES_TOOLS@@"].split()
    assert [token.split(":")[0] for token in quoted] == [t["id"] for t in windows_tools]
    proxy = re.findall(r'"([^"]+)"', values["@@ES_PROXY_ENV@@"])
    assert proxy == sorted(set(proxy), key=proxy.index)  # no duplicates
    assert {name.upper() for name in spec.proxy_env} == set(proxy)
    probe_ids = values["@@ES_PROBE_IDS@@"].split()
    assert probe_ids == [p["id"] for p in spec.probes_for("cmd")]
    all_ids = values["@@ES_ALL_PROBE_IDS@@"].split()
    assert all_ids == [p["id"] for p in spec.probes] and set(probe_ids) <= set(all_ids)


def test_spec_values_are_safe_inside_batch_expressions(spec: Spec) -> None:
    red = spec.redaction
    words = [*red["name_segments"], *red["name_contains"], *red["exact_exceptions"],
             *red["suffix_exceptions"], *red["token_prefixes"], *red["name_suffixes"],
             *red["pair_keys"], *red["option_words"], *red["header_words"]]
    for tool in spec.tools:
        words.extend([tool["id"], *tool["exe"]])
    # "tool:option" tokens are split with FOR /F delims=: and their parts compared and listed.
    for token in red["tool_options"]:
        name, option = token.split(":", 1)
        assert ":" not in option and option[:1] in ("-", "/") and 2 <= len(option) <= 4, token
        words.extend([name, option])
    words.extend(p["id"] for p in spec.probes)
    for word in words:
        assert not (set(word) & UNSAFE_IN_BATCH), f"{word!r} would break envscan.cmd"
        assert not word.startswith("~"), f"{word!r} would be read as a substring expression"
    marker = red["private_key_marker"]
    assert not (set(marker) & set('=!%"^')) and marker[:1] not in ("*", "~")
    assert not (set(red["placeholder"]) & set('!%"^'))
    for name in spec.proxy_env:
        assert not (set(name) & set('=!%"^&|<> ')), name


def test_assembled_script_is_crlf_ascii_and_lint_clean(assembled: str) -> None:
    assert target_cmd.lint(assembled) == []
    raw = assembled.encode("ascii")
    assert b"\n" not in raw.replace(b"\r\n", b"")
    assert b"@@" not in raw
    assert raw.startswith(b"@echo off\r\n")
    assert max(len(line) for line in assembled.split("\r\n")) < 8000


def test_every_cmd_probe_has_exactly_one_label(spec: Spec, source: str) -> None:
    labels = re.findall(r"^:es_probe_(\w+)\s*$", source, flags=re.MULTILINE)
    expected = [p["id"].replace(".", "_") for p in spec.probes_for("cmd")]
    assert sorted(labels) == sorted(expected), "footprint/cmd.toml and the :es_probe_ labels differ"
    assert len(labels) == len(set(labels))


def test_source_avoids_batch_parser_traps(spec: Spec, source: str) -> None:
    # cmd.exe expands %~ even in comments and aborts on a bad modifier: the per-part checks
    # reject it (and placeholders in comments) with the part name and line.
    known = target_cmd.placeholders(spec)
    for part in target_cmd.part_files(SOURCE_DIR):
        assert target_cmd.check_part(part.name, part.read_bytes(), known) == []
    for number, line in enumerate(source.split("\n"), start=1):
        stripped = line.strip().lower()
        # PowerShell's suspicious-content scan applies to envscan.ps1, not here; the launcher
        # may name the process-scoped option, but must never add it to its own command line.
        if "powershell" in stripped and "-file" in stripped and not stripped.startswith("echo"):
            assert "-executionpolicy" not in stripped, f"line {number}: launcher adds -ExecutionPolicy"
        # FOR /F "delims= ,;" is a syntax error (a space as delimiter must come last), and inside
        # a called label it only ends that call: the label silently does nothing.
        if not stripped.startswith("rem"):
            assert not re.search(r'delims= [^"]', line), f"line {number}: space first in delims"


def percent_expansions(line: str) -> list[str]:
    """The %NAME% and %NAME:...% expansions of one batch line (not %%, %1, %~dp0 or %*)."""
    found: list[str] = []
    i = 0
    while i < len(line):
        if line[i] != "%":
            i += 1
        elif line[i + 1:i + 2] == "%":
            i += 2
        elif line[i + 1:i + 2] == "*" or line[i + 1:i + 2].isdigit():
            i += 2
        elif line[i + 1:i + 2] == "~":
            match = re.match(r"%~[a-z$:A-Z]*\d", line[i:])
            i += len(match.group(0)) if match else 2
        else:
            end = line.find("%", i + 1)
            if end < 0:
                break
            found.append(line[i:end + 1])
            i = end + 1
    return found


# Expanded with %...% although not owned by the script: dynamic variables whose user overrides
# the launcher removes first, and PATH with every quote removed (each entry is then quoted).
SAFE_EXPANSIONS = {"%CD%", "%RANDOM%", "%errorlevel%", '%PATH:"=%'}


def test_outside_values_are_never_percent_expanded(source: str) -> None:
    """Security: a quote in a %expanded% value would end its quoted string and run the rest as
    commands. Values from outside are read with !expansion! and checked into __ES_* variables."""
    bad = []
    for number, line in enumerate(source.split("\n"), start=1):
        if line.lstrip().lower().startswith("rem"):
            continue
        for token in percent_expansions(line):
            if not token.startswith("%__ES_") and token not in SAFE_EXPANSIONS:
                bad.append(f"line {number}: {token}: {line.strip()}")
    assert not bad, "\n".join(bad)
    assert percent_expansions('set "A=%X%" & echo %%a %1 %~dp0 %* %Y:~1%') == ["%X%", "%Y:~1%"]


def test_system_programs_are_called_by_full_path(source: str) -> None:
    """chcp, reg, ... found on PATH could be anything: they run as %__ES_SYS%\\name.exe."""
    programs = "chcp|reg|findstr|whoami|where|mountvol|subst|tzutil|netsh|ipconfig|route"
    # A program at the start of a command: line start, after ' ( | & or "do".
    bare = re.compile(rf"(?i)(?:^|['(|&]|\bdo)\s*({programs})(?:\.exe|\.com)?(?=[\s'\"^)]|$)")
    for line in source.split("\n"):
        if line.lstrip().lower().startswith("rem"):
            continue
        assert not bare.search(line.strip()), f"program without %__ES_SYS%\\: {line.strip()}"
    assert "%__ES_SYS%\\chcp.com" in source


# Every program envscan.cmd starts. The child environment allowlist (spec/child_env.toml
# [child_env_keep]) is not applied by envscan.cmd because these are Windows System32 tools that read
# none of the variables it removes (proxies, tokens, NODE_OPTIONS, ...), besides envscan.cmd itself
# (the 64-bit relaunch) and the scanners (PowerShell, cscript), which must see the whole environment
# to report it. A third-party program here needs that allowlist first.
CMD_PROGRAMS = frozenset({"chcp.com", "reg.exe", "findstr.exe", "whoami.exe", "mountvol.exe", "subst.exe",
                          "tzutil.exe", "netsh.exe", "ipconfig.exe", "route.exe", "cscript.exe", "cmd.exe",
                          "powershell.exe", "pwsh.exe"})
SCANNER_PROGRAMS = frozenset({"cmd.exe", "cscript.exe", "powershell.exe", "pwsh.exe"})


def _code_lines(source: str) -> list[str]:
    return [line for line in source.split("\n") if not line.lstrip().lower().startswith("rem")]


def test_only_system32_tools_and_the_scanners_run(source: str) -> None:
    started = set()
    for line in _code_lines(source):
        started.update(m.lower() for m in re.findall(r"\\([A-Za-z0-9_-]+\.(?:exe|com))\b", line, flags=re.IGNORECASE))
    assert started <= CMD_PROGRAMS, sorted(started - CMD_PROGRAMS)
    for name in sorted(CMD_PROGRAMS - SCANNER_PROGRAMS):
        for line in _code_lines(source):
            if "\\" + name in line.lower():
                assert re.search(r"(?i)%__ES_SYS%\\" + re.escape(name), line), line.strip()


def labelled_lines(source: str) -> list[tuple[str, str]]:
    """(label, line) for every code line; label is the last ":label" above it ("" before the first)."""
    label, result = "", []
    for line in source.split("\n"):
        stripped = line.strip()
        if re.match(r":\w+\s*$", stripped):
            label = stripped[1:]
        elif stripped and not stripped.lower().startswith("rem"):
            result.append((label, stripped))
    return result


def test_for_f_runs_no_command_while_a_capture_file_exists(source: str) -> None:
    """FOR /F ('command') starts "%ComSpec% /c command" without /D, which runs the AutoRun commands
    of the registry. Programs write to the capture file instead; the FOR /F command form is left
    only in the *_child labels used when no private temporary folder exists."""
    command = re.compile(r"(?i)\bfor\s+/f\b.*\bin \(['`]")
    sites = [(label, line) for label, line in labelled_lines(source) if command.search(line)]
    assert sites, "expected the child-mode fallbacks"
    wrong = [f":{label}: {line}" for label, line in sites if not label.endswith("_child")]
    assert not wrong, "\n".join(wrong)
    assert not command.search("for %%c in (' / \\ @) do echo")


def test_no_program_runs_in_a_pipe(source: str) -> None:
    """cmd.exe ends the whole batch file (exit code 255, temporary files left) when a program of a
    pipe cannot be started, e.g. reg.exe blocked or missing: output goes to the capture file and
    is filtered while FOR /F reads it. (A pipe inside a FOR /F command runs in the child.)"""
    pipes = []
    for label, line in labelled_lines(source):
        if line.lower().startswith("echo"):
            continue
        code = re.sub(r'"[^"]*"', '""', line).replace("||", "").replace("^|", "")
        if "|" in code:
            pipes.append(f":{label}: {line}")
    assert not pipes, "\n".join(pipes)


def test_arguments_are_never_forwarded_as_given(source: str) -> None:
    """cmd.exe and PowerShell quote differently ("C:\\x\\" and an unclosed quote), and a raw %*
    holds the & | < > a caller escaped with ^: PowerShell and the 64-bit relaunch both get the
    checked values, each in quotes again."""
    assert not [line for _, line in labelled_lines(source) if "%*" in line]
    launches = [line for _, line in labelled_lines(source) if "-File \"%__ES_PS1%\"" in line]
    assert len(launches) == 2 and all('-File "%__ES_PS1%"%__ES_FWD% <nul' in line for line in launches), launches
    relaunch = [line for _, line in labelled_lines(source) if "Sysnative\\cmd.exe\" /d" in line]
    # The new cmd.exe expands its command line again: the script path goes in as %__ES_RL_SELF%.
    assert relaunch == ['"%__ES_WIN%\\Sysnative\\cmd.exe" /d /v:off /c ^""%%__ES_RL_SELF%%"%__ES_CMDARGS%^"'], relaunch


def test_script_path_is_taken_inside_a_label(source: str) -> None:
    """At the top of a script found on PATH, %~f0 names <working directory>\\envscan.cmd."""
    top = [line for label, line in labelled_lines(source) if not label]
    assert not [line for line in top if re.search(r"%~[a-z]*0", line)], top


def test_arguments_are_checked_before_tilde_expansion(source: str) -> None:
    """%~1 inside quotes is safe only without a quote in the argument, a raw %1 only without the
    & | < > a caller escaped with ^: each argument is first captured raw in a REM run with echo
    on (REM runs nothing) and checked by :es_arg_ok. Only without a capture file (no private
    temporary folder) is %~1 read directly, as before; no other argument expansion exists."""
    body = source.split("\n:es_parse_next\n", 1)[1].split("\nrem -------", 1)[0].split("\n")
    code = [line.strip() for line in body if line.strip() and not line.strip().lower().startswith("rem")]
    line = "@for %%a in (1) do rem %__ES_AN%#%1#"
    raw = [code_line for code_line in code if re.search(r"%\d", code_line)]
    assert raw == [line], raw
    uses = [i for i, code_line in enumerate(code) if re.search(r"%~\d", code_line)]
    assert [code[i] for i in uses] == ['set "__ES_A=%~1"', 'set "__ES_A=%~1"', 'set "__ES_A=%~2"'], uses
    checked, plain, peek = uses
    assert code[checked - 4:checked] == ["call :es_arg_ok", "if errorlevel 3 goto :es_arg_help",
                                         "if errorlevel 1 goto :es_parse_quote",
                                         "if not defined __ES_ARG goto :%__ES_RET%"]
    assert code[plain - 1] == ":es_arg_read_plain"
    assert code[peek - 1] == "if defined __ES_A goto :es_arg_read_plain_ok"
    capture = code.index(line)
    assert code[capture - 6:capture + 4] == [
        "if not defined __ES_CAP goto :es_arg_read_plain", 'set /a "__ES_AN+=1"', "setlocal", 'set "prompt=#"', "(",
        "echo on", line, ') >"%__ES_CAP%"', "@echo off", "endlocal"]
    # REM prints its help for a slash and question mark anywhere on its line, also in a comment.
    assert not [x for x in source.split("\n") if x.strip().lower().startswith("rem") and "/?" in x]


def test_launcher_never_writes_outside_its_own_files(source: str) -> None:
    code = [line for line in source.splitlines() if not line.strip().lower().startswith(("rem ", "echo"))]
    targets = [t for line in code for t in re.findall(r'(?<!\^)>>?\s*"([^"]+)"', line)]
    assert targets, "expected redirections to the output and temporary files"
    allowed = ("%__ES_ERR%", "%__ES_FILE%", "%__ES_T%", "%__ES_TF%", "%__ES_CAP%")
    for target in targets:
        assert target.startswith(allowed), f"unexpected write target {target}"
    for forbidden in ("reg add", "reg delete", "reg import", "setx", "assoc ", "ftype ", "net use"):
        assert forbidden not in source.lower(), forbidden


def test_command_lines_and_registry_strings_are_redacted(source: str) -> None:
    """AutoRun (a command line) and every registry string go through the value rules."""
    autorun =[line for line in source.splitlines() if "AutoRun" in line and not line.lower().startswith("rem")]
    assert autorun and all(line.startswith("call :es_reg_show ") for line in autorun), autorun
    for label in (":es_reg_show", ":es_reg_values", ":es_emit_value", ":es_emit_nv"):
        body = source.split(f"\n{label}\n", 1)[1].split("\nexit /b 0\n", 1)[0]
        assert "call :es_redact_value" in body, f"{label} prints values without the value rules"


def test_echo_escaping_for_list_probes() -> None:
    line = target_cmd._echo("a & b | c < d > e ^ f % g")
    assert line == "echo(a ^& b ^| c ^< d ^> e ^^ f %% g"


def test_lint_reports_lf_and_unreplaced_placeholders() -> None:
    errors = target_cmd.lint("@echo off\r\necho @@ES_NOPE@@\r\necho x\necho y\r\n")
    assert any("unreplaced placeholder @@ES_NOPE@@" in e for e in errors)
    assert any("bare LF" in e for e in errors)


HOSTILE_SPEC_VALUE = 'a"&calc&"'


def _spec_with(spec: Spec, change: Callable[[Spec], Spec | None]) -> Spec:
    copied = copy.deepcopy(spec)
    return change(copied) or copied


@pytest.mark.parametrize("where", ["option_words", "tool_options", "token_prefixes", "pair_keys",
                                   "placeholder", "private_key_marker", "proxy_env", "tool_exe", "probe_id"])
def test_build_refuses_spec_values_that_break_batch(spec: Spec, where: str) -> None:
    """Spec text is pasted raw into set "...", FOR lists and !x:a=b! expressions."""
    def change(s: Spec) -> Spec | None:
        red = s.redaction
        if where == "tool_options":
            red["tool_options"] = [*red["tool_options"], f"{HOSTILE_SPEC_VALUE}:-p"]
        elif where in ("placeholder", "private_key_marker"):
            red[where] = HOSTILE_SPEC_VALUE
        elif where == "proxy_env":
            return dataclasses.replace(s, proxy_env=(*s.proxy_env, HOSTILE_SPEC_VALUE))
        elif where == "tool_exe":
            next(t for t in s.tools if t.get("os", "all") in ("all", "windows"))["exe"].append(HOSTILE_SPEC_VALUE)
        elif where == "probe_id":
            s.probes[0]["id"] = HOSTILE_SPEC_VALUE
        else:
            red[where] = [*red[where], HOSTILE_SPEC_VALUE]
        return None
    expected = f"{HOSTILE_SPEC_VALUE}:-p" if where == "tool_options" else HOSTILE_SPEC_VALUE
    with pytest.raises(ValueError, match=re.escape(repr(expected))) as caught:
        target_cmd.assemble(_spec_with(spec, change), SOURCE_DIR)
    assert "envscan.cmd" in str(caught.value)


@pytest.mark.parametrize("char", list('"&|<>^%!()'))
def test_build_refuses_each_batch_special_character(spec: Spec, char: str) -> None:
    hostile = _spec_with(spec, lambda s: s.redaction.update(option_words=[*s.redaction["option_words"], f"x{char}y"]))
    with pytest.raises(ValueError, match="option_words"):
        target_cmd.assemble(hostile, SOURCE_DIR)
    assert target_cmd.check_spec_values(spec) == []
