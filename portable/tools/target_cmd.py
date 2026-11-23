"""cmd.exe target: assembly, placeholder substitution and lint for envscan.cmd.

The source is split into ordered parts, src/cmd/NN-name.cmd. Each part starts
with one or more "rem ## " header lines, which are left out of the output; the
rest of every part is copied byte for byte, in name order. cmd.exe's call and
goto search the joined file forward from the caller, so the order of routines
and parts is part of the design (hot routines sit right after their callers).

Every part is checked on its own (name, CRLF line endings and a final CRLF,
ASCII, header, known placeholders, no placeholder or %~ in a comment, line
length); all problems are raised together as one ValueError naming the part and
line. Spec text is pasted raw into set "...", FOR lists and !x:a=b! expressions:
check_spec_values() refuses any value bound for the batch that holds one of
" & | < > ^ % ! ( ) (the placeholder text may hold < and >, it is only used
inside quotes and through !expansion!; probe titles and footprints go through
_echo instead). lint() then checks the joined file. The build replaces these placeholders
(each must appear on its own, never inside a parenthesised block for
@@ES_LIST_PROBES@@):

    @@ES_VERSION@@       spec version, e.g. 1.0.0
    @@ES_REDACT_WORDS@@  space-separated upper-case words (segments + contains,
                         union; kept for compatibility, too coarse for names)
    @@ES_REDACT_EXCEPT@@ space-separated variable names that are never redacted
    @@ES_REDACT_SEGMENTS@@  name segments that make a name secret (exact match)
    @@ES_REDACT_CONTAINS@@  substrings of the separator-free name that make it secret
    @@ES_REDACT_SUFFIXES@@  name suffixes that are never secret (paths, sockets)
    @@ES_REDACT_PREFIXES@@  token prefixes (ghp_, AKIA, ...) redacted inside values
    @@ES_REDACT_NAME_SUFFIXES@@  endings of the joined name that make it secret (KEY, PW, ...)
    @@ES_REDACT_PAIRS@@     pair keys (<key>=<value> anywhere in a value, e.g. Pwd=)
    @@ES_REDACT_OPTIONS@@   option words ((-|--|/)<name containing one> <value>)
    @@ES_REDACT_HEADERS@@   header words (-H "<name containing one>: value")
    @@ES_REDACT_TOOL_OPTIONS@@  "tool:option" tokens (a tool's password option, e.g. mysql:-p)
    @@ES_REDACT_TOOL_NAMES@@    the tool names of those tokens, de-duplicated (cheap test)
    @@ES_REDACT_TRIGGERS@@  upper-case words of which every secret name contains at least
                            one (segments, contains, name suffixes and pair keys, without
                            words that contain another): the cheap test before a value is
                            scanned for secret keys
    @@ES_REDACT_PLACEHOLDER@@  the replacement text, e.g. <redacted>
    @@ES_REDACT_PKMARKER@@     text that marks a private key (whole value redacted)
    @@ES_REDACT_MINLEN@@       minimum length of a prefixed token (integer)
    @@ES_TOOLS@@         space-separated "id:exe1,exe2" tokens (Windows tools)
    @@ES_TOOLS_QUOTED@@  the same tokens, each double-quoted so cmd's FOR does
                         not split them at the commas
    @@ES_PROXY_ENV@@     double-quoted, upper-cased, de-duplicated proxy variable
                         names (spec proxy_env; Windows names ignore case)
    @@ES_PROBE_IDS@@     space-separated probe ids implemented by the fallback
    @@ES_ALL_PROBE_IDS@@ space-separated ids of every probe of the full scan (checks
                         --only and --skip)
    @@ES_LIST_PROBES@@   ready-to-run "echo(" lines describing every probe and
                         its footprint (escaped for cmd, delayed expansion off)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Collection, Mapping

from spec import Spec

WINDOWS_OS = ("all", "windows")
PLACEHOLDER_RE = re.compile(r"@@[A-Z_]+@@")
PART_NAME_RE = re.compile(r"\d\d-[a-z0-9]+(?:-[a-z0-9]+)*\.cmd")
PART_HEADER = "rem ## "
LINE_RE = re.compile(r"[\t\x20-\x7e]*")
CMD_LINE_LIMIT = 8000
# Characters that end a quoted string, run a command or expand a variable where a spec
# value is pasted into the batch text.
CMD_UNSAFE = frozenset('"&|<>^%!()')
CMD_UNSAFE_PLACEHOLDER = CMD_UNSAFE - {"<", ">"}
# Redaction lists whose entries reach envscan.cmd (see placeholders()).
CMD_REDACTION_LISTS = (
    "exact_exceptions", "name_segments", "name_contains", "suffix_exceptions", "token_prefixes",
    "name_suffixes", "pair_keys", "option_words", "header_words", "tool_options",
)


def _echo(text: str) -> str:
    escaped = (
        text.replace("^", "^^").replace("&", "^&").replace("|", "^|")
        .replace("<", "^<").replace(">", "^>").replace("%", "%%")
    )
    return f"echo({escaped}"


def _list_probes(spec: Spec) -> str:
    lines: list[str] = []
    for probe in spec.probes_for("cmd"):
        lines.append(_echo(f"{probe['id']}  [{probe['tier']}]  {probe['title']}"))
        lines.extend(_echo(f"    - {line}") for line in probe["footprint"])
    return "\r\n".join(lines)


def _redact_words(spec: Spec) -> str:
    words: list[str] = []
    for word in [*spec.redaction["name_segments"], *spec.redaction["name_contains"]]:
        if word not in words:
            words.append(word)
    return " ".join(words)


def _unique(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


def _triggers(red: Mapping[str, Any]) -> list[str]:
    """Minimal words such that every secret key's joined name contains one of them."""
    words = _unique([
        word.upper()
        for key in ("name_segments", "name_contains", "name_suffixes", "pair_keys")
        for word in red[key]
    ])
    return [word for word in words if not any(other != word and other in word for other in words)]


def _tool_names(red: Mapping[str, Any]) -> list[str]:
    """The tool names of the "tool:option" tokens, in order, without repeats."""
    return _unique([token.split(":", 1)[0] for token in red["tool_options"]])


def _cmd_bound_values(spec: Spec) -> list[tuple[str, str, frozenset[str]]]:
    """(where, value, refused characters) for every spec value pasted into envscan.cmd."""
    red = spec.redaction
    values = [("version", str(spec.version), CMD_UNSAFE)]
    values.extend((f"redaction.{key}", str(entry), CMD_UNSAFE) for key in CMD_REDACTION_LISTS for entry in red[key])
    values.append(("redaction.placeholder", str(red["placeholder"]), CMD_UNSAFE_PLACEHOLDER))
    values.append(("redaction.private_key_marker", str(red["private_key_marker"]), CMD_UNSAFE))
    values.append(("redaction.token_min_length", str(red["token_min_length"]), CMD_UNSAFE))
    for tool in spec.tools:
        if tool.get("os", "all") in WINDOWS_OS:
            values.append(("tools.id", str(tool["id"]), CMD_UNSAFE))
            values.extend((f"tools.{tool['id']}.exe", str(exe), CMD_UNSAFE) for exe in tool["exe"])
    values.extend(("proxy_env", str(name), CMD_UNSAFE) for name in spec.proxy_env)
    values.extend(("probes.id", str(probe["id"]), CMD_UNSAFE) for probe in spec.probes)
    return values


def check_spec_values(spec: Spec) -> list[str]:
    """Spec values that cannot be pasted into envscan.cmd safely, one message each."""
    errors: list[str] = []
    for where, value, refused in _cmd_bound_values(spec):
        bad = sorted(set(value) & refused)
        if bad:
            errors.append(f"spec {where}: {value!r} holds {' '.join(bad)}, which envscan.cmd cannot "
                          f"carry safely (refused: {' '.join(sorted(refused))})")
    return errors


def placeholders(spec: Spec) -> dict[str, str]:
    tools = [t for t in spec.tools if t.get("os", "all") in WINDOWS_OS]
    red = spec.redaction
    tokens = [f"{t['id']}:{','.join(t['exe'])}" for t in tools]
    proxy_names = _unique([name.upper() for name in spec.proxy_env])
    return {
        "@@ES_VERSION@@": spec.version,
        "@@ES_REDACT_WORDS@@": _redact_words(spec),
        "@@ES_REDACT_EXCEPT@@": " ".join(red["exact_exceptions"]),
        "@@ES_REDACT_SEGMENTS@@": " ".join(red["name_segments"]),
        "@@ES_REDACT_CONTAINS@@": " ".join(red["name_contains"]),
        "@@ES_REDACT_SUFFIXES@@": " ".join(red["suffix_exceptions"]),
        "@@ES_REDACT_PREFIXES@@": " ".join(red["token_prefixes"]),
        "@@ES_REDACT_NAME_SUFFIXES@@": " ".join(red["name_suffixes"]),
        "@@ES_REDACT_PAIRS@@": " ".join(red["pair_keys"]),
        "@@ES_REDACT_OPTIONS@@": " ".join(red["option_words"]),
        "@@ES_REDACT_HEADERS@@": " ".join(red["header_words"]),
        "@@ES_REDACT_TOOL_OPTIONS@@": " ".join(red["tool_options"]),
        "@@ES_REDACT_TOOL_NAMES@@": " ".join(_tool_names(red)),
        "@@ES_REDACT_TRIGGERS@@": " ".join(_triggers(red)),
        "@@ES_REDACT_PLACEHOLDER@@": red["placeholder"],
        "@@ES_REDACT_PKMARKER@@": red["private_key_marker"],
        "@@ES_REDACT_MINLEN@@": str(int(red["token_min_length"])),
        "@@ES_TOOLS@@": " ".join(tokens),
        "@@ES_TOOLS_QUOTED@@": " ".join(f'"{token}"' for token in tokens),
        "@@ES_PROXY_ENV@@": " ".join(f'"{name}"' for name in proxy_names),
        "@@ES_PROBE_IDS@@": " ".join(p["id"] for p in spec.probes_for("cmd")),
        "@@ES_ALL_PROBE_IDS@@": " ".join(p["id"] for p in spec.probes),
        "@@ES_LIST_PROBES@@": _list_probes(spec),
    }


def part_files(src: Path) -> list[Path]:
    """The source parts in name order. `src` is src/cmd or a path inside it (tools/build.py passes
    the former single file src/cmd/envscan.cmd; its directory is used)."""
    src_dir = src if src.is_dir() else src.parent
    parts = sorted(src_dir.glob("*.cmd"))
    if not parts or not parts[0].name.startswith("00-"):
        raise FileNotFoundError(f"{src_dir} must contain 00-*.cmd followed by the other NN-*.cmd parts")
    return parts


def _header_length(lines: list[str]) -> int:
    count = 0
    while count < len(lines) and lines[count].startswith(PART_HEADER):
        count += 1
    return count


def check_part(name: str, raw: bytes, known: Collection[str]) -> list[str]:
    """Problems in one part, each as "<part> line <n>: ..."; known = the placeholder names."""
    errors: list[str] = []
    if not PART_NAME_RE.fullmatch(name):
        errors.append(f"{name}: part names look like NN-name.cmd (lower case)")
    text = raw.decode("ascii", errors="replace")
    if "\n" in text.replace("\r\n", ""):
        errors.append(f"{name}: bare LF line endings (cmd labels break)")
    if not text.endswith("\r\n"):
        errors.append(f"{name}: must end with CRLF (its last line would run into the next part)")
    lines = text.split("\r\n")
    if lines[-1] == "":
        lines.pop()
    header = _header_length(lines)
    if header == 0:
        errors.append(f"{name}: must start with a '{PART_HEADER.strip()}' header line")
    elif header == len(lines):
        errors.append(f"{name}: has nothing after its header")
    for number, line in enumerate(lines, start=1):
        where = f"{name} line {number}"
        if not LINE_RE.fullmatch(line):
            errors.append(f"{where}: non-ASCII or control character")
        if len(line) > CMD_LINE_LIMIT:
            errors.append(f"{where}: longer than cmd.exe's line limit")
        errors.extend(f"{where}: unknown placeholder {p}" for p in PLACEHOLDER_RE.findall(line) if p not in known)
        if re.match(r"\s*rem(\s|$)", line, flags=re.IGNORECASE):
            if "%~" in line:
                errors.append(f"{where}: %~ in a comment (cmd.exe expands it and may stop)")
            if "@@" in line:
                errors.append(f"{where}: placeholder in a comment")
    return errors


def _body(raw: bytes) -> str:
    """A part without its header lines, CRLF kept."""
    lines = raw.decode("ascii", errors="replace").split("\r\n")
    return "\r\n".join(lines[_header_length(lines):])


def source_text(src: Path) -> str:
    """The joined parts without headers and before substitution, with "\\n" line endings."""
    return "".join(_body(path.read_bytes()) for path in part_files(src)).replace("\r\n", "\n")


def assemble(spec: Spec, src: Path) -> str:
    """Return envscan.cmd: the parts in name order without their headers, placeholders filled in,
    CRLF line endings. Raises ValueError listing every problem found in the parts."""
    unsafe = check_spec_values(spec)
    if unsafe:
        raise ValueError("spec values for envscan.cmd:\n" + "\n".join(unsafe))
    values = placeholders(spec)
    errors: list[str] = []
    bodies: list[str] = []
    for path in part_files(src):
        raw = path.read_bytes()
        errors.extend(check_part(path.name, raw, values))
        bodies.append(_body(raw))
    if errors:
        raise ValueError("src/cmd parts:\n" + "\n".join(errors))
    text = "".join(bodies).replace("\r\n", "\n")
    for key, value in values.items():
        text = text.replace(key, value.replace("\r\n", "\n"))
    return text.replace("\n", "\r\n")


def lint(text: str) -> list[str]:
    """Problems in the joined envscan.cmd."""
    errors: list[str] = []
    for number, line in enumerate(text.split("\r\n"), start=1):
        if not LINE_RE.fullmatch(line):
            errors.append(f"line {number}: non-ASCII or control character")
        if PLACEHOLDER_RE.search(line):
            errors.append(f"line {number}: unreplaced placeholder {PLACEHOLDER_RE.search(line).group(0)}")
        if len(line) > CMD_LINE_LIMIT:
            errors.append(f"line {number}: longer than cmd.exe's line limit")
    if "\n" in text.replace("\r\n", ""):
        errors.append("file contains bare LF line endings (cmd labels break)")
    return errors
