"""POSIX sh target: generated spec block, assembly and lint for envscan.sh.

The generated block exposes the spec as shell variables and as functions that
print tab-separated tables from quoted here-documents:

    es_spec_probes      id  title  tier  scope  footprint(|-joined)
    es_spec_tools       id  name  cat  mode  os  exe(|)  args(space-joined)  dirs(|)
    es_spec_vmanagers   id  name  markers(|)  requires  versions(|)
    es_spec_configs     id  tool  os  scope  mode  max_bytes  match(|)  paths(|)
    es_spec_caches      id  tool  paths(|)
    es_spec_findings    id  severity  title  recommendation

Empty fields are written as "-" because read collapses consecutive tabs.

Every src/sh/awk/<stem>.awk program is embedded as a function es_awk_<stem> that
prints the program (full-line comments and blank lines removed) from quoted
here-documents; the scanner writes it to its private temp directory once and runs
it with "awk -f". The awk programs are linted for POSIX awk (AWK_FORBIDDEN).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from spec import DEFAULT_CONFIG_MAX_BYTES, Spec

GEN_BEGIN = "# ---- BEGIN GENERATED (tools/build.py from spec/*.toml) - do not edit ----"
GEN_END = "# ---- END GENERATED ----"
UNIX_OS = ("all", "unix", "linux", "darwin")
HEREDOC = "ES_EOF"
HEREDOC_LIMIT = 3000
ALLOW_RE = re.compile(r"#\s*lint-allow:\s*([a-z0-9_,\- ]+)", re.IGNORECASE)
HEREDOC_START_RE = re.compile(r"<<-?\s*'?\"?([A-Za-z_][A-Za-z0-9_]*)'?\"?")

# Where a command word can start: the (left-stripped) start of the line, after ; & | and after
# the keywords then do else elif if while until and "!"; there also after a subshell "(" or a
# group "{"; after ") {" (function body), after $( and after a backquote.
_SEP = r"(?:^|[;&|]\s*|\b(?:then|do|else|elif|if|while|until)\s+|!\s+)"
STATEMENT = r"(?:" + _SEP + r"(?:[({]\s*)*|\)\s*\{\s*|\$\(\s*|`\s*)"
# A bash arithmetic command "((" at a statement start (not the POSIX expansion "$((").
COMMAND_START = _SEP + r"(?:\{\s*)*"
# Rules that must see quoted text (all others run on the code with single-quoted text blanked,
# so that awk programs and messages are not mistaken for shell).
RAW_RULES = frozenset({"grep-bre-alternation"})

# (rule, pattern) applied to left-stripped code lines (comments and here-document bodies are
# skipped).
FORBIDDEN: tuple[tuple[str, str], ...] = (
    ("local", STATEMENT + r"local\s"),
    ("double-bracket", r"(^|[\s;&|(!])\[\[\s"),
    ("function-keyword", r"(^|\s)function\s+\w+"),
    ("source", STATEMENT + r"source\s"),
    ("echo", STATEMENT + r"echo(\s|$)"),
    ("case-modification", r"\$\{[A-Za-z_][A-Za-z0-9_]*(\^|,)"),
    ("array-subscript", r"\$\{#?[A-Za-z_][A-Za-z0-9_]*\["),
    ("arith-increment", r"\$\(\([^)]*(\+\+|--)"),
    ("arith-command", COMMAND_START + r"\(\("),
    ("arith-for", r"\bfor\s*\(\("),
    ("append-assign", r"(^|[\s;&|(])[A-Za-z_][A-Za-z0-9_]*\+="),
    ("pipefail", r"\bset\s.*-[A-Za-z]*o\s+pipefail\b"),
    ("trap-err", r"\btrap\s.*\bERR\b"),
    ("export-f", r"\bexport\s+-[A-Za-z]*f"),
    ("type-p", r"\btype\s+-[A-Za-z]*[Pp]"),
    ("test-and-or", r"\[\s[^]]*\s-[ao]\s[^]]*\]"),
    ("select", STATEMENT + r"select\s"),
    ("time", STATEMENT + r"time\s"),
    ("herestring", r"<<<"),
    ("process-substitution", r"[<>]\("),
    ("redirect-both", r"&>|\|&"),
    ("ansi-c-quote", r"(^|[\s=(;&|])\$'"),
    ("declare", r"(^|\s)(declare|typeset|let|readarray|mapfile|pushd|popd|shopt)\s"),
    ("substring-expansion", r"\$\{[A-Za-z_][A-Za-z0-9_]*:([0-9]|\s+-?[0-9]|\()"),
    ("pattern-substitution", r"\$\{[A-Za-z_][A-Za-z0-9_]*/"),
    ("indirect-expansion", r"\$\{!"),
    ("random", r"\$RANDOM\b"),
    ("array", r"(^|\s)[A-Za-z_][A-Za-z0-9_]*=\("),
    ("test-double-equals", r"\[ [^]]*[^=!<>]==[^=]"),
    ("which", STATEMENT + r"which\s"),
    ("command-v", r"command\s+-v\b"),
    ("sed-extended", r"\bsed\s+(-[a-zA-Z]*[Eri]|--)"),
    ("grep-nonposix", r"\bgrep\s+(-[a-zA-Z]*[oaPrz])"),
    ("grep-bre-alternation", r"\bgrep\s[^|;]*'[^']*\\\|"),
    ("readlink-f", r"\breadlink\s+-f"),
    ("stat", STATEMENT + r"stat\s"),
    ("seq", STATEMENT + r"seq\s"),
    ("head-c", r"\bhead\s+-c"),
    ("maxdepth", r"-maxdepth"),
    ("getconf-a", r"getconf\s+-a"),
    ("date-epoch", r"date\s+\+%s"),
    ("mktemp", r"\bmktemp\b"),
    ("hostname", STATEMENT + r"hostname(\s|[;&|)`]|$)"),
    ("printf-v", r"printf\s+-v"),
    ("read-options", r"\bread\s+-[a-qs-zA-Z]"),
)

# (rule, pattern) applied to the embedded awk programs: POSIX awk only (mawk, BWK awk,
# busybox awk and gawk --posix must all run them).
AWK_FORBIDDEN: tuple[tuple[str, str], ...] = (
    ("gawk-function", r"\b(gensub|asorti?|strftime|systime|mktime|patsplit|isarray|typeof)\s*\("),
    ("gawk-variable", r"\b(PROCINFO|IGNORECASE|FIELDWIDTHS|FPAT|RT|BINMODE)\b"),
    ("bitwise-function", r"\b(and|or|xor|lshift|rshift|compl)\s*\("),
    ("nextfile", r"\bnextfile\b"),
    ("delete-array", r"\bdelete\s+[A-Za-z_][A-Za-z0-9_]*\s*($|[;}])"),
    ("regex-interval", r"[^\s{(]\{[0-9]+(,[0-9]*)?\}"),
    ("power-operator", r"\*\*"),
    ("func-keyword", r"(^|\s)func\s"),
    ("include", r"@(include|load|namespace)\b"),
)
AWK_FUNCTION_RE = re.compile(r"^es_awk_([a-z0-9_]+)\(\) \{$")


@dataclass(frozen=True)
class Assembled:
    dist: str
    lib: str


# --------------------------------------------------------------------------- generation

def _field(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        text = "|".join(str(v) for v in value)
    else:
        text = str(value)
    return text if text else "-"


def _chunks(lines: Sequence[str], limit: int) -> list[list[str]]:
    chunks: list[list[str]] = [[]]
    size = 0
    for line in lines:
        if chunks[-1] and size + len(line) + 1 > limit:
            chunks.append([])
            size = 0
        chunks[-1].append(line)
        size += len(line) + 1
    return chunks


def _table(function: str, rows: Iterable[Sequence[Any]]) -> list[str]:
    """One function printing the rows; here-documents are split below HEREDOC_LIMIT bytes
    because some dash builds (MSYS/Cygwin) silently drop larger here-documents."""
    body = ["\t".join(_field(cell) for cell in row) for row in rows]
    lines = [f"{function}() {{"]
    for chunk in _chunks(body, HEREDOC_LIMIT):
        lines.append(f"cat <<'{HEREDOC}'")
        lines.extend(chunk)
        lines.append(HEREDOC)
    lines.append("}")
    return lines


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _words(values: Iterable[Any]) -> str:
    return _sh_quote(" ".join(str(v) for v in values))


def _thresholds(thresholds: Mapping[str, Any]) -> list[str]:
    lines = []
    for key, value in thresholds.items():
        rendered = " ".join(str(v) for v in value) if isinstance(value, list) else str(value)
        lines.append(f"ES_T_{key.upper()}={_sh_quote(rendered)}")
    return lines


def _child_env(spec: Spec) -> list[str]:
    """es_child_env (the [child_env] overrides, applied in the child subshell), ES_CHILD_SET (their
    names) and the [child_env_keep] allowlist: ES_CHILD_KEEP_NAMES (" A B ", Windows-only "(X86)"
    names dropped) and ES_CHILD_KEEP_PREFIXES (see es_child_keep_init and es_child_refs)."""
    names = [n for n in spec.child_env_keep_names if "(" not in n]
    lines = [
        f"ES_CHILD_SET={_words(spec.child_env)}",
        f"ES_CHILD_KEEP_NAMES={_sh_quote(' ' + ' '.join(names) + ' ')}",
        f"ES_CHILD_KEEP_PREFIXES={_words(spec.child_env_keep_prefixes)}",
        # kept variables vetted as homes (replaced when refused) and as path lists (es_child_vet)
        f"ES_CHILD_HOME_PATHS={_sh_quote(' ' + ' '.join(spec.child_env_home_paths) + ' ')}",
        f"ES_CHILD_PATH_LISTS={_sh_quote(' ' + ' '.join(spec.child_env_path_lists) + ' ')}",
        "es_child_env() {",
    ]
    for name, value in spec.child_env.items():
        lines.append(f"  {name}={_sh_quote(value)}; export {name}")
    lines.append("}")
    return lines


def _ci(text: str) -> str:
    """A case pattern that ignores case: each letter becomes [Xx] (macOS disks ignore case)."""
    return "".join(f"[{ch.upper()}{ch}]" if ch.isalpha() else "[.]" if ch == "." else ch for ch in text)


def _case_function(name: str, subject: str, patterns: Iterable[str]) -> list[str]:
    lines = [f"{name}() {{", f"  case {subject} in"]
    lines.extend(f"    {pattern}) return 0 ;;" for pattern in patterns)
    lines.extend(["  esac", "  return 1", "}"])
    return lines


def _credential_functions(spec: Spec) -> list[str]:
    """es_cred_folder_hit / es_cred_file_hit / es_cred_key_ext from spec/policy.toml (see es_cred_match)."""
    creds = spec.credentials
    return [
        *_case_function("es_cred_folder_hit", "/$1/", (f"*/{_ci(n)}/*" for n in creds["folders"])),
        *_case_function("es_cred_file_hit", "/$1", [*(f"*/{_ci(n)}" for n in creds["files"]),
                                                    *(f"*{_ci(n)}" for n in creds["suffixes"])]),
        *_case_function("es_cred_key_ext", "$1", (f"*.{_ci(n)}" for n in creds["key_extensions"])),
        # exact leaf names of CA trust stores (spec policy.toml trust_store_names), see es_ca_path
        *_case_function("es_trust_store_leaf", "$1", (_ci(n) for n in spec.trust_store_names)),
    ]


def _variable_lines(spec: Spec) -> list[str]:
    return [
        f"ES_NAME={_sh_quote(spec.meta['name'])}",
        f"ES_VERSION={_sh_quote(spec.version)}",
        f"ES_SCHEMA={_sh_quote(spec.meta['schema'])}",
        f"ES_PACKAGE_ENV={_words(spec.package_env)}",
        f"ES_PROXY_ENV={_words(spec.proxy_env)}",
        f"ES_TLS_ENV={_words(spec.tls_env)}",
        f"ES_CA_BUNDLES={_words(spec.ca_bundles)}",
        f"ES_CA_ANCHOR_DIRS={_words(spec.ca_anchor_dirs)}",
        f"ES_NET_FS={_sh_quote(' ' + ' '.join(spec.network_fs) + ' ')}",
        # a type starting with a prefix is a network mount unless it is in ES_LOCAL_FUSE (es_is_netfs)
        f"ES_NET_FS_PREFIXES={_words(spec.network_fs_prefixes)}",
        f"ES_LOCAL_FUSE={_sh_quote(' ' + ' '.join(spec.local_fuse) + ' ')}",
        f"ES_PUBLIC_HOSTS={_words(spec.public_hosts)}",
        f"ES_NET_NEVER={_words(spec.net_never)}",
        # IBM-1047 -> Unicode, decimal, one per byte 0x00-0xFF (spec/ebcdic.toml; json.awk -v ebcdic_tab)
        f"ES_EBCDIC_TAB={_words(spec.documents['ebcdic.toml']['ibm1047']['codepoints'])}",
    ]


def _redaction_lines(red: Mapping[str, Any]) -> list[str]:
    words = {
        "ES_REDACT_SEGMENTS": "name_segments", "ES_REDACT_CONTAINS": "name_contains",
        "ES_REDACT_NAME_SUFFIXES": "name_suffixes", "ES_REDACT_EXCEPTIONS": "exact_exceptions",
        "ES_REDACT_SUFFIX_EXCEPTIONS": "suffix_exceptions", "ES_REDACT_PREFIXES": "token_prefixes",
    }
    later = {
        "ES_REDACT_PAIR_KEYS": "pair_keys", "ES_REDACT_OPTION_WORDS": "option_words",
        "ES_REDACT_HEADER_WORDS": "header_words", "ES_REDACT_TOOL_OPTIONS": "tool_options",
        "ES_REDACT_XML_ELEMENTS": "xml_elements", "ES_REDACT_XML_ATTRS": "xml_attributes",
    }
    return [
        f"ES_REDACT_PLACEHOLDER={_sh_quote(red['placeholder'])}",
        *(f"{var}={_words(red[key])}" for var, key in words.items()),
        f"ES_REDACT_MINLEN={red['token_min_length']}",
        *(f"{var}={_words(red[key])}" for var, key in later.items()),
        f"ES_REDACT_PKMARKER={_sh_quote(red['private_key_marker'])}",
    ]


def _table_lines(spec: Spec) -> list[str]:
    tools = [t for t in spec.tools if t.get("os", "all") in UNIX_OS]
    configs = [c for c in spec.configs if c.get("os", "all") in UNIX_OS]
    return [
        *_table("es_spec_probes", (
            (p["id"], p["title"], p["tier"], p["scope"], p["footprint"]) for p in spec.probes_for("sh")
        )),
        *_table("es_spec_tools", (
            (t["id"], t["name"], t["cat"], t.get("mode", "version"), t.get("os", "all"),
             t["exe"], " ".join(t.get("args", [])), t.get("dirs", []))
            for t in tools
        )),
        *_table("es_spec_vmanagers", (
            (m["id"], m["name"], m.get("markers", []), m.get("requires", ""), m["versions"])
            for m in spec.version_managers
        )),
        *_table("es_spec_configs", (
            (c["id"], c["tool"], c.get("os", "all"), c["scope"], c.get("mode", "content"),
             c.get("max_bytes", DEFAULT_CONFIG_MAX_BYTES), c.get("match", []), c["paths"])
            for c in configs
        )),
        *_table("es_spec_caches", ((c["id"], c["tool"], c["paths"]) for c in spec.caches)),
        *_table("es_spec_findings", (
            (f["id"], f["severity"], f["title"], f["recommendation"]) for f in spec.findings
        )),
    ]


def generate(spec: Spec) -> str:
    """The generated block inserted after 00-preamble.sh."""
    lines = [
        GEN_BEGIN,
        *_variable_lines(spec),
        *_redaction_lines(spec.redaction),
        *_thresholds(spec.thresholds),
        *_child_env(spec),
        *_credential_functions(spec),
        *_table_lines(spec),
        GEN_END,
    ]
    return "\n".join(lines)


def _awk_program_lines(text: str) -> list[str]:
    """awk source without full-line comments, blank lines or trailing whitespace."""
    lines = []
    for line in text.replace("\r\n", "\n").split("\n"):
        stripped = line.rstrip()
        if stripped and not stripped.lstrip().startswith("#"):
            lines.append(stripped)
    return lines


def awk_functions(awk_dir: Path) -> str:
    """es_awk_<stem>() functions printing each src/sh/awk/<stem>.awk program."""
    blocks: list[str] = []
    for path in sorted(awk_dir.glob("*.awk")):
        stem = re.sub(r"[^a-z0-9_]", "_", path.stem.lower())
        lines = _awk_program_lines(path.read_text(encoding="ascii"))
        if any(line.strip() == HEREDOC for line in lines):
            raise ValueError(f"{path.name}: a line equals the here-document terminator {HEREDOC}")
        body = [f"es_awk_{stem}() {{"]
        for chunk in _chunks(lines, HEREDOC_LIMIT):
            body.append(f"cat <<'{HEREDOC}'")
            body.extend(chunk)
            body.append(HEREDOC)
        body.append("}")
        blocks.append("\n".join(body))
    return "\n\n".join(blocks)


# --------------------------------------------------------------------------- assembly

def _modules(src_dir: Path) -> list[Path]:
    modules = sorted(src_dir.glob("*.sh"))
    if not modules or not modules[0].name.startswith("00-"):
        raise FileNotFoundError(f"{src_dir} must contain 00-*.sh followed by the other modules")
    return modules


def _join(parts: Sequence[str]) -> str:
    text = "\n\n".join(part.replace("\r\n", "\n").strip("\n") for part in parts) + "\n"
    return text


def assemble(spec: Spec, src_dir: Path) -> Assembled:
    """dist = preamble + generated block + awk programs + modules;
    lib = generated block + awk programs + modules except 00-* and 9x-*."""
    modules = _modules(src_dir)
    texts = [(m.name, m.read_text(encoding="ascii")) for m in modules]
    block = generate(spec)
    awk_dir = src_dir / "awk"
    awk = awk_functions(awk_dir) if awk_dir.is_dir() else ""
    generated = [part for part in (block, awk) if part]
    dist = _join([texts[0][1], *generated, *(text for _, text in texts[1:])])
    lib = _join([*generated, *(text for name, text in texts[1:] if not name.startswith("9"))])
    return Assembled(dist=dist, lib=lib)


# --------------------------------------------------------------------------- lint

def _code_lines(text: str) -> Iterable[tuple[int, str]]:
    """Yield (line number, line) for lines outside here-document bodies."""
    terminator: str | None = None
    for number, line in enumerate(text.split("\n"), start=1):
        if terminator is not None:
            if line.strip() == terminator:
                terminator = None
            continue
        yield number, line
        start = HEREDOC_START_RE.search(line.split("#", 1)[0]) if "<<" in line else None
        if start:
            terminator = start.group(1)


def _masked_code_lines(text: str) -> Iterable[tuple[int, str, str]]:
    """Yield (line number, line, code) for lines outside here-document bodies, where code is the
    line with single-quoted text blanked (quote characters kept) and its # comment removed.
    Quote state carries across lines, so the lines of a multi-line awk program are blank."""
    in_single = in_double = False
    for number, line in _code_lines(text):
        out: list[str] = []
        index = 0
        while index < len(line):
            char = line[index]
            if in_single:
                in_single = char != "'"
                out.append(char if not in_single else " ")
            elif char == "\\" and index + 1 < len(line):
                out.append(line[index:index + 2])
                index += 2
                continue
            elif char == '"':
                in_double = not in_double
                out.append(char)
            elif char == "'" and not in_double:
                in_single = True
                out.append(char)
            elif char == "#" and not in_double and (index == 0 or line[index - 1] in " \t;&|("):
                break
            else:
                out.append(char)
            index += 1
        yield number, line, "".join(out)


def _strip_comment(line: str) -> str:
    """Drop a trailing # comment (best effort: ignores # inside quotes or ${#...})."""
    in_single = in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            if index == 0 or line[index - 1] in " \t;":
                return line[:index]
    return line


def _oversized_heredocs(text: str) -> list[str]:
    errors: list[str] = []
    terminator: str | None = None
    start = size = 0
    for number, line in enumerate(text.split("\n"), start=1):
        if terminator is None:
            match = HEREDOC_START_RE.search(line.split("#", 1)[0]) if "<<" in line else None
            if match:
                terminator, start, size = match.group(1), number, 0
            continue
        if line.strip() == terminator:
            if size > HEREDOC_LIMIT:
                errors.append(f"line {start}: here-document of {size} bytes exceeds {HEREDOC_LIMIT} (MSYS dash drops it)")
            terminator = None
        else:
            size += len(line) + 1
    return errors


def _awk_bodies(text: str) -> Iterable[tuple[str, int, str]]:
    """Yield (function, line number, line) for the here-document lines of es_awk_* functions."""
    function: str | None = None
    in_body = False
    for number, line in enumerate(text.split("\n"), start=1):
        if function is None:
            match = AWK_FUNCTION_RE.match(line)
            if match:
                function = match.group(1)
            continue
        if line == "}" and not in_body:
            function = None
        elif line == f"cat <<'{HEREDOC}'":
            in_body = True
        elif line == HEREDOC:
            in_body = False
        elif in_body:
            yield function, number, line


def _awk_code(line: str) -> str:
    """Drop string literals (best effort) so words inside messages are not linted."""
    return re.sub(r'"(\\.|[^"\\])*"', '""', line)


AWK_FUNCTION_DEF_RE = re.compile(r"^function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")


def lint_awk(text: str) -> list[str]:
    errors: list[str] = []
    programs: dict[str, list[tuple[int, str]]] = {}
    for function, number, line in _awk_bodies(text):
        programs.setdefault(function, []).append((number, line))
        code = _awk_code(line)
        for rule, pattern in AWK_FORBIDDEN:
            if re.search(pattern, code):
                errors.append(f"line {number}: awk program {function}: non-POSIX awk [{rule}]: {line.strip()[:120]}")
    # A parameter named like a function is a parse error in every awk: the whole program fails.
    for function, lines in programs.items():
        defs = [(n, AWK_FUNCTION_DEF_RE.match(line.strip())) for n, line in lines]
        names = {m.group(1) for _, m in defs if m}
        for number, match in defs:
            if not match:
                continue
            params = [p for p in re.split(r"[\s,]+", match.group(2)) if p]
            for param in params:
                if param in names:
                    errors.append(f"line {number}: awk program {function}: parameter {param!r} of "
                                  f"{match.group(1)}() shadows a function")
    return errors


def lint(text: str) -> list[str]:
    """Return lint errors for an assembled envscan.sh."""
    errors: list[str] = _oversized_heredocs(text) + lint_awk(text)
    if "\r" in text:
        errors.append("file contains CR characters (must be LF only)")
    for number, line in enumerate(text.split("\n"), start=1):
        if not re.fullmatch(r"[\t\x20-\x7e]*", line):
            errors.append(f"line {number}: non-ASCII or control character")
    for number, line, masked in _masked_code_lines(text):
        match = ALLOW_RE.search(line)
        allowed = {r.strip().lower() for r in match.group(1).split(",")} if match else set()
        raw = _strip_comment(line).lstrip()
        code = masked.lstrip()
        for rule, pattern in FORBIDDEN:
            if rule not in allowed and re.search(pattern, raw if rule in RAW_RULES else code):
                errors.append(f"line {number}: forbidden construct [{rule}]: {line.strip()[:120]}")
    return errors
