"""Windows Script Host target: generated spec block, assembly and lint for envscan.js.

envscan.js runs under cscript.exe as JScript 5.8, an ES3 dialect: no JSON object, no Array
forEach/map/filter/indexOf, no String trim, no let/const, no arrow functions, no regex lookbehind.
The lint below rejects those constructs, any COM object outside the allowlist, non-ASCII text and
the keywords that security tooling scores as suspicious (the PowerShell list from target_ps also
applies here: AMSI scans WSH scripts too, so the same benign wording rules hold).

The syntax rules see the code only: comments and the text of string and regex literals are
blanked first (CodeView). The suspicious-keyword scan sees everything.
"""
from __future__ import annotations

import bisect
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from spec import DEFAULT_CONFIG_MAX_BYTES, Spec
from target_ps import SUSPICIOUS, WINDOWS_OS

GEN_BEGIN = "// ---- BEGIN GENERATED (tools/build.py from spec/*.toml) - do not edit ----"
GEN_END = "// ---- END GENERATED ----"
IMPL_ID = "js"

# COM ProgIDs envscan.js may create (new ActiveXObject("...")); nothing else, and never GetObject.
COM_ALLOWLIST = frozenset({
    "Scripting.FileSystemObject", "WScript.Shell", "WbemScripting.SWbemLocator",
})

# The members of the only COM instances (ES_FSO, ES_SHELL) and of WScript that the code may use: a
# positive allowlist, derived from what the engine and the probes use (compared without case, as
# COM dispatch does). A new member is a deliberate change here, reviewed like a new ProgID.
MEMBER_ALLOWLIST: dict[str, frozenset[str]] = {
    "ES_FSO": frozenset({
        "CreateFolder", "CreateTextFile", "DeleteFile", "DeleteFolder", "Drives", "FileExists",
        "FolderExists", "GetAbsolutePathName", "GetFile", "GetFileVersion", "GetFolder",
        "GetParentFolderName", "GetSpecialFolder", "OpenTextFile",
    }),
    "ES_SHELL": frozenset({"CurrentDirectory", "Environment", "Exec", "ExpandEnvironmentStrings", "RegRead"}),
    "WScript": frozenset({
        "Arguments", "Echo", "FullName", "Quit", "ScriptFullName", "Sleep", "StdErr", "StdOut", "Version",
    }),
}

# Member names never reached through a computed (bracketed) string index: they would bypass the
# dotted-name rules below.
BANNED_NAMES = frozenset(name.lower() for name in (
    "eval", "Function", "ActiveXObject", "GetObject", "CreateObject", "execScript", "ExecuteGlobal",
    "constructor", "prototype", "__proto__", "hasOwnProperty", "Run", "Exec", "ShellExecute", "RegWrite",
    "RegDelete", "Popup", "LogEvent", "SendKeys", "AppActivate", "CreateShortcut", "setTimeout",
    "setInterval", "CopyFile", "MoveFile", "CopyFolder", "MoveFolder", "DeleteFolder", "DeleteFile",
    "Delete", "Copy", "Move", "Environment", "ConnectServer", "ExecQuery", "ExecMethod_", "Terminate",
    "Item", "Methods_", "SpawnInstance_", "Get",
))

# (rule, pattern, flags): ES5+/JScript-incompatible constructs and unsafe calls, matched against the
# whole code view (comments and literals blanked), so \s also spans line breaks: a call split as
# "GetObject" + newline + "(" is seen. A match is reported on the line where it starts; a
# "// lint-allow: <rule>" tag on that line accepts it.
FORBIDDEN: tuple[tuple[str, str, int], ...] = (
    ("let-const", r"(?<![\w$.])(let|const)\s+[A-Za-z_$]", 0),
    ("arrow", r"=>", 0),
    ("template", r"`", 0),
    ("class", r"(?<![\w$.])class\s+[A-Za-z_$]", 0),
    ("for-of", r"\bfor\s*\([^)]*\bof\b", 0),
    ("spread", r"\.\.\.[A-Za-z_$\[]", 0),
    ("array-es5", r"\.(forEach|map|filter|reduce|reduceRight|some|every)\s*\(", 0),
    ("trim", r"\.trim(Left|Right|Start|End)?\s*\(", 0),
    ("object-es5", r"\bObject\s*\.\s*(keys|create|defineProperty|freeze|assign|getOwnPropertyNames)\b", 0),
    ("json-object", r"(?<![\w$.])JSON\s*\.", 0),
    ("array-isarray", r"\bArray\s*\.\s*isArray\b", 0),
    ("date-now", r"\bDate\s*\.\s*now\b", 0),
    ("bind", r"\.\s*bind\s*\(", 0),
    ("eval", r"(?<![\w$])eval\b", 0),
    ("function-ctor", r"(?<![\w$])Function\b", 0),
    ("getobject", r"(?<![\w$])(GetObject|CreateObject)\b", re.IGNORECASE),
    ("debugger", r"(?<![\w$.])debugger\b", 0),
    ("trailing-comma", r",\s*[\]}]", 0),
    ("execute-global", r"\b(ExecuteGlobal|execScript)\b", re.IGNORECASE),
    ("constructor", r"\.\s*constructor\b", 0),
    ("timer", r"(?<![\w$])(setTimeout|setInterval)\b", 0),
    ("shell-run", r"\.\s*(ShellExecute|RegWrite|RegDelete|Run|Popup|LogEvent|SendKeys|AppActivate|CreateShortcut)\s*\(",
     re.IGNORECASE),
    ("temp-cleanup", r"\.\s*(CopyFile|MoveFile|CopyFolder|MoveFolder|DeleteFolder|Copy|Move|Delete)\s*\(", re.IGNORECASE),
    ("this", r"(?<![\w$.])this\b", 0),
    ("global-lookup", r"(?<![\w$.])ES_GLOBAL\b", 0),
)
# A data key named "hasOwnProperty" shadows the method: only Object.prototype.hasOwnProperty.call(
# (or esHas) may test own keys.
HAS_OWN_RULE = ("has-own-property", r"\bhasOwnProperty\b")
_HAS_OWN_OK_RE = re.compile(r"\bObject\s*\.\s*prototype\s*\.\s*hasOwnProperty\s*\.\s*call\s*\(")
_FORBIDDEN_RES = tuple((rule, re.compile(pattern, flags)) for rule, pattern, flags in FORBIDDEN)
_SUSPICIOUS_RES = tuple((word, re.compile(re.escape(word), re.IGNORECASE)) for word in SUSPICIOUS)
# In the code view a string literal keeps its quotes and is blank inside: ("     ").
_LITERAL = r"(['\"])( *)\{n}"
_ACTIVEX_LITERAL_RE = re.compile(r"\bnew\s+ActiveXObject\s*\(\s*" + _LITERAL.format(n=1) + r"\s*\)")
_ACTIVEX_ANY_RE = re.compile(r"\bActiveXObject\b")
_RECEIVER_RE = re.compile(r"(?<![\w$.])(ES_FSO|ES_SHELL|WScript)\b(\s*\.\s*([A-Za-z_$][\w$]*))?")
_DEFINITION_RE = re.compile(r"\bvar\s+$")
_ENVIRONMENT_RE = re.compile(r"\.\s*Environment\b(\s*\(\s*" + _LITERAL.format(n=2) + r"\s*\))?", re.IGNORECASE)
_CONNECT_RE = re.compile(r"\.\s*ConnectServer\b(\s*\(\s*" + _LITERAL.format(n=2) + r"\s*,)?", re.IGNORECASE)
_INDEX_RE = re.compile(r"\[([^\[\]]*)\]")
_STRING_RE = re.compile(_LITERAL.format(n=1))
_INDEX_KEYWORDS = ("return", "typeof", "case", "in", "delete", "void", "throw", "new", "else", "do")
ALLOW_RE = re.compile(r"//\s*lint-allow:\s*([a-z0-9_,\- ]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Assembled:
    dist: str
    lib: str


# --------------------------------------------------------------------------- literals

def js_string(value: str) -> str:
    """A double-quoted ES3 string literal holding only printable ASCII."""
    out = []
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= code <= 0x7E:
            out.append(ch)
        elif code <= 0xFFFF:
            out.append(f"\\u{code:04x}")
        else:
            code -= 0x10000
            out.append(f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}")
    return '"' + "".join(out) + '"'


def js_literal(value: Any) -> str:
    """Render a Python value as an ES3 literal (keys always quoted: reserved words are keys too)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"cannot render {value!r} as a JScript literal")
        return repr(value)
    if isinstance(value, str):
        return js_string(value)
    if isinstance(value, Mapping):
        body = ", ".join(f"{js_string(str(k))}: {js_literal(v)}" for k, v in value.items())
        return "{" + body + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(js_literal(v) for v in value) + "]"
    raise TypeError(f"cannot render {type(value).__name__} as a JScript literal")


def _js_array(name: str, rows: Sequence[Mapping[str, Any]]) -> list[str]:
    if not rows:
        return [f"var {name} = [];"]
    lines = [f"var {name} = ["]
    lines.extend(f"    {js_literal(row)}," for row in rows[:-1])
    lines.append(f"    {js_literal(rows[-1])}")
    lines.append("];")
    return lines


def _windows_paths(paths: Sequence[str]) -> list[str]:
    """Spec paths that mean something on Windows (see target_ps._windows_paths)."""
    return [path for path in paths if not path.startswith("/")]


def _tool_row(tool: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": tool["id"], "name": tool["name"], "cat": tool["cat"],
        "exe": list(tool["exe"]), "args": list(tool.get("args", [])),
        "mode": tool.get("mode", "version"), "os": tool.get("os", "all"),
        "dirs": _windows_paths(tool.get("dirs", [])),
    }


def _config_row(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": config["id"], "tool": config["tool"], "scope": config["scope"],
        "mode": config.get("mode", "content"), "match": list(config.get("match", [])),
        "paths": _windows_paths(config["paths"]),
        "max_bytes": config.get("max_bytes", DEFAULT_CONFIG_MAX_BYTES),
    }


def _credential_lines(spec: Spec) -> list[str]:
    """Credential names for testEsCredentialPath, with "\\" separators as in the PowerShell target."""
    creds = spec.credentials
    lines = [f"var ES_TRUST_STORE_NAMES = {js_literal(list(spec.trust_store_names))};"]
    lines.extend(f"var ES_CRED_{key.upper()} = {js_literal([n.replace('/', chr(92)) for n in creds[key]])};"
                 for key in ("folders", "files", "suffixes", "key_extensions"))
    return lines


def generate(spec: Spec) -> str:
    """The generated block inserted after 00-*.js: the same tables as the PowerShell target."""
    probes = [
        {"id": p["id"], "title": p["title"], "tier": p["tier"], "scope": p["scope"],
         "about": p["about"], "footprint": list(p["footprint"])}
        for p in spec.probes_for(IMPL_ID)
    ]
    tools = [_tool_row(t) for t in spec.tools if t.get("os", "all") in WINDOWS_OS]
    managers = [
        {"id": m["id"], "name": m["name"], "markers": list(m.get("markers", [])),
         "requires": m.get("requires", ""), "versions": list(m["versions"])}
        for m in spec.version_managers
    ]
    configs = [row for row in (_config_row(c) for c in spec.configs if c.get("os", "all") in WINDOWS_OS)
               if row["paths"]]
    caches = [{"id": c["id"], "tool": c["tool"], "paths": _windows_paths(c["paths"])}
              for c in spec.caches if _windows_paths(c["paths"])]
    findings = {
        f["id"]: {"severity": f["severity"], "title": f["title"], "recommendation": f["recommendation"]}
        for f in spec.findings
    }
    lines = [
        GEN_BEGIN,
        f"var ES_NAME = {js_literal(spec.meta['name'])};",
        f"var ES_VERSION = {js_literal(spec.version)};",
        f"var ES_SCHEMA = {js_literal(spec.meta['schema'])};",
        *_js_array("ES_PROBES", probes),
        *_js_array("ES_TOOLS", tools),
        *_js_array("ES_VMANAGERS", managers),
        *_js_array("ES_CONFIGS", configs),
        *_js_array("ES_CACHES", caches),
        f"var ES_PACKAGE_ENV = {js_literal(list(spec.package_env))};",
        f"var ES_PROXY_ENV = {js_literal(list(spec.proxy_env))};",
        f"var ES_TLS_ENV = {js_literal(list(spec.tls_env))};",
        f"var ES_PUBLIC_HOSTS = {js_literal(list(spec.public_hosts))};",
        f"var ES_NET_NEVER = {js_literal(list(spec.net_never))};",
        *_credential_lines(spec),
        f"var ES_REDACT = {js_literal(dict(spec.redaction))};",
        f"var ES_FINDINGS = {js_literal(findings)};",
        f"var ES_THRESHOLDS = {js_literal(dict(spec.thresholds))};",
        f"var ES_CHILD_ENV = {js_literal(dict(spec.child_env))};",
        f"var ES_CHILD_ENV_KEEP_NAMES = {js_literal(list(spec.child_env_keep_names))};",
        f"var ES_CHILD_ENV_KEEP_PREFIXES = {js_literal(list(spec.child_env_keep_prefixes))};",
        f"var ES_CHILD_ENV_HOME_PATHS = {js_literal(list(spec.child_env_home_paths))};",
        f"var ES_CHILD_ENV_PATH_LISTS = {js_literal(list(spec.child_env_path_lists))};",
        GEN_END,
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- assembly

def _modules(src_dir: Path, include: Callable[[str], bool] | None = None) -> list[Path]:
    modules = [m for m in sorted(src_dir.glob("*.js")) if include is None or include(m.name)]
    if not modules or not modules[0].name.startswith("00-"):
        raise FileNotFoundError(f"{src_dir} must contain 00-*.js followed by the other modules")
    return modules


def _read_module(path: Path) -> str:
    data = path.read_bytes()
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as exc:
        line = data[:exc.start].count(b"\n") + 1
        raise ValueError(f"{path.name}: line {line}: non-ASCII byte 0x{data[exc.start]:02x}") from None


def _join(parts: Sequence[str]) -> str:
    text = "\r\n\r\n".join(part.replace("\r\n", "\n").strip("\n").replace("\n", "\r\n") for part in parts)
    return text + "\r\n"


def assemble(spec: Spec, src_dir: Path, include: Callable[[str], bool] | None = None) -> Assembled:
    """dist = every module with the generated block after 00-*; lib = dist without 9x-* (main and entry).
    `include` (module file name -> bool) selects a subset, for tests of one area; None takes all.
    A module with a non-ASCII byte raises ValueError naming the file and line."""
    modules = _modules(src_dir, include)
    texts = [(m.name, _read_module(m)) for m in modules]
    block = generate(spec)
    ordered = [texts[0][1], block, *(text for _, text in texts[1:])]
    library = [texts[0][1], block, *(text for name, text in texts[1:] if not name.startswith("9"))]
    return Assembled(dist=_join(ordered), lib=_join(library))


# --------------------------------------------------------------------------- code view

# A "/" starts a regex literal (not a division) after one of these, or at the start of the text.
_REGEX_AFTER = frozenset("(,=:[!&|?{};+-*%<>~^")
_REGEX_KEYWORDS = ("return", "typeof", "case", "in", "delete", "void", "throw", "new")


def _regex_allowed(code: list[str], index: int) -> bool:
    j = index - 1
    while j >= 0 and code[j] in " \t\r\n":
        j -= 1
    if j < 0:
        return True
    if code[j] in _REGEX_AFTER:
        return True
    end = j + 1
    while j >= 0 and (code[j].isalnum() or code[j] in "_$"):
        j -= 1
    return "".join(code[j + 1:end]) in _REGEX_KEYWORDS


def code_view(text: str) -> str:
    """`text` with comments and the contents of string and regex literals replaced by spaces (same
    length and line breaks). Quotes and regex slashes stay, so `"a" + b` keeps its shape."""
    code = list(text)
    i, n = 0, len(text)

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if code[k] not in "\r\n":
                code[k] = " "

    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(i, end)
            i = end
        elif ch in "'\"":
            j = i + 1
            while j < n and text[j] != ch and text[j] not in "\r\n":
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        elif ch == "/" and _regex_allowed(code, i):
            j, in_class = i + 1, False
            while j < n and text[j] not in "\r\n":
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "[":
                    in_class = True
                elif text[j] == "]":
                    in_class = False
                elif text[j] == "/" and not in_class:
                    break
                j += 1
            blank(i + 1, j)
            i = j + 1
        else:
            i += 1
    return "".join(code)


# --------------------------------------------------------------------------- lint

# The has-own-property rule (no direct x.hasOwnProperty( calls) is on once every module uses esHas.
CHECK_HAS_OWN = True


def _allowed_rules(line: str) -> set[str]:
    match = ALLOW_RE.search(line)
    return {rule.strip() for rule in match.group(1).split(",")} if match else set()


# JScript cannot receive WMI out parameters, so StdRegProv calls need the method's in-parameter
# object from the SWbemObject member "Methods_" (no other route exists). That one member is
# accepted on a line marked "// lint-allow: wmi-inparams", and only as ".Methods_.Item(": the word
# stays forbidden everywhere else.
_WMI_METHODS_RE = re.compile(r"\.Methods_\.Item\(")


def _wmi_methods_allowed(word: str, raw: str, allowed: set[str]) -> bool:
    if word != "Methods" or "wmi-inparams" not in allowed:
        return False
    return not re.search("methods", _WMI_METHODS_RE.sub("", raw), re.IGNORECASE)


class _Text:
    """The raw text, its code view and the line of an offset (the rules see the whole text)."""

    def __init__(self, text: str) -> None:
        self.raw = text
        self.view = code_view(text)
        self.lines = text.split("\n")
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self.allowed = [_allowed_rules(line) for line in self.lines]

    def number(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)

    def allows(self, offset: int, rule: str) -> bool:
        return rule in self.allowed[self.number(offset) - 1]

    def error(self, offset: int, rule: str) -> str:
        number = self.number(offset)
        return f"line {number}: {rule}: {self.lines[number - 1].strip()[:120]}"

    def literal(self, start: int, end: int) -> str:
        """The raw text of a blanked literal (same offsets in raw text and view)."""
        return self.raw[start:end]


def _lint_forbidden(t: _Text) -> list[str]:
    errors = []
    for rule, pattern in _FORBIDDEN_RES:
        errors.extend(t.error(m.start(), rule) for m in pattern.finditer(t.view) if not t.allows(m.start(), rule))
    return errors


def _lint_has_own(t: _Text) -> list[str]:
    ok = set()
    for m in _HAS_OWN_OK_RE.finditer(t.view):
        ok.add(t.view.index("hasOwnProperty", m.start()))
    rule, pattern = HAS_OWN_RULE
    return [t.error(m.start(), rule) for m in re.finditer(pattern, t.view)
            if m.start() not in ok and not t.allows(m.start(), rule)]


def _lint_activex(t: _Text) -> list[str]:
    """Every ActiveXObject in the file is a `new ActiveXObject("<allowlisted literal>")`."""
    errors = []
    literal_words = set()
    for m in _ACTIVEX_LITERAL_RE.finditer(t.view):
        literal_words.add(t.view.index("ActiveXObject", m.start()))
        progid = t.literal(m.start(2), m.end(2))
        if progid not in COM_ALLOWLIST:
            errors.append(t.error(m.start(), f"COM object {progid!r} is not in the allowlist"))
    errors.extend(t.error(m.start(), "ActiveXObject needs a literal ProgID")
                  for m in _ACTIVEX_ANY_RE.finditer(t.view) if m.start() not in literal_words)
    return errors


def _lint_receivers(t: _Text) -> list[str]:
    """ES_FSO, ES_SHELL and WScript: only allowlisted members, never aliased or indexed."""
    errors = []
    allow = {name: {m.lower() for m in members} for name, members in MEMBER_ALLOWLIST.items()}
    for m in _RECEIVER_RE.finditer(t.view):
        name, member = m.group(1), m.group(3)
        if member is None:
            line_start = t.starts[t.number(m.start()) - 1]
            definition = _DEFINITION_RE.search(t.view[line_start:m.start()]) and \
                re.match(r"\s*=[^=]", t.view[m.end():m.end() + 8])
            if not definition:
                errors.append(t.error(m.start(), f"{name} used other than as {name}.<member>"))
        elif member.lower() not in allow[name]:
            errors.append(t.error(m.start(), f"{name}.{member} is not in the member allowlist"))
    return errors


def _lint_com_arguments(t: _Text) -> list[str]:
    """Environment("PROCESS") only; ConnectServer(".", ...) only."""
    errors = []
    for m in _ENVIRONMENT_RE.finditer(t.view):
        if m.group(1) is None or t.literal(m.start(3), m.end(3)).upper() != "PROCESS":
            errors.append(t.error(m.start(), "environment other than PROCESS"))
    for m in _CONNECT_RE.finditer(t.view):
        if m.group(1) is None or t.literal(m.start(3), m.end(3)) != ".":
            errors.append(t.error(m.start(), "ConnectServer to another host"))
    return errors


def _is_index(view: str, bracket: int) -> bool:
    """True when the "[" at `bracket` indexes a value (a[...]), not an array literal."""
    j = bracket - 1
    while j >= 0 and view[j] in " \t\r\n":
        j -= 1
    if j < 0 or not (view[j].isalnum() or view[j] in "_$)]"):
        return False
    end = j + 1
    while j >= 0 and (view[j].isalnum() or view[j] in "_$"):
        j -= 1
    return view[j + 1:end] not in _INDEX_KEYWORDS


def _banned_piece(piece: str) -> bool:
    low = piece.lower()
    return len(low) >= 2 and any(name.startswith(low) or name.endswith(low) for name in BANNED_NAMES)


def _lint_indexes(t: _Text) -> list[str]:
    """Computed access: no banned member name as a string index, no string concatenation that
    builds one (two literals, or a literal that starts or ends a banned name)."""
    errors = []
    for m in _INDEX_RE.finditer(t.view):
        if not _is_index(t.view, m.start()):
            continue
        inner_start = m.start(1)
        pieces = [t.literal(inner_start + s.start(2), inner_start + s.end(2)) for s in _STRING_RE.finditer(m.group(1))]
        if any(p.lower() in BANNED_NAMES for p in pieces):
            errors.append(t.error(m.start(), "computed access to a banned member"))
        elif "+" in m.group(1) and (len(pieces) >= 2 or any(_banned_piece(p) for p in pieces)):
            errors.append(t.error(m.start(), "computed access by string concatenation"))
    return errors


def _lint_lines(t: _Text) -> list[str]:
    errors = []
    for number, raw in enumerate(t.lines, start=1):
        allowed = t.allowed[number - 1]
        for word, pattern in _SUSPICIOUS_RES:
            if pattern.search(raw) and not _wmi_methods_allowed(word, raw, allowed):
                errors.append(f"line {number}: suspicious keyword {word!r}: {raw.strip()[:120]}")
    return errors


def lint(text: str) -> list[str]:
    """Problems in an assembled envscan.js (empty when clean). The rules see the whole text, so a
    call split over lines is still seen; messages name the line where a match starts."""
    errors: list[str] = []
    if "\r\n" not in text or text.replace("\r\n", "").find("\n") >= 0:
        errors.append("line endings must be CRLF throughout")
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        errors.append(f"non-ASCII character at offset {exc.start}")
    t = _Text(text)
    checks = [_lint_forbidden, _lint_activex, _lint_receivers, _lint_com_arguments, _lint_indexes, _lint_lines]
    if CHECK_HAS_OWN:
        checks.append(_lint_has_own)
    for check in checks:
        errors.extend(check(t))
    errors.sort(key=lambda e: int(e.split(":")[0].split()[1]) if e.startswith("line ") else 0)
    return errors
