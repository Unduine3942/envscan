"""PowerShell target: generated spec block, assembly and lint for envscan.ps1.

envscan.ps1 must run on Windows PowerShell 2.0 through PowerShell 7 and in
ConstrainedLanguage mode, so the lint below rejects syntax and APIs that are
missing in PS 2.0/.NET 2.0 or blocked in CLM. It also rejects the keywords that
make PowerShell log a script block as "suspicious" (event 4104, Warning), so a
benign scan never looks like an attack in the security log.

The syntax rules (FORBIDDEN) see the code only: comments and the text of string
literals are blanked first, so `'openssl x509 -in f'` or `# -in is PS3+` is not
an operator. Variables and $(...) inside expandable strings stay visible, and a
string that holds a single word (`-ErrorAction 'Ignore'`) keeps that word. The
suspicious-keyword scan (SUSPICIOUS) sees everything, comments and strings included.
"""
from __future__ import annotations

import math
import re
from bisect import bisect_right
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from spec import DEFAULT_CONFIG_MAX_BYTES, Spec

GEN_BEGIN = "# ---- BEGIN GENERATED (tools/build.py from spec/*.toml) - do not edit ----"
GEN_END = "# ---- END GENERATED ----"
WINDOWS_OS = ("all", "windows")
ALLOW_RE = re.compile(r"#\s*lint-allow:\s*([a-z0-9_,\- ]+)", re.IGNORECASE)
LINE_TEXT_RE = re.compile(r"[\t\x20-\x7e]*")


def _command(names: str) -> str:
    """A command name that is not part of a longer name, a variable ($iex) or a member (.iex)."""
    return rf"(?<![\w$:.-])(?:{names})(?![\w-])"


# (rule, pattern) - PS 3+ syntax, .NET 4 APIs and CLM-blocked constructs. Matched
# case-insensitively against one line of code (comments and string text blanked).
FORBIDDEN: tuple[tuple[str, str], ...] = (
    ("ordered", r"\[ordered\]"),
    ("pscustomobject", r"\[pscustomobject\]"),
    ("ctor-new", r"::new\s*\("),
    ("class", r"^\s*(class|enum)\s+\w+"),
    ("collection-method", r"\.(ForEach|Where)\s*[({]"),
    ("in-operator", r"(?<![\w-])-[ci]?(not)?in(?![\w-])"),
    ("psitem", r"\$PSItem\b"),
    ("ea-ignore", (r"(?<![\w-])-(ErrorAction|EA|WarningAction|WA)[\s:]+Ignore\b"
                   r"|\b(ErrorAction|WarningAction)(Preference)?\s*=\s*Ignore\b")),
    ("gci-file", _command("Get-ChildItem|gci") + r"[^\r\n|;]*\s-(File|Directory)\b"),
    ("gc-raw", _command("Get-Content|gc") + r"[^\r\n|;]*\s-Raw\b"),
    ("isnullorwhitespace", r"IsNullOrWhiteSpace"),
    ("hasflag", r"\.HasFlag\s*\("),
    ("is64bitos", r"Is64BitOperatingSystem"),
    ("psscriptroot", r"\$PSScriptRoot\b"),
    ("com-object", r"(?<![\w-])-ComObject\b"),
    ("new-object", _command("New-Object")),
    ("json-cmdlet", _command("ConvertTo-Json|ConvertFrom-Json")),
    ("invoke-expression", _command("Invoke-Expression|iex")),
    ("gettype", r"\.GetType\s*\("),
    ("ps7-operator", r"\?\?|\?\.|\?\[|&&|\|\|"),
    # A method call on a CLM-blocked type, directly or through a static property
    # ([Text.Encoding]::UTF8.GetBytes(...)). Static properties alone are allowed.
    ("static-method", (r"\[(System\.)?(IO\.(Path|File|Directory)|Math|Convert|BitConverter|Environment"
                       r"|Text\.Encoding|Activator|AppDomain|Reflection\.\w+)\]::\w+(\s*\.\s*\w+)*\s*\(")),
    ("start-job", _command("Start-Job")),
    ("byte-encoding", r"(?<![\w-])-Encoding[\s:]+Byte\b|\bEncoding\s*=\s*Byte\b|(?<![\w-])-AsByteStream\b"),
    ("cim-cmdlet", _command("Get-CimInstance")),
    ("wmi-cmdlet", _command("Get-WmiObject")),
)
_FORBIDDEN_RES = tuple((rule, re.compile(pattern, re.IGNORECASE)) for rule, pattern in FORBIDDEN)
# Rules about a parameter value, which is often quoted (-ErrorAction 'Ignore', Encoding = 'Byte'):
# matched against CodeView.values, where a string holding one bare word stays visible.
VALUE_RULES = frozenset({"ea-ignore", "byte-encoding"})

# PowerShell's built-in "suspicious script block" signatures (case-insensitive substrings).
SUSPICIOUS: tuple[str, ...] = (
    "Add-Type", "DllImport", "DefineDynamicAssembly", "DefineDynamicModule", "DefineType",
    "DefineConstructor", "CreateType", "DefineLiteral", "DefineEnum", "DefineField", "ILGenerator",
    "Emit", "UnverifiableCodeAttribute", "DefinePInvokeMethod", "GetTypes", "GetAssemblies",
    "Methods", "Properties", "GetConstructor", "GetConstructors", "GetDefaultMembers", "GetEvent",
    "GetEvents", "GetField", "GetFields", "GetInterface", "GetInterfaceMap", "GetInterfaces",
    "GetMember", "GetMembers", "GetMethod", "GetMethods", "GetNestedType", "GetNestedTypes",
    "GetProperties", "GetProperty", "InvokeMember", "MakeArrayType", "MakeByRefType",
    "MakeGenericType", "MakePointerType", "DeclaringMethod", "DeclaringType", "ReflectedType",
    "TypeHandle", "TypeInitializer", "UnderlyingSystemType", "InteropServices", "Marshal",
    "AllocHGlobal", "PtrToStructure", "StructureToPtr", "FreeHGlobal", "IntPtr", "MemoryStream",
    "DeflateStream", "FromBase64String", "EncodedCommand", "Bypass", "ToBase64String",
    "ExpandString", "GetPowerShell", "OpenProcess", "VirtualAlloc", "VirtualFree",
    "WriteProcessMemory", "CreateUserThread", "CloseHandle", "GetDelegateForFunctionPointer",
    "kernel32", "CreateThread", "memcpy", "LoadLibrary", "GetModuleHandle", "GetProcAddress",
    "VirtualProtect", "FreeLibrary", "ReadProcessMemory", "CreateRemoteThread",
    "AdjustTokenPrivileges", "WriteByte", "WriteInt32", "OpenThreadToken", "PtrToString",
    "ZeroFreeGlobalAllocUnicode", "OpenProcessToken", "GetTokenInformation", "SetThreadToken",
    "ImpersonateLoggedOnUser", "RevertToSelf", "GetLogonSessionData", "CreateProcessWithToken",
    "DuplicateTokenEx", "OpenWindowStation", "OpenDesktop", "MiniDumpWriteDump",
    "AddSecurityPackage", "EnumerateSecurityPackages", "GetProcessHandle", "DangerousGetHandle",
    "CryptoServiceProvider", "Cryptography", "RijndaelManaged", "SHA1Managed", "CryptoStream",
    "CreateEncryptor", "CreateDecryptor", "TransformFinalBlock", "DeviceIoControl",
    "SetInformationProcess", "PasswordDeriveBytes", "GetAsyncKeyState", "GetKeyboardState",
    "GetForegroundWindow", "BindingFlags", "NonPublic", "ScriptBlockLogging",
    "LogPipelineExecutionDetails", "ProtectedEventLogging", "AmsiUtils", "amsiInitFailed",
)
_SUSPICIOUS_RES = tuple((word, re.compile(re.escape(word), re.IGNORECASE)) for word in SUSPICIOUS)


@dataclass(frozen=True)
class Assembled:
    dist: str
    lib: str


# --------------------------------------------------------------------------- literals

def ps_literal(value: Any) -> str:
    """Render a Python value as a PowerShell 2.0 literal."""
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"cannot render {value!r} as a PowerShell literal")
        return repr(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    if isinstance(value, Mapping):
        body = "; ".join(f"{ps_literal(str(k))} = {ps_literal(v)}" for k, v in value.items())
        return "@{ " + body + " }" if body else "@{}"
    if isinstance(value, (list, tuple)):
        return "@(" + ", ".join(ps_literal(v) for v in value) + ")"
    raise TypeError(f"cannot render {type(value).__name__} as a PowerShell literal")


def _ps_array(name: str, rows: Sequence[Mapping[str, Any]]) -> list[str]:
    if not rows:
        return [f"$script:{name} = @()"]
    lines = [f"$script:{name} = @("]
    lines.extend(f"    {ps_literal(row)}," for row in rows[:-1])
    lines.append(f"    {ps_literal(rows[-1])}")
    lines.append(")")
    return lines


def _windows_paths(paths: Sequence[str]) -> list[str]:
    """Spec paths that mean something on Windows. os = "all" entries mix in Unix-absolute paths
    ("/usr/local/go/bin"), which Windows reads as root-relative: a folder on whatever drive the scan
    runs from, which any user may have created (and a share, when started from a mapped drive)."""
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
    """spec/policy.toml credential names for Test-EsCredentialPath: "/" becomes "\\" (paths are lower-cased
    with backslashes there)."""
    creds = spec.credentials
    names = f"$script:ES_TRUST_STORE_NAMES = {ps_literal(list(spec.trust_store_names))}"
    arrays = [f"$script:ES_CRED_{key.upper()} = {ps_literal([name.replace('/', chr(92)) for name in creds[key]])}"
              for key in ("folders", "files", "suffixes", "key_extensions")]
    return [names, *arrays]


def generate(spec: Spec) -> str:
    """The generated block inserted after 00-params.ps1."""
    probes = [
        {"id": p["id"], "title": p["title"], "tier": p["tier"], "scope": p["scope"],
         "about": p["about"], "footprint": list(p["footprint"])}
        for p in spec.probes_for("ps")
    ]
    tools = [_tool_row(t) for t in spec.tools if t.get("os", "all") in WINDOWS_OS]
    managers = [
        {"id": m["id"], "name": m["name"], "markers": list(m.get("markers", [])),
         "requires": m.get("requires", ""), "versions": list(m["versions"])}
        for m in spec.version_managers
    ]
    # An entry left with no Windows path has nothing to look at.
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
        f"$script:ES_NAME = {ps_literal(spec.meta['name'])}",
        f"$script:ES_VERSION = {ps_literal(spec.version)}",
        f"$script:ES_SCHEMA = {ps_literal(spec.meta['schema'])}",
        *_ps_array("ES_PROBES", probes),
        *_ps_array("ES_TOOLS", tools),
        *_ps_array("ES_VMANAGERS", managers),
        *_ps_array("ES_CONFIGS", configs),
        *_ps_array("ES_CACHES", caches),
        f"$script:ES_PACKAGE_ENV = {ps_literal(list(spec.package_env))}",
        f"$script:ES_PROXY_ENV = {ps_literal(list(spec.proxy_env))}",
        f"$script:ES_TLS_ENV = {ps_literal(list(spec.tls_env))}",
        f"$script:ES_PUBLIC_HOSTS = {ps_literal(list(spec.public_hosts))}",
        f"$script:ES_NET_NEVER = {ps_literal(list(spec.net_never))}",
        *_credential_lines(spec),
        f"$script:ES_REDACT = {ps_literal(dict(spec.redaction))}",
        f"$script:ES_FINDINGS = {ps_literal(findings)}",
        f"$script:ES_THRESHOLDS = {ps_literal(dict(spec.thresholds))}",
        f"$script:ES_CHILD_ENV = {ps_literal(dict(spec.child_env))}",
        # [child_env_keep]: the only scan-start variables a child sees (Test-EsChildEnvKept).
        f"$script:ES_CHILD_ENV_KEEP_NAMES = {ps_literal(list(spec.child_env_keep_names))}",
        f"$script:ES_CHILD_ENV_KEEP_PREFIXES = {ps_literal(list(spec.child_env_keep_prefixes))}",
        # Kept variables holding paths, vetted before a child sees them (Get-EsChildEnvVetted).
        f"$script:ES_CHILD_ENV_HOME_PATHS = {ps_literal(list(spec.child_env_home_paths))}",
        f"$script:ES_CHILD_ENV_PATH_LISTS = {ps_literal(list(spec.child_env_path_lists))}",
        GEN_END,
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- assembly

def _modules(src_dir: Path) -> list[Path]:
    modules = sorted(src_dir.glob("*.ps1"))
    if not modules or not modules[0].name.startswith("00-"):
        raise FileNotFoundError(f"{src_dir} must contain 00-*.ps1 followed by the other modules")
    return modules


def _join(parts: Sequence[str]) -> str:
    text = "\n\n".join(part.strip("\n") for part in parts) + "\n"
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


def assemble(spec: Spec, src_dir: Path) -> Assembled:
    """dist = every module with the generated block after 00-*; lib = dist without 9x-* (main)."""
    modules = _modules(src_dir)
    texts = [(m.name, m.read_text(encoding="ascii")) for m in modules]
    block = generate(spec)
    ordered = [texts[0][1], block, *(text for _, text in texts[1:])]
    library = [texts[0][1], block, *(text for name, text in texts[1:] if not name.startswith("9"))]
    return Assembled(dist=_join(ordered), lib=_join(library))


# --------------------------------------------------------------------------- code view

_NEWLINES = "\r\n"
_NEWLINE_RE = re.compile(r"[\r\n]")
# A "#" starts a comment at the start of a token; inside a bare word (a#b) it does not.
_COMMENT_AFTER = frozenset(" \t\r\n;(){}|&,='\"")
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_VARIABLE_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z_][A-Za-z0-9_]*)?|[$?^])")
_HERE_OPEN_RE = re.compile(r"@(['\"])[ \t]*(?:\r\n|\n|\r)")


@dataclass(frozen=True)
class CodeView:
    """Copies of a script with the same length and line breaks as the original.

    code: comments and the text of string literals replaced by spaces; variables and
          $(...) inside expandable strings kept.
    values: like code, but a string literal holding one bare word ('Ignore') shows
          that word without its quotes.
    comments: only the comments; everything else replaced by spaces.
    """
    code: str
    values: str
    comments: str


class _Lexer:
    """Single pass over PowerShell source; collects what CodeView needs."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.code = list(text)
        self.comments = [ch if ch in _NEWLINES else " " for ch in text]
        self.words: list[tuple[int, int]] = []  # (open quote, close quote) of one-word strings

    def _blank(self, start: int, end: int) -> None:
        for index in range(start, min(end, len(self.text))):
            if self.text[index] not in _NEWLINES:
                self.code[index] = " "

    def _comment(self, start: int, end: int) -> None:
        self._blank(start, end)
        for index in range(start, end):
            self.comments[index] = self.text[index]

    def _line_end(self, index: int) -> int:
        match = _NEWLINE_RE.search(self.text, index)
        return match.start() if match else len(self.text)

    def scan_code(self, index: int, nested: bool = False) -> int:
        """Code from `index`; inside $(...) (nested) stop after the matching ')'."""
        text, depth = self.text, 0
        while index < len(text):
            char = text[index]
            if char == "`":
                index += 2
            elif text.startswith("<#", index):
                end = text.find("#>", index + 2)
                end = len(text) if end < 0 else end + 2
                self._comment(index, end)
                index = end
            elif char == "#" and (index == 0 or text[index - 1] in _COMMENT_AFTER):
                end = self._line_end(index)
                self._comment(index, end)
                index = end
            elif char == "@" and _HERE_OPEN_RE.match(text, index):
                index = self._here_string(index)
            elif char == "'":
                index = self._single_quoted(index)
            elif char == '"':
                index = self._double_quoted(index)
            elif text.startswith("${", index):
                end = text.find("}", index + 2)
                index = len(text) if end < 0 else end + 1
            elif nested and char == "(":
                depth += 1
                index += 1
            elif nested and char == ")":
                if depth == 0:
                    return index + 1
                depth -= 1
                index += 1
            else:
                index += 1
        return len(text)

    def _note_word(self, open_quote: int, close_quote: int) -> None:
        """Remember a string literal that holds one bare word ('Ignore') for CodeView.values.

        After the call operator (& 'Get-CimInstance') the word is a command name, so it
        stays visible in the code view as well.
        """
        if not _WORD_RE.fullmatch(self.text, open_quote + 1, close_quote):
            return
        self.words.append((open_quote, close_quote))
        before = open_quote - 1
        while before >= 0 and self.text[before] in " \t":
            before -= 1
        if before >= 0 and self.text[before] == "&" and self.text[before - 1:before] != "&":
            self.code[open_quote + 1:close_quote] = self.text[open_quote + 1:close_quote]

    def _single_quoted(self, start: int) -> int:
        text, index = self.text, start + 1
        while index < len(text):
            if text[index] == "'":
                if text.startswith("''", index):
                    index += 2
                    continue
                break
            index += 1
        self._blank(start + 1, index)
        if index < len(text):
            self._note_word(start, index)
        return index + 1

    def _expandable_step(self, index: int) -> tuple[int, bool]:
        """One element of an expandable string; returns (next index, element is code)."""
        text = self.text
        if text[index] == "`":
            self._blank(index, index + 2)
            return index + 2, False
        if text.startswith("$(", index):
            return self.scan_code(index + 2, nested=True), True
        if text.startswith("${", index):
            end = text.find("}", index + 2)
            return (len(text) if end < 0 else end + 1), True
        variable = _VARIABLE_RE.match(text, index)
        if variable is not None:
            return variable.end(), True
        self._blank(index, index + 1)
        return index + 1, False

    def _double_quoted(self, start: int) -> int:
        text, index, has_code = self.text, start + 1, False
        while index < len(text):
            if text[index] == '"':
                if not text.startswith('""', index):
                    break
                self._blank(index, index + 2)  # "" is an escaped quote
                index += 2
                continue
            index, is_code = self._expandable_step(index)
            has_code = has_code or is_code
        if index < len(text) and not has_code:
            self._note_word(start, index)
        return index + 1

    def _here_string(self, start: int) -> int:
        """@'...'@ (literal) or @"..."@ (expandable); the closing quote+@ starts a line."""
        text = self.text
        opening = _HERE_OPEN_RE.match(text, start)
        quote = opening.group(1)
        closing = re.compile(r"[\r\n]" + quote + "@").search(text, opening.end() - 1)
        body_end = closing.start() + 1 if closing else len(text)
        index = opening.end()
        if quote == "'":
            self._blank(index, body_end)
        while quote == '"' and index < body_end:
            index, _ = self._expandable_step(index)
        return closing.end() if closing else len(text)


def code_view(text: str) -> CodeView:
    """Split PowerShell source into its code, its one-word string values and its comments."""
    lexer = _Lexer(text)
    lexer.scan_code(0)
    values = list(lexer.code)
    for open_quote, close_quote in lexer.words:
        values[open_quote] = values[close_quote] = " "
        values[open_quote + 1:close_quote] = text[open_quote + 1:close_quote]
    return CodeView(code="".join(lexer.code), values="".join(values), comments="".join(lexer.comments))


# --------------------------------------------------------------------------- lint

def _lines(text: str) -> list[str]:
    """Lines split on LF only (one trailing CR removed), numbered like text.count('\\n')."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def _allowed_rules(comment: str) -> set[str]:
    match = ALLOW_RE.search(comment)
    if not match:
        return set()
    return {rule.strip().lower() for rule in match.group(1).split(",") if rule.strip()}


def _suspicious(text: str) -> list[str]:
    """Every occurrence of every suspicious keyword, anywhere in the text."""
    line_starts = [0, *(match.end() for match in re.finditer("\n", text))]
    errors: list[str] = []
    for word, pattern in _SUSPICIOUS_RES:
        for match in pattern.finditer(text):
            number = bisect_right(line_starts, match.start())
            errors.append(f"line {number}: suspicious-content keyword {word!r} (PowerShell logs such script blocks)")
    return errors


def lint(text: str) -> list[str]:
    """Return lint errors for an assembled envscan.ps1."""
    view = code_view(text)
    errors: list[str] = []
    rows = zip(_lines(text), _lines(view.code), _lines(view.values), _lines(view.comments))
    for number, (line, code, values, comment) in enumerate(rows, start=1):
        if not LINE_TEXT_RE.fullmatch(line):
            errors.append(f"line {number}: non-ASCII or control character")
        allowed = _allowed_rules(comment)
        for rule, pattern in _FORBIDDEN_RES:
            if rule not in allowed and pattern.search(values if rule in VALUE_RULES else code):
                errors.append(f"line {number}: forbidden construct [{rule}]: {line.strip()[:120]}")
    errors.extend(_suspicious(text))
    return errors
