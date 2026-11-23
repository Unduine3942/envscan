"""Load and validate the envscan spec (portable/spec/*.toml).

The spec is the single source of truth shared by envscan.ps1, envscan.sh and
envscan.cmd. Everything here is read-only data; validation returns a list of
human-readable errors instead of raising, so the build can report all of them.

load_spec() keeps every value exactly as TOML produced it (arrays become tuples,
tables become dicts, nothing is converted with str()), so validate_spec() sees
wrong types and reports them instead of a generator crashing on them later.
"""
from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomllib

TIERS = ("default", "deep", "net")
SCOPES = ("machine", "user", "process", "mixed")
IMPL_KINDS = ("script", "binary")
SEVERITIES = ("blocker", "warning", "info")
TOOL_OS = ("all", "windows", "unix", "linux", "darwin")
TOOL_CATS = (
    "runtime", "build", "vcs", "container", "cloud", "db", "pkg",
    "editor", "shell", "net", "archive", "util", "windows",
)
TOOL_MODES = ("version", "presence")
CONFIG_MODES = ("content", "lines", "list")
CONFIG_SCOPES = ("user", "machine")

IMPL_ID_RE = re.compile(r"[a-z][a-z0-9]*")
# A "/" separated path of components; a component is never "." or "..", and never starts with "-".
_POLICY_COMPONENT = r"(?!\.\.?(?:/|$))[a-z0-9_.][a-z0-9_.-]*"
POLICY_NAME_RE = re.compile(rf"{_POLICY_COMPONENT}(?:/{_POLICY_COMPONENT})*")
# A file name below dist/ or dist-bin/: one plain component.
FILE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
CHILD_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# child_env_keep names may carry a Windows "(X86)" suffix; prefixes end in "_".
KEEP_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\(X86\))?")
KEEP_PREFIX_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*_")
POLICY_FS_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
POLICY_EXT_RE = re.compile(r"[a-z0-9]+")
CREDENTIAL_KEYS = ("folders", "files", "suffixes", "key_extensions")

# Always used with fullmatch(): "$" alone would also accept a trailing newline.
PROBE_ID_RE = re.compile(r"[a-z0-9_]+\.[a-z0-9_]+")
TOOL_ID_RE = re.compile(r"[a-z0-9_+-]+")
SIMPLE_ID_RE = re.compile(r"[a-z0-9_.+-]+")
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_()]*")
PRINTABLE_RE = re.compile(r"[\x20-\x7e]*")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
THRESHOLD_KEY_RE = re.compile(r"[a-z0-9_]+")

DEFAULT_CONFIG_MAX_BYTES = 16384

# Top-level keys allowed per spec file. redaction.toml and footprint/*.toml are open:
# redaction.toml grows new rule lists, footprint keys are probe ids (checked separately).
DOCUMENT_KEYS: Mapping[str, tuple[str, ...]] = {
    "probes.toml": ("meta", "probe"),
    "tools.toml": ("tools", "version_managers"),
    "configs.toml": ("configs", "caches", "package_env", "proxy_env", "tls_env", "ca_bundles", "ca_anchor_dirs",
                     "public_hosts", "net_never"),
    "findings.toml": ("finding", "thresholds"),
    "child_env.toml": ("child_env", "child_env_keep"),
    "policy.toml": ("network_fs", "network_fs_prefixes", "local_fuse", "trust_store_names", "credentials"),
    "ebcdic.toml": ("ibm1047",),
}
SPEC_FILES = (*DOCUMENT_KEYS, "redaction.toml")


@dataclass(frozen=True)
class Shape:
    """Keys of one catalog entry: required ones are indexed directly by the generators."""
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()


PROBE_SHAPE = Shape(("id", "title", "tier", "scope", "about"))
TOOL_SHAPE = Shape(("id", "name", "cat", "exe"), ("args", "dirs", "os", "mode"))
MANAGER_SHAPE = Shape(("id", "name", "versions"), ("markers", "requires"))
CONFIG_SHAPE = Shape(("id", "tool", "scope", "paths"), ("mode", "match", "os", "max_bytes"))
CACHE_SHAPE = Shape(("id", "tool", "paths"))
FINDING_SHAPE = Shape(("id", "severity", "title", "recommendation"))
META_KEYS = ("name", "version", "schema")

REDACTION_LISTS = ("name_segments", "name_contains", "name_suffixes", "exact_exceptions", "suffix_exceptions",
                   "token_prefixes", "pair_keys", "option_words", "header_words", "tool_options", "xml_elements",
                   "xml_attributes")
# "tool:option": a lower-case program name, then an option starting with - or /.
TOOL_OPTION_RE = re.compile(r"[a-z0-9][a-z0-9._-]*:[-/][A-Za-z0-9-]+")
REDACTION_UPPER = ("name_segments", "name_contains", "name_suffixes", "exact_exceptions", "suffix_exceptions")
REDACTION_TEXTS = ("placeholder", "private_key_marker")
# A public registry's host suffix: lower-case DNS labels, at least two.
PUBLIC_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")
# A host name, IPv4/IPv6 address, or an address prefix ending in "." or ":".
NET_NEVER_RE = re.compile(r"[a-z0-9:][a-z0-9.:-]*")
REDACTION_KNOWN = (*REDACTION_LISTS, *REDACTION_TEXTS, "token_min_length")


@dataclass(frozen=True)
class Impl:
    """One implementation of the scanner. Adding one is a row here, a spec/footprint/<id>.toml and a
    builder in tools/build.py.

    kind "script": a text file in dist/ named `dist_file`; "binary": built into dist-bin/ (`dist_file` is
    the name prefix of its files). `column` heads the probe table; `report_impl` is the value of
    scanner.impl in its JSON report (None when it writes no JSON, like the cmd fallback).
    """
    id: str
    label: str
    kind: str
    dist_file: str
    column: str
    report_impl: str | None = None
    # A binary's output file names (below dist-bin/), e.g. per os/arch. The build fails if one is
    # missing or an undeclared one appears. Empty for scripts.
    outputs: tuple[str, ...] = ()


REGISTRY: tuple[Impl, ...] = (
    Impl("ps", "envscan.ps1", "script", "envscan.ps1", "ps1", "powershell"),
    Impl("sh", "envscan.sh", "script", "envscan.sh", "sh", "posix-sh"),
    Impl("cmd", "envscan.cmd (fallback)", "script", "envscan.cmd", "cmd", None),
    Impl("js", "envscan.js (Windows Script Host)", "script", "envscan.js", "js", "jscript"),
    Impl("go", "envscan-linux-ARCH (static binary)", "binary", "envscan", "go", "go",
         ("envscan-linux-amd64", "envscan-linux-arm64", "envscan-linux-s390x", "envscan-linux-ppc64le")),
)


def _validate_impl(impl: Impl) -> list[str]:
    where = f"registry {impl.id!r}"
    errors: list[str] = []
    if not IMPL_ID_RE.fullmatch(impl.id):
        errors.append(f"{where}: id must match {IMPL_ID_RE.pattern}")
    if impl.kind not in IMPL_KINDS:
        errors.append(f"{where}: kind must be one of {IMPL_KINDS}, got {impl.kind!r}")
    if not FILE_NAME_RE.fullmatch(impl.dist_file):
        errors.append(f"{where}: dist_file must be a plain file name matching {FILE_NAME_RE.pattern}, "
                      f"got {impl.dist_file!r}")
    for field_name in ("label", "column"):
        text = getattr(impl, field_name)
        if not text or not PRINTABLE_RE.fullmatch(text) or "|" in text:
            errors.append(f"{where}: {field_name} must be printable ASCII without '|', got {text!r}")
    if impl.kind == "script" and impl.outputs:
        errors.append(f"{where}: a script must not declare outputs")
    if impl.kind == "binary" and not impl.outputs:
        errors.append(f"{where}: a binary must declare its outputs (file names below dist-bin/)")
    for name in impl.outputs:
        if not FILE_NAME_RE.fullmatch(name) or name.lower() == "sha256sums":  # Windows file names ignore case
            errors.append(f"{where}: an output must be a plain file name, not {name!r}")
    folded = [n.lower() for n in impl.outputs]
    for name in sorted({n for n in folded if folded.count(n) > 1}):
        errors.append(f"{where}: duplicate output {name!r} (names are compared ignoring case)")
    return errors


def validate_registry(registry: Sequence[Impl]) -> list[str]:
    """Problems in an implementation registry; an empty list means it is usable."""
    errors: list[str] = []
    if not registry:
        errors.append("registry: needs at least one implementation")
    for field_name in ("id", "dist_file", "column"):
        values = [getattr(impl, field_name) for impl in registry]
        for value in sorted({v for v in values if values.count(v) > 1}):
            errors.append(f"registry: duplicate {field_name} {value!r}")
    for impl in registry:
        errors.extend(_validate_impl(impl))
    return errors


class SpecError(Exception):
    """Raised when the spec cannot be loaded at all (missing file, bad TOML, not UTF-8)."""


@dataclass(frozen=True)
class Spec:
    meta: Mapping[str, str]
    probes: tuple[Mapping[str, Any], ...]
    footprints: Mapping[str, Mapping[str, tuple[str, ...]]]
    tools: tuple[Mapping[str, Any], ...]
    version_managers: tuple[Mapping[str, Any], ...]
    configs: tuple[Mapping[str, Any], ...]
    caches: tuple[Mapping[str, Any], ...]
    package_env: tuple[str, ...]
    proxy_env: tuple[str, ...]
    tls_env: tuple[str, ...]
    ca_bundles: tuple[str, ...]
    ca_anchor_dirs: tuple[str, ...]
    public_hosts: tuple[str, ...]
    net_never: tuple[str, ...]
    redaction: Mapping[str, Any]
    findings: tuple[Mapping[str, Any], ...]
    thresholds: Mapping[str, Any]
    child_env: Mapping[str, str]
    # The parsed spec files by name ("tools.toml", ...), for the top-level key check.
    documents: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    # spec/policy.toml: network filesystem types and the credential-store names.
    network_fs: tuple[str, ...] = ()
    network_fs_prefixes: tuple[str, ...] = ()
    local_fuse: tuple[str, ...] = ()
    # spec/child_env.toml [child_env_keep]: the user variables child commands may see.
    child_env_keep_names: tuple[str, ...] = ()
    child_env_keep_prefixes: tuple[str, ...] = ()
    child_env_home_paths: tuple[str, ...] = ()
    child_env_path_lists: tuple[str, ...] = ()
    trust_store_names: tuple[str, ...] = ()
    credentials: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    # The implementations this spec has footprints for (the registry it was loaded with).
    impls: tuple[Impl, ...] = REGISTRY

    @property
    def version(self) -> str:
        return self.meta["version"]

    def probes_for(self, impl: str) -> tuple[Mapping[str, Any], ...]:
        """Probes implemented by `impl`, in catalog order, with footprint attached."""
        lines = self.footprints.get(impl, {})
        return tuple(
            {**probe, "footprint": lines[probe["id"]]}
            for probe in self.probes
            if probe["id"] in lines
        )


# --------------------------------------------------------------------------- loading

def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError as exc:
        raise SpecError(f"missing spec file: {path}") from exc
    except UnicodeDecodeError as exc:
        raise SpecError(f"{path} is not valid UTF-8: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SpecError(f"invalid TOML in {path}: {exc}") from exc
    except OSError as exc:
        raise SpecError(f"cannot read {path}: {exc}") from exc


def _items(value: Any) -> Any:
    """A TOML array as a tuple with its items unchanged; any other value is kept for validation."""
    if value is None:
        return ()
    return tuple(value) if isinstance(value, list) else value


def _table(value: Any) -> Any:
    """A TOML table as a new dict; any other value is kept for validation."""
    if value is None:
        return {}
    return dict(value) if isinstance(value, dict) else value


def _entries(value: Any) -> Any:
    """An array of tables as a tuple of new dicts; anything else is kept for validation."""
    if value is None:
        return ()
    if not isinstance(value, list):
        return value
    return tuple(dict(item) if isinstance(item, dict) else item for item in value)


def _credentials(value: Any) -> Any:
    """The [credentials] table as a mapping of tuples (not a mappingproxy: tests deep-copy the spec); any other value is kept for validation."""
    table = _table(value)
    if not isinstance(table, dict):
        return table
    return {key: _items(items) for key, items in table.items()}


def _read_footprint(spec_dir: Path, impl: Impl) -> dict[str, tuple[str, ...]]:
    path = spec_dir / "footprint" / f"{impl.id}.toml"
    if not path.is_file():
        raise SpecError(f"implementation {impl.id!r} is registered (tools/spec.py REGISTRY) but has no "
                        f"footprint file: {path}")
    return {probe_id: _items(lines) for probe_id, lines in _read_toml(path).items()}


def load_spec(spec_dir: Path, registry: Sequence[Impl] | None = None) -> Spec:
    """Read every spec file into an immutable Spec. Raises SpecError on I/O, encoding or TOML errors,
    and when a registered implementation has no footprint file."""
    registry = tuple(REGISTRY if registry is None else registry)
    documents = {name: _read_toml(spec_dir / name) for name in SPEC_FILES}
    footprints = {impl.id: _read_footprint(spec_dir, impl) for impl in registry}
    policy_doc = documents["policy.toml"]
    probes_doc = documents["probes.toml"]
    tools_doc = documents["tools.toml"]
    configs_doc = documents["configs.toml"]
    findings_doc = documents["findings.toml"]
    return Spec(
        meta=_table(probes_doc.get("meta")),
        probes=_entries(probes_doc.get("probe")),
        footprints=footprints,
        tools=_entries(tools_doc.get("tools")),
        version_managers=_entries(tools_doc.get("version_managers")),
        configs=_entries(configs_doc.get("configs")),
        caches=_entries(configs_doc.get("caches")),
        package_env=_items(configs_doc.get("package_env")),
        proxy_env=_items(configs_doc.get("proxy_env")),
        tls_env=_items(configs_doc.get("tls_env")),
        ca_bundles=_items(configs_doc.get("ca_bundles")),
        ca_anchor_dirs=_items(configs_doc.get("ca_anchor_dirs")),
        public_hosts=_items(configs_doc.get("public_hosts")),
        net_never=_items(configs_doc.get("net_never")),
        redaction=dict(documents["redaction.toml"]),
        findings=_entries(findings_doc.get("finding")),
        thresholds=_table(findings_doc.get("thresholds")),
        child_env=_table(documents["child_env.toml"].get("child_env")),
        documents=documents,
        network_fs=_items(policy_doc.get("network_fs")),
        network_fs_prefixes=_items(policy_doc.get("network_fs_prefixes")),
        local_fuse=_items(policy_doc.get("local_fuse")),
        child_env_keep_names=_items(_table(documents["child_env.toml"].get("child_env_keep")).get("names")),
        child_env_keep_prefixes=_items(_table(documents["child_env.toml"].get("child_env_keep")).get("prefixes")),
        child_env_home_paths=_items(_table(documents["child_env.toml"].get("child_env_keep")).get("home_paths")),
        child_env_path_lists=_items(_table(documents["child_env.toml"].get("child_env_keep")).get("path_lists")),
        trust_store_names=_items(policy_doc.get("trust_store_names")),
        credentials=_credentials(policy_doc.get("credentials")),
        impls=tuple(registry),
    )


# --------------------------------------------------------------------------- validation helpers

def _type_name(value: Any) -> str:
    return type(value).__name__


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_text(errors: list[str], where: str, value: Any, *, allow_pipe: bool = False) -> bool:
    """Spec text ends up inside PowerShell literals, sh TSV tables and batch echo lines.

    Returns True when `value` is a string, so callers run their follow-up checks only then.
    """
    if not isinstance(value, str):
        errors.append(f"{where}: expected a string, got {_type_name(value)}")
        return False
    if not PRINTABLE_RE.fullmatch(value):
        errors.append(f"{where}: must be printable ASCII without tabs: {value!r}")
    if not allow_pipe and "|" in value:
        errors.append(f"{where}: must not contain '|': {value!r}")
    return True


def _str_list(errors: list[str], where: str, value: Any, *, allow_empty: bool = True) -> tuple[str, ...]:
    """Check that `value` is a list of strings; return only its string items."""
    if not isinstance(value, (list, tuple)):
        errors.append(f"{where}: expected a list of strings, got {_type_name(value)}")
        return ()
    if not value and not allow_empty:
        errors.append(f"{where}: must not be empty")
    items: list[str] = []
    for index, item in enumerate(value):
        if isinstance(item, str):
            items.append(item)
        else:
            errors.append(f"{where}[{index}]: expected a string, got {_type_name(item)}")
    return tuple(items)


def _text_list(errors: list[str], where: str, value: Any, *, allow_empty: bool = True,
               allow_pipe: bool = False) -> tuple[str, ...]:
    """A list of printable strings; returns the string items that passed the text check."""
    items = _str_list(errors, where, value, allow_empty=allow_empty)
    return tuple(item for item in items if _check_text(errors, where, item, allow_pipe=allow_pipe))


def _entry_list(errors: list[str], where: str, value: Any) -> tuple[Mapping[str, Any], ...]:
    """Check an array of tables; return only its table items."""
    if not isinstance(value, (list, tuple)):
        errors.append(f"{where}: expected an array of tables, got {_type_name(value)}")
        return ()
    entries: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        if isinstance(item, Mapping):
            entries.append(item)
        else:
            errors.append(f"{where}[{index}]: expected a table, got {_type_name(item)}")
    return tuple(entries)


def _where(kind: str, entry: Mapping[str, Any], index: int, list_name: str) -> str:
    entry_id = entry.get("id")
    return f"{kind} {entry_id!r}" if isinstance(entry_id, str) and entry_id else f"{list_name}[{index}]"


def _check_shape(errors: list[str], where: str, entry: Mapping[str, Any], shape: Shape) -> None:
    for key in shape.required:
        if key not in entry:
            errors.append(f"{where}: missing required key {key!r}")
    for key in sorted(set(entry) - set(shape.required) - set(shape.optional)):
        errors.append(f"{where}: unknown key {key!r}")


def _check_id(errors: list[str], where: str, entry: Mapping[str, Any], pattern: re.Pattern[str]) -> str | None:
    """The entry's id when it is a well-formed string (missing ids are reported by _check_shape)."""
    if "id" not in entry:
        return None
    value = entry["id"]
    if not isinstance(value, str):
        errors.append(f"{where}: id must be a string, got {_type_name(value)}")
        return None
    if not pattern.fullmatch(value):
        errors.append(f"{where}: id must match {pattern.pattern}: {value!r}")
    return value


def _check_choice(errors: list[str], where: str, entry: Mapping[str, Any], key: str,
                  choices: tuple[str, ...]) -> None:
    if key in entry and (not isinstance(entry[key], str) or entry[key] not in choices):
        errors.append(f"{where}: {key} must be one of {choices}, got {entry[key]!r}")


def _check_unique(errors: list[str], where: str, ids: list[str]) -> None:
    seen: set[str] = set()
    for item in ids:
        if item in seen:
            errors.append(f"{where}: duplicate id {item!r}")
        seen.add(item)


# --------------------------------------------------------------------------- validation

def _validate_documents(spec: Spec, errors: list[str]) -> None:
    for name, allowed in DOCUMENT_KEYS.items():
        document = spec.documents.get(name, {})
        for key in sorted(set(document) - set(allowed)):
            errors.append(f"{name}: unknown top-level key {key!r} (expected one of {allowed})")


def _validate_meta(spec: Spec, errors: list[str]) -> None:
    meta = spec.meta
    if not isinstance(meta, Mapping):
        errors.append(f"probes.toml [meta]: expected a table, got {_type_name(meta)}")
        return
    for key in META_KEYS:
        if key not in meta:
            errors.append(f"probes.toml [meta]: missing {key}")
        elif _check_text(errors, f"probes.toml [meta] {key}", meta[key]) and not meta[key]:
            errors.append(f"probes.toml [meta]: {key} must not be empty")
    version = meta.get("version")
    if isinstance(version, str) and version and not VERSION_RE.fullmatch(version):
        errors.append(f"probes.toml [meta]: version must be MAJOR.MINOR.PATCH, got {version!r}")


def _validate_footprints(spec: Spec, errors: list[str], known: set[str]) -> set[str]:
    """Check every footprint file; return the ids of the probes implemented somewhere."""
    implemented: set[str] = set()
    for impl in (item.id for item in spec.impls):
        entries = spec.footprints.get(impl, {})
        if not isinstance(entries, Mapping):
            errors.append(f"footprint/{impl}.toml: expected a table, got {_type_name(entries)}")
            continue
        for pid, lines in entries.items():
            where = f"footprint/{impl}.toml {pid!r}"
            implemented.add(pid)
            if pid not in known:
                errors.append(f"footprint/{impl}.toml: unknown probe id {pid!r}")
            if isinstance(lines, (list, tuple)) and not lines:
                errors.append(f"{where}: has no footprint lines")
            _text_list(errors, where, lines)
    return implemented


def _validate_probes(spec: Spec, errors: list[str]) -> None:
    probes = _entry_list(errors, "probes.toml probe", spec.probes)
    ids: list[str] = []
    for index, probe in enumerate(probes):
        where = _where("probe", probe, index, "probes.toml probe")
        _check_shape(errors, where, probe, PROBE_SHAPE)
        pid = _check_id(errors, where, probe, PROBE_ID_RE)
        if pid is not None:
            ids.append(pid)
        _check_choice(errors, where, probe, "tier", TIERS)
        _check_choice(errors, where, probe, "scope", SCOPES)
        for key in ("title", "about"):
            if key in probe:
                _check_text(errors, f"{where}.{key}", probe[key])
    _check_unique(errors, "probes.toml", ids)
    known = set(ids)
    implemented = _validate_footprints(spec, errors, known)
    for pid in sorted(known - implemented):
        errors.append(f"probe {pid!r} is not implemented by any of {tuple(i.id for i in spec.impls)}")


def _validate_tool(errors: list[str], where: str, tool: Mapping[str, Any]) -> None:
    _check_shape(errors, where, tool, TOOL_SHAPE)
    if "name" in tool:
        _check_text(errors, f"{where}.name", tool["name"])
    _check_choice(errors, where, tool, "cat", TOOL_CATS)
    _check_choice(errors, where, tool, "mode", TOOL_MODES)
    _check_choice(errors, where, tool, "os", TOOL_OS)
    if "exe" in tool:
        exes = _text_list(errors, f"{where}.exe", tool["exe"])
        if isinstance(tool["exe"], (list, tuple)) and not tool["exe"]:
            errors.append(f"{where}: exe must list at least one executable name")
        for exe in exes:
            if not exe or any(ch in exe for ch in " /\\"):
                errors.append(f"{where}.exe: {exe!r} must be a bare name")
    if "args" in tool:
        for arg in _text_list(errors, f"{where}.args", tool["args"]):
            if " " in arg or not arg:
                errors.append(f"{where}.args: {arg!r} must be non-empty without spaces")
    if "dirs" in tool:
        _text_list(errors, f"{where}.dirs", tool["dirs"])


def _validate_manager(errors: list[str], where: str, manager: Mapping[str, Any]) -> None:
    _check_shape(errors, where, manager, MANAGER_SHAPE)
    if "name" in manager:
        _check_text(errors, f"{where}.name", manager["name"])
    if "requires" in manager:
        _check_text(errors, f"{where}.requires", manager["requires"])
    if "markers" in manager:
        for marker in _text_list(errors, f"{where}.markers", manager["markers"]):
            if marker != marker.lower() or "\\" in marker:
                errors.append(f"{where}.markers: {marker!r} must be lower-case with forward slashes")
    if "versions" in manager:
        _text_list(errors, f"{where}.versions", manager["versions"], allow_empty=False)


def _validate_tools(spec: Spec, errors: list[str]) -> None:
    ids: list[str] = []
    for index, tool in enumerate(_entry_list(errors, "tools.toml tools", spec.tools)):
        where = _where("tool", tool, index, "tools.toml tools")
        tid = _check_id(errors, where, tool, TOOL_ID_RE)
        if tid is not None:
            ids.append(tid)
        _validate_tool(errors, where, tool)
    _check_unique(errors, "tools.toml tools", ids)
    ids = []
    for index, manager in enumerate(_entry_list(errors, "tools.toml version_managers", spec.version_managers)):
        where = _where("version_manager", manager, index, "tools.toml version_managers")
        mid = _check_id(errors, where, manager, SIMPLE_ID_RE)
        if mid is not None:
            ids.append(mid)
        _validate_manager(errors, where, manager)
    _check_unique(errors, "tools.toml version_managers", ids)


def _validate_config(errors: list[str], where: str, config: Mapping[str, Any]) -> None:
    _check_shape(errors, where, config, CONFIG_SHAPE)
    if "tool" in config:
        _check_text(errors, f"{where}.tool", config["tool"])
    _check_choice(errors, where, config, "os", TOOL_OS)
    _check_choice(errors, where, config, "scope", CONFIG_SCOPES)
    _check_choice(errors, where, config, "mode", CONFIG_MODES)
    if "paths" in config:
        _text_list(errors, f"{where}.paths", config["paths"], allow_empty=False)
    if "match" in config:
        _text_list(errors, f"{where}.match", config["match"])
    if config.get("mode") == "lines" and not config.get("match"):
        errors.append(f"{where}: mode 'lines' requires match")
    if "max_bytes" in config and not (_is_int(config["max_bytes"]) and config["max_bytes"] > 0):
        errors.append(f"{where}: max_bytes must be a positive integer, got {config['max_bytes']!r}")


def _validate_configs(spec: Spec, errors: list[str]) -> None:
    ids: list[str] = []
    for index, config in enumerate(_entry_list(errors, "configs.toml configs", spec.configs)):
        where = _where("config", config, index, "configs.toml configs")
        cid = _check_id(errors, where, config, SIMPLE_ID_RE)
        if cid is not None:
            ids.append(cid)
        _validate_config(errors, where, config)
    _check_unique(errors, "configs.toml configs", ids)
    ids = []
    for index, cache in enumerate(_entry_list(errors, "configs.toml caches", spec.caches)):
        where = _where("cache", cache, index, "configs.toml caches")
        _check_shape(errors, where, cache, CACHE_SHAPE)
        cid = _check_id(errors, where, cache, SIMPLE_ID_RE)
        if cid is not None:
            ids.append(cid)
        if "tool" in cache:
            _check_text(errors, f"{where}.tool", cache["tool"])
        if "paths" in cache:
            _text_list(errors, f"{where}.paths", cache["paths"], allow_empty=False)
    _check_unique(errors, "configs.toml caches", ids)
    for list_name in ("package_env", "proxy_env", "tls_env"):
        for name in _str_list(errors, f"configs.toml {list_name}", getattr(spec, list_name)):
            if not ENV_NAME_RE.fullmatch(name):
                errors.append(f"configs.toml {list_name}: invalid variable name {name!r}")
    for list_name in ("ca_bundles", "ca_anchor_dirs"):
        for path in _text_list(errors, f"configs.toml {list_name}", getattr(spec, list_name)):
            if " " in path:
                errors.append(f"configs.toml {list_name}: {path!r} must not contain spaces")
    _validate_network_lists(errors, spec)


def _validate_network_lists(errors: list[str], spec: Spec) -> None:
    """public_hosts and net_never keep --net away from the internet and metadata services: never empty."""
    hosts = _str_list(errors, "configs.toml public_hosts", spec.public_hosts, allow_empty=False)
    for host in hosts:
        if not PUBLIC_HOST_RE.fullmatch(host):
            errors.append(f"configs.toml public_hosts: {host!r} must be a lower-case domain like example.org")
    _check_unique(errors, "configs.toml public_hosts", list(hosts))
    entries = _str_list(errors, "configs.toml net_never", spec.net_never, allow_empty=False)
    for entry in entries:
        if not NET_NEVER_RE.fullmatch(entry):
            errors.append(f"configs.toml net_never: {entry!r} must be a lower-case host name, address or address prefix")
    _check_unique(errors, "configs.toml net_never", list(entries))


def _validate_policy(spec: Spec, errors: list[str]) -> None:
    """policy.toml feeds case patterns in sh and regular expressions in ps1: lower-case names only."""
    _validate_policy_list(errors, "policy.toml network_fs", spec.network_fs, POLICY_FS_RE)
    _validate_policy_list(errors, "policy.toml trust_store_names", spec.trust_store_names, POLICY_FS_RE)
    creds = spec.credentials
    if not isinstance(creds, Mapping):
        errors.append(f"policy.toml credentials: expected a table, got {_type_name(creds)}")
        return
    for key in sorted(set(creds) - set(CREDENTIAL_KEYS)):
        errors.append(f"policy.toml credentials: unknown key {key!r}")
    for key in CREDENTIAL_KEYS:
        if key not in creds:
            errors.append(f"policy.toml credentials: missing {key!r}")
            continue
        pattern = POLICY_EXT_RE if key == "key_extensions" else POLICY_NAME_RE
        _validate_policy_list(errors, f"policy.toml credentials.{key}", creds[key], pattern)


def _validate_policy_list(errors: list[str], where: str, value: Any, pattern: re.Pattern[str]) -> None:
    items = _str_list(errors, where, value, allow_empty=False)
    for item in items:
        if not pattern.fullmatch(item):
            errors.append(f"{where}: {item!r} must match {pattern.pattern} "
                          "(lower case, no spaces or glob characters)")
    _check_unique(errors, where, list(items))


def _validate_redaction_extra(errors: list[str], key: str, value: Any) -> None:
    """Keys this validator does not know yet: allowed, but they must render as literals."""
    where = f"redaction.toml {key}"
    if isinstance(value, str):
        _check_text(errors, where, value, allow_pipe=True)
    elif isinstance(value, (list, tuple)):
        _text_list(errors, where, value, allow_pipe=True)
    elif not _is_int(value):
        errors.append(f"{where}: expected a string, an integer or a list of strings, got {_type_name(value)}")


def _validate_redaction(spec: Spec, errors: list[str]) -> None:
    red = spec.redaction
    for key in REDACTION_LISTS:
        if key not in red:
            errors.append(f"redaction.toml: missing {key}")
            continue
        for value in _text_list(errors, f"redaction.toml {key}", red[key], allow_empty=False):
            if " " in value:
                errors.append(f"redaction.toml {key}: {value!r} must not contain spaces")
            if key in REDACTION_UPPER and value != value.upper():
                errors.append(f"redaction.toml {key}: {value!r} must be upper-case")
            if key == "tool_options" and not TOOL_OPTION_RE.fullmatch(value):
                errors.append(f"redaction.toml {key}: {value!r} must look like tool:-option")
    token_min_length = red.get("token_min_length")
    if not (_is_int(token_min_length) and token_min_length > 0):
        errors.append(f"redaction.toml: token_min_length must be a positive integer, got {token_min_length!r}")
    for key in REDACTION_TEXTS:
        if key not in red:
            errors.append(f"redaction.toml: missing {key}")
        elif _check_text(errors, f"redaction.toml {key}", red[key]) and not red[key]:
            errors.append(f"redaction.toml: {key} must not be empty")
    for key in sorted(set(red) - set(REDACTION_KNOWN)):
        _validate_redaction_extra(errors, key, red[key])


def _valid_threshold(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    if _is_int(value):
        return True
    return isinstance(value, (list, tuple)) and all(_is_int(item) for item in value)


def _validate_findings(spec: Spec, errors: list[str]) -> None:
    ids: list[str] = []
    for index, finding in enumerate(_entry_list(errors, "findings.toml finding", spec.findings)):
        where = _where("finding", finding, index, "findings.toml finding")
        _check_shape(errors, where, finding, FINDING_SHAPE)
        fid = _check_id(errors, where, finding, PROBE_ID_RE)
        if fid is not None:
            ids.append(fid)
        _check_choice(errors, where, finding, "severity", SEVERITIES)
        for key in ("title", "recommendation"):
            if key in finding:
                _check_text(errors, f"{where}.{key}", finding[key])
    _check_unique(errors, "findings.toml", ids)
    if not isinstance(spec.thresholds, Mapping):
        errors.append(f"findings.toml thresholds: expected a table, got {_type_name(spec.thresholds)}")
        return
    for key, value in spec.thresholds.items():
        if not THRESHOLD_KEY_RE.fullmatch(key):
            errors.append(f"findings.toml thresholds: invalid key {key!r}")
        if not _valid_threshold(value):
            errors.append(f"findings.toml thresholds: {key} must be a finite number or a list of integers, "
                          f"got {value!r}")


def _validate_child_env(spec: Spec, errors: list[str]) -> None:
    if not isinstance(spec.child_env, Mapping):
        errors.append(f"child_env.toml child_env: expected a table, got {_type_name(spec.child_env)}")
        return
    for name, value in spec.child_env.items():
        if not CHILD_ENV_NAME_RE.fullmatch(name):  # exported by sh, so no "(" as in PROGRAMFILES(X86)
            errors.append(f"child_env.toml: invalid variable name {name!r}")
        if _check_text(errors, f"child_env.toml {name}", value) and any(ch in value for ch in "\"'$`%"):
            errors.append(f"child_env.toml {name}: value must not contain quotes, $, ` or %")


def _camel_split(name: str) -> str:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", name)


def is_secret_name(red: Mapping[str, Any], name: str) -> bool:
    """redaction.toml NAME RULES (the same answer every implementation gives)."""
    upper = name.upper()
    segments = [s for s in re.split(r"[^A-Z0-9]+", _camel_split(name).upper()) if s]
    normalized, joined = "_".join(segments), "".join(segments)
    if upper in red.get("exact_exceptions", ()) or any(normalized.endswith(x) for x in red.get("suffix_exceptions", ())):
        return False
    return (any(s in red.get("name_segments", ()) for s in segments)
            or any(w in joined for w in red.get("name_contains", ()))
            or any(joined.endswith(w) for w in red.get("name_suffixes", ())))


def _validate_child_env_keep(spec: Spec, errors: list[str]) -> None:
    where = "child_env.toml child_env_keep names"
    names = _str_list(errors, where, spec.child_env_keep_names, allow_empty=False)
    for name in names:
        if not KEEP_NAME_RE.fullmatch(name):
            errors.append(f"{where}: invalid variable name {name!r}")
        elif is_secret_name(spec.redaction, name):
            errors.append(f"{where}: {name!r} is a secret name")
        elif isinstance(spec.child_env, Mapping) and name in spec.child_env:
            errors.append(f"{where}: {name!r} is already set by [child_env]")
    _check_unique(errors, where, list(names))
    where = "child_env.toml child_env_keep prefixes"
    prefixes = _str_list(errors, where, spec.child_env_keep_prefixes)
    for prefix in prefixes:
        if not KEEP_PREFIX_RE.fullmatch(prefix):
            errors.append(f"{where}: {prefix!r} must match {KEEP_PREFIX_RE.pattern}")
    _check_unique(errors, where, list(prefixes))
    _validate_child_env_paths(spec, errors, set(names), prefixes)


def _validate_child_env_paths(spec: Spec, errors: list[str], kept: set[str], prefixes: tuple[str, ...]) -> None:
    """home_paths and path_lists name kept variables only, and no variable is in both."""
    lists: dict[str, tuple[str, ...]] = {}
    for key, values in (("home_paths", spec.child_env_home_paths), ("path_lists", spec.child_env_path_lists)):
        where = f"child_env.toml child_env_keep {key}"
        items = _str_list(errors, where, values, allow_empty=False)
        for name in items:
            if name not in kept and not any(name.startswith(p) for p in prefixes):
                errors.append(f"{where}: {name!r} is not kept (names or prefixes)")
        _check_unique(errors, where, list(items))
        lists[key] = items
    for name in sorted(set(lists["home_paths"]) & set(lists["path_lists"])):
        errors.append(f"child_env.toml child_env_keep: {name!r} is in both home_paths and path_lists")


def _validate_fuse_policy(spec: Spec, errors: list[str]) -> None:
    where = "policy.toml network_fs_prefixes"
    prefixes = _str_list(errors, where, spec.network_fs_prefixes)
    for prefix in prefixes:
        if not POLICY_FS_RE.fullmatch(prefix.rstrip(".")) or not prefix.endswith("."):
            errors.append(f"{where}: {prefix!r} must end with '.'")
    where = "policy.toml local_fuse"
    local = _str_list(errors, where, spec.local_fuse)
    for name in local:
        if not POLICY_FS_RE.fullmatch(name):
            errors.append(f"{where}: {name!r} must match {POLICY_FS_RE.pattern}")
        elif not any(name.startswith(p) for p in prefixes):
            errors.append(f"{where}: {name!r} must start with a network_fs_prefixes entry")
        elif isinstance(spec.network_fs, (list, tuple)) and name in spec.network_fs:
            errors.append(f"{where}: {name!r} is also in network_fs")
    _check_unique(errors, where, list(local))


def _validate_ebcdic(spec: Spec, errors: list[str]) -> None:
    """ebcdic.toml: 256 distinct code points (one per byte), the 95 printable ASCII characters among them."""
    table = spec.documents.get("ebcdic.toml", {}).get("ibm1047")
    if not isinstance(table, Mapping) or set(table) != {"codepoints"}:
        errors.append("ebcdic.toml ibm1047: expected a table with the single key 'codepoints'")
        return
    cps = table["codepoints"]
    if (not isinstance(cps, (list, tuple)) or len(cps) != 256
            or not all(isinstance(c, int) and not isinstance(c, bool) and 0 <= c <= 0x10FFFF for c in cps)):
        errors.append("ebcdic.toml ibm1047.codepoints: expected 256 integers (0..0x10FFFF), one per byte")
        return
    if len(set(cps)) != 256:
        errors.append("ebcdic.toml ibm1047.codepoints: code points must be distinct")
    missing = [c for c in range(0x20, 0x7F) if c not in set(cps)]
    if missing:
        errors.append(f"ebcdic.toml ibm1047.codepoints: printable ASCII missing: {missing[:5]}")


def validate_spec(spec: Spec) -> list[str]:
    """Return every problem found in the spec; an empty list means the spec is valid."""
    errors: list[str] = list(validate_registry(spec.impls))
    _validate_documents(spec, errors)
    _validate_meta(spec, errors)
    _validate_probes(spec, errors)
    _validate_tools(spec, errors)
    _validate_configs(spec, errors)
    _validate_redaction(spec, errors)
    _validate_findings(spec, errors)
    _validate_child_env(spec, errors)
    _validate_child_env_keep(spec, errors)
    _validate_fuse_policy(spec, errors)
    _validate_policy(spec, errors)
    _validate_ebcdic(spec, errors)
    return errors
