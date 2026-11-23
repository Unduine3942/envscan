"""Parity helper: normalized key facts of an envscan.json report, and the diff of two reports.

Used by the parity tests that run two implementations (sh vs psx, sh vs go, ...) on the same
fixture tree and compare what they found. Only facts that must agree are compared; timings,
paths of the output folder and free-form text are not. A probe or field that a report lacks is
None, so "one side did not collect it" shows up as a difference.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

MEMORY_STEP_MB = 128
LIMIT_FIELDS = ("nofile_soft", "nofile_hard", "nproc_soft", "nproc_hard", "stack_kb_soft", "core_soft",
                "memlock_kb_soft", "address_space_soft")
Doc = Mapping[str, Any]


class Difference(NamedTuple):
    key: str
    left: Any
    right: Any

    def __str__(self) -> str:
        return f"{self.key}: {self.left!r} != {self.right!r}"


def probe_data(doc: Doc, probe_id: str) -> Mapping[str, Any]:
    probe = (doc.get("probes") or {}).get(probe_id)
    data = probe.get("data") if isinstance(probe, Mapping) else None
    return data if isinstance(data, Mapping) else {}


def round_mb(value: Any, step: int = MEMORY_STEP_MB) -> int | None:
    """VALUE (MB) rounded to the nearest STEP; None for a missing or non-numeric value."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int((value + step / 2) // step) * step  # halves round up (same in every language)


def _urls(items: Any) -> list[str]:
    urls = (i.get("url") if isinstance(i, Mapping) else i for i in (items or []))
    return sorted({u for u in urls if isinstance(u, str)})


def _identity(doc: Doc) -> dict[str, Any]:
    data = probe_data(doc, "os.identity")
    return {"family": data.get("family"), "arch": data.get("arch")}


def _path_entries(doc: Doc) -> list[str]:
    entries = probe_data(doc, "env.path").get("entries") or []
    paths = (e.get("path") if isinstance(e, Mapping) else e for e in entries)
    return [p for p in paths if isinstance(p, str)]


def _tools_found(doc: Doc) -> list[str]:
    tools = probe_data(doc, "tools.inventory").get("tools") or {}
    return sorted(k for k, v in tools.items() if isinstance(v, Mapping) and v.get("found"))


def _sources(doc: Doc) -> dict[str, Any]:
    data = probe_data(doc, "pkg.sources")
    return {"endpoints": sorted(set(data.get("endpoints") or [])), "proxy_urls": _urls(data.get("proxy_urls"))}


def normalize(doc: Doc, memory_step_mb: int = MEMORY_STEP_MB) -> dict[str, Any]:
    """The key facts of DOC (a parsed envscan.json) in a form that two implementations share."""
    limits = probe_data(doc, "limits.process")
    return {
        "os.identity": _identity(doc),
        "hw.memory.total_mb": round_mb(probe_data(doc, "hw.memory").get("total_mb"), memory_step_mb),
        "limits.process": {k: limits.get(k) for k in LIMIT_FIELDS},
        "env.path": _path_entries(doc),
        "pkg.sources": _sources(doc),
        "tools.found": _tools_found(doc),
        "findings": sorted(f["id"] for f in doc.get("findings") or [] if isinstance(f, Mapping) and "id" in f),
    }


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, Mapping):
        if not value and prefix:
            return {prefix: {}}  # an empty table is not the same as a missing one
        out: dict[str, Any] = {}
        for key, item in value.items():
            out.update(_flatten(item, f"{prefix}.{key}" if prefix else str(key)))
        return out
    return {prefix: value}


def diff(left: Mapping[str, Any], right: Mapping[str, Any]) -> list[Difference]:
    """Differences between two normalized fact sets, by dotted key, in key order. A list is one
    value: the difference shows both lists."""
    a, b = _flatten(left), _flatten(right)
    return [Difference(k, a.get(k), b.get(k)) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]


def compare(left_doc: Doc, right_doc: Doc, ignore: Sequence[str] = (), memory_step_mb: int = MEMORY_STEP_MB) -> list[Difference]:
    """diff(normalize(LEFT_DOC), normalize(RIGHT_DOC)) without the keys in IGNORE (prefix match)."""
    found = diff(normalize(left_doc, memory_step_mb), normalize(right_doc, memory_step_mb))
    return [d for d in found if not any(d.key == i or d.key.startswith(i + ".") for i in ignore)]
