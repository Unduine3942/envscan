"""Language-neutral test cases for every envscan implementation, written as JSON.

The JScript (WSH) and Go ports have no Python at run time, so their harnesses read
build/testdata/*.json. The Python tables stay the single source:

* redaction.json: every redaction case (tests/redaction_cases.py). Each entry has `name`, `op`
  (name, value, line, text, cmd, named, or twice_* = apply the rule twice), `args`, `exact` and
  then `expected`, or `gone` (fragments that must disappear) and `kept` (fragments that must stay).
  `impls` lists the implementations (ps, sh) that pass today; `pending` maps an implementation
  to the reason it fails. A new implementation must pass every case, `pending` included.
* names.json: the secret-name cases (`name`, `secret`), a subset of redaction.json.
* proxy.json: tests/proxy_cases.py. `config` cases carry the spec entry limits (mode, match,
  max_bytes) of their config id; `git` cases are `git config --list` entries.

Files are deterministic: sorted keys, ASCII, LF, one trailing newline.
Usage: python tests/shared_cases.py [DEST]   (default build/testdata)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

TESTS = Path(__file__).resolve().parent
PORTABLE = TESTS.parent
for _extra in (str(PORTABLE / "tools"), str(TESTS)):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

import redaction_cases as rc  # noqa: E402
from proxy_cases import CONFIG_CASES, GIT_CASES  # noqa: E402

from spec import DEFAULT_CONFIG_MAX_BYTES, load_spec  # noqa: E402

DEFAULT_DEST = PORTABLE / "build" / "testdata"
IMPLS = ("ps", "sh")

OPS = {
    "Test-EsSecretName": "name",
    "Protect-EsValue": "value",
    "Protect-EsLine": "line",
    "Protect-EsText": "text",
    "Protect-EsCommandLine": "cmd",
    "Protect-EsNamedValue": "named",
    "Protect-TwiceValue": "twice_value",
    "Protect-TwiceLine": "twice_line",
    "Protect-TwiceCommandLine": "twice_cmd",
}


def redaction_entry(case: rc.Case) -> dict[str, Any]:
    pending = rc.KNOWN_DIVERGENCES.get(case.name, {})
    entry: dict[str, Any] = {
        "name": case.name, "op": OPS[case.fn], "args": list(case.args), "exact": case.exact,
        "impls": [i for i in IMPLS if i not in pending], "pending": dict(sorted(pending.items())),
    }
    if case.exact:
        entry["expected"] = case.expected
    else:
        entry["gone"] = list(case.gone)
        entry["kept"] = list(case.kept)
    return entry


def redaction_cases() -> list[dict[str, Any]]:
    """Every case once, in table order: shared, ps-only, then sh-only."""
    return [redaction_entry(c) for c in rc.ALL_CASES + rc.SH_CASES]


def name_cases() -> list[dict[str, Any]]:
    return [{"name": c.args[0], "secret": c.expected} for c in rc.ALL_CASES + rc.SH_CASES
            if c.fn == "Test-EsSecretName"]


def config_entry_limits(config_id: str, entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    entry = entries[config_id]
    return {"mode": entry.get("mode", "content"), "match": list(entry.get("match", [])),
            "max_bytes": entry.get("max_bytes", DEFAULT_CONFIG_MAX_BYTES)}


def proxy_cases() -> dict[str, Any]:
    entries = {c["id"]: c for c in load_spec(PORTABLE / "spec").configs}
    config = [{"name": c.name, "config_id": c.config_id, "text": c.text, "expected": list(c.expected),
               "endpoints": None if c.endpoints is None else list(c.endpoints),
               "entry": config_entry_limits(c.config_id, entries)} for c in CONFIG_CASES]
    git = [{"name": c.name, "entries": list(c.entries), "expected": list(c.expected)} for c in GIT_CASES]
    return {"config": config, "git": git}


def build_testdata() -> dict[str, Any]:
    """File name -> document, for every shared case file."""
    return {"redaction.json": redaction_cases(), "names.json": name_cases(), "proxy.json": proxy_cases()}


def dump(doc: Any) -> bytes:
    return (json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("ascii")


def write_testdata(dest: Path = DEFAULT_DEST) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, doc in build_testdata().items():
        path = dest / name
        path.write_bytes(dump(doc))
        written.append(path)
    return written


def main(argv: list[str]) -> int:
    dest = Path(argv[1]) if len(argv) > 1 else DEFAULT_DEST
    for path in write_testdata(dest):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
