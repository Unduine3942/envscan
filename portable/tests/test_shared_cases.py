"""The JSON case files for the JScript and Go ports must equal the Python tables (no drift)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import redaction_cases as rc
import shared_cases as sc
import test_ps_redaction as ps_tests
import test_sh_redaction as sh_tests
from proxy_cases import CONFIG_CASES, GIT_CASES

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def out(tmp_path_factory: pytest.TempPathFactory) -> Path:
    dest = tmp_path_factory.mktemp("testdata")
    sc.write_testdata(dest)
    return dest


def load(out: Path, name: str) -> Any:
    return json.loads((out / name).read_text(encoding="ascii"))


def to_case(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (entry["name"], entry["op"], tuple(entry["args"]), entry["exact"], entry.get("expected"),
            tuple(entry.get("gone", ())), tuple(entry.get("kept", ())))


def from_case(case: rc.Case) -> tuple[Any, ...]:
    return (case.name, sc.OPS[case.fn], tuple(case.args), case.exact, case.expected if case.exact else None,
            case.gone if not case.exact else (), case.kept if not case.exact else ())


def test_redaction_round_trips_to_the_python_cases(out: Path) -> None:
    got = [to_case(e) for e in load(out, "redaction.json")]
    assert got == [from_case(c) for c in rc.ALL_CASES + rc.SH_CASES]


def test_every_ps_and_sh_case_is_present(out: Path) -> None:
    got = {e["name"]: to_case(e) for e in load(out, "redaction.json")}
    for case in list(ps_tests.ALL_CASES) + list(sh_tests.ALL):
        assert got[case.name] == from_case(case), case.name


def test_case_names_are_unique_and_case_insensitively_distinct(out: Path) -> None:
    names = [e["name"] for e in load(out, "redaction.json")]
    assert len(names) == len(set(names))
    assert len(names) == len({n.lower() for n in names})  # PowerShell hashtable keys


def test_impls_and_pending_follow_the_known_divergences(out: Path) -> None:
    entries = {e["name"]: e for e in load(out, "redaction.json")}
    assert set(rc.KNOWN_DIVERGENCES) <= set(entries)
    for name, entry in entries.items():
        pending = rc.KNOWN_DIVERGENCES.get(name, {})
        assert entry["pending"] == pending
        assert entry["impls"] == [i for i in sc.IMPLS if i not in pending]
        assert all(pending.values())


def test_names_file_is_the_name_subset(out: Path) -> None:
    names = load(out, "names.json")
    assert len(names) >= len(rc.SECRET_NAMES)
    assert {"name": "sessionKey", "secret": True} in names
    assert {"name": "KEY", "secret": False} in names
    redaction = [e for e in load(out, "redaction.json") if e["op"] == "name"]
    assert [(n["name"], n["secret"]) for n in names] == [(e["args"][0], e["expected"]) for e in redaction]


def test_proxy_round_trips(out: Path) -> None:
    doc = load(out, "proxy.json")
    assert [(c["name"], c["config_id"], c["text"], tuple(c["expected"]),
             None if c["endpoints"] is None else tuple(c["endpoints"])) for c in doc["config"]] == [
        (c.name, c.config_id, c.text, c.expected, c.endpoints) for c in CONFIG_CASES]
    assert [(c["name"], tuple(c["entries"]), tuple(c["expected"])) for c in doc["git"]] == [
        (c.name, c.entries, c.expected) for c in GIT_CASES]
    assert all({"mode", "match", "max_bytes"} <= set(c["entry"]) for c in doc["config"])


def test_files_are_deterministic_ascii_lf_sorted(out: Path, tmp_path: Path) -> None:
    sc.write_testdata(tmp_path)
    for name in sc.build_testdata():
        raw = (out / name).read_bytes()
        assert raw == (tmp_path / name).read_bytes()
        raw.decode("ascii")
        assert b"\r" not in raw and raw.endswith(b"\n") and not raw.endswith(b"\n\n")
        doc = json.loads(raw)
        assert raw == (json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("ascii")


def test_non_ascii_is_escaped() -> None:
    assert sc.dump({"k": "café"}) == b'{\n "k": "caf\\u00e9"\n}\n'


def test_cli_writes_files(tmp_path: Path) -> None:
    assert sc.main(["shared_cases.py", str(tmp_path / "d")]) == 0
    assert sorted(p.name for p in (tmp_path / "d").iterdir()) == ["names.json", "proxy.json", "redaction.json"]
