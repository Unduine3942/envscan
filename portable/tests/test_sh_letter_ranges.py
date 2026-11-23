"""Lint: src/sh must not rely on ASCII letter ranges (A-Z, a-z).

On z/OS (EBCDIC) the ranges A-Z and a-z also contain `} \\ ~` and accented letters, so a bracket
expression such as [A-Za-z] or `tr a-z A-Z` matches the wrong characters. The z/OS work (Phase 2)
spells the letters out (no [[:alnum:]]: mawk 1.3.3 lacks the classes). The lint reports
file:line for every bracket expression or tr argument that has an A-Z / a-z range, in src/sh/*.sh
and src/sh/awk/*.awk. Comment lines are skipped.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

import pytest
from conftest import PORTABLE

SRC_SH = PORTABLE / "src" / "sh"
RANGE = r"(?:A-Z|a-z)"
BRACKET_RE = re.compile(r"\[\^?\]?(?:\[:[a-z]+:\]|[^\]\n])*?" + RANGE)
TR_RE = re.compile(r"""\btr\s+(?:-[a-z]+\s+)*(?:['"][^'"]*|[^\s'"]*)""" + RANGE)


class Hit(NamedTuple):
    path: Path
    line: int
    text: str

    def __str__(self) -> str:
        return f"{self.path.relative_to(PORTABLE).as_posix()}:{self.line}: {self.text.strip()}"


def is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def find_ranges(text: str) -> list[tuple[int, str]]:
    """(line number, line) of each line with a letter range in a bracket expression or tr argument."""
    return [(n, line) for n, line in enumerate(text.splitlines(), 1)
            if not is_comment(line) and (BRACKET_RE.search(line) or TR_RE.search(line))]


def scan(root: Path = SRC_SH) -> list[Hit]:
    files = sorted(root.glob("*.sh")) + sorted((root / "awk").glob("*.awk"))
    return [Hit(f, n, line) for f in files for n, line in find_ranges(f.read_text(encoding="utf-8"))]


@pytest.mark.unit
@pytest.mark.parametrize("line", [
    "case $x in [A-Za-z]*) ;; esac",
    "printf %s \"$x\" | tr 'a-z' 'A-Z'",
    "tr -d '\\r' | tr A-Z a-z",
    "awk '$1 ~ /^[a-z][a-z0-9]*$/'",
    "sed 's/[^A-Za-z0-9._-]//g'",
    "x=${y#[A-Z]}",
    "grep -e '[0-9A-F]*[a-z]'",
])
def test_scanner_finds_letter_ranges(line: str) -> None:
    assert find_ranges(line), line


@pytest.mark.unit
@pytest.mark.parametrize("line", [
    "# case $x in [A-Za-z]*) ;; esac",
    "case $x in [[:alpha:]]*) ;; esac",
    "tr '[:upper:]' '[:lower:]'",
    "awk '$1 ~ /^[0-9]+$/'",
    "echo 'A-Z'",
    "x=$((a-z))",
    "grep -e '[0-9a-f]*'",
])
def test_scanner_ignores_other_lines(line: str) -> None:
    assert find_ranges(line) == [], line


@pytest.mark.unit
def test_scan_reports_file_and_line(tmp_path: Path) -> None:
    (tmp_path / "awk").mkdir()
    (tmp_path / "a.sh").write_text("ok\ncase $x in [a-z]*) ;; esac\n", encoding="utf-8")
    (tmp_path / "awk" / "b.awk").write_text("BEGIN { x = 1 }\n$1 ~ /[A-Z]/\n", encoding="utf-8")
    hits = scan(tmp_path.joinpath())
    assert [(h.path.name, h.line) for h in hits] == [("a.sh", 2), ("b.awk", 2)]


@pytest.mark.unit
def test_src_sh_has_no_ascii_letter_ranges() -> None:
    hits = scan()
    assert not hits, f"{len(hits)} letter range(s) in src/sh:\n" + "\n".join(str(h) for h in hits)
