"""The POSIX sh lint of tools/target_sh.py: bash-isms are caught wherever a command can start
(indented, after then/do/else/{/(), and look-alikes in names, strings and awk programs are not."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import target_sh  # noqa: E402

BAD = [
    ("  local x=1", "local"),
    ("es_f() { local x; }", "local"),
    ("if true; then local x; fi", "local"),
    ("  do source ./x.sh", "source"),
    ("  else echo hi", "echo"),
    ("  ( echo hi )", "echo"),
    ("  x=$(which git)", "which"),
    ("  elif stat /etc/x >/dev/null; then :", "stat"),
    ("  for i in `seq 1 3`; do :; done", "seq"),
    ("  h=$(hostname)", "hostname"),
    ("  { hostname; }", "hostname"),
    ('  x=${y,,}', "case-modification"),
    ('  x="${y^^}"', "case-modification"),
    ('  n=${#a[@]}', "array-subscript"),
    ('  x=$((i++))', "arith-increment"),
    ("  ((i += 1))", "arith-command"),
    ("  while ((i < 3)); do :; done", "arith-command"),
    ("  for ((i = 0; i < 3; i++)); do :; done", "arith-for"),
    ("  x+=1", "append-assign"),
    ("  set -euo pipefail", "pipefail"),
    ("  set -o pipefail", "pipefail"),
    ("  trap 'es_x' ERR", "trap-err"),
    ("  export -f es_x", "export-f"),
    ("  p=$(type -P git)", "type-p"),
    ('  if [ -n "$a" -a -n "$b" ]; then :; fi', "test-and-or"),
    ('  [ "$a" = 1 -o "$b" = 2 ] && :', "test-and-or"),
    ("  select x in a b; do :; done", "select"),
    ("  time es_scan", "time"),
]

GOOD = [
    "  es_local_x=1",
    '  es_src "test each PATH entry (local file systems only)"',
    "  printf '%s\\n' 'echo local source which'",
    "  awk '",
    "    while ((getline l < f) > 0) { n += 1 }",
    "    NR > 1 && (($2 == 1) || ($3 == 2)) { x+=1 }",
    "  '",
    "  x=$((i + 1))",
    "  case $x in *,*) : ;; esac",
    '  [ -n "$a" ] && [ -n "$b" ]',
    '  [ "$x" = "-o" ]',
    "  es_time_init",
    "  # echo and local in a comment",
    '  n=${#x}',
]


@pytest.mark.parametrize("snippet,rule", BAD, ids=[f"{r}:{s.strip()[:30]}" for s, r in BAD])
def test_lint_rejects_bashisms(snippet: str, rule: str) -> None:
    errors = target_sh.lint(snippet + "\n")
    assert any(f"[{rule}]" in e for e in errors), errors


def test_lint_accepts_lookalikes() -> None:
    assert target_sh.lint("\n".join(GOOD) + "\n") == []


def test_lint_allow_comment_exempts_that_rule() -> None:
    assert target_sh.lint("  x=$(hostname)  # lint-allow: hostname\n") == []
