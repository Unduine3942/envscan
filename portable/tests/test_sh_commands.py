"""The sh parsers against captured raw command output (tests/data/commands.json).

Each group of the file holds `output` (what the command printed) and the `facts` it must parse
to; the Go port reuses the same file. The sh side runs the real code from build/lib/envscan-lib.sh:

  uname          es_detect_os (extracted from src/sh/90-main.sh) with a uname stub
  arch           es_norm_arch on a `uname -m` value
  versions       es_versions on a version command's output
  df             probe_hw_storage with a df stub
  limits_proc    probe_limits_process on a /proc/self/limits file
  limits_ulimit  probe_limits_process with a ulimit shell function that answers per flag
  id             probe_user_identity with an id stub
  ps             probe_proc_list with a ps stub (`format` says which ps variant the stub accepts)
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from conftest import PORTABLE
from sh_helpers import msys_path, needs_msys, run_lib, sh_unescape

pytestmark = [pytest.mark.integration, needs_msys]

DATA = Path(__file__).resolve().parent / "data" / "commands.json"
GROUPS: dict[str, list[dict[str, Any]]] = json.loads(DATA.read_text(encoding="ascii"))["groups"]
PREAMBLE = ('ES_P_DIR=$1; ES_TMP=$1; ES_ROOT=$2; ES_OS=$3; ES_TIMEOUT=10; ES_DEADLINE=99999999999999; '
            'PATH="$4:/usr/bin"; es_pid_init\n')
# probes write events to fd 5; "@ FILE" lines include a file's events
RUN_PROBE = ('{ %s; } 5>"$ES_P_DIR/ev.txt"\n'
             'while IFS= read -r l; do case $l in "@$ES_TAB"*) cat "${l#@$ES_TAB}" ;; *) printf "%%s\\n" "$l" ;; esac; done '
             '<"$ES_P_DIR/ev.txt"\n')


def parse_events(text: str) -> dict[str, Any]:
    """Event stream -> nested dict: objects ("{"), lists ("["), s/n/b scalars, z = null."""
    root: dict[str, Any] = {}
    stack: list[Any] = [root]
    for line in text.splitlines():
        kind, _, rest = line.partition("\t")
        top = stack[-1]
        if kind in ("{", "["):
            child: Any = {} if kind == "{" else []
            (top.append(child) if isinstance(top, list) else top.__setitem__(rest, child))
            stack.append(child)
        elif kind in ("}", "]"):
            stack.pop()
        elif kind == "z":
            (top.append(None) if isinstance(top, list) else top.__setitem__(rest, None))
        elif kind in ("s", "e", "l", "c", "n", "b"):
            key, _, raw = rest.partition("\t")
            value: Any = sh_unescape(raw)
            if kind == "n" and re.fullmatch(r"-?\d+", value):
                value = int(value)
            elif kind == "b":
                value = value == "true"
            (top.append(value) if isinstance(top, list) else top.__setitem__(key, value))
    return root


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


class Sandbox:
    def __init__(self, base: Path) -> None:
        self.pdir, self.root, self.stubs = base / "p", base / "root", base / "stubs"
        for d in (self.pdir, self.root, self.stubs):
            d.mkdir()

    def stub(self, name: str, body: str) -> None:
        (self.stubs / name).write_text("#!/bin/sh\n" + body, encoding="ascii", newline="\n")

    def args(self, os_name: str = "linux") -> tuple[str, ...]:
        return msys_path(self.pdir), msys_path(self.root), os_name, msys_path(self.stubs)

    def run(self, lib: Path, script: str, *extra: str, os_name: str = "linux", env: dict[str, str] | None = None) -> str:
        proc = run_lib(lib, PREAMBLE + script, *self.args(os_name), *extra, env=env)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    def put(self, name: str, text: str) -> Path:
        path = self.pdir.parent / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
        return path


@pytest.fixture
def box(tmp_path: Path) -> Sandbox:
    return Sandbox(tmp_path)


def cases(group: str) -> Any:
    return [pytest.param(c, id=c["name"]) for c in GROUPS[group]]


def detect_os_source() -> str:
    text = (PORTABLE / "src" / "sh" / "90-main.sh").read_text(encoding="utf-8")
    match = re.search(r"^es_detect_os\(\) \{\n.*?^\}\n", text, re.S | re.M)
    assert match, "es_detect_os not found in 90-main.sh"
    return match.group(0)


def test_file_is_wellformed() -> None:
    assert set(GROUPS) == {"uname", "arch", "versions", "df", "limits_proc", "limits_ulimit", "id", "ps"}
    for group, items in GROUPS.items():
        names = [i["name"] for i in items]
        assert len(names) == len(set(names)), group
        assert all("output" in i and "facts" in i and i["command"] for i in items), group
    raw = DATA.read_bytes()
    raw.decode("ascii")
    assert b"\r" not in raw


@pytest.mark.parametrize("case", cases("uname"))
def test_uname(lib: Path, box: Sandbox, case: dict[str, Any]) -> None:
    assert case["output"].startswith(" ".join(case["flags"][f] for f in ("-s", "-n", "-r")))
    box.stub("uname", 'case "$1" in -s) printf "%s\\n" "$UN_S" ;; -n) printf "%s\\n" "$UN_N" ;; '
                      '-r) printf "%s\\n" "$UN_R" ;; -m) printf "%s\\n" "$UN_M" ;; esac\n')
    script = detect_os_source() + 'es_detect_os; printf "%s|%s|%s|%s\\n" "$ES_OS" "$ES_ARCH" "$ES_F_wsl" "$ES_HOST"\n'
    f = case["flags"]
    out = box.run(lib, script, env={"UN_S": f["-s"], "UN_N": f["-n"], "UN_R": f["-r"], "UN_M": f["-m"]})
    facts = case["facts"]
    assert out.strip() == f"{facts['os']}|{facts['arch']}|{str(facts['wsl']).lower()}|{facts['hostname']}"


@pytest.mark.parametrize("case", cases("arch"))
def test_norm_arch(lib: Path, box: Sandbox, case: dict[str, Any]) -> None:
    assert box.run(lib, 'es_norm_arch "$5"; printf "%s\\n" "$ES_A"', case["output"].strip()).strip() == case["facts"]["arch"]


@pytest.mark.parametrize("case", cases("versions"))
def test_versions(lib: Path, box: Sandbox, case: dict[str, Any]) -> None:
    box.put("v/x.out", case["output"])
    out = box.run(lib, 'cd "$5" && es_versions x.out', msys_path(box.pdir.parent / "v"))
    file, version, line, status = out.rstrip("\n").split("\t")
    assert (file, version, line, status) == ("x.out", case["facts"]["version"], case["facts"]["line"], case["facts"]["status"])


@pytest.mark.parametrize("case", cases("df"))
def test_df(lib: Path, box: Sandbox, case: dict[str, Any]) -> None:
    out_file = box.put("df.txt", case["output"])
    box.stub("df", f'cat "{msys_path(out_file)}"\n')
    if "mounts_proc" in case:
        (box.root / "proc" / "self").mkdir(parents=True)
        (box.root / "proc" / "self" / "mounts").write_bytes(case["mounts_proc"].encode("ascii"))
    if "mount_cmd" in case:
        mount_file = box.put("mount.txt", case["mount_cmd"])
        box.stub("mount", f'cat "{msys_path(mount_file)}"\n')
    events = parse_events(box.run(lib, "es_mounts_init\n" + RUN_PROBE % "probe_hw_storage", os_name=case["os"]))
    got = [{k: v[k] for k in ("device", "mount", "fstype", "total_mb", "free_mb")} for v in events["volumes"]]
    assert got == case["facts"]["volumes"]


LIMIT_KEYS = ("nofile_soft", "nofile_hard", "nproc_soft", "nproc_hard", "stack_kb_soft", "core_soft", "memlock_kb_soft",
              "address_space_soft")


@pytest.mark.parametrize("case", cases("limits_proc"))
def test_limits_from_proc_self_limits(lib: Path, box: Sandbox, case: dict[str, Any]) -> None:
    target = box.root / "proc" / "self"
    target.mkdir(parents=True)
    (target / "limits").write_bytes(case["output"].encode("ascii"))
    events = parse_events(box.run(lib, RUN_PROBE % "probe_limits_process"))
    assert {k: events.get(k) for k in LIMIT_KEYS} == case["facts"]


def fake_ulimit(case: dict[str, Any], text_file: Path) -> str:
    arms = "".join(f"    {flag}) {'return 1' if value is None else 'echo ' + value} ;;\n"
                   for flag, value in case["flags"].items())
    return f'ulimit() {{\n  case "$1" in\n    -a) cat "{msys_path(text_file)}" ;;\n{arms}    *) return 1 ;;\n  esac\n}}\n'


@pytest.mark.parametrize("case", cases("limits_ulimit"))
def test_limits_from_the_ulimit_builtin(lib: Path, box: Sandbox, case: dict[str, Any]) -> None:
    text_file = box.put("ulimit.txt", case["output"])
    events = parse_events(box.run(lib, fake_ulimit(case, text_file) + RUN_PROBE % "probe_limits_process"))
    assert {k: events.get(k) for k in LIMIT_KEYS} == case["facts"]


@pytest.mark.parametrize("case", cases("id"))
def test_id(lib: Path, box: Sandbox, case: dict[str, Any]) -> None:
    out_file = box.put("id.txt", case["output"])
    box.stub("id", f'cat "{msys_path(out_file)}"\n')
    box.stub("getent", "exit 2\n")
    events = parse_events(box.run(lib, RUN_PROBE % "probe_user_identity", env={"USER": "", "LOGNAME": ""}))
    facts = case["facts"]
    assert events["name"] == facts["name"]
    assert (events["uid"], events["gid"], events["primary_group"]) == (facts["uid"], facts["gid"], facts["primary_group"])
    assert events["groups"] == facts["groups"]
    assert events["is_admin"] is facts["is_admin"]


@pytest.mark.parametrize("case", cases("ps"))
def test_ps(lib: Path, box: Sandbox, case: dict[str, Any]) -> None:
    out_file = box.put("ps.txt", case["output"])
    first_arg = "-A" if case["format"] == "uid" else "-ef"
    box.stub("ps", f'[ "$1" = {first_arg} ] || exit 1\ncat "{msys_path(out_file)}"\n')
    (box.root / "etc").mkdir()
    (box.root / "etc" / "nsswitch.conf").write_text("passwd: files\n", encoding="ascii", newline="\n")
    if case["passwd"]:
        (box.root / "etc" / "passwd").write_text(case["passwd"], encoding="ascii", newline="\n")
    me = case["me"]
    events = parse_events(box.run(lib, f'ES_F_user={me["user"]}; ES_F_uid={me["uid"]}\n' + RUN_PROBE % "probe_proc_list"))
    keys = ("pid", "ppid", "name", "user", "path", "cmdline")
    got = [{k: p.get(k) for k in keys} for p in events["processes"]]
    assert got == case["facts"]["processes"]
    assert events["count"] == case["facts"]["count"]
