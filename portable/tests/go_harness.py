"""Test harness for the Go port (src/go, the static envscan binary).

The sources are never built in src/go: they are staged into a build folder first (tools/target_go.py
stage). On this Windows dev box a *development* binary is built for the host (build tag envscan_dev,
DEV_TAGS; without it a non-Linux build refuses to scan at all); it refuses to scan unless
ENVSCAN_ROOT and ENVSCAN_TEST_OS=linux are set, never starts a child (commands come from the JSON table
named by ENVSCAN_TEST_CMDS) and has no system calls. run_dev() sets both variables.

    HAVE_GO                       a go toolchain was found (tools/target_go.find_go)
    stage_all(dest)               stage the full src/go tree
    stage_prefixes(dest, *pfx)    stage api_*, testenv_* and the files starting with a prefix
    build_dev_binary(staged, dest)  build the host test binary from a staged folder into dest
    run_dev(binary, out, *args, env=None, timeout=...)  run it with --out OUT under a fixture root
    go_cmd(staged, *args)         run `go ARGS` in a staged folder (go test, go vet; add DEV_TAGS)
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

PORTABLE = Path(__file__).resolve().parents[1]
TOOLS = PORTABLE / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import target_go  # noqa: E402
from spec import load_spec  # noqa: E402

SRC_GO = PORTABLE / "src" / "go"
FIXTURES = PORTABLE / "tests" / "fixtures"
DEFAULT_TIMEOUT = 120
BUILD_TIMEOUT = 600

try:
    GO: Path | None = target_go.find_go()
except target_go.GoMissing:
    GO = None
HAVE_GO = GO is not None

ENGINE_PREFIXES = ("engine_", "exec_", "sys_", "main")
DEV_TAGS = target_go.DEV_TAGS


def _spec():
    return load_spec(PORTABLE / "spec")


def stage_all(dest: Path) -> Path:
    """Every file of src/go plus spec.json in dest."""
    return target_go.stage(_spec(), SRC_GO, dest)


def stage_prefixes(dest: Path, *prefixes: str) -> Path:
    """api_*.go, testenv_*.go, go.mod and the files starting with one of the prefixes."""
    return target_go.stage(_spec(), SRC_GO, dest, prefixes)


def _host_env() -> dict[str, str]:
    goos = "windows" if sys.platform == "win32" else "linux"
    # fixtureRoot() of the Go tests finds tests/fixtures through this when staged outside build/
    return target_go.go_env(goos, os.environ.get("ENVSCAN_GOARCH", "amd64"), {"ENVSCAN_FIXTURES": str(FIXTURES)})


def go_cmd(staged: Path, *args: str, timeout: int = BUILD_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """`go ARGS` in the staged folder for the host (CGO off, no network, local toolchain)."""
    if GO is None:
        raise target_go.GoMissing("go not found")
    return subprocess.run([str(GO), *args], cwd=staged, env=_host_env(), capture_output=True, text=True,
                          timeout=timeout, check=False)


def build_dev_binary(staged: Path, dest: Path) -> Path:
    """The development binary for this host, built from a staged folder into dest."""
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / ("envscan-dev.exe" if sys.platform == "win32" else "envscan-dev")
    proc = go_cmd(staged, "build", *DEV_TAGS, "-trimpath", "-buildvcs=false", "-o", str(out), ".")
    if proc.returncode != 0:
        raise RuntimeError(f"go build failed:\n{proc.stderr or proc.stdout}")
    return out


def dev_env(root: Path | str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """A small environment for the dev binary: system basics, the fixture root and test mode."""
    keep = ("SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "PATH", "LOCALAPPDATA")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.update({"ENVSCAN_ROOT": str(root), "ENVSCAN_TEST_OS": "linux", "HOME": "/home/tester",
                "TMPDIR": os.environ.get("TEMP", os.environ.get("TMPDIR", "/tmp"))})
    env.update(extra or {})
    return env


def run_dev(binary: Path, out: Path, *args: str, env: Mapping[str, str] | None = None,
            root: Path | None = None, timeout: int = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess[str]:
    """Run the dev binary with --out OUT and ARGS under a fixture root (default linux-basic).
    `env` adds or replaces variables of dev_env()."""
    out.mkdir(parents=True, exist_ok=True)
    full_env = dev_env(root or FIXTURES / "linux-basic", env)
    return subprocess.run([str(binary), "--out", str(out), *args], env=full_env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
                          timeout=timeout, check=False)
