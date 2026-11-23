"""Go target: spec export, source staging, lint and cross-compilation of the static envscan binaries.

The Go sources live in src/go (package main, standard library only). The build never writes into
src/go: `stage()` copies the sources into a build folder and adds `spec.json`, which the engine
embeds (`//go:embed spec.json`). The JSON holds the same tables envscan.sh gets (Unix rows only).

    python tools/target_go.py stage DEST [PREFIX...]   stage the sources for `go test` / `go vet`; with
                                                     prefixes only api_*.go, go.mod, testenv_*.go and the
                                                     files whose names start with a prefix

Release binaries: CGO_ENABLED=0, GOTOOLCHAIN=local, GOFLAGS empty, GOAMD64=v1, -trimpath,
-buildvcs=false, -ldflags "-s -w -buildid=". Each target is built twice and must be byte-identical.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from spec import DEFAULT_CONFIG_MAX_BYTES, Spec  # noqa: E402

UNIX_OS = ("all", "unix", "linux", "darwin")
# (GOOS, GOARCH) -> output name. linux amd64/arm64 are the supported targets; s390x and ppc64le are
# experimental (built and checksummed, never run here).
TARGETS: tuple[tuple[str, str], ...] = (
    ("linux", "amd64"), ("linux", "arm64"), ("linux", "s390x"), ("linux", "ppc64le"),
)
OUTPUTS: tuple[str, ...] = tuple(f"envscan-{goos}-{goarch}" for goos, goarch in TARGETS)
BUILD_TIMEOUT = 900
# Only reach*.go may open sockets; nothing may use cgo, unsafe, os/exec outside the engine's exec file,
# or packages that reach the network implicitly.
NET_IMPORTS = ("\"net\"", "\"net/", "\"crypto/tls\"")
BANNED_IMPORTS = ("\"C\"", "\"unsafe\"", "\"plugin\"", "\"net/http\"", "\"net/rpc\"", "\"net/smtp\"",
                  "\"os/user\"", "\"debug/buildinfo\"")
EXEC_FILES_RE = re.compile(r"^exec[a-z0-9_]*\.go$")
NET_FILES_RE = re.compile(r"^reach[a-z0-9_]*\.go$")
IMPORT_BLOCK_RE = re.compile(r"^import\s*(\([^)]*\)|\"[^\"]*\")", re.MULTILINE)


class GoMissing(Exception):
    """No usable go toolchain (message says where it was looked for)."""


def spec_doc(spec: Spec) -> dict[str, Any]:
    """The spec tables of the Go binary, as plain JSON data (Unix rows only, like envscan.sh)."""
    tools = [t for t in spec.tools if t.get("os", "all") in UNIX_OS]
    configs = [c for c in spec.configs if c.get("os", "all") in UNIX_OS]
    return {
        "name": spec.meta["name"],
        "version": spec.version,
        "schema": spec.meta["schema"],
        "probes": [{"id": p["id"], "title": p["title"], "tier": p["tier"], "scope": p["scope"],
                    "footprint": list(p["footprint"])} for p in spec.probes_for("go")],
        "tools": [{"id": t["id"], "name": t["name"], "cat": t["cat"], "mode": t.get("mode", "version"),
                   "os": t.get("os", "all"), "exe": list(t["exe"]), "args": list(t.get("args", [])),
                   "dirs": list(t.get("dirs", []))} for t in tools],
        "vmanagers": [{"id": m["id"], "name": m["name"], "markers": list(m.get("markers", [])),
                       "requires": m.get("requires", ""), "versions": list(m["versions"])}
                      for m in spec.version_managers],
        "configs": [{"id": c["id"], "tool": c["tool"], "os": c.get("os", "all"), "scope": c["scope"],
                     "mode": c.get("mode", "content"), "max_bytes": c.get("max_bytes", DEFAULT_CONFIG_MAX_BYTES),
                     "match": list(c.get("match", [])), "paths": list(c["paths"])} for c in configs],
        "caches": [{"id": c["id"], "tool": c["tool"], "paths": list(c["paths"])} for c in spec.caches],
        "findings": [{"id": f["id"], "severity": f["severity"], "title": f["title"],
                      "recommendation": f["recommendation"]} for f in spec.findings],
        "package_env": list(spec.package_env),
        "proxy_env": list(spec.proxy_env),
        "tls_env": list(spec.tls_env),
        "ca_bundles": list(spec.ca_bundles),
        "ca_anchor_dirs": list(spec.ca_anchor_dirs),
        "network_fs": list(spec.network_fs),
        "network_fs_prefixes": list(spec.network_fs_prefixes),
        "local_fuse": list(spec.local_fuse),
        "public_hosts": list(spec.public_hosts),
        "net_never": list(spec.net_never),
        "trust_store_names": list(spec.trust_store_names),
        "credentials": {k: list(v) for k, v in spec.credentials.items()},
        "redaction": _plain(spec.redaction),
        "thresholds": _plain(spec.thresholds),
        "child_env": dict(spec.child_env),
        # envscan.sh skips the Windows-only "(X86)" names; the binary matches names exactly
        "child_env_keep_names": [n for n in spec.child_env_keep_names if "(" not in n],
        "child_env_keep_prefixes": list(spec.child_env_keep_prefixes),
        "child_env_home_paths": [n for n in spec.child_env_home_paths if "(" not in n],
        "child_env_path_lists": [n for n in spec.child_env_path_lists if "(" not in n],
    }


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def spec_json(spec: Spec) -> str:
    return json.dumps(spec_doc(spec), sort_keys=True, ensure_ascii=True, indent=1) + "\n"


def source_files(src_dir: Path) -> list[Path]:
    """go.mod and every *.go file of src/go (sorted; no subfolders)."""
    files = sorted(p for p in src_dir.iterdir() if p.is_file() and (p.suffix == ".go" or p.name == "go.mod"))
    return files


ALWAYS_STAGED = ("api_", "testenv_")


def _wanted(name: str, prefixes: Sequence[str]) -> bool:
    if not prefixes or name == "go.mod":
        return True
    return any(name.startswith(p) for p in (*ALWAYS_STAGED, *prefixes))


def stage(spec: Spec, src_dir: Path, dest: Path, prefixes: Sequence[str] = ()) -> Path:
    """Copy the Go sources into DEST (its old staged files removed first) and add spec.json.
    With PREFIXES only some files are staged (see the module doc). Returns DEST."""
    dest.mkdir(parents=True, exist_ok=True)
    for old in dest.iterdir():
        if old.is_file() and (old.suffix == ".go" or old.name in ("go.mod", "spec.json")):
            old.unlink()
    for path in (p for p in source_files(src_dir) if _wanted(p.name, prefixes)):
        shutil.copyfile(path, dest / path.name)
    (dest / "spec.json").write_bytes(spec_json(spec).encode("ascii"))
    return dest


def _imports(text: str) -> list[str]:
    found: list[str] = []
    for block in IMPORT_BLOCK_RE.findall(text):
        found.extend(re.findall(r"\"[^\"]+\"", block))
    return found


def lint_sources(src_dir: Path) -> list[str]:
    """Import rules: no cgo/unsafe/http; only reach*.go imports net; only exec*.go imports os/exec;
    ASCII only."""
    errors: list[str] = []
    for path in source_files(src_dir):
        raw = path.read_bytes()
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            errors.append(f"{path.name}: non-ASCII byte at offset {exc.start}")
            continue
        imports = _imports(text)
        test_file = path.name.endswith("_test.go")
        for imp in imports:
            if imp in BANNED_IMPORTS:
                errors.append(f"{path.name}: banned import {imp}")
            if any(imp == n or imp.startswith(n) for n in NET_IMPORTS) and not NET_FILES_RE.match(path.name) \
                    and not (test_file and NET_FILES_RE.match(path.name.replace("_test", ""))):
                errors.append(f"{path.name}: only reach*.go may import {imp}")
            if imp == "\"os/exec\"" and not EXEC_FILES_RE.match(path.name) and not test_file:
                errors.append(f"{path.name}: only exec*.go may import os/exec")
        if "//go:linkname" in text:
            errors.append(f"{path.name}: //go:linkname is not allowed")
    return errors


def find_go() -> Path:
    """ENVSCAN_GO (the go binary or its GOROOT), then %LOCALAPPDATA%/envscan-dev/go, then PATH."""
    candidates: list[Path] = []
    env = os.environ.get("ENVSCAN_GO", "")
    if env:
        p = Path(env)
        candidates.extend([p, p / "bin" / "go.exe", p / "bin" / "go"])
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        candidates.append(Path(local) / "envscan-dev" / "go" / "bin" / "go.exe")
    which = shutil.which("go")
    if which:
        candidates.append(Path(which))
    for c in candidates:
        if c.is_file():
            return c
    raise GoMissing("go not found; set ENVSCAN_GO or add go to PATH "
                    "(the toolchain is only needed on the build machine, never on a target)")


def go_env(goos: str, goarch: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GO") and k != "CGO_ENABLED"}
    env.update({"CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOOS": goos, "GOARCH": goarch,
                "GOAMD64": "v1", "GOARM64": "v8.0", "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off",
                "GOTELEMETRY": "off"})
    env.update(extra or {})
    return env


def _run(go: Path, args: Sequence[str], cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(go), *args], cwd=cwd, env=dict(env), capture_output=True, text=True,
                          timeout=BUILD_TIMEOUT, check=False)


# The Windows development build (test-command hook, test mode) exists only with this build tag;
# release builds never use it.
DEV_TAGS = ("-tags", "envscan_dev")
# (GOOS, GOARCH, extra go vet arguments): the release target, the Windows development build and
# the Windows build without the tag (it refuses to scan).
VET_TARGETS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("linux", "amd64", ()), ("windows", "amd64", DEV_TAGS), ("windows", "amd64", ()),
)


def vet(go: Path, staged: Path) -> list[str]:
    errors: list[str] = []
    for goos, goarch, extra in VET_TARGETS:
        proc = _run(go, ["vet", *extra, "."], staged, go_env(goos, goarch))
        if proc.returncode != 0:
            label = f"{goos}/{goarch}{' ' + ' '.join(extra) if extra else ''}"
            errors.append(f"go vet ({label}): {(proc.stderr or proc.stdout).strip()[-3000:]}")
    return errors


def build_one(go: Path, staged: Path, goos: str, goarch: str, out: Path) -> str | None:
    args = ["build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", str(out), "."]
    proc = _run(go, args, staged, go_env(goos, goarch))
    if proc.returncode != 0:
        return f"go build {goos}/{goarch}: {(proc.stderr or proc.stdout).strip()[-3000:]}"
    return None


def build_all(spec: Spec, src_dir: Path, work: Path) -> tuple[dict[str, bytes], list[str]]:
    """Stage, lint, vet and cross-compile every target twice. Returns (name -> bytes, errors)."""
    go = find_go()
    errors = lint_sources(src_dir)
    if errors:
        return {}, errors
    staged = stage(spec, src_dir, work / "src")
    errors.extend(vet(go, staged))
    if errors:
        return {}, errors
    files: dict[str, bytes] = {}
    for (goos, goarch), name in zip(TARGETS, OUTPUTS):
        digests = []
        for attempt in ("a", "b"):
            out = work / attempt / name
            out.parent.mkdir(parents=True, exist_ok=True)
            problem = build_one(go, staged, goos, goarch, out)
            if problem:
                errors.append(problem)
                break
            digests.append(hashlib.sha256(out.read_bytes()).hexdigest())
        else:
            if digests[0] != digests[1]:
                errors.append(f"{name}: two builds differ ({digests[0]} != {digests[1]}); the build is not reproducible")
            files[name] = (work / "a" / name).read_bytes()
    return files, errors


def main(argv: Sequence[str]) -> int:
    from spec import load_spec  # noqa: PLC0415
    if len(argv) < 2 or argv[0] != "stage":
        print(__doc__, file=sys.stderr)
        return 2
    spec = load_spec(TOOLS_DIR.parent / "spec")
    dest = stage(spec, TOOLS_DIR.parent / "src" / "go", Path(argv[1]), argv[2:])
    print(dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
