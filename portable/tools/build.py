"""Build the envscan bundle.

    python portable/tools/build.py            release: validate, assemble and lint EVERY registered target
    python portable/tools/build.py --check    validate and lint the script targets only, write nothing
    python portable/tools/build.py --targets go   build only some targets (see below)

Outputs (relative to portable/):
    dist/envscan.ps1 dist/envscan.sh dist/envscan.cmd dist/envscan.js dist/README.md dist/SHA256SUMS   (plain text only)
    dist-bin/<binaries> dist-bin/SHA256SUMS                                           (binary targets)
    build/lib/envscan-lib.ps1 build/lib/envscan-lib.sh build/lib/envscan-lib.js   (test libraries without main)
    docs/PROBES.md

The targets are the implementations in tools/spec.py REGISTRY: "script" targets go to dist/, "binary"
targets to dist-bin/. A release build stops with a message when a binary toolchain is missing.
`--targets` may name every script target, every binary target, or both, because each SHA256SUMS must
cover its whole set; a subset only works with --check. A binary-only build writes nothing to dist/.
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import target_cmd  # noqa: E402
import target_go  # noqa: E402
import target_js  # noqa: E402
import target_ps  # noqa: E402
import target_sh  # noqa: E402

import docs  # noqa: E402
from spec import REGISTRY, Impl, Spec, SpecError, load_spec, validate_registry, validate_spec  # noqa: E402

ROOT = TOOLS_DIR.parent
LOG = logging.getLogger("envscan.build")
BIN_DIR = "dist-bin"
SUMS_NAME = "SHA256SUMS"


class ToolchainMissing(Exception):
    """A binary builder raises this when its compiler is not installed (the message says how to get it)."""


def script_targets(registry: Sequence[Impl] | None = None) -> tuple[str, ...]:
    return tuple(i.id for i in (REGISTRY if registry is None else registry) if i.kind == "script")


def binary_targets(registry: Sequence[Impl] | None = None) -> tuple[str, ...]:
    return tuple(i.id for i in (REGISTRY if registry is None else registry) if i.kind == "binary")


def all_targets(registry: Sequence[Impl] | None = None) -> tuple[str, ...]:
    return tuple(i.id for i in (REGISTRY if registry is None else registry))


def dist_files(registry: Sequence[Impl] | None = None) -> tuple[str, ...]:
    """The files dist/SHA256SUMS covers: every script, then the README."""
    scripts = sorted(i.dist_file for i in (REGISTRY if registry is None else registry) if i.kind == "script")
    return (*scripts, "README.md")


ALL_TARGETS = all_targets()
SCRIPT_TARGETS = script_targets()
DIST_FILES = dist_files()
# A generator or template problem is reported as a build error, never as a traceback.
STEP_ERRORS = (OSError, ValueError, KeyError, TypeError)


@dataclass(frozen=True)
class BuildResult:
    files: Mapping[str, bytes] = field(default_factory=dict)
    errors: Sequence[str] = ()

    @property
    def ok(self) -> bool:
        return not self.errors


def _ascii(text: str, name: str, errors: list[str]) -> bytes:
    try:
        return text.encode("ascii")
    except UnicodeEncodeError as exc:
        errors.append(f"{name}: non-ASCII character at offset {exc.start}")
        return b""


def _build_ps(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
    assembled = target_ps.assemble(spec, root / "src" / "ps")
    errors.extend(f"envscan.ps1: {e}" for e in target_ps.lint(assembled.dist))
    return {
        "dist/envscan.ps1": _ascii(assembled.dist, "envscan.ps1", errors),
        "build/lib/envscan-lib.ps1": _ascii(assembled.lib, "envscan-lib.ps1", errors),
    }


def _build_sh(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
    assembled = target_sh.assemble(spec, root / "src" / "sh")
    errors.extend(f"envscan.sh: {e}" for e in target_sh.lint(assembled.dist))
    return {
        "dist/envscan.sh": _ascii(assembled.dist, "envscan.sh", errors),
        "build/lib/envscan-lib.sh": _ascii(assembled.lib, "envscan-lib.sh", errors),
    }


def _build_cmd(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
    text = target_cmd.assemble(spec, root / "src" / "cmd")
    errors.extend(f"envscan.cmd: {e}" for e in target_cmd.lint(text))
    return {"dist/envscan.cmd": _ascii(text, "envscan.cmd", errors)}


Builder = Callable[[Spec, Path, list[str]], dict[str, bytes]]
def _build_js(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
    assembled = target_js.assemble(spec, root / "src" / "js")
    errors.extend(f"envscan.js: {e}" for e in target_js.lint(assembled.dist))
    return {
        "dist/envscan.js": _ascii(assembled.dist, "envscan.js", errors),
        "build/lib/envscan-lib.js": _ascii(assembled.lib, "envscan-lib.js", errors),
    }


def _build_go(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
    """The static Go binaries (tools/target_go.py), staged and compiled under build/go-work."""
    try:
        target_go.find_go()
    except target_go.GoMissing as exc:
        raise ToolchainMissing(str(exc)) from exc
    files, problems = target_go.build_all(spec, root / "src" / "go", root / "build" / "go-work")
    errors.extend(f"go: {p}" for p in problems)
    return {f"{BIN_DIR}/{name}": data for name, data in files.items()}


BUILDERS: dict[str, Builder] = {"ps": _build_ps, "sh": _build_sh, "cmd": _build_cmd, "js": _build_js,
                                "go": _build_go}


def _describe(exc: Exception) -> str:
    return str(exc) if type(exc) is ValueError else f"{type(exc).__name__}: {exc}"


def _build_docs(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    try:
        template = (root / "docs" / "README.dist.md").read_text(encoding="utf-8")
        files["dist/README.md"] = docs.render_readme(template, spec).encode("utf-8")
    except STEP_ERRORS as exc:
        errors.append(f"README: {_describe(exc)}")
    try:
        files["docs/PROBES.md"] = docs.probes_markdown(spec).encode("utf-8")
    except STEP_ERRORS as exc:
        errors.append(f"PROBES.md: {_describe(exc)}")
    return files


def _checksums(files: Mapping[str, bytes], names: Sequence[str], folder: str, errors: list[str]) -> bytes:
    """SHA256SUMS over every file of `folder`; a missing one is an error, never a shorter list."""
    lines = []
    for name in names:
        content = files.get(f"{folder}/{name}")
        if content is None:
            errors.append(f"SHA256SUMS: {folder}/{name} was not built")
            continue
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}")
    try:
        return ("\n".join(lines) + "\n").encode("ascii")
    except UnicodeEncodeError as exc:
        errors.append(f"SHA256SUMS: non-ASCII file name in {folder}/ (offset {exc.start})")
        return b""


SCRIPT_DIRS = ("dist", "build/lib")


def _allowed(impl: Impl) -> str:
    return f"{BIN_DIR}/" if impl.kind == "binary" else "dist/ and build/lib/"


def _output_problem(impl: Impl, name: str) -> str | None:
    """Why `name` is not an allowed output path of `impl`, or None. Names are plain "/" relative paths:
    no absolute path, no "." or ".." component, no backslash or drive colon."""
    parts = name.split("/")
    if not name or "\\" in name or ":" in name or any(part in ("", ".", "..") for part in parts):
        return "not a plain relative path"
    if impl.kind == "binary":
        ok = len(parts) == 2 and parts[0] == BIN_DIR and parts[1].lower() != SUMS_NAME.lower()
        return None if ok else f"binaries are {BIN_DIR}/<name>, never {SUMS_NAME}"
    folder = str(PurePosixPath(name).parent)
    ok = folder in SCRIPT_DIRS and parts[-1].lower() != SUMS_NAME.lower()
    return None if ok else f"scripts are dist/<name> or build/lib/<name>, never {SUMS_NAME}"


def _screen_outputs(impl: Impl, built: Mapping[str, bytes], errors: list[str]) -> dict[str, bytes]:
    """The builder's files when all of them are allowed (and, for a binary, exactly the declared
    outputs); otherwise errors are added and nothing is kept."""
    problems = [f"{impl.id}: output {name!r} is outside {_allowed(impl)} ({problem})" for name in built
                if (problem := _output_problem(impl, name))]
    if impl.kind == "binary" and not problems:
        got = {name.split("/")[-1] for name in built}
        problems.extend(f"{impl.id}: missing declared output {name!r}" for name in impl.outputs if name not in got)
        problems.extend(f"{impl.id}: undeclared output {name!r}" for name in sorted(got - set(impl.outputs)))
    folded = [name.lower() for name in built]
    problems.extend(f"{impl.id}: outputs collide ignoring case: {name!r}" for name in sorted(set(folded))
                    if folded.count(name) > 1)
    errors.extend(problems)
    return {} if problems else dict(built)


def _run_builders(spec: Spec, root: Path, requested: Sequence[str], registry: Sequence[Impl],
                  builders: Mapping[str, Builder], errors: list[str]) -> dict[str, bytes]:
    impls = {impl.id: impl for impl in registry}
    files: dict[str, bytes] = {}
    for target in requested:
        if target not in builders:
            errors.append(f"{target}: no builder for registered implementation {target!r} (tools/build.py BUILDERS)")
            continue
        try:
            built = builders[target](spec, root, errors)
        except ToolchainMissing as exc:
            errors.append(f"{target}: binary toolchain missing: {exc} (the release build needs every registered "
                          f"target; to build only the scripts use --targets {','.join(script_targets(registry))})")
            continue
        except STEP_ERRORS as exc:
            errors.append(f"{target}: {_describe(exc)}")
            continue
        files.update(_screen_outputs(impls[target], built, errors))
    return files


def _check_targets(registry: Sequence[Impl], requested: Sequence[str]) -> str | None:
    unknown = [target for target in requested if target not in all_targets(registry)]
    if unknown:
        return f"unknown target(s) {', '.join(map(repr, unknown))}; expected some of {', '.join(all_targets(registry))}"
    return None


def _checksum_files(files: Mapping[str, bytes], requested: Sequence[str], registry: Sequence[Impl],
                    errors: list[str]) -> dict[str, bytes]:
    sums: dict[str, bytes] = {}
    if set(script_targets(registry)) <= set(requested):
        sums[f"dist/{SUMS_NAME}"] = _checksums(files, dist_files(registry), "dist", errors)
    binaries = binary_targets(registry)
    if binaries and set(binaries) <= set(requested):
        names = sorted(name for impl in registry if impl.kind == "binary" for name in impl.outputs)
        sums[f"{BIN_DIR}/{SUMS_NAME}"] = _checksums(files, names, BIN_DIR, errors)
    return sums


def build(root: Path = ROOT, targets: Sequence[str] | None = None, *, registry: Sequence[Impl] | None = None,
          builders: Mapping[str, Builder] | None = None) -> BuildResult:
    """Assemble every requested target (default: the script targets) and, with scripts, the docs.

    Never writes to disk. dist/SHA256SUMS is produced only when every script target is built, and
    dist-bin/SHA256SUMS only when every binary target is. `registry` and `builders` default to the
    real ones; tests inject others.
    """
    registry = tuple(REGISTRY if registry is None else registry)
    builders = BUILDERS if builders is None else builders
    problems = validate_registry(registry)
    if problems:
        return BuildResult(errors=tuple(problems))
    requested = tuple(dict.fromkeys(script_targets(registry) if targets is None else targets))
    message = _check_targets(registry, requested)
    if message:
        return BuildResult(errors=(message,))
    try:
        spec = load_spec(root / "spec", registry)
    except SpecError as exc:
        return BuildResult(errors=(str(exc),))
    errors = list(validate_spec(spec))
    if errors:
        return BuildResult(errors=tuple(errors))
    files = _run_builders(spec, root, requested, registry, builders, errors)
    if set(requested) & set(script_targets(registry)):
        files.update(_build_docs(spec, root, errors))
    if not errors:  # a checksum list of a failed build would vouch for a partial set
        files.update(_checksum_files(files, requested, registry, errors))
    return BuildResult(files=MappingProxyType(files), errors=tuple(errors))


def write_outputs(root: Path, files: Mapping[str, bytes]) -> None:
    """Write `files` below `root`: every path is checked to stay inside it before anything is written,
    and the SHA256SUMS files go last, so an interrupted write never leaves checksums for new files."""
    base = root.resolve()
    ordered = sorted(files, key=lambda name: (PurePosixPath(name).name.lower() == SUMS_NAME.lower(), name))
    paths = []
    for relative in ordered:
        path = root / relative
        if PurePosixPath(relative).is_absolute() or not path.resolve().is_relative_to(base):
            raise ValueError(f"output {relative!r} is outside {root}")
        paths.append(path)
    for relative, path in zip(ordered, paths):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(files[relative])


def _complete(targets: Sequence[str]) -> bool:
    """True when the targets cover whole sets: every script target and/or every binary target."""
    chosen = set(targets)
    for group in (set(script_targets(REGISTRY)), set(binary_targets(REGISTRY))):
        if chosen & group and not group <= chosen:
            return False
    return bool(chosen)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the envscan bundle.")
    parser.add_argument("--check", action="store_true", help="validate and lint the script targets only")
    parser.add_argument("--targets", default=None,
                        help=f"comma-separated: {','.join(all_targets(REGISTRY))} "
                             "(default: every script with --check, every target for a release)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if args.targets is None:
        targets = list(script_targets(REGISTRY) if args.check else all_targets(REGISTRY))
    else:
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if not targets:
        LOG.error("no targets given (expected some of %s)", ", ".join(all_targets(REGISTRY)))
        return 2
    unknown = sorted(set(targets) - set(all_targets(REGISTRY)))
    if unknown:
        LOG.error("unknown target(s): %s", ", ".join(unknown))
        return 2
    if not args.check and not _complete(targets):
        LOG.error("refusing to write a partial bundle (each SHA256SUMS must cover its whole set: scripts %s, "
                  "binaries %s); build whole sets, or add --check",
                  ", ".join(script_targets(REGISTRY)), ", ".join(binary_targets(REGISTRY)) or "none")
        return 2
    result = build(ROOT, targets, registry=REGISTRY)
    for error in result.errors:
        LOG.error("ERROR %s", error)
    if not result.ok:
        LOG.error("build failed: %d error(s)", len(result.errors))
        return 1
    if not args.check:
        try:
            write_outputs(ROOT, result.files)
        except (OSError, ValueError) as exc:
            LOG.error("cannot write the outputs: %s", exc)
            return 1
        for relative in sorted(result.files):
            LOG.info("wrote %s", relative)
    LOG.info("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
