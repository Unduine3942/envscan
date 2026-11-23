"""The implementation registry (tools/spec.py REGISTRY) and the script/binary build split."""
from __future__ import annotations

import dataclasses
import hashlib
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest
from conftest import PORTABLE

import build as build_module
import docs
import spec as spec_module
from spec import REGISTRY, Impl, Spec, SpecError, load_spec, validate_registry

pytestmark = pytest.mark.unit

BIN_NAMES = ("envscan-fake-linux-amd64", "envscan-fake-linux-arm64")
FAKE = Impl(id="fake", label="envscan-fake binary", kind="binary", dist_file="envscan-fake", column="fake",
            report_impl=None, outputs=BIN_NAMES)
# the script rows plus a fake binary (the real go row needs a go toolchain; tests/test_go_*.py cover it)
REGISTRY_WITH_FAKE = (*(i for i in REGISTRY if i.kind == "script"), FAKE)
Builder = Callable[[Spec, Path, list[str]], dict[str, bytes]]


# ------------------------------------------------------------------ registry

def test_registry_lists_four_scripts_and_the_go_binary() -> None:
    assert [(i.id, i.kind) for i in REGISTRY] == [("ps", "script"), ("sh", "script"), ("cmd", "script"),
                                                  ("js", "script"), ("go", "binary")]
    assert [i.column for i in REGISTRY] == ["ps1", "sh", "cmd", "js", "go"]
    go = REGISTRY[-1]
    assert go.report_impl == "go"
    assert go.outputs == ("envscan-linux-amd64", "envscan-linux-arm64", "envscan-linux-s390x", "envscan-linux-ppc64le")
    assert validate_registry(REGISTRY) == []
    assert validate_registry(REGISTRY_WITH_FAKE) == []


@pytest.mark.parametrize("rows, expected", [
    ((REGISTRY[0], REGISTRY[0]), "duplicate id 'ps'"),
    ((dataclasses.replace(REGISTRY[0], kind="dll"),), "kind must be one of"),
    ((dataclasses.replace(REGISTRY[0], id="Bad Id"),), "id must match"),
    ((REGISTRY[0], dataclasses.replace(REGISTRY[1], dist_file=REGISTRY[0].dist_file)), "duplicate dist_file"),
    ((), "at least one"),
    ((dataclasses.replace(REGISTRY[0], dist_file="a/b.ps1"),), "dist_file must be a plain file name"),
    ((dataclasses.replace(REGISTRY[0], dist_file=".."),), "dist_file must be a plain file name"),
    ((dataclasses.replace(REGISTRY[0], dist_file="a\\b"),), "dist_file must be a plain file name"),
    ((dataclasses.replace(REGISTRY[0], column="a|b"),), "column must be printable"),
    ((dataclasses.replace(REGISTRY[0], label="caf\u00e9"),), "label must be printable"),
    ((dataclasses.replace(REGISTRY[0], label="a|b"),), "label must be printable"),
    ((FAKE, dataclasses.replace(REGISTRY[0], outputs=("x",))), "script must not declare outputs"),
    ((dataclasses.replace(FAKE, outputs=()),), "binary must declare its outputs"),
    ((dataclasses.replace(FAKE, outputs=("../x",)),), "output must be a plain file name"),
    ((dataclasses.replace(FAKE, outputs=("SHA256SUMS",)),), "output must be a plain file name"),
    ((dataclasses.replace(FAKE, outputs=("a", "a")),), "duplicate output"),
    ((dataclasses.replace(FAKE, outputs=("Sha256Sums",)),), "output must be a plain file name"),
    ((dataclasses.replace(FAKE, outputs=("Tool", "tool")),), "duplicate output"),
])
def test_registry_validation(rows: tuple[Impl, ...], expected: str) -> None:
    assert any(expected in error for error in validate_registry(rows)), validate_registry(rows)


def test_registry_row_without_a_footprint_file_is_a_clear_spec_error() -> None:
    with pytest.raises(SpecError) as caught:
        load_spec(PORTABLE / "spec", (*REGISTRY, FAKE))
    message = str(caught.value)
    assert "'fake'" in message and "footprint" in message and "fake.toml" in message


def test_load_spec_reads_the_registry_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(spec_module, "REGISTRY", REGISTRY_WITH_FAKE)
    with pytest.raises(SpecError, match="'fake'"):
        load_spec(PORTABLE / "spec")


def test_every_registered_impl_has_a_footprint_and_a_builder() -> None:
    spec = load_spec(PORTABLE / "spec")
    assert tuple(spec.impls) == REGISTRY
    for impl in REGISTRY:
        assert impl.id in spec.footprints and impl.id in build_module.BUILDERS


def test_spec_policy_data_is_immutable_tuples() -> None:
    spec = load_spec(PORTABLE / "spec")
    assert all(isinstance(values, tuple) for values in spec.credentials.values())
    assert isinstance(spec.network_fs, tuple)


def test_build_derives_its_lists_from_the_registry() -> None:
    assert build_module.ALL_TARGETS == tuple(i.id for i in REGISTRY)
    assert build_module.SCRIPT_TARGETS == ("ps", "sh", "cmd", "js")
    assert build_module.DIST_FILES == ("envscan.cmd", "envscan.js", "envscan.ps1", "envscan.sh", "README.md")


def _spec_with_fake() -> Spec:
    spec = load_spec(PORTABLE / "spec")
    return dataclasses.replace(spec, impls=REGISTRY_WITH_FAKE,
                               footprints={**spec.footprints, "fake": spec.footprints["ps"]})


def test_docs_table_header_and_headings_come_from_the_registry() -> None:
    spec = load_spec(PORTABLE / "spec")
    assert docs.probe_table(spec).splitlines()[0] == "| Probe | Title | Tier | Scope | ps1 | sh | cmd | js | go |"
    extended = _spec_with_fake()
    table = docs.probe_table(extended).splitlines()
    assert table[0].endswith("| ps1 | sh | cmd | js | fake |")
    assert table[1] == "|---|---|---|---|---|---|---|---|---|"
    assert all(row.endswith("| yes |") or row.endswith("| - |") for row in table[2:])
    assert "### envscan-fake binary" in docs.footprint_section(extended)


# ------------------------------------------------------------------ build split

def _fake_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    shutil.copytree(PORTABLE / "spec", root / "spec")
    shutil.copy2(root / "spec" / "footprint" / "ps.toml", root / "spec" / "footprint" / "fake.toml")
    (root / "docs").mkdir()
    shutil.copy2(PORTABLE / "docs" / "README.dist.md", root / "docs" / "README.dist.md")
    return root


def _script(name: str) -> Builder:
    def build(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
        return {f"dist/{name}": f"script {name}\n".encode("ascii")}
    return build


def _binary(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
    return {f"dist-bin/{BIN_NAMES[0]}": b"\x7fELF fake", f"dist-bin/{BIN_NAMES[1]}": b"\x7fELF fake2"}


def _emits(files: Mapping[str, bytes]) -> Builder:
    def build(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
        return dict(files)
    return build


def _builders(binary: Builder = _binary, **scripts: Builder) -> Mapping[str, Builder]:
    base = {"ps": _script("envscan.ps1"), "sh": _script("envscan.sh"), "cmd": _script("envscan.cmd"),
            "js": _script("envscan.js")}
    return {**base, **scripts, "fake": binary}


def _fake_build(tmp_path: Path, binary: Builder, targets: tuple[str, ...] = ("fake",)) -> build_module.BuildResult:
    return build_module.build(_fake_root(tmp_path), targets, registry=REGISTRY_WITH_FAKE, builders=_builders(binary))


def test_default_targets_are_the_scripts_only(tmp_path: Path) -> None:
    result = build_module.build(_fake_root(tmp_path), registry=REGISTRY_WITH_FAKE, builders=_builders())
    assert result.ok, result.errors
    assert not [name for name in result.files if name.startswith("dist-bin/")]
    assert "dist/SHA256SUMS" in result.files and "dist-bin/SHA256SUMS" not in result.files


def test_binary_target_goes_to_dist_bin_with_its_own_checksums(tmp_path: Path) -> None:
    result = _fake_build(tmp_path, _binary)
    assert result.ok, result.errors
    assert set(result.files) == {f"dist-bin/{n}" for n in BIN_NAMES} | {"dist-bin/SHA256SUMS"}
    sums = result.files["dist-bin/SHA256SUMS"].decode("ascii").splitlines()
    assert sums == [f"{hashlib.sha256(result.files['dist-bin/' + n]).hexdigest()}  {n}" for n in BIN_NAMES]


def test_release_build_builds_every_target_and_keeps_dist_text_only(tmp_path: Path) -> None:
    targets = build_module.all_targets(REGISTRY_WITH_FAKE)
    result = _fake_build(tmp_path, _binary, targets)
    assert result.ok, result.errors
    dist_sums = result.files["dist/SHA256SUMS"].decode("ascii")
    assert "fake" not in dist_sums and "dist-bin" not in dist_sums
    assert [line.split("  ")[1] for line in dist_sums.splitlines()] == list(build_module.DIST_FILES)
    assert "dist-bin/SHA256SUMS" in result.files


def test_binary_build_never_touches_dist(tmp_path: Path) -> None:
    result = _fake_build(tmp_path, _binary)
    assert not [name for name in result.files if name.startswith(("dist/", "docs/"))]


# HIGH 1: every declared binary must come out, and nothing else.
@pytest.mark.parametrize("emitted, expected", [
    ({}, "missing declared output"),
    ({f"dist-bin/{BIN_NAMES[0]}": b"x"}, f"missing declared output {BIN_NAMES[1]!r}"),
    ({**{f"dist-bin/{n}": b"x" for n in BIN_NAMES}, "dist-bin/surprise": b"x"}, "undeclared output 'surprise'"),
])
def test_a_binary_builder_must_produce_exactly_its_declared_outputs(
        tmp_path: Path, emitted: dict[str, bytes], expected: str) -> None:
    result = _fake_build(tmp_path, _emits(emitted))
    assert not result.ok
    assert any("fake" in e and expected in e for e in result.errors), result.errors
    assert "dist-bin/SHA256SUMS" not in result.files


# HIGH 2: output names are plain relative paths in the target's own folder.
@pytest.mark.parametrize("name", [
    "dist-bin/../dist/envscan.ps1", "dist-bin/sub/x", "/dist-bin/x", "dist-bin/SHA256SUMS", "dist/envscan-fake",
    "dist-bin\\x", "C:/x", "dist-bin/", "dist-bin/..", "../x", "dist-bin/sha256sums",
    "dist-bin/Sha256SUMS",
])
def test_a_binary_builder_cannot_leave_dist_bin(tmp_path: Path, name: str) -> None:
    result = _fake_build(tmp_path, _emits({**{f"dist-bin/{n}": b"x" for n in BIN_NAMES}, name: b"evil"}))
    assert not result.ok
    assert any("fake" in e and "dist-bin/" in e for e in result.errors), result.errors
    assert name not in result.files


@pytest.mark.parametrize("name", ["dist/../x", "dist/sub/../../x", "/x", "dist-bin/x", "docs/PROBES.md", "build/lib/../x",
                                  "dist/SHA256SUMS", "C:/x", "dist/sha256sums"])
def test_a_script_builder_stays_in_dist_and_build_lib(tmp_path: Path, name: str) -> None:
    bad = _emits({"dist/envscan.ps1": b"x", name: b"evil"})
    result = build_module.build(_fake_root(tmp_path), ("ps", "sh", "cmd", "js"), registry=REGISTRY_WITH_FAKE,
                                builders=_builders(ps=bad))
    assert not result.ok
    assert any(e.startswith("ps:") and "outside" in e for e in result.errors), result.errors


def test_outputs_that_collide_ignoring_case_are_refused(tmp_path: Path) -> None:
    emitted = {f"dist-bin/{BIN_NAMES[0]}": b"a", f"dist-bin/{BIN_NAMES[0].upper()}": b"b", f"dist-bin/{BIN_NAMES[1]}": b"c"}
    result = _fake_build(tmp_path, _emits(emitted))
    assert not result.ok and any("collide" in e for e in result.errors), result.errors


def test_write_outputs_refuses_paths_that_escape_the_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    for name in ("../evil.txt", "dist/../../evil.txt", str(tmp_path / "abs.txt")):
        with pytest.raises(ValueError, match="outside"):
            build_module.write_outputs(root, {name: b"x"})
    assert not (tmp_path / "evil.txt").exists() and not (tmp_path / "abs.txt").exists()


def test_write_outputs_writes_checksums_last(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    real = Path.write_bytes

    def record(self: Path, data: bytes) -> int:
        order.append(self.name)
        return real(self, data)

    monkeypatch.setattr(Path, "write_bytes", record)
    build_module.write_outputs(tmp_path, {"dist/SHA256SUMS": b"s", "dist/a": b"a", "dist-bin/SHA256SUMS": b"s",
                                          "dist-bin/b": b"b"})
    assert order[-2:] == ["SHA256SUMS", "SHA256SUMS"] and set(order[:2]) == {"a", "b"}


def test_main_reports_a_write_failure_clearly(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    def fail(root: Path, files: Mapping[str, bytes]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(build_module, "build", lambda *a, **k: build_module.BuildResult(files={"dist/x": b"x"}))
    monkeypatch.setattr(build_module, "write_outputs", fail)
    assert build_module.main([]) == 1
    assert "cannot write" in caplog.text and "disk full" in caplog.text


def test_checksums_report_a_non_ascii_name_instead_of_raising() -> None:
    errors: list[str] = []
    build_module._checksums({"dist/caf\u00e9": b"x"}, ("caf\u00e9",), "dist", errors)
    assert errors and "non-ASCII" in errors[-1]


def test_missing_toolchain_stops_the_release_build_with_a_clear_message(tmp_path: Path) -> None:
    def missing(spec: Spec, root: Path, errors: list[str]) -> dict[str, bytes]:
        raise build_module.ToolchainMissing("go not found; set ENVSCAN_GO or add go to PATH")

    result = _fake_build(tmp_path, missing, build_module.all_targets(REGISTRY_WITH_FAKE))
    assert not result.ok
    assert any("fake" in e and "toolchain" in e and "go not found" in e for e in result.errors), result.errors


def test_registered_impl_without_a_builder_is_an_error(tmp_path: Path) -> None:
    builders = {k: v for k, v in _builders().items() if k != "fake"}
    result = build_module.build(_fake_root(tmp_path), ("fake",), registry=REGISTRY_WITH_FAKE, builders=builders)
    assert any("no builder" in e and "'fake'" in e for e in result.errors), result.errors


def test_unknown_target_lists_the_registry() -> None:
    result = build_module.build(PORTABLE, ("zsh",))
    assert not result.ok and "ps, sh, cmd" in result.errors[0]


def test_main_check_ignores_binary_toolchains_but_release_needs_them(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, ...]] = []

    def fake_build(root: Path, targets: tuple[str, ...] | None = None, **kwargs: object) -> build_module.BuildResult:
        seen.append(tuple(targets or ()))
        return build_module.BuildResult(files={})

    monkeypatch.setattr(build_module, "REGISTRY", REGISTRY_WITH_FAKE)
    monkeypatch.setattr(build_module, "build", fake_build)
    monkeypatch.setattr(build_module, "write_outputs", lambda root, files: None)
    assert build_module.main(["--check"]) == 0
    assert seen[-1] == ("ps", "sh", "cmd", "js")
    assert build_module.main([]) == 0
    assert seen[-1] == ("ps", "sh", "cmd", "js", "fake")
    assert build_module.main(["--targets", "fake"]) == 0  # a binary-only build is complete
    assert build_module.main(["--targets", "ps,fake"]) == 2  # a partial script bundle is refused
    assert build_module.main(["--targets", "nope"]) == 2
    assert build_module.main(["--check", "--targets", ""]) == 2  # an empty list builds nothing
    assert build_module.main(["--targets", " , "]) == 2
