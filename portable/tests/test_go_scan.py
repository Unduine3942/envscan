"""The Go binary end to end: a Windows dev build scans tests/fixtures/linux-basic (ENVSCAN_ROOT,
ENVSCAN_TEST_OS=linux), and the release cross-build produces static, reproducible Linux binaries.

Parity: on the same fixture tree, the probes whose data comes only from files must give exactly the
data envscan.sh gives (sh runs under MSYS here, so command-derived values describe this host and are
not compared).
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

import go_harness as gh
from conftest import find_output, load_report, schema_errors

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not gh.HAVE_GO, reason="go toolchain not found")]

ROOT = gh.FIXTURES / "linux-basic"
FILE_PROBES = ("limits.kernel", "limits.cgroup", "net.ports", "net.interfaces", "net.routes", "net.dns",
               "net.listening", "net.proxy", "net.firewall")
CANARY = "envscanCanaryTok3n9f8e7d6c5b4a"
ELF_MACHINE = {"envscan-linux-amd64": 62, "envscan-linux-arm64": 183, "envscan-linux-s390x": 22,
               "envscan-linux-ppc64le": 21}


@pytest.fixture(scope="module")
def dev_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    work = tmp_path_factory.mktemp("go-dev")
    staged = gh.stage_all(work / "src")
    return gh.build_dev_binary(staged, work / "bin")


def _tree_state(root: Path) -> list[tuple[str, int]]:
    return sorted((str(p.relative_to(root)), p.stat().st_size) for p in root.rglob("*"))


def _temp_scanner_dirs() -> set[str]:
    temp = Path(tempfile.gettempdir())
    return {p.name for p in temp.iterdir() if p.name.startswith("envscan.")}


@pytest.fixture(scope="module")
def scan(dev_binary: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    before_tree, before_tmp = _tree_state(ROOT), _temp_scanner_dirs()
    out = tmp_path_factory.mktemp("go-scan")
    env = gh.dev_env(ROOT, {"ENVSCAN_TEST_SECRET_TOKEN": CANARY})
    proc = gh.run_dev(dev_binary, out, env=env)
    folder = Path(proc.stdout.strip())
    return {"proc": proc, "folder": folder, "doc": json.loads((folder / "envscan.json").read_text(encoding="utf-8")),
            "tree_same": _tree_state(ROOT) == before_tree, "new_tmp": _temp_scanner_dirs() - before_tmp}


def test_full_scan_is_schema_valid_and_complete(scan: dict[str, Any]) -> None:
    doc = scan["doc"]
    assert scan["proc"].returncode in (0, 1), scan["proc"].stderr[-2000:]
    assert schema_errors(doc) == []
    assert doc["scanner"]["impl"] == "go"
    assert doc["scanner"]["shell_version"].startswith("go1.")
    assert doc["run"]["test_root"] == str(ROOT)
    assert len(doc["probes"]) == 49
    bad = {k: (p["status"], p.get("error")) for k, p in doc["probes"].items() if p["status"] in ("error", "timeout")}
    assert bad == {}


def test_stdout_is_exactly_the_output_folder(scan: dict[str, Any]) -> None:
    assert scan["proc"].stdout.count("\n") == 1
    assert sorted(p.name for p in scan["folder"].iterdir()) == ["AGENT_BRIEF.md", "envscan.json", "envscan.log",
                                                                  "envscan.md"]


def test_default_tier_skips_deep_and_net_probes(scan: dict[str, Any]) -> None:
    probes = scan["doc"]["probes"]
    assert probes["net.reachability"]["status"] == "skipped"
    assert probes["user.privileges"]["status"] == "skipped"


def test_nothing_left_behind(scan: dict[str, Any]) -> None:
    assert scan["tree_same"], "the scan changed the fixture tree"
    assert scan["new_tmp"] == set()


def test_secrets_in_the_environment_never_reach_the_output(scan: dict[str, Any]) -> None:
    for name in ("envscan.json", "envscan.md", "AGENT_BRIEF.md", "envscan.log"):
        assert CANARY not in (scan["folder"] / name).read_text(encoding="utf-8", errors="replace"), name


def test_fixture_identity_and_findings(scan: dict[str, Any]) -> None:
    doc = scan["doc"]
    ident = doc["probes"]["os.identity"]["data"]
    assert (ident["name"], ident["version"], ident["distro_id"]) == ("Ubuntu 22.04.4 LTS", "22.04", "ubuntu")
    assert doc["host"]["os_name"] == "Ubuntu 22.04.4 LTS"
    ids = {f["id"] for f in doc["findings"]}
    assert {"net.proxy_configured", "scan.partial"} <= ids
    brief = (scan["folder"] / "AGENT_BRIEF.md").read_text(encoding="utf-8")
    assert "static binary" in brief


@pytest.mark.skipif(sys.platform != "win32", reason="the sh side runs under MSYS on the Windows dev box")
def test_file_derived_probes_match_envscan_sh(built: Path, dev_binary: Path, tmp_path: Path) -> None:
    from sh_helpers import BASH, DASH, run_scan  # noqa: PLC0415
    if not DASH.exists() or not BASH.exists():
        pytest.skip("Git for Windows dash/bash not found")
    only = ["--only", ",".join(FILE_PROBES)]
    sh_out, go_out = tmp_path / "sh", tmp_path / "go"
    sh_out.mkdir(), go_out.mkdir()
    proc = run_scan(built / "dist" / "envscan.sh", sh_out, only, env={"ENVSCAN_ROOT": str(ROOT)}, timeout=600)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    sh_doc = load_report(find_output(sh_out))
    go = gh.run_dev(dev_binary, go_out, *only, env=gh.dev_env(ROOT))
    go_doc = json.loads((Path(go.stdout.strip()) / "envscan.json").read_text(encoding="utf-8"))
    for pid in FILE_PROBES:
        assert go_doc["probes"][pid]["status"] == sh_doc["probes"][pid]["status"], pid
        assert go_doc["probes"][pid]["data"] == sh_doc["probes"][pid]["data"], pid


# ---------------------------------------------------------------- release binaries

def _elf_facts(data: bytes) -> tuple[int, bool, int]:
    """(e_machine, has PT_INTERP, ELF class) of a 64-bit ELF image."""
    assert data[:4] == b"\x7fELF"
    little = data[5] == 1
    end = "<" if little else ">"
    machine = struct.unpack_from(end + "H", data, 18)[0]
    phoff = struct.unpack_from(end + "Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from(end + "HH", data, 54)
    interp = any(struct.unpack_from(end + "I", data, phoff + i * phentsize)[0] == 3 for i in range(phnum))
    return machine, interp, data[4]


@pytest.fixture(scope="module")
def release(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    sys.path.insert(0, str(gh.TOOLS))
    import target_go  # noqa: PLC0415
    from spec import load_spec  # noqa: PLC0415
    files, errors = target_go.build_all(load_spec(gh.PORTABLE / "spec"), gh.SRC_GO,
                                        tmp_path_factory.mktemp("go-release"))
    assert errors == []
    return files


def test_release_builds_every_declared_output_reproducibly(release: dict[str, bytes]) -> None:
    assert sorted(release) == sorted(ELF_MACHINE)


@pytest.mark.parametrize("name", sorted(ELF_MACHINE))
def test_release_binary_is_static_elf_for_its_arch(release: dict[str, bytes], name: str) -> None:
    machine, interp, elf_class = _elf_facts(release[name])
    assert (machine, interp, elf_class) == (ELF_MACHINE[name], False, 2)
    assert len(release[name]) < 16 * 1024 * 1024
    assert b"ENVSCAN_TEST_CMDS" not in release[name], "the dev-only command hook is in a release build"


def test_release_binaries_carry_no_build_paths(release: dict[str, bytes]) -> None:
    home = os.path.expanduser("~").encode()
    for name, data in release.items():
        assert home not in data and b"Enviornment_Scanner" not in data, name


def test_go_unit_tests_pass_on_the_whole_tree(tmp_path: Path) -> None:
    from shared_cases import write_testdata  # noqa: PLC0415
    write_testdata(tmp_path / "testdata")
    staged = gh.stage_all(tmp_path / "src")
    env = {**gh._host_env(), "ENVSCAN_TESTDATA": str(tmp_path / "testdata"),
           "ENVSCAN_TESTDATA_FINDINGS": str(gh.PORTABLE / "tests" / "data"), "ENVSCAN_FIXTURES": str(gh.FIXTURES)}
    proc = subprocess.run([str(gh.GO), "test", *gh.DEV_TAGS, "-count=1", "."], cwd=staged, env=env,
                          capture_output=True, text=True, timeout=gh.BUILD_TIMEOUT, check=False)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-4000:]
    vet = gh.go_cmd(staged, "vet", *gh.DEV_TAGS, ".")
    assert vet.returncode == 0, vet.stderr[-3000:]


def test_lint_is_clean() -> None:
    sys.path.insert(0, str(gh.TOOLS))
    import target_go  # noqa: PLC0415
    assert target_go.lint_sources(gh.SRC_GO) == []

