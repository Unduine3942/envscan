"""envscan.sh on z/OS UNIX and IBM i PASE (tier 2, best effort, UNVERIFIED): whole scans of the dev box
with a stub `uname` that answers like those systems, ENVSCAN_ROOT fixtures (tests/fixtures/zos,
tests/fixtures/os400) and command stubs (tests/stubs/zos, tests/stubs/os400). The stub answers are
written from IBM's documentation, not captured from a system, so these tests pin the scanner's
behaviour (what it runs, what it refuses to touch, how it fails) and not the real output formats.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from conftest import DASH, find_output, load_report, schema_errors
from sh_helpers import FIXTURES, STUBS, msys_path, needs_msys, run_lib

pytestmark = [pytest.mark.integration, needs_msys]

ZOS_PROBES = ("os.identity,hw.cpu,hw.storage,limits.kernel,limits.process,user.identity,runtime.java,fs.mounts,"
              "svc.list,net.interfaces,tls.trust,net.firewall,virt.platform")
OS400_PROBES = "os.identity,hw.cpu,hw.storage,limits.kernel,user.identity,user.privileges,runtime.java,fs.mounts,svc.list"


def scan(built: Path, tmp_path: Path, system: str, probes: str, *extra: str,
         more_env: dict[str, str] | None = None) -> dict[str, Any]:
    out = tmp_path / "out"
    out.mkdir()
    log = tmp_path / "stub.log"
    env = {"ENVSCAN_ROOT": msys_path(FIXTURES / system), "ES_STUB_LOG": msys_path(log), "ENVSCAN_TEST_STUBS": "1",
           "PATH": f"{msys_path(STUBS / system)}:/usr/bin:/bin", "HOME": msys_path(tmp_path), **(more_env or {})}
    # a Windows --out path is converted only when the host looks like Cygwin/MSYS, which the stub
    # uname hides: pass the POSIX form, as a user on z/OS or IBM i would
    proc = subprocess.run([str(DASH), str(built / "dist" / "envscan.sh"), "--out", msys_path(out), "--only", probes, *extra],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
                          env={**os.environ, **env}, stdin=subprocess.DEVNULL, cwd=out)
    assert proc.returncode in (0, 1), proc.stderr[-3000:]
    folder = find_output(out)
    return {"report": load_report(folder), "folder": folder, "log": log.read_text().splitlines() if log.exists() else [],
            "proc": proc}


@pytest.fixture(scope="module")
def zos(built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return scan(built, tmp_path_factory.mktemp("zos"), "zos", ZOS_PROBES)


@pytest.fixture(scope="module")
def os400(built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return scan(built, tmp_path_factory.mktemp("os400"), "os400", OS400_PROBES, "--deep")


@pytest.fixture(scope="module")
def os400_default(built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return scan(built, tmp_path_factory.mktemp("os400-default"), "os400", OS400_PROBES)


def probe(run: dict[str, Any], pid: str) -> dict[str, Any]:
    return run["report"]["probes"][pid]


# ------------------------------------------------------------------ z/OS

def test_zos_report_is_valid_and_names_the_system(zos: dict[str, Any]) -> None:
    report = zos["report"]
    assert schema_errors(report) == []
    assert report["host"]["os_family"] == "zos"
    assert report["host"]["arch"] == "s390x"
    assert report["host"]["os_name"] == "z/OS 2.5"
    assert report["host"]["os_version"] == "2.5"
    assert report["host"]["hostname"] == "ZOS1"


def test_zos_identity_keeps_uname_ia_raw(zos: dict[str, Any]) -> None:
    entry = probe(zos, "os.identity")
    assert entry["status"] == "ok", entry.get("notes")
    assert entry["data"]["distro_id"] == "zos"
    assert entry["data"]["machine"] == "8561"
    assert "z/OS ZOS1 05.00 02 8561" in entry["raw"]["uname_Ia"]
    assert "uname -Ia" in zos["log"]


def test_zos_cpu_is_named_from_the_machine_type(zos: dict[str, Any]) -> None:
    data = probe(zos, "hw.cpu")["data"]
    assert data["model"] == "IBM Z (machine type 8561)" and data["vendor"] == "IBM"


def test_zos_df_runs_only_on_known_local_mount_points(zos: dict[str, Any]) -> None:
    df_calls = [line for line in zos["log"] if line.startswith("df ")]
    assert df_calls, "df was not run"
    queried = {m for line in df_calls for m in line.split()[1:] if m.startswith("/")}
    assert queried == {"/", "/u"}, df_calls
    assert all(sorted(line.split()[1:3]) == ["-P", "-k"] for line in df_calls), df_calls
    assert "-l" not in " ".join(df_calls).split() and not any(line == "df" for line in df_calls)
    volumes = {v["mount"]: v for v in probe(zos, "hw.storage")["data"]["volumes"]}
    assert set(volumes) == {"/", "/u"}
    assert volumes["/"]["fstype"] == "zfs" and volumes["/"]["total_mb"] == 4000 and volumes["/"]["network"] is False


def test_zos_network_and_unknown_file_systems_are_never_queried(zos: dict[str, Any]) -> None:
    text = "\n".join(zos["log"])
    assert "/nfs/proj" not in text and "/home" not in text and "/mystery" not in text
    notes = " ".join(probe(zos, "hw.storage")["notes"])
    assert "never queried" in notes


def test_zos_mount_table_marks_nfs_and_automount_as_network(zos: dict[str, Any]) -> None:
    mounts = {m["mount"]: m for m in probe(zos, "fs.mounts")["data"]["mounts"]}
    assert mounts["/nfs/proj"]["fstype"] == "nfs" and mounts["/home"]["fstype"] == "automnt"
    assert mounts["/mystery"]["fstype"] == "unknown"


def test_zos_kernel_limits_are_not_applicable_with_a_reason(zos: dict[str, Any]) -> None:
    entry = probe(zos, "limits.kernel")
    assert entry["status"] == "not_applicable"
    assert "BPXPRMxx" in " ".join(entry["notes"])


def test_zos_user_is_not_reported_absent_from_etc_passwd(zos: dict[str, Any]) -> None:
    data = probe(zos, "user.identity")["data"]
    assert data["name"] == "USER1" and data["uid"] == 1234
    assert data.get("passwd_entry") is not False
    assert "RACF" in " ".join(probe(zos, "user.identity")["notes"])


def test_zos_java_is_found_under_usr_lpp_java(zos: dict[str, Any]) -> None:
    jdks = probe(zos, "runtime.java")["data"]["jdks"]
    assert any(j["path"].endswith("/usr/lpp/java/J8.0_64") and j["version"] == "1.8.0_391" and j["arch"] == "s390x"
               for j in jdks), jdks


def test_zos_services_are_not_applicable(zos: dict[str, Any]) -> None:
    assert probe(zos, "svc.list")["status"] == "not_applicable"


def test_zos_interfaces_keep_home_addresses_raw_and_say_not_parsed(zos: dict[str, Any]) -> None:
    entry = probe(zos, "net.interfaces")
    assert entry["status"] == "partial"
    assert "10.30.1.9" in entry["raw"]["onetstat_h"]
    assert "not parsed" in " ".join(entry["notes"])


def test_zos_certificate_stores_are_named_as_not_read(zos: dict[str, Any]) -> None:
    assert "RACF" in " ".join(probe(zos, "tls.trust")["notes"])


def test_zos_scan_runs_only_known_commands(zos: dict[str, Any]) -> None:
    ran = {line.split()[0] for line in zos["log"]}
    assert ran <= {"uname", "mount", "df", "onetstat"}, ran


def test_zos_outputs_are_plain_text_without_conversion_on_an_ascii_host(zos: dict[str, Any]) -> None:
    # the dev box is ASCII: es_ebcdic_convert must not run (no iconv, no chtag messages)
    assert "iconv" not in zos["proc"].stderr and "chtag" not in zos["proc"].stderr
    zos["folder"].joinpath("envscan.json").read_bytes().decode("ascii")


# ------------------------------------------------------------------ IBM i

def test_os400_report_is_valid_and_names_the_system(os400: dict[str, Any]) -> None:
    report = os400["report"]
    assert schema_errors(report) == []
    assert report["host"]["os_family"] == "os400"
    assert report["host"]["arch"] == "ppc64"
    assert report["host"]["os_name"] == "IBM i 7.5"
    assert report["host"]["os_version"] == "7.5"
    assert probe(os400, "os.identity")["data"]["distro_id"] == "ibmi"


def test_os400_deep_tier_reads_only_display_system_values(os400: dict[str, Any]) -> None:
    calls = [line for line in os400["log"] if not line.split()[0] in ("uname", "mount", "df")]
    assert calls == [f"DSPSYSVAL SYSVAL({n})" for n in ("QSECURITY", "QCCSID", "QTIMZON", "QLANGID")]
    entry = probe(os400, "user.privileges")
    assert entry["data"]["ibmi_system_values"] == ["QSECURITY", "QCCSID", "QTIMZON", "QLANGID"]
    assert "QN0900UTC1" in entry["raw"]["ibmi_system_values"]


def test_os400_default_tier_runs_no_system_command(os400_default: dict[str, Any]) -> None:
    assert not any(line.startswith("DSPSYSVAL") for line in os400_default["log"])
    assert probe(os400_default, "user.privileges")["status"] == "skipped"


def test_os400_qntc_mount_is_network(os400: dict[str, Any]) -> None:
    mounts = {m["mount"]: m for m in probe(os400, "fs.mounts")["data"]["mounts"]}
    assert mounts["/QNTC/ntshost"]["device"] == "ntshost:/share" and mounts["/QNTC/ntshost"]["fstype"] == "nfs3"
    storage = {v["mount"] for v in probe(os400, "hw.storage")["data"]["volumes"]}
    assert "/QNTC/ntshost" not in storage
    assert not any("/QNTC" in line for line in os400["log"] if line.startswith("df "))


def test_os400_java_is_found_in_the_ibm_i_javavm_directory(os400: dict[str, Any]) -> None:
    jdks = probe(os400, "runtime.java")["data"]["jdks"]
    assert any(j["path"].endswith("/QOpenSys/QIBM/ProdData/JavaVM/jdk80/64bit") and j["version"] == "1.8.0_381"
               for j in jdks), jdks


def test_os400_services_are_not_applicable_and_kernel_limits_say_why(os400: dict[str, Any]) -> None:
    assert probe(os400, "svc.list")["status"] == "not_applicable"
    assert "PASE" in " ".join(probe(os400, "limits.kernel")["notes"])


def test_os400_user_is_not_reported_absent_from_etc_passwd(os400: dict[str, Any]) -> None:
    assert probe(os400, "user.identity")["data"].get("passwd_entry") is not False


# ------------------------------------------------------------------ network roots (library level)

@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def sh(lib: Path, script: str, *args: str, env: dict[str, str] | None = None) -> str:
    proc = run_lib(lib, script, *args, env=env)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.mark.parametrize("path,network", [
    ("/QNTC", True), ("/QNTC/server/share/file", True), ("/QFileSvr.400/ibmi2/home/x", True),
    ("/QFileSvr.400", True), ("/QOpenSys/pkgs/bin", False), ("/QNTCX/file", False), ("/home/qntc", False),
])
def test_os400_qntc_and_qfilesvr_are_network_paths(lib: Path, tmp_path: Path, path: str, network: bool) -> None:
    script = (f'ES_TMP="$1"; : >"$ES_TMP/mounts.tsv"; ES_OS=os400; es_netmnts_init\n'
              f'if es_on_netfs "{path}"; then printf net; else printf local; fi\n')
    assert sh(lib, script, msys_path(tmp_path)) == ("net" if network else "local")


def test_other_systems_do_not_treat_qntc_as_network(lib: Path, tmp_path: Path) -> None:
    script = 'ES_TMP="$1"; : >"$ES_TMP/mounts.tsv"; ES_OS=aix; es_netmnts_init; es_on_netfs /QNTC/x && printf net || printf local'
    assert sh(lib, script, msys_path(tmp_path)) == "local"


def test_os400_path_entries_in_qntc_are_never_searched(lib: Path, tmp_path: Path) -> None:
    script = ('ES_TMP="$1"; : >"$ES_TMP/mounts.tsv"; ES_OS=os400; es_netmnts_init\n'
              'PATH="/QNTC/srv/bin:/QFileSvr.400/h/bin:/usr/bin"; es_path_init\n'
              'printf "%s" "$ES_PATH_SKIP"\n')
    assert sh(lib, script, msys_path(tmp_path)).split() == ["/QNTC/srv/bin", "/QFileSvr.400/h/bin"]


@pytest.mark.parametrize("fstype", ["nfs", "nfs3", "nfs4", "automnt", "dfs", "qntc", "qfilesvr.400"])
def test_zos_and_ibm_i_network_file_system_types(lib: Path, tmp_path: Path, fstype: str) -> None:
    (tmp_path / "mounts.tsv").write_text(f"NET.FS\t/mnt/net\t{fstype}\t\nLOCAL\t/u\tzfs\t\n", encoding="ascii")
    script = 'ES_TMP="$1"; ES_OS=zos; es_netmnts_init; printf "%s" "$ES_NETMNTS"'
    assert sh(lib, script, msys_path(tmp_path)).split() == ["/mnt/net"]


def test_zfs_hfs_and_tfs_are_local(lib: Path, tmp_path: Path) -> None:
    (tmp_path / "mounts.tsv").write_text("A\t/a\tzfs\t\nB\t/b\thfs\t\nC\t/c\ttfs\t\n", encoding="ascii")
    script = 'ES_TMP="$1"; ES_OS=zos; es_netmnts_init; printf "%s" "$ES_NETMNTS"'
    assert sh(lib, script, msys_path(tmp_path)) == ""


# ------------------------------------------------------------------ stubs are well-formed

@pytest.mark.unit
@pytest.mark.parametrize("system", ["zos", "os400"])
def test_stubs_and_fixtures_are_plain_text_with_lf(system: str) -> None:
    for root in (STUBS / system, FIXTURES / system):
        for path in root.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                assert b"\r" not in data, path
                data.decode("ascii")
    assert os.path.isdir(FIXTURES / system / "etc")


# ------------------------------------------------------------------ fix round: identity, env, mounts

def test_zos_never_runs_uname_p_and_uses_uname_i(zos: dict[str, Any]) -> None:
    assert not any(line.startswith("uname -p") for line in zos["log"])
    assert "uname -Ia" in zos["log"]
    # plain uname -r/-v are the OS/390-compatible "12.00 03", never the version shown
    assert zos["report"]["host"]["os_version"] == "2.5"


def test_zos_without_uname_i_falls_back_with_a_note(built: Path, tmp_path: Path) -> None:
    run = scan(built, tmp_path, "zos", "os.identity", more_env={"ES_STUB_NO_I": "1"})
    entry = probe(run, "os.identity")
    assert entry["status"] == "partial"
    assert any("uname -I" in n for n in entry["notes"]), entry["notes"]
    assert entry["data"]["name"].startswith("z/OS") and "2.5" not in entry["data"]["name"]
    assert not any(line.startswith("uname -p") for line in run["log"])


def test_zos_env_vars_show_the_original_code_page_settings(built: Path, tmp_path: Path) -> None:
    run = scan(built, tmp_path, "zos", "env.vars,os.identity",
               more_env={"_CEE_RUNOPTS": "XPLINK(ON)", "_BPXK_AUTOCVT": "OFF"})
    env = probe(run, "env.vars")
    assert env["data"]["process"]["_CEE_RUNOPTS"] == "XPLINK(ON)"
    assert env["data"]["process"]["_BPXK_AUTOCVT"] == "OFF"
    assert any("_CEE_RUNOPTS" in n and "_BPXK_AUTOCVT" in n for n in env["notes"]), env["notes"]


def test_zos_env_vars_omit_settings_the_user_never_had(zos_env_unset: dict[str, Any]) -> None:
    process = probe(zos_env_unset, "env.vars")["data"]["process"]
    assert "_CEE_RUNOPTS" not in process and "_BPXK_AUTOCVT" not in process


@pytest.fixture(scope="module")
def zos_env_unset(built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return scan(built, tmp_path_factory.mktemp("zos-env"), "zos", "env.vars")


@pytest.mark.parametrize("os_name,fstype,network", [
    ("zos", "unknown", True), ("zos", "nfs3", True), ("zos", "nfs", True), ("zos", "zfs", False),
    ("zos", "hfs", False), ("zos", "tfs", False), ("zos", "somefs", True),
    ("os400", "unknown", True), ("os400", "nfs3", True), ("os400", "udfs", False), ("os400", "qsys", False),
    ("os400", "root", False), ("os400", "somefs", True),
    ("linux", "somefs", False), ("aix", "jfs2", False),
])
def test_zos_and_ibm_i_mounts_are_network_unless_known_local(lib: Path, tmp_path: Path, os_name: str, fstype: str,
                                                            network: bool) -> None:
    (tmp_path / "mounts.tsv").write_text(f"DEV\t/mnt/x\t{fstype}\t\n", encoding="ascii")
    script = f'ES_TMP="$1"; ES_OS={os_name}; es_netmnts_init; printf "%s" "$ES_NETMNTS"'
    assert ("/mnt/x" in sh(lib, script, msys_path(tmp_path)).split()) is network


def test_early_netmnts_always_include_the_ibm_i_network_roots(lib: Path, tmp_path: Path) -> None:
    stubs = tmp_path / "s"
    stubs.mkdir()
    (stubs / "uname").write_text("#!/bin/sh\nprintf 'OS400\\n'\n", encoding="ascii", newline="\n")
    script = 'PATH="$1:/usr/bin"; ES_ROOT=/nonexistent; unset ES_OS; es_netmnts_early; printf "%s" "$ES_NETMNTS"'
    assert sh(lib, script, msys_path(stubs)).split() == ["/QNTC", "/QFileSvr.400"]


def test_early_netmnts_do_not_add_them_elsewhere(lib: Path, tmp_path: Path) -> None:
    stubs = tmp_path / "s"
    stubs.mkdir()
    (stubs / "uname").write_text("#!/bin/sh\nprintf 'Linux\\n'\n", encoding="ascii", newline="\n")
    script = 'PATH="$1:/usr/bin"; ES_ROOT=/nonexistent; unset ES_OS; es_netmnts_early; printf "%s" "$ES_NETMNTS"'
    assert sh(lib, script, msys_path(stubs)) == ""


def test_os400_df_fallback_never_queries_network_mounts(built: Path, tmp_path: Path) -> None:
    run = scan(built, tmp_path, "os400", "hw.storage", more_env={"ES_STUB_DF_NO_L": "1"})
    df_calls = [line for line in run["log"] if line.startswith("df ")]
    assert any("-l" in line.split() for line in df_calls), df_calls  # the -l attempt failed
    assert not any("/QNTC" in line for line in df_calls), df_calls


def test_zos_empty_mount_table_makes_fs_mounts_partial_with_a_note(built: Path, tmp_path: Path) -> None:
    run = scan(built, tmp_path, "zos", "fs.mounts", more_env={"ES_STUB_NO_MOUNT": "1"})
    entry = probe(run, "fs.mounts")
    assert entry["status"] == "partial"
    assert any("network" in n for n in entry["notes"]), entry["notes"]
