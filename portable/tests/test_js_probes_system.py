"""The system probes of the Windows Script Host port (src/js/26-probes-*.js).

Each probe runs on this machine through the JScript runner and is compared with the
PowerShell result of the same probe (dist/envscan.ps1 --only <ids>), both started from the
same working directory. fs.exec_test (deep) runs on a fake fs.locations result that points at
a private folder only, and must leave nothing behind.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import HAVE_POWERSHELL, find_output, load_report, ps_eval, ps_quote, requires_powershell, run_ps, scrubbed_env
from js_harness import HAVE_CSCRIPT, build_js, run_script
from test_js_probes_network import JS_RUN_PROBES, js_json, js_prelude

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not HAVE_CSCRIPT, reason="needs cscript.exe (Windows)")]

SYS_IDS = ("fs.locations", "fs.semantics", "proc.list", "svc.list", "sched.tasks")
WRITE_TEST_IDS = ("temp", "local_appdata", "local_programs", "appdata", "home", "programdata", "cwd")
ACL_IDS = ("system_drive_root", "program_files")


@pytest.fixture(scope="module")
def lib(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_js(tmp_path_factory.mktemp("jssys"))[1]


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("syscwd")


@pytest.fixture(scope="module")
def js_sys(lib: Path, workdir: Path) -> dict[str, Any]:
    # run_js has no working directory: the same script it would write, started from workdir.
    script = lib.parent / "snippet-sys-probes.js"
    body = lib.read_text(encoding="ascii") + "\r\n" + (js_prelude() + JS_RUN_PROBES).replace("\n", "\r\n")
    script.write_bytes(body.encode("ascii"))
    try:
        proc = run_script(script, ",".join(SYS_IDS), env=scrubbed_env(), cwd=workdir)
    finally:
        script.unlink(missing_ok=True)
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def ps_sys(built: Path, workdir: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    if not HAVE_POWERSHELL:
        pytest.skip("needs Windows PowerShell")
    out = tmp_path_factory.mktemp("pssys")
    proc = run_ps(built / "dist" / "envscan.ps1", ["--only", ",".join(SYS_IDS), "--out", str(out)], cwd=workdir)
    assert proc.returncode in (0, 1), proc.stderr
    return load_report(find_output(out))["probes"]


def locations(result: dict[str, Any]) -> dict[str, Any]:
    return {entry["id"]: entry for entry in result["fs.locations"]["data"]["locations"]}


# ------------------------------------------------------------------ this machine, compared with ps

@pytest.mark.parametrize("probe_id", ("fs.semantics", "proc.list", "svc.list"))
def test_status_equals_ps(js_sys: dict[str, Any], ps_sys: dict[str, Any], probe_id: str) -> None:
    assert js_sys[probe_id]["status"] == ps_sys[probe_id]["status"], (js_sys[probe_id], ps_sys[probe_id]["notes"])


@pytest.mark.parametrize("probe_id", SYS_IDS)
def test_data_keys_equal_ps(js_sys: dict[str, Any], ps_sys: dict[str, Any], probe_id: str) -> None:
    assert set(js_sys[probe_id]["data"]) == set(ps_sys[probe_id]["data"])


def test_locations_equal_ps_where_a_test_file_decides(js_sys: dict[str, Any], ps_sys: dict[str, Any]) -> None:
    js, ps = locations(js_sys), locations(ps_sys)
    assert list(js) == list(ps)
    for key, entry in ps.items():
        if key == "script_dir":
            continue  # the two scripts live in different folders
        mine = js[key]
        for field in ("path", "exists", "network", "onedrive", "method", "free_mb", "fstype", "noexec"):
            assert mine[field] == entry[field], (key, field, mine, entry)
        if entry["method"] == "write-test":
            assert mine["writable"] == entry["writable"], (key, mine, entry)
            assert set(mine) == set(entry), key


def test_locations_without_acl_are_unknown_and_noted(js_sys: dict[str, Any]) -> None:
    got = js_sys["fs.locations"]
    acl = [entry for entry in got["data"]["locations"] if entry["method"] == "acl" and entry["exists"]]
    assert acl, got
    for entry in acl:
        assert entry["writable"] is None and entry["can_create_dirs"] is None, entry
    assert got["status"] == "partial"
    assert any("directory ACLs cannot be read in the WSH port" in note for note in got["notes"]), got["notes"]
    assert "system_drive_root" not in got["data"]["writable_install_locations"]


def test_locations_never_write_to_personal_folders(js_sys: dict[str, Any]) -> None:
    for entry in js_sys["fs.locations"]["data"]["locations"]:
        if entry.get("write_test_skipped"):
            assert entry["method"] == "acl" and entry["writable"] is None, entry
    for source in js_sys["fs.locations"]["sources"]:
        lowered = source.lower()
        assert not (lowered.startswith("write") and ("\\desktop" in lowered or "\\documents" in lowered or "onedrive" in lowered))


def test_semantics_equal_ps(js_sys: dict[str, Any], ps_sys: dict[str, Any]) -> None:
    js, ps = js_sys["fs.semantics"]["data"], ps_sys["fs.semantics"]["data"]
    for key in ("case_sensitive", "hardlink", "junction", "symlink", "long_paths_enabled", "short_names", "name_max",
                "path_max", "temp_fstype"):
        assert js[key] == ps[key], key


def test_processes_match_ps(js_sys: dict[str, Any], ps_sys: dict[str, Any]) -> None:
    js, ps = js_sys["proc.list"]["data"], ps_sys["proc.list"]["data"]
    assert abs(js["count"] - ps["count"]) <= max(30, ps["count"] // 5)
    pids = [p["pid"] for p in js["processes"]]
    assert pids == sorted(pids)
    names = {p["name"] for p in ps["processes"]}
    assert len({p["name"] for p in js["processes"]} & names) >= 0.8 * len(names)
    assert set(js["processes"][0]) == set(ps["processes"][0])


def test_services_equal_ps(js_sys: dict[str, Any], ps_sys: dict[str, Any]) -> None:
    js, ps = js_sys["svc.list"]["data"], ps_sys["svc.list"]["data"]
    assert js["count"] == ps["count"] and js["manager"] == ps["manager"] and js["truncated"] == ps["truncated"]
    by_name = {s["name"]: s for s in ps["services"]}
    assert {s["name"] for s in js["services"]} == set(by_name)
    for service in js["services"]:
        expected = dict(by_name[service["name"]])
        for volatile in ("state", "pid"):
            service = {k: v for k, v in service.items() if k != volatile}
            expected.pop(volatile)
        assert service == expected


def test_tasks_equal_ps(js_sys: dict[str, Any], ps_sys: dict[str, Any]) -> None:
    js, ps = js_sys["sched.tasks"]["data"], ps_sys["sched.tasks"]["data"]
    assert (js["count"], js["microsoft_task_count"]) == (ps["count"], ps["microsoft_task_count"])
    assert [(t["path"], t["name"]) for t in js["tasks"]] == [(t["path"], t["name"]) for t in ps["tasks"]]
    assert set(js["tasks"][0]) == set(ps["tasks"][0]) if ps["tasks"] else True


def test_tasks_mark_embedded_objects_unknown(js_sys: dict[str, Any], ps_sys: dict[str, Any]) -> None:
    # The WMI worker passes embedded objects (actions, principal) as null: unknown, partial.
    got = js_sys["sched.tasks"]
    unknown = [t for t in got["data"]["tasks"] if t["actions"] is None or t["principal"] is None]
    if unknown:
        assert got["status"] == "partial"
        assert any("not available in the WSH port (embedded WMI objects)" in n for n in got["notes"]), got["notes"]
    else:
        assert got["status"] == ps_sys["sched.tasks"]["status"]


# ------------------------------------------------------------------ fs.exec_test (deep), private folder only

EXEC_SNIPPET = """
jsTest_init();
var esOut = {};
try {
    jsTest_fake("fs.locations", "ok", { locations: [
        { id: "temp", path: WScript.Arguments.Item(0), writable: true, method: "write-test" },
        { id: "programdata", path: WScript.Arguments.Item(0), writable: true, method: "write-test" },
        { id: "home", path: WScript.Arguments.Item(0), writable: true, method: "acl" }] });
    esOut = probe_fs_exec_test();
} finally { jsTest_done(); }
WScript.Echo(convertToEsJson(esOut));
"""


def ps_exec_test(built: Path, folder: Path) -> dict[str, Any]:
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    # ps_eval starts PowerShell with a process-scope policy (PSExecutionPolicyPreference), which
    # its child powershell.exe would inherit; cscript has none, so drop it for a fair comparison.
    expression = (
        "Remove-Item Env:PSExecutionPolicyPreference -ErrorAction SilentlyContinue; Initialize-EsTemp; "
        "$script:ES_RESULTS = @{ 'fs.locations' = @{ status = 'ok'; notes = @(); data = @{ locations = @("
        f"@{{ id = 'temp'; path = {ps_quote(folder)}; writable = $true; method = 'write-test' }}) }} }} }}; "
        "try { $r = probe_fs_exec_test } finally { Remove-EsTemp }; ConvertTo-EsJson $r"
    )
    proc = ps_eval(lib, expression)
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    return json.loads(proc.stdout)


def test_exec_test_runs_only_in_per_user_write_tested_folders(lib: Path, tmp_path: Path) -> None:
    folder = tmp_path / "exec"
    folder.mkdir()
    got = js_json(lib, EXEC_SNIPPET, str(folder))
    assert got["status"] == "ok", got
    results = got["data"]["results"]
    assert [(r["id"], r["kind"]) for r in results] == [("temp", "cmd"), ("temp", "ps1")]
    assert results[0]["outcome"] == "ok" and results[0]["detail"] is None, results
    assert results[1]["outcome"] in ("ok", "blocked"), results
    for item in results:
        assert Path(item["path"]).parent == folder
    assert list(folder.iterdir()) == []


@requires_powershell
def test_exec_test_outcomes_equal_ps(lib: Path, built: Path, tmp_path: Path) -> None:
    js_folder, ps_folder = tmp_path / "js", tmp_path / "ps"
    js_folder.mkdir()
    ps_folder.mkdir()
    js = js_json(lib, EXEC_SNIPPET, str(js_folder))["data"]["results"]
    ps = ps_exec_test(built, ps_folder)["data"]["results"]
    assert [(r["kind"], r["outcome"]) for r in js] == [(r["kind"], r["outcome"]) for r in ps]
    assert list(js_folder.iterdir()) == [] and list(ps_folder.iterdir()) == []


def test_exec_test_needs_fs_locations(lib: Path) -> None:
    snippet = "jsTest_init(); var esR; try { esR = probe_fs_exec_test(); } finally { jsTest_done(); } WScript.Echo(convertToEsJson(esR));"
    got = js_json(lib, snippet)
    assert got["status"] == "error" and got["error"] == "depends on fs.locations, which is not run"


def test_exec_test_skips_cmd_metacharacters(lib: Path, tmp_path: Path) -> None:
    folder = tmp_path / "a&b"
    folder.mkdir()
    got = js_json(lib, EXEC_SNIPPET, str(folder))
    cmd = [r for r in got["data"]["results"] if r["kind"] == "cmd"]
    assert cmd and cmd[0]["outcome"] == "skipped" and cmd[0]["detail"] == "path contains cmd.exe metacharacters"
    assert list(folder.iterdir()) == []


# ------------------------------------------------------------------ helpers the engine's output folder uses

def test_personal_folders_and_under_folder(lib: Path) -> None:
    snippet = """
var esP = getEsPersonalFolders();
WScript.Echo(convertToEsJson({ personal: esP,
    under: testEsUnderFolder(esP.length ? esP[0].toUpperCase() + "\\\\x" : "C:\\\\none", esP),
    same: testEsUnderFolder(esP.length ? esP[0] + "\\\\" : "C:\\\\none", esP),
    sibling: testEsUnderFolder(esP.length ? esP[0] + "x\\\\y" : "C:\\\\none", esP),
    join: [joinEsPathSafe(null, "x"), joinEsPathSafe("C:\\\\a", "b")],
    dirs: getEsCandidateDirs().length }));
"""
    got = js_json(lib, "saveEsEnvSnapshot();" + snippet)
    personal = got["personal"]
    assert personal and all(p == p.lower() and not p.endswith("\\") for p in personal)
    assert any(p.endswith("\\desktop") for p in personal)
    assert (got["under"], got["same"], got["sibling"]) == (True, True, False)
    assert got["join"] == [None, "C:\\a\\b"] and got["dirs"] == 10


@requires_powershell
def test_personal_folders_equal_ps(lib: Path, built: Path) -> None:
    got = js_json(lib, "saveEsEnvSnapshot(); WScript.Echo(convertToEsJson(getEsPersonalFolders()));")
    lib_ps = built / "build" / "lib" / "envscan-lib.ps1"
    proc = ps_eval(lib_ps, "$script:ES_ENV_SNAPSHOT = @{}; foreach ($n in @('USERPROFILE','OneDrive','OneDriveCommercial','OneDriveConsumer')) "
                   "{ $v = [Environment]::GetEnvironmentVariable($n); if ($null -ne $v) { $script:ES_ENV_SNAPSHOT[$n] = $v } }; "
                   "ConvertTo-EsJson @(Get-EsPersonalFolders)")
    assert proc.returncode == 0, proc.stderr
    assert sorted(got) == sorted(json.loads(proc.stdout))
