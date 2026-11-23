"""Links in the envscan.ps1 library. A file the scanner reads (a configuration file, the hosts
file, a Java release file, a package manifest) or a folder it lists (a configs entry in list
mode, a dependency cache) that is a symbolic link or junction is read only when the link ends on
a local path that is no credential store. Otherwise nothing behind it is touched, the probe notes
"<path> not read: <reason>" and is partial. PowerShell before 5 cannot read a link's target, so
there every reparse point that is not a cloud placeholder counts as a link to an unknown target.

One PowerShell process per language mode evaluates tests/ps/link_cases.ps1. Creating a symbolic
link needs a privilege a standard user lacks, so Get-Item returns fake link items there; a real
junction covers a real reparse point.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import ps_command, ps_quote, requires_powershell

pytestmark = [pytest.mark.integration, requires_powershell]

CASES = Path(__file__).resolve().parent / "ps" / "link_cases.ps1"
MODES = ("FullLanguage", "ConstrainedLanguage")
NETWORK = "link to a network path"
CREDENTIAL = "link to a credential store"
UNKNOWN = "link target unknown"
# Text a touched path must never hold: the network share, the mapped network drive, the stores.
FORBIDDEN = ("\\\\srv", "Z:\\", ".ssh", ".aws")


@pytest.fixture(scope="module", params=MODES)
def results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    mode = request.param
    scratch = tmp_path_factory.mktemp(f"pslinks-{mode}")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if mode != "FullLanguage" else ""
    proc = ps_command(f"{prefix}& {ps_quote(CASES)} -Lib {ps_quote(lib)} -Scratch {ps_quote(scratch)}",
                      timeout=300, cwd=scratch)
    assert proc.returncode == 0, proc.stderr
    assert not proc.stderr.strip(), proc.stderr
    data = json.loads(proc.stdout)
    assert data["language_mode"] == mode
    return data


def case(results: dict[str, Any], name: str) -> Any:
    value = results[name]
    if isinstance(value, dict) and "case_error" in value:
        pytest.fail(f"case {name} failed: {value['case_error']}")
    return value


def assert_untouched(touched: list[str], *paths: str) -> None:
    """Nothing behind a refused link is opened or listed, and nothing on the network is named."""
    for path in paths:
        assert f"read|{path}" not in touched and f"list|{path}" not in touched, (path, touched)
    assert not [t for t in touched if any(f.lower() in t.lower() for f in FORBIDDEN)], touched


def own(touched: list[str], path: str) -> list[str]:
    """The touches of PATH itself."""
    return [t for t in touched if t.split("|", 1)[1].lower() == path.lower()]


def below(touched: list[str], folder: str) -> list[str]:
    """The touches of paths below FOLDER (Windows would follow a link at FOLDER for them)."""
    prefix = folder.lower() + "\\"
    return [t for t in touched if t.split("|", 1)[1].lower().startswith(prefix)]


def assert_only_folders_above(touched: list[str], path: str) -> None:
    """Every touch that is not of PATH itself looks at a folder above it (Get-Item, no more)."""
    for touch in touched:
        kind, target = touch.split("|", 1)
        if target.lower() != path.lower():
            assert kind == "item" and path.lower().startswith(target.lower() + "\\"), (touch, path)


@pytest.mark.parametrize("name,reason", [
    ("unc", NETWORK), ("unc_device", NETWORK), ("unc_long", NETWORK), ("mapped", NETWORK), ("chain", NETWORK),
    ("hop", NETWORK), ("cred", CREDENTIAL), ("relative_cred", CREDENTIAL), ("volume", UNKNOWN),
    ("root_relative", UNKNOWN), ("no_target", UNKNOWN), ("loop", UNKNOWN),
])
def test_links_that_leave_the_local_disk_are_not_read(results: dict[str, Any], name: str, reason: str) -> None:
    read = case(results, "reads")[name]
    assert (read["error"], read["text"]) == (reason, None)
    assert_untouched(read["touched"], read["path"])


@pytest.mark.parametrize("name", ["local", "relative"])
def test_links_to_a_local_file_are_read(results: dict[str, Any], name: str) -> None:
    reads = case(results, "reads")
    read = reads[name]
    assert (read["error"], read["text"]) == (None, f"proxy=http://{name}.corp:8080")
    # The target is looked at (is it a link too?) before the file is read through the link.
    assert f"item|{reads['target_path']}" in read["touched"]
    assert read["touched"][-1] == f"read|{read['path']}"


def test_plain_files_and_other_reparse_points_are_read(results: dict[str, Any]) -> None:
    reads = case(results, "reads")
    plain_path = reads["plain_path"]
    assert reads["plain"]["error"] is None and reads["plain"]["text"] == "proxy=http://plain.corp:8080"
    assert own(reads["plain"]["touched"], plain_path) == [f"item|{plain_path}", f"read|{plain_path}"]
    assert_only_folders_above(reads["plain"]["touched"], plain_path)
    # A reparse point that is no link (a cloud file that is on disk, a deduplicated file).
    assert reads["other_reparse"]["error"] is None
    assert reads["placeholder"]["error"] == "cloud placeholder (not downloaded)"


def test_powershell_before_5_reads_no_reparse_point(results: dict[str, Any]) -> None:
    reads = case(results, "reads_ps4")
    for name in ("local", "other_reparse"):
        assert reads[name]["error"] == UNKNOWN, name
        assert [t for t in reads[name]["touched"] if not t.startswith("item|")] == [], reads[name]["touched"]
        # The link itself and the folders above it; never its target.
        assert len(own(reads[name]["touched"], reads[name]["path"])) == 1, reads[name]["touched"]
        assert_only_folders_above(reads[name]["touched"], reads[name]["path"])
    assert reads["plain"]["error"] is None and reads["plain"]["text"] == "proxy=http://plain.corp:8080"


def test_git_include_links_give_include_reasons(results: dict[str, Any]) -> None:
    # "git include not read (<reason>): <path>" keeps its reasons for a link.
    assert case(results, "git_includes") == {"plain": None, "unc": "network path", "chain": "network path",
                                              "cred": "credential store", "volume": "not a local path", "local": None,
                                              "below_cred": "credential store", "below_cred_touched": [],
                                              "below_unc": "network path", "below_unc_touched": []}


def test_config_entries_note_links_they_do_not_read(results: dict[str, Any]) -> None:
    configs = case(results, "configs")
    unc, plain, list_dir = configs["unc"], configs["plain"], configs["list_dir"]
    assert configs["status"] == "partial"
    assert configs["notes"] == [f"{unc} not read: {NETWORK}", f"{list_dir} not read: {NETWORK}"]
    entries = {e["path"]: e for e in configs["entries"]}
    assert (entries[unc]["error"], entries[unc]["lines"]) == (NETWORK, [])
    assert (entries[plain]["error"], entries[plain]["lines"]) == (None, ["proxy=http://plain.corp:8080"])
    assert (entries[list_dir]["error"], entries[list_dir]["lines"]) == (NETWORK, [])
    assert_untouched(configs["touched"], unc, list_dir)


def test_caches_behind_links_are_not_listed(results: dict[str, Any]) -> None:
    caches = case(results, "caches")
    net, junction = caches["net"], caches["junction"]
    assert caches["status"] == "partial"
    assert caches["notes"] == [f"{net} not read: {NETWORK}"]
    # A real junction to a local folder is listed (its target is read from the junction).
    assert caches["caches"] == [{"id": "junction", "path": junction, "entries": 2}]
    assert f"list|{junction}" in caches["touched"]
    assert_untouched(caches["touched"], net)


def test_caches_behind_reparse_points_are_not_listed_before_powershell_5(results: dict[str, Any]) -> None:
    caches = case(results, "caches")
    assert caches["old_notes"] == [f"{caches['net']} not read: {UNKNOWN}", f"{caches['junction']} not read: {UNKNOWN}"]
    # Not "not_found": the caches exist, they were not listed.
    assert (caches["old_status"], caches["old_caches"]) == ("partial", [])


def test_java_release_behind_a_link_is_not_read(results: dict[str, Any]) -> None:
    java = case(results, "java")
    assert java["status"] == "partial"
    assert java["notes"] == [f"{java['release']} not read: {NETWORK}"]
    assert (java["net_version"], java["ok_version"]) == (None, "17.0.9")
    assert_untouched(java["touched"], java["release"])


def test_package_manifest_behind_a_link_is_not_read(results: dict[str, Any]) -> None:
    manifests = case(results, "manifests")
    assert manifests["status"] == "partial"
    assert manifests["notes"] == [f"{manifests['manifest']} not read: {NETWORK}"]
    versions = {p["name"]: p["version"] for p in manifests["packages"]}
    assert versions == {"netapp": None, "okapp": "1.2.3"}
    assert_untouched(manifests["touched"], manifests["manifest"])


def test_keytool_never_opens_a_cacerts_behind_a_link(results: dict[str, Any]) -> None:
    cacerts = case(results, "cacerts")
    assert cacerts["status"] == "partial"
    assert cacerts["notes"] == [f"{cacerts['cacerts']} not read: {NETWORK}"]
    assert [s for s in cacerts["sources"] if s.startswith("run ")] == []
    assert_untouched(cacerts["touched"], cacerts["cacerts"])


def test_hosts_file_behind_a_link_is_not_read(results: dict[str, Any]) -> None:
    hosts = case(results, "hosts")
    assert hosts["status"] == "partial"
    assert hosts["notes"] == [f"{hosts['path']} not read: {NETWORK}"]
    assert hosts["entries"] == []
    assert_untouched(hosts["touched"], hosts["path"])


# ------------------------------------------------------------------ folders above a path

def test_files_below_a_folder_link_to_the_network_are_not_read(results: dict[str, Any]) -> None:
    # Second review 2026-11-11: Windows follows a folder link for every path below it, so the
    # folders above a file are checked (from the volume root down) before the file is looked at.
    reads = case(results, "folder_reads")
    net_dir = reads["net_dir"]
    assert (reads["in_net"]["error"], reads["in_net"]["text"]) == (NETWORK, None)
    assert f"item|{net_dir}" in reads["in_net"]["touched"]
    assert below(reads["in_net"]["touched"], net_dir) == []
    assert reads["in_ok"] == {"error": None, "text": "proxy=http://inok.corp:8080"}
    # A link to a local file below a folder link to the network: the target is not looked at.
    assert reads["hop"]["error"] == NETWORK
    assert below(reads["hop"]["touched"], net_dir) == []


def test_patterns_below_a_folder_link_are_not_tested_or_listed(results: dict[str, Any]) -> None:
    patterns = case(results, "folder_patterns")
    net_dir = patterns["net_dir"]
    assert (patterns["literal"], patterns["glob"], patterns["star_folder"]) == ([], [], [])
    assert patterns["ok"] == [patterns["ok_file"]]
    assert (patterns["status"], patterns["notes"]) == ("partial", [f"{net_dir} not read: {NETWORK}"])
    assert f"list|{net_dir}" not in patterns["touched"]
    assert below(patterns["touched"], net_dir) == []


def test_programs_below_or_behind_a_link_are_not_tested_or_run(results: dict[str, Any]) -> None:
    tools = case(results, "folder_tools")
    assert tools["dirs"] == [tools["ok_dir"]]
    assert tools["found"] == [tools["tool"]]
    assert tools["reason"] == f"{NETWORK}; not run"
    assert tools["run"] == f"not run: {NETWORK}"
    assert tools["arch"] is None
    assert f"read|{tools['tool']}" not in tools["touched"]
    assert f"read|{tools['ok_tool']}" in tools["touched"]
    assert below(tools["touched"], tools["net_dir"]) == []
    assert_untouched(tools["touched"], tools["tool"])


def test_package_roots_and_folders_behind_links_are_not_listed(results: dict[str, Any]) -> None:
    packages = case(results, "folder_packages")
    net_dir, net_app = packages["net_dir"], packages["net_app"]
    assert packages["status"] == "partial"
    assert packages["notes"] == [f"{net_dir} not read: {NETWORK}", f"{net_app} not read: {NETWORK}"]
    assert packages["packages"] == [{"name": "netapp", "version": None, "source": "scoop"},
                                    {"name": "okapp", "version": "1.2.3", "source": "scoop"}]
    assert f"list|{net_dir}" not in packages["touched"]
    assert below(packages["touched"], net_dir) == [] and below(packages["touched"], net_app) == []


@pytest.mark.parametrize("name, path, reason", [
    ("unc", "\\\\srv\\share\\tools\\x.exe", "network path"),
    ("mapped", "Z:\\tools\\x.exe", "network path"),
    ("device", "\\\\?\\C:\\tools\\x.exe", "not a local path"),
    ("relative", "tools\\x.exe", "not a local path"),
    ("rooted", "\\tools\\x.exe", "not a local path"),
    ("drive_relative", "C:tools\\x.exe", "not a local path"),
])
def test_link_guards_refuse_paths_that_are_not_local_untouched(results: dict[str, Any], name: str, path: str,
                                                             reason: str) -> None:
    got = case(results, "nonlocal_guards")[name]
    assert got["touched"] == []
    assert (got["link"], got["cached"], got["safe"], got["listable"]) == (reason, reason, False, False)
    assert got["read"] == reason and got["run"] == f"not run: {reason}"
    assert got["notes"] == [f"{path} not read: {reason}"]


def test_a_bare_drive_is_local(results: dict[str, Any]) -> None:
    got = case(results, "nonlocal_guards")
    assert got["drive"] is None and got["drive_notes"] == []
    assert any(p.lower().endswith("\\windows") for p in got["drive_glob"]), got["drive_glob"]
