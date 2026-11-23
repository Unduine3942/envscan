"""Review findings of 2026-11-11 in the envscan.ps1 library: paths, JSON and Markdown escaping,
absent data, PowerShell 2.0 branches, arguments, external commands, registry reads, git home,
process trees, --net targets and endpoint extraction.

One PowerShell process per language mode evaluates tests/ps/hardening_cases.ps1 and prints a
JSON object (case name -> result). A case that throws reports {"case_error": message} instead of
stopping the others. Cases that simulate PowerShell 2.0 run in FullLanguage only: PowerShell 2.0
has no ConstrainedLanguage mode.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from conftest import PORTABLE, ps_command, ps_quote, requires_powershell

pytestmark = [pytest.mark.integration, requires_powershell]

CASES = Path(__file__).resolve().parent / "ps" / "hardening_cases.ps1"
MODES = ("FullLanguage", "ConstrainedLanguage")
PS_SRC = PORTABLE / "src" / "ps"


@pytest.fixture(scope="module", params=MODES)
def results(request: pytest.FixtureRequest, built: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    mode = request.param
    scratch = tmp_path_factory.mktemp(f"pshard-{mode}")
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; " if mode != "FullLanguage" else ""
    command = f"{prefix}& {ps_quote(CASES)} -Lib {ps_quote(lib)} -Scratch {ps_quote(scratch)}"
    proc = ps_command(command, timeout=600, cwd=scratch)
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


def full_language_only(results: dict[str, Any]) -> None:
    if results["language_mode"] != "FullLanguage":
        pytest.skip("PowerShell 2.0 has no ConstrainedLanguage mode")


# ------------------------------------------------------------------ 1: spec paths are absolute and local

@pytest.mark.parametrize("kind", ["unix_absolute", "root_relative", "drive_relative", "relative", "unc", "mapped",
                                  "home_unset"])
def test_spec_paths_never_resolve_against_the_current_drive(results: dict[str, Any], kind: str) -> None:
    # Each pattern names a folder that exists relative to the current location (the scratch
    # folder), so only the absolute-path rule keeps it out.
    assert case(results, "paths")[kind] == []


def test_absolute_local_spec_paths_still_resolve(results: dict[str, Any]) -> None:
    paths = case(results, "paths")
    assert [Path(p).name for p in paths["local"]] == ["bin"]
    assert [Path(p).name for p in paths["local_glob"]] == ["bin"]


def test_tool_lookup_ignores_relative_spec_dirs(results: dict[str, Any]) -> None:
    assert case(results, "paths")["find_relative_tool"] == []


def test_write_test_and_acl_refuse_relative_paths(results: dict[str, Any]) -> None:
    guards = case(results, "paths")
    assert guards["writable_relative"] is None
    assert guards["sddl_relative"]["create_files"] is None


# ------------------------------------------------------------------ 2: JSON and Markdown with a trailing newline

def test_json_strings_ending_in_a_newline_stay_valid(results: dict[str, Any]) -> None:
    raw = case(results, "json_newline")
    data = json.loads(raw)
    assert data == {"s": "line\n", "crlf": "x\r\n", "arr": ["a\n", "b"], "key\n": "v", "plain": "ok"}


def test_markdown_values_ending_in_a_newline_stay_on_one_line(results: dict[str, Any]) -> None:
    md = case(results, "md_newline")
    for value in md.values():
        assert "\n" not in value and "\r" not in value, md


# ------------------------------------------------------------------ 4: absent data is never a finding

def test_no_app_control_finding_without_data(results: dict[str, Any]) -> None:
    absent = case(results, "absent")
    assert "exec.app_control" not in absent["finding_ids"]
    assert absent["weak_tls"] == ""


def test_app_control_finding_needs_enforced_entries(results: dict[str, Any]) -> None:
    present = case(results, "app_control_present")
    assert present["detail"] == "AppLocker (Exe)"
    assert "- Application control: AppLocker (Exe);" in present["brief"]


@pytest.mark.parametrize("claim", [
    "Application control: ;", "Application control: none", "workgroup", "container: no", "JAVA_HOME=unset",
    "cmd disabled by policy: no", "disabled (MAX_PATH 260)", "(long paths disabled)", "hosts file entries: 0",
    "0 added root CA(s)",
])
def test_brief_claims_nothing_about_probes_that_did_not_run(results: dict[str, Any], claim: str) -> None:
    assert claim not in case(results, "absent")["brief"]


@pytest.mark.parametrize("text", [
    "Application control: not fully checked", "domain membership unknown", "container: unknown",
    "JAVA_HOME=not checked", "cmd disabled by policy: unknown", "hosts file entries: not checked",
])
def test_brief_says_not_checked(results: dict[str, Any], text: str) -> None:
    assert text in case(results, "absent")["brief"]


# ------------------------------------------------------------------ 5: progress never on stdout

def test_progress_writer_never_uses_stdout(results: dict[str, Any]) -> None:
    # The harness runs with stdout redirected (a pipe): ConstrainedLanguage has no stderr route
    # and must not fall back to Write-Host, which writes to stdout.
    assert case(results, "progress_stdout") == []


# ------------------------------------------------------------------ 6: PowerShell 2.0 decodes OEM output

def test_ps2_reads_oem_output_like_ps3(results: dict[str, Any]) -> None:
    full_language_only(results)
    oem = case(results, "oem")
    assert oem["ps2"] == oem["ps3"] and oem["ps2"].startswith("caf") and oem["ps2"].endswith("\nx")


def test_ps2_never_passes_oem_to_get_content(results: dict[str, Any]) -> None:
    full_language_only(results)
    assert "Oem" not in case(results, "oem")["encodings"]


def test_get_content_never_gets_a_literal_oem_encoding() -> None:
    # The only Oem decoding goes through Read-EsCommandOutput, which branches on the version.
    for path in sorted(PS_SRC.glob("*.ps1")):
        for number, line in enumerate(path.read_text(encoding="ascii").splitlines(), start=1):
            if re.search(r"Get-Content\b", line, re.I):
                assert not re.search(r"-Encoding\s+'?Oem\b", line, re.I), f"{path.name}:{number}: {line.strip()}"


# ------------------------------------------------------------------ 7 and 17: arguments

@pytest.mark.parametrize("name, message", [
    ("net_false", "option --net takes no value"),
    ("deep_zero", "option --deep takes no value"),
    ("no_redact_false", "option --no-redact takes no value"),
    ("version_value", "option --version takes no value"),
    ("help_value", "option --help takes no value"),
    ("list_value", "option --list-probes takes no value"),
    ("h_value", "option --h takes no value"),
    ("only_bad_char", "--only: invalid pattern 'os.ident[ity' (allowed: letters, digits, . _ - *)"),
    ("only_no_match", "--only: pattern 'nosuch.*' matches no probe"),
    ("skip_bad", "--skip: invalid pattern 'bad?' (allowed: letters, digits, . _ - *)"),
    ("only_space", "--only: invalid pattern 'os identity' (allowed: letters, digits, . _ - *)"),
    # Second review 2026-11-11: an empty id list must not run (or skip) everything.
    ("only_empty", "--only needs probe ids"),
    ("only_comma", "--only needs probe ids"),
    ("only_blank_list", "--only needs probe ids"),
    ("skip_empty", "--skip needs probe ids"),
    ("skip_comma", "--skip needs probe ids"),
    ("skip_blank_list", "--skip needs probe ids"),
])
def test_argument_errors(results: dict[str, Any], name: str, message: str) -> None:
    assert case(results, "args")[name]["errors"] == [message]


def test_boolean_flags_with_a_value_change_nothing(results: dict[str, Any]) -> None:
    args = case(results, "args")
    assert args["net_false"]["net"] is False
    assert args["deep_zero"]["deep"] is False
    assert args["no_redact_false"]["redact"] is True


@pytest.mark.parametrize("name", ["out_value", "only_ok", "skip_ok", "only_exact"])
def test_valid_arguments_pass(results: dict[str, Any], name: str) -> None:
    assert case(results, "args")[name]["errors"] == []


# ------------------------------------------------------------------ 8: endpoints from the raw text, never userinfo

@pytest.mark.parametrize("name, expected", [
    ("pip", ["https://pypi.corp.example"]),
    ("proxy", ["http://proxy.corp:8080"]),
    ("separators", ["https://npm.corp.example:8443"]),
    ("xmlns", ["https://nexus.corp"]),
    ("comment", []),
    ("ipv6", ["http://[fd00::5]:3128"]),
    ("upper", ["https://nexus.corp.example"]),
    ("inside_word", []),
    ("two", ["https://a.corp", "https://b.corp:444"]),
    ("trailing_dot", ["https://registry.npmjs.org", "https://nexus.corp:8443"]),
])
def test_endpoint_urls(results: dict[str, Any], name: str, expected: list[str]) -> None:
    assert case(results, "endpoint_urls")[name] == expected


def test_a_trailing_dot_does_not_escape_the_public_registry_skip(results: dict[str, Any]) -> None:
    assert "public registry" in (case(results, "endpoint_urls")["skip_trailing_dot"] or "")


def test_config_entry_urls_come_from_the_raw_text(results: dict[str, Any]) -> None:
    entry = case(results, "config_entry")
    assert entry["urls"] == ["https://npm.corp.example", "http://proxy.corp.example:8080"]
    assert entry["proxy_urls"] == ["http://proxy.corp.example:8080"]
    flat = json.dumps(entry)
    assert "S3cretPw9" not in flat and "npm_tok_secret" not in flat and "alice" not in flat.replace("alice:<redacted>", "")


def test_proxy_endpoints_never_take_userinfo_as_host(results: dict[str, Any]) -> None:
    endpoints = case(results, "proxy_from_config")
    hosts = {(e["host"], e["port"]) for e in endpoints}
    assert ("proxy.corp.example", 8080) in hosts
    assert not [h for h, _ in hosts if ":" in h or "alice" in h], hosts


def test_git_endpoints_come_from_raw_values(results: dict[str, Any]) -> None:
    git = case(results, "git_urls")
    assert git["endpoints"] == ["http://gitproxy.corp:3128", "https://git.corp.example", "https://github.com"]
    assert git["proxy_urls"] == [{"tool": "git", "url": "http://gitproxy.corp:3128"}]
    flat = json.dumps(git)
    assert "GitPw9" not in flat and "GitPw8" not in flat


# ------------------------------------------------------------------ 10: Java banners

@pytest.mark.parametrize("name, version", [("tool_options", "17.0.2"), ("jdk_options", "1.8.0_381"),
                                           ("java_options_only", None)])
def test_java_option_banners_are_not_versions(results: dict[str, Any], name: str, version: str | None) -> None:
    assert case(results, "java_banner")[name] == version


# ------------------------------------------------------------------ 11: .cmd and .bat run with cmd.exe /d

def test_batch_tools_run_through_cmd_without_autorun(results: dict[str, Any]) -> None:
    run = case(results, "cmd_tool")
    assert run["error"] is None and run["exit_code"] == 0
    line = run["stdout"].lower()
    assert "\\system32\\cmd.exe" in line and " /d " in line, run
    assert "[--version]" in run["stdout"]
    assert run["command"].lower().startswith(run["system_cmd"].lower()), run


# ------------------------------------------------------------------ 12: Defender exclusions are never read

def test_defender_policy_read_skips_every_exclusion(results: dict[str, Any]) -> None:
    defender = case(results, "defender")
    touched = [entry for entry in defender["opened"] if re.search(r"exclusion|allowedapplications", entry, re.I)]
    assert touched == []
    assert not [key for key in defender["keys"] if re.search(r"exclusion|allowedapplications", key, re.I)]
    assert "Real-Time Protection\\DisableRealtimeMonitoring" in defender["keys"]
    assert "Windows Defender Exploit Guard\\ASR\\Rules\\rule1" in defender["keys"]


def test_policy_read_never_opens_the_ipsec_key(results: dict[str, Any]) -> None:
    # Stock Windows denies HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec to standard users; it
    # is out of scope and would make every --deep sec.av partial.
    policy = case(results, "policy_ipsec")
    assert not [entry for entry in policy["opened"] if "ipsec" in entry.lower()], policy["opened"]
    assert "Microsoft\\Windows\\System\\EnableSmartScreen" in policy["keys"]


def test_policy_read_is_not_denied_the_ipsec_key_on_this_machine(results: dict[str, Any]) -> None:
    denied = case(results, "policy_ipsec_real")
    assert not [key for key in denied if "\\ipsec" in key.lower()], denied


# ------------------------------------------------------------------ 13: unreadable subkeys

def test_unreadable_subkeys_do_not_hide_the_others(results: dict[str, Any]) -> None:
    subkeys = case(results, "subkeys")
    assert {"SOFTWARE", "SYSTEM"} <= set(subkeys["root"])
    assert subkeys["missing_issues"] == []
    assert any("SECURITY" in issue for issue in subkeys["denied_issues"]), subkeys


def test_a_denied_registry_read_makes_the_probe_partial(results: dict[str, Any]) -> None:
    probe = case(results, "subkeys_probe")
    assert probe["status"] == "partial"
    assert any("SECURITY" in note for note in probe["notes"]), probe
    assert case(results, "subkeys_probe_clean")["status"] == "ok"


# ------------------------------------------------------------------ 14: git and a network home

def test_git_home_follows_git_for_windows(results: dict[str, Any]) -> None:
    homes = case(results, "git_home")
    assert {name: homes[name] for name in ("network", "explicit", "profile", "missing_local")} == {
        "network": "H:\\", "explicit": "C:\\Users\\u", "profile": "C:\\Users\\u", "missing_local": "C:\\Users\\u"}
    assert "pshard-" in homes["existing_local"], homes  # HOMEDRIVE + HOMEPATH is the scratch folder


@pytest.mark.parametrize("name, variable, path, scope", [
    ("home", "HOME", "C:\\Users\\u", "global"),
    ("gitconfig", "HOME", "C:\\Users\\u\\.gitconfig", "global"),
    ("xdg", "XDG_CONFIG_HOME", "C:\\Users\\u\\.config\\git", "global"),
])
def test_git_locations_behind_links_are_replaced_like_network_ones(results: dict[str, Any], name: str, variable: str,
                                                                   path: str, scope: str) -> None:
    locations = case(results, "git_link_locations")
    got = locations[name]
    assert got["env"] == {variable: locations["local"]}
    assert got["status"] == "partial"
    assert len(got["notes"]) == 1 and path in got["notes"][0] and "link to a network path" in got["notes"][0]
    assert f"{scope} git configuration" in got["notes"][0]


@pytest.mark.parametrize("name", ["programdata", "unc_programdata"])
def test_git_system_scope_is_off_when_programdata_is_not_local(results: dict[str, Any], name: str) -> None:
    got = case(results, "git_link_locations")[name]
    assert got["env"] == {"GIT_CONFIG_NOSYSTEM": "1"}
    assert got["status"] == "partial"
    assert len(got["notes"]) == 1 and "ProgramData" in got["notes"][0] and "system git configuration" in got["notes"][0]


def test_git_locations_without_links_are_kept(results: dict[str, Any]) -> None:
    got = case(results, "git_link_locations")["clean"]
    assert (got["env"], got["status"], got["notes"]) == ({}, "ok", [])


def test_git_runs_with_a_local_home_when_home_is_on_the_network(results: dict[str, Any]) -> None:
    run = case(results, "git_network_home")
    assert run["home"] == run["local_home"]
    assert run["status"] == "partial"
    assert any("network path" in note and "global git" in note for note in run["notes"]), run
    assert run["caller_home"] == run["caller_home_before"]


def test_git_keeps_a_local_home(results: dict[str, Any]) -> None:
    run = case(results, "git_local_home")
    assert run["home"] != run["local_home"]
    assert run["status"] == "ok", run["notes"]


# ------------------------------------------------------------------ 20: git include files

def _include_note(reason: str, path: str) -> str:
    return f"git include not read ({reason}): {path}"


def test_git_quoted_paths_are_decoded(results: dict[str, Any]) -> None:
    # git --show-origin C-quotes a path with a backslash, a quote or a non-ASCII byte (octal UTF-8).
    # A quoted form that does not decode gives None: the origin is then not a local file.
    assert case(results, "git_unquote") == {
        "plain": "C:/Users/u/.gitconfig",
        "escapes": 'C:\\a\tb"c"',
        "utf8": "q\u00f6\U0001F600/x",
        "origin": "C:\\Users\\J\u00f6rg\\.gitconfig",
        "origin_plain": "C:\\Program Files\\Git\\etc\\gitconfig",
        "command_line": None,
        "bad_utf8": None,
        "unterminated": None,
        "dangling": None,
        "unknown_escape": None,
        "origin_bad": None,
    }


CREDENTIAL_STORES = ("C:\\Users\\u\\.ssh\\config", "C:\\Users\\u\\.SSH", "D:\\x\\.aws\\credentials", "C:/k/.kube/config",
                     "C:\\Users\\u\\.netrc", "C:\\Users\\u\\_NETRC", "C:/Users/u/.git-credentials", "C:\\x\\Auth.json",
                     "C:\\Users\\u\\.docker\\config.json", "C:\\Users\\u\\.bash_history",
                     "C:\\x\\ConsoleHost_history.txt",
                     # Second review 2026-11-11: zsh and other shell history files.
                     "C:\\Users\\u\\.history", "C:/Users/u/.ZHISTORY", "C:\\Users\\u\\.histfile",
                     # Third review 2026-11-12: Windows drops trailing dots and spaces, a ":" after the
                     # drive names a stream, and a "~<digit>" component may be the 8.3 name of a store.
                     "C:\\Users\\u\\.ssh.\\config", "C:\\Users\\u\\.ssh \\config", "C:\\Users\\u\\.netrc. ",
                     "C:\\Users\\u\\.netrc::$DATA", "C:\\x\\pip.ini:hidden", "C:\\Users\\u\\SSH~1\\config",
                     "C:\\Users\\u\\GIT-CR~1", "C:\\Users\\u\\BASH_H~1", "\\\\?\\C:\\Users\\u\\.ssh\\config",
                     # Security review 2026-11-12: more stores, key files (cacerts and CA bundles stay readable).
                     'C:\\Users\\u\\.gnupg\\pubring.kbx',
                     'C:\\Users\\u\\.gnupg',
                     'C:\\Users\\u\\AppData\\Roaming\\postgresql\\.pgpass',
                     'C:\\Users\\u\\.pgpass',
                     'C:\\Users\\u\\.azure\\msal_token_cache.json',
                     'C:\\Users\\u\\.config\\gcloud\\credentials.db',
                     'C:/Users/u/.config/gh/hosts.yml',
                     'C:\\Users\\u\\.terraform.d\\credentials.tfrc.json',
                     'C:\\Users\\u\\.vault-token',
                     'C:\\Users\\u\\.pypirc',
                     'C:\\Users\\u\\.gem\\credentials',
                     'C:\\Users\\u\\.cargo\\credentials.toml',
                     'C:\\Users\\u\\.m2\\settings-security.xml',
                     'C:\\var\\run\\secrets\\kubernetes.io\\serviceaccount\\token',
                     'C:\\certs\\client.pem',
                     'C:\\certs\\server.KEY',
                     'C:\\certs\\me.p12',
                     'C:\\certs\\me.pfx',
                     'C:\\certs\\store.jks',
                     'C:\\certs\\app.keystore',
                     'C:\\Users\\u\\keys\\id_rsa',
                     'C:\\Users\\u\\keys\\id_ecdsa',
                     'C:\\Users\\u\\keys\\ID_ED25519',
                     )


def test_credential_store_names(results: dict[str, Any]) -> None:
    # The same rule as es_cred_path in src/sh/11-policy.sh, in any case and with either separator.
    names = case(results, "cred_names")
    assert {path for path, store in names.items() if store} == set(CREDENTIAL_STORES)


NORMALISED_STORES = (
    "C:\\Users\\u\\.config\\.\\gcloud\\x", "C:\\Users\\u\\.docker\\\\config.json", "C:/Users/u/.docker//config.json",
    "C:\\var\\run\\secrets\\kubernetes.io\\serviceaccount\\\\token", "C:\\Users\\u\\x\\..\\.ssh\\config",
    "C:\\Users\\u\\.ssh\\x\\..\\config", "C:\\certs\\x.pem\\", "C:\\certs\\x.pem/", "C:\\Users\\u\\.config\\gcloud\\.",
    "C:\\Users\\u\\.docker\\.\\config.json", "C:\\Users\\u\\.docker\\config.json\\\\",
    # 8.3 short names of the spec folders (a short name drops the leading dot)
    "C:\\Users\\u\\TERRAF~1.D\\credentials.tfrc.json", "C:\\Users\\u\\CONFIG~1\\gcloud",
    "C:\\Users\\u\\CARGO~1\\credentials.toml", "C:\\Users\\u\\GEM~1\\credentials",
    "C:\\Users\\u\\M2~1\\settings-security.xml", "C:\\Users\\u\\SERVIC~1\\token", "C:\\Users\\u\\.ssh\\.. \\config",
)


def test_credential_paths_are_normalised(results: dict[str, Any]) -> None:
    names = case(results, "cred_names_normalised")
    assert {path for path, store in names.items() if store} == set(NORMALISED_STORES)


def test_link_targets_are_normalised(results: dict[str, Any]) -> None:
    full_language_only(results)
    targets = case(results, "link_target_normalised")
    if not targets:
        pytest.skip("PowerShell below 5 reads no link targets")
    assert targets == {"dotdot": "C:\\a\\x", "doubled": "C:\\a\\b\\sub\\.ssh", "absolute_dots": "C:\\a\\c"}


def test_reserved_device_names(results: dict[str, Any]) -> None:
    names = case(results, "device_names")
    assert {path for path, device in names.items() if device} == {
        "C:\\x\\NUL", "C:\\x\\nul.txt", "C:\\x\\Con", "C:/x/com1", "C:\\x\\LPT9.log", "C:\\x\\CONIN$", "C:\\x\\conout$",
        "C:\\x\\aux.gitconfig", "C:\\x\\PRN"}


def test_spec_paths_never_name_a_credential_store(results: dict[str, Any]) -> None:
    # A spec path or a {env:X} value that names a credential store (PIP_CONFIG_FILE=~/.netrc) is
    # dropped before anything looks at it; a folder listing never returns one either.
    paths = case(results, "cred_paths")
    for name in ("netrc", "ssh", "ssh_glob", "auth", "history", "history_glob"):
        assert paths[name] == [], (name, paths[name])
    assert paths["control"] == [paths["control_path"]]
    assert paths["any_glob"] == [paths["control_path"]]
    touched = [p for p in paths["touched"] if re.search(r"\.netrc|\.ssh|auth\.json|_history", p, re.I)]
    assert touched == [], touched


def test_globs_never_list_a_credential_folder(results: dict[str, Any]) -> None:
    # Second review 2026-11-11: a "*" in a folder component (or a {env:} value holding one) could
    # match .ssh. Patterns expand one component at a time, every folder checked before it is
    # listed: no Get-Item with a wildcard before a "\", no listing of a credential folder.
    paths = case(results, "cred_paths")
    for name in ("ssh_star_dir", "star_dir", "env_glob_dir"):
        assert paths[name] == [], (name, paths[name])
    assert [p for p in paths["touched"] if re.search(r"[*?][^\\]*\\", p)] == []
    assert [p for p in paths["listed"] if re.search(r"\\\.(ssh|aws|kube)$", p, re.I)] == []
    assert paths["listed"], "the globs list the folders they expand"


def test_spec_paths_never_name_a_device(results: dict[str, Any]) -> None:
    # A {env:X} path ending in a reserved device name (CON, NUL.txt, COM1.cfg, CONIN$, LPT9) is
    # dropped before Test-Path or Get-Item: opening it would open the device.
    paths = case(results, "device_paths")
    for name in ("con", "nul_ext", "com", "conin", "lpt"):
        assert paths[name] == [], (name, paths[name])
    assert paths["control"] == [paths["control_path"]]
    # Get-EsEnv looks variables up on the env: drive; the control file is the only file looked
    # at, after the folders above it (each checked once: is it a link that is not followed?).
    control = paths["control_path"]
    touched = [p for p in paths["touched"] if not p.lower().startswith("env:")]
    assert touched[-1] == control and touched.count(control) == 1, touched
    assert all(control.lower().startswith(p.lower() + "\\") for p in touched[:-1]), touched


def test_git_include_paths_resolve_like_git(results: dict[str, Any]) -> None:
    # ~/ is the git home folder and a relative path is relative to the including file; a path
    # that would resolve against the current drive or location, ~user and %(prefix) give None.
    assert case(results, "git_include_paths") == {
        "relative": "C:\\cfg\\sub\\x.cfg",
        "parent": "C:\\cfg\\..\\x.cfg",
        "tilde": "C:\\home\\x.cfg",
        "tilde_unset": None,
        "tilde_user": None,
        "absolute": "D:\\x.cfg",
        "unc": "\\\\srv\\share\\x.cfg",
        "device": None,
        "root_relative": None,
        "drive_relative": None,
        "prefix": None,
        "no_origin": None,
    }


def test_git_reads_local_include_files_one_level(results: dict[str, Any]) -> None:
    run = case(results, "git_includes")
    cfg, home = Path(run["cfg_dir"]), Path(run["home_dir"])
    items = {(item["origin"], item["key"]): item["value"] for item in run["items"]}
    included = f"file:{cfg / 'inc.gitconfig'}"
    quoted = cfg / "q\u00f6" / "q.gitconfig"
    assert items[(included, "http.proxy")] == "http://ip:<redacted>@incproxy.corp:3128"
    assert items[(included, "include.path")] == "nested.gitconfig"
    assert items[(f"file:{home / 'home.gitconfig'}", "core.fromhome")] == "yes"
    assert items[(f"file:{quoted}", "core.fromquoted")] == "yes"
    assert "http://incproxy.corp:3128" in run["urls"]
    assert {"tool": "git", "url": "http://incproxy.corp:3128", "source": included} in run["proxy_urls"]
    runs = [source for source in run["sources"] if source.startswith("run ")]
    assert all("--no-includes" in source for source in runs), runs
    # inc.gitconfig once (it is named twice), the home file, the locked file and the quoted one;
    # never the missing file or one that is not local.
    reads = [source for source in runs if " --file " in source]
    assert len(reads) == 4, reads
    assert not [source for source in reads if "absent" in source or "envscan-test-server" in source], reads


def test_git_includes_not_read_are_noted(results: dict[str, Any]) -> None:
    run = case(results, "git_includes")
    assert run["status"] == "partial"
    assert sorted(run["notes"]) == sorted([
        _include_note("network path", "\\\\envscan-test-server\\share\\team.gitconfig"),
        _include_note("not a local path", "/etc/gitconfig-extra"),
        _include_note("not a local path", "cl.gitconfig"),
        _include_note("unreadable", str(Path(run["cfg_dir"]) / "locked.gitconfig")),
        _include_note("nested include", "nested.gitconfig"),
        _include_note("condition gitdir:~/work/", "~/work.gitconfig"),
        _include_note("condition onbranch:main", "nested2.gitconfig"),
        _include_note("condition hasconfig:remote.*.url:https://ci:<redacted>@git.corp.example/**", "~/hc.gitconfig"),
    ])


def test_git_include_notes_and_entries_are_redacted(results: dict[str, Any]) -> None:
    # Notes go through the value rules like data: a credentialed hasconfig condition is redacted
    # in the note and in the entry name.
    run = case(results, "git_includes")
    assert "HasPw55" not in json.dumps(run) and "IncPw7" not in json.dumps(run)
    keys = {item["key"] for item in run["items"]}
    assert "includeif.hasconfig:remote.*.url:https://ci:<redacted>@git.corp.example/**.path" in keys


def test_conditional_includes_are_noted_without_changing_the_status(results: dict[str, Any]) -> None:
    run = case(results, "git_conditional")
    assert run["status"] == "ok"
    assert run["notes"] == [_include_note("condition gitdir:~/work/", "~/work.gitconfig")]


def test_git_without_no_includes_runs_again_without_it(results: dict[str, Any]) -> None:
    # git before 1.7.10 has no --no-includes and no includes: its include entries name no file
    # that git reads, so none is read (no --file run) or noted.
    run = case(results, "git_old")
    assert run["status"] == "ok" and run["notes"] == [], run
    assert {"origin": "file:x", "key": "core.editor", "value": "vim"} in run["items"]
    assert len(run["items"]) == 3, run["items"]
    runs = [source for source in run["sources"] if source.startswith("run ")]
    assert len(runs) == 2, runs
    assert "--no-includes" in runs[0] and "--no-includes" not in runs[1] and "--show-origin" in runs[1]


def test_git_without_show_origin_runs_again_without_it(results: dict[str, Any]) -> None:
    # git before 2.8 has no --show-origin: the entries are listed without an origin.
    run = case(results, "git_ancient")
    assert run["status"] == "ok" and run["notes"] == [], run
    assert run["items"] == [{"origin": "", "key": "core.editor", "value": "vim"}]
    runs = [source for source in run["sources"] if source.startswith("run ")]
    assert len(runs) == 3, runs
    assert "--show-origin" not in runs[2] and "--no-includes" not in runs[2]


def test_git_include_targets_that_are_never_opened(results: dict[str, Any]) -> None:
    run = case(results, "git_include_guards")
    cfg, home = Path(run["cfg_dir"]), Path(run["home_dir"])
    assert run["status"] == "partial"
    assert sorted(run["notes"]) == sorted([
        _include_note("credential store", str(home / ".ssh" / "config")),
        _include_note("credential store", str(home / ".git-credentials")),
        _include_note("unreadable", str(cfg / "NUL")),
        _include_note("unreadable", str(cfg / "con.gitconfig")),
        _include_note("unreadable", str(cfg / "subdir")),
        _include_note("not a local path", "x.gitconfig"),
    ])
    # Only the ordinary include file is read; a credential store or device name is never looked at.
    reads = [source for source in run["sources"] if " --file " in source]
    assert len(reads) == 1 and "team.gitconfig" in reads[0], reads
    assert {"origin": f"file:{home / 'team.gitconfig'}", "key": "core.fromteam", "value": "yes"} in run["items"]
    touched = [p for p in run["touched"] if re.search(r"\.ssh|git-credentials|\\NUL$|con\.gitconfig", p, re.I)]
    assert touched == [], touched


def test_git_include_under_a_network_home_is_not_read(results: dict[str, Any]) -> None:
    # ~/ is the user's real home, also when git runs with a local stand-in for a network home.
    run = case(results, "git_include_network_home")
    assert run["status"] == "partial"
    assert _include_note("network path", "H:\\envscan-home\\team.gitconfig") in run["notes"]
    assert _include_note("credential store", "H:\\envscan-home\\.ssh\\config") in run["notes"]
    assert any(note.startswith("git home folder H:\\envscan-home is on a network path") for note in run["notes"])
    assert not [source for source in run["sources"] if " --file " in source]


def test_a_failing_git_config_makes_the_probe_partial(results: dict[str, Any]) -> None:
    run = case(results, "git_failed")
    assert run["status"] == "partial"
    assert run["notes"] == ["git config: exit code 128: fatal: bad config line 1 in file C:/x/.gitconfig"]
    assert run["items"] == []


# ------------------------------------------------------------------ 15: process trees and PID reuse

def test_process_tree_ignores_children_older_than_their_parent(results: dict[str, Any]) -> None:
    trees = case(results, "tree")
    assert sorted(trees["cim"]) == [100, 101, 102, 103]
    assert sorted(trees["wmi"]) == [500, 501]
    assert trees["unknown_root"] == [999]


# ------------------------------------------------------------------ 16: --net never contacts public or metadata hosts

def test_reachability_never_resolves_public_or_forbidden_names(results: dict[str, Any]) -> None:
    reach = case(results, "reach")
    assert sorted(reach["resolved"]) == ["mixed.corp.example", "nexus.corp.example", "proxy.corp.example",
                                         "rebind.corp.example"]


def test_reachability_never_connects_to_forbidden_addresses(results: dict[str, Any]) -> None:
    reach = case(results, "reach")
    assert sorted(reach["tcp"]) == ["10.0.0.9:8080", "10.0.0.9:8443"]


def test_skipped_targets_are_recorded_with_a_reason(results: dict[str, Any]) -> None:
    reach = case(results, "reach")
    targets = {t["host"]: t for t in reach["targets"]}
    for host in ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "metadata.google.internal",
                 "169.254.169.254", "rebind.corp.example", "mixed.corp.example"):
        assert targets[host]["tcp"] == "skipped", targets[host]
        assert targets[host]["reason"], targets[host]
        # The contract (DEVELOPING.md, as envscan.sh): a skipped target has only these fields,
        # also when it was skipped because its name resolves to a net-never address.
        assert set(targets[host]) == {"host", "port", "source", "tcp", "reason"}, targets[host]
    assert targets["nexus.corp.example"]["tcp"] == "ok"
    assert reach["notes"], reach


IPV6_WHY = "IPv6 address outside the global and unique-local ranges; never contacted"
NO_RESOLVER_WHY = "no resolver available; names are not contacted"
SKIPPED_FIELDS = {"host", "port", "source", "tcp", "reason"}


def test_reachability_lookup_outcomes(results: dict[str, Any]) -> None:
    # Second review 2026-11-11: only a definitive "no address" is "unresolved"; a timeout or a
    # failed lookup is an "error" and makes the probe partial; literals are never looked up.
    lookup = case(results, "reach_lookup")["lookup"]
    targets = {t["host"]: t for t in lookup["targets"]}
    # Hardening round 2026-11-15: the resolver is asked for the absolute name (no search domains).
    assert sorted(lookup["resolved"]) == ["dual.corp.example.", "nxdomain.corp.example.", "slow.corp.example.",
                                          "ula.corp.example.", "v6bad.corp.example.", "v6good.corp.example."]
    assert (targets["nxdomain.corp.example"]["tcp"], targets["nxdomain.corp.example"]["error"]) == (
        "unresolved", "the name has no address")
    assert (targets["slow.corp.example"]["tcp"], targets["slow.corp.example"]["error"]) == ("error", "name lookup timed out")
    assert lookup["status"] == "partial"
    assert "the name lookup failed for 1 host(s); they were not contacted" in lookup["notes"]


def test_reachability_contacts_only_global_and_unique_local_ipv6(results: dict[str, Any]) -> None:
    lookup = case(results, "reach_lookup")["lookup"]
    targets = {t["host"]: t for t in lookup["targets"]}
    # IPv4 first; else the first allowed IPv6 address; never a name, never a refused address.
    assert lookup["tcp"] == ["2001:DB8::10|443", "10.0.0.7|443", "fd12:3456::1|443", "2001:db8::5|3128", "3fff::1|80"]
    for host in ("v6bad.corp.example", "::1", "fd00:ec2::7", "4000::1"):
        assert targets[host] == {"host": host, "port": targets[host]["port"], "source": "config", "tcp": "skipped",
                                 "reason": IPV6_WHY}, targets[host]
    assert targets["fe80::1%4"]["reason"] == "cloud metadata or link-local address; never contacted"
    for host in ("v6good.corp.example", "dual.corp.example", "ula.corp.example", "2001:db8::5", "3fff::1"):
        assert targets[host]["tcp"] == "ok", targets[host]


def test_reachability_without_a_resolver_contacts_no_name(results: dict[str, Any]) -> None:
    none = case(results, "reach_lookup")["no_resolver"]
    targets = {t["host"]: t for t in none["targets"]}
    assert targets["proxy.corp.example"] == {"host": "proxy.corp.example", "port": 8080, "source": "env",
                                             "tcp": "skipped", "reason": NO_RESOLVER_WHY}
    assert set(targets["proxy.corp.example"]) == SKIPPED_FIELDS
    # A literal address needs no resolver.
    assert targets["10.1.2.3"]["tcp"] == "ok" and none["tcp"] == ["10.1.2.3|8080"]
    assert none["status"] == "partial"
    assert "no resolver (nslookup) is available: host names were not looked up or contacted" in none["notes"]


def test_net_proxy_lists_the_settings_pkg_sources_found(results: dict[str, Any]) -> None:
    # Second review 2026-11-11: {tool, setting, value, file} from the settings found by name;
    # a configuration line that merely holds "proxy" (a registry URL) is not listed.
    lists = case(results, "proxy_list")
    assert lists["without"] == []
    assert lists["with"] == [{"tool": "npm", "setting": "https-proxy", "value": "http://proxy.corp:8080",
                              "file": "C:\\Users\\u\\.npmrc"}]


@pytest.mark.parametrize("value, allowed", [
    ("2001:db8::1", True), ("2000::", True), ("3fff:ffff::1", True), ("1fff::1", False), ("4000::1", False),
    ("fc00::1", True), ("FDFF::1", True), ("fe00::1", False), ("fe80::1", False), ("fd00:ec2::254", False),
    ("fd00:0ec2::1", False), ("fd00:ec20::1", True), ("fd00::ec2", True), ("::1", False), ("::ffff:10.0.0.1", False),
    ("64:ff9b::a00:1", False), ("ff02::1", False), ("2001:db8::1%3", False), ("[2001:db8::1]", True),
    ("02001::1", False), ("g001::1", False), ("10.0.0.1", False),
])
def test_ipv6_contact_rule(results: dict[str, Any], value: str, allowed: bool) -> None:
    # The same rule as es_ip6_ok in src/sh/28-reach.sh.
    assert case(results, "ipv6_allowed")[value] is allowed


def test_nslookup_answers_follow_the_server_block(results: dict[str, Any]) -> None:
    # The server's own address (here IPv6) comes before the first blank line and is never an answer.
    ns = case(results, "nslookup")
    assert ns["server6"] == ["2001:db8::10", "10.0.0.9"]
    assert ns["aliases"] == ["10.0.0.8"]
    assert ns["empty"] == []


@pytest.mark.parametrize("name, status, error", [
    ("ok", "ok", None),
    ("nxdomain", "none", None),
    ("nodata", "none", None),
    ("request_timeout", "error", "name lookup timed out"),
    ("killed", "error", "name lookup timed out"),
    ("no_server", "error", "name lookup failed: *** Default servers are not available"),
    ("launch_failed", "unavailable", "The system cannot find the file specified"),
    ("missing", "unavailable", None),
])
def test_nslookup_outcomes(results: dict[str, Any], name: str, status: str, error: str | None) -> None:
    answer = case(results, "nslookup")[name]
    assert (answer["status"], answer["error"]) == (status, error), answer
    assert answer["addresses"] == (["2001:db8::10", "10.0.0.9"] if name == "ok" else [])


@pytest.mark.parametrize("value, never", [
    ("169.254.169.254", True), ("::ffff:169.254.1.1", True), ("FE80::1%12", True), ("[fe80::1]", True),
    ("fd00:ec2::254", True), ("100.100.100.200", True), ("168.63.129.16", True), ("Metadata", True),
    ("metadata.google.internal", True), ("instance-data", True), ("10.0.0.1", False),
    ("metadata.corp.example", False), ("169.25.1.1", False), ("fd00:ec2::2540", False),
    # Security review 2026-11-12.
    ("fd20:ce::254", True), ("192.0.0.192", True), ("2002:c000:204::1", True), ("2002::", True), ("2003::1", False),
])
def test_net_never_list(results: dict[str, Any], value: str, never: bool) -> None:
    assert case(results, "net_never")[value] is never


# ------------------------------------------------------------------ 18: PowerShell 2.0 ACL reads

def test_ps2_acl_read_works_without_literal_path(results: dict[str, Any]) -> None:
    # The folder name holds wildcard characters; Get-Acl -Path fails on them even escaped.
    full_language_only(results)
    acl = case(results, "acl_ps2")
    assert acl["exists"] and acl["error"] is None and acl["create_files"] is True, acl
    assert not [call for call in acl["calls"] if call.startswith("literal:")], acl


# ------------------------------------------------------------------ 19: one CIM query per class and filter

def test_probes_share_cim_queries(results: dict[str, Any]) -> None:
    assert case(results, "cim_cache") == ["Win32_Processor|", "Win32_Processor|DeviceID='CPU0'"]


# ------------------------------------------------------------------ tables with an entry named Keys or Count

def test_json_writer_lists_entries_named_like_hashtable_properties(results: dict[str, Any]) -> None:
    assert json.loads(case(results, "json_shadow_keys")) == {"keys": "k", "Count": 2, "a": 1}


def test_data_safety_net_keeps_entries_named_like_hashtable_properties(results: dict[str, Any]) -> None:
    assert case(results, "data_shadow_keys") == {"keys": "password=<redacted>", "values": "x", "b": "plain"}


@pytest.mark.parametrize("name, shown", [("not_run", "not run"), ("skipped", "skipped"), ("error", "error")])
def test_probes_built_on_missing_data_are_partial(results: dict[str, Any], name: str, shown: str) -> None:
    # Third review 2026-11-12: net.proxy without pkg.sources, net.reachability without net.proxy
    # or pkg.sources: partial with a note, never ok or not_found from data that is missing.
    got = case(results, "missing_inputs")[name]
    assert got["proxy_status"] == "partial"
    assert f"pkg.sources is {shown}" in " | ".join(got["proxy_notes"])
    assert got["reach_status"] == "partial"
    joined = " | ".join(got["reach_notes"])
    assert f"net.proxy is {shown}" in joined and f"pkg.sources is {shown}" in joined


def test_probes_built_on_complete_data_keep_their_status(results: dict[str, Any]) -> None:
    got = case(results, "missing_inputs")["ok"]
    assert (got["proxy_status"], got["reach_status"]) == ("ok", "not_found")


def test_tables_keyed_by_system_names_may_hold_keys_and_count(results: dict[str, Any]) -> None:
    got = case(results, "system_keys")
    assert got["vars_process"] == ["Count", "Keys", "Path"] and got["vars_count"] == 3
    assert got["vars_machine"] == ["Count", "Keys", "Plain"]
    assert got["tree"] == ["Count", "Keys"]
    assert got["limited"] == ["Count", "Keys", "Other"]
    assert any("redirected: Count, Keys" in detail for detail in got["findings"]), got["findings"]


PUBLIC_V4_WHY = "public IPv4 address; never contacted"


@pytest.mark.parametrize("value, allowed", [
    ("10.0.0.1", True), ("10.255.255.255", True), ("172.16.0.1", True), ("172.31.255.255", True), ("172.15.0.1", False),
    ("172.32.0.1", False), ("192.168.0.1", True), ("192.169.0.1", False), ("100.64.0.1", True),
    ("100.127.255.255", True), ("100.63.0.1", False), ("100.128.0.1", False), ("8.8.8.8", False), ("127.0.0.1", False),
    ("0.0.0.0", False), ("255.255.255.255", False), ("010.0.0.1", False), ("10.0.0.256", False), ("10.0.0", False),
    ("fd00::1", False),
])
def test_ipv4_contact_rule(results: dict[str, Any], value: str, allowed: bool) -> None:
    assert case(results, "ipv4_allowed")[value] is allowed


def test_reachability_contacts_only_private_ipv4(results: dict[str, Any]) -> None:
    ipv4 = case(results, "reach_lookup")["ipv4"]
    targets = {t["host"]: t for t in ipv4["targets"]}
    assert sorted(ipv4["resolved"]) == ["mixedv4.corp.example.", "public.corp.example."]
    assert sorted(ipv4["tcp"]) == ["100.64.0.1|80", "172.31.255.1|80", "192.168.1.5|443"]
    for host in ("public.corp.example", "8.8.8.8", "172.32.0.1", "100.128.0.1", "127.0.0.1"):
        assert targets[host] == {"host": host, "port": targets[host]["port"], "source": "config", "tcp": "skipped",
                                 "reason": PUBLIC_V4_WHY}, targets[host]
    for host in ("192.0.0.192", "fd20:ce::254", "2002:c000:204::1"):
        assert targets[host]["reason"] == "cloud metadata or link-local address; never contacted", targets[host]
