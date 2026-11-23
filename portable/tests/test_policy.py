"""spec/policy.toml: the credential-store names and network filesystem types, generated into sh and ps1."""
from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest
import target_ps
import target_sh
from conftest import PORTABLE, ps_eval, ps_quote, requires_powershell
from sh_helpers import needs_msys, run_lib

import build as build_module
from spec import DOCUMENT_KEYS, Spec, load_spec, validate_spec

pytestmark = pytest.mark.unit
replace = dataclasses.replace


@pytest.fixture(scope="module")
def spec() -> Spec:
    return load_spec(PORTABLE / "spec")


# ------------------------------------------------------------------ spec file

def test_policy_is_a_registered_spec_document(spec: Spec) -> None:
    assert "policy.toml" in DOCUMENT_KEYS
    assert validate_spec(spec) == []
    assert "nfs" in spec.network_fs and "cifs" in spec.network_fs
    creds = spec.credentials
    assert ".ssh" in creds["folders"] and ".config/gcloud" in creds["folders"]
    assert ".netrc" in creds["files"] and "id_rsa" in creds["files"]
    assert "_history" in creds["suffixes"]
    assert set(creds["key_extensions"]) == {"pem", "key", "p12", "pfx", "jks", "keystore"}


BAD_POLICY = {
    "network_fs as a string": (lambda s: replace(s, network_fs="nfs"), "network_fs: expected a list of strings"),
    "network_fs empty": (lambda s: replace(s, network_fs=()), "network_fs: must not be empty"),
    "network_fs upper case": (lambda s: replace(s, network_fs=("NFS",)), "network_fs: 'NFS' must match"),
    "network_fs duplicate": (lambda s: replace(s, network_fs=("nfs", "nfs")), "network_fs: duplicate"),
    "credentials not a table": (lambda s: replace(s, credentials=[]), "credentials: expected a table"),
    "unknown credentials key": (lambda s: replace(s, credentials={**s.credentials, "extra": ["x"]}),
                                "credentials: unknown key 'extra'"),
    "folders missing": (lambda s: replace(s, credentials={k: v for k, v in s.credentials.items() if k != "folders"}),
                        "credentials: missing 'folders'"),
    "folder upper case": (lambda s: replace(s, credentials={**s.credentials, "folders": (".SSH",)}),
                          "credentials.folders: '.SSH' must match"),
    "folder with a backslash": (lambda s: replace(s, credentials={**s.credentials, "folders": (".a\\b",)}),
                                "credentials.folders: '.a\\\\b' must match"),
    "file with a glob": (lambda s: replace(s, credentials={**s.credentials, "files": ("*.key",)}),
                         "credentials.files: '*.key' must match"),
    "extension with a dot": (lambda s: replace(s, credentials={**s.credentials, "key_extensions": (".pem",)}),
                             "credentials.key_extensions: '.pem' must match"),
    "folder dot": (lambda s: replace(s, credentials={**s.credentials, "folders": (".",)}),
                   "credentials.folders: '.' must match"),
    "folder dot-dot": (lambda s: replace(s, credentials={**s.credentials, "folders": ("a/../b",)}),
                       "credentials.folders: 'a/../b' must match"),
    "file leading dash": (lambda s: replace(s, credentials={**s.credentials, "files": ("-rf",)}),
                          "credentials.files: '-rf' must match"),
    "child env name with parentheses": (lambda s: replace(s, child_env={"PROGRAMFILES(X86)": "x"}),
                                        "child_env.toml: invalid variable name 'PROGRAMFILES(X86)'"),
    "trust names as a string": (lambda s: replace(s, trust_store_names="cacerts"),
                                "trust_store_names: expected a list of strings"),
    "trust names empty": (lambda s: replace(s, trust_store_names=()), "trust_store_names: must not be empty"),
    "trust name with a path": (lambda s: replace(s, trust_store_names=("a/b",)), "trust_store_names: 'a/b' must match"),
    "trust name upper case": (lambda s: replace(s, trust_store_names=("CACerts",)),
                              "trust_store_names: 'CACerts' must match"),
    "trust names duplicate": (lambda s: replace(s, trust_store_names=("cacerts", "cacerts")),
                              "trust_store_names: duplicate"),
    "empty folders": (lambda s: replace(s, credentials={**s.credentials, "folders": ()}),
                      "credentials.folders: must not be empty"),
    "duplicate file": (lambda s: replace(s, credentials={**s.credentials, "files": (".netrc", ".netrc")}),
                       "credentials.files: duplicate"),
}


@pytest.mark.parametrize("name", sorted(BAD_POLICY))
def test_bad_policy_is_reported(spec: Spec, name: str) -> None:
    change, expected = BAD_POLICY[name]
    assert any(expected in error for error in validate_spec(change(spec))), validate_spec(change(spec))


# ------------------------------------------------------------------ generated data

def test_sh_gets_the_network_filesystems_as_data(spec: Spec) -> None:
    block = target_sh.generate(spec)
    assert "ES_NET_FS=' " + " ".join(spec.network_fs) + " '" in block
    core = (PORTABLE / "src" / "sh" / "10-core.sh").read_text(encoding="ascii")
    assert not re.search(r"^ES_NET_FS=", core, re.MULTILINE), "10-core.sh must use the generated list"


def test_sh_credential_patterns_ignore_case(spec: Spec) -> None:
    block = target_sh.generate(spec)
    assert "[.][Ss][Ss][Hh]" in block and "[Pp][Ee][Mm]" in block
    policy = (PORTABLE / "src" / "sh" / "11-policy.sh").read_text(encoding="ascii")
    assert ".gnupg" not in policy.split("es_cred_match()", 1)[1].split("es_ca_path()", 1)[0]


def test_ps_gets_the_credential_names_as_data(spec: Spec) -> None:
    block = target_ps.generate(spec)
    for key, name in (("FOLDERS", ".config\\gcloud"), ("FILES", ".git-credentials"),
                      ("SUFFIXES", "_history.txt"), ("KEY_EXTENSIONS", "keystore")):
        line = next(row for row in block.splitlines() if row.startswith(f"$script:ES_CRED_{key} = "))
        assert f"'{name}'" in line, key
    line = next(row for row in block.splitlines() if row.startswith("$script:ES_TRUST_STORE_NAMES = "))
    assert all(f"'{name}'" in line for name in spec.trust_store_names)
    source = (PORTABLE / "src" / "ps" / "11-exec.ps1").read_text(encoding="ascii")
    assert not re.search(r"^\$script:ES_TRUST_STORE_NAMES = ", source, re.MULTILINE), "must use the generated list"
    assert r"\.gnupg" not in source and r"\.vault-token" not in source


def test_generated_scripts_pass_their_lints() -> None:
    result = build_module.build(PORTABLE, ("ps", "sh"))
    assert result.ok, result.errors


# ------------------------------------------------------------------ behaviour

def test_trust_store_names_are_in_the_spec(spec: Spec) -> None:
    assert isinstance(spec.trust_store_names, tuple)
    assert {"cacerts", "ca-bundle.crt", "cert.pem"} <= set(spec.trust_store_names)


def test_policy_lists_are_tuples(spec: Spec) -> None:
    assert isinstance(spec.network_fs, tuple)
    assert all(isinstance(values, tuple) for values in spec.credentials.values())


def _variants(spec: Spec) -> list[tuple[str, str]]:
    """(label, path) for every policy name, in the spelling of a case-insensitive disk."""
    creds = spec.credentials
    paths = [(f"folder {n}", f"/Users/Alice/{n.upper()}/x") for n in creds["folders"]]
    paths += [(f"folder {n}", f"/Users/Alice/{n.title()}/X") for n in creds["folders"]]
    paths += [(f"file {n}", f"/Users/Alice/{n.upper()}") for n in creds["files"]]
    paths += [(f"suffix {n}", f"/Users/Alice/Zsh{n.upper()}") for n in creds["suffixes"]]
    paths += [(f"ext {n}", f"/Users/Alice/Keys/Me.{n.upper()}") for n in creds["key_extensions"]]
    return paths


@needs_msys
def test_sh_matches_every_credential_name_in_any_case(spec: Spec, built: Path) -> None:
    lib = built / "build" / "lib" / "envscan-lib.sh"
    cases = _variants(spec)
    script = 'for p in "$@"; do es_cred_path "$p" || printf "MISS %s\\n" "$p"; done; echo done'
    proc = run_lib(lib, script, *[path for _, path in cases])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["done"], proc.stdout


K8S = ["/var/run/secrets/kubernetes.io/serviceaccount/token", "/var/run/secrets/kubernetes.io/serviceaccount/..data/token",
       "/run/secrets/kubernetes.io/serviceaccount/ca.crt", "/run/secrets/kubernetes.io/serviceaccount/namespace",
       "/Var/Run/Secrets/Kubernetes.io/ServiceAccount/..Data/Token"]


@needs_msys
def test_sh_covers_the_whole_serviceaccount_directory(built: Path) -> None:
    lib = built / "build" / "lib" / "envscan-lib.sh"
    script = 'for p in "$@"; do es_cred_path "$p" || printf "MISS %s\n" "$p"; done; echo done'
    proc = run_lib(lib, script, *K8S)
    assert proc.stdout.split() == ["done"], proc.stdout


@requires_powershell
def test_ps_covers_the_whole_serviceaccount_directory(built: Path) -> None:
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    array = "@(" + ", ".join(ps_quote(p) for p in K8S) + ")"
    proc = ps_eval(lib, f"foreach ($p in {array}) {{ if (-not (Test-EsCredentialPath $p)) {{ 'MISS ' + $p }} }}; 'done'")
    assert proc.stdout.split() == ["done"], proc.stdout


@needs_msys
@pytest.mark.parametrize("path", ["/Users/Alice/.sshfoo/x", "/Users/Alice/Library/Caches/x", "/Users/Alice/.Npmrc",
                                  "/Users/Alice/id_rsa.pub", "/Users/Alice/ssh/config"])
def test_sh_leaves_ordinary_paths_alone(built: Path, path: str) -> None:
    lib = built / "build" / "lib" / "envscan-lib.sh"
    proc = run_lib(lib, 'es_cred_path "$1" && echo store || echo other', path)
    assert proc.stdout.strip() == "other", proc.stderr


@needs_msys
def test_sh_network_filesystem_check_uses_the_spec_list(spec: Spec, built: Path) -> None:
    lib = built / "build" / "lib" / "envscan-lib.sh"
    for fstype in spec.network_fs:
        proc = run_lib(lib, 'es_is_netfs "$1" && echo net || echo local', fstype)
        assert proc.stdout.strip() == "net", fstype
    assert run_lib(lib, 'es_is_netfs "$1" && echo net || echo local', "ext4").stdout.strip() == "local"



@requires_powershell
def test_ps_matches_the_same_credential_names_in_any_case(spec: Spec, built: Path) -> None:
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    paths = [path for _, path in _variants(spec)]
    array = "@(" + ", ".join(ps_quote(p) for p in paths) + ")"
    expression = f"foreach ($p in {array}) {{ if (-not (Test-EsCredentialPath $p)) {{ 'MISS ' + $p }} }}; 'done'"
    proc = ps_eval(lib, expression)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["done"], proc.stdout


@requires_powershell
def test_ps_leaves_ordinary_paths_alone(built: Path) -> None:
    lib = built / "build" / "lib" / "envscan-lib.ps1"
    ordinary = ["C:/Users/Alice/.sshfoo/x", "C:/Users/Alice/.npmrc", "C:/Users/Alice/id_rsa.pub"]
    array = "@(" + ", ".join(ps_quote(p) for p in ordinary) + ")"
    proc = ps_eval(lib, f"foreach ($p in {array}) {{ [string](Test-EsCredentialPath $p) }}")
    assert proc.stdout.split() == ["False"] * len(ordinary), proc.stdout
