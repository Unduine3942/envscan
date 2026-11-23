"""Spec data for the cross-port hardening round (2026-11-15).

1. child_env.toml [child_env_keep]: the only variables of the user's environment that reach the
   commands the scanner runs (an allowlist; everything else, tokens included, stays out).
2. policy.toml network_fs_prefixes / local_fuse: any fuse.* mount is a network mount unless it is
   on the local list; more cluster and network file systems in network_fs.
"""
from __future__ import annotations

import dataclasses

import pytest
from conftest import PORTABLE

from spec import DOCUMENT_KEYS, Spec, load_spec, validate_spec

pytestmark = pytest.mark.unit
replace = dataclasses.replace


@pytest.fixture(scope="module")
def spec() -> Spec:
    return load_spec(PORTABLE / "spec")


def test_spec_is_valid_and_documents_registered(spec: Spec) -> None:
    assert validate_spec(spec) == []
    assert "child_env_keep" in DOCUMENT_KEYS["child_env.toml"]
    assert {"network_fs_prefixes", "local_fuse"} <= set(DOCUMENT_KEYS["policy.toml"])


def test_child_env_keep_holds_what_tools_need_and_no_secrets(spec: Spec) -> None:
    names = set(spec.child_env_keep_names)
    assert {"PATH", "HOME", "LANG", "TZ", "TMPDIR", "SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "USERPROFILE",
            "JAVA_HOME", "LD_LIBRARY_PATH", "LIBPATH", "ODMDIR", "PROGRAMFILES(X86)"} <= names
    assert set(spec.child_env_keep_prefixes) >= {"LC_", "XDG_", "_BPXK_", "_CEE_"}
    # never: proxies (may hold user:password), tokens, loader and option injection
    for bad in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "GITHUB_TOKEN", "NPM_TOKEN", "LD_PRELOAD",
                "NODE_OPTIONS", "JAVA_TOOL_OPTIONS", "BASH_ENV", "ENV", "DOCKER_HOST", "GIT_CONFIG_PARAMETERS"):
        assert bad not in names, bad
        assert not any(bad.startswith(p) for p in spec.child_env_keep_prefixes), bad


def test_child_env_overrides_are_not_also_kept(spec: Spec) -> None:
    assert not set(spec.child_env) & set(spec.child_env_keep_names)


def test_child_env_path_vetting_lists(spec: Spec) -> None:
    assert {"HOME", "USERPROFILE", "APPDATA", "TMPDIR", "TEMP", "XDG_CONFIG_HOME"} <= set(spec.child_env_home_paths)
    assert {"PATH", "LD_LIBRARY_PATH", "LIBPATH", "PSMODULEPATH", "XDG_DATA_DIRS"} <= set(spec.child_env_path_lists)


def test_fuse_policy(spec: Spec) -> None:
    assert spec.network_fs_prefixes == ("fuse.",)
    local = set(spec.local_fuse)
    assert {"fuse.lxcfs", "fuse.fuse-overlayfs", "fuse.snapfuse", "fuse.squashfuse"} <= local
    assert all(t.startswith("fuse.") for t in local)
    # layering FUSE types often sit on NFS/CIFS/sshfs folders: never "local"
    assert not local & {"fuse.mergerfs", "fuse.bindfs", "fuse.gocryptfs", "fuse.encfs", "fuse.archivemount"}
    assert not local & set(spec.network_fs)
    for fs in ("fuse", "beegfs", "gfs2", "ocfs2", "orangefs", "nfs3", "afpfs", "webdav", "mvfs"):
        assert fs in spec.network_fs, fs


BAD = {
    "keep names empty": (lambda s: replace(s, child_env_keep_names=()), "child_env_keep names: must not be empty"),
    "keep name invalid": (lambda s: replace(s, child_env_keep_names=("A-B",)),
                          "child_env_keep names: invalid variable name 'A-B'"),
    "keep name duplicate": (lambda s: replace(s, child_env_keep_names=("PATH", "PATH")),
                            "child_env_keep names: duplicate"),
    "keep name is secret": (lambda s: replace(s, child_env_keep_names=("PATH", "API_TOKEN")),
                            "child_env_keep names: 'API_TOKEN' is a secret name"),
    "keep prefix without underscore": (lambda s: replace(s, child_env_keep_prefixes=("LC",)),
                                       "child_env_keep prefixes: 'LC' must match"),
    "keep prefix empty list ok but not a string": (lambda s: replace(s, child_env_keep_prefixes="LC_"),
                                                   "child_env_keep prefixes: expected a list of strings"),
    "home path not kept": (lambda s: replace(s, child_env_home_paths=("HOME", "NOPE")),
                           "child_env_keep home_paths: 'NOPE' is not kept"),
    "path list empty": (lambda s: replace(s, child_env_path_lists=()), "child_env_keep path_lists: must not be empty"),
    "in both lists": (lambda s: replace(s, child_env_path_lists=("PATH", "HOME")),
                      "'HOME' is in both home_paths and path_lists"),
    "fuse prefix wrong": (lambda s: replace(s, network_fs_prefixes=("nfs",)),
                          "network_fs_prefixes: 'nfs' must end with '.'"),
    "local fuse not fuse": (lambda s: replace(s, local_fuse=("ext4",)),
                            "local_fuse: 'ext4' must start with a network_fs_prefixes entry"),
    "local fuse also network": (lambda s: replace(s, local_fuse=("fuse.sshfs",)),
                                "local_fuse: 'fuse.sshfs' is also in network_fs"),
}


@pytest.mark.parametrize("name", sorted(BAD))
def test_bad_values_are_rejected(spec: Spec, name: str) -> None:
    mutate, message = BAD[name]
    errors = validate_spec(mutate(spec))
    assert any(message in e for e in errors), errors
