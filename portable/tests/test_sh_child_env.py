"""Child environment allowlist in envscan.sh (hardening round 2026-11-15, contract item 1).

Every command run through es_exec gets only (a) the scan-start variables named in
spec/child_env.toml [child_env_keep] (names exact, or a prefix), (b) the [child_env] overrides,
LC_ALL and DOCKER_CONTEXT, and (c) the per-call extras of a probe (ES_CHILD_EXTRA). Everything
else (proxies, tokens, loader and option injection) stays out; the scanner's own environment is
unchanged.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sh_helpers import msys_path, needs_msys, run_lib

pytestmark = [pytest.mark.integration, needs_msys]

CANARIES = {
    "ENVSCAN_TEST_CHILD_CANARY": "canary-child-1",
    "HTTP_PROXY": "http://u:pw@p:1",
    "https_proxy": "http://u:pw@p:2",
    "GITHUB_TOKEN": "ghp_canarycanarycanarycanary",
    "NODE_OPTIONS": "--require /tmp/evil.js",
    "BASH_ENV": "/tmp/evil.sh",
    "ENV": "/tmp/evil.sh",
    "DOCKER_HOST": "tcp://evil:2375",
    "GIT_CONFIG_PARAMETERS": "'http.proxy'='http://u:pw@p:3'",
    "ENVSCAN-DASHED": "dashed-canary",
}
KEPT = {"LC_ENVSCAN_TEST": "kept-lc", "XDG_ENVSCAN_TEST": "kept-xdg", "JAVA_HOME": "/opt/jdk-test"}

# es_pid_init finds the env command; the scan start is es_child_keep_init (es_init runs it)
SETUP = 'ES_TMP=$1; es_pid_init; es_child_keep_init\n'


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def _env_of_child(lib: Path, tmp_path: Path, script: str, env: dict[str, str]) -> dict[str, str]:
    proc = run_lib(lib, SETUP + script, msys_path(tmp_path), env=env)
    assert proc.returncode == 0, proc.stderr
    out = (tmp_path / "env.out").read_text(encoding="utf-8", errors="replace")
    pairs: dict[str, str] = {}
    for line in out.splitlines():
        name, sep, value = line.partition("=")
        if sep:
            pairs[name] = value
    return pairs


def test_child_gets_only_the_allowlist(lib: Path, tmp_path: Path) -> None:
    child = _env_of_child(lib, tmp_path, 'es_exec 10 "$ES_TMP/env.out" - env', {**CANARIES, **KEPT})
    for name in CANARIES:
        assert name not in child, name
    out = (tmp_path / "env.out").read_text(encoding="utf-8", errors="replace")
    for value in CANARIES.values():
        assert value not in out, value
    assert "PATH" in child and "HOME" in child
    for name, value in KEPT.items():
        assert child.get(name) == value, name
    # [child_env] overrides and the fixed settings
    assert (child["NO_COLOR"], child["TERM"], child["GIT_TERMINAL_PROMPT"]) == ("1", "dumb", "0")
    assert (child["LC_ALL"], child["DOCKER_CONTEXT"]) == ("C", "default")


def test_scanner_environment_is_unchanged(lib: Path, tmp_path: Path) -> None:
    script = ('es_exec 10 "$ES_TMP/env.out" - env\n'
              'awk \'BEGIN { print ENVIRON["ENVSCAN_TEST_CHILD_CANARY"] "|" ENVIRON["HTTP_PROXY"] }\'')
    proc = run_lib(lib, SETUP + script, msys_path(tmp_path), env=CANARIES)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "canary-child-1|http://u:pw@p:1"


def test_values_with_newlines_and_quotes_pass_intact(lib: Path, tmp_path: Path) -> None:
    value = "line one\nline 'two' \"$HOME\" `x` $(y)\n"
    script = ('es_exec 10 "$ES_TMP/env.out" - "$ES_SH" -c \'printf "[%s]" "$XDG_ENVSCAN_TEST"\'')
    proc = run_lib(lib, SETUP + script, msys_path(tmp_path), env={"XDG_ENVSCAN_TEST": value})
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "env.out").read_text(encoding="utf-8") == f"[{value}]"


def test_per_call_extras_and_scan_start_rule(lib: Path, tmp_path: Path) -> None:
    """ES_CHILD_EXTRA names (set by a probe, e.g. GIT_CEILING_DIRECTORIES, XDG_CACHE_HOME) pass;
    a kept-prefix variable exported after the scan start does not; a kept variable the probe
    changed passes with its current value (the git probe's replacement HOME)."""
    script = ('GIT_CEILING_DIRECTORIES=/tmp/ceil; export GIT_CEILING_DIRECTORIES\n'
              'LC_LATE=late; export LC_LATE; HOME=/tmp/githome; export HOME\n'
              'ES_CHILD_EXTRA="GIT_CEILING_DIRECTORIES bad-name 1X"\n'
              'es_exec 10 "$ES_TMP/env.out" - env')
    child = _env_of_child(lib, tmp_path, script, {})
    assert child["GIT_CEILING_DIRECTORIES"] == "/tmp/ceil"
    assert "LC_LATE" not in child
    assert child["HOME"] == "/tmp/githome"


def test_user_locale_mode_keeps_the_original_lc_all(lib: Path, tmp_path: Path) -> None:
    script = ('ES_ORIG_LC_ALL_SET=; ES_CHILD_LOCALE=user; unset LC_ALL\n'
              'es_exec 10 "$ES_TMP/env.out" - env')
    child = _env_of_child(lib, tmp_path, script, {"LC_ALL": "de_DE.UTF-8"})
    assert "LC_ALL" not in child


def test_without_env_command_the_rest_is_unset(lib: Path, tmp_path: Path) -> None:
    """Fallback when no env command exists: the subshell unsets every other exported variable."""
    child = _env_of_child(lib, tmp_path, 'ES_ENV_BIN=; es_exec 10 "$ES_TMP/env.out" - env', {**CANARIES, **KEPT})
    for name in CANARIES:
        if name != "ENVSCAN-DASHED":  # not a shell name: a shell cannot unset it
            assert name not in child, name
    assert child["JAVA_HOME"] == "/opt/jdk-test" and "PATH" in child and child["NO_COLOR"] == "1"


def test_generated_lists_come_from_the_spec(lib: Path) -> None:
    proc = run_lib(lib, 'printf "%s|%s|%s\\n" "$ES_CHILD_KEEP_NAMES" "$ES_CHILD_KEEP_PREFIXES" "$ES_CHILD_SET"')
    names, prefixes, overrides = proc.stdout.rstrip("\n").split("|")
    assert {"PATH", "HOME", "LD_LIBRARY_PATH", "LIBPATH", "STEPLIB", "ODMDIR"} <= set(names.split())
    assert not [n for n in names.split() if "(" in n], "(X86) names are Windows-only"
    assert names.startswith(" ") and names.endswith(" ")
    assert {"_BPXK_", "_CEE_", "LC_", "XDG_"} <= set(prefixes.split())
    assert {"NO_COLOR", "TERM", "GOTOOLCHAIN"} <= set(overrides.split())


def test_stub_settings_pass_only_with_the_test_hook(lib: Path, tmp_path: Path) -> None:
    child = _env_of_child(lib, tmp_path, 'es_exec 10 "$ES_TMP/env.out" - env',
                          {"ES_STUB_LOG": "/tmp/log", "ENVSCAN_TEST_STUBS": ""})
    assert "ES_STUB_LOG" not in child
    child = _env_of_child(lib, tmp_path, 'es_exec 10 "$ES_TMP/env.out" - env',
                          {"ES_STUB_LOG": "/tmp/log", "ENVSCAN_TEST_STUBS": "1", **CANARIES})
    assert child.get("ES_STUB_LOG") == "/tmp/log"
    assert not set(CANARIES) & set(child)


def test_zos_prefixed_variables_are_kept(lib: Path, tmp_path: Path) -> None:
    env = {"_BPXK_AUTOCVT": "ON", "_CEE_RUNOPTS": "FILETAG(AUTOCVT,AUTOTAG) POSIX(ON)", "_TAG_REDIR_OUT": "TXT"}
    child = _env_of_child(lib, tmp_path, 'es_exec 10 "$ES_TMP/env.out" - env', env)
    for name, value in env.items():
        assert child.get(name) == value, name


# ---------------------------------------------------------------- review fixes 2026-11-15

def test_pid_wrapper_starts_with_the_child_environment(lib: Path, tmp_path: Path) -> None:
    """Without $BASHPID the pid wrapper "$ES_SH -c ..." runs in front of the command: it must
    already run with the child environment (env -i first), so BASH_ENV/ENV and tokens never
    reach a shell started with the scanner's full environment."""
    dump = tmp_path / "wrapper.env"
    wrapper = tmp_path / "wrapsh"
    wrapper.write_text(f'#!/bin/sh\nenv >"{msys_path(dump)}"\nexec /bin/sh "$@"\n', encoding="ascii", newline="\n")
    script = ('ES_OWNPID=; ES_SH=$2\n'
              'es_exec 10 "$ES_TMP/env.out" - env')
    proc = run_lib(lib, SETUP + script, msys_path(tmp_path), msys_path(wrapper), env={**CANARIES, **KEPT})
    assert proc.returncode == 0, proc.stderr
    seen = dump.read_text(encoding="utf-8", errors="replace")
    for name, value in CANARIES.items():
        assert value not in seen, name
    assert "JAVA_HOME=/opt/jdk-test" in seen
    child = (tmp_path / "env.out").read_text(encoding="utf-8", errors="replace")
    assert "NO_COLOR=1" in child and "canary-child-1" not in child


NET_SETUP = SETUP + 'ES_NETMNTS="/net$ES_NL"; es_child_vet_init\n'


def test_path_lists_drop_refused_entries(lib: Path, tmp_path: Path) -> None:
    """X2: LD_LIBRARY_PATH=/net/lib:/usr/lib with /net an nfs mount -> the child sees /usr/lib;
    a list left empty is removed; PATH loses its network entries; unchanged lists stay exact."""
    env = {"LD_LIBRARY_PATH": "/net/lib:/usr/lib", "LIBPATH": "/net/a:/net/b", "PATH": "/net/bin:/usr/bin:/bin",
           "XDG_DATA_DIRS": "/usr/share::/usr/local/share"}
    proc = run_lib(lib, NET_SETUP + 'es_exec 10 "$ES_TMP/env.out" - /usr/bin/env', msys_path(tmp_path), env=env)
    assert proc.returncode == 0, proc.stderr
    child = dict(line.partition("=")[::2] for line in (tmp_path / "env.out").read_text().splitlines() if "=" in line)
    assert child["LD_LIBRARY_PATH"] == "/usr/lib"
    assert "LIBPATH" not in child
    assert child["PATH"] == "/usr/bin:/bin"
    assert child["XDG_DATA_DIRS"] == "/usr/share::/usr/local/share"


def test_home_paths_are_replaced_and_other_paths_removed(lib: Path, tmp_path: Path) -> None:
    """X2: HOME on nfs -> an empty folder in the scanner's temp folder; TMPDIR -> the temp folder
    itself; a credential store counts as refused; other kept absolute paths that are refused
    (network, UNC, credential store) are removed; local paths and non-paths stay; the scanner's
    own variables do not change."""
    env = {"HOME": "/net/home/u", "TMPDIR": "/net/tmp", "XDG_CONFIG_HOME": "/home/u/.ssh",
           "XDG_CACHE_HOME": "/home/u/.cache", "JAVA_HOME": "/net/jdk", "JDK_HOME": "//server/share/jdk",
           "SSL_CERT_DIR": "/home/u/.aws/certs", "JRE_HOME": "/opt/jre", "LANG": "C.UTF-8"}
    script = (NET_SETUP + 'es_exec 10 "$ES_TMP/env.out" - /usr/bin/env\n'
              'printf "own %s|%s|%s\n" "$HOME" "$TMPDIR" "$JAVA_HOME"')
    proc = run_lib(lib, script, msys_path(tmp_path), env=env)
    assert proc.returncode == 0, proc.stderr
    child = dict(line.partition("=")[::2] for line in (tmp_path / "env.out").read_text().splitlines() if "=" in line)
    tmp = msys_path(tmp_path)
    assert child["HOME"].startswith(tmp + "/") and (tmp_path / child["HOME"][len(tmp) + 1:]).is_dir()
    assert not list((tmp_path / child["HOME"][len(tmp) + 1:]).iterdir())
    assert child["TMPDIR"] == tmp
    assert child["XDG_CONFIG_HOME"].startswith(tmp + "/")
    assert child["XDG_CACHE_HOME"] == "/home/u/.cache"
    for name in ("JAVA_HOME", "JDK_HOME", "SSL_CERT_DIR"):
        assert name not in child, name
    assert (child["JRE_HOME"], child["LANG"]) == ("/opt/jre", "C.UTF-8")
    assert "own /net/home/u|/net/tmp|/net/jdk" in proc.stdout


def test_vetting_follows_a_value_the_probe_changed(lib: Path, tmp_path: Path) -> None:
    """A kept variable changed after the scan start is vetted with its current value."""
    script = (NET_SETUP + 'JAVA_HOME=/net/other; export JAVA_HOME\n'
              'es_exec 10 "$ES_TMP/env.out" - /usr/bin/env')
    proc = run_lib(lib, script, msys_path(tmp_path), env={"JAVA_HOME": "/opt/jdk"})
    assert proc.returncode == 0, proc.stderr
    assert "JAVA_HOME=" not in (tmp_path / "env.out").read_text()


def test_generated_vetting_lists_come_from_the_spec(lib: Path) -> None:
    proc = run_lib(lib, 'printf "%s|%s\n" "$ES_CHILD_HOME_PATHS" "$ES_CHILD_PATH_LISTS"')
    homes, lists = proc.stdout.rstrip("\n").split("|")
    assert {"HOME", "TMPDIR", "XDG_CACHE_HOME"} <= set(homes.split()) and homes.startswith(" ")
    assert {"PATH", "LD_LIBRARY_PATH", "XDG_DATA_DIRS"} <= set(lists.split()) and lists.endswith(" ")


def test_git_children_get_their_settings_without_changing_the_scanner(lib: Path, tmp_path: Path) -> None:
    """es_git_config passes GIT_CEILING_DIRECTORIES and the replacement HOME to the git children
    only (ES_CHILD_EXTRA NAME=SOURCE); the scanner's own values stay as they were."""
    stubs, pdir, dump = tmp_path / "stubs", tmp_path / "p", tmp_path / "git.env"
    stubs.mkdir()
    pdir.mkdir()
    (stubs / "git").write_text(f'#!/bin/sh\nenv >>"{msys_path(dump)}"\nexit 0\n', encoding="ascii", newline="\n")
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_TIMEOUT=10; PATH="$2:/usr/bin"; es_pid_init; es_child_keep_init\n'
              'ES_NETMNTS="/net$ES_NL"\n'
              'es_git_config 5>/dev/null\n'
              'printf "own %s|%s|%s\n" "$GIT_CEILING_DIRECTORIES" "$HOME" "$XDG_CONFIG_HOME"')
    env = {"GIT_CEILING_DIRECTORIES": "/user/ceil", "HOME": "/net/home/u", "XDG_CONFIG_HOME": "/net/cfg"}
    proc = run_lib(lib, script, msys_path(pdir), msys_path(stubs), env=env)
    assert proc.returncode == 0, proc.stderr
    assert "own /user/ceil|/net/home/u|/net/cfg" in proc.stdout
    seen = dict(line.partition("=")[::2] for line in dump.read_text().splitlines() if "=" in line)
    assert seen["GIT_CEILING_DIRECTORIES"] == msys_path(pdir)
    assert seen["HOME"].startswith(msys_path(pdir) + "/") and seen["XDG_CONFIG_HOME"].startswith(msys_path(pdir) + "/")


def test_fc_list_cache_does_not_change_the_scanner(lib: Path, tmp_path: Path) -> None:
    """fc-list gets XDG_CACHE_HOME in the scanner temp folder; the scanner keeps its own value."""
    stubs, pdir, dump = tmp_path / "stubs", tmp_path / "p", tmp_path / "fc.env"
    stubs.mkdir()
    pdir.mkdir()
    (stubs / "fc-list").write_text(f'#!/bin/sh\nenv >"{msys_path(dump)}"\nprintf "a\nb\n"\n', encoding="ascii",
                                   newline="\n")
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_TIMEOUT=10; PATH="$2:/usr/bin"; es_pid_init; es_child_keep_init\n'
              'es_font_count; printf "fonts=%s own=%s\n" "$ES_FONTS" "$XDG_CACHE_HOME"')
    proc = run_lib(lib, script, msys_path(pdir), msys_path(stubs), env={"XDG_CACHE_HOME": "/user/cache"})
    assert proc.returncode == 0, proc.stderr
    assert "fonts=2 own=/user/cache" in proc.stdout
    seen = dict(line.partition("=")[::2] for line in dump.read_text().splitlines() if "=" in line)
    assert seen["XDG_CACHE_HOME"] == msys_path(pdir) + "/fc-cache"
