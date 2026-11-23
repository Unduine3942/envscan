"""envscan.sh hardening (second review 2026-11-11, findings B, E, G and K): network or autofs
mounts are never touched and credential stores never tested (paths from the environment, HOME,
globs and symbolic links are vetted against the mount table before any file test); raw
configuration data is removed right after its last use, and a signal removes the temp directory.

A fake mount table: ES_NETMNTS (the scanner's list of network mount points) names a test
directory. Links are made with ln -s; under MSYS, MSYS=winsymlinks:lnk makes it create a
shortcut that MSYS treats as a symbolic link (no privilege needed).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from sh_helpers import DASH, STUBS, msys_path, needs_msys, run_lib

pytestmark = [pytest.mark.integration, needs_msys]


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def sh(lib: Path, script: str, *args: str) -> str:
    proc = run_lib(lib, script, *args)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _write(path: Path, text: str = "x\n", exe: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii", newline="\n")
    if exe:
        path.chmod(0o755)
    return path


def _link(lib: Path, target: Path, link: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    sh(lib, 'MSYS=winsymlinks:lnk ln -s "$1" "$2" && [ -h "$2" ]', msys_path(target), msys_path(link))


def _events(out: str) -> list[str]:
    return out.splitlines()


def test_which_never_follows_a_link_onto_a_network_mount(lib: Path, tmp_path: Path) -> None:
    """es_which and es_which_all: /usr/local/bin/java -> /nfs/jdk/bin/java is never stat'ed
    (a -f or -x test follows the link); the link is left out and noted (ES_NETSKIP)."""
    net, local = tmp_path / "net", tmp_path / "local"
    java = _write(net / "jdk" / "bin" / "java", "#!/bin/sh\necho java\n", exe=True)
    _write(local / "bin" / "javac", "#!/bin/sh\necho javac\n", exe=True)
    _link(lib, java, local / "bin" / "java")
    script = ('ES_NETMNTS="$1$ES_NL"; PATH="$2/bin:/usr/bin"; es_path_init\n'
              'es_which java && echo "which=$ES_W" || echo "which="\n'
              'es_which_all java; echo "all=$ES_WA"\n'
              'es_which javac && echo "javac=$ES_W"\n'
              'printf "skip=%s\\n" "$ES_NETSKIP"')
    out = _events(sh(lib, script, msys_path(net), msys_path(local)))
    assert "which=" in out and "all=" in out, out
    assert f"javac={msys_path(local)}/bin/javac" in out
    assert f"skip={msys_path(local)}/bin/java" in out


def test_java_homes_on_network_mounts_are_never_tested(lib: Path, tmp_path: Path) -> None:
    """runtime.java: JAVA_HOME, ~/.jdks/<link to a network JDK> and a glob whose base is a link
    into a network mount (~/.sdkman) are neither tested nor listed."""
    net, home, root, pdir = tmp_path / "net", tmp_path / "home", tmp_path / "root", tmp_path / "p"
    for jdk in ("jdk17", "jdk21", "sdkman/candidates/java/11"):
        _write(net / jdk / "bin" / "java", "#!/bin/sh\n", exe=True)
        _write(net / jdk / "release", 'JAVA_VERSION="17"\n')
    _link(lib, net / "jdk21", home / ".jdks" / "jdk-21")
    _link(lib, net / "sdkman", home / ".sdkman")
    _write(home / ".jdks" / "local-jdk" / "release", 'JAVA_VERSION="8"\n')
    (root / "usr").mkdir(parents=True)
    pdir.mkdir()
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_ROOT=$2; HOME=$3; JAVA_HOME=$4/jdk17; ES_NETMNTS="$4$ES_NL"\n'
              'ES_OS=linux; ES_TIMEOUT=5; PATH=/usr/bin; es_pid_init; es_path_init\n'
              'probe_runtime_java 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"; printf "skip=%s\\n" "$ES_NETSKIP"')
    out = sh(lib, script, msys_path(pdir), msys_path(root), msys_path(home), msys_path(net))
    paths = [line.split("\t")[2] for line in out.splitlines() if line.startswith("s\tpath\t")]
    assert paths == [f"{msys_path(home)}/.jdks/local-jdk"], out
    assert f"{msys_path(net)}/jdk17" in out  # noted (skip list), never tested


def test_dotnet_and_keytool_on_network_mounts_are_never_tested(lib: Path, tmp_path: Path) -> None:
    """runtime.dotnet (DOTNET_ROOT), tls.trust and tls.java_cacerts (JAVA_HOME cacerts and
    keytool) on a network mount: not found, never stat'ed."""
    net, root, pdir = tmp_path / "net", tmp_path / "root", tmp_path / "p"
    _write(net / "dotnet" / "dotnet", "#!/bin/sh\n", exe=True)
    _write(net / "jdk" / "lib" / "security" / "cacerts", "certs\n")
    _write(net / "jdk" / "bin" / "keytool", "#!/bin/sh\necho Your keystore contains 1 entries\n", exe=True)
    (root / "etc").mkdir(parents=True)
    pdir.mkdir()
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_ROOT=$2; HOME=$1; DOTNET_ROOT=$3/dotnet; JAVA_HOME=$3/jdk\n'
              'ES_NETMNTS="$3$ES_NL"; ES_OS=linux; ES_TIMEOUT=5; PATH=/usr/bin; es_pid_init; es_path_init\n'
              '{ probe_runtime_dotnet; echo "dotnet-status=$(cat "$ES_P_DIR/status" 2>/dev/null)"; rm -f "$ES_P_DIR/status"\n'
              '  probe_tls_trust; probe_tls_java_cacerts; echo "keytool-status=$(cat "$ES_P_DIR/status")"; } 5>"$ES_P_DIR/ev.txt"\n'
              'cat "$ES_P_DIR/ev.txt"')
    out = sh(lib, script, msys_path(pdir), msys_path(root), msys_path(net))
    lines = out.splitlines()
    assert "z\tjava_cacerts" in lines, out
    assert not [line for line in lines if line.startswith("s\tdotnet\t") or line.startswith("s\tkeytool\t")], out
    assert "keytool-status=not_found" in out


def test_home_and_path_entries_on_network_mounts_are_not_tested(lib: Path, tmp_path: Path) -> None:
    """user.profile: a HOME on a network mount (directly or through a link) is not tested
    (exists and writable unknown, a note); env.path: such PATH entries are not tested either."""
    net, local, pdir = tmp_path / "net", tmp_path / "local", tmp_path / "p"
    (net / "home" / ".config").mkdir(parents=True)
    _write(net / "home" / ".config" / "user-dirs.dirs", 'XDG_DESKTOP_DIR="$HOME/Desk"\n')
    (net / "bin").mkdir()
    _link(lib, net / "bin", local / "netbin")
    pdir.mkdir()
    script = ('ES_P_DIR=$1; ES_TMP=$1; HOME=$2/home; ES_NETMNTS="$2$ES_NL"; unset XDG_CONFIG_HOME\n'
              'PATH="$2/bin:$3/netbin:/usr/bin"; es_path_init\n'
              '{ probe_user_profile; probe_env_path; } 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"\n'
              'sed "s/^/note: /" "$ES_P_DIR/notes"')
    out = sh(lib, script, msys_path(pdir), msys_path(net), msys_path(local))
    lines = out.splitlines()
    assert "z\thome_exists" in lines and "z\thome_writable" in lines and "b\thome_network\ttrue" in lines, out
    assert "note: HOME is on a network or autofs mount: it is not tested (exists and writable unknown)" in lines
    assert "XDG_DESKTOP_DIR" not in out  # user-dirs.dirs on the network home is not read
    entries = out.split("[\tentries")[1]
    for entry in (f"{msys_path(net)}/bin", f"{msys_path(local)}/netbin"):
        block = entries.split(f"s\tpath\t{entry}\n")[1].split("}")[0]
        assert "z\texists" in block and "b\tnetwork\ttrue" in block, block


def test_scheduled_tasks_in_a_network_home_are_not_listed(lib: Path, tmp_path: Path) -> None:
    """sched.tasks: ~/Library/LaunchAgents of a network HOME is neither tested nor listed."""
    net, root, pdir = tmp_path / "net", tmp_path / "root", tmp_path / "p"
    _write(net / "Library" / "LaunchAgents" / "com.corp.agent.plist")
    (root / "etc").mkdir(parents=True)
    pdir.mkdir()
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_ROOT=$2; HOME=$3; ES_NETMNTS="$3$ES_NL"; ES_TIMEOUT=5; PATH=/usr/bin\n'
              'es_pid_init; probe_sched_tasks 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"; printf "skip=%s\\n" "$ES_NETSKIP"')
    out = sh(lib, script, msys_path(pdir), msys_path(root), msys_path(net))
    assert "com.corp.agent.plist" not in out
    assert f"skip={msys_path(net)}/Library/LaunchAgents" in out


def test_temp_directory_is_never_on_a_network_mount(lib: Path, tmp_path: Path) -> None:
    """es_mktemp reads /proc/self/mounts before the temp directory exists: a TMPDIR on an NFS
    mount is skipped (nothing is created there)."""
    net, root = tmp_path / "nettmp", tmp_path / "root"
    net.mkdir()
    _write(root / "proc" / "self" / "mounts",
           f"/dev/sda1 / ext4 rw 0 0\nfiler:/export/tmp {msys_path(net)} nfs4 rw,vers=4.2 0 0\n")
    script = ('ES_ROOT=$2; TMPDIR=$1; es_mktemp; printf "tmp=%s\\n" "$ES_TMP"\n'
              'case $ES_TMP in "$1"/*) ;; *) rmdir "$ES_TMP" ;; esac')
    out = sh(lib, script, msys_path(net), msys_path(root))
    assert "tmp=" in out and f"tmp={msys_path(net)}" not in out, out
    assert list(net.iterdir()) == []


def test_globs_never_list_a_credential_directory(lib: Path, tmp_path: Path) -> None:
    """Review K: es_expand checks the pattern before globbing, so ~/.ssh is never listed;
    .history, .zhistory and .histfile are credential stores too."""
    _write(tmp_path / ".ssh" / "config", "Host x\n")
    for name in (".history", ".zhistory", ".histfile"):
        _write(tmp_path / name, "secret command\n")
    script = ('ES_ROOT=; HOME=$1\n'
              'for p in "~/.ssh/*" "~/.ssh" "~/.history" "~/.zhistory" "~/.histfile" "~/.h*"; do\n'
              '  es_expand "$p" && printf "%s => %s\\n" "$p" "$(printf "%s" "$ES_X" | tr "\\n" " ")" || echo "$p => none"\n'
              'done')
    out = sh(lib, script, msys_path(tmp_path)).splitlines()
    assert out[:5] == ["~/.ssh/* => none", "~/.ssh => none", "~/.history => none", "~/.zhistory => none",
                       "~/.histfile => none"], out
    assert out[5] == "~/.h* => none", out  # the glob's results are credential stores: left out untested


def test_shim_check_keeps_the_symlink_result(lib: Path) -> None:
    """Review G: es_shim_of used es_sl, the variable that holds fs.semantics' symlink result."""
    out = sh(lib, 'es_sl=ok; es_shim_of /usr/bin; es_shim_of /home/u/.pyenv/shims; echo "es_sl=$es_sl"')
    assert out.strip() == "es_sl=ok"


RAW = ("cfg.cur", "config_lines.txt", "env_lines.txt", "git_lines.txt", "git_urls.txt", "git-incl.txt",
       "tls_off.txt", "proxy_urls.tsv", "sys.tsv")


def test_raw_configuration_data_is_removed_after_its_last_use(lib: Path, tmp_path: Path) -> None:
    """Review E: pkg.sources removes its unredacted intermediates (configuration lines, git
    configuration, command outputs) when it ends; only pkg_proxy.tsv stays, for net.proxy, which
    removes it."""
    home, tmp = tmp_path / "home", tmp_path / "t"
    p1, p2 = tmp / "p" / "1", tmp / "p" / "2"
    for d in (p1, p2):
        d.mkdir(parents=True)
    _write(home / ".npmrc", "registry=https://nexus.corp/\nproxy=http://bob:RawPw9@proxy.corp:8080\n"
                            "strict-ssl=false\n")
    gitconfig = msys_path(home / ".gitconfig")
    listing = _write(tmp_path / "list.tsv", f"file:{gitconfig}\thttp.proxy=http://bob:GitPw9@gitproxy.corp:3128\n")
    spec = _write(tmp_path / "configs.spec", "npmrc.user\tnpm\tall\tuser\tcontent\t16384\t-\t~/.npmrc\n")
    script = ('ES_TMP=$1; ES_ROOT=; ES_OS=linux; HOME=$2; ES_TIMEOUT=10; PATH="$3:/usr/bin"; ES_PACKAGE_ENV=\n'
              'unset XDG_CONFIG_HOME GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM; es_awk_proxy >"$ES_TMP/proxy.awk"\n'
              'es_test_spec=$4; es_spec_configs() { cat "$es_test_spec"; }\n'
              'ES_P_DIR=$ES_TMP/p/1; es_pid_init; probe_pkg_sources 5>"$ES_TMP/ev1.txt"\n'
              'echo "after-pkg: $(ls "$ES_TMP/p/1" | tr "\\n" " ") | $(ls "$ES_TMP" | tr "\\n" " ")"\n'
              'ES_P_DIR=$ES_TMP/p/2; ES_CN=0; probe_net_proxy 5>"$ES_TMP/ev2.txt"\n'
              'echo "after-proxy: $(ls "$ES_TMP/p/2" | tr "\\n" " ") | $(ls "$ES_TMP" | tr "\\n" " ")"')
    proc = run_lib(lib, script, msys_path(tmp), msys_path(home), msys_path(STUBS / "git"), msys_path(spec),
                   env={"ES_STUB_GIT_LIST": msys_path(listing), "ES_STUB_LOG": "", "ES_STUB_GIT_OLD": ""})
    assert proc.returncode == 0, proc.stderr
    after_pkg = next(line for line in proc.stdout.splitlines() if line.startswith("after-pkg: "))
    pdir_files, tmp_files = (part.split() for part in after_pkg[len("after-pkg: "):].split("|"))
    assert not [f for f in pdir_files if f in RAW or f.endswith((".out", ".err"))], pdir_files
    assert "gitconfig.txt" not in tmp_files and "pkg_proxy.tsv" in tmp_files, tmp_files
    after_proxy = next(line for line in proc.stdout.splitlines() if line.startswith("after-proxy: "))
    pdir_files, tmp_files = (part.split() for part in after_proxy[len("after-proxy: "):].split("|"))
    assert "sys.tsv" not in pdir_files and "pkg_proxy.tsv" not in tmp_files, after_proxy
    # the report still gets the (redacted at render) proxy setting from pkg_proxy.tsv
    assert "proxy.corp:8080" in (tmp / "ev2.txt").read_text(encoding="utf-8")


def test_a_signal_removes_the_temp_directory(built: Path, tmp_path: Path) -> None:
    """Review E: SIGTERM while a probe runs: the INT/TERM/HUP trap stops the probe and removes
    the private temp directory (with every raw file in it)."""
    tmpd, out = tmp_path / "t", tmp_path / "out"
    tmpd.mkdir()
    out.mkdir()
    script = ('"$1" "$2" --only hw.gpu --timeout 60 --out "$3" >/dev/null 2>&1 & p=$!\n'
              'i=0; while [ $i -lt 200 ] && ! ls -d "$4"/envscan.*/p/*/c*.out >/dev/null 2>&1; do sleep 0.1; i=$((i + 1)); done\n'
              'kill -TERM $p; wait $p; echo "rc=$?"')
    env = {**os.environ, "TMPDIR": msys_path(tmpd),
           "PATH": str(STUBS / "hang") + os.pathsep + os.environ.get("PATH", "")}
    proc = subprocess.run([str(DASH), "-c", script, "sig-test", msys_path(DASH), msys_path(built / "dist" / "envscan.sh"),
                           msys_path(out), msys_path(tmpd)], capture_output=True, text=True, timeout=180,
                          stdin=subprocess.DEVNULL, env=env)
    assert "rc=2" in proc.stdout, (proc.stdout, proc.stderr)
    assert list(tmpd.iterdir()) == []


def test_net_proxy_names_the_package_manager(lib: Path, tmp_path: Path) -> None:
    """Parity with ps: net.proxy package_managers[].tool is the manager (npm, pip, git), not the
    file's base name (.npmrc)."""
    home, tmp = tmp_path / "home", tmp_path / "t"
    for d in (tmp / "p" / "1", tmp / "p" / "2"):
        d.mkdir(parents=True)
    _write(home / ".npmrc", "proxy=http://proxy.corp:8080\n")
    _write(home / ".config" / "pip" / "pip.conf", "[global]\nproxy = http://pipproxy.corp:3128\n")
    gitconfig = msys_path(home / ".gitconfig")
    listing = _write(tmp_path / "list.tsv", f"file:{gitconfig}\thttp.proxy=http://gitproxy.corp:3128\n")
    spec = _write(tmp_path / "configs.spec", "npmrc.user\tnpm\tall\tuser\tcontent\t16384\t-\t~/.npmrc\n"
                  "pip.user\tpip\tall\tuser\tcontent\t16384\t-\t~/.config/pip/pip.conf\n")
    script = ('ES_TMP=$1; ES_ROOT=; ES_OS=linux; HOME=$2; ES_TIMEOUT=10; PATH="$3:/usr/bin"; ES_PACKAGE_ENV=\n'
              'unset XDG_CONFIG_HOME GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM; es_awk_proxy >"$ES_TMP/proxy.awk"\n'
              'es_test_spec=$4; es_spec_configs() { cat "$es_test_spec"; }\n'
              'ES_P_DIR=$ES_TMP/p/1; es_pid_init; probe_pkg_sources 5>"$ES_TMP/ev1.txt"\n'
              'ES_P_DIR=$ES_TMP/p/2; ES_CN=0; probe_net_proxy 5>"$ES_TMP/ev2.txt"; cat "$ES_TMP/ev2.txt"')
    proc = run_lib(lib, script, msys_path(tmp), msys_path(home), msys_path(STUBS / "git"), msys_path(spec),
                   env={"ES_STUB_GIT_LIST": msys_path(listing), "ES_STUB_LOG": "", "ES_STUB_GIT_OLD": ""})
    assert proc.returncode == 0, proc.stderr
    block = proc.stdout.split("[\tpackage_managers")[1].split("\n]")[0]
    tools = [line.split("\t")[2] for line in block.splitlines() if line.startswith("s\ttool\t")]
    assert tools == ["npm", "pip", "git"], block


def test_links_into_credential_stores_are_never_followed(lib: Path, tmp_path: Path) -> None:
    """Round 3 (HIGH): es_cred_path checked the text only, so ~/.pip -> ~/.aws read
    ~/.aws/pip.conf and ~/.m2/repository -> ~/.aws listed ~/.aws. Every link target is checked,
    with or without network mounts: such a path is left out (ES_CREDSKIP) and never tested."""
    home = tmp_path / "home"
    _write(home / ".aws" / "pip.conf", "[global]\nindex-url = https://AwsCanary9@pypi.corp/\n")
    _write(home / "dotfiles" / "npmrc", "registry=https://nexus.corp/\n")
    _link(lib, home / ".aws", home / ".pip")
    _link(lib, home / ".aws", home / ".m2" / "repository")
    _link(lib, home / "dotfiles" / "npmrc", home / ".npmrc")
    script = ('ES_ROOT=; HOME=$1; ES_NETMNTS=\n'
              'for p in "~/.pip/pip.conf" "~/.p*/pip.conf" "~/.m2/repository" "~/.m2/*" "~/.npmrc"; do\n'
              '  es_expand "$p" && printf "%s => %s\n" "$p" "$(printf "%s" "$ES_X" | tr "\n" " ")" || echo "$p => none"\n'
              'done\n'
              'es_ltest -f "$1/.pip/pip.conf" && echo ltest=yes || echo ltest=no\n'
              'printf "cred=%s\n" "$(printf "%s" "$ES_CREDSKIP" | sort -u | tr "\n" " ")"\n'
              'printf "net=%s\n" "$ES_NETSKIP"')
    h = msys_path(home)
    out = sh(lib, script, h).splitlines()
    assert out[:4] == ["~/.pip/pip.conf => none", "~/.p*/pip.conf => none", "~/.m2/repository => none",
                       "~/.m2/* => none"], out
    assert out[4] == f"~/.npmrc => {h}/.npmrc ", out
    assert "ltest=no" in out
    # ~/.p*/pip.conf: the directory ~/.pip is checked before it is entered
    assert f"cred={h}/.m2/repository {h}/.pip {h}/.pip/pip.conf " in out, out
    assert "net=" in out


def test_a_link_into_a_credential_store_is_noted_and_the_probe_partial(lib: Path, tmp_path: Path) -> None:
    """pkg.caches: ~/.m2/repository -> ~/.aws is not listed; the probe notes
    "<path> not read: link to a credential store" and is partial."""
    home, pdir = tmp_path / "home", tmp_path / "p"
    pdir.mkdir()
    _write(home / ".aws" / "credentials", "[default]\naws_secret_access_key = AwsCanary9\n")
    _write(home / ".npm" / "_cacache" / "index", "x\n")
    _link(lib, home / ".aws", home / ".m2" / "repository")
    spec = _write(tmp_path / "caches.spec", "maven\tmvn\t~/.m2/repository\nnpm\tnpm\t~/.npm/_cacache\n")
    script = ('ES_ROOT=; HOME=$1; ES_NETMNTS=; ES_P_DIR=$2; ES_CN=0; ES_NETSKIP=; ES_CREDSKIP=\n'
              'es_test_spec=$3; es_spec_caches() { cat "$es_test_spec"; }\n'
              'probe_pkg_caches 5>"$ES_P_DIR/ev.txt"\n'
              '[ -n "$ES_NETSKIP$ES_CREDSKIP" ] && es_netskip_note\n'
              'cat "$ES_P_DIR/ev.txt"; echo "status=$(cat "$ES_P_DIR/status")"; cat "$ES_P_DIR/notes"')
    out = sh(lib, script, msys_path(home), msys_path(pdir), msys_path(spec))
    assert "status=partial" in out, out
    assert f"{msys_path(home)}/.m2/repository not read: link to a credential store" in out, out
    assert "_cacache" in out and "\tmaven" not in out, out


def test_cygwin_network_paths_are_never_touched(lib: Path, tmp_path: Path) -> None:
    """Round 3 (MEDIUM): under Cygwin/MSYS //server/share/... and a mapped network drive
    (/proc/registry/HKEY_CURRENT_USER/Network/<letter>: /z/..., /cygdrive/z/...) count as
    network paths, with or without a mount table."""
    root = tmp_path / "root"
    (root / "proc" / "registry" / "HKEY_CURRENT_USER" / "Network" / "Z").mkdir(parents=True)
    script = ('ES_ROOT=$1; es_netmnts_early\n'
              'for p in //server/share/pip.conf "$2" /z/pip.conf /cygdrive/z/x /Z/y /c/x /zz/x; do\n'
              '  es_local_path "$p" && printf "%s local\\n" "$p" || printf "%s network\\n" "$p"\n'
              'done\n'
              'es_ltest -e //server/share/f; printf "skip=%s\n" "$ES_NETSKIP"\n'
              'mkdir -p "$1/tmp"; printf "x\t/\text4\trw\n" >"$1/tmp/mounts.tsv"; ES_TMP=$1/tmp; es_netmnts_init\n'
              'es_local_path /cygdrive/z/x && echo "init local" || echo "init network"')
    out = sh(lib, script, msys_path(root), "\\\\server\\share\\x").splitlines()
    assert out[:7] == ["//server/share/pip.conf network", "\\\\server\\share\\x network", "/z/pip.conf network",
                       "/cygdrive/z/x network", "/Z/y network", "/c/x local", "/zz/x local"], out
    assert "skip=//server/share/f" in out
    assert "init network" in out


@pytest.mark.parametrize("reexec", ["", "crlf"])
def test_crlf_dir_from_the_environment_is_never_removed(built: Path, tmp_path: Path, reexec: str) -> None:
    """Round 3 (LOW): ENVSCAN_CRLF_DIR was taken from the environment and given to rm -rf at
    exit. It is trusted only in the CRLF re-exec child and only when it is the directory of the
    running script (the copy the parent made); a directory named in the environment survives."""
    victim = tmp_path / "envscan-crlf.4242"
    _write(victim / "keep.txt", "precious\n")
    out = tmp_path / "out"
    out.mkdir()
    env = {**os.environ, "ENVSCAN_CRLF_DIR": msys_path(victim), "ENVSCAN_REEXEC": reexec}
    proc = subprocess.run([str(DASH), str(built / "dist" / "envscan.sh"), "--only", "os.identity", "--out", str(out)],
                          capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL, env=env)
    assert proc.returncode in (0, 1), proc.stderr
    assert (victim / "keep.txt").is_file()
