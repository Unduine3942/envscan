"""Unit tests of envscan.sh library functions, sourced into dash (build/lib/envscan-lib.sh)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sh_helpers import FIXTURES, STUBS, msys_path, needs_msys, run_lib

pytestmark = [pytest.mark.integration, needs_msys]


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def sh(lib: Path, script: str, *args: str) -> str:
    proc = run_lib(lib, script, *args)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.mark.parametrize("value,expected", [
    ("a\nb\tc\rd", "a b c d"),
    ("# heading", " # heading"),
    ("- item", " - item"),
    ("-x and #y", "-x and #y"),
    ("plain", "plain"),
])
def test_oneline_keeps_brief_values_on_one_line(lib: Path, value: str, expected: str) -> None:
    assert sh(lib, 'es_oneline "$1"; printf "[%s]" "$ES_T"', value) == f"[{expected}]"


@pytest.mark.parametrize("path,expected", [
    ("/no/such//dir/./x/../y/", "/no/such/dir/y"),
    ("/", "/"),
    ("relative/x", "relative/x"),
])
def test_resolve_normalises_paths(lib: Path, path: str, expected: str) -> None:
    assert sh(lib, 'ES_NETMNTS=; es_resolve "$1"; printf "%s" "$ES_RPATH"', path) == expected


def test_network_mount_checks_are_textual(lib: Path) -> None:
    script = (
        'ES_NETMNTS="/net/home$ES_NL/mnt/auto$ES_NL"\n'
        'for p in /net/home/u/.npmrc /net/homework /mnt/auto /usr/bin; do\n'
        '  if es_local_path "$p"; then printf "%s local\n" "$p"; else printf "%s network %s\n" "$p" "$ES_RPATH"; fi\n'
        'done\n'
        'es_netmnt_under /net && printf "under /net\n"\n'
        'es_netmnt_under /opt || printf "not under /opt\n"\n'
    )
    assert sh(lib, script).splitlines() == [
        "/net/home/u/.npmrc network /net/home/u/.npmrc",
        "/net/homework local",
        "/mnt/auto network /mnt/auto",
        "/usr/bin local",
        "under /net",
        "not under /opt",
    ]


def test_dedup_last_keeps_first_position_and_last_value(lib: Path, tmp_path: Path) -> None:
    f = tmp_path / "kv.tsv"
    f.write_bytes(b"a\t1\nb\t2\na\t3\n")
    from sh_helpers import msys_path
    assert sh(lib, 'es_dedup_last "$1"; cat "$1"', msys_path(f)) == "a\t3\nb\t2\n"


@pytest.mark.parametrize("data,expected,note", [
    # killed while awk wrote to fd 5: the last line has no line break (a cut-off value)
    (b"[\tlist\ns\t-\tone\n{\t-\ns\tname\tab", {"list": ["one", {}]}, "incomplete data line was dropped"),
    (b"{\tobj\ns\tkey\tvalue\n{\tne", {"obj": {"key": "value"}}, "incomplete data line was dropped"),
    # stopped between events: only closers are missing
    (b"[\tlist\ns\t-\tone\n", {"list": ["one"]}, "probe data is incomplete"),
    (b"s\tk\tv\n", {"k": "v"}, None),
])
def test_ev_check_keeps_later_probes_out_of_a_stopped_probe(lib: Path, tmp_path: Path, data: bytes,
                                                            expected: dict, note: str | None) -> None:
    """Review finding 5: the closers of a stopped probe are never glued onto a cut-off line, so the
    next probe does not end up inside the stopped probe's data."""
    probe = tmp_path / "p" / "1"
    probe.mkdir(parents=True)
    (probe / "data.ev").write_bytes(data)
    (tmp_path / "report.ev").write_bytes(
        f"{{\t-\n{{\tprobes\n{{\tp1\n{{\tdata\n@\t{msys_path(probe / 'data.ev')}\n}}\n}}\n"
        "{\tp2\ns\tstatus\tok\n}\n}\n}\n".encode("ascii"))
    script = ('ES_TMP=$1; ES_REDACT=1; es_awk_program >"$ES_TMP/json.awk"\n'
              'es_ev_check "$ES_TMP/p/1" && es_awk json "$ES_TMP/report.ev"\n')
    doc = json.loads(sh(lib, script, msys_path(tmp_path)))
    assert doc == {"probes": {"p1": {"data": expected}, "p2": {"status": "ok"}}}
    assert (probe / "data.ev").read_bytes().endswith(b"\n")
    notes = (probe / "notes").read_text(encoding="ascii") if (probe / "notes").exists() else ""
    assert (note in notes) if note else notes == ""


def _stub_tree(root: Path, rels: tuple[str, ...]) -> Path:
    """Executable stubs that log their own path to root/ran.log when run."""
    body = f'#!/bin/sh\nprintf "%s\\n" "$0" >>"{msys_path(root / "ran.log")}"\necho "stub 9.9.9"\n'
    for rel in rels:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="ascii", newline="\n")
    return root


def test_shims_are_recognised_by_their_own_directory(lib: Path, tmp_path: Path) -> None:
    """Review finding 1: a shim directory is recognised however the file was found: a PATH entry
    with a trailing slash, a doubled slash, or a spec directory that is not on PATH (rustup
    proxies in ~/.cargo/bin, found in cron or CI shells)."""
    home = _stub_tree(tmp_path / "home", (".pyenv/shims/python3", ".cargo/bin/rustc", ".cargo/bin/cargo",
                                          ".cargo/bin/rustup", "tools/bin/node", "plain/.cargo/bin/rustc"))
    script = (
        'ES_TMP=$1; HOME=$2; ES_OS=linux; ES_F_wsl=false; ES_NETMNTS=\n'
        'PATH="$HOME/.pyenv/shims/:$HOME/tools/bin//:$PATH"\n'
        'es_shim_init\n'
        'for t in python3 node; do es_which "$t"; if es_runnable "$ES_W"; then echo "$t run"; else echo "$t skip $ES_WHY"; fi; done\n'
        'for p in "$HOME/.cargo/bin/rustc" "$HOME/.cargo/bin//cargo/" "$HOME/.cargo/bin/rustup" '
        '"$HOME/plain/.cargo/bin/rustc"; do\n'
        '  if es_runnable "${p%/}"; then echo "$p run"; else echo "$p skip $ES_WHY"; fi\n'
        'done\n'
        'printf "%s" "$ES_SHIM_DIRS" | tr "\\t" " "\n'
    )
    out = sh(lib, script, msys_path(tmp_path), msys_path(home)).splitlines()
    h = msys_path(home)
    assert out == [
        "python3 skip version-manager shim (pyenv, not executed)",
        "node run",
        f"{h}/.cargo/bin/rustc skip version-manager shim (rustup, not executed)",
        f"{h}/.cargo/bin//cargo/ skip version-manager shim (rustup, not executed)",
        f"{h}/.cargo/bin/rustup skip version-manager shim (rustup, not executed)",
        f"{h}/plain/.cargo/bin/rustc run",
        f"{h}/.pyenv/shims pyenv",
    ]
    assert not (tmp_path / "home" / "ran.log").exists()


def test_children_run_in_the_c_locale(lib: Path, tmp_path: Path) -> None:
    """Review finding 13: output that is parsed must not depend on the user's locale (a German
    id prints "Gruppen="); only the locale probe asks for the user's locale (ES_CHILD_LOCALE)."""
    script = (
        'ES_TMP=$1; es_pid_init\n'
        'ES_ORIG_LC_ALL_SET=x; ES_ORIG_LC_ALL=de_DE.UTF-8; LC_ALL=C; export LC_ALL\n'
        'es_exec 10 "$ES_TMP/a.out" "$ES_TMP/a.err" env; grep "^LC_ALL=" "$ES_TMP/a.out"\n'
        'ES_CHILD_LOCALE=user; es_exec 10 "$ES_TMP/b.out" "$ES_TMP/b.err" env; grep "^LC_ALL=" "$ES_TMP/b.out"\n'
        'ES_ORIG_LC_ALL_SET=; es_exec 10 "$ES_TMP/c.out" "$ES_TMP/c.err" env; grep -c "^LC_ALL=" "$ES_TMP/c.out"\n'
    )
    proc = run_lib(lib, script, msys_path(tmp_path))
    assert proc.stdout.splitlines() == ["LC_ALL=C", "LC_ALL=de_DE.UTF-8", "0"], proc.stderr


VERSION_OUTPUTS = {
    # review finding 11: the JVM prints "Picked up ..." before the version
    "java": ('Picked up JAVA_TOOL_OPTIONS: -Dhttps.protocols=TLSv1.2\nopenjdk version "17.0.9" 2023-10-17\n',
             "17.0.9", 'openjdk version "17.0.9" 2023-10-17', "-"),
    "jdk": ("NOTE: Picked up JDK_JAVA_OPTIONS: -Dx=1.5\nPicked up _JAVA_OPTIONS: -Xmx1g -Dv=2.0\n"
            'openjdk version "21.0.1" 2023-10-17\n', "21.0.1", 'openjdk version "21.0.1" 2023-10-17', "-"),
    # review finding 12: loader errors are not versions
    "node": ("/usr/bin/node: /lib64/libstdc++.so.6: version `GLIBCXX_3.4.21' not found (required by /usr/bin/node)\n",
             "-", "/usr/bin/node: /lib64/libstdc++.so.6: version `GLIBCXX_3.4.21' not found (required by /usr/bin/node)",
             "loader"),
    "py": ("python3: error while loading shared libraries: libpython3.11.so.1.0: cannot open shared object file\n",
           "-", "python3: error while loading shared libraries: libpython3.11.so.1.0: cannot open shared object file",
           "loader"),
    "musl": ("Error loading shared library libssl.so.3: No such file or directory (needed by /usr/bin/x)\n", "-",
             "Error loading shared library libssl.so.3: No such file or directory (needed by /usr/bin/x)", "loader"),
    "git": ("git version 2.43.0\n", "2.43.0", "git version 2.43.0", "-"),
}


def test_versions_skip_jvm_banners_and_recognise_loader_errors(lib: Path, tmp_path: Path) -> None:
    for name, (text, *_rest) in VERSION_OUTPUTS.items():
        (tmp_path / f"{name}.out").write_text(text, encoding="ascii", newline="\n")
    out = sh(lib, 'cd "$1" && es_versions *.out | sort', msys_path(tmp_path))
    rows = {line.split("\t")[0]: line.split("\t")[1:] for line in out.splitlines()}
    for name, (_text, version, line, status) in VERSION_OUTPUTS.items():
        assert rows[f"{name}.out"] == [version, line, status], name


PEM = ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\nKEYFRAG9f3c=AAAAC3NzaC1lZDI1NTE5\n"
       "-----END OPENSSH PRIVATE KEY-----")


@pytest.mark.parametrize("lc_all", ["", "de_DE.UTF-8"])
def test_env_capture_takes_names_from_the_environment(lib: Path, lc_all: str) -> None:
    """Review finding 2: lines of a multi-line value that look like NAME=value (a PEM key) never
    become variables; values are escaped; LC_ALL is reported as it was before the scan set it."""
    script = (f'ES_ORIG_LC_ALL_SET={"x" if lc_all else ""}; ES_ORIG_LC_ALL={lc_all}; LC_ALL=C; export LC_ALL\n'
              'es_env_capture\nprintf "%s\\n" "$ES_ENV_ORIG"\n')
    proc = run_lib(lib, script, env={"SSH_PRIVATE_KEY": PEM, "PLAIN_VAR": "a\tb\\c", "LC_ALL": "C"})
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    names = [line.split("\t", 1)[0] for line in lines]
    assert names == sorted(names)
    assert not any(n.startswith(("b3Bl", "KEYFRAG", "-----")) for n in names), names
    values = dict(line.split("\t", 1) for line in lines)
    assert values["SSH_PRIVATE_KEY"] == PEM.replace("\n", "\\n")
    assert values["PLAIN_VAR"] == "a\\tb\\\\c"
    assert values.get("LC_ALL") == (lc_all or None)
    assert "ENVSCAN_LC_ORIG" not in values


@pytest.mark.parametrize("text,expected", [
    ("http_proxy=http://p.corp:3128", "p.corp:3128"),
    ("https://proxy.corp:8443/path?x=y", "proxy.corp:8443"),
    ("proxy.corp:3128", "proxy.corp:3128"),
    ("socks5://s.corp", "s.corp:1080"),
])
def test_hostport_keeps_urls_with_equals_signs(lib: Path, text: str, expected: str) -> None:
    assert sh(lib, 'es_hostport "$1"; printf "%s" "$ES_T"', text) == expected


PROXY_INPUT = """\
/h/.npmrc\tregistry=https://nexus.corp/repository/npm-proxy/
/h/.npmrc\thttps-proxy=http://bob:pw@proxy.corp:8080/
/h/.npmrc\tnoproxy=.corp
/h/.npmrc\tproxy = http://proxy.corp:3128
/etc/apt/apt.conf\tAcquire::http::Proxy "http://aptproxy.corp:3142";
/h/.yarnrc\thttps-proxy "http://yarnproxy.corp:8080"
/h/.condarc\tchannel_alias: https://nexus.corp/repository/conda-proxy
/h/.condarc\tproxy_servers:
/h/.condarc\t  http: http://condaproxy.corp:8080
/h/.condarc\t  https: https://condaproxy.corp:8443
/h/.condarc\tssl_verify: true
/h/.m2/settings.xml\t<settings>
/h/.m2/settings.xml\t  <!-- <proxy><host>old.corp</host></proxy> -->
/h/.m2/settings.xml\t  <proxies>
/h/.m2/settings.xml\t    <proxy>
/h/.m2/settings.xml\t      <id>corp</id>
/h/.m2/settings.xml\t      <protocol>http</protocol>
/h/.m2/settings.xml\t      <host>mvnproxy.corp</host>
/h/.m2/settings.xml\t      <port>8081</port>
/h/.m2/settings.xml\t      <username>bob</username>
/h/.m2/settings.xml\t      <password>pw</password>
/h/.m2/settings.xml\t      <nonProxyHosts>localhost|*.corp</nonProxyHosts>
/h/.m2/settings.xml\t    </proxy>
/h/.m2/settings.xml\t  </proxies>
/h/.m2/settings.xml\t  <mirrors><mirror><url>https://nexus.corp/repository/maven-proxy/</url></mirror></mirrors>
/h/.m2/settings.xml\t</settings>
/h/gradle.properties\tsystemProp.https.proxyHost=gradleproxy.corp
/h/gradle.properties\tsystemProp.https.proxyPort=8443
/h/gradle.properties\tsystemProp.https.proxyPassword=pw
/etc/docker/daemon.json\t{
/etc/docker/daemon.json\t  "proxies": {
/etc/docker/daemon.json\t    "http-proxy": "http://dockerproxy.corp:3128",
/etc/docker/daemon.json\t    "no-proxy": "*.corp"
/etc/docker/daemon.json\t  },
/etc/docker/daemon.json\t  "registry-mirrors": ["https://nexus.corp/repository/docker-proxy"]
/etc/docker/daemon.json\t}
/h/NuGet.Config\t<add key="nuget-proxy" value="https://nexus.corp/repository/nuget-proxy/index.json" />
/h/NuGet.Config\t<add key="http_proxy" value="http://nugetproxy.corp:8080" />
/h/NuGet.Config\t<add key="http_proxy.password" value="pw" />
git:file:/h/.gitconfig\turl.https://nexus.corp/repository/github-proxy/.insteadof=https://github.com/
git:file:/h/.gitconfig\thttp.proxy=http://gitproxy.corp:3128
/h/.cargo/config.toml\t[http]
/h/.cargo/config.toml\tproxy = "cargoproxy.corp:8080"
/h/pip.conf\t# proxy = http://commented.corp:1
/h/pip.conf\tproxy=pipproxy.corp
/etc/environment\tPIP_INDEX_URL=https://nexus.corp/repository/pypi-proxy/simple
/etc/environment\texport http_proxy="http://envproxy.corp:3128"  # corporate
"""

PROXY_EXPECTED = [
    ("/h/.npmrc", "proxy", "proxy.corp:8080", "https-proxy", "http://bob:pw@proxy.corp:8080/"),
    ("/h/.npmrc", "exclusion", "-", "noproxy", ".corp"),
    ("/h/.npmrc", "proxy", "proxy.corp:3128", "proxy", "http://proxy.corp:3128"),
    ("/etc/apt/apt.conf", "proxy", "aptproxy.corp:3142", "Acquire::http::Proxy", "http://aptproxy.corp:3142"),
    ("/h/.yarnrc", "proxy", "yarnproxy.corp:8080", "https-proxy", "http://yarnproxy.corp:8080"),
    ("/h/.condarc", "proxy", "condaproxy.corp:8080", "proxy_servers.http", "http://condaproxy.corp:8080"),
    ("/h/.condarc", "proxy", "condaproxy.corp:8443", "proxy_servers.https", "https://condaproxy.corp:8443"),
    ("/h/.m2/settings.xml", "exclusion", "-", "proxies.proxy.nonProxyHosts", "localhost|*.corp"),
    ("/h/.m2/settings.xml", "proxy", "mvnproxy.corp:8081", "proxies.proxy", "http://mvnproxy.corp:8081"),
    ("/h/gradle.properties", "proxy", "gradleproxy.corp:8443", "systemProp.https.proxyHost", "gradleproxy.corp"),
    ("/h/gradle.properties", "other", "-", "systemProp.https.proxyPort", "8443"),
    ("/etc/docker/daemon.json", "proxy", "dockerproxy.corp:3128", "proxies.http-proxy", "http://dockerproxy.corp:3128"),
    ("/etc/docker/daemon.json", "exclusion", "-", "proxies.no-proxy", "*.corp"),
    ("/h/NuGet.Config", "proxy", "nugetproxy.corp:8080", "http_proxy", "http://nugetproxy.corp:8080"),
    ("git:file:/h/.gitconfig", "proxy", "gitproxy.corp:3128", "http.proxy", "http://gitproxy.corp:3128"),
    ("/h/.cargo/config.toml", "proxy", "cargoproxy.corp:8080", "proxy", "cargoproxy.corp:8080"),
    ("/h/pip.conf", "proxy", "pipproxy.corp:80", "proxy", "pipproxy.corp"),
    ("/etc/environment", "proxy", "envproxy.corp:3128", "http_proxy", "http://envproxy.corp:3128"),
]


def test_proxy_settings_are_found_by_their_key(lib: Path, tmp_path: Path) -> None:
    """Review findings 10 and 3: a registry URL containing "proxy" is not a proxy, values are
    trimmed, blocks and host/port pairs fold into one proxy, credentials never come out."""
    source = tmp_path / "lines.txt"
    source.write_text(PROXY_INPUT, encoding="ascii", newline="\n")
    out = sh(lib, 'ES_TMP=$1; es_awk_proxy >"$ES_TMP/proxy.awk" && es_proxy_settings "$2"',
             msys_path(tmp_path), msys_path(source))
    rows = [tuple(line.split("\t")) for line in out.splitlines()]
    assert [row[:5] for row in rows] == PROXY_EXPECTED
    assert rows[3][5] == 'Acquire::http::Proxy "http://aptproxy.corp:3142";'
    assert "pw" not in [row[4] for row in rows]


@pytest.mark.parametrize("text,mode,cap,match,expected", [
    # review finding 9: lines-mode matching ignores case (apt's "Acquire::http::Proxy")
    ('Acquire::http::Proxy "http://p:3142";\nAPT::Other "1";\n', "lines", "65536", "proxy|Verify-Peer",
     ['Acquire::http::Proxy "http://p:3142";']),
    # the byte cap counts the newlines between lines, as json.awk's config_lines does
    ("a=1\nb=2", "content", "7", "-", ["a=1", "b=2"]),
    ("a=1\nb=2", "content", "6", "-", ["a=1"]),
    ("# c\nc=3\n", "content", "0", "-", ["c=3"]),
])
def test_config_raw_keeps_the_lines_the_report_keeps(lib: Path, tmp_path: Path, text: str, mode: str, cap: str,
                                                      match: str, expected: list[str]) -> None:
    cfg = tmp_path / "cfg"
    cfg.write_text(text, encoding="ascii", newline="\n")
    out = sh(lib, 'ES_P_DIR=$1; es_config_raw "$2" "$3" "$4" "$5"; cut -f 2- "$ES_P_DIR/config_lines.txt"',
             msys_path(tmp_path), msys_path(cfg), mode, cap, match)
    assert out.splitlines() == expected


@pytest.mark.parametrize("path,unsafe", [
    ("/home/u", False),
    ("/home/u/.local", False),
    ("/home/u/Docs", True),
    ("/home/u/Docs/x", True),
    ("/home/u/Desktop", True),
    ("/opt", False),
])
def test_disabled_xdg_dirs_do_not_cover_home(lib: Path, path: str, unsafe: bool) -> None:
    """Review finding 7: XDG_DESKTOP_DIR="$HOME/" (a disabled XDG directory) and "/" must not
    make all of HOME a Desktop folder."""
    script = 'es_xdg_dirs; if es_unsafe_dir "$1"; then echo safe; else echo "unsafe: $ES_WHY"; fi'
    proc = run_lib(lib, script, path, env={"HOME": "/home/u", "XDG_CONFIG_HOME": "/nonexistent",
                                           "XDG_DESKTOP_DIR": "/home/u/", "XDG_DOCUMENTS_DIR": "/home/u//Docs/"})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("unsafe" if unsafe else "safe"), proc.stdout
    proc = run_lib(lib, script, path, env={"HOME": "/home/u", "XDG_CONFIG_HOME": "/nonexistent",
                                           "XDG_DESKTOP_DIR": "/", "XDG_DOCUMENTS_DIR": "/home"})
    assert proc.stdout.startswith("unsafe" if path.endswith("Desktop") else "safe"), proc.stdout


@pytest.mark.parametrize("states,expected", [
    ({"home": "not_writable", "opt": "writable"}, "true"),
    ({"home": "not_writable", "opt": "absent", "cwd": "not_writable"}, "false"),
    # skipped (network mount, Desktop/Documents/sync folder) or inconclusive: unknown, never false
    ({"home": "not_writable", "cwd": "skipped"}, ""),
    ({"home": "unknown", "opt": "not_writable"}, ""),
    ({"tmp": "writable", "home": "not_writable"}, "false"),
])
def test_install_verdict_is_false_only_when_every_candidate_was_tested(lib: Path, tmp_path: Path,
                                                                        states: dict[str, str], expected: str) -> None:
    """Review finding 7: the fs.no_writable_install_dir blocker needs a tested verdict."""
    loc = tmp_path / "loc.tsv"
    loc.write_text("".join(f"{i}\t/p/{i}\t-\t-\t-\t{s}\n" for i, s in states.items()), encoding="ascii", newline="\n")
    assert sh(lib, 'es_install_verdict "$1"; printf "[%s]" "$ES_T"', msys_path(loc)) == f"[{expected}]"


def test_python_candidates_skip_network_mounts(lib: Path, tmp_path: Path) -> None:
    """Review finding 8: the python3.N search must not list (glob) PATH entries or fixed
    locations on network or autofs mounts."""
    net, local, root = tmp_path / "net", tmp_path / "local", tmp_path / "root"
    for d in (net / "bin", local, root / "usr" / "local" / "bin"):
        d.mkdir(parents=True)
    for f in (net / "bin" / "python3.11", local / "python3.12", root / "usr" / "local" / "bin" / "python3"):
        f.write_text("#!/bin/sh\necho Python 3.0\n", encoding="ascii", newline="\n")
    script = ('ES_ROOT=$3; ES_NETMNTS="$1$ES_NL$3/usr/local$ES_NL"; PATH="$1/bin:$2:$PATH"; es_path_init\n'
              'es_python_cands; printf "%s" "$ES_T"')
    found = sh(lib, script, msys_path(net), msys_path(local), msys_path(root)).splitlines()
    assert f"{msys_path(local)}/python3.12" in found
    assert not [p for p in found if p.startswith((msys_path(net), msys_path(root)))], found


def test_exec_test_never_touches_network_mounts(lib: Path, tmp_path: Path) -> None:
    """Review finding 8: fs.exec_test (--deep) writes and runs a script only on local disks."""
    home, temp, pdir = tmp_path / "nethome", tmp_path / "nettmp", tmp_path / "p"
    for d in (home / ".local", home / "bin", temp, pdir):
        d.mkdir(parents=True)
    script = ('ES_P_DIR=$1; ES_TMP=$2; HOME=$3; ES_NETMNTS="$2$ES_NL$3$ES_NL"; ES_TIMEOUT=5\n'
              'probe_fs_exec_test 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"')
    out = sh(lib, script, msys_path(pdir), msys_path(temp), msys_path(home))
    assert out.count("s\toutcome\tskipped") == 4, out
    assert "network or autofs mount" in out
    leftovers = [p for d in (home, home / ".local", home / "bin", temp) for p in d.iterdir()]
    assert sorted(leftovers) == sorted([home / ".local", home / "bin"])  # nothing was created


ROUTE_STUBS = {
    "missing": None,
    "no_default": "#!/bin/sh\necho 'route: writing to routing socket: not in table' >&2\nexit 1\n",
    "gateway": "#!/bin/sh\nprintf '   route to: default\ndestination: default\n    gateway: 10.1.2.1\n  interface: en0\n'\n",
    "broken": "#!/bin/sh\necho 'route: bad option' >&2\nexit 64\n",
}


@pytest.mark.parametrize("stub,expected,partial", [
    ("missing", "z\tdefault_route", True),
    ("no_default", "b\tdefault_route\tfalse", False),
    ("gateway", "b\tdefault_route\ttrue", False),
    ("broken", "z\tdefault_route", True),
])
def test_routes_without_a_route_command_are_unknown(lib: Path, tmp_path: Path, stub: str, expected: str,
                                                    partial: bool) -> None:
    """Review finding 14: a missing or failing route command is not "no default route"."""
    stubs, root, pdir = tmp_path / "stubs", tmp_path / "root", tmp_path / "p"
    for d in (stubs, root, pdir):
        d.mkdir()
    if ROUTE_STUBS[stub]:
        (stubs / "route").write_text(ROUTE_STUBS[stub], encoding="ascii", newline="\n")
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_ROOT=$2; ES_OS=darwin; ES_TIMEOUT=10; PATH="$3:/usr/bin"; es_pid_init\n'
              'probe_net_routes 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"; echo "status=$(cat "$ES_P_DIR/status" 2>/dev/null)"')
    out = sh(lib, script, msys_path(pdir), msys_path(root), msys_path(stubs))
    assert expected in out.splitlines(), out
    assert ("status=partial" in out) is partial, out


def parse_items(events: str) -> list[dict[str, object]]:
    """The "{ -" ... "}" items of a probe's event stream: s/n/b values, z as None, lists."""
    items: list[dict[str, object]] = []
    item: dict[str, object] | None = None
    current: list[str] | None = None
    for line in events.splitlines():
        kind, _, rest = line.partition("\t")
        if line == "{\t-":
            item = {}
        elif line == "}" and item is not None:
            items.append(item)
            item = None
        elif item is not None and kind == "[":
            current = []
            item[rest] = current
        elif item is not None and kind == "]":
            current = None
        elif item is not None and current is not None and kind == "s":
            current.append(rest.split("\t", 1)[1])
        elif item is not None and kind in ("s", "n", "b"):
            key, _, value = rest.partition("\t")
            item[key] = value
        elif item is not None and kind == "z":
            item[rest] = None
    return items


def test_reachability_never_contacts_public_or_metadata_hosts(lib: Path, tmp_path: Path) -> None:
    """Review finding 15: public registries are not looked up, cloud metadata and link-local
    hosts are neither looked up nor contacted (also when a name resolves to one), and the TCP
    check connects to the vetted address, never to the name."""
    log, pdir = tmp_path / "stub.log", tmp_path / "p"
    pdir.mkdir()
    proxies = ["proxy.corp:3128", "METADATA.google.internal:80", "169.254.169.254:80", "rebind.corp:8080",
               "registry.npmjs.org:443", "[fd00::25]:3128", "v6only.corp:3128", "2852039166:80"]
    # multi-line values go through files: a Windows command line does not carry line breaks to MSYS
    (tmp_path / "proxies.txt").write_text("\n".join(proxies) + "\n", encoding="ascii", newline="\n")
    (tmp_path / "mirrors.txt").write_text("https://nexus.corp/repository/npm-proxy/\n", encoding="ascii", newline="\n")
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_OS=linux; ES_TIMEOUT=10; ES_DEADLINE=99999999999999; PATH="$2:/usr/bin"\n'
              'es_pid_init; ES_F_proxy_hosts=$(cat "$3/proxies.txt"); ES_F_endpoints_internal=$(cat "$3/mirrors.txt")\n'
              'probe_net_reachability 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"\n'
              'echo "status=$(cat "$ES_P_DIR/status" 2>/dev/null)"; sed "s/^/note: /" "$ES_P_DIR/notes"')
    # net-abs: the resolver answers absolute names only ("proxy.corp."); the single-label numeric
    # name 2852039166 is never looked up (hardening round 2026-11-15)
    proc = run_lib(lib, script, msys_path(pdir), msys_path(STUBS / "net-abs"), msys_path(tmp_path),
                   env={"ES_STUB_LOG": msys_path(log)})
    assert proc.returncode == 0, proc.stderr
    calls = log.read_text(encoding="ascii").splitlines()
    looked_up = sorted({c.split()[-1] for c in calls if c.startswith("getent")})
    # IP literals ([fd00::25]) are never handed to the resolver (review fix X4d)
    assert looked_up == ["nexus.corp.", "proxy.corp.", "rebind.corp.", "v6only.corp."], calls
    connects = sorted(c.split()[-1] for c in calls if c.startswith("curl"))
    assert connects == ["telnet://10.0.0.5:3128", "telnet://10.0.0.6:443", "telnet://[fd00::25]:3128",
                        "telnet://[fd00::25]:3128"], calls
    items = {f"{i['host']}:{i['port']}": i for i in parse_items(proc.stdout)}
    skipped = ("metadata.google.internal:80", "169.254.169.254:80", "rebind.corp:8080", "registry.npmjs.org:443",
               "2852039166:80")
    notes = [line[6:] for line in proc.stdout.splitlines() if line.startswith("note: ")]
    for target in skipped:
        # the shared contract: tcp "skipped" and a reason, no resolved/ms/error, one note per skip
        assert items[target]["tcp"] == "skipped" and items[target]["reason"], items[target]
        assert not {"resolved", "ms", "error"} & set(items[target]), items[target]
        assert [n for n in notes if n.startswith(f"skipped {target}: ")], notes
    assert "resolves to" in str(items["rebind.corp:8080"]["reason"])
    assert "status=\n" in proc.stdout  # skips leave the status alone
    proxy = items["proxy.corp:3128"]
    assert (proxy["tcp"], proxy["resolved"], proxy["error"], proxy["reason"]) == ("ok", ["10.0.0.5"], None, None)
    assert items["nexus.corp:443"]["source"] == "package source"


def event_list(events: str, name: str) -> list[str]:
    """The values of the top-level list NAME in a probe's event stream."""
    values: list[str] | None = None
    for line in events.splitlines():
        if line == f"[\t{name}":
            values = []
        elif values is not None and line == "]":
            return values
        elif values is not None and line.startswith("s\t-\t"):
            values.append(line[4:])
    return values or []


# /proc/net as a big-endian Linux (s390x, ppc64, sparc) prints the linux-basic fixture: IPv4
# words in network byte order instead of reversed
BIG_ENDIAN_PROC = {
    "route": ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
              "eth0\t00000000\t0A140001\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
              "eth0\t0A140000\t00000000\t0001\t0\t0\t100\tFFFF0000\t0\t0\t0\n"
              "tun0\t00000000\t00000000\t0001\t0\t0\t0\t80000000\t0\t0\t0\n"
              "tun0\t80000000\t00000000\t0001\t0\t0\t0\t80000000\t0\t0\t0\n"),
    "tcp": ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1\n"
            "   1: 7F000001:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 2 1\n"
            "   2: 0A140105:A2C4 0A140035:0035 01 00000000:00000000 00:00000000 00000000  1000        0 3 1\n"),
    "tcp6": ("  sl  local_address                         remote_address                        st\n"
             "   0: 00000000000000000000FFFF0A140105:2382 00000000000000000000000000000000:0000 0A 0\n"
             "   1: 00000000000000000000000000000001:0277 00000000000000000000000000000000:0000 0A 0\n"),
}


@pytest.mark.parametrize("order", ["little", "big"])
def test_proc_net_addresses_follow_the_byte_order(lib: Path, tmp_path: Path, order: str) -> None:
    """Review finding 18: /proc/net/route and tcp print IPv4 words in host byte order; a
    big-endian host is recognised by the ELF header of /proc/self/exe."""
    root, pdir = tmp_path / "root", tmp_path / "p"
    (root / "proc" / "self").mkdir(parents=True)
    pdir.mkdir()
    shutil.copytree(FIXTURES / "linux-basic" / "proc" / "net", root / "proc" / "net")
    elf = b"\x7fELF\x02" + (b"\x02" if order == "big" else b"\x01") + b"\x01" + bytes(9)
    (root / "proc" / "self" / "exe").write_bytes(elf)
    if order == "big":
        for name, text in BIG_ENDIAN_PROC.items():
            (root / "proc" / "net" / name).write_text(text, encoding="ascii", newline="\n")
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_ROOT=$2; ES_OS=linux; ES_UNAME_M=x86_64; ES_TIMEOUT=10; PATH=/usr/bin\n'
              'es_pid_init; { probe_net_routes; probe_net_listening; } 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"')
    out = sh(lib, script, msys_path(pdir), msys_path(root))
    assert event_list(out, "default_gateways") == ["10.20.0.1 dev eth0", "(on-link) dev tun0", "fe80:0:0:0:0:0:0:1 dev eth0"]
    assert event_list(out, "routes") == ["default via 10.20.0.1 dev eth0 metric 100", "10.20.0.0/16 dev eth0 metric 100",
                                         "0.0.0.0/1 dev tun0", "128.0.0.0/1 dev tun0"]
    listening = sorted((i["address"], int(str(i["port"]))) for i in parse_items(out) if "address" in i)
    assert listening == [("0.0.0.0", 8080), ("127.0.0.1", 5432), ("::1", 631), ("::ffff:10.20.1.5", 9090)]


def test_cache_counts_are_capped_and_marked_truncated(lib: Path, tmp_path: Path) -> None:
    """Review finding 19: entry counting stops at the cap and says so (truncated, a note)."""
    home, pdir = tmp_path / "home", tmp_path / "p"
    npm, pip = home / ".npm" / "_cacache", home / ".cache" / "pip"
    for d in (npm, pip, pdir):
        d.mkdir(parents=True)
    for name in ("a", "b", "c", "d", ".e"):
        (npm / name).mkdir()
    for name in ("x", ".y"):
        (pip / name).write_text("", encoding="ascii")
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_ROOT=; HOME=$2; ES_CACHE_CAP=3\n'
              'probe_pkg_caches 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"\n'
              'echo "truncated=$([ -f "$ES_P_DIR/truncated" ] && echo yes)"; cat "$ES_P_DIR/notes" 2>/dev/null || :')
    out = sh(lib, script, msys_path(pdir), msys_path(home))
    caches = {str(i["path"]): i for i in parse_items(out)}
    npm_item, pip_item = caches[f"{msys_path(npm)}"], caches[f"{msys_path(pip)}"]
    assert (npm_item["entries"], npm_item["truncated"]) == ("3", "true"), out
    assert (pip_item["entries"], pip_item["truncated"]) == ("2", "false"), out
    assert "truncated=yes" in out
    assert "counted up to 3 per directory" in out


def test_endpoints_are_bases_without_metadata_or_loopback_hosts(lib: Path, tmp_path: Path) -> None:
    """Shared contract for pkg.sources.endpoints: scheme://host[:port] from the raw values, no
    userinfo or path; cloud metadata, link-local (net_never) and loopback hosts are dropped."""
    lines = tmp_path / "lines.txt"
    lines.write_text("".join(f"/h/.npmrc\t{text}\n" for text in (
        "registry=https://bob:pw@nexus.corp:8443/repository/npm/",
        "proxy=http://localhost:3128",
        "mirror=http://127.0.0.1:8080/x",
        "meta=http://169.254.169.254/latest",
        "meta2=http://METADATA.google.internal./computeMetadata",
        "v6=http://[::1]:9000/",
        "v6b=http://[fd00:ec2::254]/",
        "pub=https://registry.npmjs.org/",
    )), encoding="ascii", newline="\n")
    out = sh(lib, 'es_endpoints "$1"', msys_path(lines))
    assert out.splitlines() == ["internal\thttps://nexus.corp:8443", "public\thttps://registry.npmjs.org"]


def _git_config(lib: Path, tmp_path: Path, listing: list[str], *, old: bool = False,
                net: str = "", extra_env: dict[str, str] | None = None) -> dict[str, object]:
    """Run es_git_config with the stub git (tests/stubs/git). LISTING holds "origin TAB
    key=value" lines; "$HOME" in them is the test HOME. Returns the stub calls, the notes, the
    status and the lines read (gitconfig.txt)."""
    home, pdir, log = tmp_path / "home", tmp_path / "p", tmp_path / "git.log"
    pdir.mkdir()
    listing_file = tmp_path / "list.tsv"
    listing_file.write_text("".join(line.replace("$HOME", msys_path(home)) + "\n" for line in listing),
                            encoding="ascii", newline="\n")
    script = ('ES_P_DIR=$1; ES_TMP=$1; HOME=$2; ES_TIMEOUT=10; PATH="$3:/usr/bin"; es_pid_init\n'
              'ES_NETMNTS=${4:+$4$ES_NL}; unset XDG_CONFIG_HOME GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM\n'
              'es_git_config 5>"$ES_P_DIR/ev.txt"\n'
              'echo "status=$(cat "$ES_P_DIR/status" 2>/dev/null)"; sed "s/^/note: /" "$ES_P_DIR/notes" 2>/dev/null\n'
              'sed "s/^/line: /" "$ES_TMP/gitconfig.txt"; :')
    env = {"ES_STUB_LOG": msys_path(log), "ES_STUB_GIT_LIST": msys_path(listing_file),
           "ES_STUB_GIT_OLD": "1" if old else "", **(extra_env or {})}
    proc = run_lib(lib, script, msys_path(pdir), msys_path(home), msys_path(STUBS / "git"), net, env=env)
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    return {
        "calls": log.read_text(encoding="ascii").splitlines() if log.exists() else [],
        "notes": [line[6:] for line in lines if line.startswith("note: ")],
        "partial": "status=partial" in lines,
        "lines": [line[6:] for line in lines if line.startswith("line: ")],
    }


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii", newline="\n")
    return path


def test_git_local_include_is_followed_once(lib: Path, tmp_path: Path) -> None:
    """git runs with --no-includes; the scanner reads an unconditional include from a local
    path itself, one level deep (~/ from HOME, a relative path from the origin's directory),
    each file once; a missing include file is skipped silently, as git does."""
    home = tmp_path / "home"
    extra = _write(home / "inc" / "extra.gitconfig", "http.proxy=http://incproxy.corp:3128\n")
    rel = _write(home / "rel.gitconfig", "url.https://nexus.corp/git/.insteadof=https://github.com/\n")
    r = _git_config(lib, tmp_path, ["file:$HOME/.gitconfig\tuser.name=Bob",
                                     "file:$HOME/.gitconfig\tinclude.path=~/inc/extra.gitconfig",
                                     "file:$HOME/.gitconfig\tinclude.path=$HOME/inc/extra.gitconfig",
                                     "file:$HOME/.gitconfig\tinclude.path=rel.gitconfig",
                                     "file:$HOME/.gitconfig\tinclude.path=~/missing.gitconfig"])
    assert r["calls"] == ["git config --list --show-origin --no-includes",
                          f"git config --list --no-includes --file {msys_path(extra)}",
                          f"git config --list --no-includes --file {msys_path(rel)}"]
    assert f"file:{msys_path(extra)}\thttp.proxy=http://incproxy.corp:3128" in r["lines"]
    assert f"file:{msys_path(rel)}\turl.https://nexus.corp/git/.insteadof=https://github.com/" in r["lines"]
    assert (r["notes"], r["partial"]) == ([], False)


def test_git_includes_that_are_not_read_make_the_probe_partial(lib: Path, tmp_path: Path) -> None:
    """A network include is never touched; ~user/ and %(prefix)/ are not local paths; anything
    but a regular file is unreadable and never opened; an include inside an included file is
    not followed."""
    home, net = tmp_path / "home", tmp_path / "net"
    shared = _write(net / "shared.gitconfig", "http.proxy=http://netproxy.corp:3128\n")
    nested = _write(home / "nested.gitconfig", "core.editor=vi\ninclude.path=/srv/deeper.gitconfig\n")
    (home / "adir.gitconfig").mkdir(parents=True)
    _write(home / ".git-credentials", "https://bob:CredPw9@git.corp\n")
    r = _git_config(lib, tmp_path, ["file:$HOME/.gitconfig\tinclude.path=" + msys_path(shared),
                                     "file:$HOME/.gitconfig\tinclude.path=~bob/x.gitconfig",
                                     "file:$HOME/.gitconfig\tinclude.path=%(prefix)/etc/x.gitconfig",
                                     "command line:\tinclude.path=relative.gitconfig",
                                     "file:$HOME/.gitconfig\tinclude.path=~/adir.gitconfig",
                                     "file:$HOME/.gitconfig\tinclude.path=C:/shared/x.gitconfig",
                                     'file:"$HOME/caf\\303\\251/.gitconfig"\tinclude.path=quoted.gitconfig',
                                     "file:$HOME/.gitconfig\tinclude.path=~/.git-credentials",
                                     "file:$HOME/.gitconfig\tinclude.path=nested.gitconfig"], net=msys_path(net))
    assert r["notes"] == [f"git include not read (network path): {msys_path(shared)}",
                          "git include not read (not a local path): ~bob/x.gitconfig",
                          "git include not read (not a local path): %(prefix)/etc/x.gitconfig",
                          "git include not read (not a local path): relative.gitconfig",
                          f"git include not read (unreadable): {msys_path(home / 'adir.gitconfig')}",
                          "git include not read (not a local path): C:/shared/x.gitconfig",
                          "git include not read (not a local path): quoted.gitconfig",
                          f"git include not read (credential store): {msys_path(home / '.git-credentials')}",
                          "git include not read (nested include): /srv/deeper.gitconfig"]
    assert r["partial"] is True
    assert not [c for c in r["calls"] if "shared.gitconfig" in c or "deeper" in c or "adir" in c
                or "credentials" in c], r["calls"]
    assert f"file:{msys_path(nested)}\tcore.editor=vi" in r["lines"]


def test_git_network_home_is_never_read(lib: Path, tmp_path: Path) -> None:
    """A HOME on a network or autofs mount: git runs with an empty local HOME (the global
    configuration there is not read; a partial note says so) and a ~/ include, which names a
    file in the network HOME, is noted and never touched."""
    home, homes = tmp_path / "home", tmp_path / "homes.log"
    _write(home / "x.gitconfig", "http.proxy=http://homeproxy.corp:3128\n")
    r = _git_config(lib, tmp_path, ["file:/etc/gitconfig\tinclude.path=~/x.gitconfig"], net=msys_path(home),
                    extra_env={"ES_STUB_GIT_HOMES": msys_path(homes)})
    assert r["notes"] == [f"git home folder {msys_path(home)} is on a network path: global git configuration "
                          "from there is not read",
                          f"git include not read (network path): {msys_path(home / 'x.gitconfig')}"]
    assert r["partial"] is True
    assert r["calls"] == ["git config --list --show-origin --no-includes"]
    assert homes.read_text(encoding="ascii").split() == [msys_path(tmp_path / "p" / "githome")]


def test_git_conditional_include_is_only_noted(lib: Path, tmp_path: Path) -> None:
    """includeIf.<cond>.path is never read: a note with the condition, no status change, also
    inside an included file."""
    home = tmp_path / "home"
    _write(home / "work.gitconfig", "includeif.onbranch:main.path=branch.gitconfig\n")
    r = _git_config(lib, tmp_path, ["file:$HOME/.gitconfig\tincludeif.gitdir:~/work/.path=~/work.gitconfig",
                                     "file:$HOME/.gitconfig\tinclude.path=~/work.gitconfig"])
    assert r["notes"] == ["git include not read (condition gitdir:~/work/): ~/work.gitconfig",
                          "git include not read (condition onbranch:main): branch.gitconfig"]
    assert r["partial"] is False


def test_git_older_than_1_7_10_falls_back(lib: Path, tmp_path: Path) -> None:
    """A git that rejects --show-origin and --no-includes (RHEL 6's 1.7.1) is asked plainly; it
    has no includes, so include.path is an ordinary key there."""
    r = _git_config(lib, tmp_path, ["file:$HOME/.gitconfig\thttp.proxy=http://oldproxy.corp:3128",
                                     "file:$HOME/.gitconfig\tinclude.path=/etc/x.gitconfig"], old=True)
    assert r["calls"] == ["git config --list --show-origin --no-includes", "git config --list --no-includes",
                          "git config --list"]
    assert r["lines"] == ["unknown\thttp.proxy=http://oldproxy.corp:3128", "unknown\tinclude.path=/etc/x.gitconfig"]
    assert (r["notes"], r["partial"]) == ([], False)


def test_package_sources_list_urls_and_proxy_urls_per_file(lib: Path, tmp_path: Path) -> None:
    """Shared contract for pkg.sources: each configs item has urls (endpoint bases) and
    proxy_urls from its raw lines; the top-level proxy_urls list ({tool, url, source}) covers the
    files and git. Proxies come from proxy settings, never from a registry URL that contains
    "proxy" (a Nexus npm-proxy repository), and never carry userinfo."""
    home, pdir = tmp_path / "home", tmp_path / "p"
    pdir.mkdir()
    npmrc = _write(home / ".npmrc", "registry=https://nexus.corp/repository/npm-proxy/\n"
                                    "proxy=http://alice:S3cretPw9@proxy.corp.example:8080\n"
                                    "https-proxy=proxy.corp.example:8443\n"
                                    "//nexus.corp/repository/npm-proxy/:_authToken=npm_tok_secret\n")
    _write(home / ".config" / "pip" / "pip.conf", "[global]\nindex-url = https://pypi.corp.example/simple\n")
    gitconfig = msys_path(home / ".gitconfig")
    listing = tmp_path / "list.tsv"
    listing.write_text(f"file:{gitconfig}\thttp.proxy=http://bob:GitPw9@gitproxy.corp:3128\n"
                       f"file:{gitconfig}\turl.https://git.corp.example/.insteadof=https://github.com/\n",
                       encoding="ascii", newline="\n")
    spec = tmp_path / "configs.spec"
    spec.write_text("npmrc.user\tnpm\tall\tuser\tcontent\t16384\t-\t~/.npmrc\n"
                    "pip.user\tpip\tall\tuser\tcontent\t16384\t-\t~/.config/pip/pip.conf\n",
                    encoding="ascii", newline="\n")
    script = ('ES_P_DIR=$1; ES_TMP=$1; ES_ROOT=; ES_OS=linux; HOME=$2; ES_TIMEOUT=10; PATH="$3:/usr/bin"\n'
              'ES_PACKAGE_ENV=; unset XDG_CONFIG_HOME GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM; es_pid_init\n'
              'es_awk_proxy >"$ES_TMP/proxy.awk"; es_test_spec=$4; es_spec_configs() { cat "$es_test_spec"; }\n'
              'probe_pkg_sources 5>"$ES_P_DIR/ev.txt"; cat "$ES_P_DIR/ev.txt"')
    proc = run_lib(lib, script, msys_path(pdir), msys_path(home), msys_path(STUBS / "git"), msys_path(spec),
                   env={"ES_STUB_GIT_LIST": msys_path(listing), "ES_STUB_LOG": "", "ES_STUB_GIT_OLD": ""})
    assert proc.returncode == 0, proc.stderr
    items = parse_items(proc.stdout)
    configs = {str(i["id"]): i for i in items if "id" in i}
    assert configs["npmrc.user"]["urls"] == ["https://nexus.corp", "http://proxy.corp.example:8080"]
    assert configs["npmrc.user"]["proxy_urls"] == ["http://proxy.corp.example:8080", "http://proxy.corp.example:8443"]
    assert (configs["pip.user"]["urls"], configs["pip.user"]["proxy_urls"]) == (["https://pypi.corp.example"], [])
    proxies = [(i["tool"], i["url"], i["source"]) for i in items if set(i) == {"tool", "url", "source"}]
    assert proxies == [("npm", "http://proxy.corp.example:8080", msys_path(npmrc)),
                       ("npm", "http://proxy.corp.example:8443", msys_path(npmrc)),
                       ("git", "http://gitproxy.corp:3128", f"file:{gitconfig}")]
    assert "https://git.corp.example" in event_list(proc.stdout, "internal_endpoints")
    urls = json.dumps([configs, proxies])
    assert not [s for s in ("S3cretPw9", "GitPw9", "npm_tok_secret", "alice", "npm-proxy") if s in urls], urls


@pytest.mark.parametrize("path,store", [
    ("/home/u/.ssh", True),
    ("/home/u/.ssh/config", True),
    ("/home/u/.aws/credentials", True),
    ("/home/u/.kube/config", True),
    ("/home/u/.netrc", True),
    ("/home/u/_netrc", True),
    ("/home/u/.git-credentials", True),
    ("/run/user/1000/containers/auth.json", True),
    ("/home/u/.docker/config.json", True),
    ("/home/u/.bash_history", True),
    ("/home/u/.local/share/powershell/PSReadLine/ConsoleHost_history.txt", True),
    ("/home/u/.history", True),
    ("/home/u/.zhistory", True),
    ("/home/u/.histfile", True),
    ("/home/u/.ssh/*", True),
    # parity with ps: case-insensitive (macOS disks), trailing dots and spaces per component
    ("/Users/u/.SSH/config", True),
    ("/Users/u/.Git-Credentials", True),
    ("/home/u/.ssh./config", True),
    ("/home/u/.netrc. ", True),
    ("/home/u/.aws /credentials", True),
    ("/home/u/../u/.npmrc", False),
    ("/home/u/./.npmrc", False),
    ("/home/u/.sshrc", False),
    ("/etc/ssh/ssh_config", False),
    ("/home/u/.docker/daemon.json", False),
    ("/home/u/.gitconfig", False),
    ("/home/u/.npmrc", False),
    # round 3: the stores of ps (Test-EsCredentialPath), keys and key stores by name
    ("/home/u/.gnupg/pubring.kbx", True),
    ("/home/u/.pgpass", True),
    ("/home/u/.azure/msal_token_cache.json", True),
    ("/home/u/.config/gcloud/credentials.db", True),
    ("/home/u/.config/gh/hosts.yml", True),
    ("/home/u/.terraform.d/credentials.tfrc.json", True),
    ("/home/u/.vault-token", True),
    ("/home/u/.pypirc", True),
    ("/home/u/.gem/credentials", True),
    ("/home/u/.cargo/credentials.toml", True),
    ("/home/u/.m2/settings-security.xml", True),
    ("/var/run/secrets/kubernetes.io/serviceaccount/token", True),
    ("/home/u/certs/client.pem", True),
    ("/etc/ssl/private/server.key", True),
    ("/home/u/client.P12", True),
    ("/home/u/client.pfx", True),
    ("/home/u/app.jks", True),
    ("/home/u/release.keystore", True),
    ("/home/u/keys/id_rsa", True),
    ("/home/u/keys/id_ecdsa", True),
    ("/home/u/keys/id_ed25519", True),
    # CA bundles, anchors and Java trust stores are read on purpose (tls.trust, tls.java_cacerts)
    ("/etc/ssl/cert.pem", False),
    ("/tmp/root/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", False),
    ("/usr/local/share/ca-certificates/corp-root.pem", False),
    ("/etc/ssl/certs/Corp_Root.pem", False),
    ("/opt/homebrew/Cellar/ca-certificates/2024-11-26/share/ca-certificates/cacert.pem", False),
    ("/opt/jdk/lib/security/cacerts", False),
    ("/home/u/.config/gh/config.yml", False),
    ("/home/u/.cargo/config.toml", False),
    ("/home/u/.m2/settings.xml", False),
    ("/home/u/keys/id_rsa.pub", False),
    ("/home/u/.gemrc", False),
])
def test_credential_store_paths_are_recognised(lib: Path, path: str, store: bool) -> None:
    """spec/configs.toml: credential stores are never opened or tested for existence."""
    assert sh(lib, 'es_cred_path "$1" && echo store || echo other', path).strip() == ("store" if store else "other")


def test_config_paths_never_lead_into_a_credential_store(lib: Path, tmp_path: Path) -> None:
    """A {env:NAME} config path that names a credential store (PIP_CONFIG_FILE=~/.netrc) is
    left out without being tested; an ordinary one is found."""
    _write(tmp_path / ".netrc", "machine pypi.corp login bob password NetrcPw9\n")
    _write(tmp_path / ".npmrc", "registry=https://nexus.corp/\n")
    script = ('ES_ROOT=; HOME=$1; PIP_CONFIG_FILE=$1/.netrc; NPM_CONFIG_USERCONFIG=$1/.npmrc\n'
              'es_expand "{env:PIP_CONFIG_FILE}" && echo "pip=$ES_X" || echo "pip=none"\n'
              'es_expand "{env:NPM_CONFIG_USERCONFIG}" && echo "npm=$ES_X"')
    out = sh(lib, script, msys_path(tmp_path))
    assert out.splitlines() == ["pip=none", f"npm={msys_path(tmp_path / '.npmrc')}", ""] or \
        out.splitlines() == ["pip=none", f"npm={msys_path(tmp_path / '.npmrc')}"], out
