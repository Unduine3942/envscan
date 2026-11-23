"""sh: credential-store checks cannot be bypassed by path spelling (security review 2026-11-12).

Covers `//`, `/./`, `/../` and trailing `/` in es_cred_path, es_resolve failing on a resolved
credential path, the narrowed CA exemption, Windows (Cygwin/MSYS) short names and :streams, the
NUL guard of es_list_lines and unique decoded-copy names.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sh_helpers import msys_path, needs_msys, run_lib

pytestmark = [pytest.mark.integration, needs_msys]


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def verdicts(lib: Path, paths: list[str], os_name: str = "linux") -> list[str]:
    script = ('ES_OS=$1; shift\nfor p in "$@"; do es_cred_path "$p" && echo store || echo other; done')
    proc = run_lib(lib, script, os_name, *paths)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.split()


STORES = [
    "/home/u/.config//gcloud/x", "/home/u/.config/./gcloud/x", "/home/u/.docker//config.json",
    "/home/u/.docker/./config.json", "/var/run/secrets/kubernetes.io/serviceaccount//token",
    "/var/run/secrets/kubernetes.io/serviceaccount/./token", "/home/u/.config/foo/../gcloud/x",
    "/home/u//.ssh/id_rsa", "/home/u/.aws///credentials", "/home/u/.ssh/./", "/home/u/x/../.aws/credentials",
    # trailing separators (MEDIUM 6)
    "/home/u/id_rsa/", "/home/u/.netrc/", "/home/u/keys/x.pem/", "/home/u/keys/x.pem//", "/home/u/.netrc/.",
]


def test_spelling_variants_of_credential_stores_are_stores(lib: Path) -> None:
    assert verdicts(lib, STORES) == ["store"] * len(STORES)


@pytest.mark.parametrize("path", ["/home/u//src/x", "/home/u/./src/../src/x", "/home/u/proj/", "/home/u/.config//git/config",
                                  "/home/u/.sshfoo//x", "/home/u/a/./b"])
def test_ordinary_paths_with_odd_spelling_stay_ordinary(lib: Path, path: str) -> None:
    assert verdicts(lib, [path]) == ["other"]


def test_glob_patterns_with_spelling_variants_are_stores(lib: Path) -> None:
    assert verdicts(lib, ["/home/u/.config//gcloud/*", "/home/u/.ss*/./config", "/home/u/.config/./gcloud"]) == [
        "store", "other", "store"]


def test_es_resolve_fails_for_a_resolved_credential_path(lib: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".config" / "gcloud").mkdir(parents=True)
    (home / ".config" / "gcloud" / "creds").write_text("x\n", encoding="ascii")
    script = ('ES_NETMNTS=; ES_ROOT=; H=$1\n'
              'for p in "$H/.config//gcloud/creds" "$H/.config/./gcloud/creds" "$H/.config/x/../gcloud/creds" "$H/.config/ok"; do\n'
              '  es_resolve "$p" && echo "ok $ES_CREDLINK" || echo "refused $ES_CREDLINK"\n'
              'done\n'
              'es_glob "$H/.config//gcloud/creds" && echo "glob found" || echo "glob none"\n'
              'es_ltest -f "$H/.config//gcloud/creds" && echo ltest=yes || echo ltest=no')
    proc = run_lib(lib, script, msys_path(home))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split("\n")[:7] == ["refused 1", "refused 1", "refused 1", "ok ", "glob none", "ltest=no", ""], proc.stdout


@pytest.mark.parametrize("path, store", [
    ("/etc/ssl/certs/cacerts.p12", True), ("/home/u/cacerts.key", True), ("/home/u/cacerts.pfx", True),
    ("/etc/ssl/certs/server-key.pem", True), ("/etc/pki/trust/anchors/private.pem", True),
    ("/etc/ssl/certs/privkey.pem", True), ("/etc/ssl/certs/tls.key", True),
    ("/etc/ssl/certs/ISRG_Root_X1.pem", False), ("/etc/pki/ca-trust/source/anchors/corp-root.pem", False),
    ("/etc/ssl/cert.pem", False), ("/etc/pki/tls/certs/ca-bundle.crt", False), ("/etc/pki/tls/cert.pem", False),
    ("/usr/lib/jvm/java/lib/security/cacerts", False),
])
def test_ca_exemption_is_narrow(lib: Path, path: str, store: bool) -> None:
    assert verdicts(lib, [path]) == ["store" if store else "other"]


@pytest.mark.parametrize("path", ["/c/Users/u/GIT-CR~1/x", "/c/Users/u/.ssh::$DATA", "/c/Users/u/a:b/x", "/c/Users/u/.ssh:x",
                                  "C:/Users/u/PROGRA~1/x", "C:\\Users\\u\\GIT-CR~1\\x", "/c/Users/u/x~1"])
def test_msys_refuses_short_names_and_streams(lib: Path, path: str) -> None:
    assert verdicts(lib, [path], "cygwin") == ["store"]


@pytest.mark.parametrize("path", ["C:/Users/u/x", "C:\\Users\\u\\x", "/c/Users/u/x", "/cygdrive/c/Users/u/x", "/c/Users/u/a~b"])
def test_msys_keeps_drive_letters_and_plain_paths(lib: Path, path: str) -> None:
    assert verdicts(lib, [path], "cygwin") == ["other"]


def test_other_systems_do_not_refuse_tilde_digit_or_colon(lib: Path) -> None:
    assert verdicts(lib, ["/home/u/a~1/x", "/home/u/a:b/x"], "linux") == ["other", "other"]


def test_list_lines_does_not_emit_a_nul_file(lib: Path, tmp_path: Path) -> None:
    f = tmp_path / "hosts.txt"
    f.write_bytes("127.0.0.1 a\n".encode("utf-16-le"))
    script = ('ES_TMP=$1; ES_P_DIR=$1; ES_ROOT=; : >"$ES_P_DIR/status"\n'
              '{ es_list_lines entries "$2" s 50; } 5>"$ES_TMP/ev.txt"\n'
              'cat "$ES_TMP/ev.txt"; cat "$ES_P_DIR/status" "$ES_P_DIR/notes"')
    proc = run_lib(lib, script, msys_path(tmp_path), msys_path(f))
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.replace("\x00", "")
    assert "127" not in out and "[\tentries\n]" in out, out
    assert "UTF-16 or binary content" in out


def test_decoded_copies_get_unique_names_even_from_subshells(lib: Path, tmp_path: Path) -> None:
    f = tmp_path / "a.conf"
    f.write_bytes(b"\xff\xfe" + "password=x\n".encode("utf-16-le"))
    script = ('ES_TMP=$1; ES_P_DIR=$1; ES_P_ID=p.x\n'
              'a=$(es_text_prep "$2"; echo "$ES_TXT"); b=$(es_text_prep "$2"; echo "$ES_TXT"); es_text_prep "$2"; c=$ES_TXT\n'
              '[ "$a" != "$b" ] && [ "$b" != "$c" ] && [ "$a" != "$c" ] && echo unique || echo "clash $a $b $c"')
    proc = run_lib(lib, script, msys_path(tmp_path), msys_path(f))
    assert proc.stdout.strip() == "unique", proc.stdout + proc.stderr
