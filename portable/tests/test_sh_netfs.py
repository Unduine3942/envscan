"""Network file systems in envscan.sh (hardening round 2026-11-15, contract item 2).

A mount type T (lower-cased) is a network mount when T is in spec network_fs, or T starts with a
network_fs_prefixes entry ("fuse.") and is not in local_fuse. The rule is applied by es_is_netfs
and by every awk filter over the mount table (es_netmnts_init, es_netmnts_early, hw.storage).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sh_helpers import msys_path, needs_msys, run_lib

pytestmark = [pytest.mark.integration, needs_msys]

# review fix X3: "fuse." with an empty subtype is a network mount; layering FUSE types too
NETWORK = ("fuse.sshfs", "fuse.blobfuse2", "fuse.unknownthing", "fuse", "beegfs", "nfs", "gfs2", "webdav",
           "FUSE.SSHFS", "NFS4", "fuse.", "FUSE.", "fuse.mergerfs", "fuse.bindfs")
LOCAL = ("fuse.lxcfs", "fuse.fuse-overlayfs", "fuseblk", "ext4", "xfs", "tmpfs", "FUSE.LXCFS", "fusectl")


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def test_is_netfs_follows_the_spec_rule(lib: Path) -> None:
    script = 'for t in "$@"; do if es_is_netfs "$t"; then echo "$t net"; else echo "$t local"; fi; done'
    proc = run_lib(lib, script, *NETWORK, *LOCAL)
    assert proc.returncode == 0, proc.stderr
    expected = [f"{t} net" for t in NETWORK] + [f"{t} local" for t in LOCAL]
    assert proc.stdout.splitlines() == expected


def test_awk_rule_matches_the_shell_rule(lib: Path) -> None:
    """ES_AWK_NETFS es_isnet() gives the same verdict as es_is_netfs ("fuse." included)."""
    script = ('printf "%s\\n" "$@" | awk -v net="$ES_NET_FS" -v npre="$ES_NET_FS_PREFIXES" -v lfuse="$ES_LOCAL_FUSE" '
              '"$ES_AWK_NETFS"\' { print $0 " " (es_isnet($0) ? "net" : "local") }\'')
    proc = run_lib(lib, script, *NETWORK, *LOCAL)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [f"{t} net" for t in NETWORK] + [f"{t} local" for t in LOCAL]


def test_generated_lists_come_from_the_spec(lib: Path) -> None:
    proc = run_lib(lib, 'printf "%s|%s\\n" "$ES_NET_FS_PREFIXES" "$ES_LOCAL_FUSE"')
    prefixes, local = proc.stdout.strip().split("|")
    assert prefixes.split() == ["fuse."]
    assert "fuse.lxcfs" in local.split() and "fuse.snapfuse" in local.split()


def _mount_lines() -> str:
    rows = [("srv:/x", "/mnt/nfs", "nfs4"), ("u@h:/", "/mnt/ssh", "fuse.sshfs"), ("blob", "/mnt/blob", "fuse.blobfuse2"),
            ("lxcfs", "/proc/cpuinfo", "fuse.lxcfs"), ("ovl", "/var/lib/c", "fuse.fuse-overlayfs"),
            ("/dev/sdb1", "/media/usb", "fuseblk"), ("/dev/sda1", "/data", "ext4"), ("bee", "/mnt/bee", "beegfs"),
            ("x", "/mnt/fuse", "fuse"), ("y", "/mnt/fdot", "fuse.")]
    return "".join(f"{d} {m} {t} rw 0 0\n" for d, m, t in rows)


NET_MOUNTS = ["/mnt/nfs", "/mnt/ssh", "/mnt/blob", "/mnt/bee", "/mnt/fuse", "/mnt/fdot"]


def test_mount_table_filters_use_the_rule(lib: Path, tmp_path: Path) -> None:
    """es_netmnts_early (before the temp directory exists) and es_netmnts_init (from mounts.tsv)."""
    (tmp_path / "root" / "proc" / "self").mkdir(parents=True)
    (tmp_path / "root" / "proc" / "self" / "mounts").write_text(_mount_lines(), encoding="ascii", newline="\n")
    (tmp_path / "tmp").mkdir()
    script = ('ES_ROOT=$1; ES_TMP=$2; ES_OS=linux\n'
              'es_netmnts_early; printf "early %s\\n" $ES_NETMNTS\n'
              'es_mounts_init; es_netmnts_init; printf "init %s\\n" $ES_NETMNTS')
    proc = run_lib(lib, script, msys_path(tmp_path / "root"), msys_path(tmp_path / "tmp"))
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert sorted(x[6:] for x in lines if x.startswith("early ")) == sorted(NET_MOUNTS)
    assert sorted(x[5:] for x in lines if x.startswith("init ")) == sorted(NET_MOUNTS)


def test_storage_df_skips_fuse_network_mounts(lib: Path) -> None:
    """hw.storage passes only local mount points to df: the awk filter shares the rule."""
    proc = run_lib(lib, 'printf "%s\\n" "$ES_AWK_NETFS" | grep -c "function es_isnet"')
    assert proc.stdout.strip() == "1", proc.stderr
    src = (Path(__file__).resolve().parent.parent / "src" / "sh" / "20-os.sh").read_text(encoding="ascii")
    assert 'index(net, " " $3 " ")' not in src, "hw.storage must use es_isnet"


# Review fix X3: every \ooo escape of /proc/*/mounts is decoded to its byte. Tab and newline (the
# separators of the mount table) stay as the escapes \011 and \012, and every path is compared in
# that same spelling (es_mount_text), so a mount point with a tab or a newline matches exactly.
BS = "\\"


def _proc_mounts(lib: Path, tmp_path: Path, text: str) -> list[list[str]]:
    src = tmp_path / "mounts"
    src.write_bytes(text.encode("ascii"))
    proc = run_lib(lib, 'es_proc_mounts "$1"', msys_path(src))
    assert proc.returncode == 0, proc.stderr
    return [line.split("\t") for line in proc.stdout.split("\n") if line]


def test_proc_mounts_decodes_every_octal_escape(lib: Path, tmp_path: Path) -> None:
    text = (f"srv:/a{BS}040b /mnt/x{BS}043y{BS}134z fuse.my{BS}040fs rw{BS}054x 0 0\n"
            f"d /mnt/q{BS}777r{BS}12s ext4 rw 0 0\n")
    rows = _proc_mounts(lib, tmp_path, text)
    assert rows[0] == ["srv:/a b", f"/mnt/x#y{BS}z", "fuse.my fs", "rw,x"]
    # not three octal digits, or above \377: kept as written
    assert rows[1] == ["d", f"/mnt/q{BS}777r{BS}12s", "ext4", "rw"]


def test_tab_and_newline_mount_points_match_exactly(lib: Path, tmp_path: Path) -> None:
    """A network mount point holding a tab or a newline refuses exactly that path and what lies
    below it; the path with a space instead (the old decoding) is another folder."""
    (tmp_path / "root" / "proc" / "self").mkdir(parents=True)
    (tmp_path / "root" / "proc" / "self" / "mounts").write_bytes(
        f"srv:/a /mnt/a{BS}011b nfs rw 0 0\nsrv:/c /mnt/c{BS}012d nfs4 rw 0 0\n/dev/sda1 / ext4 rw 0 0\n".encode("ascii"))
    (tmp_path / "tmp").mkdir()
    script = ('ES_ROOT=$1; ES_TMP=$2; ES_OS=linux; es_mounts_init; es_netmnts_init\n'
              'for p in "/mnt/a${ES_TAB}b" "/mnt/a${ES_TAB}b/x" "/mnt/a b" "/mnt/c${ES_NL}d/y" "/mnt/c" "/mnt/d"; do\n'
              '  if es_on_netfs "$p"; then echo net; else echo local; fi\n'
              'done\n'
              'es_mount_of "/mnt/c${ES_NL}d/y" && echo "fs=$ES_MFS"')
    proc = run_lib(lib, script, msys_path(tmp_path / "root"), msys_path(tmp_path / "tmp"))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == ["net", "net", "local", "net", "local", "local", "fs=nfs4"]
