"""sh: UTF-16 and binary files are decoded or never read (redaction cannot match NUL-interleaved text)."""
from __future__ import annotations

from pathlib import Path

import pytest

from sh_helpers import make_awk_tool, msys_path, needs_msys, run_lib

pytestmark = [pytest.mark.integration, needs_msys]

SECRET = "Sup3rSecretValue77"
TEXT = f"[global]\nindex-url = https://pypi.corp.example/simple\npassword = {SECRET}\n"


@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


def sh(lib: Path, tmp: Path, script: str, *args: str) -> str:
    proc = run_lib(lib, f'ES_TMP="$1"; ES_P_DIR="$1"; ES_ROOT=; shift\n{script}', msys_path(tmp), *args)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def write(tmp: Path, name: str, data: bytes) -> Path:
    path = tmp / name
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("name, data, binary", [
    ("plain", TEXT.encode(), False),
    ("empty", b"", False),
    ("le_bom", b"\xff\xfe" + TEXT.encode("utf-16-le"), True),
    ("be_bom", b"\xfe\xff" + TEXT.encode("utf-16-be"), True),
    ("le_no_bom", TEXT.encode("utf-16-le"), True),
    ("nul_late", b"a=b\n" * 5000 + b"\x00x\n", True),
])
def test_bin_file_detects_utf16_and_nul(lib: Path, tmp_path: Path, name: str, data: bytes, binary: bool) -> None:
    path = write(tmp_path, name, data)
    out = sh(lib, tmp_path, 'if es_bin_file "$1"; then echo bin; else echo text; fi', msys_path(path))
    assert out.strip() == ("bin" if binary else "text")


@pytest.mark.parametrize("name, data", [
    ("le", b"\xff\xfe" + TEXT.replace("\n", "\r\n").encode("utf-16-le")),
    ("be", b"\xfe\xff" + TEXT.encode("utf-16-be")),
])
def test_text_prep_decodes_ascii_utf16(lib: Path, tmp_path: Path, name: str, data: bytes) -> None:
    path = write(tmp_path, name, data)
    out = sh(lib, tmp_path, 'es_text_prep "$1" && cat "$ES_TXT"; echo "rc=$?"', msys_path(path))
    assert f"password = {SECRET}" in out
    assert "\x00" not in out and "\xff" not in out
    assert "rc=0" in out


@pytest.mark.parametrize("name, data", [
    ("nul_no_bom", TEXT.encode("utf-16-le")),
    ("le_non_ascii", b"\xff\xfe" + "café password=x\n".encode("utf-16-le")),  # no iconv: not ASCII-only
    ("odd_length", b"\xff\xfe" + TEXT.encode("utf-16-le") + b"x"),
    ("binary", b"\x7fELF\x00\x01\x02" + SECRET.encode()),
])
def test_text_prep_refuses_what_it_cannot_decode(lib: Path, tmp_path: Path, name: str, data: bytes) -> None:
    path = write(tmp_path, name, data)
    out = sh(lib, tmp_path, 'es_text_prep "$1"; echo "rc=$?"; ls "$ES_TMP"', msys_path(path))
    # iconv may exist on the host and decode the non-ASCII file; every other case is refused
    if name == "le_non_ascii" and "rc=0" in out:
        return
    assert "rc=1" in out
    assert not [line for line in out.splitlines() if line.startswith("dec.")]  # no decoded copy left


def test_config_raw_never_reads_undecodable_content(lib: Path, tmp_path: Path) -> None:
    path = write(tmp_path, "pip.conf", TEXT.encode("utf-16-le"))  # no BOM, NUL bytes
    script = (': >"$ES_P_DIR/config_lines.txt"; es_config_raw "$1" content 65536 "-"; cat "$ES_P_DIR/cfg.cur" "$ES_P_DIR/config_lines.txt"; echo done')
    out = sh(lib, tmp_path, script, msys_path(path))
    assert out.strip() == "done"


def test_config_raw_reads_decodable_utf16(lib: Path, tmp_path: Path) -> None:
    path = write(tmp_path, "pip.conf", b"\xff\xfe" + TEXT.encode("utf-16-le"))
    script = (': >"$ES_P_DIR/config_lines.txt"; es_config_raw "$1" content 65536 "-"; cat "$ES_P_DIR/cfg.cur"')
    out = sh(lib, tmp_path, script, msys_path(path))
    assert "index-url = https://pypi.corp.example/simple" in out
    assert out.startswith(msys_path(path))  # the source tag is the original path, not the decoded copy
    assert "\x00" not in out


def test_text_ok_marks_the_probe_partial(lib: Path, tmp_path: Path) -> None:
    path = write(tmp_path, "limits.conf", b"* soft nofile 1\n\x00\x00\n")
    script = ('es_status ok; if es_text_ok "$1"; then echo ok; else echo refused; fi\n'
              'cat "$ES_P_DIR/status" "$ES_P_DIR/notes"')
    out = sh(lib, tmp_path, script, msys_path(path))
    assert out.splitlines()[0] == "refused"
    assert "partial" in out and "UTF-16 or binary content" in out


@pytest.mark.parametrize("name, data", [
    ("nul_no_bom", TEXT.encode("utf-16-le")),
    ("be_bom", b"\xfe\xff" + TEXT.encode("utf-16-be")),
])
def test_event_writer_refuses_utf16_without_decoding(built: Path, tmp_path: Path, name: str, data: bytes) -> None:
    """The awk F and f events never print a file with a BOM or NUL bytes (they cannot decode it)."""
    tool = make_awk_tool(built / "build" / "lib" / "envscan-lib.sh", tmp_path)
    path = write(tmp_path, name, data)
    out = tool.run("json", f"{{\t-\nF\tlines\t{path.as_posix()}\t65536\tcontent\t-\nf\traw\t{path.as_posix()}\n}}\n")
    assert SECRET not in out.replace("\x00", "")
    assert "UTF-16 or binary content not read" in out
