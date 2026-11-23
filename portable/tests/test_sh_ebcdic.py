"""EBCDIC support of envscan.sh (z/OS UNIX, IBM i QSH): the IBM-1047 table, json.awk in EBCDIC
mode, EBCDIC detection and the report conversion after the scan.

No EBCDIC host exists here, so the awk path is tested with gawk on an ASCII host in "hybrid" form:
the 95 printable ASCII characters keep their ASCII bytes (json.awk learns them from a string
literal of its own, which is how it stays right in any EBCDIC code page), and every other byte is
IBM-1047 data that must come out as the \\uXXXX escape of the cp1047 codec's character. That is
the part of json.awk that is specific to EBCDIC; the table itself is checked against Python's
cp1047 codec. Unverified on a real z/OS system.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

from conftest import PORTABLE, TOOLS
from sh_helpers import GAWK, make_awk_tool, msys_path, needs_msys, run_lib
from spec import load_spec, validate_spec

sys.path.insert(0, str(TOOLS))

TABLE = [ord(bytes([b]).decode("cp1047")) for b in range(256)]
PRINTABLE = set(range(0x20, 0x7F))
# bytes that are neither printable ASCII (the host's own characters) nor handled as awk literals
DATA_BYTES = [b for b in range(1, 256) if b not in PRINTABLE and b not in (0x09, 0x0A, 0x0D)]


# ------------------------------------------------------------------ the spec table

@pytest.mark.unit
def test_spec_table_is_the_cp1047_codec() -> None:
    spec = load_spec(PORTABLE / "spec")
    assert list(spec.documents["ebcdic.toml"]["ibm1047"]["codepoints"]) == TABLE


@pytest.mark.unit
def test_table_file_is_what_the_generator_writes() -> None:
    proc = subprocess.run([sys.executable, "-I", str(TOOLS / "gen_ebcdic.py"), "--check"], capture_output=True)
    assert proc.returncode == 0, "spec/ebcdic.toml differs from tools/gen_ebcdic.py output"


@pytest.mark.unit
def test_ibm1047_known_code_points() -> None:
    # letters, digits and the characters that differ between IBM-1047 and IBM-037
    assert [TABLE[b] for b in (0xC1, 0xF0, 0x81, 0x40, 0xAD, 0xBD, 0x5F, 0xE0, 0xC0, 0xD0)] == [
        ord("A"), ord("0"), ord("a"), ord(" "), ord("["), ord("]"), ord("^"), ord("\\"), ord("{"), ord("}")]
    assert TABLE[0x15] == 0x0A  # NL, the z/OS UNIX newline


def _spec_with(table: Any) -> list[str]:
    spec = load_spec(PORTABLE / "spec")
    documents = {**spec.documents, "ebcdic.toml": {"ibm1047": table}}
    import dataclasses
    return validate_spec(dataclasses.replace(spec, documents=documents))


@pytest.mark.unit
@pytest.mark.parametrize("name,table,expected", [
    ("short", {"codepoints": TABLE[:255]}, "256 integers"),
    ("long", {"codepoints": [*TABLE, 0]}, "256 integers"),
    ("string entry", {"codepoints": [*TABLE[:255], "x"]}, "256 integers"),
    ("boolean entry", {"codepoints": [*TABLE[:255], True]}, "256 integers"),
    ("out of range", {"codepoints": [*TABLE[:255], 0x110000]}, "256 integers"),
    ("duplicate", {"codepoints": [*TABLE[:255], TABLE[0]]}, "distinct"),
    ("not a table", [1, 2], "single key"),
    ("extra key", {"codepoints": TABLE, "x": 1}, "single key"),
])
def test_table_validation(name: str, table: Any, expected: str) -> None:
    assert any(expected in e for e in _spec_with(table)), name


@pytest.mark.unit
def test_valid_table_has_no_errors() -> None:
    assert _spec_with({"codepoints": TABLE}) == []


@pytest.mark.unit
def test_missing_printable_ascii_is_reported() -> None:
    table = [0x1000 + i if cp == ord("A") else cp for i, cp in enumerate(TABLE)]
    assert any("printable ASCII missing" in e for e in _spec_with({"codepoints": table}))


@pytest.mark.unit
def test_ebcdic_toml_is_a_registered_spec_document() -> None:
    from spec import DOCUMENT_KEYS
    assert DOCUMENT_KEYS["ebcdic.toml"] == ("ibm1047",)


# ------------------------------------------------------------------ json.awk in EBCDIC mode

@pytest.fixture(scope="module")
def lib(built: Path) -> Path:
    return built / "build" / "lib" / "envscan-lib.sh"


@pytest.fixture(scope="module")
def table_arg(lib: Path) -> str:
    proc = run_lib(lib, 'printf "%s" "$ES_EBCDIC_TAB"')
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.fixture(scope="module")
def runner(lib: Path, table_arg: str, tmp_path_factory: pytest.TempPathFactory) -> Callable[..., bytes]:
    tool = make_awk_tool(lib, tmp_path_factory.mktemp("ebcdic-awk"))

    def run(mode: str, data: bytes, *, ebcdic: bool, redact: bool = False) -> bytes:
        args = [str(GAWK), "--posix", "-v", f"mode={mode}", "-v", f"redact={1 if redact else 0}", *tool.variables,
                "-v", f"ebcdic={1 if ebcdic else 0}", "-v", f"ebcdic_tab={table_arg if ebcdic else ''}",
                "-f", str(tool.program)]
        proc = subprocess.run(args, input=data, capture_output=True, timeout=120, env={**os.environ, "LC_ALL": "C"})
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        return proc.stdout

    return run


def events(*values: bytes) -> bytes:
    return b"{\t-\n" + b"".join(b"s\tk" + str(i).encode() + b"\t" + v + b"\n" for i, v in enumerate(values)) + b"}\n"


@pytest.mark.integration
@needs_msys
def test_generated_table_variable_matches_the_spec(table_arg: str) -> None:
    assert [int(x) for x in table_arg.split()] == TABLE


@pytest.mark.integration
@needs_msys
def test_every_non_printable_byte_becomes_its_ibm1047_escape(runner: Callable[..., bytes]) -> None:
    value = bytes(DATA_BYTES)
    out = runner("json", events(value), ebcdic=True)
    assert max(out) < 0x80, "the JSON must be pure ASCII"
    assert json.loads(out)["k0"] == "".join(chr(TABLE[b]) for b in DATA_BYTES)


@pytest.mark.integration
@needs_msys
def test_each_byte_alone_and_between_letters(runner: Callable[..., bytes]) -> None:
    values = [b"ab" + bytes([b]) + b"cd" for b in DATA_BYTES]
    got = json.loads(runner("json", events(*values), ebcdic=True))
    assert [got[f"k{i}"] for i in range(len(values))] == [f"ab{chr(TABLE[b])}cd" for b in DATA_BYTES]


@pytest.mark.integration
@needs_msys
def test_printable_ascii_is_identical_in_both_modes(runner: Callable[..., bytes]) -> None:
    every = bytes(range(0x20, 0x7F))
    cases = [every, b"", b"plain", b"back\\slash and \"quote\" and [brackets] ^caret -dash `tick` ~tilde {brace}",
             b"C:\\Users\\x", b"a" * 5000, every * 20]
    data = events(*cases)
    assert runner("json", data, ebcdic=True) == runner("json", data, ebcdic=False)
    assert runner("md", data, ebcdic=True) == runner("md", data, ebcdic=False)


@pytest.mark.integration
@needs_msys
def test_whitespace_escapes_use_the_hosts_own_characters(runner: Callable[..., bytes]) -> None:
    data = b"{\t-\nS\tk\ta\\tb\\nc\\rd\\\\e\n}\n"
    assert json.loads(runner("json", data, ebcdic=True))["k"] == "a\tb\nc\rd\\e"


LETTER_BYTES = [b for b in DATA_BYTES if TABLE[b] >= 0xA0 and chr(TABLE[b]).isalpha()]


@pytest.mark.integration
@needs_msys
def test_mixed_text_decodes_to_the_original(runner: Callable[..., bytes]) -> None:
    picks = LETTER_BYTES[:4]
    encoded = b"caf" + bytes([picks[0]]) + b" na" + bytes([picks[1]]) + b"ve \\ " + bytes([picks[2], picks[3]]) + b"!"
    original = "caf" + chr(TABLE[picks[0]]) + " na" + chr(TABLE[picks[1]]) + "ve \\ " + "".join(chr(TABLE[b]) for b in picks[2:]) + "!"
    assert json.loads(runner("json", events(encoded), ebcdic=True))["k0"] == original


@pytest.mark.integration
@needs_msys
def test_redaction_still_runs_in_ebcdic_mode(runner: Callable[..., bytes]) -> None:
    data = b"{\t-\ne\tMY_API_TOKEN\tsecret-value-123\ns\tother\thttps://u:hunter2pass@host.example/x\n}\n"
    got = json.loads(runner("json", data, ebcdic=True, redact=True))
    assert "secret-value-123" not in json.dumps(got) and "hunter2pass" not in json.dumps(got)


@pytest.mark.integration
@needs_msys
def test_markdown_replaces_controls_and_keeps_the_rest(runner: Callable[..., bytes]) -> None:
    control = next(b for b in DATA_BYTES if TABLE[b] < 32)
    kept = LETTER_BYTES[0]
    out = runner("md", events(b"a" + bytes([control]) + b"b" + bytes([kept]) + b"c"), ebcdic=True)
    assert b"a b" + bytes([kept]) + b"c" in out
    assert bytes([control]) not in out


@pytest.mark.integration
@needs_msys
def test_utf8_is_not_validated_in_ebcdic_mode(runner: Callable[..., bytes]) -> None:
    # bytes c3 a9 are two IBM-1047 characters here, never one UTF-8 e-acute
    got = json.loads(runner("json", events(b"\xc3\xa9"), ebcdic=True))["k0"]
    assert got == chr(TABLE[0xC3]) + chr(TABLE[0xA9])


@pytest.mark.integration
@needs_msys
def test_ascii_mode_is_unchanged_for_utf8(runner: Callable[..., bytes]) -> None:
    assert json.loads(runner("json", events("caf\u00e9".encode()), ebcdic=False))["k0"] == "caf\u00e9"


# ------------------------------------------------------------------ non-1047 EBCDIC: fail visibly

@pytest.mark.integration
@needs_msys
def test_without_the_table_non_printable_bytes_are_replacement_characters(lib: Path, table_arg: str,
                                                                        tmp_path_factory: pytest.TempPathFactory) -> None:
    """In an EBCDIC code page other than IBM-1047 the shell passes no table: bytes outside printable
    ASCII must show as U+FFFD (JSON) or ? (Markdown), never as a wrong character."""
    tool = make_awk_tool(lib, tmp_path_factory.mktemp("ebcdic-notab"))

    def run(mode: str, data: bytes) -> bytes:
        args = [str(GAWK), "--posix", "-v", f"mode={mode}", "-v", "redact=0", *tool.variables,
                "-v", "ebcdic=1", "-v", "ebcdic_tab=", "-f", str(tool.program)]
        proc = subprocess.run(args, input=data, capture_output=True, timeout=120, env={**os.environ, "LC_ALL": "C"})
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        return proc.stdout

    value = b"ok" + bytes([DATA_BYTES[0], DATA_BYTES[40], DATA_BYTES[-1]]) + b"end"
    assert json.loads(run("json", events(value)))["k0"] == "ok\ufffd\ufffd\ufffdend"
    out = run("md", events(value))
    assert b"ok???end" in out and max(out) < 0x80


# ------------------------------------------------------------------ detection and conversion (shell)

@pytest.fixture
def stubs(tmp_path: Path) -> Path:
    d = tmp_path / "stubs"
    d.mkdir()
    return d


def stub(d: Path, name: str, body: str) -> None:
    (d / name).write_text("#!/bin/sh\n" + body, encoding="ascii", newline="\n")


def od_stub(d: Path, letter_a: str, bracket: str) -> None:
    """An od that answers for the two probes of es_detect_ebcdic (stdin is "A" or "[")."""
    stub(d, "od", f'c=$(cat)\ncase "$c" in A) printf "%s\\n" " {letter_a}" ;; "[") printf "%s\\n" " {bracket}" ;; esac\n')


@pytest.mark.integration
@needs_msys
@pytest.mark.parametrize("a,bracket,ebcdic,is1047", [
    ("c1", "ad", "1", "1"),      # IBM-1047
    ("c1", "ba", "1", "0"),      # IBM-037: letters agree, [ does not
    ("c1", "", "1", "0"),
    ("41", "5b", "0", "0"),      # ASCII
    ("", "", "0", "0"),          # no od
])
def test_detect_ebcdic_and_code_page_from_od(lib: Path, stubs: Path, a: str, bracket: str, ebcdic: str,
                                             is1047: str) -> None:
    od_stub(stubs, a, bracket)
    proc = run_lib(lib, 'PATH="$1:/usr/bin"; es_detect_ebcdic; printf "%s|%s|%s" "$ES_EBCDIC" "${ES_EBCDIC_1047:-0}" '
                        '"${ES_EBCDIC_ARG:+tab}"', msys_path(stubs))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == f"{ebcdic}|{is1047}|{'tab' if is1047 == '1' else ''}"


CONVERT = ('PATH="$1:/usr/bin"; ES_OS=zos; ES_EBCDIC=1; ES_EBCDIC_1047=1; ES_TMP="$2/tmp"; mkdir -p "$ES_TMP"\n'
           'es_say() { printf "%s\\n" "$*"; }\n'
           'es_ebcdic_convert "$2/out/$3" "$2/out/$4"; printf "rc=%s\\n" "$?"\n')


def converting(tmp_path: Path, stubs: Path, lib: Path, *, iconv: str, chtag: str, files: dict[str, bytes],
               prelude: str = "") -> tuple[str, dict[str, bytes], Path]:
    work = tmp_path / "work"
    (work / "out").mkdir(parents=True)
    for name, data in files.items():
        (work / "out" / name).write_bytes(data)
    stub(stubs, "iconv", iconv)
    stub(stubs, "chtag", chtag)
    names = list(files) + ["none"] * (2 - len(files))
    proc = run_lib(lib, prelude + CONVERT, msys_path(stubs), msys_path(work), *names)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout, {n: (work / "out" / n).read_bytes() for n in files}, work


ICONV_OK = ('[ "$1" = -f ] && [ "$2" = IBM-1047 ] && [ "$3" = -t ] && [ "$4" = UTF-8 ] || exit 3\n'
            'tr "a-z" "A-Z"\n')
# z/OS iconv that keeps NL as U+0085 (C2 85) instead of LF, and one that writes no line feed at all
ICONV_NL_C285 = "awk 'BEGIN { ORS = \"\\302\\205\" } { print }'\n"
ICONV_NO_LF = "tr -d '\\n'\n"
ICONV_NOT_JSON = "printf 'x'; cat\n"


@pytest.mark.integration
@needs_msys
def test_conversion_converts_and_tags_with_the_numeric_ccsid(lib: Path, stubs: Path, tmp_path: Path) -> None:
    log = tmp_path / "chtag.log"
    out, files, work = converting(tmp_path, stubs, lib, iconv=ICONV_OK,
                                  chtag=f'printf "%s\\n" "$*" >>"{msys_path(log)}"\n',
                                  files={"a.txt": b"abc\n", "b.txt": b"def\n"})
    assert files == {"a.txt": b"ABC\n", "b.txt": b"DEF\n"}
    assert out == "rc=0\n"
    assert sorted(log.read_text().split("\n")[:-1]) == [f"-tc 1208 {msys_path(work)}/out/a.txt",
                                                        f"-tc 1208 {msys_path(work)}/out/b.txt"]
    assert not list((work / "out").glob("*.conv")) and not list((work / "tmp").glob("*"))


@pytest.mark.integration
@needs_msys
def test_conversion_writes_below_the_private_temp_directory(lib: Path, stubs: Path, tmp_path: Path) -> None:
    """The temporary .conv file is created in $ES_TMP: when that is unusable the original stays."""
    out, files, _ = converting(tmp_path, stubs, lib, iconv=ICONV_OK, chtag="",
                               files={"a.txt": b"abc\n"},
                               prelude="")  # ES_TMP is made by CONVERT; break it afterwards below
    assert files["a.txt"] == b"ABC\n"
    work = tmp_path / "w2"
    (work / "out").mkdir(parents=True)
    (work / "out" / "a.txt").write_bytes(b"abc\n")
    script = CONVERT.replace('mkdir -p "$ES_TMP"', 'ES_TMP="$2/no/such/dir"')
    proc = run_lib(lib, script, msys_path(stubs), msys_path(work), "a.txt", "none")
    assert proc.returncode == 0, proc.stderr
    assert (work / "out" / "a.txt").read_bytes() == b"abc\n"
    assert "iconv IBM-1047 to UTF-8 failed for a.txt" in proc.stdout
    assert not list((work / "out").glob("*.conv"))


@pytest.mark.integration
@needs_msys
def test_conversion_runs_without_autoconversion_settings(lib: Path, stubs: Path, tmp_path: Path) -> None:
    env_file = tmp_path / "env.txt"
    iconv = f'printf "%s|%s\\n" "$_BPXK_AUTOCVT" "${{_CEE_RUNOPTS-unset}}" >"{msys_path(env_file)}"; cat\n'
    work = tmp_path / "w"
    (work / "out").mkdir(parents=True)
    (work / "out" / "a.txt").write_bytes(b"x\n")
    stub(stubs, "iconv", iconv)
    stub(stubs, "chtag", "")
    proc = run_lib(lib, CONVERT, msys_path(stubs), msys_path(work), "a.txt", "none",
                   env={"_BPXK_AUTOCVT": "ON", "_CEE_RUNOPTS": "FILETAG(AUTOCVT,AUTOTAG)"})
    assert proc.returncode == 0, proc.stderr
    assert env_file.read_text() == "OFF|unset\n"


@pytest.mark.integration
@needs_msys
def test_failed_iconv_leaves_the_text_and_logs(lib: Path, stubs: Path, tmp_path: Path) -> None:
    out, files, work = converting(tmp_path, stubs, lib, iconv="cat >/dev/null; exit 1\n", chtag="",
                                  files={"a.txt": b"report\n", "b.txt": b"brief\n"})
    assert files == {"a.txt": b"report\n", "b.txt": b"brief\n"}
    assert out.count("iconv IBM-1047 to UTF-8 failed") == 2 and "a.txt" in out and "b.txt" in out
    assert not list((work / "out").glob("*.conv"))


@pytest.mark.integration
@needs_msys
def test_empty_iconv_output_counts_as_failure(lib: Path, stubs: Path, tmp_path: Path) -> None:
    out, files, _ = converting(tmp_path, stubs, lib, iconv="cat >/dev/null\n", chtag="",
                               files={"a.txt": b"report\n", "b.txt": b"x\n"})
    assert files["a.txt"] == b"report\n"
    assert "failed for a.txt" in out


@pytest.mark.integration
@needs_msys
@pytest.mark.parametrize("name,iconv,why", [
    ("nl_kept_as_u0085", ICONV_NL_C285, "self-check"),
    ("no_line_feed", ICONV_NO_LF, "self-check"),
])
def test_self_check_keeps_the_original_when_nl_was_not_converted_to_lf(lib: Path, stubs: Path, tmp_path: Path,
                                                                       name: str, iconv: str, why: str) -> None:
    original = b"line one\nline two\n"
    out, files, work = converting(tmp_path, stubs, lib, iconv=iconv, chtag="exit 9\n",
                                  files={"a.txt": original, "b.txt": original})
    assert files == {"a.txt": original, "b.txt": original}, name
    assert out.count(why) == 2 and "stays in IBM-1047" in out
    assert "chtag" not in out  # nothing was tagged: the file was never replaced
    assert not list((work / "out").glob("*.conv"))


@pytest.mark.integration
@needs_msys
def test_self_check_accepts_a_real_lf_and_rejects_json_that_does_not_start_with_a_brace(lib: Path, stubs: Path,
                                                                                         tmp_path: Path) -> None:
    ok, files, _ = converting(tmp_path / "a", stubs, lib, iconv="cat\n", chtag="", files={"envscan.json": b"{\n}\n"})
    assert files["envscan.json"] == b"{\n}\n" and "self-check" not in ok
    bad, files, _ = converting(tmp_path / "b", stubs, lib, iconv=ICONV_NOT_JSON, chtag="",
                               files={"envscan.json": b"{\n}\n", "envscan.md": b"# t\n"})
    assert files["envscan.json"] == b"{\n}\n", "a JSON file that does not start with { is never replaced"
    assert "copy of envscan.json failed the self-check" in bad
    assert files["envscan.md"] == b"x# t\n", "the brace rule is only for envscan.json"


@pytest.mark.integration
@needs_msys
def test_failed_chtag_keeps_the_converted_file_and_says_so(lib: Path, stubs: Path, tmp_path: Path) -> None:
    out, files, _ = converting(tmp_path, stubs, lib, iconv=ICONV_OK, chtag="exit 1\n",
                               files={"a.txt": b"abc\n", "b.txt": b"def\n"})
    assert files == {"a.txt": b"ABC\n", "b.txt": b"DEF\n"}
    assert out.count("chtag failed") == 2 and "untagged" in out


@pytest.mark.integration
@needs_msys
def test_other_ebcdic_code_pages_are_left_unconverted(lib: Path, stubs: Path, tmp_path: Path) -> None:
    out, files, _ = converting(tmp_path, stubs, lib, iconv=ICONV_OK, chtag="", files={"a.txt": b"abc\n"},
                               prelude="")
    assert files["a.txt"] == b"ABC\n"
    work = tmp_path / "w3"
    (work / "out").mkdir(parents=True)
    (work / "out" / "a.txt").write_bytes(b"abc\n")
    script = CONVERT.replace("ES_EBCDIC_1047=1", "ES_EBCDIC_1047=0")
    proc = run_lib(lib, script, msys_path(stubs), msys_path(work), "a.txt", "none")
    assert proc.returncode == 0, proc.stderr
    assert (work / "out" / "a.txt").read_bytes() == b"abc\n"
    assert "not IBM-1047" in proc.stdout and "host code page" in proc.stdout


@pytest.mark.integration
@needs_msys
@pytest.mark.parametrize("os_name,ebcdic", [("linux", "1"), ("aix", "1"), ("zos", "0"), ("os400", "0")])
def test_conversion_only_on_zos_in_ebcdic(lib: Path, stubs: Path, tmp_path: Path, os_name: str, ebcdic: str) -> None:
    work = tmp_path / "w"
    (work / "out").mkdir(parents=True)
    (work / "out" / "a.txt").write_bytes(b"abc\n")
    stub(stubs, "iconv", "tr a-z A-Z\n")
    stub(stubs, "chtag", "")
    script = CONVERT.replace("ES_OS=zos; ES_EBCDIC=1", f"ES_OS={os_name}; ES_EBCDIC={ebcdic}")
    proc = run_lib(lib, script, msys_path(stubs), msys_path(work), "a.txt", "none")
    assert proc.returncode == 0, proc.stderr
    assert (work / "out" / "a.txt").read_bytes() == b"abc\n"
