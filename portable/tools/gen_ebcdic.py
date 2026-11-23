"""Regenerate spec/ebcdic.toml from Python's cp1047 codec (run by hand, once).

The table is frozen data in the spec: tests/test_sh_ebcdic.py checks it against the codec, and
tools/spec.py validates its shape. The generator is only needed if the table must be rebuilt.

    python tools/gen_ebcdic.py            # rewrite spec/ebcdic.toml
    python tools/gen_ebcdic.py --check    # exit 1 when the file differs from the codec
"""
from __future__ import annotations

import sys
from pathlib import Path

SPEC_FILE = Path(__file__).resolve().parent.parent / "spec" / "ebcdic.toml"
HEADER = """\
# IBM-1047 (the default z/OS UNIX code page) to Unicode: the code point of each byte 0x00-0xFF.
# Used by src/sh/awk/json.awk when the scanner runs on an EBCDIC host (z/OS, IBM i QSH): every
# byte that is not one of the 95 printable ASCII characters becomes a \\uXXXX escape from this
# table, so envscan.json stays pure ASCII. Generated from Python's cp1047 codec by
# tools/gen_ebcdic.py and verified against it by tests/test_sh_ebcdic.py. Do not edit by hand.
[ibm1047]
codepoints = [
"""


def codepoints() -> list[int]:
    return [ord(bytes([b]).decode("cp1047")) for b in range(256)]


def render() -> str:
    cps = codepoints()
    rows = [", ".join(f"{cp:5d}" for cp in cps[i:i + 16]) + "," for i in range(0, 256, 16)]
    return HEADER + "\n".join(f"  {row}" for row in rows) + "\n]\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        current = SPEC_FILE.read_text(encoding="ascii") if SPEC_FILE.is_file() else ""
        return 0 if current == text else 1
    SPEC_FILE.write_bytes(text.encode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
