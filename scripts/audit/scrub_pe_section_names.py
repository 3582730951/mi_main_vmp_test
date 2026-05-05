#!/usr/bin/env python3
"""Remove printable PE section names from a generated release artifact."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def scrub(path: Path) -> int:
    data = bytearray(path.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("expected PE artifact with MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_header_size
    if section_table + section_count * 40 > len(data):
        raise ValueError("invalid PE section table")
    for index in range(section_count):
        name_offset = section_table + index * 40
        data[name_offset : name_offset + 8] = bytes(
            (
                0x80 | ((index + 1) & 0x0F),
                0x90 | ((index + 3) & 0x0F),
                0xA0 | ((index + 5) & 0x0F),
                0xB0 | ((index + 7) & 0x0F),
                0,
                0,
                0,
                0,
            )
        )
    path.write_bytes(data)
    return section_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    args = parser.parse_args()
    count = scrub(Path(args.artifact))
    print(f"scrubbed PE section names: sections={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
