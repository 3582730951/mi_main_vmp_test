#!/usr/bin/env python3
"""Remove printable PE/COFF metadata names from a generated release artifact."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

COFF_SYMBOL_SIZE = 18


def coff_symbol_table_end(data: bytearray, symbol_table: int, symbol_count: int) -> int:
    symbols_end = symbol_table + symbol_count * COFF_SYMBOL_SIZE
    if symbols_end > len(data):
        return len(data)
    if symbols_end + 4 > len(data):
        return symbols_end
    string_table_size = struct.unpack_from("<I", data, symbols_end)[0]
    if string_table_size < 4:
        return symbols_end
    return min(len(data), symbols_end + string_table_size)


def scrub(path: Path) -> int:
    data = bytearray(path.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("expected PE artifact with MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    symbol_table = struct.unpack_from("<I", data, pe_offset + 12)[0]
    symbol_count = struct.unpack_from("<I", data, pe_offset + 16)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_header_size
    if section_table + section_count * 40 > len(data):
        raise ValueError("invalid PE section table")
    section_data_end = 0
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
        raw_size = struct.unpack_from("<I", data, name_offset + 16)[0]
        raw_pointer = struct.unpack_from("<I", data, name_offset + 20)[0]
        if raw_size and raw_pointer:
            section_data_end = max(section_data_end, raw_pointer + raw_size)
    if symbol_table and symbol_count:
        symbol_end = coff_symbol_table_end(data, symbol_table, symbol_count)
        struct.pack_into("<II", data, pe_offset + 12, 0, 0)
        if symbol_table >= section_data_end and symbol_end == len(data):
            del data[symbol_table:]
        elif symbol_table < len(data):
            data[symbol_table:symbol_end] = b"\0" * (symbol_end - symbol_table)
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
