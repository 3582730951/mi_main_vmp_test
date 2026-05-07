#!/usr/bin/env python3
"""Remove an empty PE export directory from a generated platform DLL."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def pe_layout(data: bytes) -> tuple[int, int, int, int, int]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("expected PE artifact with MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:
        data_directories = optional + 112
    elif magic == 0x10B:
        data_directories = optional + 96
    else:
        raise ValueError(f"unsupported PE optional header magic: 0x{magic:x}")
    section_table = optional + optional_header_size
    if section_table + section_count * 40 > len(data):
        raise ValueError("invalid PE section table")
    return pe_offset, section_count, optional_header_size, data_directories, section_table


def rva_to_file_offset(data: bytes, rva: int, section_count: int, section_table: int) -> int | None:
    for index in range(section_count):
        base = section_table + index * 40
        virtual_size = struct.unpack_from("<I", data, base + 8)[0]
        virtual_address = struct.unpack_from("<I", data, base + 12)[0]
        raw_size = struct.unpack_from("<I", data, base + 16)[0]
        raw_pointer = struct.unpack_from("<I", data, base + 20)[0]
        covered = max(virtual_size, raw_size)
        if covered and virtual_address <= rva < virtual_address + covered:
            offset = raw_pointer + (rva - virtual_address)
            return offset if offset < len(data) else None
    return None


def scrub(path: Path) -> dict[str, int | bool]:
    data = bytearray(path.read_bytes())
    _, section_count, _, data_directories, section_table = pe_layout(data)
    export_directory_entry = data_directories
    if export_directory_entry + 8 > len(data):
        raise ValueError("missing PE export data directory")
    export_rva, export_size = struct.unpack_from("<II", data, export_directory_entry)
    if not export_rva and not export_size:
        return {"changed": False, "export_rva": 0, "export_size": 0, "number_of_functions": 0, "number_of_names": 0}
    export_offset = rva_to_file_offset(data, export_rva, section_count, section_table)
    if export_offset is None or export_offset + 40 > len(data):
        raise ValueError("invalid PE export directory RVA")
    number_of_functions = struct.unpack_from("<I", data, export_offset + 20)[0]
    number_of_names = struct.unpack_from("<I", data, export_offset + 24)[0]
    if number_of_functions or number_of_names:
        raise ValueError(
            "refusing to remove non-empty PE export directory: "
            f"functions={number_of_functions} names={number_of_names}"
        )
    struct.pack_into("<II", data, export_directory_entry, 0, 0)
    export_end = min(len(data), export_offset + export_size)
    data[export_offset:export_end] = b"\0" * (export_end - export_offset)
    path.write_bytes(data)
    return {
        "changed": True,
        "export_rva": export_rva,
        "export_size": export_size,
        "number_of_functions": number_of_functions,
        "number_of_names": number_of_names,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    args = parser.parse_args()
    result = scrub(Path(args.artifact))
    print(
        "scrubbed PE export directory: "
        f"changed={result['changed']} functions={result['number_of_functions']} names={result['number_of_names']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
