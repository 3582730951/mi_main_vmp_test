#!/usr/bin/env python3
"""Remove an empty PE import directory from a generated protected executable."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

IMPORT_DESCRIPTOR_SIZE = 20


def pe_layout(data: bytes) -> tuple[int, int, int, int]:
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
    return section_count, data_directories, section_table, optional_header_size


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


def import_descriptors_are_empty(data: bytes, import_offset: int, import_size: int) -> bool:
    if import_size < IMPORT_DESCRIPTOR_SIZE or import_offset + import_size > len(data):
        return False
    descriptor_count = import_size // IMPORT_DESCRIPTOR_SIZE
    for index in range(descriptor_count):
        base = import_offset + index * IMPORT_DESCRIPTOR_SIZE
        descriptor = data[base : base + IMPORT_DESCRIPTOR_SIZE]
        if any(descriptor):
            return False
    return True


def scrub(path: Path) -> dict[str, int | bool]:
    data = bytearray(path.read_bytes())
    section_count, data_directories, section_table, _ = pe_layout(data)
    import_directory_entry = data_directories + 8
    if import_directory_entry + 8 > len(data):
        raise ValueError("missing PE import data directory")
    import_rva, import_size = struct.unpack_from("<II", data, import_directory_entry)
    if not import_rva and not import_size:
        return {"changed": False, "import_rva": 0, "import_size": 0}
    import_offset = rva_to_file_offset(data, import_rva, section_count, section_table)
    if import_offset is None:
        raise ValueError("invalid PE import directory RVA")
    if not import_descriptors_are_empty(data, import_offset, import_size):
        raise ValueError("refusing to remove non-empty PE import directory")
    struct.pack_into("<II", data, import_directory_entry, 0, 0)
    import_end = min(len(data), import_offset + import_size)
    data[import_offset:import_end] = b"\0" * (import_end - import_offset)
    path.write_bytes(data)
    return {"changed": True, "import_rva": import_rva, "import_size": import_size}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    args = parser.parse_args()
    result = scrub(Path(args.artifact))
    print(
        "scrubbed PE import directory: "
        f"changed={result['changed']} rva=0x{result['import_rva']:x} size={result['import_size']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
