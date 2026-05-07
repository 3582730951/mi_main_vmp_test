#!/usr/bin/env python3
"""Append randomized, unreferenced PE decoy sections to raise script-locator cost."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path


SECTION_HEADER_SIZE = 40
PE_READ_INITIALIZED_DATA = 0x40000040


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def random_high_name(seed: bytes, index: int) -> bytes:
    digest = hashlib.blake2s(seed + index.to_bytes(4, "little"), digest_size=8, person=b"vmpdsect").digest()
    return bytes(0x80 | (byte & 0x7F) for byte in digest)


def add_decoy_sections(path: Path, minimum: int = 2, maximum: int = 5, seed: str | None = None) -> dict[str, object]:
    if minimum < 0 or maximum < minimum:
        raise ValueError("invalid decoy section bounds")
    data = bytearray(path.read_bytes())
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("expected PE artifact with MZ header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    section_table = optional + optional_header_size
    old_section_table_end = section_table + section_count * SECTION_HEADER_SIZE
    if old_section_table_end > len(data):
        raise ValueError("invalid PE section table")
    if optional_header_size < 64:
        raise ValueError("unsupported PE optional header")
    section_alignment = struct.unpack_from("<I", data, optional + 32)[0]
    file_alignment = struct.unpack_from("<I", data, optional + 36)[0]
    size_of_headers = struct.unpack_from("<I", data, optional + 60)[0]

    material = hashlib.sha256((seed or "").encode("utf-8")).digest() if seed else os.urandom(32)
    count = minimum + (material[0] % (maximum - minimum + 1))
    new_section_table_end = old_section_table_end + count * SECTION_HEADER_SIZE
    first_raw_pointer = min(
        (
            struct.unpack_from("<I", data, section_table + index * SECTION_HEADER_SIZE + 20)[0]
            for index in range(section_count)
            if struct.unpack_from("<I", data, section_table + index * SECTION_HEADER_SIZE + 20)[0] > 0
        ),
        default=size_of_headers,
    )
    if new_section_table_end > min(size_of_headers, first_raw_pointer):
        raise ValueError("not enough PE header slack for decoy section headers")

    last_virtual_end = 0
    last_raw_end = len(data)
    for index in range(section_count):
        header = section_table + index * SECTION_HEADER_SIZE
        virtual_size = struct.unpack_from("<I", data, header + 8)[0]
        virtual_address = struct.unpack_from("<I", data, header + 12)[0]
        raw_size = struct.unpack_from("<I", data, header + 16)[0]
        raw_pointer = struct.unpack_from("<I", data, header + 20)[0]
        if virtual_address:
            last_virtual_end = max(last_virtual_end, virtual_address + max(virtual_size, raw_size))
        if raw_pointer and raw_size:
            last_raw_end = max(last_raw_end, raw_pointer + raw_size)

    sections = []
    for added in range(count):
        digest = hashlib.blake2s(material + added.to_bytes(4, "little"), digest_size=32, person=b"vmpddata").digest()
        payload_size = 96 + ((digest[0] << 1) % 416)
        payload = bytearray(os.urandom(payload_size))
        for offset in range(payload_size):
            payload[offset] ^= digest[offset % len(digest)]
        raw_size = align_up(payload_size, file_alignment)
        raw_pointer = align_up(last_raw_end, file_alignment)
        virtual_address = align_up(last_virtual_end, section_alignment)
        name = random_high_name(material, added)
        if len(data) < raw_pointer:
            data.extend(b"\0" * (raw_pointer - len(data)))
        data.extend(payload)
        data.extend(b"\0" * (raw_size - payload_size))
        header = section_table + (section_count + added) * SECTION_HEADER_SIZE
        data[header : header + 8] = name
        struct.pack_into("<I", data, header + 8, payload_size)
        struct.pack_into("<I", data, header + 12, virtual_address)
        struct.pack_into("<I", data, header + 16, raw_size)
        struct.pack_into("<I", data, header + 20, raw_pointer)
        struct.pack_into("<I", data, header + 24, 0)
        struct.pack_into("<I", data, header + 28, 0)
        struct.pack_into("<H", data, header + 32, 0)
        struct.pack_into("<H", data, header + 34, 0)
        struct.pack_into("<I", data, header + 36, PE_READ_INITIALIZED_DATA)
        sections.append(
            {
                "index": section_count + added,
                "temporary_name_hex": name.hex(),
                "virtual_address": virtual_address,
                "raw_pointer": raw_pointer,
                "virtual_size": payload_size,
                "raw_size": raw_size,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        last_virtual_end = virtual_address + max(payload_size, raw_size)
        last_raw_end = raw_pointer + raw_size

    struct.pack_into("<H", data, pe_offset + 6, section_count + count)
    struct.pack_into("<I", data, optional + 56, align_up(last_virtual_end, section_alignment))
    path.write_bytes(data)
    return {
        "schema": "vmp.pe.decoy_sections.v1",
        "artifact": str(path),
        "original_section_count": section_count,
        "decoy_section_count": count,
        "final_section_count": section_count + count,
        "seed_fingerprint": hashlib.sha256(material).hexdigest()[:16],
        "sections": sections,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    parser.add_argument("--min", type=int, default=2)
    parser.add_argument("--max", type=int, default=5)
    parser.add_argument("--seed", default=None)
    parser.add_argument("--report", default=None)
    args = parser.parse_args()
    report = add_decoy_sections(Path(args.artifact), minimum=args.min, maximum=args.max, seed=args.seed)
    if args.report:
        output = Path(args.report)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "added PE decoy sections: "
        f"count={report['decoy_section_count']} final_sections={report['final_section_count']} "
        f"seed_fingerprint={report['seed_fingerprint']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
