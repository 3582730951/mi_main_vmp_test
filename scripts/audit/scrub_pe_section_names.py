#!/usr/bin/env python3
"""Remove printable PE/COFF metadata names from a generated release artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

COFF_SYMBOL_SIZE = 18
SECTION_NAME_SIZE = 8


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


def seed_material(path: Path, data: bytes, explicit_seed: str | None = None) -> bytes:
    if explicit_seed:
        return hashlib.sha256(explicit_seed.encode("utf-8")).digest()
    env_seed = os.environ.get("VMP_PE_SECTION_NAME_SEED")
    if env_seed:
        return hashlib.sha256(env_seed.encode("utf-8")).digest()
    return os.urandom(32) + hashlib.sha256(path.as_posix().encode("utf-8") + data).digest()


def randomized_section_name(seed: bytes, original_data: bytes, index: int) -> bytes:
    digest = hashlib.blake2s(
        original_data + index.to_bytes(4, "little"),
        key=seed[:32],
        digest_size=SECTION_NAME_SIZE,
        person=b"vmpsectn",
    ).digest()
    return bytes(0x80 | (byte & 0x7F) for byte in digest)


def scrub(path: Path, seed: str | None = None) -> int:
    return scrub_with_report(path, seed=seed)["section_count"]


def scrub_with_report(path: Path, seed: str | None = None) -> dict[str, object]:
    data = bytearray(path.read_bytes())
    original_data = bytes(data)
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

    if 0x40 <= pe_offset <= len(data):
        data[0x40:pe_offset] = b"\0" * (pe_offset - 0x40)
    struct.pack_into("<I", data, pe_offset + 8, 0)
    optional_header = pe_offset + 24
    if optional_header + 4 <= len(data):
        data[optional_header + 2 : optional_header + 4] = b"\0\0"

    material = seed_material(path, original_data, seed)
    seed_fingerprint = hashlib.sha256(material).hexdigest()[:16]
    section_data_end = 0
    section_names = []
    for index in range(section_count):
        name_offset = section_table + index * 40
        name = randomized_section_name(material, original_data, index)
        data[name_offset : name_offset + SECTION_NAME_SIZE] = name
        section_names.append(name.hex())
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
    return {
        "schema": "vmp.pe.section_name_scrub.v2",
        "artifact": str(path),
        "section_count": section_count,
        "seed_fingerprint": seed_fingerprint,
        "section_name_hex": section_names,
        "randomized_nonprintable_section_names": True,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    parser.add_argument("--seed", default=None)
    parser.add_argument("--report", default=None)
    args = parser.parse_args()
    report = scrub_with_report(Path(args.artifact), seed=args.seed)
    if args.report:
        output = Path(args.report)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "scrubbed PE section names: "
        f"sections={report['section_count']} seed_fingerprint={report['seed_fingerprint']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
