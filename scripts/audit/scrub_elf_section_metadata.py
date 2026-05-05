#!/usr/bin/env python3
"""Remove non-loaded ELF section metadata from a generated release artifact."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import NamedTuple

PT_LOAD = 1


class ElfLayout(NamedTuple):
    prefix: str
    elf_class: str
    phoff: int
    shoff: int
    phentsize: int
    phnum: int
    shoff_field: int
    shentsize_field: int
    shnum_field: int
    shstrndx_field: int


def parse_layout(data: bytearray) -> ElfLayout:
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        raise ValueError("expected ELF artifact")
    elf_class = data[4]
    endian = data[5]
    if endian == 1:
        prefix = "<"
    elif endian == 2:
        prefix = ">"
    else:
        raise ValueError("unsupported ELF endian")
    try:
        if elf_class == 2:
            return ElfLayout(
                prefix=prefix,
                elf_class="ELF64",
                phoff=struct.unpack_from(prefix + "Q", data, 32)[0],
                shoff=struct.unpack_from(prefix + "Q", data, 40)[0],
                phentsize=struct.unpack_from(prefix + "H", data, 54)[0],
                phnum=struct.unpack_from(prefix + "H", data, 56)[0],
                shoff_field=40,
                shentsize_field=58,
                shnum_field=60,
                shstrndx_field=62,
            )
        if elf_class == 1:
            return ElfLayout(
                prefix=prefix,
                elf_class="ELF32",
                phoff=struct.unpack_from(prefix + "I", data, 28)[0],
                shoff=struct.unpack_from(prefix + "I", data, 32)[0],
                phentsize=struct.unpack_from(prefix + "H", data, 42)[0],
                phnum=struct.unpack_from(prefix + "H", data, 44)[0],
                shoff_field=32,
                shentsize_field=46,
                shnum_field=48,
                shstrndx_field=50,
            )
    except struct.error as error:
        raise ValueError(str(error)) from error
    raise ValueError("unsupported ELF class")


def loaded_file_end(data: bytearray, layout: ElfLayout) -> int:
    if layout.phoff == 0 or layout.phentsize == 0 or layout.phnum == 0:
        raise ValueError("missing ELF program header table")
    table_end = layout.phoff + layout.phentsize * layout.phnum
    if table_end > len(data):
        raise ValueError("invalid ELF program header table")
    loaded_end = 0
    for index in range(layout.phnum):
        offset = layout.phoff + index * layout.phentsize
        try:
            p_type = struct.unpack_from(layout.prefix + "I", data, offset)[0]
            if p_type != PT_LOAD:
                continue
            if layout.elf_class == "ELF64":
                p_offset = struct.unpack_from(layout.prefix + "Q", data, offset + 8)[0]
                p_filesz = struct.unpack_from(layout.prefix + "Q", data, offset + 32)[0]
            else:
                p_offset = struct.unpack_from(layout.prefix + "I", data, offset + 4)[0]
                p_filesz = struct.unpack_from(layout.prefix + "I", data, offset + 16)[0]
        except struct.error as error:
            raise ValueError(str(error)) from error
        loaded_end = max(loaded_end, p_offset + p_filesz)
    if loaded_end == 0 or loaded_end > len(data):
        raise ValueError("invalid ELF load segment layout")
    if layout.shoff and loaded_end > layout.shoff:
        raise ValueError("unexpected ELF load/section layout")
    return loaded_end


def scrub(path: Path, *, preserve_size: bool = False) -> dict[str, int | str | bool]:
    data = bytearray(path.read_bytes())
    layout = parse_layout(data)
    loaded_end = loaded_file_end(data, layout)
    if layout.elf_class == "ELF64":
        struct.pack_into(layout.prefix + "Q", data, layout.shoff_field, 0)
    else:
        struct.pack_into(layout.prefix + "I", data, layout.shoff_field, 0)
    struct.pack_into(layout.prefix + "H", data, layout.shentsize_field, 0)
    struct.pack_into(layout.prefix + "H", data, layout.shnum_field, 0)
    struct.pack_into(layout.prefix + "H", data, layout.shstrndx_field, 0)
    original_size = len(data)
    if preserve_size:
        data[loaded_end:] = b"\0" * (len(data) - loaded_end)
    else:
        del data[loaded_end:]
    path.write_bytes(data)
    return {
        "elf_class": layout.elf_class,
        "loaded_file_end": loaded_end,
        "original_size": original_size,
        "scrubbed_size": len(data),
        "preserve_size": preserve_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preserve-size",
        action="store_true",
        help="zero non-loaded trailing metadata instead of truncating the file",
    )
    parser.add_argument("artifact")
    args = parser.parse_args()
    result = scrub(Path(args.artifact), preserve_size=args.preserve_size)
    print(
        "scrubbed ELF section metadata: "
        f"class={result['elf_class']} original_size={result['original_size']} "
        f"scrubbed_size={result['scrubbed_size']} preserve_size={result['preserve_size']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
