#!/usr/bin/env python3
"""Audit Mach-O metadata exposure for iOS/macOS artifacts.

The default mode is report-only because Mach-O segment/load-command metadata and
code signatures are part of the platform contract. Strict mode is available for
experiments and will fail on the observed surface findings.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from anti_analysis import ArtifactSurfacePolicy


DEFAULT_ARTIFACTS = ("build/ios-logic/libmi_platform.a",)

THIN_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xfe\xed\xfa\xce": (">", False),
    b"\xce\xfa\xed\xfe": ("<", False),
    b"\xfe\xed\xfa\xcf": (">", True),
    b"\xcf\xfa\xed\xfe": ("<", True),
}

FAT_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}

FILETYPE_NAMES = {
    0x1: "MH_OBJECT",
    0x2: "MH_EXECUTE",
    0x3: "MH_FVMLIB",
    0x4: "MH_CORE",
    0x5: "MH_PRELOAD",
    0x6: "MH_DYLIB",
    0x7: "MH_DYLINKER",
    0x8: "MH_BUNDLE",
    0x9: "MH_DYLIB_STUB",
    0xA: "MH_DSYM",
    0xB: "MH_KEXT_BUNDLE",
    0xC: "MH_FILESET",
}

LC_REQ_DYLD = 0x80000000

LOAD_COMMAND_NAMES = {
    0x1: "LC_SEGMENT",
    0x2: "LC_SYMTAB",
    0xB: "LC_DYSYMTAB",
    0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER",
    0xF: "LC_ID_DYLINKER",
    0x18 | LC_REQ_DYLD: "LC_LOAD_WEAK_DYLIB",
    0x19: "LC_SEGMENT_64",
    0x1B: "LC_UUID",
    0x1C | LC_REQ_DYLD: "LC_RPATH",
    0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x1F | LC_REQ_DYLD: "LC_REEXPORT_DYLIB",
    0x20: "LC_LAZY_LOAD_DYLIB",
    0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO",
    0x22 | LC_REQ_DYLD: "LC_DYLD_INFO_ONLY",
    0x23 | LC_REQ_DYLD: "LC_LOAD_UPWARD_DYLIB",
    0x24: "LC_VERSION_MIN_MACOSX",
    0x25: "LC_VERSION_MIN_IPHONEOS",
    0x26: "LC_FUNCTION_STARTS",
    0x27: "LC_DYLD_ENVIRONMENT",
    0x28 | LC_REQ_DYLD: "LC_MAIN",
    0x29: "LC_DATA_IN_CODE",
    0x2A: "LC_SOURCE_VERSION",
    0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x2D: "LC_LINKER_OPTION",
    0x2E: "LC_LINKER_OPTIMIZATION_HINT",
    0x2F: "LC_VERSION_MIN_TVOS",
    0x30: "LC_VERSION_MIN_WATCHOS",
    0x31: "LC_NOTE",
    0x32: "LC_BUILD_VERSION",
    0x33 | LC_REQ_DYLD: "LC_DYLD_EXPORTS_TRIE",
    0x34 | LC_REQ_DYLD: "LC_DYLD_CHAINED_FIXUPS",
    0x35 | LC_REQ_DYLD: "LC_FILESET_ENTRY",
}

DYLIB_COMMANDS = {
    0xC,
    0xD,
    0x18 | LC_REQ_DYLD,
    0x1F | LC_REQ_DYLD,
    0x20,
    0x23 | LC_REQ_DYLD,
}

STANDARD_MACHO_NAMES = (
    b"__PAGEZERO",
    b"__TEXT",
    b"__text",
    b"__stubs",
    b"__stub_helper",
    b"__cstring",
    b"__const",
    b"__DATA",
    b"__DATA_CONST",
    b"__la_symbol_ptr",
    b"__nl_symbol_ptr",
    b"__mod_init_func",
    b"__LINKEDIT",
    b"__objc_classname",
    b"__objc_methname",
    b"__objc_methtype",
    b"__objc_classlist",
    b"__swift",
)


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run_tool(args: list[str], cwd: Path) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)
    return completed.returncode, completed.stdout.decode("utf-8", errors="replace")


def decode_c_string(raw: bytes) -> str:
    value = raw.split(b"\0", 1)[0]
    return value.decode("utf-8", errors="replace").strip()


def command_name(cmd: int) -> str:
    if cmd in LOAD_COMMAND_NAMES:
        return LOAD_COMMAND_NAMES[cmd]
    base = cmd & ~LC_REQ_DYLD
    if cmd & LC_REQ_DYLD and base in LOAD_COMMAND_NAMES:
        return f"{LOAD_COMMAND_NAMES[base]}|LC_REQ_DYLD"
    return f"0x{cmd:x}"


def find_hits(data: bytes, patterns: tuple[bytes, ...], base_offset: int) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for pattern in patterns:
        start = 0
        while True:
            offset = data.find(pattern, start)
            if offset < 0:
                break
            hits.append(
                {
                    "pattern": pattern.decode("ascii", errors="backslashreplace"),
                    "offset": base_offset + offset,
                }
            )
            start = offset + max(1, len(pattern))
            if len(hits) >= 80:
                return hits
    return hits


def _read_u32(prefix: str, data: bytes, offset: int) -> int:
    return struct.unpack_from(prefix + "I", data, offset)[0]


def parse_segment_sections(
    data: bytes,
    cursor: int,
    cmd: int,
    cmdsize: int,
    prefix: str,
) -> tuple[list[str], list[str]]:
    segment_names: list[str] = []
    section_names: list[str] = []
    if cmd == 0x19 and cmdsize >= 72:
        segment_name = decode_c_string(data[cursor + 8 : cursor + 24])
        if segment_name:
            segment_names.append(segment_name)
        nsects = _read_u32(prefix, data, cursor + 64)
        section_cursor = cursor + 72
        section_size = 80
    elif cmd == 0x1 and cmdsize >= 56:
        segment_name = decode_c_string(data[cursor + 8 : cursor + 24])
        if segment_name:
            segment_names.append(segment_name)
        nsects = _read_u32(prefix, data, cursor + 48)
        section_cursor = cursor + 56
        section_size = 68
    else:
        return segment_names, section_names

    command_end = cursor + cmdsize
    for _ in range(min(nsects, 4096)):
        if section_cursor + section_size > command_end:
            break
        section_name = decode_c_string(data[section_cursor : section_cursor + 16])
        section_segment_name = decode_c_string(data[section_cursor + 16 : section_cursor + 32])
        if section_name:
            section_names.append(
                f"{section_segment_name},{section_name}" if section_segment_name else section_name
            )
        section_cursor += section_size
    return segment_names, section_names


def parse_macho(data: bytes, label: str, base_offset: int) -> dict[str, Any]:
    magic = data[:4]
    if magic not in THIN_MAGICS:
        return {"path": label, "status": "unsupported_format"}
    prefix, is_64 = THIN_MAGICS[magic]
    header_size = 32 if is_64 else 28
    if len(data) < header_size:
        return {"path": label, "status": "error", "detail": "truncated Mach-O header"}

    try:
        cputype = _read_u32(prefix, data, 4)
        filetype = _read_u32(prefix, data, 12)
        ncmds = _read_u32(prefix, data, 16)
        sizeofcmds = _read_u32(prefix, data, 20)
        flags = _read_u32(prefix, data, 24)
    except struct.error as error:
        return {"path": label, "status": "error", "detail": str(error)}

    if header_size + sizeofcmds > len(data):
        return {
            "path": label,
            "status": "error",
            "detail": "load command table extends beyond artifact",
        }

    load_commands: list[str] = []
    segment_names: list[str] = []
    section_names: list[str] = []
    dylibs: list[str] = []
    symtab: dict[str, int] | None = None
    dysymtab: dict[str, int] | None = None
    code_signature: dict[str, int] | None = None
    encryption_info: dict[str, int] | None = None
    diagnostics: list[str] = []
    cursor = header_size

    for index in range(min(ncmds, 65535)):
        if cursor + 8 > len(data):
            diagnostics.append(f"load command {index} truncated")
            break
        try:
            cmd = _read_u32(prefix, data, cursor)
            cmdsize = _read_u32(prefix, data, cursor + 4)
        except struct.error as error:
            diagnostics.append(str(error))
            break
        if cmdsize < 8 or cursor + cmdsize > len(data):
            diagnostics.append(f"load command {index} has invalid size {cmdsize}")
            break
        load_commands.append(command_name(cmd))

        if cmd in {0x1, 0x19}:
            segments, sections = parse_segment_sections(data, cursor, cmd, cmdsize, prefix)
            segment_names.extend(segments)
            section_names.extend(sections)
        elif cmd == 0x2 and cmdsize >= 24:
            symtab = {
                "symoff": _read_u32(prefix, data, cursor + 8),
                "nsyms": _read_u32(prefix, data, cursor + 12),
                "stroff": _read_u32(prefix, data, cursor + 16),
                "strsize": _read_u32(prefix, data, cursor + 20),
            }
        elif cmd == 0xB and cmdsize >= 80:
            dysymtab = {
                "ilocalsym": _read_u32(prefix, data, cursor + 8),
                "nlocalsym": _read_u32(prefix, data, cursor + 12),
                "iextdefsym": _read_u32(prefix, data, cursor + 16),
                "nextdefsym": _read_u32(prefix, data, cursor + 20),
                "iundefsym": _read_u32(prefix, data, cursor + 24),
                "nundefsym": _read_u32(prefix, data, cursor + 28),
            }
        elif cmd in DYLIB_COMMANDS and cmdsize >= 24:
            name_offset = _read_u32(prefix, data, cursor + 8)
            if 0 < name_offset < cmdsize:
                name = decode_c_string(data[cursor + name_offset : cursor + cmdsize])
                if name:
                    dylibs.append(name)
        elif cmd == 0x1D and cmdsize >= 16:
            code_signature = {
                "dataoff": _read_u32(prefix, data, cursor + 8),
                "datasize": _read_u32(prefix, data, cursor + 12),
            }
        elif cmd in {0x21, 0x2C} and cmdsize >= 20:
            encryption_info = {
                "cryptoff": _read_u32(prefix, data, cursor + 8),
                "cryptsize": _read_u32(prefix, data, cursor + 12),
                "cryptid": _read_u32(prefix, data, cursor + 16),
            }
        cursor += cmdsize

    return {
        "path": label,
        "status": "observed",
        "file_offset": base_offset,
        "magic": magic.hex(),
        "class": "Mach-O 64-bit" if is_64 else "Mach-O 32-bit",
        "endian": "little" if prefix == "<" else "big",
        "cpu_type": cputype,
        "filetype": FILETYPE_NAMES.get(filetype, f"0x{filetype:x}"),
        "flags": flags,
        "load_command_count": ncmds,
        "sizeof_load_commands": sizeofcmds,
        "load_commands": load_commands,
        "segment_names": sorted(set(segment_names)),
        "section_names": sorted(set(section_names)),
        "dylibs": sorted(set(dylibs)),
        "symtab": symtab,
        "dysymtab": dysymtab,
        "code_signature": code_signature,
        "encryption_info": encryption_info,
        "standard_name_hits": find_hits(data, STANDARD_MACHO_NAMES, base_offset),
        "diagnostics": diagnostics,
    }


def parse_fat_macho(data: bytes, label: str, base_offset: int) -> tuple[list[dict[str, Any]], list[str]]:
    prefix, is_64 = FAT_MAGICS[data[:4]]
    diagnostics: list[str] = []
    observations: list[dict[str, Any]] = []
    if len(data) < 8:
        return observations, ["truncated fat Mach-O header"]
    nfat_arch = _read_u32(prefix, data, 4)
    entry_size = 32 if is_64 else 20
    cursor = 8
    for index in range(min(nfat_arch, 64)):
        if cursor + entry_size > len(data):
            diagnostics.append(f"fat arch {index} truncated")
            break
        try:
            if is_64:
                arch_offset = struct.unpack_from(prefix + "Q", data, cursor + 8)[0]
                arch_size = struct.unpack_from(prefix + "Q", data, cursor + 16)[0]
            else:
                arch_offset = _read_u32(prefix, data, cursor + 8)
                arch_size = _read_u32(prefix, data, cursor + 12)
        except struct.error as error:
            diagnostics.append(str(error))
            break
        if arch_offset + arch_size > len(data):
            diagnostics.append(f"fat arch {index} extends beyond artifact")
        else:
            observations.extend(
                collect_macho_observations(
                    data[arch_offset : arch_offset + arch_size],
                    f"{label}:arch{index}",
                    base_offset + arch_offset,
                )[0]
            )
        cursor += entry_size
    return observations, diagnostics


def gnu_archive_name(table: bytes, raw_name: str) -> str:
    name_offset = int(raw_name[1:].strip().rstrip("/"))
    if name_offset >= len(table):
        return raw_name
    end = table.find(b"\n", name_offset)
    if end < 0:
        end = len(table)
    return table[name_offset:end].rstrip(b"/").decode("utf-8", errors="replace")


def parse_ar_archive(data: bytes, label: str, base_offset: int) -> tuple[list[dict[str, Any]], list[str]]:
    observations: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    gnu_name_table = b""
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        if header[58:60] != b"`\n":
            diagnostics.append(f"invalid ar member header at offset {base_offset + offset}")
            break
        raw_name = header[:16].decode("utf-8", errors="replace").strip()
        raw_size = header[48:58].decode("ascii", errors="ignore").strip()
        try:
            size = int(raw_size)
        except ValueError:
            diagnostics.append(f"invalid ar member size at offset {base_offset + offset}")
            break
        content_start = offset + 60
        content_end = content_start + size
        if content_end > len(data):
            diagnostics.append(f"ar member {raw_name} extends beyond archive")
            break

        content = data[content_start:content_end]
        payload = content
        payload_offset = base_offset + content_start
        member_name = raw_name.rstrip("/")

        if raw_name.startswith("#1/"):
            try:
                name_length = int(raw_name[3:].strip())
            except ValueError:
                name_length = 0
            if 0 < name_length <= len(content):
                member_name = decode_c_string(content[:name_length])
                payload = content[name_length:]
                payload_offset += name_length
        elif raw_name == "//":
            gnu_name_table = content
        elif raw_name.startswith("/") and raw_name[1:].strip().rstrip("/").isdigit() and gnu_name_table:
            member_name = gnu_archive_name(gnu_name_table, raw_name)

        if payload[:4] in THIN_MAGICS or payload[:4] in FAT_MAGICS:
            nested, nested_diagnostics = collect_macho_observations(
                payload,
                f"{label}!{member_name or f'member@{offset}'}",
                payload_offset,
            )
            observations.extend(nested)
            diagnostics.extend(nested_diagnostics)

        offset = content_end + (size % 2)
    return observations, diagnostics


def collect_macho_observations(data: bytes, label: str, base_offset: int = 0) -> tuple[list[dict[str, Any]], list[str]]:
    if data.startswith(b"!<arch>\n"):
        return parse_ar_archive(data, label, base_offset)
    if data[:4] in FAT_MAGICS:
        return parse_fat_macho(data, label, base_offset)
    if data[:4] in THIN_MAGICS:
        return [parse_macho(data, label, base_offset)], []
    return [], [f"{label} is not a Mach-O, fat Mach-O, or ar archive"]


def observed_findings(binary: dict[str, Any]) -> list[dict[str, Any]]:
    if binary.get("status") != "observed":
        return []
    findings: list[dict[str, Any]] = []
    if binary.get("symtab"):
        findings.append(
            {
                "category": "macho_symbol_table_present",
                "pattern": "LC_SYMTAB",
                "offset": binary.get("file_offset"),
                "evidence": binary["symtab"],
            }
        )
    if binary.get("dysymtab"):
        findings.append(
            {
                "category": "macho_dynamic_symbol_table_present",
                "pattern": "LC_DYSYMTAB",
                "offset": binary.get("file_offset"),
                "evidence": binary["dysymtab"],
            }
        )
    if binary.get("dylibs"):
        findings.append(
            {
                "category": "macho_dylib_load_command",
                "pattern": "LC_LOAD_DYLIB",
                "offset": binary.get("file_offset"),
                "evidence": binary["dylibs"],
            }
        )
    if binary.get("code_signature"):
        findings.append(
            {
                "category": "macho_code_signature_present",
                "pattern": "LC_CODE_SIGNATURE",
                "offset": binary.get("file_offset"),
                "evidence": binary["code_signature"],
            }
        )
    if binary.get("standard_name_hits"):
        findings.append(
            {
                "category": "macho_standard_name_string",
                "pattern": "standard Mach-O segment/section name",
                "offset": None,
                "evidence": binary["standard_name_hits"],
            }
        )
    return findings


def surface_findings(path: Path) -> list[dict[str, Any]]:
    result = ArtifactSurfacePolicy.default().scan_file(path)
    return [
        {
            "category": finding.category.value,
            "pattern": finding.pattern,
            "offset": finding.offset,
            "evidence": finding.evidence,
        }
        for finding in result.findings
    ]


def _as_sequence(value: Any) -> list[Any]:
    if callable(value):
        try:
            value = value()
        except TypeError:
            return []
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    try:
        return list(value)
    except TypeError:
        return []


def _names(value: Any, limit: int = 40) -> list[str]:
    names = []
    for item in _as_sequence(value):
        name = getattr(item, "name", item)
        if callable(name):
            try:
                name = name()
            except TypeError:
                name = str(item)
        if name is None:
            continue
        text = str(name)
        if text:
            names.append(text)
    return sorted(set(names))[:limit]


def lief_observations(artifact: Path) -> dict[str, Any]:
    if importlib.util.find_spec("lief") is None:
        return {"tool": "lief", "status": "unavailable", "install_hint": "python3 -m pip install lief"}
    try:
        import lief  # type: ignore[import-not-found]
    except Exception as error:
        return {"tool": "lief", "status": "unavailable", "detail": str(error)[:200]}
    try:
        binary = lief.parse(str(artifact))
    except Exception as error:
        return {"tool": "lief", "status": "error", "detail": str(error)[:200]}
    if binary is None:
        return {"tool": "lief", "status": "unsupported_format"}
    return {
        "tool": "lief",
        "status": "observed",
        "format": str(getattr(binary, "format", "unknown")),
        "entrypoint": getattr(binary, "entrypoint", None),
        "libraries": _names(getattr(binary, "libraries", [])),
        "sections_sample": _names(getattr(binary, "sections", []), limit=80)[:30],
        "symbols_sample": _names(getattr(binary, "symbols", []), limit=80)[:30],
    }


def otool_observations(root: Path, artifact: Path) -> dict[str, Any]:
    if not has_tool("otool"):
        return {"tool": "otool", "status": "unavailable", "install_hint": "available on macOS runners"}
    code, output = run_tool(["otool", "-l", str(artifact)], root)
    if code != 0:
        return {"tool": "otool", "status": "error", "detail": output.strip()[:300]}
    command_names = re.findall(r"^\s*cmd\s+(\S+)", output, flags=re.MULTILINE)
    return {
        "tool": "otool",
        "status": "observed",
        "load_command_count": len(command_names),
        "commands_sample": sorted(set(command_names))[:40],
    }


def llvm_objdump_observations(root: Path, artifact: Path) -> dict[str, Any]:
    tool = next(
        (
            candidate
            for candidate in (
                os.environ.get("LLVM_OBJDUMP", ""),
                "llvm-objdump-18",
                "llvm-objdump-17",
                "llvm-objdump-16",
                "llvm-objdump-15",
                "llvm-objdump-14",
                "llvm-objdump",
            )
            if candidate and has_tool(candidate)
        ),
        None,
    )
    if tool is None:
        return {"tool": "llvm-objdump", "status": "unavailable", "install_hint": "install llvm-objdump"}
    code, output = run_tool([tool, "--macho", "--private-headers", str(artifact)], root)
    if code != 0:
        return {"tool": tool, "status": "error", "detail": output.strip()[:300]}
    commands = re.findall(r"^\s*cmd\s+(\S+)", output, flags=re.MULTILINE)
    return {
        "tool": tool,
        "status": "observed",
        "load_command_count": len(commands),
        "commands_sample": sorted(set(commands))[:40],
    }


def external_tool_observations(root: Path, artifact: Path) -> dict[str, Any]:
    return {
        "lief": lief_observations(artifact),
        "otool": otool_observations(root, artifact),
        "llvm_objdump": llvm_objdump_observations(root, artifact),
    }


def relative_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def scan_artifact(root: Path, relative: str) -> tuple[dict[str, Any] | None, bool]:
    artifact = (root / relative).resolve()
    if not artifact.exists():
        return None, False
    data = artifact.read_bytes()
    binaries, diagnostics = collect_macho_observations(data, relative_path(root, artifact), 0)
    metadata_findings = [finding for binary in binaries for finding in observed_findings(binary)]
    product_surface_findings = surface_findings(artifact)
    container = "ar_archive" if data.startswith(b"!<arch>\n") else "fat_macho" if data[:4] in FAT_MAGICS else "macho"
    return (
        {
            "artifact": relative_path(root, artifact),
            "container": container,
            "binary_count": len([binary for binary in binaries if binary.get("status") == "observed"]),
            "binaries": binaries,
            "diagnostics": diagnostics,
            "metadata_observed_findings": metadata_findings,
            "surface_observed_findings": product_surface_findings,
            "external_tool_observations": external_tool_observations(root, artifact),
        },
        bool(binaries),
    )


def build_report(root: Path, artifacts: list[str], strict: bool = False) -> dict[str, Any]:
    scanned = []
    missing = []
    unsupported = []
    observed_findings_total = 0
    for relative in artifacts:
        scan, supported = scan_artifact(root, relative)
        if scan is None:
            missing.append(relative)
            continue
        if not supported:
            unsupported.append(scan["artifact"])
        observed_findings_total += len(scan["metadata_observed_findings"]) + len(scan["surface_observed_findings"])
        scanned.append(scan)

    strict_findings = observed_findings_total if strict else 0
    status = "pass" if not missing and not unsupported and strict_findings == 0 else "fail"
    return {
        "schema": "vmp.qa.ios_macho_metadata.v1",
        "status": status,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "gate": "strict" if strict else "report_only_runtime_preserving",
        "scanned_artifacts": scanned,
        "missing_artifacts": missing,
        "unsupported_artifacts": unsupported,
        "observed_surface_findings": observed_findings_total,
        "strict_surface_findings": strict_findings,
        "policy_note": (
            "Mach-O load commands, segment names, symbol tables, and code signatures are observed for iOS "
            "artifact QA. The default gate is report-only because mutating these fields can break linking, "
            "loading, or Apple code signing; use --strict only for controlled experiments."
        ),
        "tooling": {
            "primary_parser": "built-in Mach-O/fat/ar parser",
            "optional_tools": ["lief", "otool", "llvm-objdump"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="docs/qa/reports/ios-macho-metadata.json")
    parser.add_argument("--artifact", action="append", default=[], help="artifact path relative to root")
    parser.add_argument("--strict", action="store_true", help="fail on observed Mach-O metadata findings")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    artifacts = args.artifact or list(DEFAULT_ARTIFACTS)
    report = build_report(root, artifacts, strict=args.strict)
    output = root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "ios macho metadata "
        f"{report['status']}: gate={report['gate']} observed_surface_findings={report['observed_surface_findings']}"
    )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
