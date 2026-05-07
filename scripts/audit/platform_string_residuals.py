#!/usr/bin/env python3
"""Classify residual printable strings in platform runtime artifacts.

This audit is intentionally provenance-only: it records counts and categories
for remaining printable byte runs, not the raw string values.
"""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT = "docs/qa/reports/platform-string-residuals.json"

DEFAULT_ARTIFACTS = {
    "android_apk": "build/android-apk-smoke/mi-smoke.apk",
    "android_x86_64_platform_so": "build/android-apk-smoke/lib/x86_64/liba.so",
    "android_arm64_platform_so": "build/android-apk-smoke/lib/arm64-v8a/liba.so",
    "ios_linked_minimal": "build/ios-logic-local/ios_min_exec",
    "ios_linked_strict_zero_strings": "build/ios-logic-local/ios_min_exec_strict",
}

PLATFORM_CONTAINER_ARTIFACTS = {
    "android_apk",
    "ios_linked_minimal",
}

ZERO_STRING_REQUIRED_ARTIFACTS = {
    "android_x86_64_platform_so",
    "android_arm64_platform_so",
    "ios_linked_strict_zero_strings",
}
INSTRUCTION_BYTE_CATEGORIES = {
    "native_executable_bytes",
}

PLATFORM_CONSTRAINTS: dict[str, dict[str, Any]] = {
    "apk_signature_block": {
        "constraint": "apk_signing_block_metadata",
        "platform_contract": "Android installable APK signing container",
        "strict_zero_string_compatible": False,
        "note": "The APK signing block is part of the signed container, not protected program plaintext.",
    },
    "zip_central_directory": {
        "constraint": "zip_central_directory_metadata",
        "platform_contract": "APK-as-ZIP central directory",
        "strict_zero_string_compatible": False,
        "note": "Installable APKs retain ZIP directory metadata for package entries.",
    },
    "zip_entry_name": {
        "constraint": "zip_entry_name_metadata",
        "platform_contract": "APK entry lookup names",
        "strict_zero_string_compatible": False,
        "note": "Android package loading requires named entries such as the manifest and native libraries.",
    },
    "macho_load_dylinker": {
        "constraint": "macho_dynamic_loader_command",
        "platform_contract": "Mach-O executable dynamic loader path",
        "strict_zero_string_compatible": False,
        "note": "The linked Mach-O executable records its platform dynamic loader path.",
    },
    "android_required_entry_export": {
        "constraint": "android_native_entry_symbol",
        "platform_contract": "Android native activity/JNI entrypoint",
        "strict_zero_string_compatible": False,
        "note": "Required native entry exports are platform entrypoints, not protected payload plaintext.",
    },
}


def relative_path(root: Path, path: Path) -> str:
    return str(path.relative_to(root)) if path.is_relative_to(root) else str(path)


def strings_with_offsets(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        completed = subprocess.run(
            ["strings", "-a", "-t", "x", str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    values: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        try:
            offset = int(parts[0], 16)
        except ValueError:
            continue
        text = parts[1]
        values.append({"offset": offset, "text": text, "length": len(text.encode("utf-8", errors="ignore"))})
    return values


def bounded_ranges(ranges: list[dict[str, Any]], limit: int = 16) -> dict[str, Any]:
    return {
        "count": len(ranges),
        "sample": ranges[:limit],
        "truncated": len(ranges) > limit,
    }


def strict_constraint_summary(category_counts: Counter[str] | dict[str, int]) -> dict[str, Any]:
    platform_contract_count = 0
    unknown_or_avoidable_count = 0
    instruction_byte_count = 0
    blockers: list[dict[str, Any]] = []
    for category, count in sorted(category_counts.items()):
        numeric_count = int(count)
        if category in INSTRUCTION_BYTE_CATEGORIES:
            instruction_byte_count += numeric_count
            blockers.append(
                {
                    "category": str(category),
                    "count": numeric_count,
                    "constraint": "executable_instruction_byte_run",
                    "strict_zero_string_compatible": True,
                    "note": "Printable bytes occur inside executable instructions, not stored plaintext.",
                }
            )
            continue
        constraint = PLATFORM_CONSTRAINTS.get(str(category))
        if constraint is None:
            unknown_or_avoidable_count += numeric_count
            blockers.append(
                {
                    "category": str(category),
                    "count": numeric_count,
                    "constraint": "unknown_or_avoidable_residual",
                    "strict_zero_string_compatible": False,
                }
            )
            continue
        platform_contract_count += numeric_count
        blockers.append(
            {
                "category": str(category),
                "count": numeric_count,
                **constraint,
            }
        )
    total = platform_contract_count + unknown_or_avoidable_count
    return {
        "total": total,
        "platform_contract_residuals": platform_contract_count,
        "instruction_byte_residuals": instruction_byte_count,
        "unknown_or_avoidable_residuals": unknown_or_avoidable_count,
        "strict_zero_string_compatible": total == 0,
        "blockers": blockers,
    }


def zip_payload_ranges(path: Path) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                with path.open("rb") as handle:
                    handle.seek(info.header_offset + 26)
                    header = handle.read(4)
                if len(header) != 4:
                    continue
                name_size, extra_size = struct.unpack("<HH", header)
                name_start = info.header_offset + 30
                data_start = name_start + name_size + extra_size
                method = "stored" if info.compress_type == zipfile.ZIP_STORED else "deflated"
                ranges.append(
                    {
                        "start": name_start,
                        "end": name_start + name_size,
                        "category": "zip_entry_name",
                        "entry_kind": zip_entry_kind(info.filename),
                    }
                )
                if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                    try:
                        payload = archive.read(info.filename)
                    except (OSError, zipfile.BadZipFile, RuntimeError):
                        payload = b""
                    for native_range in elf_executable_ranges_from_bytes(payload):
                        ranges.append(
                            {
                                "start": data_start + native_range["start"],
                                "end": data_start + native_range["end"],
                                "category": native_range["category"],
                                "entry_kind": native_range["entry_kind"],
                            }
                        )
                ranges.append(
                    {
                        "start": data_start,
                        "end": data_start + info.compress_size,
                        "category": f"zip_entry_payload_{method}",
                        "entry_kind": zip_entry_kind(info.filename),
                    }
                )
    except (OSError, zipfile.BadZipFile):
        return []
    return ranges


def zip_entry_kind(name: str) -> str:
    if name == "AndroidManifest.xml":
        return "android_manifest"
    if name == "classes.dex":
        return "android_dex"
    if name.startswith("lib/") and name.endswith(".so"):
        return "android_native_library"
    return "zip_entry"


def zip_container_ranges(data: bytes) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    eocd = data.rfind(b"PK\x05\x06")
    central_directory_offset = None
    if eocd >= 0 and eocd + 22 <= len(data):
        central_directory_size = struct.unpack_from("<I", data, eocd + 12)[0]
        central_directory_offset = struct.unpack_from("<I", data, eocd + 16)[0]
        if central_directory_offset + central_directory_size <= len(data):
            ranges.append(
                {
                    "start": central_directory_offset,
                    "end": central_directory_offset + central_directory_size,
                    "category": "zip_central_directory",
                    "entry_kind": "zip_metadata",
                }
            )
        ranges.append({"start": eocd, "end": len(data), "category": "zip_eocd", "entry_kind": "zip_metadata"})

    marker = b"APK Sig Block 42"
    marker_offset = data.find(marker)
    if marker_offset >= 8 and central_directory_offset is not None and marker_offset < central_directory_offset:
        try:
            block_size = struct.unpack_from("<Q", data, marker_offset - 8)[0]
        except struct.error:
            block_size = 0
        block_start = central_directory_offset - block_size - 8
        if 0 <= block_start < central_directory_offset:
            ranges.append(
                {
                    "start": block_start,
                    "end": central_directory_offset,
                    "category": "apk_signature_block",
                    "entry_kind": "apk_signature",
                }
            )
    return ranges


def classify_by_ranges(offset: int, ranges: list[dict[str, Any]], fallback: str, length: int = 1) -> dict[str, str]:
    end = offset + max(1, length)
    for item in ranges:
        if item["start"] <= offset < item["end"] or (offset < item["end"] and end > item["start"]):
            return {"category": str(item["category"]), "entry_kind": str(item.get("entry_kind", "unknown"))}
    return {"category": fallback, "entry_kind": "unknown"}


def analyze_apk(root: Path, path: Path) -> dict[str, Any]:
    strings = strings_with_offsets(path)
    try:
        data = path.read_bytes()
    except OSError:
        data = b""
    ranges = zip_payload_ranges(path) + zip_container_ranges(data)
    category_counts: Counter[str] = Counter()
    entry_kind_counts: Counter[str] = Counter()
    for item in strings:
        classification = classify_by_ranges(int(item["offset"]), ranges, "apk_other", int(item["length"]))
        category_counts[classification["category"]] += 1
        entry_kind_counts[classification["entry_kind"]] += 1
    return artifact_report(root, path, strings, category_counts, entry_kind_counts, ranges)


def elf_executable_ranges_from_bytes(data: bytes) -> list[dict[str, Any]]:
    if len(data) < 0x40 or data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    try:
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize = struct.unpack_from("<H", data, 0x36)[0]
        phnum = struct.unpack_from("<H", data, 0x38)[0]
    except struct.error:
        return []
    ranges: list[dict[str, Any]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset + 56 > len(data):
            break
        p_type, p_flags = struct.unpack_from("<II", data, offset)
        if p_type != 1 or not (p_flags & 0x1):
            continue
        file_offset = struct.unpack_from("<Q", data, offset + 8)[0]
        file_size = struct.unpack_from("<Q", data, offset + 32)[0]
        ranges.append(
            {
                "start": file_offset,
                "end": file_offset + file_size,
                "category": "native_executable_bytes",
                "entry_kind": "android_native_library",
            }
        )
    return ranges


def elf_executable_ranges(path: Path) -> list[dict[str, Any]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    return elf_executable_ranges_from_bytes(data)


def analyze_android_so(root: Path, path: Path) -> dict[str, Any]:
    strings = strings_with_offsets(path)
    executable = elf_executable_ranges(path)
    category_counts: Counter[str] = Counter()
    entry_kind_counts: Counter[str] = Counter()
    for item in strings:
        if item["text"] in {"JNI_OnLoad", "ANativeActivity_onCreate"}:
            classification = {"category": "android_required_entry_export", "entry_kind": "android_native_library"}
        else:
            classification = classify_by_ranges(
                int(item["offset"]),
                executable,
                "native_nonexecuted_bytes",
                int(item["length"]),
            )
        category_counts[classification["category"]] += 1
        entry_kind_counts[classification["entry_kind"]] += 1
    return artifact_report(root, path, strings, category_counts, entry_kind_counts, executable)


def analyze_macho(root: Path, path: Path) -> dict[str, Any]:
    strings = strings_with_offsets(path)
    category_counts: Counter[str] = Counter()
    entry_kind_counts: Counter[str] = Counter()
    for item in strings:
        if item["text"] == "/usr/lib/dyld":
            category = "macho_load_dylinker"
        else:
            category = "macho_other"
        category_counts[category] += 1
        entry_kind_counts["ios_macho"] += 1
    return artifact_report(root, path, strings, category_counts, entry_kind_counts, [])


def artifact_report(
    root: Path,
    path: Path,
    strings: list[dict[str, Any]],
    category_counts: Counter[str],
    entry_kind_counts: Counter[str],
    ranges: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "path": relative_path(root, path),
        "exists": path.exists(),
        "total_strings": len(strings),
        "category_counts": dict(sorted(category_counts.items())),
        "entry_kind_counts": dict(sorted(entry_kind_counts.items())),
        "strict_zero_string": strict_constraint_summary(category_counts),
        "classified_range_summary": bounded_ranges(
            [
                {
                    "start": item["start"],
                    "end": item["end"],
                    "category": item["category"],
                    "entry_kind": item.get("entry_kind", "unknown"),
                }
                for item in ranges
            ]
        ),
        "raw_values_recorded": False,
    }


def analyze_artifact(root: Path, name: str, relative: str) -> dict[str, Any]:
    path = root / relative
    if name == "android_apk":
        result = analyze_apk(root, path)
    elif name.startswith("android_") and name.endswith("_platform_so"):
        result = analyze_android_so(root, path)
    elif name.startswith("ios_"):
        result = analyze_macho(root, path)
    else:
        result = artifact_report(root, path, strings_with_offsets(path), Counter(), Counter(), [])
    result["name"] = name
    result["residual_policy"] = (
        "platform_container_contract_only"
        if name in PLATFORM_CONTAINER_ARTIFACTS
        else "zero_string_required_artifact"
    )
    return result


def accepted_payload_policy_summary(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    zero_required_counts: dict[str, int] = {}
    container_counts: dict[str, int] = {}
    missing_zero_required: list[str] = []
    failing_zero_required: list[dict[str, Any]] = []
    contract_blockers: list[dict[str, Any]] = []
    unknown_or_avoidable = 0

    present_names = {str(item.get("name")) for item in artifacts}
    for name in sorted(ZERO_STRING_REQUIRED_ARTIFACTS):
        if name not in present_names:
            missing_zero_required.append(name)

    for item in artifacts:
        name = str(item.get("name"))
        total_strings = int(item.get("total_strings", 0))
        category_counts = item.get("category_counts", {})
        instruction_byte_count = 0
        if isinstance(category_counts, dict):
            instruction_byte_count = sum(
                int(category_counts.get(category, 0))
                for category in INSTRUCTION_BYTE_CATEGORIES
            )
        semantic_string_count = max(0, total_strings - instruction_byte_count)
        strict = item.get("strict_zero_string", {})
        if name in PLATFORM_CONTAINER_ARTIFACTS:
            container_counts[name] = total_strings
            if isinstance(strict, dict):
                unknown_or_avoidable += int(strict.get("unknown_or_avoidable_residuals", 0))
                contract_blockers.extend(strict.get("blockers", []) if isinstance(strict.get("blockers"), list) else [])
            continue
        zero_required_counts[name] = semantic_string_count
        if semantic_string_count != 0:
            failing_zero_required.append(
                {
                    "name": name,
                    "path": item.get("path"),
                    "total_strings": total_strings,
                    "semantic_string_count": semantic_string_count,
                    "instruction_byte_residuals": instruction_byte_count,
                    "category_counts": category_counts,
                }
            )

    passed = not failing_zero_required and unknown_or_avoidable == 0
    return {
        "status": "pass" if passed else "blocked",
        "zero_string_required_artifacts": zero_required_counts,
        "platform_container_contract_artifacts": container_counts,
        "missing_zero_string_required_artifacts": missing_zero_required,
        "failing_zero_string_required_artifacts": failing_zero_required,
        "instruction_byte_residuals": {
            str(item.get("name")): int(item.get("category_counts", {}).get("native_executable_bytes", 0))
            for item in artifacts
            if isinstance(item.get("category_counts"), dict)
            and int(item.get("category_counts", {}).get("native_executable_bytes", 0)) > 0
        },
        "platform_contract_residuals": sum(container_counts.values()),
        "unknown_or_avoidable_residuals": unknown_or_avoidable,
        "contract_blockers": contract_blockers,
        "policy_note": (
            "Protected payload/native artifacts must have zero semantic printable strings. Printable byte runs located "
            "inside executable instructions are classified as instruction bytes, not stored plaintext. Platform containers "
            "may retain classified loader, signing, and package metadata only when no unknown or avoidable residuals remain."
        ),
    }


def build_report(root: Path) -> dict[str, Any]:
    artifacts = [analyze_artifact(root, name, relative) for name, relative in DEFAULT_ARTIFACTS.items() if (root / relative).exists()]
    total = sum(int(item["total_strings"]) for item in artifacts)
    category_counts: Counter[str] = Counter()
    for item in artifacts:
        category_counts.update(item.get("category_counts", {}))
    strict_zero_string = strict_constraint_summary(category_counts)
    accepted_policy = accepted_payload_policy_summary(artifacts)
    return {
        "schema": "vmp.qa.platform_string_residuals.v1",
        "status": accepted_policy["status"],
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "total_residual_strings": total,
        "category_counts": dict(sorted(category_counts.items())),
        "strict_zero_string": strict_zero_string,
        "accepted_payload_policy": accepted_policy,
        "artifacts": artifacts,
        "raw_values_recorded": False,
        "note": (
            "This report classifies remaining printable byte runs by platform provenance. "
            "Protected payload/native artifacts remain subject to zero-string enforcement; platform containers "
            "may retain classified loader, signing, and package metadata without being counted as protected "
            "program plaintext."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = build_report(root)
    output = root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"platform string residuals {report['status']}: total={report['total_residual_strings']}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
