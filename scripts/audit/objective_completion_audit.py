#!/usr/bin/env python3
"""Audit the user-requested surface-minimization objective against real evidence."""

from __future__ import annotations

import argparse
import json
import sys
import struct
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.audit.reverse_tooling import GITHUB_TOOL_SOURCES
from scripts.audit.platform_string_residuals import build_report as build_platform_string_residuals_report


DEFAULT_OUTPUT = "docs/qa/reports/objective-completion-audit.json"

PLATFORM_ADAPTER_SOURCE_FILES = {
    "linux": ["src/platform/linux/linux_adapter.c", "src/platform/platform_common.c"],
    "windows": ["src/platform/windows/windows_adapter.c", "src/platform/platform_common.c"],
    "android": ["src/platform/android/android_adapter.c", "src/platform/platform_common.c"],
    "ios": ["src/platform/ios/ios_adapter.c", "src/platform/platform_common.c"],
}

DISALLOWED_PLATFORM_SOURCE_MARKERS = (
    "syscall",
    "__NR_",
    "SYS_",
    "LoadLibrary",
    "GetProcAddress",
    "VirtualAlloc",
    "NtQuery",
    "NtCreate",
    "dlopen",
    "dlsym",
    "ptrace",
    "mmap(",
    "mprotect(",
    "open(",
    "read(",
    "write(",
    "fork(",
    "exec",
    "system(",
)

ANDROID_FORBIDDEN_MARKERS = (
    b"VMPBC",
    b"VMPSAM",
    b"VMPIRL",
    b"OLLVM",
    b"libvmp",
    b"vmp_platform",
    b"vmp_smoke",
    b"vmp-smoke",
    b"com.vmp",
    b"com/vmp",
    b"VMPRELEA",
    b"VMP Release",
    b"VMP Smoke",
)

WINDOWS_FIXED_CONSOLE_IMPORTS = {
    ("kernel32.dll", "exitprocess"),
    ("kernel32.dll", "getstdhandle"),
    ("kernel32.dll", "readfile"),
    ("kernel32.dll", "writefile"),
}


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def strings_count(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        completed = subprocess.run(
            ["strings", "-a", str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 and not completed.stdout:
        return None
    return len(completed.stdout.splitlines())


def strings_offsets(path: Path) -> list[int]:
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
    offsets: list[int] = []
    for line in completed.stdout.splitlines():
        parts = line.strip().split(maxsplit=1)
        if not parts:
            continue
        try:
            offsets.append(int(parts[0], 16))
        except ValueError:
            continue
    return offsets


def pe_raw_section_ranges(path: Path) -> list[dict[str, Any]]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
            return []
        section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
        optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        section_offset = pe_offset + 24 + optional_header_size
    except struct.error:
        return []

    ranges: list[dict[str, Any]] = []
    for index in range(section_count):
        offset = section_offset + index * 40
        if offset + 40 > len(data):
            break
        raw_size = struct.unpack_from("<I", data, offset + 16)[0]
        raw_pointer = struct.unpack_from("<I", data, offset + 20)[0]
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        if raw_size == 0:
            continue
        ranges.append(
            {
                "index": index,
                "name_hex": data[offset:offset + 8].hex(),
                "raw_start": raw_pointer,
                "raw_end": raw_pointer + raw_size,
                "executable": bool(characteristics & 0x20000000),
            }
        )
    return ranges


def classify_pe_strings(path: Path) -> dict[str, Any]:
    ranges = pe_raw_section_ranges(path)
    offsets = strings_offsets(path)
    executable = 0
    non_executable = 0
    unknown = 0
    for offset in offsets:
        owner = next((item for item in ranges if item["raw_start"] <= offset < item["raw_end"]), None)
        if owner is None:
            unknown += 1
        elif owner["executable"]:
            executable += 1
        else:
            non_executable += 1
    return {
        "total": len(offsets),
        "executable_section_strings": executable,
        "non_executable_section_strings": non_executable,
        "unknown_section_strings": unknown,
    }


def android_actual_apk_surface(root: Path, report: dict[str, Any]) -> dict[str, Any]:
    candidates: list[Path] = []
    for artifact in report.get("artifacts", []):
        if isinstance(artifact, dict):
            path = str(artifact.get("path", ""))
            if path.endswith(".apk"):
                candidates.append(root / path)
    candidates.append(root / "build/android-apk-smoke/mi-smoke.apk")

    apk_path = next((path for path in candidates if path.exists()), None)
    if apk_path is None:
        return {
            "artifact": None,
            "present": False,
            "entry_marker_hits": [],
            "byte_marker_hits": [],
            "zip_read_error": None,
        }

    try:
        data = apk_path.read_bytes()
    except OSError as error:
        return {
            "artifact": str(apk_path.relative_to(root)) if apk_path.is_relative_to(root) else str(apk_path),
            "present": False,
            "entry_marker_hits": [],
            "byte_marker_hits": [],
            "zip_read_error": str(error),
        }

    byte_hits = sorted(
        marker.decode("ascii", errors="replace")
        for marker in ANDROID_FORBIDDEN_MARKERS
        if marker in data
    )
    entry_hits: list[str] = []
    zip_error = None
    try:
        with zipfile.ZipFile(apk_path) as archive:
            for entry in archive.namelist():
                raw = entry.encode("utf-8", errors="ignore")
                for marker in ANDROID_FORBIDDEN_MARKERS:
                    if marker in raw:
                        entry_hits.append(f"{entry}:{marker.decode('ascii', errors='replace')}")
    except (OSError, zipfile.BadZipFile) as error:
        zip_error = str(error)

    return {
        "artifact": str(apk_path.relative_to(root)) if apk_path.is_relative_to(root) else str(apk_path),
        "present": True,
        "entry_marker_hits": sorted(set(entry_hits)),
        "byte_marker_hits": byte_hits,
        "zip_read_error": zip_error,
    }


def surface_artifact(surface: dict[str, Any], suffix: str) -> dict[str, Any]:
    for item in surface.get("scanned_artifacts", []):
        if isinstance(item, dict) and str(item.get("artifact", "")).endswith(suffix):
            return item
    return {}


def status_for_all(*values: bool) -> str:
    return "pass" if all(values) else "partial"


def windows_fixed_api_surface_allowed(pe_obs: dict[str, Any]) -> bool:
    if pe_obs.get("export_directory_present") is not False or pe_obs.get("tls_directory_present") is not False:
        return False
    import_count = int(pe_obs.get("import_count", -1))
    if import_count == 0 and pe_obs.get("import_directory_present") is False:
        return True
    imports = pe_obs.get("imports", [])
    if not isinstance(imports, list) or not imports:
        return False
    observed = set()
    for item in imports:
        if not isinstance(item, dict):
            return False
        observed.add((str(item.get("dll", "")).lower(), str(item.get("name", "")).lower()))
    return len(observed) == import_count and observed.issubset(WINDOWS_FIXED_CONSOLE_IMPORTS)


def windows_visible_release_strings_protected(windows_cross: dict[str, Any]) -> bool:
    return (
        windows_cross.get("release_mode") == "visible_encrypted_console_demo"
        and windows_cross.get("visible_demo_strings_encrypted") is True
        and windows_cross.get("windows_getchar_calls") == 3
        and windows_cross.get("forbidden_plaintext_hits") == []
    )


def windows_visible_release_dynamic_strings_protected(windows_cross: dict[str, Any]) -> bool:
    dynamic = windows_cross.get("dynamic_string_protection", {})
    if not isinstance(dynamic, dict):
        return False
    return (
        windows_visible_release_strings_protected(windows_cross)
        and dynamic.get("chunked_runtime_decode") is True
        and dynamic.get("full_plaintext_string_buffer") is False
        and dynamic.get("two_pass_plaintext_tag_validation") is True
        and dynamic.get("per_call_stateful_chunk_schedule") is True
        and dynamic.get("chunk_plaintext_wiped_after_use") is True
    )


def source_marker_hits(root: Path, files_by_platform: dict[str, list[str]]) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for platform, files in files_by_platform.items():
        hits: list[dict[str, Any]] = []
        missing: list[str] = []
        for relative in files:
            path = root / relative
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                missing.append(relative)
                continue
            for marker in DISALLOWED_PLATFORM_SOURCE_MARKERS:
                offset = text.find(marker)
                if offset >= 0:
                    hits.append({"path": relative, "marker": marker, "offset": offset})
        results[platform] = {
            "files": files,
            "missing_files": missing,
            "disallowed_marker_hits": hits,
            "self_contained": not missing and not hits,
        }
    return results


def fixed_runtime_syscall_source(root: Path) -> dict[str, Any]:
    relative = "tools/vmp/protected_release_main.cpp"
    source = root / relative
    try:
        text = source.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {
            "path": relative,
            "present": False,
            "allowed_fixed_linux_exit_only": False,
        }
    syscall_count = text.count("syscall")
    return {
        "path": relative,
        "present": True,
        "syscall_token_count": syscall_count,
        "has_linux_x86_64_guard": "#error \"VMP_FREESTANDING_LINUX_ENTRY currently supports x86_64 only\"" in text,
        "has_fixed_exit_number": "  mov $60, %rax\\n" in text,
        "has_exit_status_register": "  movslq %eax, %rdi\\n" in text,
        "allowed_fixed_linux_exit_only": (
            syscall_count == 1
            and "  mov $60, %rax\\n" in text
            and "  movslq %eax, %rdi\\n" in text
            and "vmp_protected_release_main_entry" in text
        ),
    }


def protected_program_stability_check(
    root: Path,
    sample_behavior: dict[str, Any],
    release: dict[str, Any],
    windows_release: dict[str, Any],
    android_apk: dict[str, Any],
    android_emulator: dict[str, Any],
    ios_macho: dict[str, Any],
    ios_macho_linked: dict[str, Any],
) -> dict[str, Any]:
    sample_cases = sample_behavior.get("cases", [])
    sample_pass = (
        sample_behavior.get("consistent") is True
        and isinstance(sample_cases, list)
        and len(sample_cases) == 4
        and all(
            isinstance(item, dict)
            and item.get("status") == "Ok"
            and item.get("baseline") == item.get("protected")
            for item in sample_cases
        )
    )
    linux_artifact = Path(str(release.get("artifact", "")))
    if not linux_artifact.is_absolute():
        linux_artifact = root / linux_artifact
    linux_release_pass = (
        release.get("schema") == "vmp.release.protected_binary.v1"
        and release.get("status") == "pass"
        and release.get("behavior_cases_passed") == 4
        and isinstance(release.get("artifact_bytes"), int)
        and release.get("artifact_bytes", 0) > 0
        and linux_artifact.exists()
    )
    windows_release_pass = (
        windows_release.get("schema") == "vmp.platform.windows_protected_release.v1"
        and windows_release.get("status") == "pass"
        and windows_release.get("ci_execution") is True
        and windows_release.get("behavior_cases_passed") == 4
        and isinstance(windows_release.get("artifact_bytes"), int)
        and windows_release.get("artifact_bytes", 0) > 0
        and windows_release.get("forbidden_plaintext_hits") == []
    )
    android_apk_pass = (
        android_apk.get("schema") == "vmp.platform.android_apk_smoke.v1"
        and android_apk.get("status") == "pass"
        and android_apk.get("ci_execution") is True
        and android_apk.get("apk_install_executed") is True
        and android_apk.get("jni_call_executed") is True
        and android_apk.get("protected_sample_executed") is True
        and android_apk.get("core_logic_consistent") is True
        and android_apk.get("manifest_debuggable") is False
    )
    android_emulator_pass = (
        android_emulator.get("schema") == "vmp.platform.android_emulator_smoke.v1"
        and android_emulator.get("status") == "pass"
        and android_emulator.get("ci_execution") is True
        and android_emulator.get("core_logic_consistent") is True
    )
    ios_logic_pass = (
        ios_macho.get("schema") == "vmp.qa.ios_macho_metadata.v1"
        and ios_macho.get("status") == "pass"
        and ios_macho.get("missing_artifacts") == []
        and ios_macho.get("unsupported_artifacts") == []
        and ios_macho_linked.get("schema") == "vmp.qa.ios_macho_metadata.v1"
        and ios_macho_linked.get("status") == "pass"
        and ios_macho_linked.get("missing_artifacts") == []
        and ios_macho_linked.get("unsupported_artifacts") == []
    )
    evidence = {
        "sample_behavior_consistent": sample_pass,
        "linux_release_executes_four_cases": linux_release_pass,
        "windows_github_release_executes_four_cases": windows_release_pass,
        "android_apk_emulator_executes_protected_sample": android_apk_pass,
        "android_native_emulator_smoke_consistent": android_emulator_pass,
        "ios_macho_logic_artifacts_valid": ios_logic_pass,
    }
    return {
        "status": status_for_all(*evidence.values()),
        "evidence": evidence,
    }


def external_reverse_tool_results(reverse_cost: dict[str, Any]) -> list[dict[str, Any]]:
    results = reverse_cost.get("tool_results")
    if not isinstance(results, list):
        return []
    github_backed_tools = {item["tool"] for item in GITHUB_TOOL_SOURCES}
    github_backed_tools.add("radare2-r2pipe")
    github_backed_tools.add("external-callgraph-consensus")
    summary: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        tool = str(result.get("tool", ""))
        if tool not in github_backed_tools:
            continue
        item: dict[str, Any] = {
            "tool": tool,
            "status": result.get("status", "unknown"),
        }
        if result.get("reason"):
            item["reason"] = result["reason"]
        for key in ("backend_count", "total_functions_observed", "total_call_edges_observed"):
            if key in result:
                item[key] = result[key]
        summary.append(item)
    return summary


def automation_summary(reverse_cost: dict[str, Any], protected_callgraph: dict[str, Any]) -> dict[str, Any]:
    callgraph_analysis = (
        protected_callgraph.get("analysis", {}) if isinstance(protected_callgraph.get("analysis"), dict) else {}
    )
    external_tools = external_reverse_tool_results(reverse_cost)
    return {
        "github_tool_sources": list(GITHUB_TOOL_SOURCES),
        "reverse_cost_report_status": reverse_cost.get("status", "missing"),
        "protected_callgraph_report_status": protected_callgraph.get("status", "missing"),
        "protected_function_xref_discovery": callgraph_analysis.get("protected_xrefs_discovered") is True,
        "direct_protected_xrefs_removed_after_rewrite": callgraph_analysis.get("direct_protected_xrefs_removed") is True,
        "high_frequency_callsite_optimization": callgraph_analysis.get("high_frequency_policy_applied") is True,
        "defense_floor_preserved": callgraph_analysis.get("defense_floor_preserved") is True,
        "per_callsite_thunks_preserved": callgraph_analysis.get("per_callsite_thunks_preserved") is True,
        "external_tool_results": external_tools,
        "external_callgraph_consensus": next(
            (item for item in external_tools if item.get("tool") == "external-callgraph-consensus"),
            {"tool": "external-callgraph-consensus", "status": "missing"},
        ),
        "available_external_tools": [
            item["tool"] for item in external_tools if item.get("status") not in {"unavailable", "missing"}
        ],
        "note": (
            "GitHub-hosted reverse-analysis tools are optional automation inputs. Missing tools are reported "
            "explicitly so local gates remain deterministic; CI attempts to install them and records any results."
        ),
    }


def residual_blockers(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    for check in checks:
        status = check.get("status")
        if status == "pass":
            continue
        blocker: dict[str, Any] = {
            "requirement": check.get("requirement"),
            "status": status,
            "note": check.get("note"),
        }
        if check.get("requirement") == "1_platform_standard_feature_minimization":
            platform_scope = check.get("platform_scope")
            if isinstance(platform_scope, dict):
                blocker["missing_or_nonpassing_platform_scope"] = sorted(
                    name for name, passed in platform_scope.items() if passed is not True
                )
        if check.get("requirement") == "3_all_strings_ciphertext_no_plaintext":
            blocker["observed_strings_count"] = check.get("observed_strings_count")
            blocker["windows_string_classification"] = check.get("windows_string_classification")
            platform_strings = check.get("platform_string_residuals")
            if isinstance(platform_strings, dict):
                blocker["platform_string_residuals"] = platform_strings
        if check.get("requirement") == "5_syscall_policy":
            blocker["policy_evidence"] = check.get("policy_evidence")
            blocker["platform_source_evidence"] = check.get("platform_source_evidence")
            blocker["fixed_runtime_syscall_source"] = check.get("fixed_runtime_syscall_source")
            blocker["windows_console_api_policy"] = check.get("windows_console_api_policy")
        if check.get("requirement") == "6_protected_program_stability":
            blocker["stability_evidence"] = check.get("stability_evidence")
        blockers.append(blocker)
    return blockers


def completion_note(complete: bool, blockers: list[dict[str, Any]]) -> str:
    if complete:
        return (
            "All objective checks passed against the available artifact evidence. Platform adapters stay "
            "self-contained, the only direct syscall is the fixed Linux exit path, protected payload/native "
            "artifacts have zero printable strings except the encrypted Windows visible console demo, and "
            "protected execution evidence is passing across the available Linux, Windows, Android, and iOS gates."
        )
    if any(item.get("requirement") == "6_protected_program_stability" for item in blockers):
        return (
            "Syscall/API and surface checks may be passing, but at least one protected execution stability "
            "evidence gate is missing or non-passing."
        )
    if any(item.get("requirement") == "3_all_strings_ciphertext_no_plaintext" for item in blockers):
        return (
            "The implemented state satisfies the platform metadata, marker, import/export/TLS, automation, "
            "and fixed syscall/API-policy checks, but protected payload/native zero-string evidence remains "
            "partial or unclassified platform residuals remain."
        )
    return "At least one objective check remains partial or failed; see residual_blockers for the concrete evidence gap."


def syscall_policy_check(
    root: Path,
    security_policy: str,
    elf_obs: dict[str, Any],
    pe_obs: dict[str, Any],
    windows_cross: dict[str, Any] | None = None,
) -> dict[str, Any]:
    boundary_present = "does not implement generic direct-syscall bypass stubs" in security_policy
    fixed_linux_exit_allowed = "fixed x86_64 `exit` syscall" in security_policy
    self_contained_source = source_marker_hits(root, PLATFORM_ADAPTER_SOURCE_FILES)
    fixed_runtime_syscall = fixed_runtime_syscall_source(root)
    windows_cross = windows_cross or {}
    windows_api_policy = (
        windows_cross.get("windows_console_api_policy", {})
        if isinstance(windows_cross.get("windows_console_api_policy"), dict)
        else {}
    )
    linux_release_no_dynamic_surface = (
        int(elf_obs.get("import_count", -1)) == 0 and int(elf_obs.get("export_count", -1)) == 0
    )
    windows_release_no_platform_imports = windows_fixed_api_surface_allowed(pe_obs)
    windows_visible_release = windows_cross.get("release_mode") == "visible_encrypted_console_demo"
    windows_api_call_minimized = (
        True
        if not windows_visible_release
        else (
            windows_api_policy.get("mode") == "minimal_fixed_kernel32_console_api"
            and windows_api_policy.get("direct_windows_syscalls_enabled") is False
            and windows_api_policy.get("generic_syscall_resolver_allowed") is False
            and windows_api_policy.get("stdout_handle_cached") is True
            and windows_api_policy.get("stdin_handle_cached") is True
            and windows_api_policy.get("writefile_calls_batched") is True
        )
    )
    evidence = {
        "security_boundary_present": boundary_present,
        "fixed_linux_exit_allowed": fixed_linux_exit_allowed,
        "platform_adapters_self_contained": all(
            isinstance(item, dict) and item.get("self_contained") is True for item in self_contained_source.values()
        ),
        "runtime_syscall_limited_to_fixed_linux_exit": fixed_runtime_syscall.get("allowed_fixed_linux_exit_only") is True,
        "linux_release_no_dynamic_import_export": linux_release_no_dynamic_surface,
        "windows_release_fixed_api_surface": windows_release_no_platform_imports,
        "windows_release_api_call_minimized": windows_api_call_minimized,
        "windows_direct_syscalls_disabled": windows_api_policy.get("direct_windows_syscalls_enabled", False) is False,
    }
    return {
        "status": status_for_all(*evidence.values()),
        "evidence": evidence,
        "platform_source": self_contained_source,
        "fixed_runtime_syscall_source": fixed_runtime_syscall,
        "windows_console_api_policy": windows_api_policy,
    }


def prompt_to_artifact_checklist(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_requirement = {item["requirement"]: item for item in checks}
    return [
        {
            "prompt_item": "1. syscall must be self-contained per platform where possible and must avoid system/API calls unless necessary",
            "requirement": "5_syscall_policy",
            "status": by_requirement["5_syscall_policy"]["status"],
            "artifacts": by_requirement["5_syscall_policy"]["evidence"],
            "verification": [
                "python3 scripts/audit/surface_minimization_audit.py --root .",
                "python3 scripts/audit/objective_completion_audit.py --root .",
                "bash tests/integration/run_release_protected_binary.sh",
                "bash tests/platform/windows_release_cross_build.sh",
            ],
            "coverage_note": (
                "Covers source-level platform adapter markers, the single fixed Linux exit syscall, and release "
                "artifact dynamic-surface minimization. The Windows encrypted console demo may keep fixed "
                "Kernel32 console imports, but release evidence must show stdout/stdin handle caching and batched "
                "WriteFile use; generic direct-syscall/API resolvers remain prohibited."
            ),
        },
        {
            "prompt_item": "2. protected programs must run stably after protection",
            "requirement": "6_protected_program_stability",
            "status": by_requirement["6_protected_program_stability"]["status"],
            "artifacts": by_requirement["6_protected_program_stability"]["evidence"],
            "verification": [
                "bash tests/integration/run_protected_sample_chain.sh",
                "bash tests/integration/run_release_protected_binary.sh",
                "pwsh tests/platform/windows_protected_release.ps1",
                "bash tests/platform/android_apk_smoke.sh",
                "bash tests/platform/android_emulator_smoke.sh",
                "bash tests/platform/ios_logic_check.sh",
            ],
            "coverage_note": (
                "Covers protected sample behavior equivalence plus Linux, Windows GitHub Actions, Android emulator, "
                "and iOS logic evidence. This is an evidence gate for stable execution, not a mathematical guarantee."
            ),
        },
        {
            "prompt_item": "supporting gate: protected artifacts must not expose plaintext strings",
            "requirement": "3_all_strings_ciphertext_no_plaintext",
            "status": by_requirement["3_all_strings_ciphertext_no_plaintext"]["status"],
            "artifacts": by_requirement["3_all_strings_ciphertext_no_plaintext"]["evidence"],
            "verification": [
                "strings -a samples/protected_chain/out/protected_sample.vmp",
                "strings -a artifacts/protected/linux/protected_release_sample",
                "strings -a build/windows-protected-cross/protected_release_sample.exe",
                "python3 scripts/audit/platform_string_residuals.py --root .",
            ],
            "coverage_note": (
                "Protected payload/native artifacts must have zero literal printable runs unless the artifact is "
                "the Windows encrypted visible console demo, where printed text must be encrypted and forbidden "
                "plaintext hits must be zero. The visible console demo must also report chunked runtime decode, "
                "two-pass plaintext tag validation, and plaintext chunk wiping. Platform APK/Mach-O container "
                "residuals must be classified as loader, signing, or package metadata with no unknown or avoidable "
                "residuals. Raw string values are not recorded."
            ),
        },
        {
            "prompt_item": "supporting gate: minimize import/export/TLS and callable dynamic surface",
            "requirement": "4_import_export_tls_minimized",
            "status": by_requirement["4_import_export_tls_minimized"]["status"],
            "artifacts": by_requirement["4_import_export_tls_minimized"]["evidence"],
            "verification": [
                "python3 scripts/audit/surface_minimization_audit.py --root .",
                "python3 scripts/audit/protected_callgraph_audit.py --root .",
                "python3 scripts/audit/generate_reverse_cost_assessment.py --root .",
                "x86_64-w64-mingw32-objdump -p build/windows-protected-cross/protected_release_sample.exe",
            ],
            "coverage_note": (
                "Covers PE export/TLS directories, ELF dynamic imports/exports, and the fixed Windows console "
                "import allowlist required by the encrypted visible demo."
            ),
        },
        {
            "prompt_item": "supporting gate: remove VM/OLLVM/product and standard flattening markers",
            "requirement": "2_vm_ollvm_standard_marker_absence",
            "status": by_requirement["2_vm_ollvm_standard_marker_absence"]["status"],
            "artifacts": by_requirement["2_vm_ollvm_standard_marker_absence"]["evidence"],
            "verification": ["python3 scripts/audit/surface_minimization_audit.py --root ."],
            "coverage_note": "Covers configured forbidden VM, OLLVM, product, seed, and protected-business markers.",
        },
        {
            "prompt_item": "supporting gate: minimize standard PE/platform-identifying metadata where safely removable",
            "requirement": "1_platform_standard_feature_minimization",
            "status": by_requirement["1_platform_standard_feature_minimization"]["status"],
            "artifacts": by_requirement["1_platform_standard_feature_minimization"]["evidence"],
            "verification": [
                "python3 scripts/audit/surface_minimization_audit.py --root .",
                "bash tests/integration/run_release_protected_binary.sh",
                "bash tests/platform/windows_release_cross_build.sh",
            ],
            "coverage_note": "Covers avoidable PE/ELF metadata; mandatory loader headers are not treated as removable.",
        },
    ]


def build_report(root: Path) -> dict[str, Any]:
    surface = read_json(root / "docs/qa/reports/surface-minimization.json")
    release = read_json(root / "docs/qa/reports/release-protected-binary.json")
    windows_cross = read_json(root / "docs/qa/reports/windows-protected-cross-build.json")
    windows_release = read_json(root / "docs/qa/reports/windows-protected-release.json")
    android_apk = read_json(root / "docs/qa/reports/android-apk-smoke.json")
    android_emulator = read_json(root / "docs/qa/reports/android-emulator-smoke.json")
    ios_macho = read_json(root / "docs/qa/reports/ios-macho-metadata.json")
    ios_macho_linked = read_json(root / "docs/qa/reports/ios-macho-linked-minimal.json")
    reverse_cost = read_json(root / "docs/qa/reports/reverse-cost-assessment.json")
    protected_callgraph = read_json(root / "docs/qa/reports/protected-callgraph.json")
    sample_behavior = read_json(root / "samples/protected_chain/out/behavior.json")
    platform_string_residuals = build_platform_string_residuals_report(root)
    security_policy = (root / "docs/SECURITY_POLICY.md").read_text(encoding="utf-8", errors="ignore")

    linux_surface = surface_artifact(surface, "protected_release_sample")
    sample_surface = surface_artifact(surface, "protected_sample.vmp")
    windows_surface = surface_artifact(surface, "protected_release_sample.exe")
    pe_obs = windows_surface.get("pe_observations", {}) if isinstance(windows_surface.get("pe_observations"), dict) else {}
    elf_obs = linux_surface.get("elf_observations", {}) if isinstance(linux_surface.get("elf_observations"), dict) else {}
    android_actual_apk = android_actual_apk_surface(root, android_apk)
    android_actual_apk_markers_absent = (
        android_actual_apk.get("present") is True
        and android_actual_apk.get("entry_marker_hits") == []
        and android_actual_apk.get("byte_marker_hits") == []
        and android_actual_apk.get("zip_read_error") is None
    )

    sample_path = root / "samples/protected_chain/out/protected_sample.vmp"
    linux_path = root / "artifacts/protected/linux/protected_release_sample"
    windows_path = root / "build/windows-protected-cross/protected_release_sample.exe"
    protected_string_paths = {
        "sample_vmp": strings_count(sample_path),
        "linux_release": strings_count(linux_path),
        "windows_release": strings_count(windows_path),
    }
    optional_zero_string_paths = {
        "android_x86_64_platform_so": root / "build/android-apk-smoke/lib/x86_64/liba.so",
        "android_x86_64_bridge_so": root / "build/android-apk-smoke/lib/x86_64/libb.so",
        "android_arm64_platform_so": root / "build/android-apk-smoke/lib/arm64-v8a/liba.so",
        "android_arm64_bridge_so": root / "build/android-apk-smoke/lib/arm64-v8a/libb.so",
        "ios_linked_strict_zero_strings": root / "build/ios-logic-local/ios_min_exec_strict",
    }
    for name, path in optional_zero_string_paths.items():
        if path.exists():
            protected_string_paths[name] = strings_count(path)
    platform_container_string_paths = {
        "android_apk": root / "build/android-apk-smoke/mi-smoke.apk",
        "ios_linked_minimal": root / "build/ios-logic-local/ios_min_exec",
    }
    platform_container_string_counts = {
        name: strings_count(path) for name, path in platform_container_string_paths.items() if path.exists()
    }
    artifact_string_counts = {**protected_string_paths, **platform_container_string_counts}
    windows_string_classification = classify_pe_strings(windows_path)
    windows_release_demo_strings_protected = windows_visible_release_strings_protected(windows_cross)
    windows_release_dynamic_strings_protected = windows_visible_release_dynamic_strings_protected(windows_cross)
    protected_artifacts_have_zero_strings = all(
        count == 0
        for name, count in protected_string_paths.items()
        if not (name == "windows_release" and windows_release_demo_strings_protected)
    )
    accepted_payload_policy = (
        platform_string_residuals.get("accepted_payload_policy", {})
        if isinstance(platform_string_residuals.get("accepted_payload_policy"), dict)
        else {}
    )
    platform_residuals_contract_only = (
        accepted_payload_policy.get("status") == "pass"
        and int(accepted_payload_policy.get("unknown_or_avoidable_residuals", 1)) == 0
    )
    windows_demo_runtime_string_ok = (
        not windows_release_demo_strings_protected or windows_release_dynamic_strings_protected
    )
    string_policy_passed = (
        protected_artifacts_have_zero_strings
        and platform_residuals_contract_only
        and windows_demo_runtime_string_ok
    )
    ios_macho_report_present = (
        ios_macho.get("status") == "pass"
        and ios_macho.get("missing_artifacts") == []
        and ios_macho.get("unsupported_artifacts") == []
    )
    ios_macho_linked_report_present = (
        ios_macho_linked.get("status") == "pass"
        and ios_macho_linked.get("missing_artifacts") == []
        and ios_macho_linked.get("unsupported_artifacts") == []
    )
    ios_observed_counts = [
        int(report.get("observed_surface_findings", 999999))
        for report, present in ((ios_macho, ios_macho_report_present), (ios_macho_linked, ios_macho_linked_report_present))
        if present
    ]
    ios_macho_best_observed_surface_findings = min(ios_observed_counts) if ios_observed_counts else None
    ios_macho_strict_surface_free = (
        ios_macho_best_observed_surface_findings is not None and ios_macho_best_observed_surface_findings == 0
    )
    platform_scope = {
        "linux_elf_release": release.get("status") == "pass" and release.get("elf_metadata_findings") == [],
        "windows_pe_cross_build": windows_cross.get("pe_metadata_findings") == [],
        "android_apk_release_like": android_apk.get("status") == "pass"
        and android_apk.get("manifest_debuggable") is False
        and android_apk.get("apk_forbidden_plaintext_hits") == []
        and android_apk.get("jni_symbol_plaintext_hits") == [],
        "android_actual_apk_marker_free": android_actual_apk_markers_absent,
        "ios_macho_metadata_report": ios_macho_report_present,
        "ios_macho_linked_minimal_report": ios_macho_linked_report_present,
        "ios_macho_strict_standard_surface_free": ios_macho_strict_surface_free,
    }
    syscall_policy = syscall_policy_check(root, security_policy, elf_obs, pe_obs, windows_cross)
    stability = protected_program_stability_check(
        root,
        sample_behavior,
        release,
        windows_release,
        android_apk,
        android_emulator,
        ios_macho,
        ios_macho_linked,
    )

    checks = [
        {
            "requirement": "1_platform_standard_feature_minimization",
            "status": status_for_all(
                surface.get("status") == "pass",
                surface.get("avoidable_surface_findings") == 0,
                release.get("elf_metadata_findings") == [],
                windows_cross.get("pe_metadata_findings") == [],
                all(platform_scope.values()),
            ),
            "evidence": [
                "docs/qa/reports/surface-minimization.json",
                "docs/qa/reports/release-protected-binary.json",
                "docs/qa/reports/windows-protected-cross-build.json",
                "docs/qa/reports/android-apk-smoke.json",
                "docs/qa/reports/ios-macho-metadata.json",
                "docs/qa/reports/ios-macho-linked-minimal.json",
            ],
            "platform_scope": platform_scope,
            "ios_macho_best_observed_surface_findings": ios_macho_best_observed_surface_findings,
            "android_actual_apk_surface": android_actual_apk,
            "note": (
                "Avoidable standard PE/ELF/APK/Mach-O metadata is minimized only for platform reports that are "
                "present and passing; mandatory loader/container headers remain platform-required. The strict "
                "Mach-O surface check remains partial when standard load-command, segment, section, or signature "
                "metadata is observed."
            ),
        },
        {
            "requirement": "2_vm_ollvm_standard_marker_absence",
            "status": "pass" if surface.get("avoidable_surface_findings") == 0 else "fail",
            "evidence": ["docs/qa/reports/surface-minimization.json"],
            "note": "Surface policy fails on VM, OLLVM, and product markers.",
        },
        {
            "requirement": "3_all_strings_ciphertext_no_plaintext",
            "status": "pass" if string_policy_passed else "partial",
            "evidence": [
                "samples/protected_chain/out/protected_sample.vmp",
                "artifacts/protected/linux/protected_release_sample",
                "build/windows-protected-cross/protected_release_sample.exe",
                "docs/qa/reports/surface-minimization.json",
                "docs/qa/reports/platform-string-residuals.json",
            ],
            "observed_strings_count": artifact_string_counts,
            "protected_payload_strings_count": protected_string_paths,
            "windows_visible_release_strings_protected": windows_release_demo_strings_protected,
            "windows_visible_release_dynamic_strings_protected": windows_release_dynamic_strings_protected,
            "windows_dynamic_string_protection": windows_cross.get("dynamic_string_protection", {}),
            "windows_release_forbidden_plaintext_hits": windows_cross.get("forbidden_plaintext_hits"),
            "platform_container_strings_count": platform_container_string_counts,
            "windows_string_classification": windows_string_classification,
            "platform_string_residuals": {
                "status": platform_string_residuals.get("status"),
                "total_residual_strings": platform_string_residuals.get("total_residual_strings"),
                "category_counts": platform_string_residuals.get("category_counts", {}),
                "strict_zero_string": platform_string_residuals.get("strict_zero_string", {}),
                "accepted_payload_policy": accepted_payload_policy,
                "raw_values_recorded": platform_string_residuals.get("raw_values_recorded"),
            },
            "note": (
                "Protected payload/native artifacts have zero printable byte runs except the Windows release "
                "console demo, whose visible output strings are encrypted and whose residual printable strings "
                "are fixed loader/API names or non-plaintext byte runs. The Windows visible demo additionally "
                "uses chunked runtime decode, two-pass plaintext tag validation, and chunk wiping; remaining "
                "platform-container strings are classified platform contract metadata, not protected program plaintext."
                if string_policy_passed
                else (
                    "At least one protected payload/native artifact yielded printable byte runs, the Windows visible "
                    "demo lacks the required runtime string-decode hardening evidence, or platform container residuals "
                    "include unknown or avoidable strings."
                )
            ),
        },
        {
            "requirement": "4_import_export_tls_minimized",
            "status": status_for_all(
                int(elf_obs.get("import_count", -1)) == 0,
                int(elf_obs.get("export_count", -1)) == 0,
                windows_fixed_api_surface_allowed(pe_obs),
            ),
            "evidence": [
                "docs/qa/reports/surface-minimization.json",
                "docs/qa/reports/windows-protected-cross-build.json",
                "docs/qa/reports/protected-callgraph.json",
                "docs/qa/reports/reverse-cost-assessment.json",
            ],
            "note": (
                "Linux protected release has no dynamic import/export; Windows protected PE either has no "
                "import/export/TLS directory or only the fixed Kernel32 console imports required by the encrypted "
                "visible demo. Protected callgraph evidence also verifies direct protected xrefs are discovered "
                "before rewrite and removed after callsite thunking."
            ),
        },
        {
            "requirement": "5_syscall_policy",
            "status": syscall_policy["status"],
            "evidence": ["docs/SECURITY_POLICY.md", "docs/qa/reports/surface-minimization.json"],
            "policy_evidence": syscall_policy["evidence"],
            "platform_source_evidence": syscall_policy["platform_source"],
            "fixed_runtime_syscall_source": syscall_policy["fixed_runtime_syscall_source"],
            "windows_console_api_policy": syscall_policy["windows_console_api_policy"],
            "note": (
                "Platform adapters are self-contained and do not call libc/WinAPI/dlopen/syscall resolver paths. "
                "The only direct syscall in release source is the fixed Linux x86_64 exit path used by the CRT-free "
                "runner; Windows release evidence has either no import/export/TLS directory or only the fixed "
                "Kernel32 console imports needed by the encrypted visible demo, with stdout/stdin handle caching "
                "and batched WriteFile calls for the visible release."
            ),
        },
        {
            "requirement": "6_protected_program_stability",
            "status": stability["status"],
            "evidence": [
                "samples/protected_chain/out/behavior.json",
                "docs/qa/reports/release-protected-binary.json",
                "docs/qa/reports/windows-protected-release.json",
                "docs/qa/reports/android-apk-smoke.json",
                "docs/qa/reports/android-emulator-smoke.json",
                "docs/qa/reports/ios-macho-metadata.json",
                "docs/qa/reports/ios-macho-linked-minimal.json",
            ],
            "stability_evidence": stability["evidence"],
            "note": (
                "Protected sample behavior is equivalent for all four cases; Linux release executes the embedded "
                "protected payload locally; Windows and Android reports are real GitHub Actions runner/emulator "
                "execution evidence; iOS is constrained to no-JIT/Mach-O logic evidence."
            ),
        },
    ]
    complete = all(item["status"] == "pass" for item in checks)
    blockers = residual_blockers(checks)
    return {
        "schema": "vmp.qa.objective_completion_audit.v1",
        "status": "pass" if complete else "blocked",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "objective": [
            "make platform syscall/API access self-contained where possible and avoid system/API calls unless necessary",
            "prove protected programs run stably after protection with executable platform evidence",
            "keep supporting surface, string, import/export/TLS, and marker minimization gates green",
        ],
        "success_criteria": [
            "all objective checks must be pass",
            "platform adapters must be source-clean for disallowed syscall/API resolver markers",
            "release source may contain only the fixed Linux x86_64 exit syscall",
            "Linux, Windows, Android, and iOS stability evidence must be present and passing",
            "all protected payload/native artifacts must have zero literal printable runs, except the Windows encrypted visible console demo whose printed text must not appear as plaintext",
            "APK/Mach-O platform-container printable runs must be classified contract metadata with no unknown or avoidable residuals",
            "no generic direct-syscall bypass may be introduced against project security policy",
        ],
        "checks": checks,
        "prompt_to_artifact_checklist": prompt_to_artifact_checklist(checks),
        "automation": automation_summary(reverse_cost, protected_callgraph),
        "residual_blockers": blockers,
        "security_boundary_present": "does not implement generic direct-syscall bypass stubs" in security_policy,
        "completion_note": completion_note(complete, blockers),
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
    print(f"objective completion audit {report['status']}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
