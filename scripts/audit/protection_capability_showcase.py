#!/usr/bin/env python3
"""Build a concrete protection-capability showcase from current artifacts.

This report is intentionally evidence-oriented. It describes what this checkout
can demonstrate from generated IR, release artifacts, platform demos, and QA
reports. It does not turn local evidence into final commercial sign-off.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JSON = "docs/qa/reports/protection-capability-showcase.json"
DEFAULT_MARKDOWN = "docs/qa/ProtectionCapabilityShowcase.md"

FORBIDDEN_PLAINTEXT = (
    "visible windows protected demo",
    "parse_status=failed",
    "demo_function=authorized_sample_behavior",
    "case %u",
    "windows_getchar_pause=3",
    "CRITICAL_AUTHZ_TOKEN_SAMPLE",
    "https://license.sample.invalid",
    "Authorization:",
    "Bearer ",
    "JNI_OnLoad",
    "Java_",
    "dlopen",
    "dlsym",
    "VMPBC",
    "VMPSAM",
    "VMPIRL",
    "OLLVM",
    "Mingw-w64 runtime failure",
    "GCC: (GNU)",
    "msvcrt.dll",
    "printf",
    "fprintf",
    "vfprintf",
    "getchar",
)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_length:
            strings.append(current.decode("ascii", errors="ignore"))
        current.clear()
    if len(current) >= min_length:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings


def scan_artifact(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    if not path.exists():
        return {
            "path": relative,
            "exists": False,
            "bytes": 0,
            "sha256": None,
            "printable_string_count": None,
            "forbidden_plaintext_hits": [],
            "residual_printable_strings": [],
        }
    data = path.read_bytes()
    strings = printable_strings(data)
    hits = [needle for needle in FORBIDDEN_PLAINTEXT if any(needle in item for item in strings)]
    return {
        "path": relative,
        "exists": True,
        "bytes": len(data),
        "sha256": sha256_file(path),
        "printable_string_count": len(strings),
        "forbidden_plaintext_hits": hits,
        "residual_printable_strings": strings[:80],
    }


def parse_plugin_report(log_text: str) -> dict[str, int] | None:
    match = re.search(
        r"VMPPassPlugin report: selected_functions=(?P<selected>\d+) "
        r"lowered_functions=(?P<lowered>\d+) replaced_functions=(?P<replaced>\d+) "
        r"unsupported_functions=(?P<unsupported>\d+) stages=(?P<stages>\d+)",
        log_text,
    )
    if not match:
        return None
    return {key: int(value) for key, value in match.groupdict().items()}


def stage_manifest_summary(root: Path) -> dict[str, Any]:
    path = root / "tests/core/.llvm-out/vmp-stage-manifest.json"
    manifest = read_json(path)
    stages = manifest.get("stages", [])
    if not isinstance(stages, list):
        stages = []
    implemented = [
        str(stage.get("name"))
        for stage in stages
        if isinstance(stage, dict) and stage.get("implemented") is True
    ]
    placeholders = [
        str(stage.get("name"))
        for stage in stages
        if isinstance(stage, dict) and stage.get("kind") == "placeholder_noop"
    ]
    effects = sorted(
        {
            str(effect)
            for stage in stages
            if isinstance(stage, dict)
            for effect in stage.get("capability_effects", [])
            if isinstance(effect, str)
        }
    )
    return {
        "path": "tests/core/.llvm-out/vmp-stage-manifest.json",
        "exists": bool(manifest),
        "schema": manifest.get("schema"),
        "pipeline": manifest.get("pipeline", {}),
        "implemented_stages": implemented,
        "placeholder_noop_stages": placeholders,
        "capability_effects": effects,
        "sha256": sha256_file(path),
        "generic_const_string_encryption_implemented": "vmp-const-string-encryption" in implemented,
    }


def ir_summary(root: Path) -> dict[str, Any]:
    sample_ir = read_text(root / "tests/core/.llvm-out/sample.protected.ll")
    hotspot_ir = read_text(root / "tests/core/.llvm-out/hotspot-callsite.protected.ll")
    return {
        "sample_ir": "tests/core/.llvm-out/sample.protected.ll",
        "hotspot_ir": "tests/core/.llvm-out/hotspot-callsite.protected.ll",
        "bytecode_global_definitions": len(re.findall(r"^@vmp\.bytecode\.", sample_ir, flags=re.MULTILINE)),
        "replaced_metadata_markers": sample_ir.count("!vmp.replaced"),
        "decompiler_trap_label_present": "vmp.decompiler.trap:" in hotspot_ir,
        "opaque_switch_trap_present": "switch i32 0" in hotspot_ir,
        "anti_analysis_policy_metadata_present": "!vmp.anti_analysis.policy" in hotspot_ir,
        "direct_secret_hot_call_present": "call i32 @secret_hot" in hotspot_ir,
    }


def capability(
    name: str,
    status: str,
    evidence: dict[str, Any],
    limitations: list[str],
    evidence_paths: list[str],
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "evidence": evidence,
        "limitations": limitations,
        "evidence_paths": evidence_paths,
    }


def surface_artifact(surface: dict[str, Any], suffix: str) -> dict[str, Any]:
    for item in surface.get("scanned_artifacts", []):
        if isinstance(item, dict) and str(item.get("artifact", "")).endswith(suffix):
            return item
    return {}


def build_report(root: Path) -> dict[str, Any]:
    reports = root / "docs/qa/reports"
    plugin_log_text = read_text(root / "tests/core/.llvm-out/plugin.log")
    plugin_report = parse_plugin_report(plugin_log_text)
    manifest = stage_manifest_summary(root)
    ir = ir_summary(root)
    callgraph = read_json(reports / "protected-callgraph.json")
    reverse_cost = read_json(reports / "reverse-cost-assessment.json")
    release = read_json(reports / "release-protected-binary.json")
    surface = read_json(reports / "surface-minimization.json")
    capability_matrix = read_json(reports / "capability-matrix.json")
    visible_demo = read_json(reports / "windows-visible-demo-cross-build.json")
    windows_cross = read_json(reports / "windows-protected-cross-build.json")
    ida_review = read_json(reports / "ida-ollydbg-review.json")
    vmprotect_review = read_json(reports / "vmprotect-tier-review.json")
    hostile = read_json(reports / "hostile-environment.json")

    strict_artifacts = [
        scan_artifact(root, "artifacts/protected/linux/protected_release_sample"),
        scan_artifact(root, "samples/protected_chain/out/protected_sample.vmp"),
        scan_artifact(root, "build/windows-protected-cross/protected_release_sample.exe"),
    ]
    visible_scan = scan_artifact(root, "build/windows-visible-demo/protected_visible_demo.exe")
    windows_release_demo_strings_protected = (
        windows_cross.get("release_mode") == "visible_encrypted_console_demo"
        and windows_cross.get("visible_demo_strings_encrypted") is True
        and windows_cross.get("windows_getchar_calls") == 3
        and windows_cross.get("forbidden_plaintext_hits") == []
    )
    visible_dynamic_strings = (
        visible_demo.get("dynamic_string_protection", {})
        if isinstance(visible_demo.get("dynamic_string_protection"), dict)
        else {}
    )
    windows_dynamic_strings = (
        windows_cross.get("dynamic_string_protection", {})
        if isinstance(windows_cross.get("dynamic_string_protection"), dict)
        else {}
    )
    windows_api_policy = (
        windows_cross.get("windows_console_api_policy", {})
        if isinstance(windows_cross.get("windows_console_api_policy"), dict)
        else {}
    )
    strict_strings_zero = all(
        item.get("printable_string_count") == 0
        for item in strict_artifacts
        if item.get("exists") and item.get("path") != "build/windows-protected-cross/protected_release_sample.exe"
    )
    windows_release_string_surface_ok = strict_artifacts[2].get("printable_string_count") == 0 or windows_release_demo_strings_protected
    strict_forbidden_absent = all(not item.get("forbidden_plaintext_hits") for item in strict_artifacts if item.get("exists"))
    visible_forbidden_absent = not visible_scan.get("forbidden_plaintext_hits")

    callgraph_analysis = callgraph.get("analysis", {}) if isinstance(callgraph.get("analysis"), dict) else {}
    callsite_obfuscation = (
        callgraph.get("callsite_obfuscation", {}) if isinstance(callgraph.get("callsite_obfuscation"), dict) else {}
    )
    linux_surface = surface_artifact(surface, "protected_release_sample")
    windows_surface = surface_artifact(surface, "protected_release_sample.exe")
    elf_observations = linux_surface.get("elf_observations", {}) if isinstance(linux_surface, dict) else {}
    pe_observations = windows_surface.get("pe_observations", {}) if isinstance(windows_surface, dict) else {}

    pipeline = manifest.get("pipeline", {})
    placeholder_stages = list(manifest.get("placeholder_noop_stages", []))
    generic_const_strings = bool(manifest.get("generic_const_string_encryption_implemented"))
    plugin_lowered = bool(plugin_report and plugin_report["lowered"] > 0 and plugin_report["replaced"] > 0)

    capabilities = [
        capability(
            "vm_bytecode_lowering_and_function_replacement",
            "partial" if plugin_lowered else "missing",
            {
                "plugin_report": plugin_report,
                "stage_pipeline": pipeline,
                "bytecode_global_definitions": ir["bytecode_global_definitions"],
                "replaced_metadata_markers": ir["replaced_metadata_markers"],
                "implemented_stages": manifest["implemented_stages"],
            },
            [
                f"placeholder_noop_stages={placeholder_stages}",
                "Unsupported IR shapes are intentionally left native instead of pretending they were virtualized.",
            ],
            [
                "tests/core/.llvm-out/plugin.log",
                "tests/core/.llvm-out/sample.protected.ll",
                "tests/core/.llvm-out/vmp-stage-manifest.json",
                "src/core/llvm/VMPPassPlugin.cpp",
            ],
        ),
        capability(
            "protected_xref_and_callgraph_distortion",
            "demonstrated" if callgraph.get("status") == "pass" else "missing",
            {
                "analysis": callgraph_analysis,
                "rewritten_calls": callsite_obfuscation.get("rewritten_calls"),
                "unique_thunks": callsite_obfuscation.get("unique_thunks"),
                "protected_thunk_call_edges": callsite_obfuscation.get("protected_thunk_call_edges"),
                "direct_secret_hot_call_present_after_protection": ir["direct_secret_hot_call_present"],
            },
            [
                "The automated proof is IR-level and report-level; binary-level manual review remains a separate evidence source.",
            ],
            [
                "docs/qa/reports/protected-callgraph.json",
                "tests/core/.llvm-out/hotspot-callsite.protected.ll",
            ],
        ),
        capability(
            "anti_decompiler_trap_and_f5_distortion",
            "partial",
            {
                "ir_decompiler_trap_label_present": ir["decompiler_trap_label_present"],
                "ir_opaque_switch_trap_present": ir["opaque_switch_trap_present"],
                "anti_analysis_policy_metadata_present": ir["anti_analysis_policy_metadata_present"],
                "ida_ollydbg_review_status": ida_review.get("status", "missing"),
                "reviewed_indicators": ida_review.get("reviewed_indicators", {}),
                "ida_plugin_recovery_residual_risk": True,
            },
            [
                "Current traps raise reverse cost but are not enough to claim resilience against stronger IDA plugin automation.",
            ],
            [
                "tests/core/.llvm-out/hotspot-callsite.protected.ll",
                "docs/qa/reports/ida-ollydbg-review.json",
            ],
        ),
        capability(
            "string_plaintext_hiding",
            "partial" if strict_strings_zero and windows_release_string_surface_ok and strict_forbidden_absent and visible_forbidden_absent else "missing",
            {
                "strict_artifacts_zero_printable_strings": strict_strings_zero,
                "windows_release_visible_demo_strings_protected": windows_release_demo_strings_protected,
                "strict_artifacts_forbidden_plaintext_absent": strict_forbidden_absent,
                "visible_demo_forbidden_plaintext_absent": visible_forbidden_absent,
                "visible_demo_string_encryption_reported": visible_demo.get("visible_demo_strings_encrypted"),
                "generic_llvm_const_string_encryption_implemented": generic_const_strings,
                "artifact_scans": strict_artifacts + [visible_scan],
            },
            [
                (
                    "Generic LLVM const-string encryption is implemented for private/internal constant byte arrays."
                    if generic_const_strings
                    else "Generic LLVM const-string encryption is still a placeholder stage."
                ),
                "The Windows visible demo uses generated per-build encrypted text; strict release artifacts use zero-printable-string policy.",
            ],
            [
                "samples/protected_chain/out/strings.json",
                "build/windows-visible-demo/protected_visible_demo.strings.txt",
                "docs/qa/reports/windows-visible-demo-cross-build.json",
                "tests/core/.llvm-out/vmp-stage-manifest.json",
            ],
        ),
        capability(
            "dynamic_string_runtime_decryption",
            "demonstrated"
            if windows_release_demo_strings_protected
            and visible_dynamic_strings.get("chunked_runtime_decode") is True
            and visible_dynamic_strings.get("full_plaintext_string_buffer") is False
            and visible_dynamic_strings.get("two_pass_plaintext_tag_validation") is True
            and windows_dynamic_strings.get("chunked_runtime_decode") is True
            else "missing",
            {
                "visible_demo_dynamic_string_protection": visible_dynamic_strings,
                "windows_release_dynamic_string_protection": windows_dynamic_strings,
                "visible_demo_forbidden_plaintext_absent": visible_forbidden_absent,
                "windows_release_demo_strings_protected": windows_release_demo_strings_protected,
            },
            [
                (
                    "This protects generated visible-demo text at runtime; the LLVM const-string pass now covers private/internal constant byte arrays."
                    if generic_const_strings
                    else "This protects generated visible-demo text at runtime; the generic LLVM const-string pass is still a separate placeholder."
                ),
            ],
            [
                "tools/vmp/protected_release_main.cpp",
                "tests/platform/windows_visible_demo_cross_build.sh",
                "docs/qa/reports/windows-visible-demo-cross-build.json",
                "docs/qa/reports/windows-protected-cross-build.json",
            ],
        ),
        capability(
            "strict_import_export_tls_surface_minimization",
            "demonstrated" if surface.get("status") == "pass" and surface.get("avoidable_surface_findings") == 0 else "missing",
            {
                "surface_status": surface.get("status"),
                "avoidable_surface_findings": surface.get("avoidable_surface_findings"),
                "linux_elf_observations": elf_observations,
                "windows_pe_observations": pe_observations,
            },
            [
                "The Windows release artifact is now the encrypted visible console demo, so fixed Kernel32 console imports are expected.",
            ],
            [
                "docs/qa/reports/surface-minimization.json",
                "docs/qa/reports/windows-protected-cross-build.json",
                "tools/vmp/protected_release_main.cpp",
            ],
        ),
        capability(
            "windows_api_call_minimization_policy",
            "demonstrated"
            if windows_api_policy.get("mode") == "minimal_fixed_kernel32_console_api"
            and windows_api_policy.get("direct_windows_syscalls_enabled") is False
            and windows_api_policy.get("generic_syscall_resolver_allowed") is False
            and windows_api_policy.get("stdout_handle_cached") is True
            and windows_api_policy.get("stdin_handle_cached") is True
            and windows_api_policy.get("writefile_calls_batched") is True
            else "partial",
            {
                "windows_console_api_policy": windows_api_policy,
                "windows_pe_observations": pe_observations,
                "surface_syscall_policy": surface.get("syscall_policy", {}),
            },
            [
                "The accepted Windows visible release minimizes and batches fixed console API use; it does not enable direct Windows syscall stubs or syscall-number harvesting.",
            ],
            [
                "docs/SECURITY_POLICY.md",
                "docs/qa/reports/surface-minimization.json",
                "docs/qa/reports/windows-protected-cross-build.json",
            ],
        ),
        capability(
            "pe_section_name_randomization",
            "demonstrated"
            if windows_cross.get("section_names_randomized") is True
            and visible_demo.get("section_names_randomized") is True
            else "missing",
            {
                "windows_release_section_names_randomized": windows_cross.get("section_names_randomized"),
                "windows_release_section_name_seed_fingerprint": windows_cross.get("section_name_seed_fingerprint"),
                "windows_release_section_name_hex": windows_cross.get("section_name_hex", []),
                "windows_release_decoy_sections": windows_cross.get("decoy_sections", {}),
                "visible_demo_section_names_randomized": visible_demo.get("section_names_randomized"),
                "visible_demo_section_name_seed_fingerprint": visible_demo.get("section_name_seed_fingerprint"),
                "visible_demo_section_name_hex": visible_demo.get("section_name_hex", []),
                "visible_demo_decoy_sections": visible_demo.get("decoy_sections", {}),
                "pe_metadata_observations": windows_cross.get("pe_metadata_observations", {}),
            },
            [
                "This prevents fixed section-name scripts from keying on stable names, but it does not randomize the whole PE layout.",
            ],
            [
                "scripts/audit/scrub_pe_section_names.py",
                "docs/qa/reports/windows-protected-cross-build.json",
                "docs/qa/reports/windows-visible-demo-cross-build.json",
            ],
        ),
        capability(
            "windows_visible_protected_demo",
            "demonstrated" if visible_demo.get("status") == "pass" and visible_forbidden_absent else "missing",
            {
                "report_status": visible_demo.get("status"),
                "artifact_bytes": visible_demo.get("artifact_bytes"),
                "embedded_sample_bytes": visible_demo.get("embedded_sample_bytes"),
                "windows_getchar_calls": visible_demo.get("windows_getchar_calls"),
                "wine_execution_status": visible_demo.get("wine_execution_status"),
                "printable_string_count": visible_scan.get("printable_string_count"),
                "forbidden_plaintext_hits": visible_scan.get("forbidden_plaintext_hits"),
                "residual_printable_strings": visible_scan.get("residual_printable_strings"),
            },
            [
                "Wine execution is optional in this Linux environment; if unavailable, the evidence is cross-build plus static PE scan.",
            ],
            [
                "tests/platform/windows_visible_demo_cross_build.sh",
                "build/windows-visible-demo/protected_visible_demo.exe",
                "docs/qa/reports/windows-visible-demo-cross-build.json",
            ],
        ),
        capability(
            "runtime_stability",
            "demonstrated" if release.get("status") == "pass" and release.get("behavior_cases_passed") == 4 else "missing",
            {
                "release_status": release.get("status"),
                "behavior_cases_passed": release.get("behavior_cases_passed"),
                "forbidden_plaintext_hits": release.get("forbidden_plaintext_hits"),
                "artifact_bytes": release.get("artifact_bytes"),
            },
            [
                "The local release runner validates the protected sample behavior, not arbitrary application workloads.",
            ],
            [
                "docs/qa/reports/release-protected-binary.json",
                "tests/integration/run_release_protected_binary.sh",
            ],
        ),
        capability(
            "reverse_cost_automation",
            "demonstrated" if reverse_cost.get("status") == "pass" else "missing",
            {
                "status": reverse_cost.get("status"),
                "minimum_reverse_cost_days": reverse_cost.get("minimum_reverse_cost_days"),
                "score_breakdown": reverse_cost.get("score_breakdown", {}),
                "assessed_capabilities": reverse_cost.get("assessed_capabilities", {}),
            },
            [
                "Automated reverse-cost scoring is repeatable evidence, not a substitute for a human red-team guarantee.",
            ],
            [
                "docs/qa/reports/reverse-cost-assessment.json",
                "scripts/audit/generate_reverse_cost_assessment.py",
            ],
        ),
        capability(
            "anti_debug_injection_tamper_review_scope",
            "reviewed" if vmprotect_review.get("status") == "pass" else "partial",
            {
                "hostile_environment_status": hostile.get("status", "missing"),
                "hostile_trigger_scope": hostile.get("real_platform_trigger_scope", "missing"),
                "vmprotect_tier_review_status": vmprotect_review.get("status", "missing"),
                "vmprotect_tier_capabilities": vmprotect_review.get("capabilities", {}),
            },
            [
                "Hostile trigger and VMProtect-tier review files are provenance-sensitive; local-only reproduction must not be called final sign-off.",
            ],
            [
                "docs/qa/reports/hostile-environment.json",
                "docs/qa/reports/vmprotect-tier-review.json",
            ],
        ),
    ]

    blockers = [
        f"placeholder_noop_stages={placeholder_stages}",
        "accepted Windows release does not enable syscall-only I/O; direct Windows syscall stubs remain outside the release gate by policy",
        "full broad LLVM IR virtualization is not proven; unsupported functions remain native by policy",
        "IDA plugin recovery remains a real residual risk until flattening, production crypto, and broader binary-level anti-decompiler validation are implemented.",
    ]
    if capability_matrix.get("final_signoff_allowed") is not True:
        blockers.insert(0, "final_signoff_allowed=false in capability matrix")
    if not generic_const_strings:
        blockers.insert(2, "generic LLVM const-string encryption is not implemented as a general pass")
    if capability_matrix.get("status") and capability_matrix.get("status") != "pass":
        blockers.append(f"capability_matrix_status={capability_matrix.get('status')}")

    return {
        "schema": "vmp.qa.protection_capability_showcase.v1",
        "status": "evidence_available",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "root": str(root),
        "summary": {
            "current_project_capability": (
                "The project demonstrates local VM bytecode lowering/replacement, protected-callsite thunking, "
                "xref removal, decompiler-trap markers, strict release string/import minimization, a hardened "
                "Windows visible demo, and automated reverse-cost evidence."
            ),
            "not_claimed": (
                "This report does not claim complete VMProtect-tier commercial coverage for arbitrary programs."
            ),
            "final_signoff_allowed": capability_matrix.get("final_signoff_allowed", False),
        },
        "capabilities": capabilities,
        "stage_manifest": manifest,
        "blockers_and_limits": blockers,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Protection Capability Showcase",
        "",
        f"Generated: `{report['generated_at_utc']}`",
        "",
        report["summary"]["current_project_capability"],
        "",
        f"Not claimed: {report['summary']['not_claimed']}",
        "",
        "| Capability | Status | Key Evidence | Main Limit |",
        "| --- | --- | --- | --- |",
    ]
    for item in report["capabilities"]:
        key_parts = markdown_evidence_summary(item)
        limit = item["limitations"][0] if item["limitations"] else ""
        lines.append(
            f"| `{item['name']}` | `{item['status']}` | {'; '.join(key_parts)} | {limit} |"
        )
    lines.extend(["", "## Blockers And Limits", ""])
    for blocker in report["blockers_and_limits"]:
        lines.append(f"- {blocker}")
    lines.append("")
    return "\n".join(lines)


def markdown_evidence_summary(item: dict[str, Any]) -> list[str]:
    evidence = item["evidence"]
    name = item["name"]
    if name == "vm_bytecode_lowering_and_function_replacement":
        plugin = evidence.get("plugin_report") or {}
        stage = evidence.get("stage_pipeline") or {}
        return [
            f"selected={plugin.get('selected')}",
            f"lowered={plugin.get('lowered')}",
            f"replaced={plugin.get('replaced')}",
            f"unsupported={plugin.get('unsupported')}",
            f"implemented_stages={stage.get('implemented_count')}",
        ]
    if name == "protected_xref_and_callgraph_distortion":
        return [
            f"direct_xrefs_removed={evidence.get('analysis', {}).get('direct_protected_xrefs_removed')}",
            f"rewritten_calls={evidence.get('rewritten_calls')}",
            f"unique_thunks={evidence.get('unique_thunks')}",
            f"direct_call_after={evidence.get('direct_secret_hot_call_present_after_protection')}",
        ]
    if name == "anti_decompiler_trap_and_f5_distortion":
        return [
            f"trap_label={evidence.get('ir_decompiler_trap_label_present')}",
            f"opaque_switch={evidence.get('ir_opaque_switch_trap_present')}",
            f"ida_review={evidence.get('ida_ollydbg_review_status')}",
            f"plugin_recovery_risk={evidence.get('ida_plugin_recovery_residual_risk')}",
        ]
    if name == "string_plaintext_hiding":
        return [
            f"strict_zero_strings={evidence.get('strict_artifacts_zero_printable_strings')}",
            f"windows_release_demo_encrypted={evidence.get('windows_release_visible_demo_strings_protected')}",
            f"visible_forbidden_absent={evidence.get('visible_demo_forbidden_plaintext_absent')}",
            f"generic_const_string_pass={evidence.get('generic_llvm_const_string_encryption_implemented')}",
        ]
    if name == "dynamic_string_runtime_decryption":
        visible = evidence.get("visible_demo_dynamic_string_protection") or {}
        release = evidence.get("windows_release_dynamic_string_protection") or {}
        return [
            f"chunked={visible.get('chunked_runtime_decode')}",
            f"full_plaintext_buffer={visible.get('full_plaintext_string_buffer')}",
            f"two_pass_tag={visible.get('two_pass_plaintext_tag_validation')}",
            f"release_chunked={release.get('chunked_runtime_decode')}",
        ]
    if name == "strict_import_export_tls_surface_minimization":
        pe = evidence.get("windows_pe_observations") or {}
        elf = evidence.get("linux_elf_observations") or {}
        return [
            f"surface={evidence.get('surface_status')}",
            f"linux_imports={elf.get('import_count')}",
            f"windows_imports={pe.get('import_count')}",
            f"windows_tls={pe.get('tls_directory_present')}",
        ]
    if name == "windows_api_call_minimization_policy":
        policy = evidence.get("windows_console_api_policy") or {}
        pe = evidence.get("windows_pe_observations") or {}
        return [
            f"mode={policy.get('mode')}",
            f"direct_syscalls={policy.get('direct_windows_syscalls_enabled')}",
            f"batched_write={policy.get('writefile_calls_batched')}",
            f"imports={pe.get('import_count')}",
        ]
    if name == "pe_section_name_randomization":
        metadata = evidence.get("pe_metadata_observations") or {}
        return [
            f"release_randomized={evidence.get('windows_release_section_names_randomized')}",
            f"decoys={(evidence.get('windows_release_decoy_sections') or {}).get('decoy_section_count')}",
            f"distinct={metadata.get('section_name_distinct_count')}",
            f"high_bit={metadata.get('nonprintable_high_bit_section_names')}",
            f"zero_padded={metadata.get('zero_padded_section_names')}",
        ]
    if name == "windows_visible_protected_demo":
        return [
            f"getchar_calls={evidence.get('windows_getchar_calls')}",
            f"printable_strings={evidence.get('printable_string_count')}",
            f"forbidden_hits={len(evidence.get('forbidden_plaintext_hits') or [])}",
            f"wine={evidence.get('wine_execution_status')}",
        ]
    if name == "runtime_stability":
        return [
            f"release={evidence.get('release_status')}",
            f"behavior_cases={evidence.get('behavior_cases_passed')}",
            f"forbidden_hits={len(evidence.get('forbidden_plaintext_hits') or [])}",
        ]
    if name == "reverse_cost_automation":
        return [
            f"status={evidence.get('status')}",
            f"reverse_cost_days={evidence.get('minimum_reverse_cost_days')}",
        ]
    if name == "anti_debug_injection_tamper_review_scope":
        return [
            f"hostile={evidence.get('hostile_environment_status')}",
            f"scope={evidence.get('hostile_trigger_scope')}",
            f"tier_review={evidence.get('vmprotect_tier_review_status')}",
        ]
    return [str(evidence)[:160]]


def write_report(root: Path, json_path: Path, markdown_path: Path) -> dict[str, Any]:
    report = build_report(root)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default=DEFAULT_JSON)
    parser.add_argument("--markdown", default=DEFAULT_MARKDOWN)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    json_path = root / args.output
    markdown_path = root / args.markdown
    report = write_report(root, json_path, markdown_path)
    print(
        "protection capability showcase "
        f"{report['status']}: capabilities={len(report['capabilities'])} "
        f"final_signoff_allowed={report['summary']['final_signoff_allowed']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
