#!/usr/bin/env python3
"""Generate a machine-readable VMProtect-tier capability matrix.

The report is evidence, not a waiver: missing production lowering, production
cryptography, Windows CI execution, and hostile-platform triggers keep final
sign-off blocked.
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "qa" / "reports" / "capability-matrix.json"


def exists(path: str) -> bool:
    return (ROOT / path).exists()


def contains(path: str, needle: str) -> bool:
    target = ROOT / path
    return target.exists() and needle in target.read_text(encoding="utf-8", errors="ignore")


def json_status(path: str) -> str:
    target = ROOT / path
    if not target.exists():
        return "missing"
    try:
        return str(json.loads(target.read_text(encoding="utf-8")).get("status", "unknown"))
    except json.JSONDecodeError:
        return "invalid"


def json_report(path: str) -> dict[str, object] | None:
    target = ROOT / path
    if not target.exists():
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def hostile_platform_status() -> str:
    report = json_report("docs/qa/reports/hostile-environment.json")
    if not report:
        return "missing"
    scope = str(report.get("real_platform_trigger_scope", "none"))
    if scope == "none":
        return "blocked"
    return scope


def hostile_platform_gap() -> str:
    status = hostile_platform_status()
    if status == "partial_linux":
        return "Synthetic and partial Linux trigger evidence exists; Android emulator baseline probes may also exist, but Windows hardware/page breakpoints/DLL injection and Android root/Xposed/LSPosed/Frida/hook hostile-trigger coverage are missing."
    if status == "partial_linux_android":
        return "Synthetic, partial Linux, and Android root/debuggable baseline trigger evidence exists; Windows hardware/page breakpoints/DLL injection and Android Xposed/LSPosed/Frida/hook triggers are missing."
    if status == "partial_linux_windows_controlled":
        return "Synthetic, partial Linux, and controlled Windows trigger evidence exists; external Windows debugger/hardware breakpoint/DLL injection and Android root/Xposed/LSPosed/Frida/hook triggers are missing."
    if status == "partial_linux_windows_controlled_android":
        return "Synthetic, partial Linux, controlled Windows, and Android root/debuggable baseline trigger evidence exists; external Windows debugger/hardware breakpoint/DLL injection and Android Xposed/LSPosed/Frida/hook triggers are missing."
    return "Synthetic policy coverage exists, but required real Windows and Android hostile trigger evidence is missing."


def file_sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def llvm_stage_manifest() -> dict[str, object]:
    path = ROOT / "tests/core/.llvm-out/vmp-stage-manifest.json"
    report = json_report("tests/core/.llvm-out/vmp-stage-manifest.json")
    if not report or report.get("schema") != "vmp.llvm.stage_manifest.v1":
        return {
            "path": "tests/core/.llvm-out/vmp-stage-manifest.json",
            "status": "missing",
            "implemented_stages": [],
            "placeholder_noop_stages": [],
            "excluded_stage_evidence": [],
            "sha256": None,
        }
    stages = report.get("stages", [])
    if not isinstance(stages, list):
        stages = []
    implemented = [
        str(stage.get("name"))
        for stage in stages
        if isinstance(stage, dict) and stage.get("implemented") is True
    ]
    noops = [
        str(stage.get("name"))
        for stage in stages
        if isinstance(stage, dict) and stage.get("kind") == "placeholder_noop"
    ]
    return {
        "path": "tests/core/.llvm-out/vmp-stage-manifest.json",
        "status": "pass",
        "implemented_stages": implemented,
        "placeholder_noop_stages": noops,
        "excluded_stage_evidence": noops,
        "sha256": file_sha256(path),
    }


def main() -> int:
    stage_manifest = llvm_stage_manifest()
    implemented_stages = set(stage_manifest["implemented_stages"])
    capabilities = [
        {
            "name": "code_virtualization",
            "status": "partial" if {"vmp-ir-to-bytecode", "vmp-function-replacement"}.issubset(implemented_stages) else "missing",
            "evidence": [
                "src/runtime/VMRuntime.cpp",
                "src/runtime/VMRuntime.h",
                "src/core/Bytecode.cpp",
                "tests/core/fixtures/runtime_entry_smoke.cpp",
                "tests/core/.llvm-out/sample.protected.ll",
                "tests/core/.llvm-out/vmp-stage-manifest.json",
                "samples/protected_chain/out/protected_sample.vmp",
            ],
            "gap": "Local VM bytecode sample exists and the LLVM fixture now derives executable VM runtime stubs for narrow i32 zero-, one-, two-, three-, and four-argument functions with straight-line local alloca/load/store, repeated loads from a definite local store, branch-condition loads whose defining store is on the entry-to-branch prefix, single-slot branch/merge local stores with a definite store on every lowered path, add/sub/mul/and/or/xor/select expressions, zext/sext from supported icmp-i32 predicates to i32, narrow trunc-i32-to-i1/i8/i16 followed by zext/sext back to i32 or through a wider integer and safely truncated back to i32, constant shl/lshr/ashr shifts with shift amounts in 0..31, dynamic shifts whose amount is masked with and-i32-31, eq/ne/sgt/slt/sge/sle/ugt/ult/uge/ule acyclic branch trees and select conditions, simple PHI return merges, and direct internal ordinary_add host-call cases including multiple linear calls with preserved intermediate results, local-stack stores fed by select/call values, and simple branch-return host-call paths; nested VM branch targets are rebased when serialized, pre-existing bytecode globals must match a fresh lowering of the current body and be pass-marked immutable private globals before reuse, and replacement refreshes bytecode metadata to the actual generated global; unmasked dynamic shifts, constant shifts outside 0..31, poison-generating nuw/nsw/exact arithmetic or shift flags, unsupported integer casts outside the narrow trunc-extension and safe wide-round-trip pattern, reserved opaque-dispatch name collisions, pre-existing outline-name collisions, loops or irreducible control flow, uninitialized branch-local loads, loads outside the lowered store path or branch prefix, stale or mutable pre-seeded bytecode globals, local memory combined with PHI shapes, observable side-effecting IR, and global-store IR remain native, and unsupported selected functions are reported explicitly; broad LLVM IR lowering and production function replacement are not complete.",
        },
        {
            "name": "mutation_obfuscation",
            "status": "partial" if {"vmp-bogus-branch", "vmp-instruction-substitution"}.issubset(implemented_stages) and contains("tests/core/.llvm-out/sample.protected.ll", "vmp.fake.xref") else "missing",
            "evidence": ["tests/core/.llvm-out/sample.protected.ll", "tests/core/.llvm-out/vmp-stage-manifest.json", "src/core/llvm/VMPPassPlugin.cpp"],
            "gap": "LLVM pass now emits limited bogus dispatch and XOR substitution; full OLLVM flatten/split/substitution coverage is incomplete.",
        },
        {
            "name": "combined_protection",
            "status": "partial",
            "evidence": [
                "tests/core/run_llvm_plugin_test.sh",
                "tests/core/fixtures/runtime_entry_smoke.cpp",
                "samples/protected_chain/out/behavior.json",
                "samples/protected_chain/out/randomness.json",
                "docs/qa/reports/android-apk-smoke.json",
                "docs/qa/reports/performance-sample.json",
            ],
            "gap": "Local sample and LLVM fixture combine VM runtime stubs, randomized opcode maps, encrypted payloads, string scan, benchmark, and release-like Android APK/JNI smoke only; production release platform artifacts are not proven.",
        },
        {
            "name": "string_hiding",
            "status": "pass" if contains("samples/protected_chain/out/strings.json", "\"critical_strings_absent\": true") else "missing",
            "evidence": ["samples/protected_chain/out/strings.json", "scripts/audit/acceptance_audit.py"],
            "gap": "Sample artifact is clean, but full release API/JNI/import string hiding is not proven.",
        },
        {
            "name": "import_hiding",
            "status": "partial",
            "evidence": ["src/platform/platform_common.c", "tests/platform/windows_acceptance.ps1"],
            "gap": "Hash helpers and smoke scans exist; production import resolver and release PE proof are incomplete.",
        },
        {
            "name": "anti_debug_injection",
            "status": hostile_platform_status(),
            "evidence": ["docs/qa/reports/hostile-environment.json", "src/anti_analysis/environment.py"],
            "gap": hostile_platform_gap(),
        },
        {
            "name": "anti_tamper",
            "status": "partial",
            "evidence": ["src/core/Bytecode.cpp", "tests/core/core_tests.cpp"],
            "gap": "Bytecode auth tag rejects sample payload and opcode-map tampering; production cryptographic primitive and platform seal are incomplete.",
        },
        {
            "name": "android_emulator",
            "status": json_status("docs/qa/reports/android-apk-smoke.json"),
            "evidence": ["docs/qa/reports/android-apk-smoke.json", "tests/platform/android_apk_smoke.sh"],
            "gap": "Release-like local emulator APK/JNI smoke embeds the protected payload inside the JNI .so, but signed production release evidence and hostile-env evidence are missing.",
        },
        {
            "name": "windows_ci",
            "status": "blocked",
            "evidence": [
                "docs/qa/reports/windows-cross-build.json",
                "docs/qa/reports/windows-protected-cross-build.json",
                "docs/qa/ExternalEvidenceRequest.md",
                ".github/workflows/platform-windows.yml",
            ],
            "gap": "Local cross-build is not GitHub Actions Windows execution; Windows hard acceptance requires reports with ci_execution=true from a Windows GitHub Actions runner.",
        },
    ]
    status = "blocked" if any(item["status"] != "pass" for item in capabilities) else "pass"
    github_run_url = None
    if os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID"):
        github_run_url = f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    report = {
        "schema": "vmp.qa.capability_matrix.v1",
        "status": status,
        "final_signoff_allowed": False,
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "github_workflow": os.environ.get("GITHUB_WORKFLOW"),
        "github_repository": os.environ.get("GITHUB_REPOSITORY"),
        "github_sha": os.environ.get("GITHUB_SHA"),
        "github_event_name": os.environ.get("GITHUB_EVENT_NAME"),
        "github_ref": os.environ.get("GITHUB_REF"),
        "github_ref_name": os.environ.get("GITHUB_REF_NAME"),
        "github_ref_protected": os.environ.get("GITHUB_REF_PROTECTED"),
        "github_run_url": github_run_url,
        "capabilities": capabilities,
        "llvm_stage_manifest": stage_manifest,
        "summary": "Current evidence is stronger than a pure skeleton, but still not VMProtect-tier commercial protection.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
