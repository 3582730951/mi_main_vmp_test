#!/usr/bin/env python3
"""Plan-to-artifact completion audit.

This audit is intentionally separate from acceptance_audit.py. It parses
plan/1.txt, maps every T000-T155 task to concrete evidence candidates, and
fails hard acceptance items that do not have real artifact or command evidence.
It never reads passwd.txt.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import urllib.request
import urllib.parse
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    from .reverse_cost_gate import current_git_sha, validate_report as validate_reverse_cost_report
except ImportError:  # pragma: no cover - script execution path
    from reverse_cost_gate import current_git_sha, validate_report as validate_reverse_cost_report


TASK_RE = re.compile(r"^T\d{3}$")
BACKTICK_RE = re.compile(r"`([^`]+)`")
PIPE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache", "node_modules", "build", "dist"}
DOC_NAME_DIRS = ("docs", "docs/specs", "docs/qa", "docs/platform", "docs/anti-analysis", "docs/references")
GENERATED_REPORT_GLOBS = (
    "samples/protected_chain/out/*.json",
    "docs/qa/reports/**/*",
    "artifacts/protected/**/*",
)
TRUSTED_GITHUB_EVENTS = {"push", "workflow_dispatch", "schedule"}
MAX_GITHUB_RUN_AGE_DAYS = 30
EXPECTED_WORKFLOW_PATHS = {
    "platform-android": ".github/workflows/platform-android-plan.yml",
    "platform-windows": ".github/workflows/platform-windows.yml",
    "vmprotect-tier": ".github/workflows/vmprotect-tier.yml",
    "manual-review": ".github/workflows/manual-review.yml",
}


@dataclass(frozen=True)
class Task:
    task_id: str
    owner: str
    dependency: str
    deliverable: str
    acceptance: str


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    exists: bool


@dataclass(frozen=True)
class TaskResult:
    task_id: str
    owner: str
    deliverable: str
    status: str
    evidence: list[Evidence]
    notes: list[str]


@dataclass(frozen=True)
class HardAcceptanceResult:
    item: str
    status: str
    evidence: list[Evidence]
    notes: list[str]


@dataclass(frozen=True)
class ObjectiveRequirementResult:
    item: str
    status: str
    evidence: list[Evidence]
    notes: list[str]


def _split_row(line: str) -> list[str]:
    match = PIPE_ROW_RE.match(line)
    if not match:
        return []
    return [cell.strip() for cell in match.group(1).split("|")]


def parse_plan(plan_path: Path) -> tuple[list[Task], list[tuple[str, str]]]:
    text = safe_read_text(plan_path)
    tasks: list[Task] = []
    hard_acceptance: list[tuple[str, str]] = []
    in_hard_acceptance = False

    for line in text.splitlines():
        if line.startswith("## "):
            in_hard_acceptance = "Hard Acceptance" in line
            continue

        cells = _split_row(line)
        if not cells or cells[0].startswith("---") or cells[0] in {"Task", "项目"}:
            continue

        if in_hard_acceptance and len(cells) >= 2:
            hard_acceptance.append((cells[0], cells[1]))
            continue

        if not TASK_RE.match(cells[0]):
            continue
        if len(cells) == 4:
            task_id, owner, deliverable, acceptance = cells
            dependency = ""
        elif len(cells) >= 5:
            task_id, owner, dependency, deliverable, acceptance = cells[:5]
        else:
            continue
        tasks.append(Task(task_id, owner, dependency, deliverable, acceptance))

    return tasks, hard_acceptance


def safe_read_text(path: Path) -> str:
    if path.name == "passwd.txt":
        raise RuntimeError("plan completion audit must not read passwd.txt")
    return path.read_text(encoding="utf-8")


def iter_repo_files(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if path.name == "passwd.txt":
                continue
            yield path


def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def evidence_path(root: Path, value: str) -> Evidence:
    value = value.strip()
    candidates: list[Path] = []
    raw = value[2:] if value.startswith("./") else value.lstrip("/")
    candidates.append(root / raw)
    if "/" not in raw:
        for base in DOC_NAME_DIRS:
            candidates.append(root / base / raw)
    existing = next((path for path in candidates if path.exists()), None)
    return Evidence("path", rel(existing, root) if existing else raw, existing is not None)


def command_evidence(root: Path, value: str) -> Evidence:
    path = root / value
    exists = path.exists() and path.is_file()
    if exists and path.suffix in {".sh", ".ps1", ".py"}:
        return Evidence("command", value, True)
    return Evidence("command", value, exists and os.access(path, os.X_OK))


def glob_evidence(root: Path, pattern: str) -> Evidence:
    matches = sorted(path for path in root.glob(pattern) if path.name != "passwd.txt")
    return Evidence("glob", pattern, bool(matches))


def explicit_evidence(root: Path, task: Task) -> list[Evidence]:
    evidence: list[Evidence] = []
    for token in BACKTICK_RE.findall(f"{task.deliverable} {task.acceptance}"):
        if token == "passwd.txt" or token.startswith("${{"):
            continue
        if ":" in token and not token.startswith((".", "/")):
            continue
        if token.endswith((".sh", ".ps1", ".py")):
            evidence.append(command_evidence(root, token))
        elif "/" in token or "." in Path(token).name:
            evidence.append(evidence_path(root, token))
    return evidence


def inferred_task_evidence(root: Path, task: Task) -> list[Evidence]:
    text = f"{task.owner} {task.deliverable} {task.acceptance}".lower()
    evidence: list[Evidence] = explicit_evidence(root, task)

    def add_path(value: str) -> None:
        evidence.append(evidence_path(root, value))

    def add_cmd(value: str) -> None:
        evidence.append(command_evidence(root, value))

    if "llvm" in text or "ollvm" in text or "opcode" in text or "bytecode" in text or "config parser" in text:
        add_path("src/core")
        add_cmd("tests/core/run_core_tests.sh")
    if "llvm pass plugin" in text or "new pm" in text or "pass plugin" in text:
        add_path("src/core/llvm/VMPPassPlugin.cpp")
        add_cmd("tests/core/run_llvm_plugin_test.sh")
    if "vm runtime" in text or "dispatcher" in text or "nested" in text or "handler" in text:
        add_path("src/runtime")
        add_cmd("tests/core/run_core_tests.sh")
    if "anti" in text or "debug" in text or "injection" in text or "string" in text or "junk" in text:
        add_path("src/anti_analysis")
        add_path("tests/anti_analysis")
    if "windows" in text or ".exe" in text or ".dll" in text or "pe/coff" in text:
        add_path("src/platform/windows")
        add_path(".github/workflows/platform-windows.yml")
        add_cmd("tests/platform/windows_acceptance.ps1")
    if "linux" in text or "elf" in text or ".so" in text or "dlopen" in text or "dlsym" in text:
        add_path("src/platform/linux")
        add_path(".github/workflows/platform-linux.yml")
        add_cmd("tests/platform/linux_smoke.sh")
    if "android" in text or "apk" in text or "jni" in text or "xposed" in text or "lsposed" in text or "frida" in text:
        add_path("src/platform/android")
        add_path(".github/workflows/platform-android-plan.yml")
        add_cmd("tests/platform/android_emulator_plan.sh")
    if "ios" in text or "mach-o" in text or "xcode" in text or "signing" in text or "no-jit" in text:
        add_path("src/platform/ios")
        add_path("docs/platform/ios.md")
        add_path(".github/workflows/platform-ios-logic.yml")
        add_cmd("tests/platform/ios_logic_check.sh")
    if "ci" in text or "github actions" in text or "workflow" in text or "secrets" in text:
        add_path(".github/workflows")
        add_path("docs/CI_SECRETS.md")
    if "remote repository" in text or "远端" in text or "repository setup" in text:
        add_path("docs/CI_SECRETS.md")
    if task.task_id == "T005" or "联网资料" in task.deliverable:
        add_path("docs/references/OFFICIAL_SOURCES.md")
    if "qa" in task.owner or "acceptance" in text or "report" in text or "validation" in text or "tests" in text:
        add_path("docs/qa")
        add_path("docs/specs/Acceptance.md")
        add_path("tests/qa")
    if "performance" in text or "benchmark" in text:
        add_path("docs/qa")
        add_path("tests/qa")
    if task.task_id == "T155" or "final sign-off" in text or "final sign" in text:
        add_path("docs/qa/FinalSignOff.md")

    return dedupe_evidence(evidence)


def dedupe_evidence(evidence: Iterable[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, str]] = set()
    unique: list[Evidence] = []
    for item in evidence:
        key = (item.kind, item.value)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def classify_task(root: Path, task: Task, evidence: list[Evidence]) -> tuple[str, list[str]]:
    text = f"{task.deliverable} {task.acceptance}".lower()
    notes: list[str] = []
    existing = [item for item in evidence if item.exists]
    if task.task_id == "T097":
        if windows_github_actions_evidence_exists(root):
            notes.append("Windows GitHub Actions runner evidence exists for protected .exe execution and .dll load")
            return "pass", notes
        notes.append("Windows CI acceptance remains blocked until GitHub Actions Windows reports show protected .exe execution and .dll load")
        return "blocker", notes
    if task.task_id == "T117":
        if android_hostile_full_coverage_exists(root):
            notes.append("Android hostile-environment report covers root, Xposed/LSPosed, and Frida/hook trigger categories")
            return "pass", notes
        notes.append("Android hostile-environment acceptance remains blocked until root, Xposed/LSPosed, and Frida/hook trigger reports exist")
        return "blocker", notes
    if task.task_id == "T155":
        signoff = next((item for item in existing if item.value == "docs/qa/FinalSignOff.md"), None)
        if signoff is None:
            notes.append("final sign-off document is missing")
            return "blocker", notes
        if final_signoff_evidence_exists(root):
            notes.append("final sign-off is signed and all strict external evidence gates are satisfied")
            return "pass", notes
        notes.append("final sign-off exists but is explicitly blocked or external evidence is incomplete")
        return "blocker", notes
    if "人工复核" in task.acceptance or "ida/ollydbg" in text:
        notes.append("manual reverse-engineering review portion is excluded from this automated audit")
        return "manual-excluded", notes
    if existing:
        command_exists = any(item.kind == "command" and item.exists for item in existing)
        if "tests" in text or "validation" in text or "acceptance" in text or "ci" in text:
            return ("pass" if command_exists or any(item.kind == "path" for item in existing) else "implemented"), notes
        return "implemented", notes
    notes.append("no concrete artifact, command, or report path exists for deliverable")
    return "blocker", notes


def task_results(root: Path, tasks: list[Task]) -> list[TaskResult]:
    results: list[TaskResult] = []
    for task in tasks:
        evidence = inferred_task_evidence(root, task)
        status, notes = classify_task(root, task, evidence)
        results.append(TaskResult(task.task_id, task.owner, task.deliverable, status, evidence, notes))
    return results


def hard_acceptance_evidence(root: Path, item: str, standard: str) -> list[Evidence]:
    text = f"{item} {standard}".lower()
    evidence: list[Evidence] = []

    def path(value: str) -> None:
        evidence.append(evidence_path(root, value))

    def cmd(value: str) -> None:
        evidence.append(command_evidence(root, value))

    def glob(value: str) -> None:
        evidence.append(glob_evidence(root, value))

    normalized_item = item.lower()
    if item.upper() == "CI" or "github" in normalized_item:
        path(".github/workflows")
        path("docs/CI_SECRETS.md")
        path("acceptance.sh")
        path("final_acceptance.sh")
        glob("docs/qa/reports/windows-*.json")
        glob("docs/qa/reports/android-*.json")
    elif "动态" in item or "breakpoint" in text or "注入" in item or "frida" in text:
        path("src/anti_analysis/environment.py")
        path("src/platform")
        cmd("tests/platform/run_all_local.sh")
        cmd("tests/platform/hostile_environment_report.py")
        path("docs/qa/reports/windows-hostile-triggers.json")
        path("docs/qa/reports/windows-hostile-github-actions-verification.json")
        path("docs/qa/reports/android-hostile-triggers.json")
        path("docs/qa/reports/android-hostile-github-actions-verification.json")
        glob("docs/qa/**/*Hostile*")
        glob("docs/qa/reports/*hostile*")
    elif "合法" in item or "rootkit" in text:
        path("docs/SECURITY_POLICY.md")
    elif "android" in normalized_item:
        path("src/platform/android")
        cmd("tests/platform/android_emulator_plan.sh")
        cmd("tests/platform/android_environment_check.sh")
        path(".github/workflows/platform-android-plan.yml")
        glob("**/*.apk")
        glob("**/android*/**/*.so")
        glob("docs/qa/**/*Android*")
        glob("docs/qa/reports/android-*.json")
    elif "ios" in normalized_item:
        path("docs/platform/ios.md")
        path("src/platform/ios")
        cmd("tests/platform/ios_logic_check.sh")
        path(".github/workflows/platform-ios-logic.yml")
    elif "windows" in normalized_item:
        path("src/platform/windows")
        path(".github/workflows/platform-windows.yml")
        cmd("tests/platform/windows_acceptance.ps1")
        glob("**/*.exe")
        glob("**/*.dll")
        glob("docs/qa/**/*Windows*")
        glob("docs/qa/reports/windows-*.json")
    elif "对标" in item or "vmprotect" in text:
        path("src/core")
        path("src/runtime")
        path("src/anti_analysis")
        path("docs/qa/CompletionAudit.md")
        glob("docs/qa/reports/*capability*")
        path("docs/qa/reports/general-ir-lowering.json")
        path("docs/qa/reports/production-crypto-key-management.json")
        path("docs/qa/reports/vmprotect-tier-review.json")
        path("docs/qa/reports/vmprotect-tier-github-actions-verification.json")
        glob("samples/protected_chain/out/randomness.json")
        glob("samples/protected_chain/out/behavior.json")
    elif "字符串" in item or "string" in text:
        path("src/anti_analysis/string_policy.py")
        path("tests/anti_analysis/test_string_policy.py")
        glob("build/release/**/*")
        glob("artifacts/protected/**/*")
        glob("docs/qa/**/*String*")
        glob("samples/protected_chain/out/strings.json")
    elif "ida" in text or "ollydbg" in text or "xref" in text:
        path("docs/qa/TaskCoverage.md")
        path("src/anti_analysis/junk_templates.py")
        path("tests/anti_analysis/test_junk_templates.py")
        path("docs/qa/reports/ida-ollydbg-review.json")
        path("docs/qa/reports/ida-ollydbg-github-actions-verification.json")
        glob("docs/qa/reports/*ida*review*.json")
    elif "优先级" in item or "防御强度" in text:
        path("docs/ARCHITECTURE.md")
        path("docs/SECURITY_POLICY.md")

    return dedupe_evidence(evidence)


def read_json_report(root: Path, relative_path: str) -> dict[str, object] | None:
    path = root / relative_path
    if not path.exists() or path.name == "passwd.txt":
        return None
    try:
        return json.loads(safe_read_text(path))
    except (OSError, json.JSONDecodeError):
        return None


def android_apk_protected_sample_evidence_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/android-apk-smoke.json")
    return bool(
        report
        and report.get("status") == "pass"
        and report.get("apk_install_executed") is True
        and report.get("core_logic_consistent") is True
        and report.get("protected_sample_executed") is True
        and report.get("hostile_evidence_claim") is not True
    )


def android_native_so_smoke_evidence_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/android-emulator-smoke.json")
    return bool(
        report
        and report.get("status") == "pass"
        and report.get("emulator_execution") is True
        and report.get("protected_so_loaded") is True
        and (report.get("core_logic_consistent") is True or report.get("jni_on_load_called") is True)
    )


def android_release_strength_evidence_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/android-apk-smoke.json")
    so_report = read_json_report(root, "docs/qa/reports/android-emulator-smoke.json")
    return bool(
        report
        and so_report
        and github_actions_verification_matches(
            root,
            "docs/qa/reports/android-github-actions-verification.json",
            [report, so_report],
            ["docs/qa/reports/android-apk-smoke.json", "docs/qa/reports/android-emulator-smoke.json"],
            expected_workflow="platform-android",
        )
        and report.get("status") == "pass"
        and so_report.get("status") == "pass"
        and report.get("github_actions") is True
        and so_report.get("github_actions") is True
        and report.get("ci_execution") is True
        and so_report.get("ci_execution") is True
        and report.get("github_workflow") == "platform-android"
        and so_report.get("github_workflow") == "platform-android"
        and report.get("release_signing_secret_used") is True
        and report.get("signing_key_scope") == "github_secret_keystore"
        and report.get("manifest_debuggable") is False
        and report.get("protected_payload_embedded_in_jni") is True
        and report.get("protected_sample_asset_packaged") is False
        and report.get("apk_forbidden_plaintext_hits") == []
        and report.get("jni_symbol_plaintext_hits") == []
        and report.get("core_logic_consistent") is True
        and so_report.get("emulator_execution") is True
        and so_report.get("protected_so_loaded") is True
        and (so_report.get("core_logic_consistent") is True or so_report.get("jni_on_load_called") is True)
    )


def hostile_real_trigger_scope(root: Path) -> str:
    report = read_json_report(root, "docs/qa/reports/hostile-environment.json")
    if not report or not report.get("real_platform_triggers"):
        return "none"
    scope = report.get("real_platform_trigger_scope")
    return str(scope) if scope else "unknown"


def windows_protected_cross_evidence_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/windows-protected-cross-build.json")
    return bool(report and report.get("status") == "partial" and report.get("local_cross_compile") is True)


def hostile_full_coverage_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/hostile-environment.json")
    if not report or report.get("status") != "pass":
        return False
    required = {
        "windows_hardware_breakpoint",
        "windows_memory_breakpoint",
        "windows_dll_injection",
        "android_root",
        "android_xposed_lsposed",
        "android_frida_hook",
    }
    covered = set(str(item) for item in report.get("real_trigger_types", []))
    return (
        required.issubset(covered)
        and windows_hostile_full_coverage_exists(root)
        and android_hostile_full_coverage_exists(root)
    )


def windows_hostile_full_coverage_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/windows-hostile-triggers.json")
    if not report or report.get("status") != "pass":
        return False
    if not github_actions_verification_matches(
        root,
        "docs/qa/reports/windows-hostile-github-actions-verification.json",
        [report],
        ["docs/qa/reports/windows-hostile-triggers.json"],
        expected_workflow="platform-windows",
    ):
        return False
    if report.get("schema") != "vmp.platform.windows_hostile_triggers.v1":
        return False
    if report.get("github_workflow") != "platform-windows":
        return False
    if report.get("ci_execution") is not True or report.get("github_actions") is not True:
        return False
    if str(report.get("runner_os", "")).lower() != "windows":
        return False
    if report.get("missing_required_external_triggers") != []:
        return False
    required_flags = (
        "non_self_hardware_breakpoint_observed",
        "memory_page_breakpoint_observed",
        "external_debugger_observed",
        "external_dll_injection_observed",
    )
    if not all(report.get(flag) is True for flag in required_flags):
        return False
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return False
    signals = {
        str(finding.get("signal", "")).lower()
        for finding in findings
        if isinstance(finding, dict)
    }
    has_hardware = any("hardware" in signal or "dr" in signal for signal in signals)
    has_memory = any("memory" in signal or "page" in signal or "guard" in signal for signal in signals)
    has_debugger = any("debugger" in signal for signal in signals)
    has_injection = any("dll" in signal or "injection" in signal or "module" in signal for signal in signals)
    return has_hardware and has_memory and has_debugger and has_injection


def android_hostile_full_coverage_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/android-hostile-triggers.json")
    if not report or report.get("status") != "pass":
        return False
    if report.get("schema") != "vmp.platform.android_hostile_triggers.v1":
        return False
    if report.get("missing_required_triggers") != []:
        return False
    if report.get("github_workflow") != "platform-android":
        return False
    if report.get("ci_execution") is not True or report.get("github_actions") is not True:
        return False
    device = report.get("device")
    if not isinstance(device, dict):
        return False
    for key in ("adb_serial", "abi", "build_fingerprint"):
        if not isinstance(device.get(key), str) or not device.get(key):
            return False
    profile_id = report.get("hostile_profile_id")
    if report.get("authorized_hostile_profile") is not True or not isinstance(profile_id, str) or not profile_id:
        return False
    run_id = report.get("github_run_id")
    repository = report.get("github_repository")
    sha = report.get("github_sha")
    if not (isinstance(run_id, str) and run_id and isinstance(repository, str) and repository):
        return False
    if not is_sha1_hex(sha) or not github_event_is_trusted(report.get("github_event_name")):
        return False
    if not github_actions_verification_matches(
        root,
        "docs/qa/reports/android-hostile-github-actions-verification.json",
        [report],
        ["docs/qa/reports/android-hostile-triggers.json"],
        expected_workflow="platform-android",
    ):
        return False
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return False
    signals = {
        str(finding.get("signal", "")).lower()
        for finding in findings
        if isinstance(finding, dict)
    }
    categories = {
        str(finding.get("category", "")).lower()
        for finding in findings
        if isinstance(finding, dict)
    }
    has_root = "root" in categories
    has_xposed = any(marker in signal for signal in signals for marker in ("xposed", "lsposed", "edxposed", "zygisk"))
    has_frida = any(marker in signal for signal in signals for marker in ("frida", "hook"))
    return has_root and has_xposed and has_frida


def vmprotect_tier_evidence_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/capability-matrix.json")
    lowering = read_json_report(root, "docs/qa/reports/general-ir-lowering.json")
    crypto = read_json_report(root, "docs/qa/reports/production-crypto-key-management.json")
    review = read_json_report(root, "docs/qa/reports/vmprotect-tier-review.json")
    required_capabilities = {
        "code_virtualization",
        "mutation_obfuscation",
        "combined_protection",
        "string_hiding",
        "import_hiding",
        "anti_debug",
        "anti_injection",
        "anti_tamper",
    }
    capabilities = review.get("capabilities", {}) if isinstance(review, dict) else {}
    review_platforms = review.get("platforms_proven", []) if isinstance(review, dict) else []
    platforms = set(str(platform).lower() for platform in review_platforms)
    provenance_ok = github_actions_verification_matches(
        root,
        "docs/qa/reports/vmprotect-tier-github-actions-verification.json",
        [report, lowering, crypto, review],
        [
            "docs/qa/reports/capability-matrix.json",
            "docs/qa/reports/general-ir-lowering.json",
            "docs/qa/reports/production-crypto-key-management.json",
            "docs/qa/reports/vmprotect-tier-review.json",
        ],
        expected_workflow="vmprotect-tier",
    )
    return bool(
        report
        and report.get("status") == "pass"
        and report.get("final_signoff_allowed") is True
        and provenance_ok
        and all(item.get("github_workflow") == "vmprotect-tier" for item in (report, lowering, crypto, review))
        and lowering
        and lowering.get("schema") == "vmp.qa.general_ir_lowering.v1"
        and lowering.get("status") == "pass"
        and lowering.get("broad_ir_lowering") is True
        and lowering.get("bounded_i32_only") is False
        and crypto
        and crypto.get("schema") == "vmp.qa.production_crypto_key_management.v1"
        and crypto.get("status") == "pass"
        and crypto.get("production_crypto") is True
        and crypto.get("static_keys_present") is False
        and crypto.get("key_rotation_supported") is True
        and review
        and review.get("schema") == "vmp.qa.vmprotect_tier_review.v1"
        and review.get("status") == "pass"
        and review.get("manual_review") is True
        and review.get("open_vulnerabilities") == 0
        and review.get("open_findings") == 0
        and all(capabilities.get(capability) is True for capability in required_capabilities)
        and {"linux", "windows", "android"}.issubset(platforms)
    )


def ida_ollydbg_manual_review_evidence_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/ida-ollydbg-review.json")
    if not report:
        return False
    provenance_ok = github_actions_verification_matches(
        root,
        "docs/qa/reports/ida-ollydbg-github-actions-verification.json",
        [report],
        ["docs/qa/reports/ida-ollydbg-review.json"],
        expected_workflow="manual-review",
    )
    required_tools = {str(tool).lower() for tool in report.get("tools", [])}
    required_indicators = report.get("reviewed_indicators", {})
    if not isinstance(required_indicators, dict):
        return False
    return bool(
        report.get("schema") == "vmp.qa.manual_reverse_review.v1"
        and report.get("status") == "pass"
        and provenance_ok
        and report.get("github_workflow") == "manual-review"
        and report.get("manual_review") is True
        and isinstance(report.get("reviewer"), str)
        and report.get("reviewer")
        and isinstance(report.get("review_date"), str)
        and report.get("review_date")
        and {"ida", "ollydbg"}.issubset(required_tools)
        and report.get("open_vulnerabilities") == 0
        and report.get("open_findings") == 0
        and required_indicators.get("f5_or_decompiler_distortion") is True
        and required_indicators.get("xref_or_callgraph_distortion") is True
        and required_indicators.get("string_reference_distortion") is True
        and required_indicators.get("debugger_or_breakpoint_behavior") is True
    )


def final_signoff_evidence_exists(root: Path) -> bool:
    path = root / "docs/qa/FinalSignOff.md"
    if not path.exists():
        return False
    try:
        text = safe_read_text(path)
    except OSError:
        return False
    required_markers = (
        "Status: **signed off**",
        "Strict completion audit: pass",
        "Open vulnerabilities: 0",
        "Open findings: 0",
    )
    return bool(
        all(marker in text for marker in required_markers)
        and windows_github_actions_evidence_exists(root)
        and android_release_strength_evidence_exists(root)
        and hostile_full_coverage_exists(root)
        and vmprotect_tier_evidence_exists(root)
        and ida_ollydbg_manual_review_evidence_exists(root)
        and reverse_cost_evidence_exists(root)
    )


def reverse_cost_evidence_exists(root: Path) -> bool:
    report = read_json_report(root, "docs/qa/reports/reverse-cost-assessment.json")
    if not report:
        return False
    return validate_reverse_cost_report(report, current_git_sha(root)) == []


def ci_runner_evidence_exists(root: Path) -> bool:
    return windows_github_actions_evidence_exists(root)


def is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def is_sha1_hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None


def github_event_is_trusted(value: object) -> bool:
    return isinstance(value, str) and value in TRUSTED_GITHUB_EVENTS


def sha256_file(path: Path) -> str:
    if path.name == "passwd.txt":
        raise RuntimeError("plan completion audit must not read passwd.txt")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch_github_run(repository: str, run_id: str, github_auth: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_auth}",
            "User-Agent": "vmp-completion-audit",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_github_artifacts(repository: str, run_id: str, github_auth: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_auth}",
            "User-Agent": "vmp-completion-audit",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def download_github_artifact_zip(download_url: str, github_auth: str) -> bytes:
    class ArtifactRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
            if redirected is None:
                return None
            source_host = urllib.parse.urlparse(req.full_url).netloc
            target_host = urllib.parse.urlparse(newurl).netloc
            if target_host and target_host != source_host:
                redirected.remove_header("Authorization")
                redirected.remove_header("Accept")
                redirected.remove_header("X-GitHub-Api-Version")
            return redirected

    request = urllib.request.Request(
        download_url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_auth}",
            "User-Agent": "vmp-completion-audit",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    opener = urllib.request.build_opener(ArtifactRedirectHandler)
    with opener.open(request, timeout=30) as response:
        return response.read()


def parse_github_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def github_artifact_contains_reports(
    root: Path,
    verification_path: str,
    verification: dict[str, object],
    report_paths: list[str],
    github_auth: str,
) -> bool:
    artifact_name = verification.get("artifact_name")
    repository = verification.get("github_repository")
    run_id = verification.get("github_run_id")
    run_attempt = verification.get("github_run_attempt")
    if not (
        isinstance(artifact_name, str)
        and artifact_name
        and isinstance(repository, str)
        and repository
        and isinstance(run_id, str)
        and run_id
    ):
        return False
    try:
        artifacts = fetch_github_artifacts(repository, run_id, github_auth)
    except Exception:
        return False
    candidates = []
    for artifact in artifacts.get("artifacts", []):
        if not isinstance(artifact, dict) or artifact.get("name") != artifact_name:
            continue
        if artifact.get("expired") is True:
            continue
        workflow_run = artifact.get("workflow_run")
        artifact_attempt = workflow_run.get("run_attempt") if isinstance(workflow_run, dict) else None
        if artifact_attempt is not None and str(artifact_attempt) != str(run_attempt):
            continue
        candidates.append(artifact)
    if len(candidates) != 1:
        return False
    download_url = candidates[0].get("archive_download_url")
    if not isinstance(download_url, str) or not download_url:
        return False
    try:
        zip_bytes = download_github_artifact_zip(download_url, github_auth)
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception:
        return False
    expected_hashes = dict(verification.get("report_sha256", {})) if isinstance(verification.get("report_sha256"), dict) else {}
    expected_paths = [verification_path, *report_paths]
    try:
        names = set(archive.namelist())
        for relative_path in expected_paths:
            if relative_path not in names:
                return False
            digest = hashlib.sha256(archive.read(relative_path)).hexdigest()
            if relative_path == verification_path:
                if digest != sha256_file(root / verification_path):
                    return False
            elif digest != str(expected_hashes.get(relative_path, "")).lower():
                return False
    except Exception:
        return False
    finally:
        archive.close()
    return True


def github_actions_verification_matches(
    root: Path,
    relative_path: str,
    reports: list[dict[str, object]],
    report_paths: list[str],
    expected_workflow: str | None = None,
    expected_workflow_path: str | None = None,
) -> bool:
    verification = read_json_report(root, relative_path)
    if not verification:
        return False
    status = verification.get("status")
    if status not in {"pass", "provisional"} or verification.get("github_api_verified") is not True:
        return False
    if verification.get("schema") != "vmp.qa.github_actions_verification.v1":
        return False
    if verification.get("github_actions_runtime") is not True:
        return False
    if status == "pass" and (verification.get("run_status") != "completed" or verification.get("run_conclusion") != "success"):
        return False
    if status == "provisional" and verification.get("final_run_revalidation_required") is not True:
        return False
    if verification.get("max_run_age_days") not in (None, MAX_GITHUB_RUN_AGE_DAYS):
        return False
    allowed_mismatches = ["api:run_not_completed"] if status == "provisional" else []
    if verification.get("mismatches") != allowed_mismatches:
        return False
    run_id = verification.get("github_run_id")
    repository = verification.get("github_repository")
    sha = verification.get("github_sha")
    event_name = verification.get("github_event_name")
    run_url = verification.get("github_run_url")
    run_attempt = verification.get("github_run_attempt")
    ref_name = verification.get("github_ref_name")
    if not (isinstance(run_id, str) and run_id and isinstance(repository, str) and repository):
        return False
    if not (isinstance(run_attempt, str) and run_attempt and isinstance(ref_name, str) and ref_name):
        return False
    if not is_sha1_hex(sha) or not github_event_is_trusted(event_name):
        return False
    if verification.get("github_ref_protected") is not True:
        return False
    if verification.get("pull_requests") != []:
        return False
    if verification.get("head_repository") not in (None, repository):
        return False
    expected_path = expected_workflow_path or (EXPECTED_WORKFLOW_PATHS.get(expected_workflow) if expected_workflow else None)
    if expected_workflow and verification.get("github_workflow") != expected_workflow:
        return False
    workflow_path = verification.get("workflow_path")
    if expected_path:
        if workflow_path != expected_path:
            return False
    elif workflow_path and not str(workflow_path).startswith(".github/workflows/"):
        return False
    if not (isinstance(run_url, str) and run_url.startswith(f"https://github.com/{repository}/") and run_url.endswith(f"/actions/runs/{run_id}")):
        return False
    expected_reports = set(report_paths)
    actual_reports = {str(item) for item in verification.get("evidence_reports", [])}
    if not expected_reports.issubset(actual_reports):
        return False
    report_hashes = verification.get("report_sha256")
    if not isinstance(report_hashes, dict):
        return False
    for report_path in report_paths:
        actual_hash = report_hashes.get(report_path)
        if not (isinstance(actual_hash, str) and re.fullmatch(r"[0-9a-fA-F]{64}", actual_hash)):
            return False
        try:
            if sha256_file(root / report_path) != actual_hash.lower():
                return False
        except OSError:
            return False
    for report in reports:
        for key in ("github_run_id", "github_run_attempt", "github_repository", "github_sha", "github_event_name", "github_run_url"):
            if report.get(key) != verification.get(key):
                return False
        if report.get("github_workflow") and report.get("github_workflow") != verification.get("github_workflow"):
            return False
    github_auth = os.environ.get("GITHUB_TOKEN")
    if not github_auth:
        return False
    try:
        run = fetch_github_run(repository, run_id, github_auth)
    except Exception:
        return False
    head_repository = run.get("head_repository")
    head_repository_name = head_repository.get("full_name") if isinstance(head_repository, dict) else None
    if str(run.get("id")) != run_id:
        return False
    if str(run.get("run_attempt")) != run_attempt:
        return False
    if run.get("head_sha") != sha or run.get("event") != event_name or run.get("html_url") != run_url:
        return False
    if run.get("event") not in TRUSTED_GITHUB_EVENTS:
        return False
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return False
    if expected_workflow and run.get("name") != expected_workflow:
        return False
    if run.get("name") != verification.get("github_workflow"):
        return False
    if head_repository_name and head_repository_name != repository:
        return False
    if run.get("pull_requests", []) != []:
        return False
    if run.get("head_branch") not in (None, ref_name):
        return False
    api_workflow_path = run.get("path")
    if expected_path:
        if api_workflow_path != expected_path:
            return False
    elif api_workflow_path and not str(api_workflow_path).startswith(".github/workflows/"):
        return False
    run_created_at = run.get("created_at") or run.get("run_started_at")
    run_created = parse_github_timestamp(run_created_at)
    if run_created is None:
        return False
    if verification.get("run_created_at") and verification.get("run_created_at") != run_created_at:
        return False
    if (datetime.now(timezone.utc) - run_created).total_seconds() > MAX_GITHUB_RUN_AGE_DAYS * 24 * 60 * 60:
        return False
    if not github_artifact_contains_reports(root, relative_path, verification, report_paths, github_auth):
        return False
    return True


def windows_github_actions_evidence_exists(root: Path) -> bool:
    acceptance = read_json_report(root, "docs/qa/reports/windows-acceptance.json")
    protected = read_json_report(root, "docs/qa/reports/windows-protected-release.json")
    if not isinstance(acceptance, dict) or not isinstance(protected, dict):
        return False

    acceptance_artifacts = acceptance.get("artifacts")
    if not isinstance(acceptance_artifacts, list):
        return False
    valid_artifacts = [
        artifact
        for artifact in acceptance_artifacts
        if isinstance(artifact, dict)
        and isinstance(artifact.get("bytes"), int)
        and artifact.get("bytes", 0) > 0
        and is_sha256_hex(artifact.get("sha256"))
    ]
    artifact_kinds = {str(artifact.get("kind", "")).lower() for artifact in valid_artifacts}
    run_id = acceptance.get("github_run_id")
    run_url = acceptance.get("github_run_url")
    protected_run_id = protected.get("github_run_id")
    protected_run_url = protected.get("github_run_url")
    repository = acceptance.get("github_repository")
    sha = acceptance.get("github_sha")
    workflow = acceptance.get("github_workflow")
    event_name = acceptance.get("github_event_name")
    reports_match_verified_run = github_actions_verification_matches(
        root,
        "docs/qa/reports/windows-github-actions-verification.json",
        [acceptance, protected],
        ["docs/qa/reports/windows-acceptance.json", "docs/qa/reports/windows-protected-release.json"],
        expected_workflow="platform-windows",
    )
    return bool(
        acceptance
        and protected
        and reports_match_verified_run
        and acceptance.get("status") == "pass"
        and protected.get("status") == "pass"
        and acceptance.get("ci_execution") is True
        and protected.get("ci_execution") is True
        and acceptance.get("github_actions") is True
        and protected.get("github_actions") is True
        and isinstance(run_id, str)
        and run_id
        and run_id == protected_run_id
        and isinstance(repository, str)
        and repository
        and repository == protected.get("github_repository")
        and isinstance(sha, str)
        and re.fullmatch(r"[0-9a-fA-F]{40}", sha) is not None
        and sha == protected.get("github_sha")
        and isinstance(workflow, str)
        and workflow == "platform-windows"
        and workflow == protected.get("github_workflow")
        and isinstance(event_name, str)
        and event_name in {"push", "workflow_dispatch", "schedule"}
        and event_name == protected.get("github_event_name")
        and isinstance(run_url, str)
        and run_url.startswith(f"https://github.com/{repository}/")
        and run_url.endswith(f"/actions/runs/{run_id}")
        and run_url == protected_run_url
        and str(acceptance.get("runner_os", "")).lower() == "windows"
        and str(protected.get("runner_os", "")).lower() == "windows"
        and acceptance.get("smoke_exe_executed") is True
        and acceptance.get("dll_load_executed") is True
        and {"exe", "dll"}.issubset(artifact_kinds)
        and isinstance(protected.get("artifact_bytes"), int)
        and protected.get("artifact_bytes", 0) > 0
        and is_sha256_hex(protected.get("artifact_sha256"))
        and protected.get("behavior_cases_passed") == 4
        and protected.get("forbidden_plaintext_hits") == []
    )


def classify_hard_acceptance(root: Path, item: str, evidence: list[Evidence]) -> tuple[str, list[str]]:
    notes: list[str] = []
    existing = [entry for entry in evidence if entry.exists]
    lower_item = item.lower()
    if "ida" in lower_item or "ollydbg" in lower_item:
        if ida_ollydbg_manual_review_evidence_exists(root):
            notes.append("manual IDA/OllyDbg reverse-engineering review evidence exists with no open vulnerabilities or findings")
            return "pass", notes
        notes.append("automated anti-analysis indicators exist, but the plan's manual reverse-engineering review requirement is excluded from this workspace and cannot be marked hard-pass")
        return "blocker", notes
    requires_generated_evidence = item in {"Android", "Windows", "CI", "字符串", "对标", "动态对抗"}
    if not existing:
        notes.append("no concrete evidence exists")
        return "blocker", notes
    if requires_generated_evidence:
        has_output = any(entry.kind == "glob" and entry.exists for entry in evidence)
        if not has_output:
            notes.append("hard acceptance requires generated artifact/report evidence, not source/docs/commands alone")
            return "blocker", notes
    if item == "CI":
        if ci_runner_evidence_exists(root):
            notes.append("generated GitHub Actions runner evidence exists for the required non-Linux protected execution gate")
            return "pass", notes
        notes.append("workflow and secret-hygiene wiring exists, but aggregate CI hard acceptance requires generated non-Linux runner evidence and cannot pass on local files alone")
        return "blocker", notes
    if item == "Android":
        apk_evidence = android_apk_protected_sample_evidence_exists(root)
        so_evidence = android_native_so_smoke_evidence_exists(root)
        release_evidence = android_release_strength_evidence_exists(root)
        if release_evidence and so_evidence:
            notes.append("Android GitHub Actions evidence exists for secret-signed non-debuggable APK/JNI protected-sample execution and native .so smoke")
            return "pass", notes
        if apk_evidence and so_evidence:
            notes.append("Android emulator APK/JNI protected-sample evidence and native .so smoke evidence exist, but they remain local test-signed evidence and do not prove release-strength Android protection")
        elif apk_evidence:
            notes.append("Android emulator APK/JNI evidence executes the generated protected sample, but native .so smoke and release-strength Android proof remain incomplete")
        elif so_evidence:
            notes.append("Android emulator native .so smoke evidence exists, but APK/JNI protected-sample execution and release-strength Android proof remain incomplete")
        else:
            notes.append("environment/report evidence does not include passing emulator execution of a protected APK/JNI sample or Android .so")
        return "blocker", notes
    if item == "Windows":
        if windows_github_actions_evidence_exists(root):
            notes.append("GitHub Actions Windows runner evidence exists for protected .exe execution and .dll load")
            return "pass", notes
        if windows_protected_cross_evidence_exists(root):
            notes.append("local protected PE cross-build and workflow wiring exist, but the required GitHub Actions Windows execution gate has not produced run evidence")
        else:
            notes.append("local PE cross-build does not satisfy the required GitHub Actions Windows execution gate")
        return "blocker", notes
    if item == "动态对抗":
        if hostile_full_coverage_exists(root):
            notes.append("real hostile-environment trigger evidence covers Windows hardware/memory breakpoints, DLL injection, and Android root/Xposed/Frida/hook categories")
            return "pass", notes
        scope = hostile_real_trigger_scope(root)
        if scope == "none":
            notes.append("synthetic policy report does not satisfy required real hostile-environment trigger evidence")
        else:
            notes.append(f"partial real hostile-environment trigger evidence exists ({scope}), but required Windows hostile triggers and Android root/Xposed/LSPosed/Frida/hook coverage are still missing")
        return "blocker", notes
    if item == "对标":
        if vmprotect_tier_evidence_exists(root):
            notes.append("capability matrix permits final sign-off with VMProtect-tier evidence")
            return "pass", notes
        notes.append("local sample and narrow IR-derived i32 runtime-stub lowering for zero-, one-, two-, three-, and four-argument functions with straight-line local alloca/load/store, repeated loads from a definite local store, branch-condition loads whose defining store is on the entry-to-branch prefix, single-slot branch/merge local stores with a definite store on every lowered path, add/sub/mul/and/or/xor/select expressions, zext/sext from supported icmp-i32 predicates to i32, narrow trunc-i32-to-i1/i8/i16 followed by zext/sext back to i32 or through a wider integer and safely truncated back to i32, constant shl/lshr/ashr shifts with shift amounts in 0..31, masked dynamic shifts, eq/ne/sgt/slt/sge/sle/ugt/ult/uge/ule acyclic branch trees and select conditions, simple PHI return merges, and direct internal ordinary_add host-call cases including multiple linear calls with preserved intermediate results, local-stack stores fed by select/call values, and simple branch-return host-call paths, with nested VM branch targets rebased when serialized, pre-existing bytecode globals required to match a fresh lowering of the current body and be pass-marked immutable private globals before reuse and replacement refreshing bytecode metadata to the actual generated global, and with unmasked dynamic shifts, constant shifts outside 0..31, poison-generating nuw/nsw/exact arithmetic or shift flags, unsupported integer casts outside the narrow trunc-extension and safe wide-round-trip pattern, reserved opaque-dispatch name collisions, pre-existing outline-name collisions, loops or irreducible control flow, uninitialized branch-local loads, loads outside the lowered store path or branch prefix, stale or mutable pre-seeded bytecode globals, local memory combined with PHI shapes, global stores, and observable side-effecting unsupported IR left native, is not sufficient to prove VMProtect-tier commercial protection")
        return "blocker", notes
    return "pass", notes


def hard_acceptance_results(root: Path, hard_acceptance: list[tuple[str, str]]) -> list[HardAcceptanceResult]:
    results: list[HardAcceptanceResult] = []
    for item, standard in hard_acceptance:
        evidence = hard_acceptance_evidence(root, item, standard)
        status, notes = classify_hard_acceptance(root, item, evidence)
        results.append(HardAcceptanceResult(item, status, evidence, notes))
    return results


def objective_requirement_results(root: Path) -> list[ObjectiveRequirementResult]:
    return [
        review_requirement_result(root),
        parallel_agent_requirement_result(root),
    ]


def review_requirement_result(root: Path) -> ObjectiveRequirementResult:
    review_dir = root / "docs" / "qa" / "reviews"
    reviews = sorted(review_dir.glob("*.md")) if review_dir.exists() else []
    evidence = [Evidence("glob", "docs/qa/reviews/*.md", bool(reviews))]
    valid: list[str] = []
    invalid: list[str] = []
    required_markers = (
        "Review status: pass",
        "Open vulnerabilities: 0",
        "Open findings: 0",
    )
    for path in reviews:
        rel_path = rel(path, root)
        evidence.append(Evidence("path", rel_path, True))
        text = safe_read_text(path)
        if all(marker in text for marker in required_markers):
            valid.append(rel_path)
        else:
            invalid.append(rel_path)
    notes: list[str] = []
    if len(valid) >= 3 and not invalid:
        notes.append("three independent comprehensive review records exist and report no open vulnerabilities or findings")
        return ObjectiveRequirementResult("three_review_closure", "pass", dedupe_evidence(evidence), notes)
    if len(valid) < 3:
        notes.append(f"requires at least three review records with Review status: pass, Open vulnerabilities: 0, and Open findings: 0; found {len(valid)}")
    if invalid:
        notes.append("review records missing closure markers: " + ", ".join(invalid))
    return ObjectiveRequirementResult("three_review_closure", "blocker", dedupe_evidence(evidence), notes)


def parallel_agent_requirement_result(root: Path) -> ObjectiveRequirementResult:
    run_dir = root / "docs" / "qa" / "agent-runs"
    records = sorted(run_dir.glob("*.md")) if run_dir.exists() else []
    evidence = [Evidence("glob", "docs/qa/agent-runs/*.md", bool(records))]
    valid: list[str] = []
    invalid: list[str] = []
    for path in records:
        rel_path = rel(path, root)
        evidence.append(Evidence("path", rel_path, True))
        text = safe_read_text(path)
        count_match = re.search(r"Agent count:\s*`?(\d+)`?", text)
        agent_count = int(count_match.group(1)) if count_match else 0
        has_parallel_marker = "Parallel execution: yes" in text
        has_secret_marker = "No passwd.txt access: yes" in text
        if agent_count >= 3 and has_parallel_marker and has_secret_marker:
            valid.append(rel_path)
        else:
            invalid.append(rel_path)
    notes: list[str] = []
    if valid:
        notes.append("parallel multi-agent execution record exists with at least three agents and passwd.txt exclusion")
        return ObjectiveRequirementResult("parallel_agent_execution", "pass", dedupe_evidence(evidence), notes)
    notes.append("requires a docs/qa/agent-runs record with Agent count >= 3, Parallel execution: yes, and No passwd.txt access: yes")
    if invalid:
        notes.append("agent-run records missing required markers: " + ", ".join(invalid))
    return ObjectiveRequirementResult("parallel_agent_execution", "blocker", dedupe_evidence(evidence), notes)


def missing_task_ids(tasks: list[Task]) -> list[str]:
    present = {task.task_id for task in tasks}
    return [f"T{number:03d}" for number in range(156) if f"T{number:03d}" in present or number in _expected_numbers(present) if f"T{number:03d}" not in present]


def _expected_numbers(present: set[str]) -> set[int]:
    numbers = {int(task[1:]) for task in present}
    if not numbers:
        return set()
    return set(range(min(numbers), max(numbers) + 1)) & {
        *range(0, 6),
        *range(10, 15),
        *range(20, 30),
        *range(30, 38),
        *range(40, 47),
        *range(50, 57),
        *range(60, 68),
        *range(70, 81),
        *range(90, 98),
        *range(100, 107),
        *range(110, 118),
        *range(120, 127),
        *range(130, 136),
        *range(140, 145),
        *range(150, 156),
    }


def run_once(root: Path) -> dict[str, object]:
    plan_path = root / "plan" / "1.txt"
    tasks, hard_acceptance = parse_plan(plan_path)
    tasks_audit = task_results(root, tasks)
    hard_audit = hard_acceptance_results(root, hard_acceptance)
    objective_audit = objective_requirement_results(root)
    missing = missing_task_ids(tasks)
    findings: list[dict[str, str]] = []

    for task in tasks_audit:
        if task.status == "blocker":
            findings.append({"check": "task", "item": task.task_id, "message": "; ".join(task.notes)})
    for item in hard_audit:
        if item.status == "blocker":
            findings.append({"check": "hard_acceptance", "item": item.item, "message": "; ".join(item.notes)})
    for item in objective_audit:
        if item.status == "blocker":
            findings.append({"check": "objective", "item": item.item, "message": "; ".join(item.notes)})
    for task_id in missing:
        findings.append({"check": "plan_parse", "item": task_id, "message": "expected task id was not parsed from plan"})

    metrics = {
        "tasks": len(tasks_audit),
        "task_blockers": sum(1 for task in tasks_audit if task.status == "blocker"),
        "task_pass": sum(1 for task in tasks_audit if task.status == "pass"),
        "task_implemented": sum(1 for task in tasks_audit if task.status == "implemented"),
        "task_manual_excluded": sum(1 for task in tasks_audit if task.status == "manual-excluded"),
        "hard_acceptance": len(hard_audit),
        "hard_blockers": sum(1 for item in hard_audit if item.status == "blocker"),
        "objective_requirements": len(objective_audit),
        "objective_blockers": sum(1 for item in objective_audit if item.status == "blocker"),
    }

    return {
        "status": "pass" if not findings else "fail",
        "metrics": metrics,
        "findings": findings,
        "tasks": [task_to_dict(task) for task in tasks_audit],
        "hard_acceptance": [hard_to_dict(item) for item in hard_audit],
        "objective_requirements": [objective_to_dict(item) for item in objective_audit],
    }


def task_to_dict(task: TaskResult) -> dict[str, object]:
    data = asdict(task)
    data["evidence"] = [asdict(item) for item in task.evidence]
    return data


def hard_to_dict(item: HardAcceptanceResult) -> dict[str, object]:
    data = asdict(item)
    data["evidence"] = [asdict(entry) for entry in item.evidence]
    return data


def objective_to_dict(item: ObjectiveRequirementResult) -> dict[str, object]:
    data = asdict(item)
    data["evidence"] = [asdict(entry) for entry in item.evidence]
    return data


def render_markdown(report: dict[str, object]) -> str:
    metrics = report["metrics"]
    lines = [
        "# Completion Audit",
        "",
        "Generated by `scripts/audit/plan_completion_audit.py`. The audit parses `plan/1.txt`, skips `passwd.txt`, and maps plan deliverables to concrete paths, commands, reports, or generated artifacts.",
        "",
        "## Summary",
        "",
        f"- Status: `{report['status']}`",
        f"- Tasks parsed: `{metrics['tasks']}`",
        f"- Task statuses: `{metrics['task_pass']}` pass, `{metrics['task_implemented']}` implemented, `{metrics['task_manual_excluded']}` manual-excluded, `{metrics['task_blockers']}` blocker",
        f"- Hard acceptance blockers: `{metrics['hard_blockers']}` of `{metrics['hard_acceptance']}`",
        f"- Objective requirement blockers: `{metrics['objective_blockers']}` of `{metrics['objective_requirements']}`",
        "",
        "## Objective Requirements",
        "",
        "| Item | Status | Evidence | Notes |",
        "|---|---|---|---|",
    ]
    for item in report["objective_requirements"]:
        evidence = ", ".join(format_evidence(entry) for entry in item["evidence"]) or "none"
        notes = "; ".join(item["notes"]) or ""
        lines.append(f"| {item['item']} | `{item['status']}` | {evidence} | {notes} |")

    lines.extend([
        "",
        "## Hard Acceptance",
        "",
        "| Item | Status | Evidence | Notes |",
        "|---|---|---|---|",
    ])
    for item in report["hard_acceptance"]:
        evidence = ", ".join(format_evidence(entry) for entry in item["evidence"]) or "none"
        notes = "; ".join(item["notes"]) or ""
        lines.append(f"| {item['item']} | `{item['status']}` | {evidence} | {notes} |")

    lines.extend(["", "## Task Evidence", "", "| Task | Owner | Status | Deliverable | Evidence | Notes |", "|---|---|---|---|---|---|"])
    for task in report["tasks"]:
        evidence = ", ".join(format_evidence(entry) for entry in task["evidence"]) or "none"
        notes = "; ".join(task["notes"]) or ""
        lines.append(f"| {task['task_id']} | {task['owner']} | `{task['status']}` | {task['deliverable']} | {evidence} | {notes} |")

    if report["findings"]:
        lines.extend(["", "## Gaps And Blockers", ""])
        for finding in report["findings"]:
            lines.append(f"- `{finding['check']}` `{finding['item']}`: {finding['message']}")
    return "\n".join(lines) + "\n"


def format_evidence(entry: dict[str, object]) -> str:
    mark = "yes" if entry["exists"] else "no"
    return f"{entry['kind']}:{entry['value']} ({mark})"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run plan-to-artifact completion audit")
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--write-doc", action="store_true", help="write docs/qa/CompletionAudit.md")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = run_once(root)
    if args.write_doc:
        out_path = root / "docs" / "qa" / "CompletionAudit.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(render_markdown(report), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_markdown(report))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
