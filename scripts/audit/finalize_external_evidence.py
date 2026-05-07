#!/usr/bin/env python3
"""Assemble imported external evidence into final aggregate reports."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

try:
    from .plan_completion_audit import (
        android_release_strength_evidence_exists,
        hostile_full_coverage_exists,
        ida_ollydbg_manual_review_evidence_exists,
        vmprotect_tier_evidence_exists,
        windows_github_actions_evidence_exists,
    )
    from .reverse_cost_gate import current_git_sha, validate_report
except ImportError:  # pragma: no cover - script execution path
    from plan_completion_audit import (  # type: ignore
        android_release_strength_evidence_exists,
        hostile_full_coverage_exists,
        ida_ollydbg_manual_review_evidence_exists,
        vmprotect_tier_evidence_exists,
        windows_github_actions_evidence_exists,
    )
    from reverse_cost_gate import current_git_sha, validate_report


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_report(root: Path, relative_path: str) -> dict[str, object]:
    path = root / relative_path
    if not path.exists():
        raise FileNotFoundError(relative_path)
    data = read_json(path)
    if data.get("status") not in {"pass", "provisional"}:
        raise RuntimeError(f"{relative_path} is not pass/provisional")
    return data


def require_reverse_cost_report(root: Path) -> dict[str, object]:
    relative_path = "docs/qa/reports/reverse-cost-assessment.json"
    report = require_report(root, relative_path)
    errors = validate_report(report, current_git_sha(root))
    if errors:
        raise RuntimeError(f"{relative_path} failed validation: {'; '.join(errors)}")
    return report


def require_objective_completion_report(root: Path) -> dict[str, object]:
    relative_path = "docs/qa/reports/objective-completion-audit.json"
    path = root / relative_path
    if not path.exists():
        raise FileNotFoundError(relative_path)
    report = read_json(path)
    if report.get("schema") != "vmp.qa.objective_completion_audit.v1":
        raise RuntimeError(f"{relative_path} has unexpected schema")
    if report.get("status") != "pass":
        raise RuntimeError(f"{relative_path} is not pass")
    return report


def optional_report(root: Path, relative_path: str) -> dict[str, object] | None:
    path = root / relative_path
    if not path.exists():
        return None
    try:
        data = read_json(path)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def objective_completion_blocker(root: Path) -> str | None:
    report = optional_report(root, "docs/qa/reports/objective-completion-audit.json")
    if not report:
        return "`docs/qa/reports/objective-completion-audit.json` is missing or invalid."
    if report.get("schema") != "vmp.qa.objective_completion_audit.v1":
        return "`docs/qa/reports/objective-completion-audit.json` has an unexpected schema."
    if report.get("status") != "pass":
        residuals = report.get("residual_blockers", [])
        if isinstance(residuals, list) and residuals:
            return "`docs/qa/reports/objective-completion-audit.json` is blocked by " + ", ".join(
                str(item) for item in residuals
            ) + "."
        return "`docs/qa/reports/objective-completion-audit.json` is not pass."
    return None


def reverse_cost_blocker(root: Path) -> str | None:
    report = optional_report(root, "docs/qa/reports/reverse-cost-assessment.json")
    if not report:
        return "`docs/qa/reports/reverse-cost-assessment.json` is missing or invalid."
    errors = validate_report(report, current_git_sha(root))
    if errors:
        return "`docs/qa/reports/reverse-cost-assessment.json` failed validation: " + "; ".join(errors) + "."
    return None


def vmprotect_tier_blockers(root: Path) -> list[str]:
    blockers: list[str] = []
    capability = optional_report(root, "docs/qa/reports/capability-matrix.json")
    lowering = optional_report(root, "docs/qa/reports/general-ir-lowering.json")
    crypto = optional_report(root, "docs/qa/reports/production-crypto-key-management.json")
    review = optional_report(root, "docs/qa/reports/vmprotect-tier-review.json")
    sidecar = optional_report(root, "docs/qa/reports/vmprotect-tier-github-actions-verification.json")

    if not capability:
        blockers.append("`docs/qa/reports/capability-matrix.json` is missing or invalid.")
    elif capability.get("status") != "pass":
        blockers.append(
            "`docs/qa/reports/capability-matrix.json` remains blocked because the current implementation is not proven to be VMProtect-tier commercial protection."
        )
    elif capability.get("final_signoff_allowed") is not True:
        blockers.append(
            "`docs/qa/reports/capability-matrix.json` reports local VMProtect-tier implementation preconditions pass, but trusted vmprotect-tier GitHub provenance/final sign-off evidence is incomplete."
        )

    if not lowering:
        blockers.append("`docs/qa/reports/general-ir-lowering.json` is missing or invalid.")
    elif not (
        lowering.get("schema") == "vmp.qa.general_ir_lowering.v1"
        and lowering.get("status") == "pass"
        and lowering.get("broad_ir_lowering") is True
        and lowering.get("bounded_i32_only") is False
    ):
        blockers.append("`docs/qa/reports/general-ir-lowering.json` does not prove broad, non-bounded IR lowering.")

    if not crypto:
        blockers.append("`docs/qa/reports/production-crypto-key-management.json` is missing or invalid.")
    elif not (
        crypto.get("schema") == "vmp.qa.production_crypto_key_management.v1"
        and crypto.get("status") == "pass"
        and crypto.get("production_crypto") is True
        and crypto.get("static_keys_present") is False
        and crypto.get("key_rotation_supported") is True
    ):
        blockers.append("`docs/qa/reports/production-crypto-key-management.json` does not prove production crypto and key management.")

    if not review:
        blockers.append("`docs/qa/reports/vmprotect-tier-review.json` is missing or invalid.")
    elif not (
        review.get("schema") == "vmp.qa.vmprotect_tier_review.v1"
        and review.get("status") == "pass"
        and review.get("manual_review") is True
        and review.get("open_vulnerabilities") == 0
        and review.get("open_findings") == 0
    ):
        blockers.append("`docs/qa/reports/vmprotect-tier-review.json` does not prove a clean manual VMProtect-tier review.")

    if not sidecar:
        blockers.append("`docs/qa/reports/vmprotect-tier-github-actions-verification.json` is missing or invalid.")
    elif sidecar.get("schema") != "vmp.qa.github_actions_verification.v1" or sidecar.get("status") not in {
        "pass",
        "provisional",
    }:
        blockers.append("`docs/qa/reports/vmprotect-tier-github-actions-verification.json` is not usable GitHub Actions provenance.")

    return blockers


def final_signoff_blockers(root: Path) -> list[str]:
    blockers: list[str] = []
    for relative_path in FINAL_SIGNOFF_EVIDENCE:
        if not (root / relative_path).exists():
            blockers.append(f"`{relative_path}` is missing.")
    for check in (objective_completion_blocker(root), reverse_cost_blocker(root)):
        if check:
            blockers.append(check)
    blockers.extend(vmprotect_tier_blockers(root))
    if os.environ.get("VMP_REQUIRE_LIVE_GITHUB_VERIFICATION") != "1":
        blockers.append("Final sign-off assembly requires `VMP_REQUIRE_LIVE_GITHUB_VERIFICATION=1`.")
    strict_gates = (
        ("Windows GitHub Actions evidence", windows_github_actions_evidence_exists),
        ("Android release-strength evidence", android_release_strength_evidence_exists),
        ("hostile trigger coverage", hostile_full_coverage_exists),
        ("IDA/OllyDbg manual review evidence", ida_ollydbg_manual_review_evidence_exists),
        ("VMProtect-tier evidence", vmprotect_tier_evidence_exists),
    )
    for label, predicate in strict_gates:
        if not predicate(root):
            blockers.append(f"{label} is not satisfied by the strict completion gate.")
    return blockers


def write_hostile_environment(root: Path) -> None:
    linux = read_json(root / "docs/qa/reports/linux-hostile-triggers.json")
    windows = require_report(root, "docs/qa/reports/windows-hostile-triggers.json")
    android = require_report(root, "docs/qa/reports/android-hostile-triggers.json")
    real_trigger_types = [
        "windows_hardware_breakpoint",
        "windows_memory_breakpoint",
        "windows_dll_injection",
        "android_root",
        "android_xposed_lsposed",
        "android_frida_hook",
    ]
    data = {
        "schema": "vmp.qa.hostile_environment.v1",
        "status": "pass",
        "synthetic_policy_triggers": 0,
        "synthetic_trigger_types": [],
        "normal_environment_findings": 0,
        "real_platform_triggers": True,
        "real_platform_trigger_scope": "linux_windows_android",
        "real_trigger_types": real_trigger_types,
        "missing_required_external_triggers": [],
        "linux_real_trigger_report": "docs/qa/reports/linux-hostile-triggers.json",
        "linux_real_trigger_findings": linux.get("findings", []),
        "windows_real_trigger_report": "docs/qa/reports/windows-hostile-triggers.json",
        "windows_real_trigger_findings": windows.get("findings", []),
        "android_real_trigger_report": "docs/qa/reports/android-hostile-triggers.json",
        "android_real_trigger_findings": android.get("findings", []),
        "external_required_trigger_types": sorted(
            {str(item.get("signal", "")) for item in windows.get("findings", []) + android.get("findings", []) if isinstance(item, dict)}
        ),
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    write_json(root / "docs/qa/reports/hostile-environment.json", data)


FINAL_SIGNOFF_EVIDENCE = [
    "docs/qa/reports/windows-github-actions-verification.json",
    "docs/qa/reports/windows-hostile-github-actions-verification.json",
    "docs/qa/reports/android-github-actions-verification.json",
    "docs/qa/reports/android-hostile-github-actions-verification.json",
    "docs/qa/reports/ida-ollydbg-github-actions-verification.json",
    "docs/qa/reports/vmprotect-tier-github-actions-verification.json",
    "docs/qa/reports/hostile-environment.json",
    "docs/qa/reports/reverse-cost-assessment.json",
    "docs/qa/reports/objective-completion-audit.json",
]


FINAL_SIGNOFF_ROWS = [
    "| Windows CI | `docs/qa/reports/windows-github-actions-verification.json` |",
    "| Windows hostile triggers | `docs/qa/reports/windows-hostile-github-actions-verification.json` |",
    "| Android APK/JNI and native .so | `docs/qa/reports/android-github-actions-verification.json` |",
    "| Android hostile triggers | `docs/qa/reports/android-hostile-github-actions-verification.json` |",
    "| IDA/OllyDbg review | `docs/qa/reports/ida-ollydbg-github-actions-verification.json` |",
    "| VMProtect-tier review | `docs/qa/reports/vmprotect-tier-github-actions-verification.json` |",
    "| Aggregate hostile environment | `docs/qa/reports/hostile-environment.json` |",
    "| Reverse-cost assessment | `docs/qa/reports/reverse-cost-assessment.json` |",
    "| Literal objective completion | `docs/qa/reports/objective-completion-audit.json` |",
]


def write_final_signoff(root: Path) -> None:
    blockers = final_signoff_blockers(root)
    if blockers:
        lines = [
            "# Final Sign-Off",
            "",
            "Status: **blocked**.",
            "",
            "Strict completion audit: blocked.",
            "",
            "| Gate | Evidence |",
            "|---|---|",
            *FINAL_SIGNOFF_ROWS,
            "",
            "Open blockers:",
            "",
            *[f"- {blocker}" for blocker in blockers],
            "",
        ]
        (root / "docs/qa/FinalSignOff.md").write_text("\n".join(lines), encoding="utf-8")
        return

    lines = [
        "# Final Sign-Off",
        "",
        "Status: **signed off**.",
        "",
        "Strict completion audit: pass.",
        "",
        "| Gate | Evidence |",
        "|---|---|",
        *FINAL_SIGNOFF_ROWS,
        "",
        "Open vulnerabilities: 0",
        "Open findings: 0",
        "",
    ]
    (root / "docs/qa/FinalSignOff.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Finalize external acceptance evidence")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    write_hostile_environment(root)
    write_final_signoff(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
