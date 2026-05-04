#!/usr/bin/env python3
"""Generate a defensive hostile-environment validation report.

The report intentionally separates synthetic policy trigger coverage from real
platform trigger evidence. Synthetic coverage is useful for local regression,
but it does not satisfy the hard acceptance requirement by itself.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from anti_analysis import PassiveEnvironmentDetector  # noqa: E402


def load_linux_real_trigger_report() -> dict[str, object] | None:
    path = ROOT / "docs/qa/reports/linux-hostile-triggers.json"
    if not path.exists():
        subprocess.run([sys.executable, str(ROOT / "tests/platform/linux_hostile_trigger_report.py"), str(path)], check=False)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def load_windows_real_trigger_report() -> dict[str, object] | None:
    path = ROOT / "docs/qa/reports/windows-hostile-triggers.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def load_android_real_trigger_report() -> dict[str, object] | None:
    path = ROOT / "docs/qa/reports/android-hostile-triggers.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def finding_json(finding) -> dict[str, object]:
    return {
        "category": finding.category.value,
        "severity": finding.severity.value,
        "signal": finding.signal,
        "source": finding.source,
        "confidence": finding.confidence,
        "action": finding.action,
        "details": dict(finding.details),
    }


def android_required_trigger_coverage(report: dict[str, object] | None) -> bool:
    if not report:
        return False
    if report.get("status") != "pass":
        return False
    if report.get("ci_execution") is not True or report.get("github_actions") is not True:
        return False
    if report.get("authorized_hostile_profile") is not True or not report.get("hostile_profile_id"):
        return False
    required_missing = {
        str(item)
        for item in report.get(
            "missing_required_triggers",
            ["root_trigger_device_or_image", "xposed_or_lsposed_trigger", "frida_or_hook_trigger"],
        )
    }
    if required_missing:
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


def main() -> int:
    out = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "docs/qa/reports/hostile-environment.json")
    out.parent.mkdir(parents=True, exist_ok=True)

    detector = PassiveEnvironmentDetector()
    hostile_observations = (
        detector.debugger_stub("debugger_attached", True, "synthetic_windows", 0.95),
        detector.hardware_breakpoint_stub("external_dr_register", True, "synthetic_windows", 0.90),
        detector.memory_breakpoint_stub("guard_page_breakpoint", True, "synthetic_windows", 0.90),
        detector.injection_stub("unexpected_module", True, "synthetic_windows", 0.90),
        detector.injection_stub("ld_preload_module", True, "synthetic_linux", 0.90),
        detector.root_stub("root_indicator", True, "synthetic_android", 0.90),
        detector.hook_stub("xposed_or_frida_indicator", True, "synthetic_android", 0.90),
    )
    normal_observations = (
        detector.debugger_stub("debugger_attached", False, "synthetic_normal", 1.0),
        detector.injection_stub("unexpected_module", False, "synthetic_normal", 1.0),
        detector.root_stub("root_indicator", False, "synthetic_normal", 1.0),
        detector.hook_stub("xposed_or_frida_indicator", False, "synthetic_normal", 1.0),
    )

    hostile_findings = detector.evaluate(hostile_observations)
    normal_findings = detector.evaluate(normal_observations)
    linux_real = load_linux_real_trigger_report()
    linux_real_findings = linux_real.get("findings", []) if linux_real else []
    windows_real = load_windows_real_trigger_report()
    windows_real_findings = windows_real.get("findings", []) if windows_real else []
    android_real = load_android_real_trigger_report()
    android_baseline_findings = android_real.get("findings", []) if android_real else []
    android_required_complete = android_required_trigger_coverage(android_real)
    android_real_findings = android_baseline_findings if android_required_complete else []
    android_real_trigger_types = (
        ["android_root", "android_xposed_lsposed", "android_frida_hook"] if android_required_complete else []
    )
    real_parts = []
    if linux_real_findings:
        real_parts.append("linux")
    if windows_real_findings:
        real_parts.append("windows_controlled")
    if android_real_findings:
        real_parts.append("android")
    real_scope = "partial_" + "_".join(real_parts) if real_parts else "none"
    data = {
        "schema": "vmp.qa.hostile_environment.v1",
        "status": "blocked",
        "synthetic_policy_triggers": len(hostile_findings),
        "synthetic_trigger_types": sorted({finding.signal for finding in hostile_findings}),
        "normal_environment_findings": len(normal_findings),
        "real_platform_triggers": bool(linux_real_findings or windows_real_findings or android_real_findings),
        "real_platform_trigger_scope": real_scope,
        "local_controlled_trigger_types": sorted(
            {str(finding.get("signal", "")) for finding in linux_real_findings + windows_real_findings if finding.get("signal")}
        ),
        "external_required_trigger_types": sorted(
            {str(finding.get("signal", "")) for finding in android_real_findings if finding.get("signal")}
        ),
        "real_trigger_types": android_real_trigger_types,
        "missing_required_external_triggers": [
            "windows_hardware_breakpoint",
            "windows_memory_breakpoint",
            "windows_dll_injection",
        ] + ([] if android_required_complete else ["android_root", "android_xposed_lsposed", "android_frida_hook"]),
        "synthetic_policy_findings": [finding_json(finding) for finding in hostile_findings],
        "linux_real_trigger_report": "docs/qa/reports/linux-hostile-triggers.json" if linux_real else None,
        "linux_real_trigger_findings": linux_real_findings,
        "windows_real_trigger_report": "docs/qa/reports/windows-hostile-triggers.json" if windows_real else None,
        "windows_real_trigger_findings": windows_real_findings,
        "android_real_trigger_report": "docs/qa/reports/android-hostile-triggers.json" if android_real else None,
        "android_real_trigger_findings": android_real_findings,
        "android_baseline_probe_report": "docs/qa/reports/android-hostile-triggers.json" if android_real else None,
        "android_baseline_trigger_findings": android_baseline_findings,
        "covered_categories": sorted({finding.category.value for finding in hostile_findings}),
        "blocking_note": "Synthetic policy triggers, Linux local probes, optional controlled Windows reports when present, and Android emulator baseline probes do not satisfy hard acceptance; external Windows hardware breakpoint/DLL injection and Android root/Xposed/LSPosed/Frida/hook trigger reports are still required.",
    }
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("hostile environment report written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
