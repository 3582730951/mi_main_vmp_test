#!/usr/bin/env python3
"""Validate external reverse-cost assessment evidence for final sign-off."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPORT_PATH = "docs/qa/reports/reverse-cost-assessment.json"
SCHEMA = "vmp.qa.reverse_cost_assessment.v1"
MINIMUM_REVERSE_COST_DAYS = 365
REQUIRED_CAPABILITIES = (
    "automatic_hotspot_analysis",
    "defense_floor_preserved",
    "callsite_obfuscation",
    "per_callsite_thunks",
    "protected_function_address_not_materialized",
    "decompiler_traps",
    "randomized_stack_backtrace",
)


def current_git_sha(root: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def is_sha1(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None


def validate_report(report: dict[str, Any], expected_sha: str | None = None) -> list[str]:
    errors: list[str] = []
    if report.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if report.get("status") != "pass":
        errors.append('status must be "pass"')
    if report.get("manual_review") is not True:
        errors.append("manual_review must be true")
    if not report.get("reviewer"):
        errors.append("reviewer must be present")
    if not report.get("methodology"):
        errors.append("methodology must be present")
    if not report.get("assessment_date"):
        errors.append("assessment_date must be present")
    if not isinstance(report.get("review_tools"), list) or not report["review_tools"]:
        errors.append("review_tools must be a non-empty list")

    days = report.get("minimum_reverse_cost_days")
    if not isinstance(days, int) or days < MINIMUM_REVERSE_COST_DAYS:
        errors.append(f"minimum_reverse_cost_days must be at least {MINIMUM_REVERSE_COST_DAYS}")

    github_sha = report.get("github_sha")
    if not is_sha1(github_sha):
        errors.append("github_sha must be a 40-character hex SHA")
    elif expected_sha is not None and github_sha.lower() != expected_sha.lower():
        errors.append("github_sha must match the current checked-out commit")

    artifact_sha = report.get("protected_artifact_sha256")
    if not isinstance(artifact_sha, str) or re.fullmatch(r"[0-9a-fA-F]{64}", artifact_sha) is None:
        errors.append("protected_artifact_sha256 must be a 64-character hex SHA-256")

    capabilities = report.get("assessed_capabilities")
    if not isinstance(capabilities, dict):
        errors.append("assessed_capabilities must be an object")
    else:
        for name in REQUIRED_CAPABILITIES:
            if capabilities.get(name) is not True:
                errors.append(f"assessed_capabilities.{name} must be true")

    return errors


def load_report(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--report", default=REPORT_PATH, help="assessment report path relative to root")
    parser.add_argument("--skip-current-sha", action="store_true", help="do not compare report SHA to git HEAD")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    report_path = root / args.report
    report = load_report(report_path)
    if report is None:
        print(f"reverse cost gate failed: missing or invalid JSON report: {args.report}", file=sys.stderr)
        return 1

    expected_sha = None if args.skip_current_sha else current_git_sha(root)
    errors = validate_report(report, expected_sha)
    if errors:
        print("reverse cost gate failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"reverse cost gate passed: minimum_reverse_cost_days={report['minimum_reverse_cost_days']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
