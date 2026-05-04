#!/usr/bin/env python3
"""Verify imported GitHub Actions evidence against the GitHub run API.

This script never reads passwd.txt. It is intended to run inside a trusted
GitHub Actions job with GITHUB_TOKEN available, then emit a sidecar report that
the strict completion audit can require before accepting platform evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


TRUSTED_GITHUB_EVENTS = {"push", "workflow_dispatch", "schedule"}
MAX_GITHUB_RUN_AGE_DAYS = 30
CURRENT_RUN_ENV = (
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_REPOSITORY",
    "GITHUB_SHA",
    "GITHUB_EVENT_NAME",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_PROTECTED",
    "GITHUB_WORKFLOW",
)


def read_json(path: Path) -> dict[str, object]:
    if path.name == "passwd.txt":
        raise RuntimeError("must not read passwd.txt")
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    if path.name == "passwd.txt":
        raise RuntimeError("must not read passwd.txt")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_report(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fetch_run(repository: str, run_id: str, github_auth: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_auth}",
            "User-Agent": "vmp-evidence-verifier",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def current_github_run() -> dict[str, str]:
    return {key: os.environ.get(key, "") for key in CURRENT_RUN_ENV}


def current_run_url(metadata: dict[str, str]) -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{metadata['GITHUB_REPOSITORY']}/actions/runs/{metadata['GITHUB_RUN_ID']}"


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify GitHub Actions evidence provenance")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="docs/qa/reports/windows-github-actions-verification.json")
    parser.add_argument("--expected-workflow", help="required GitHub Actions workflow name")
    parser.add_argument("--expected-workflow-path", help="required .github/workflows path for the run")
    parser.add_argument("--artifact-name", help="GitHub Actions artifact name that will contain the reports and sidecar")
    parser.add_argument("reports", nargs="+", help="JSON reports that must share the same GitHub run")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output = root / args.output
    report_paths = [root / item for item in args.reports]
    try:
        reports = [read_json(path) for path in report_paths]
    except (OSError, json.JSONDecodeError, RuntimeError) as error:
        write_report(output, {
            "schema": "vmp.qa.github_actions_verification.v1",
            "status": "blocked",
            "github_api_verified": False,
            "blocking_note": f"could not read evidence reports: {error}",
        })
        return 2

    first = reports[0] if reports else {}
    metadata = current_github_run()
    run_id = metadata["GITHUB_RUN_ID"]
    run_attempt = metadata["GITHUB_RUN_ATTEMPT"]
    repository = metadata["GITHUB_REPOSITORY"]
    sha = metadata["GITHUB_SHA"]
    event_name = metadata["GITHUB_EVENT_NAME"]
    github_auth = os.environ.get("GITHUB_TOKEN")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        write_report(output, {
            "schema": "vmp.qa.github_actions_verification.v1",
            "status": "blocked",
            "github_api_verified": False,
            "github_actions_runtime": False,
            "blocking_note": "Final platform evidence verification must run inside GitHub Actions.",
        })
        return 3
    if not (run_id and run_attempt and repository and sha and event_name and github_auth):
        write_report(output, {
            "schema": "vmp.qa.github_actions_verification.v1",
            "status": "blocked",
            "github_api_verified": False,
            "github_run_id": first.get("github_run_id"),
            "github_repository": first.get("github_repository"),
            "blocking_note": "GITHUB_TOKEN and current GITHUB_RUN_ID/GITHUB_RUN_ATTEMPT/GITHUB_REPOSITORY/GITHUB_SHA/GITHUB_EVENT_NAME are required for live API verification.",
        })
        return 3
    if event_name not in TRUSTED_GITHUB_EVENTS:
        write_report(output, {
            "schema": "vmp.qa.github_actions_verification.v1",
            "status": "blocked",
            "github_api_verified": False,
            "github_run_id": run_id,
            "github_repository": repository,
            "github_sha": sha,
            "github_event_name": event_name,
            "allowed_events": sorted(TRUSTED_GITHUB_EVENTS),
            "blocking_note": "pull_request and other untrusted events cannot produce final platform evidence.",
        })
        return 3

    try:
        run = fetch_run(repository, run_id, github_auth)
    except Exception as error:  # pragma: no cover - network error shape depends on runner
        write_report(output, {
            "schema": "vmp.qa.github_actions_verification.v1",
            "status": "blocked",
            "github_api_verified": False,
            "github_run_id": run_id,
            "github_repository": repository,
            "blocking_note": f"GitHub Actions API verification failed: {error}",
        })
        return 4

    expected = {
        "github_run_id": str(run.get("id")),
        "github_run_attempt": str(run.get("run_attempt")),
        "github_repository": repository,
        "github_sha": run.get("head_sha"),
        "github_event_name": run.get("event"),
        "github_run_url": run.get("html_url"),
    }
    mismatches: list[str] = []
    current_expected = {
        "github_run_id": run_id,
        "github_run_attempt": run_attempt,
        "github_repository": repository,
        "github_sha": sha,
        "github_event_name": event_name,
        "github_run_url": current_run_url(metadata),
    }
    for key, expected_value in current_expected.items():
        if str(expected.get(key)) != str(expected_value):
            mismatches.append(f"current_run:{key}")
    if metadata["GITHUB_WORKFLOW"] and str(run.get("name")) != metadata["GITHUB_WORKFLOW"]:
        mismatches.append("current_run:github_workflow")
    for report, path in zip(reports, report_paths):
        rel_path = path.relative_to(root).as_posix()
        for key, expected_value in expected.items():
            if str(report.get(key)) != str(expected_value):
                mismatches.append(f"{rel_path}:{key}")
        if args.expected_workflow and report.get("github_workflow") != args.expected_workflow:
            mismatches.append(f"{rel_path}:github_workflow")
        if report.get("github_workflow") and report.get("github_workflow") != run.get("name"):
            mismatches.append(f"{rel_path}:github_workflow")
        for key in ("github_ref", "github_ref_name", "github_ref_protected"):
            expected_value = metadata.get(key.upper())
            if expected_value and str(report.get(key)) != str(expected_value):
                mismatches.append(f"{rel_path}:{key}")

    head_repository = run.get("head_repository")
    head_repository_name = head_repository.get("full_name") if isinstance(head_repository, dict) else None
    pull_requests = run.get("pull_requests", [])
    ref_name = metadata["GITHUB_REF_NAME"]
    ref_ok = bool(ref_name) and (run.get("head_branch") in (None, ref_name))
    protected_ref_ok = metadata["GITHUB_REF_PROTECTED"] == "true"
    if head_repository_name and head_repository_name != repository:
        mismatches.append("api:head_repository")
    if not ref_ok:
        mismatches.append("api:head_branch")
    if pull_requests != []:
        mismatches.append("api:pull_requests")
    if not protected_ref_ok:
        mismatches.append("current_run:github_ref_protected")
    workflow_path = run.get("path")
    if args.expected_workflow and run.get("name") != args.expected_workflow:
        mismatches.append("api:github_workflow")
    if args.expected_workflow_path:
        if workflow_path != args.expected_workflow_path:
            mismatches.append("api:workflow_path")
    elif workflow_path and not str(workflow_path).startswith(".github/workflows/"):
        mismatches.append("api:workflow_path")
    run_created_at = run.get("created_at") or run.get("run_started_at")
    run_created = parse_github_timestamp(run_created_at)
    verified_at = datetime.now(timezone.utc)
    max_age_seconds = MAX_GITHUB_RUN_AGE_DAYS * 24 * 60 * 60
    if run_created is None:
        mismatches.append("api:created_at")
    elif (verified_at - run_created).total_seconds() > max_age_seconds:
        mismatches.append("api:run_age")

    event_ok = run.get("event") in TRUSTED_GITHUB_EVENTS
    run_status = run.get("status")
    run_conclusion = run.get("conclusion")
    current_run_status_ok = run_status in {"queued", "in_progress", "completed"}
    completed_successfully = run_status == "completed" and run_conclusion == "success"
    metadata_ok = current_run_status_ok and event_ok and not mismatches
    status_ok = completed_successfully and metadata_ok
    report_sha256 = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in report_paths
    }
    if run_status != "completed" and not mismatches:
        mismatches.append("api:run_not_completed")
    write_report(output, {
        "schema": "vmp.qa.github_actions_verification.v1",
        "status": "pass" if status_ok else ("provisional" if metadata_ok else "blocked"),
        "github_api_verified": metadata_ok,
        "github_actions_runtime": True,
        "github_run_id": run_id,
        "github_run_attempt": run_attempt,
        "github_repository": repository,
        "github_sha": run.get("head_sha"),
        "github_event_name": run.get("event"),
        "github_ref": metadata["GITHUB_REF"],
        "github_ref_name": metadata["GITHUB_REF_NAME"],
        "github_ref_protected": protected_ref_ok,
        "github_run_url": run.get("html_url"),
        "github_workflow": run.get("name"),
        "head_branch": run.get("head_branch"),
        "head_repository": head_repository_name,
        "workflow_path": workflow_path,
        "pull_requests": pull_requests,
        "run_created_at": run_created_at,
        "run_status": run_status,
        "run_conclusion": run_conclusion,
        "final_run_revalidation_required": not status_ok,
        "verified_at_utc": verified_at.isoformat().replace("+00:00", "Z"),
        "max_run_age_days": MAX_GITHUB_RUN_AGE_DAYS,
        "allowed_events": sorted(TRUSTED_GITHUB_EVENTS),
        "expected_workflow": args.expected_workflow,
        "expected_workflow_path": args.expected_workflow_path,
        "artifact_name": args.artifact_name,
        "evidence_reports": [path.relative_to(root).as_posix() for path in report_paths],
        "report_sha256": report_sha256,
        "mismatches": mismatches,
    })
    return 0 if metadata_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
