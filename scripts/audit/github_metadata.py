"""Shared GitHub Actions metadata helpers for evidence reports."""

from __future__ import annotations

import os


def current_run_url() -> str | None:
    server = os.environ.get("GITHUB_SERVER_URL")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if not (server and repository and run_id):
        return None
    return f"{server}/{repository}/actions/runs/{run_id}"


def current_github_metadata() -> dict[str, object]:
    return {
        "ci_execution": os.environ.get("GITHUB_ACTIONS") == "true",
        "github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "github_workflow": os.environ.get("GITHUB_WORKFLOW"),
        "github_repository": os.environ.get("GITHUB_REPOSITORY"),
        "github_sha": os.environ.get("GITHUB_SHA"),
        "github_event_name": os.environ.get("GITHUB_EVENT_NAME"),
        "github_ref": os.environ.get("GITHUB_REF"),
        "github_ref_name": os.environ.get("GITHUB_REF_NAME"),
        "github_ref_protected": os.environ.get("GITHUB_REF_PROTECTED"),
        "github_run_url": current_run_url(),
        "runner_os": os.environ.get("RUNNER_OS"),
        "runner_name": os.environ.get("RUNNER_NAME"),
    }
