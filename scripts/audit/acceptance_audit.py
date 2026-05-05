#!/usr/bin/env python3
"""Automated acceptance audit for QA-owned checks.

The audit intentionally skips reading passwd.txt. It scans every other text file
for obvious secret hygiene and policy violations, checks QA task coverage, and
reports deterministic summary counts for the three-run gate.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import importlib.util
import json
import os
import re
import subprocess
import sys
import traceback
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


TASK_RE = re.compile(r"\|\s*(T\d{3})\s*\|([^|]*)\|")
GITHUB_PAT_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
SENSITIVE_ASSIGN_RE = re.compile(
    r"(?i)\b(?:pat|token|password|passwd|secret|api[_-]?key)\b\s*[:=]\s*['\"]?([^\s'\"$][^\s'\"]{7,})"
)
SECRET_EXPR_RE = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
WORKFLOW_KEY_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*:")
SENSITIVE_KEY_PARTS = {"PAT", "TOKEN", "PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY"}
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
FORBIDDEN_PROTECTED_ARTIFACT_BYTES = (
    b"JNI_OnLoad",
    b"Java_",
    b"GetProcAddress",
    b"LoadLibrary",
    b"dlopen",
    b"dlsym",
    b"Authorization:",
    b"Bearer ",
    b"CRITICAL_AUTHZ_TOKEN_SAMPLE",
    b"https://license.sample.invalid",
    b"ANDROID_KEYSTORE_PASSWORD",
    b"IOS_CERTIFICATE_PASSWORD",
    b"PLATFORM_WINDOWS_SIGNING_PASSWORD",
)
TRUSTED_GITHUB_EVENTS = {"push", "workflow_dispatch", "schedule"}
MAX_GITHUB_RUN_AGE_DAYS = 30
EXPECTED_WORKFLOW_PATHS = {
    "platform-android": ".github/workflows/platform-android-plan.yml",
    "platform-windows": ".github/workflows/platform-windows.yml",
    "vmprotect-tier": ".github/workflows/vmprotect-tier.yml",
    "manual-review": ".github/workflows/manual-review.yml",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".codex",
    ".build",
    ".release-build",
    ".llvm-build",
    ".llvm-out",
    "__pycache__",
    ".pytest_cache",
    "CMakeFiles",
    "node_modules",
    "build",
    "dist",
}

TEXT_SUFFIXES = {
    "",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".java",
    ".kt",
    ".m",
    ".mm",
    ".swift",
    ".py",
    ".sh",
    ".ps1",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".cmake",
}


@dataclass(frozen=True)
class Finding:
    check: str
    path: str
    message: str


def iter_files(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            rel = path.relative_to(root)
            if rel.as_posix() == "passwd.txt":
                continue
            yield path


def read_text(path: Path) -> str | None:
    if path.suffix not in TEXT_SUFFIXES:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="ignore")


def read_json_report(root: Path, relative_path: str) -> dict[str, object]:
    path = root / relative_path
    if path.name == "passwd.txt":
        raise RuntimeError("acceptance audit must not read passwd.txt")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def is_sha1_hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{40}", value) is not None


def sha256_file(path: Path) -> str:
    if path.name == "passwd.txt":
        raise RuntimeError("acceptance audit must not read passwd.txt")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch_github_run(repository: str, run_id: str, github_auth: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_auth}",
            "User-Agent": "vmp-acceptance-audit",
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
            "User-Agent": "vmp-acceptance-audit",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def download_github_artifact_zip(download_url: str, github_auth: str) -> bytes:
    request = urllib.request.Request(
        download_url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_auth}",
            "User-Agent": "vmp-acceptance-audit",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
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
    if verification.get("schema") != "vmp.qa.github_actions_verification.v1":
        return False
    if status not in {"pass", "provisional"} or verification.get("github_api_verified") is not True:
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
    event_name = verification.get("github_event_name")
    if not isinstance(event_name, str) or event_name not in TRUSTED_GITHUB_EVENTS:
        return False
    run_id = verification.get("github_run_id")
    repository = verification.get("github_repository")
    sha = verification.get("github_sha")
    run_url = verification.get("github_run_url")
    run_attempt = verification.get("github_run_attempt")
    ref_name = verification.get("github_ref_name")
    if not (isinstance(run_id, str) and run_id and isinstance(repository, str) and repository and is_sha1_hex(sha)):
        return False
    if not (isinstance(run_attempt, str) and run_attempt and isinstance(ref_name, str) and ref_name):
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
    if str(run.get("id")) != run_id or str(run.get("run_attempt")) != run_attempt:
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


def android_device_metadata_complete(report: dict[str, object]) -> bool:
    device = report.get("device")
    if not isinstance(device, dict):
        return False
    return all(isinstance(device.get(key), str) and device.get(key) for key in ("adb_serial", "abi", "build_fingerprint"))


def parse_plan_tasks(plan_path: Path) -> tuple[set[str], set[str]]:
    text = plan_path.read_text(encoding="utf-8")
    all_tasks: set[str] = set()
    qa_tasks: set[str] = set()
    for match in TASK_RE.finditer(text):
        task = match.group(1)
        row_tail = match.group(2)
        end = text.find("\n", match.end())
        row = text[match.start() : end if end != -1 else len(text)]
        all_tasks.add(task)
        if "qa_agent" in row or "qa_agent" in row_tail:
            qa_tasks.add(task)
    return all_tasks, qa_tasks


def check_task_coverage(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    plan_path = root / "plan" / "1.txt"
    acceptance_path = root / "docs" / "specs" / "Acceptance.md"
    qa_docs = sorted((root / "docs" / "qa").glob("**/*")) if (root / "docs" / "qa").exists() else []

    if not plan_path.exists():
        return [Finding("task_coverage", "plan/1.txt", "missing plan baseline")], {}
    if not acceptance_path.exists():
        findings.append(Finding("task_coverage", "docs/specs/Acceptance.md", "missing acceptance spec"))

    all_tasks, qa_tasks = parse_plan_tasks(plan_path)
    doc_text = ""
    for path in [acceptance_path, *qa_docs]:
        if path.is_file():
            doc_text += "\n" + (read_text(path) or "")

    missing = sorted(task for task in qa_tasks if task not in doc_text)
    for task in missing:
        findings.append(Finding("task_coverage", "docs/qa", f"missing QA task coverage for {task}"))

    return findings, {"plan_tasks": len(all_tasks), "qa_tasks": len(qa_tasks), "qa_tasks_missing": len(missing)}


def check_secret_hygiene(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    scanned = 0
    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        scanned += 1
        rel = path.relative_to(root).as_posix()
        if GITHUB_PAT_RE.search(text):
            findings.append(Finding("secrets", rel, "contains a GitHub PAT-like token"))
        if PRIVATE_KEY_RE.search(text):
            findings.append(Finding("secrets", rel, "contains a private key block"))
        for match in SENSITIVE_ASSIGN_RE.finditer(text):
            value = match.group(1)
            if value.startswith("${{") or value.startswith("$") or value.startswith("secrets."):
                continue
            if rel in {"plan/1.txt"} and "passwd.txt" in match.group(0):
                continue
            findings.append(Finding("secrets", rel, "contains a sensitive-looking literal assignment"))
            break
    return findings, {"text_files_scanned": scanned}


def check_workflows(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    workflow_root = root / ".github" / "workflows"
    workflows = sorted(workflow_root.glob("*.yml")) + sorted(workflow_root.glob("*.yaml")) if workflow_root.exists() else []
    for path in workflows:
        text = read_text(path) or ""
        lines = text.splitlines()
        rel = path.relative_to(root).as_posix()
        has_pull_request_trigger = bool(re.search(r"(?m)^\s*pull_request\s*:", text))
        if "permissions:" not in text or not re.search(r"(?m)^\s+contents:\s+read\s*$", text):
            findings.append(Finding("workflows", rel, "workflow must declare read-only contents permission"))
        if "passwd.txt" in text:
            findings.append(Finding("workflows", rel, "workflow references passwd.txt"))
        for line_no, line in enumerate(lines, start=1):
            key_match = WORKFLOW_KEY_RE.search(line)
            if not key_match:
                continue
            key = key_match.group(1).replace("-", "_").upper()
            key_parts = set(key.split("_"))
            is_sensitive = key in SENSITIVE_KEY_PARTS or bool(key_parts & SENSITIVE_KEY_PARTS)
            if not is_sensitive:
                continue
            if "github.token" in line:
                if not has_pull_request_trigger or workflow_secret_line_is_pr_guarded(lines, line_no - 1):
                    continue
                findings.append(Finding("workflows", rel, f"pull_request workflow github.token is not isolated from PR-controlled code on line {line_no}"))
                continue
            if "secrets." in line and SECRET_EXPR_RE.search(line):
                if has_pull_request_trigger and not workflow_secret_line_is_pr_guarded(lines, line_no - 1):
                    findings.append(Finding("workflows", rel, f"pull_request workflow secret is not isolated from PR-controlled code on line {line_no}"))
                continue
            if line.strip().startswith("#"):
                continue
            findings.append(Finding("workflows", rel, f"sensitive workflow reference is not backed by secrets.* on line {line_no}"))
    return findings, {"workflows_scanned": len(workflows)}


def workflow_secret_line_is_pr_guarded(lines: list[str], index: int) -> bool:
    start = max(0, index - 12)
    for line in reversed(lines[start : index + 1]):
        stripped = line.strip()
        if stripped.startswith("- name:"):
            return False
        if stripped.startswith("if:") and "github.event_name" in stripped and "pull_request" in stripped and "!=" in stripped:
            return True
    return False


def check_string_policy(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    acceptance = root / "docs" / "specs" / "Acceptance.md"
    text = read_text(acceptance) or ""
    required_terms = ["business-critical", "API names", "JNI names", "Authorization", "URLs", "key material"]
    for term in required_terms:
        if term not in text:
            findings.append(Finding("string_policy", acceptance.relative_to(root).as_posix(), f"missing string policy term: {term}"))

    artifact_dirs = [
        root / "build" / "release",
        root / "dist",
        root / "artifacts" / "protected",
        root / "samples" / "protected_chain" / "out",
    ]
    artifacts = [path for base in artifact_dirs if base.exists() for path in base.rglob("*") if path.is_file()]
    url_hits = 0
    forbidden_hits = 0
    if not artifacts:
        findings.append(Finding("string_policy", "samples/protected_chain/out", "no protected artifacts discovered for string scan"))
    for path in artifacts:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        matches = URL_RE.findall(data)
        if matches:
            url_hits += len(matches)
            findings.append(Finding("string_policy", path.relative_to(root).as_posix(), "contains plaintext URL-like strings"))
        for needle in FORBIDDEN_PROTECTED_ARTIFACT_BYTES:
            if needle in data:
                forbidden_hits += 1
                findings.append(
                    Finding(
                        "string_policy",
                        path.relative_to(root).as_posix(),
                        f"contains forbidden protected-artifact marker: {needle.decode('ascii', errors='ignore')}",
                    )
                )
    return findings, {
        "protected_artifacts_scanned": len(artifacts),
        "protected_url_hits": url_hits,
        "protected_forbidden_string_hits": forbidden_hits,
    }


def check_available_tests(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    qa_tests = sorted((root / "tests" / "qa").glob("test_*.py")) if (root / "tests" / "qa").exists() else []
    anti_analysis_tests = (
        sorted((root / "tests" / "anti_analysis").glob("test_*.py"))
        if (root / "tests" / "anti_analysis").exists()
        else []
    )
    audit_scripts = sorted((root / "scripts" / "audit").glob("*.py")) if (root / "scripts" / "audit").exists() else []
    if not qa_tests:
        findings.append(Finding("tests", "tests/qa", "no QA tests discovered"))
    if not anti_analysis_tests:
        findings.append(Finding("tests", "tests/anti_analysis", "no anti-analysis tests discovered"))
    if not audit_scripts:
        findings.append(Finding("tests", "scripts/audit", "no audit scripts discovered"))
    return findings, {
        "qa_tests": len(qa_tests),
        "anti_analysis_tests": len(anti_analysis_tests),
        "audit_scripts": len(audit_scripts),
    }


def check_performance_report(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    report_path = root / "docs" / "qa" / "reports" / "performance-sample.json"
    if not report_path.exists():
        return [Finding("performance", "docs/qa/reports/performance-sample.json", "missing sample performance report")], {
            "performance_reports": 0
        }
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding("performance", report_path.relative_to(root).as_posix(), f"invalid JSON performance report: {error}")], {
            "performance_reports": 1
        }

    required = {
        "schema": "vmp.sample.performance.v1",
        "status": "pass",
        "defense_priority": True,
    }
    for key, expected in required.items():
        if report.get(key) != expected:
            findings.append(Finding("performance", report_path.relative_to(root).as_posix(), f"unexpected {key} value"))
    for key in ("iterations", "baseline_ns", "protected_ns", "overhead_ratio", "artifact_bytes"):
        value = report.get(key)
        if not isinstance(value, (int, float)) or value <= 0:
            findings.append(Finding("performance", report_path.relative_to(root).as_posix(), f"missing positive {key}"))
    return findings, {"performance_reports": 1}


def check_capability_matrix(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    report_path = root / "docs" / "qa" / "reports" / "capability-matrix.json"
    if not report_path.exists():
        return [Finding("capability", "docs/qa/reports/capability-matrix.json", "missing capability matrix")], {
            "capability_reports": 0
        }
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding("capability", report_path.relative_to(root).as_posix(), f"invalid JSON capability matrix: {error}")], {
            "capability_reports": 1
        }
    if report.get("schema") != "vmp.qa.capability_matrix.v1":
        findings.append(Finding("capability", report_path.relative_to(root).as_posix(), "unexpected capability matrix schema"))
    if report.get("final_signoff_allowed") is not False:
        findings.append(Finding("capability", report_path.relative_to(root).as_posix(), "capability matrix must not allow final sign-off while hard blockers remain"))
    capabilities = report.get("capabilities")
    if not isinstance(capabilities, list) or len(capabilities) < 8:
        findings.append(Finding("capability", report_path.relative_to(root).as_posix(), "capability matrix is incomplete"))
    return findings, {"capability_reports": 1}


def check_hostile_environment_report(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    report_path = root / "docs" / "qa" / "reports" / "hostile-environment.json"
    if not report_path.exists():
        return [Finding("hostile_environment", "docs/qa/reports/hostile-environment.json", "missing hostile environment report")], {
            "hostile_reports": 0
        }
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding("hostile_environment", report_path.relative_to(root).as_posix(), f"invalid JSON hostile report: {error}")], {
            "hostile_reports": 1
        }
    if report.get("schema") != "vmp.qa.hostile_environment.v1":
        findings.append(Finding("hostile_environment", report_path.relative_to(root).as_posix(), "unexpected hostile report schema"))
    if report.get("status") != "blocked":
        findings.append(Finding("hostile_environment", report_path.relative_to(root).as_posix(), "hostile report must remain blocked until all real platform triggers exist"))
    allowed_scopes = {
        "partial_linux",
        "partial_linux_windows_controlled",
        "partial_linux_android",
        "partial_linux_windows_controlled_android",
    }
    if report.get("real_platform_trigger_scope") not in allowed_scopes:
        findings.append(Finding("hostile_environment", report_path.relative_to(root).as_posix(), "expected partial Linux-only or Linux-plus-controlled-Windows trigger scope"))
    if not report.get("linux_real_trigger_findings"):
        findings.append(Finding("hostile_environment", report_path.relative_to(root).as_posix(), "missing Linux real trigger findings"))
    linux_path = root / "docs" / "qa" / "reports" / "linux-hostile-triggers.json"
    try:
        linux_report = json.loads(linux_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        findings.append(Finding("hostile_environment", linux_path.relative_to(root).as_posix(), f"invalid Linux hostile trigger report: {error}"))
        linux_report = {}
    linux_signals = {str(finding.get("signal", "")) for finding in linux_report.get("findings", []) if isinstance(finding, dict)}
    for required_signal in {"ld_preload_module_mapped", "tracer_pid_nonzero"}:
        if required_signal not in linux_signals:
            findings.append(Finding("hostile_environment", linux_path.relative_to(root).as_posix(), f"missing Linux trigger signal {required_signal}"))
    if linux_report.get("normal_environment_findings") != 0:
        findings.append(Finding("hostile_environment", linux_path.relative_to(root).as_posix(), "Linux baseline controls must not produce findings"))
    baseline_controls = linux_report.get("baseline_controls")
    if not isinstance(baseline_controls, dict):
        findings.append(Finding("hostile_environment", linux_path.relative_to(root).as_posix(), "missing Linux baseline controls"))
    else:
        for control_name in ("ld_preload", "tracer"):
            control = baseline_controls.get(control_name)
            if not isinstance(control, dict):
                findings.append(Finding("hostile_environment", linux_path.relative_to(root).as_posix(), f"missing Linux baseline control {control_name}"))
                continue
            if control.get("present") is not False:
                findings.append(Finding("hostile_environment", linux_path.relative_to(root).as_posix(), f"Linux baseline control {control_name} unexpectedly triggered"))
    if linux_report.get("baseline_findings") != []:
        findings.append(Finding("hostile_environment", linux_path.relative_to(root).as_posix(), "Linux baseline findings must be empty"))
    android_path = root / "docs" / "qa" / "reports" / "android-hostile-triggers.json"
    try:
        android_report = json.loads(android_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        android_report = {}
    android_missing = {
        str(item)
        for item in android_report.get(
            "missing_required_triggers",
            ["root_trigger_device_or_image", "xposed_or_lsposed_trigger", "frida_or_hook_trigger"],
        )
    }
    android_report_passed = (
        android_report.get("status") == "pass"
        and not android_missing
        and android_report.get("ci_execution") is True
        and android_report.get("github_actions") is True
        and android_report.get("github_workflow") == "platform-android"
        and android_report.get("authorized_hostile_profile") is True
        and bool(android_report.get("hostile_profile_id"))
        and android_device_metadata_complete(android_report)
    )
    android_report_passed = android_report_passed and github_actions_verification_matches(
        root,
        "docs/qa/reports/android-hostile-github-actions-verification.json",
        [android_report],
        ["docs/qa/reports/android-hostile-triggers.json"],
        expected_workflow="platform-android",
    )
    if android_report.get("status") == "pass" and not android_report_passed:
        findings.append(Finding("hostile_environment", android_path.relative_to(root).as_posix(), "Android hostile trigger pass report must include trusted GitHub verification sidecar and device metadata"))
    if report.get("android_real_trigger_findings") and {"xposed_or_lsposed_trigger", "frida_or_hook_trigger"} & android_missing:
        findings.append(Finding("hostile_environment", report_path.relative_to(root).as_posix(), "Android baseline findings must not be reported as real Android hostile-hook coverage"))
    android_real_findings = report.get("android_real_trigger_findings")
    if android_real_findings:
        if not isinstance(android_real_findings, list):
            findings.append(Finding("hostile_environment", report_path.relative_to(root).as_posix(), "Android real trigger findings must be a list"))
            android_real_findings = []
        if not android_report_passed:
            findings.append(Finding("hostile_environment", android_path.relative_to(root).as_posix(), "Android real trigger findings require android-hostile-triggers status pass with no missing required triggers"))
        android_signals = {
            str(finding.get("signal", "")).lower()
            for finding in android_real_findings
            if isinstance(finding, dict)
        }
        android_categories = {
            str(finding.get("category", "")).lower()
            for finding in android_real_findings
            if isinstance(finding, dict)
        }
        has_root = "root" in android_categories
        has_xposed = any(marker in signal for signal in android_signals for marker in ("xposed", "lsposed", "edxposed", "zygisk"))
        has_frida = any(marker in signal for signal in android_signals for marker in ("frida", "hook"))
        if not (has_root and has_xposed and has_frida):
            findings.append(Finding("hostile_environment", report_path.relative_to(root).as_posix(), "Android real trigger findings must include root, Xposed/LSPosed, and Frida/hook evidence"))
    if "android" in str(report.get("real_platform_trigger_scope", "")) and not android_real_findings:
        findings.append(Finding("hostile_environment", report_path.relative_to(root).as_posix(), "Android trigger scope cannot be claimed without real Android trigger findings"))
    return findings, {"hostile_reports": 1}


def check_release_binary_report(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    report_path = root / "docs" / "qa" / "reports" / "release-protected-binary.json"
    if not report_path.exists():
        return [Finding("release_binary", "docs/qa/reports/release-protected-binary.json", "missing release protected binary report")], {
            "release_binary_reports": 0
        }
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding("release_binary", report_path.relative_to(root).as_posix(), f"invalid JSON release report: {error}")], {
            "release_binary_reports": 1
        }
    if report.get("schema") != "vmp.release.protected_binary.v1":
        findings.append(Finding("release_binary", report_path.relative_to(root).as_posix(), "unexpected release report schema"))
    if report.get("status") != "pass":
        findings.append(Finding("release_binary", report_path.relative_to(root).as_posix(), "release protected binary report did not pass"))
    if report.get("forbidden_plaintext_hits") != []:
        findings.append(Finding("release_binary", report_path.relative_to(root).as_posix(), "release binary contains forbidden plaintext"))
    if report.get("behavior_cases_passed") != 4:
        findings.append(Finding("release_binary", report_path.relative_to(root).as_posix(), "release binary behavior cases did not pass"))
    return findings, {"release_binary_reports": 1}


def check_surface_minimization_report(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    report_path = root / "docs" / "qa" / "reports" / "surface-minimization.json"
    if not report_path.exists():
        return [Finding("surface_minimization", "docs/qa/reports/surface-minimization.json", "missing surface minimization report")], {
            "surface_reports": 0
        }
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding("surface_minimization", report_path.relative_to(root).as_posix(), f"invalid JSON surface report: {error}")], {
            "surface_reports": 1
        }
    if report.get("schema") != "vmp.qa.surface_minimization.v1":
        findings.append(Finding("surface_minimization", report_path.relative_to(root).as_posix(), "unexpected surface report schema"))
    if report.get("status") != "pass":
        findings.append(Finding("surface_minimization", report_path.relative_to(root).as_posix(), "surface minimization report did not pass"))
    if report.get("avoidable_surface_findings") != 0:
        findings.append(Finding("surface_minimization", report_path.relative_to(root).as_posix(), "avoidable protected-surface markers remain"))
    syscall_policy = report.get("syscall_policy", {})
    if not isinstance(syscall_policy, dict) or not syscall_policy.get("status"):
        findings.append(Finding("surface_minimization", report_path.relative_to(root).as_posix(), "missing syscall policy declaration"))
    return findings, {"surface_reports": 1}


def check_protected_callgraph_report(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    report_path = root / "docs" / "qa" / "reports" / "protected-callgraph.json"
    if not report_path.exists():
        return [Finding("protected_callgraph", "docs/qa/reports/protected-callgraph.json", "missing protected callgraph report")], {
            "protected_callgraph_reports": 0
        }
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [Finding("protected_callgraph", report_path.relative_to(root).as_posix(), f"invalid JSON callgraph report: {error}")], {
            "protected_callgraph_reports": 1
        }
    if report.get("schema") != "vmp.qa.protected_callgraph.v1":
        findings.append(Finding("protected_callgraph", report_path.relative_to(root).as_posix(), "unexpected protected callgraph schema"))
    if report.get("status") != "pass":
        findings.append(Finding("protected_callgraph", report_path.relative_to(root).as_posix(), "protected callgraph report did not pass"))
    analysis = report.get("analysis", {})
    if not isinstance(analysis, dict):
        findings.append(Finding("protected_callgraph", report_path.relative_to(root).as_posix(), "missing protected callgraph analysis"))
    else:
        for key in (
            "protected_xrefs_discovered",
            "direct_protected_xrefs_removed",
            "high_frequency_policy_applied",
            "defense_floor_preserved",
            "per_callsite_thunks_preserved",
        ):
            if analysis.get(key) is not True:
                findings.append(Finding("protected_callgraph", report_path.relative_to(root).as_posix(), f"analysis.{key} must be true"))
    return findings, {"protected_callgraph_reports": 1}


def run_once(root: Path) -> dict[str, object]:
    checks = [
        check_task_coverage,
        check_secret_hygiene,
        check_workflows,
        check_string_policy,
        check_available_tests,
        check_performance_report,
        check_capability_matrix,
        check_hostile_environment_report,
        check_release_binary_report,
        check_surface_minimization_report,
        check_protected_callgraph_report,
    ]
    findings: list[Finding] = []
    metrics: dict[str, int] = {}
    for check in checks:
        check_findings, check_metrics = check(root)
        findings.extend(check_findings)
        metrics.update(check_metrics)
    return {
        "status": "pass" if not findings else "fail",
        "metrics": metrics,
        "findings": [finding.__dict__ for finding in findings],
    }


def run_tests(root: Path) -> int:
    if not (root / "tests" / "qa").exists():
        return 1
    qa_status = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests/qa"],
        cwd=root,
        check=False,
    ).returncode
    anti_analysis_status = run_function_tests(root, root / "tests" / "anti_analysis")
    return 1 if qa_status != 0 or anti_analysis_status != 0 else 0


def run_function_tests(root: Path, test_dir: Path) -> int:
    """Run simple pytest-style test functions without requiring pytest."""
    if not test_dir.exists():
        print(f"missing test directory: {test_dir.relative_to(root).as_posix()}", file=sys.stderr)
        return 1

    sys.path.insert(0, str(root / "src"))
    sys.path.insert(0, str(root))
    failures = 0
    executed = 0

    for path in sorted(test_dir.glob("test_*.py")):
        module_name = f"_acceptance_audit_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            print(f"could not load {path.relative_to(root).as_posix()}", file=sys.stderr)
            failures += 1
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception:
            print(f"failed importing {path.relative_to(root).as_posix()}", file=sys.stderr)
            traceback.print_exc()
            failures += 1
            continue

        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            fn = getattr(module, name)
            if not callable(fn):
                continue
            executed += 1
            try:
                fn()
            except Exception:
                print(f"failed {path.relative_to(root).as_posix()}::{name}", file=sys.stderr)
                traceback.print_exc()
                failures += 1

    print(f"anti-analysis function tests: {executed} run")
    return 1 if failures or executed == 0 else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run automated QA acceptance audit")
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--runs", type=int, default=1, help="repeat audit count")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument("--tests", action="store_true", help="run tests/qa after audit")
    parser.add_argument("--pytest", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    reports = [run_once(root) for _ in range(args.runs)]
    first_metrics = reports[0]["metrics"] if reports else {}
    deterministic = all(report["metrics"] == first_metrics for report in reports)
    if not deterministic:
        reports.append({
            "status": "fail",
            "metrics": {},
            "findings": [{"check": "determinism", "path": ".", "message": "audit metrics changed between runs"}],
        })

    if args.json:
        print(json.dumps({"runs": reports}, indent=2, sort_keys=True))
    else:
        for index, report in enumerate(reports, start=1):
            print(f"run {index}: {report['status']} {report['metrics']}")
            for finding in report["findings"]:
                print(f"  {finding['check']}: {finding['path']}: {finding['message']}")

    audit_failed = any(report["status"] != "pass" for report in reports) or not deterministic
    test_failed = False
    if args.tests or args.pytest:
        test_failed = run_tests(root) != 0
    return 1 if audit_failed or test_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
