import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts.audit import verify_github_actions_evidence


RUN_CREATED_AT = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
RUN_METADATA = {
    "github_run_id": "123456789",
    "github_run_attempt": "1",
    "github_run_url": "https://github.com/example/repo/actions/runs/123456789",
    "github_repository": "example/repo",
    "github_sha": "a" * 40,
    "github_workflow": "platform-android",
    "github_event_name": "workflow_dispatch",
    "github_ref": "refs/heads/main",
    "github_ref_name": "main",
    "github_ref_protected": "true",
}


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verifier_env(event_name: str = "workflow_dispatch") -> dict[str, str]:
    return {
        "GITHUB_TOKEN": "token-for-test",
        "GITHUB_ACTIONS": "true",
        "GITHUB_RUN_ID": RUN_METADATA["github_run_id"],
        "GITHUB_RUN_ATTEMPT": RUN_METADATA["github_run_attempt"],
        "GITHUB_REPOSITORY": RUN_METADATA["github_repository"],
        "GITHUB_SHA": RUN_METADATA["github_sha"],
        "GITHUB_EVENT_NAME": event_name,
        "GITHUB_REF": RUN_METADATA["github_ref"],
        "GITHUB_REF_NAME": RUN_METADATA["github_ref_name"],
        "GITHUB_REF_PROTECTED": RUN_METADATA["github_ref_protected"],
        "GITHUB_WORKFLOW": RUN_METADATA["github_workflow"],
        "GITHUB_SERVER_URL": "https://github.com",
    }


def api_run(event_name: str = "workflow_dispatch") -> dict[str, object]:
    return {
        "id": int(RUN_METADATA["github_run_id"]),
        "run_attempt": int(RUN_METADATA["github_run_attempt"]),
        "head_sha": RUN_METADATA["github_sha"],
        "event": event_name,
        "html_url": RUN_METADATA["github_run_url"],
        "status": "completed",
        "conclusion": "success",
        "name": RUN_METADATA["github_workflow"],
        "head_branch": RUN_METADATA["github_ref_name"],
        "head_repository": {"full_name": RUN_METADATA["github_repository"]},
        "pull_requests": [],
        "path": ".github/workflows/platform-android-plan.yml",
        "created_at": RUN_CREATED_AT,
    }


class GitHubActionsVerifierTests(unittest.TestCase):
    def run_verifier(self, root: Path, env: dict[str, str], fetched_run: dict[str, object]) -> int:
        argv = [
            "verify_github_actions_evidence.py",
            "--root",
            str(root),
            "--output",
            "docs/qa/reports/android-github-actions-verification.json",
            "--expected-workflow",
            "platform-android",
            "--expected-workflow-path",
            ".github/workflows/platform-android-plan.yml",
            "--artifact-name",
            "android-emulator-smoke-evidence",
            "docs/qa/reports/android-apk-smoke.json",
        ]
        with mock.patch.dict(os.environ, env, clear=True), \
            mock.patch.object(sys, "argv", argv), \
            mock.patch.object(verify_github_actions_evidence, "fetch_run", return_value=fetched_run):
            return verify_github_actions_evidence.main()

    def test_verifier_accepts_current_trusted_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "docs/qa/reports/android-apk-smoke.json", {
                "status": "pass",
                **RUN_METADATA,
            })

            code = self.run_verifier(root, verifier_env(), api_run())
            output = json.loads((root / "docs/qa/reports/android-github-actions-verification.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(output["status"], "pass")
        self.assertTrue(output["github_api_verified"])
        self.assertTrue(output["github_actions_runtime"])
        self.assertEqual(output["run_created_at"], RUN_CREATED_AT)
        self.assertEqual(output["max_run_age_days"], verify_github_actions_evidence.MAX_GITHUB_RUN_AGE_DAYS)
        self.assertEqual(output["expected_workflow"], "platform-android")
        self.assertEqual(output["expected_workflow_path"], ".github/workflows/platform-android-plan.yml")
        self.assertEqual(output["artifact_name"], "android-emulator-smoke-evidence")
        self.assertEqual(output["mismatches"], [])
        self.assertIn("docs/qa/reports/android-apk-smoke.json", output["report_sha256"])

    def test_verifier_emits_provisional_sidecar_for_current_in_progress_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "docs/qa/reports/android-apk-smoke.json", {
                "status": "pass",
                **RUN_METADATA,
            })
            run = api_run()
            run["status"] = "in_progress"
            run["conclusion"] = None

            code = self.run_verifier(root, verifier_env(), run)
            output = json.loads((root / "docs/qa/reports/android-github-actions-verification.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 0)
        self.assertEqual(output["status"], "provisional")
        self.assertTrue(output["github_api_verified"])
        self.assertTrue(output["final_run_revalidation_required"])
        self.assertEqual(output["mismatches"], ["api:run_not_completed"])

    def test_verifier_rejects_wrong_workflow_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "docs/qa/reports/android-apk-smoke.json", {
                "status": "pass",
                **RUN_METADATA,
            })
            run = api_run()
            run["path"] = ".github/workflows/unrelated.yml"

            code = self.run_verifier(root, verifier_env(), run)
            output = json.loads((root / "docs/qa/reports/android-github-actions-verification.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 1)
        self.assertEqual(output["status"], "blocked")
        self.assertIn("api:workflow_path", output["mismatches"])

    def test_verifier_rejects_pull_request_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = dict(RUN_METADATA)
            report["github_event_name"] = "pull_request"
            write_json(root / "docs/qa/reports/android-apk-smoke.json", {
                "status": "pass",
                **report,
            })

            code = self.run_verifier(root, verifier_env("pull_request"), api_run("pull_request"))
            output = json.loads((root / "docs/qa/reports/android-github-actions-verification.json").read_text(encoding="utf-8"))

        self.assertNotEqual(code, 0)
        self.assertEqual(output["status"], "blocked")
        self.assertFalse(output["github_api_verified"])

    def test_verifier_rejects_report_from_different_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stale = dict(RUN_METADATA)
            stale["github_run_id"] = "987654321"
            stale["github_run_url"] = "https://github.com/example/repo/actions/runs/987654321"
            write_json(root / "docs/qa/reports/android-apk-smoke.json", {
                "status": "pass",
                **stale,
            })

            code = self.run_verifier(root, verifier_env(), api_run())
            output = json.loads((root / "docs/qa/reports/android-github-actions-verification.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 1)
        self.assertEqual(output["status"], "blocked")
        self.assertIn("docs/qa/reports/android-apk-smoke.json:github_run_id", output["mismatches"])

    def test_verifier_rejects_stale_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "docs/qa/reports/android-apk-smoke.json", {
                "status": "pass",
                **RUN_METADATA,
            })
            stale_run = api_run()
            stale_run["created_at"] = "2000-01-01T00:00:00Z"

            code = self.run_verifier(root, verifier_env(), stale_run)
            output = json.loads((root / "docs/qa/reports/android-github-actions-verification.json").read_text(encoding="utf-8"))

        self.assertEqual(code, 1)
        self.assertEqual(output["status"], "blocked")
        self.assertIn("api:run_age", output["mismatches"])


if __name__ == "__main__":
    unittest.main()
