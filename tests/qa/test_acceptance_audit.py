from pathlib import Path
import tempfile
import unittest

from scripts.audit import acceptance_audit


ROOT = Path(__file__).resolve().parents[2]


class AcceptanceAuditTests(unittest.TestCase):
    def test_audit_passes_current_workspace(self):
        report = acceptance_audit.run_once(ROOT)
        self.assertEqual(report["status"], "pass", report["findings"])
        self.assertGreaterEqual(report["metrics"]["anti_analysis_tests"], 4)
        self.assertGreater(report["metrics"]["protected_artifacts_scanned"], 0)
        self.assertEqual(report["metrics"]["protected_forbidden_string_hits"], 0)
        self.assertEqual(report["metrics"]["performance_reports"], 1)
        self.assertEqual(report["metrics"]["capability_reports"], 1)
        self.assertEqual(report["metrics"]["hostile_reports"], 1)
        self.assertEqual(report["metrics"]["release_binary_reports"], 1)
        self.assertEqual(report["metrics"]["surface_reports"], 1)
        self.assertEqual(report["metrics"]["protected_callgraph_reports"], 1)

    def test_audit_does_not_read_passwd(self):
        original_read_bytes = Path.read_bytes
        original_read_text = Path.read_text

        def guarded_read_bytes(path):
            self.assertNotEqual(path.name, "passwd.txt")
            return original_read_bytes(path)

        def guarded_read_text(path, *args, **kwargs):
            self.assertNotEqual(path.name, "passwd.txt")
            return original_read_text(path, *args, **kwargs)

        try:
            Path.read_bytes = guarded_read_bytes
            Path.read_text = guarded_read_text
            report = acceptance_audit.run_once(ROOT)
        finally:
            Path.read_bytes = original_read_bytes
            Path.read_text = original_read_text

        self.assertEqual(report["status"], "pass", report["findings"])

    def test_workflows_have_read_only_permissions(self):
        findings, metrics = acceptance_audit.check_workflows(ROOT)

        self.assertEqual(metrics["workflows_scanned"], 7)
        self.assertEqual(findings, [])

    def test_pull_request_workflow_secrets_must_be_pr_guarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_dir = root / ".github/workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "bad.yml").write_text(
                "name: bad\n"
                "on:\n"
                "  pull_request:\n"
                "permissions:\n"
                "  contents: read\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - name: unsafe\n"
                "        env:\n"
                "          ANDROID_KEYSTORE_PASSWORD: ${{ secrets.ANDROID_KEYSTORE_PASSWORD }}\n"
                "        run: ./repo-script.sh\n",
                encoding="utf-8",
            )

            findings, _ = acceptance_audit.check_workflows(root)

        self.assertTrue(any("pull_request workflow secret" in finding.message for finding in findings))

    def test_three_runs_are_deterministic(self):
        reports = [acceptance_audit.run_once(ROOT) for _ in range(3)]
        metrics = [report["metrics"] for report in reports]
        self.assertEqual(metrics[0], metrics[1])
        self.assertEqual(metrics[1], metrics[2])
        self.assertTrue(all(report["status"] == "pass" for report in reports))


if __name__ == "__main__":
    unittest.main()
