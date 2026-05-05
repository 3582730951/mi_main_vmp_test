import os
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FinalAcceptanceTests(unittest.TestCase):
    def make_repo(self, acceptance_body: str) -> Path:
        root = Path(tempfile.mkdtemp())
        shutil.copy(ROOT / "final_acceptance.sh", root / "final_acceptance.sh")
        os.chmod(root / "final_acceptance.sh", 0o755)
        (root / "acceptance.sh").write_text(acceptance_body, encoding="utf-8")
        os.chmod(root / "acceptance.sh", 0o755)
        audit = root / "scripts/audit/plan_completion_audit.py"
        audit.parent.mkdir(parents=True)
        audit.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n", encoding="utf-8")
        os.chmod(audit, 0o755)
        reverse_cost = root / "scripts/audit/reverse_cost_gate.py"
        reverse_cost.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n", encoding="utf-8")
        os.chmod(reverse_cost, 0o755)
        finalize = root / "scripts/audit/finalize_external_evidence.py"
        finalize.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)\n", encoding="utf-8")
        os.chmod(finalize, 0o755)
        return root

    def run_final(self, root: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["./final_acceptance.sh"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_restores_existing_external_report_when_acceptance_fails(self):
        root = self.make_repo(textwrap.dedent("""\
            #!/usr/bin/env sh
            set -eu
            mkdir -p docs/qa/reports
            printf '%s\n' '{"status":"local-overwrite"}' > docs/qa/reports/android-apk-smoke.json
            exit 42
        """))
        report = root / "docs/qa/reports/android-apk-smoke.json"
        report.parent.mkdir(parents=True)
        report.write_text('{"status":"external"}\n', encoding="utf-8")
        try:
            result = self.run_final(root)

            self.assertEqual(result.returncode, 42)
            self.assertEqual(report.read_text(encoding="utf-8"), '{"status":"external"}\n')
        finally:
            shutil.rmtree(root)

    def test_removes_external_report_that_was_absent_before_acceptance(self):
        root = self.make_repo(textwrap.dedent("""\
            #!/usr/bin/env sh
            set -eu
            mkdir -p docs/qa/reports
            printf '%s\n' '{"status":"local-created"}' > docs/qa/reports/android-emulator-smoke.json
        """))
        report = root / "docs/qa/reports/android-emulator-smoke.json"
        try:
            result = self.run_final(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(report.exists())
        finally:
            shutil.rmtree(root)


if __name__ == "__main__":
    unittest.main()
