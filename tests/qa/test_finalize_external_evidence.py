import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scripts.audit import finalize_external_evidence


class FinalizeExternalEvidenceTests(unittest.TestCase):
    def test_requires_objective_completion_pass_for_final_signoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "docs/qa/reports/objective-completion-audit.json", {
                "schema": "vmp.qa.objective_completion_audit.v1",
                "status": "blocked",
            })

            with self.assertRaises(RuntimeError):
                finalize_external_evidence.require_objective_completion_report(root)

    def test_accepts_passing_objective_completion_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "docs/qa/reports/objective-completion-audit.json", {
                "schema": "vmp.qa.objective_completion_audit.v1",
                "status": "pass",
            })

            report = finalize_external_evidence.require_objective_completion_report(root)

        self.assertEqual(report["status"], "pass")

    def test_write_final_signoff_keeps_blocked_when_capability_matrix_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_required_signoff_reports(root, capability_status="blocked", final_signoff_allowed=False)

            finalize_external_evidence.write_final_signoff(root)

            text = (root / "docs/qa/FinalSignOff.md").read_text(encoding="utf-8")
        self.assertIn("Status: **blocked**", text)
        self.assertIn("capability-matrix.json", text)
        self.assertIn("not proven to be VMProtect-tier", text)
        self.assertNotIn("3_all_strings_ciphertext_no_plaintext", text)

    def test_write_final_signoff_keeps_blocked_for_local_only_vmprotect_tier_preconditions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_required_signoff_reports(root, capability_status="pass", final_signoff_allowed=False)

            finalize_external_evidence.write_final_signoff(root)

            text = (root / "docs/qa/FinalSignOff.md").read_text(encoding="utf-8")
        self.assertIn("Status: **blocked**", text)
        self.assertIn("local VMProtect-tier implementation preconditions pass", text)
        self.assertIn("trusted vmprotect-tier GitHub provenance", text)
        self.assertNotIn("not proven to be VMProtect-tier", text)

    def test_write_final_signoff_requires_broad_lowering_and_production_crypto(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_required_signoff_reports(root)
            write_json(root / "docs/qa/reports/general-ir-lowering.json", {
                "schema": "vmp.qa.general_ir_lowering.v1",
                "status": "pass",
                "broad_ir_lowering": False,
                "bounded_i32_only": True,
            })

            finalize_external_evidence.write_final_signoff(root)

            text = (root / "docs/qa/FinalSignOff.md").read_text(encoding="utf-8")
        self.assertIn("Status: **blocked**", text)
        self.assertIn("does not prove broad, non-bounded IR lowering", text)

    def test_write_final_signoff_can_sign_when_required_reports_are_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_required_signoff_reports(root)

            with strict_gate_mocks(), mock.patch.dict(
                os.environ,
                {"VMP_REQUIRE_LIVE_GITHUB_VERIFICATION": "1"},
                clear=False,
            ):
                finalize_external_evidence.write_final_signoff(root)

            text = (root / "docs/qa/FinalSignOff.md").read_text(encoding="utf-8")
        self.assertIn("Status: **signed off**", text)
        self.assertIn("Strict completion audit: pass", text)
        self.assertIn("Open findings: 0", text)

    def test_write_final_signoff_requires_live_verification_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_required_signoff_reports(root)

            with strict_gate_mocks(), mock.patch.dict(os.environ, {}, clear=True):
                finalize_external_evidence.write_final_signoff(root)

            text = (root / "docs/qa/FinalSignOff.md").read_text(encoding="utf-8")
        self.assertIn("Status: **blocked**", text)
        self.assertIn("VMP_REQUIRE_LIVE_GITHUB_VERIFICATION=1", text)

    def test_write_final_signoff_requires_strict_completion_gate_predicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_required_signoff_reports(root)

            with strict_gate_mocks(android=False), mock.patch.dict(
                os.environ,
                {"VMP_REQUIRE_LIVE_GITHUB_VERIFICATION": "1"},
                clear=False,
            ):
                finalize_external_evidence.write_final_signoff(root)

            text = (root / "docs/qa/FinalSignOff.md").read_text(encoding="utf-8")
        self.assertIn("Status: **blocked**", text)
        self.assertIn("Android release-strength evidence", text)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def write_required_signoff_reports(
    root: Path,
    *,
    capability_status: str = "pass",
    final_signoff_allowed: bool = True,
) -> None:
    reports = root / "docs/qa/reports"
    for relative_path in finalize_external_evidence.FINAL_SIGNOFF_EVIDENCE:
        if relative_path.endswith("github-actions-verification.json"):
            write_json(root / relative_path, {
                "schema": "vmp.qa.github_actions_verification.v1",
                "status": "pass",
            })
        else:
            write_json(root / relative_path, {"status": "pass"})

    write_json(reports / "objective-completion-audit.json", {
        "schema": "vmp.qa.objective_completion_audit.v1",
        "status": "pass",
        "residual_blockers": [],
    })
    write_json(reports / "reverse-cost-assessment.json", {
        "schema": "vmp.qa.reverse_cost_assessment.v1",
        "status": "pass",
        "assessment_mode": "automated_tooling",
        "automated_review": True,
        "manual_review": False,
        "reviewer": "test",
        "methodology": "test",
        "assessment_date": "2026-05-07",
        "review_tools": ["test"],
        "tool_results": [{"tool": "test", "status": "pass"}],
        "score_breakdown": {"test": 365},
        "minimum_reverse_cost_days": 365,
        "github_sha": "a" * 40,
        "protected_artifact_sha256": "b" * 64,
        "assessed_capabilities": {
            name: True for name in finalize_external_evidence.validate_report.__globals__["REQUIRED_CAPABILITIES"]
        },
    })
    write_json(reports / "capability-matrix.json", {
        "schema": "vmp.qa.capability_matrix.v1",
        "status": capability_status,
        "final_signoff_allowed": final_signoff_allowed,
    })
    write_json(reports / "general-ir-lowering.json", {
        "schema": "vmp.qa.general_ir_lowering.v1",
        "status": "pass",
        "broad_ir_lowering": True,
        "bounded_i32_only": False,
    })
    write_json(reports / "production-crypto-key-management.json", {
        "schema": "vmp.qa.production_crypto_key_management.v1",
        "status": "pass",
        "production_crypto": True,
        "static_keys_present": False,
        "key_rotation_supported": True,
    })
    write_json(reports / "vmprotect-tier-review.json", {
        "schema": "vmp.qa.vmprotect_tier_review.v1",
        "status": "pass",
        "manual_review": True,
        "reviewer": "test",
        "review_date": "2026-05-07",
        "open_vulnerabilities": 0,
        "open_findings": 0,
    })


def strict_gate_mocks(**overrides: bool):
    defaults = {
        "windows": True,
        "android": True,
        "hostile": True,
        "ida": True,
        "vmprotect": True,
    }
    defaults.update(overrides)
    patches = [
        mock.patch.object(finalize_external_evidence, "windows_github_actions_evidence_exists", return_value=defaults["windows"]),
        mock.patch.object(finalize_external_evidence, "android_release_strength_evidence_exists", return_value=defaults["android"]),
        mock.patch.object(finalize_external_evidence, "hostile_full_coverage_exists", return_value=defaults["hostile"]),
        mock.patch.object(finalize_external_evidence, "ida_ollydbg_manual_review_evidence_exists", return_value=defaults["ida"]),
        mock.patch.object(finalize_external_evidence, "vmprotect_tier_evidence_exists", return_value=defaults["vmprotect"]),
    ]
    return context_stack(patches)


class context_stack:
    def __init__(self, contexts):
        self.contexts = contexts
        self.entered = []

    def __enter__(self):
        for context in self.contexts:
            self.entered.append(context)
            context.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        while self.entered:
            self.entered.pop().__exit__(exc_type, exc, tb)


if __name__ == "__main__":
    unittest.main()
