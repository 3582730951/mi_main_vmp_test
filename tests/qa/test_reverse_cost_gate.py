import unittest

from scripts.audit import reverse_cost_gate


def valid_report() -> dict:
    return {
        "schema": reverse_cost_gate.SCHEMA,
        "status": "pass",
        "manual_review": True,
        "reviewer": "authorized-red-team",
        "methodology": "Manual reverse-cost assessment of the protected release artifact.",
        "assessment_date": "2026-05-05",
        "review_tools": ["IDA", "Ghidra", "LLDB"],
        "github_sha": "a" * 40,
        "protected_artifact_sha256": "b" * 64,
        "minimum_reverse_cost_days": 365,
        "assessed_capabilities": {
            "automatic_hotspot_analysis": True,
            "defense_floor_preserved": True,
            "callsite_obfuscation": True,
            "per_callsite_thunks": True,
            "protected_function_address_not_materialized": True,
            "decompiler_traps": True,
            "randomized_stack_backtrace": True,
        },
    }


def valid_automated_report() -> dict:
    report = valid_report()
    report["manual_review"] = False
    report["assessment_mode"] = "automated_tooling"
    report["automated_review"] = True
    report["tool_results"] = [{"tool": "strings", "status": "pass"}]
    report["score_breakdown"] = {"callsite_graph_distortion": 365}
    return report


class ReverseCostGateTests(unittest.TestCase):
    def test_accepts_valid_current_sha_report(self) -> None:
        self.assertEqual(reverse_cost_gate.validate_report(valid_report(), expected_sha="a" * 40), [])

    def test_rejects_below_one_year_estimate(self) -> None:
        report = valid_report()
        report["minimum_reverse_cost_days"] = 364
        errors = reverse_cost_gate.validate_report(report, expected_sha="a" * 40)
        self.assertTrue(any("minimum_reverse_cost_days" in error for error in errors))

    def test_rejects_stale_sha(self) -> None:
        errors = reverse_cost_gate.validate_report(valid_report(), expected_sha="c" * 40)
        self.assertTrue(any("current checked-out commit" in error for error in errors))

    def test_rejects_missing_required_capability(self) -> None:
        report = valid_report()
        report["assessed_capabilities"]["per_callsite_thunks"] = False
        errors = reverse_cost_gate.validate_report(report, expected_sha="a" * 40)
        self.assertTrue(any("per_callsite_thunks" in error for error in errors))

    def test_accepts_automated_tooling_report(self) -> None:
        self.assertEqual(reverse_cost_gate.validate_report(valid_automated_report(), expected_sha="a" * 40), [])

    def test_rejects_automated_report_without_tool_results(self) -> None:
        report = valid_automated_report()
        report["tool_results"] = []
        errors = reverse_cost_gate.validate_report(report, expected_sha="a" * 40)
        self.assertTrue(any("tool_results" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
