import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.audit import objective_completion_audit


class ObjectiveCompletionAuditTests(unittest.TestCase):
    def test_current_workspace_reports_literal_goal_status(self) -> None:
        root = Path(__file__).resolve().parents[2]

        report = objective_completion_audit.build_report(root)

        self.assertEqual(report["schema"], "vmp.qa.objective_completion_audit.v1")
        self.assertIn(report["status"], {"pass", "blocked"})
        statuses = {item["requirement"]: item["status"] for item in report["checks"]}
        self.assertEqual(statuses["2_vm_ollvm_standard_marker_absence"], "pass")
        self.assertEqual(statuses["4_import_export_tls_minimized"], "pass")
        self.assertEqual(statuses["5_syscall_policy"], "pass")
        self.assertEqual(statuses["6_protected_program_stability"], "pass")
        self.assertEqual(len(report["prompt_to_artifact_checklist"]), 6)
        self.assertTrue(all(item["artifacts"] for item in report["prompt_to_artifact_checklist"]))
        self.assertEqual(
            report["prompt_to_artifact_checklist"][0]["requirement"],
            "5_syscall_policy",
        )
        self.assertEqual(
            report["prompt_to_artifact_checklist"][1]["requirement"],
            "6_protected_program_stability",
        )

    def test_missing_reports_do_not_false_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "docs/SECURITY_POLICY.md").write_text("", encoding="utf-8")

            report = objective_completion_audit.build_report(root)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("partial", {item["status"] for item in report["checks"]})

    def test_string_requirement_passes_when_all_artifacts_have_zero_printable_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "docs/qa/reports"
            reports.mkdir(parents=True)
            (root / "docs/SECURITY_POLICY.md").parent.mkdir(parents=True, exist_ok=True)
            (root / "docs/SECURITY_POLICY.md").write_text(
                "does not implement generic direct-syscall bypass stubs",
                encoding="utf-8",
            )
            sample = root / "samples/protected_chain/out/protected_sample.vmp"
            linux = root / "artifacts/protected/linux/protected_release_sample"
            windows = root / "build/windows-protected-cross/protected_release_sample.exe"
            for path in (sample, linux, windows):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"\x00\x01\x02\x03\xff\x80\x00")

            write_json(reports / "release-protected-binary.json", {
                "status": "pass",
                "elf_metadata_findings": [],
            })
            write_json(reports / "windows-protected-cross-build.json", {
                "status": "partial",
                "pe_metadata_findings": [],
            })
            write_json(reports / "surface-minimization.json", {
                "status": "pass",
                "avoidable_surface_findings": 0,
                "scanned_artifacts": [
                    {
                        "artifact": "artifacts/protected/linux/protected_release_sample",
                        "elf_observations": {"import_count": 0, "export_count": 0},
                    },
                    {"artifact": "samples/protected_chain/out/protected_sample.vmp"},
                    {
                        "artifact": "build/windows-protected-cross/protected_release_sample.exe",
                        "pe_observations": {
                            "import_count": 0,
                            "import_directory_present": False,
                            "export_directory_present": False,
                            "tls_directory_present": False,
                        },
                    },
                ],
            })

            report = objective_completion_audit.build_report(root)

        string_check = next(item for item in report["checks"] if item["requirement"] == "3_all_strings_ciphertext_no_plaintext")
        self.assertEqual(string_check["status"], "pass")
        self.assertEqual(string_check["observed_strings_count"], {
            "linux_release": 0,
            "sample_vmp": 0,
            "windows_release": 0,
        })

    def test_pe_string_classification_separates_executable_and_data_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.exe"
            path.write_bytes(fake_pe_with_printable_runs())

            classification = objective_completion_audit.classify_pe_strings(path)

        self.assertEqual(classification["total"], 2)
        self.assertEqual(classification["executable_section_strings"], 1)
        self.assertEqual(classification["non_executable_section_strings"], 1)
        self.assertEqual(classification["unknown_section_strings"], 0)

    def test_string_blocker_includes_platform_constraint_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "docs/qa/reports"
            reports.mkdir(parents=True)
            (root / "docs/SECURITY_POLICY.md").write_text("", encoding="utf-8")
            apk = root / "build/android-apk-smoke/mi-smoke.apk"
            apk.parent.mkdir(parents=True)
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"ABCD", compress_type=zipfile.ZIP_STORED)

            report = objective_completion_audit.build_report(root)

        blocker = next(
            item for item in report["residual_blockers"]
            if item["requirement"] == "3_all_strings_ciphertext_no_plaintext"
        )
        strict = blocker["platform_string_residuals"]["strict_zero_string"]
        self.assertFalse(strict["strict_zero_string_compatible"])
        self.assertGreaterEqual(strict["platform_contract_residuals"], 1)
        self.assertEqual(strict["unknown_or_avoidable_residuals"], 0)

    def test_automation_summary_reports_xref_hotspot_and_github_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "docs/qa/reports"
            reports.mkdir(parents=True)
            (root / "docs/SECURITY_POLICY.md").parent.mkdir(parents=True, exist_ok=True)
            (root / "docs/SECURITY_POLICY.md").write_text("", encoding="utf-8")
            write_json(reports / "protected-callgraph.json", {
                "status": "pass",
                "analysis": {
                    "protected_xrefs_discovered": True,
                    "direct_protected_xrefs_removed": True,
                    "high_frequency_policy_applied": True,
                    "defense_floor_preserved": True,
                    "per_callsite_thunks_preserved": True,
                },
            })
            write_json(reports / "reverse-cost-assessment.json", {
                "status": "pass",
                "tool_results": [
                    {"tool": "lief", "status": "pass"},
                    {"tool": "angr", "status": "unavailable", "reason": "not installed"},
                    {
                        "tool": "external-callgraph-consensus",
                        "status": "pass",
                        "backend_count": 2,
                        "total_functions_observed": 5,
                        "total_call_edges_observed": 4,
                    },
                ],
            })

            report = objective_completion_audit.build_report(root)

        automation = report["automation"]
        self.assertTrue(automation["protected_function_xref_discovery"])
        self.assertTrue(automation["direct_protected_xrefs_removed_after_rewrite"])
        self.assertTrue(automation["high_frequency_callsite_optimization"])
        self.assertTrue(automation["defense_floor_preserved"])
        self.assertEqual(automation["available_external_tools"], ["lief", "external-callgraph-consensus"])
        self.assertEqual(automation["external_callgraph_consensus"]["backend_count"], 2)
        self.assertEqual(automation["external_callgraph_consensus"]["total_call_edges_observed"], 4)
        self.assertIn({"tool": "angr", "status": "unavailable", "reason": "not installed"}, automation["external_tool_results"])
        self.assertIn("radare2", {item["tool"] for item in automation["github_tool_sources"]})

    def test_ios_macho_report_does_not_false_pass_strict_standard_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "docs/qa/reports"
            reports.mkdir(parents=True)
            (root / "docs/SECURITY_POLICY.md").parent.mkdir(parents=True, exist_ok=True)
            (root / "docs/SECURITY_POLICY.md").write_text("", encoding="utf-8")
            write_json(reports / "surface-minimization.json", {
                "status": "pass",
                "avoidable_surface_findings": 0,
                "scanned_artifacts": [],
            })
            write_json(reports / "release-protected-binary.json", {
                "status": "pass",
                "elf_metadata_findings": [],
            })
            write_json(reports / "windows-protected-cross-build.json", {
                "status": "pass",
                "pe_metadata_findings": [],
            })
            write_json(reports / "android-apk-smoke.json", {
                "status": "pass",
                "manifest_debuggable": False,
                "apk_forbidden_plaintext_hits": [],
                "jni_symbol_plaintext_hits": [],
            })
            write_json(reports / "ios-macho-metadata.json", {
                "status": "pass",
                "missing_artifacts": [],
                "unsupported_artifacts": [],
                "observed_surface_findings": 3,
            })

            report = objective_completion_audit.build_report(root)

        platform_check = next(
            item for item in report["checks"] if item["requirement"] == "1_platform_standard_feature_minimization"
        )
        self.assertEqual(platform_check["status"], "partial")
        self.assertTrue(platform_check["platform_scope"]["ios_macho_metadata_report"])
        self.assertFalse(platform_check["platform_scope"]["ios_macho_strict_standard_surface_free"])

    def test_android_actual_apk_marker_scan_finds_entry_and_byte_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "build/android-apk-smoke/mi-smoke.apk"
            apk.parent.mkdir(parents=True)
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/x86_64/libvmp_platform.so", b"native")
                archive.writestr("classes.dex", b"VMPBC")

            result = objective_completion_audit.android_actual_apk_surface(root, {})

        self.assertTrue(result["present"])
        self.assertIn("lib/x86_64/libvmp_platform.so:libvmp", result["entry_marker_hits"])
        self.assertIn("VMPBC", result["byte_marker_hits"])


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def fake_pe_with_printable_runs() -> bytes:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset:pe_offset + 4] = b"PE\0\0"
    data[pe_offset + 4:pe_offset + 6] = (0x8664).to_bytes(2, "little")
    data[pe_offset + 6:pe_offset + 8] = (2).to_bytes(2, "little")
    data[pe_offset + 20:pe_offset + 22] = (0).to_bytes(2, "little")
    section_offset = pe_offset + 24
    write_section(data, section_offset, b"\x81\x93\xa5\xb7", 0x200, 0x200, 0x60000020)
    write_section(data, section_offset + 40, b"\x82\x94\xa6\xb8", 0x200, 0x400, 0xC0000040)
    data[0x210:0x215] = b"CODE!"
    data[0x410:0x415] = b"DATA!"
    return bytes(data)


def write_section(data: bytearray, offset: int, name: bytes, raw_size: int, raw_pointer: int, characteristics: int) -> None:
    data[offset:offset + 8] = name.ljust(8, b"\0")
    data[offset + 16:offset + 20] = raw_size.to_bytes(4, "little")
    data[offset + 20:offset + 24] = raw_pointer.to_bytes(4, "little")
    data[offset + 36:offset + 40] = characteristics.to_bytes(4, "little")


if __name__ == "__main__":
    unittest.main()
