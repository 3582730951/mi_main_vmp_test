import json
import tempfile
import unittest
from pathlib import Path

from scripts.audit import protection_capability_showcase


class ProtectionCapabilityShowcaseTests(unittest.TestCase):
    def test_current_workspace_report_separates_capability_from_final_signoff(self) -> None:
        root = Path(__file__).resolve().parents[2]

        report = protection_capability_showcase.build_report(root)

        self.assertEqual(report["schema"], "vmp.qa.protection_capability_showcase.v1")
        self.assertEqual(report["status"], "evidence_available")
        self.assertFalse(report["summary"]["final_signoff_allowed"])
        capabilities = {item["name"]: item for item in report["capabilities"]}
        self.assertIn("string_plaintext_hiding", capabilities)
        self.assertIn("dynamic_string_runtime_decryption", capabilities)
        self.assertIn("windows_api_call_minimization_policy", capabilities)
        self.assertIn("protected_xref_and_callgraph_distortion", capabilities)
        self.assertIn("windows_visible_protected_demo", capabilities)
        self.assertTrue(
            capabilities["string_plaintext_hiding"]["evidence"]["generic_llvm_const_string_encryption_implemented"]
        )
        self.assertNotIn(
            "generic LLVM const-string encryption is not implemented as a general pass",
            report["blockers_and_limits"],
        )
        self.assertIn(
            "accepted Windows release does not enable syscall-only I/O; direct Windows syscall stubs remain outside the release gate by policy",
            report["blockers_and_limits"],
        )

    def test_temp_report_flags_visible_demo_string_hiding_without_general_string_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "docs/qa/reports"
            reports.mkdir(parents=True)
            llvm_out = root / "tests/core/.llvm-out"
            llvm_out.mkdir(parents=True)

            write_json(reports / "capability-matrix.json", {
                "status": "blocked",
                "final_signoff_allowed": False,
            })
            write_json(reports / "protected-callgraph.json", {
                "status": "pass",
                "analysis": {
                    "protected_xrefs_discovered": True,
                    "direct_protected_xrefs_removed": True,
                    "high_frequency_policy_applied": True,
                    "defense_floor_preserved": True,
                    "per_callsite_thunks_preserved": True,
                },
                "callsite_obfuscation": {
                    "rewritten_calls": 3,
                    "unique_thunks": 3,
                    "protected_thunk_call_edges": 3,
                },
            })
            write_json(reports / "reverse-cost-assessment.json", {
                "status": "pass",
                "minimum_reverse_cost_days": 570,
                "score_breakdown": {"callsite_graph_distortion": 85},
                "assessed_capabilities": {"callsite_obfuscation": True},
            })
            write_json(reports / "release-protected-binary.json", {
                "status": "pass",
                "behavior_cases_passed": 4,
                "forbidden_plaintext_hits": [],
                "artifact_bytes": 16,
            })
            write_json(reports / "surface-minimization.json", {
                "status": "pass",
                "avoidable_surface_findings": 0,
                "scanned_artifacts": [
                    {
                        "artifact": "artifacts/protected/linux/protected_release_sample",
                        "elf_observations": {"import_count": 0, "export_count": 0},
                    },
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
            write_json(reports / "windows-visible-demo-cross-build.json", {
                "status": "pass",
                "artifact_bytes": 128,
                "embedded_sample_bytes": 32,
                "visible_demo_strings_encrypted": True,
                "dynamic_string_protection": {
                    "chunked_runtime_decode": True,
                    "full_plaintext_string_buffer": False,
                    "two_pass_plaintext_tag_validation": True,
                    "per_call_stateful_chunk_schedule": True,
                    "chunk_plaintext_wiped_after_use": True,
                },
                "windows_getchar_calls": 3,
                "wine_execution_status": "skipped",
            })
            write_json(reports / "windows-protected-cross-build.json", {
                "release_mode": "visible_encrypted_console_demo",
                "visible_demo_strings_encrypted": True,
                "windows_getchar_calls": 3,
                "forbidden_plaintext_hits": [],
                "dynamic_string_protection": {
                    "chunked_runtime_decode": True,
                    "full_plaintext_string_buffer": False,
                    "two_pass_plaintext_tag_validation": True,
                    "per_call_stateful_chunk_schedule": True,
                    "chunk_plaintext_wiped_after_use": True,
                },
                "windows_console_api_policy": {
                    "mode": "minimal_fixed_kernel32_console_api",
                    "direct_windows_syscalls_enabled": False,
                    "generic_syscall_resolver_allowed": False,
                    "stdout_handle_cached": True,
                    "stdin_handle_cached": True,
                    "writefile_calls_batched": True,
                },
            })
            write_json(reports / "ida-ollydbg-review.json", {
                "status": "pass",
                "reviewed_indicators": {"f5_or_decompiler_distortion": True},
            })
            write_json(reports / "vmprotect-tier-review.json", {
                "status": "pass",
                "capabilities": {"code_virtualization": True},
            })
            write_json(reports / "hostile-environment.json", {
                "status": "blocked",
                "real_platform_trigger_scope": "partial_linux",
            })
            write_json(llvm_out / "vmp-stage-manifest.json", {
                "schema": "vmp.llvm.stage_manifest.v1",
                "pipeline": {
                    "executed_count": 16,
                    "implemented_count": 9,
                    "placeholder_noop_count": 6,
                    "report_only_count": 1,
                },
                "stages": [
                    {
                        "name": "vmp-ir-to-bytecode",
                        "implemented": True,
                        "kind": "transform",
                        "capability_effects": ["code_virtualization.bytecode_lowering"],
                    },
                    {
                        "name": "vmp-const-string-encryption",
                        "implemented": False,
                        "kind": "placeholder_noop",
                        "capability_effects": [],
                    },
                ],
            })
            (llvm_out / "plugin.log").write_text(
                "VMPPassPlugin report: selected_functions=2 lowered_functions=1 "
                "replaced_functions=1 unsupported_functions=1 stages=16\n",
                encoding="utf-8",
            )
            (llvm_out / "sample.protected.ll").write_text(
                "@vmp.bytecode.foo = private constant [1 x i8] c\"\\00\"\n"
                "define i32 @foo() !vmp.replaced !1 { ret i32 0 }\n",
                encoding="utf-8",
            )
            (llvm_out / "hotspot-callsite.protected.ll").write_text(
                "vmp.decompiler.trap:\n"
                "  switch i32 0, label %x []\n"
                "!vmp.anti_analysis.policy = !{}\n",
                encoding="utf-8",
            )
            write_binary(root / "artifacts/protected/linux/protected_release_sample", b"\x00\x01\x02")
            write_binary(root / "samples/protected_chain/out/protected_sample.vmp", b"\x80\x81\x82")
            write_binary(root / "build/windows-protected-cross/protected_release_sample.exe", b"\x00\xff\x01")
            write_binary(
                root / "build/windows-visible-demo/protected_visible_demo.exe",
                b"MZ\x00ExitProcess\x00GetStdHandle\x00ReadFile\x00WriteFile\x00KERNEL32.dll\x00",
            )

            report = protection_capability_showcase.build_report(root)

        capabilities = {item["name"]: item for item in report["capabilities"]}
        string_capability = capabilities["string_plaintext_hiding"]
        self.assertEqual(string_capability["status"], "partial")
        self.assertFalse(string_capability["evidence"]["generic_llvm_const_string_encryption_implemented"])
        self.assertTrue(string_capability["evidence"]["strict_artifacts_zero_printable_strings"])
        self.assertTrue(string_capability["evidence"]["visible_demo_forbidden_plaintext_absent"])
        windows_demo = capabilities["windows_visible_protected_demo"]
        self.assertEqual(windows_demo["status"], "demonstrated")
        self.assertEqual(windows_demo["evidence"]["windows_getchar_calls"], 3)
        self.assertEqual(windows_demo["evidence"]["forbidden_plaintext_hits"], [])
        self.assertEqual(capabilities["dynamic_string_runtime_decryption"]["status"], "demonstrated")
        self.assertEqual(capabilities["windows_api_call_minimization_policy"]["status"], "demonstrated")

    def test_write_report_emits_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs/qa/reports").mkdir(parents=True)
            json_path = root / "docs/qa/reports/protection-capability-showcase.json"
            markdown_path = root / "docs/qa/ProtectionCapabilityShowcase.md"

            report = protection_capability_showcase.write_report(root, json_path, markdown_path)

            self.assertEqual(report["schema"], "vmp.qa.protection_capability_showcase.v1")
            self.assertTrue(json_path.exists())
            self.assertTrue(markdown_path.exists())
            self.assertIn("Protection Capability Showcase", markdown_path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def write_binary(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


if __name__ == "__main__":
    unittest.main()
