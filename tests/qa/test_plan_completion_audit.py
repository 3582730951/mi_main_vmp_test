import hashlib
import contextlib
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest import mock

from scripts.audit import plan_completion_audit


ROOT = Path(__file__).resolve().parents[2]
GITHUB_CREATED_AT = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_vmprotect_tier_reports(root: Path, omit=frozenset(), overrides=None):
    overrides = overrides or {}
    reports = {
        "capability": {
            "path": root / "docs/qa/reports/capability-matrix.json",
            "data": {
                "status": "pass",
                "final_signoff_allowed": True,
            },
        },
        "lowering": {
            "path": root / "docs/qa/reports/general-ir-lowering.json",
            "data": {
                "schema": "vmp.qa.general_ir_lowering.v1",
                "status": "pass",
                "broad_ir_lowering": True,
                "bounded_i32_only": False,
            },
        },
        "crypto": {
            "path": root / "docs/qa/reports/production-crypto-key-management.json",
            "data": {
                "schema": "vmp.qa.production_crypto_key_management.v1",
                "status": "pass",
                "production_crypto": True,
                "static_keys_present": False,
                "key_rotation_supported": True,
            },
        },
        "review": {
            "path": root / "docs/qa/reports/vmprotect-tier-review.json",
            "data": {
                "schema": "vmp.qa.vmprotect_tier_review.v1",
                "status": "pass",
                "manual_review": True,
                "open_vulnerabilities": 0,
                "open_findings": 0,
                "capabilities": {
                    "code_virtualization": True,
                    "mutation_obfuscation": True,
                    "combined_protection": True,
                    "string_hiding": True,
                    "import_hiding": True,
                    "anti_debug": True,
                    "anti_injection": True,
                    "anti_tamper": True,
                },
                "platforms_proven": ["Linux", "Windows", "Android"],
            },
        },
    }
    for report in reports.values():
        report["data"].update(github_metadata("vmprotect-tier"))
    for name, patch in overrides.items():
        reports[name]["data"].update(patch)
    for name, report in reports.items():
        if name not in omit:
            write_json(report["path"], report["data"])


def github_metadata(workflow: str = "platform-ci") -> dict:
    return {
        "github_run_id": "123456789",
        "github_run_attempt": "1",
        "github_run_url": "https://github.com/example/repo/actions/runs/123456789",
        "github_repository": "example/repo",
        "github_sha": "a" * 40,
        "github_workflow": workflow,
        "github_event_name": "workflow_dispatch",
        "github_ref": "refs/heads/main",
        "github_ref_name": "main",
        "github_ref_protected": "true",
    }


def github_api_run(workflow: str = "platform-ci") -> dict:
    workflow_path = plan_completion_audit.EXPECTED_WORKFLOW_PATHS.get(workflow, f".github/workflows/{workflow}.yml")
    return {
        "id": 123456789,
        "run_attempt": 1,
        "head_sha": "a" * 40,
        "event": "workflow_dispatch",
        "html_url": "https://github.com/example/repo/actions/runs/123456789",
        "status": "completed",
        "conclusion": "success",
        "name": workflow,
        "head_branch": "main",
        "head_repository": {"full_name": "example/repo"},
        "pull_requests": [],
        "path": workflow_path,
        "created_at": GITHUB_CREATED_AT,
    }


def artifact_zip(root: Path) -> bytes:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        report_dir = root / "docs/qa/reports"
        if report_dir.exists():
            for path in sorted(report_dir.glob("*.json")):
                archive.write(path, path.relative_to(root).as_posix())
    return data.getvalue()


@contextlib.contextmanager
def live_github_verification(root: Path, *workflows: str):
    runs = [github_api_run(workflow) for workflow in workflows] or [github_api_run()]
    with mock.patch.object(plan_completion_audit, "fetch_github_run", side_effect=runs), \
        mock.patch.object(plan_completion_audit, "fetch_github_artifacts", return_value={
            "artifacts": [{
                "name": "test-evidence",
                "expired": False,
                "archive_download_url": "https://api.github.com/artifacts/test.zip",
                "workflow_run": {"run_attempt": 1},
            }],
        }), \
        mock.patch.object(plan_completion_audit, "download_github_artifact_zip", return_value=artifact_zip(root)):
        yield


def write_github_verification(root: Path, path: str, reports: list[str], workflow: str = "platform-ci") -> None:
    workflow_path = plan_completion_audit.EXPECTED_WORKFLOW_PATHS.get(workflow, f".github/workflows/{workflow}.yml")
    data = {
        "schema": "vmp.qa.github_actions_verification.v1",
        "status": "pass",
        "github_api_verified": True,
        "github_actions_runtime": True,
        **github_metadata(workflow),
        "github_ref_protected": True,
        "head_branch": "main",
        "head_repository": "example/repo",
        "workflow_path": workflow_path,
        "pull_requests": [],
        "run_created_at": GITHUB_CREATED_AT,
        "run_status": "completed",
        "run_conclusion": "success",
        "max_run_age_days": plan_completion_audit.MAX_GITHUB_RUN_AGE_DAYS,
        "artifact_name": "test-evidence",
        "evidence_reports": reports,
        "report_sha256": {
            report: hashlib.sha256((root / report).read_bytes()).hexdigest()
            for report in reports
        },
        "mismatches": [],
    }
    write_json(root / path, data)


def write_full_hostile_evidence(root: Path) -> None:
    full_types = [
        "windows_hardware_breakpoint",
        "windows_memory_breakpoint",
        "windows_dll_injection",
        "android_root",
        "android_xposed_lsposed",
        "android_frida_hook",
    ]
    write_json(root / "docs/qa/reports/hostile-environment.json", {
        "schema": "vmp.qa.hostile_environment.v1",
        "status": "pass",
        "real_trigger_types": full_types,
    })
    write_json(root / "docs/qa/reports/windows-hostile-triggers.json", {
        "schema": "vmp.platform.windows_hostile_triggers.v1",
        "status": "pass",
        "ci_execution": True,
        "github_actions": True,
        **github_metadata("platform-windows"),
        "runner_os": "Windows",
        "missing_required_external_triggers": [],
        "non_self_hardware_breakpoint_observed": True,
        "memory_page_breakpoint_observed": True,
        "external_debugger_observed": True,
        "external_dll_injection_observed": True,
        "findings": [
            {"signal": "external_hardware_dr_register"},
            {"signal": "guard_page_memory_breakpoint"},
            {"signal": "external_debugger_attached"},
            {"signal": "external_dll_injection"},
        ],
    })
    write_github_verification(
        root,
        "docs/qa/reports/windows-hostile-github-actions-verification.json",
        ["docs/qa/reports/windows-hostile-triggers.json"],
        "platform-windows",
    )
    write_json(root / "docs/qa/reports/android-hostile-triggers.json", {
        "schema": "vmp.platform.android_hostile_triggers.v1",
        "status": "pass",
        "ci_execution": True,
        "github_actions": True,
        **github_metadata("platform-android"),
        "authorized_hostile_profile": True,
        "hostile_profile_id": "authorized-profile-1",
        "device": {
            "adb_serial": "emulator-5554",
            "abi": "x86_64",
            "build_fingerprint": "test/fingerprint",
        },
        "missing_required_triggers": [],
        "findings": [
            {"category": "root", "signal": "su_or_magisk_path_present"},
            {"category": "hook_framework", "signal": "lsposed_module_present"},
            {"category": "hook_framework", "signal": "frida_hook_socket_present"},
        ],
    })
    write_github_verification(
        root,
        "docs/qa/reports/android-hostile-github-actions-verification.json",
        ["docs/qa/reports/android-hostile-triggers.json"],
        "platform-android",
    )


class PlanCompletionAuditTests(unittest.TestCase):
    def test_parses_plan_task_range(self):
        tasks, hard_acceptance = plan_completion_audit.parse_plan(ROOT / "plan" / "1.txt")
        task_ids = {task.task_id for task in tasks}

        self.assertEqual(len(tasks), 109)
        self.assertIn("T000", task_ids)
        self.assertIn("T155", task_ids)
        self.assertEqual(len(hard_acceptance), 10)

    def test_audit_does_not_read_passwd(self):
        original_read_text = Path.read_text

        def guarded_read_text(path, *args, **kwargs):
            self.assertNotEqual(path.name, "passwd.txt")
            return original_read_text(path, *args, **kwargs)

        try:
            Path.read_text = guarded_read_text
            report = plan_completion_audit.run_once(ROOT)
        finally:
            Path.read_text = original_read_text

        self.assertIn(report["status"], {"pass", "fail"})

    def test_explicit_doc_deliverable_maps_to_existing_path(self):
        task = plan_completion_audit.Task("T001", "main_agent", "", "`ARCHITECTURE.md`", "architecture exists")
        [result] = plan_completion_audit.task_results(ROOT, [task])

        self.assertEqual(result.status, "implemented")
        self.assertIn("docs/ARCHITECTURE.md", {item.value for item in result.evidence if item.exists})

    def test_official_source_list_maps_to_t005(self):
        task = plan_completion_audit.Task("T005", "main_agent", "", "联网资料清单", "official source list exists")
        [result] = plan_completion_audit.task_results(ROOT, [task])

        self.assertIn("docs/references/OFFICIAL_SOURCES.md", {item.value for item in result.evidence if item.exists})

    def test_manual_ida_task_is_manual_excluded(self):
        task = plan_completion_audit.Task("T153", "qa_agent", "", "anti-IDA/OllyDbg report", "人工复核通过")
        [result] = plan_completion_audit.task_results(ROOT, [task])

        self.assertEqual(result.status, "manual-excluded")

    def test_objective_requirements_need_review_and_parallel_agent_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review_dir = root / "docs/qa/reviews"
            review_dir.mkdir(parents=True)
            for index in range(1, 4):
                (review_dir / f"review-{index}.md").write_text(
                    "# Review\n\n"
                    "Review status: pass\n"
                    "Open vulnerabilities: 0\n"
                    "Open findings: 0\n",
                    encoding="utf-8",
                )
            run_dir = root / "docs/qa/agent-runs"
            run_dir.mkdir(parents=True)
            (run_dir / "parallel-run.md").write_text(
                "# Parallel Run\n\n"
                "Agent count: 3\n"
                "Parallel execution: yes\n"
                "No passwd.txt access: yes\n",
                encoding="utf-8",
            )

            results = plan_completion_audit.objective_requirement_results(root)

        self.assertEqual({result.item: result.status for result in results}, {
            "three_review_closure": "pass",
            "parallel_agent_execution": "pass",
        })

    def test_hard_acceptance_requires_generated_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src/platform/android").mkdir(parents=True)
            (root / "tests/platform").mkdir(parents=True)
            (root / "tests/platform/android_emulator_plan.sh").write_text("#!/bin/sh\n", encoding="utf-8")

            [result] = plan_completion_audit.hard_acceptance_results(
                root,
                [("Android", "protected APK or .so must run in an emulator")],
            )

        self.assertEqual(result.status, "blocker")
        self.assertIn("generated artifact/report evidence", "; ".join(result.notes))

    def test_ida_ollydbg_hard_acceptance_blocks_without_manual_review(self):
        [result] = plan_completion_audit.hard_acceptance_results(
            ROOT,
            [("IDA/OllyDbg", "automated indicators and human reverse-engineering review must pass")],
        )

        self.assertEqual(result.status, "blocker")
        self.assertIn("manual reverse-engineering review", "; ".join(result.notes))

    def test_ida_ollydbg_hard_acceptance_can_pass_with_manual_review_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "docs/qa/reports/ida-ollydbg-review.json", {
                "schema": "vmp.qa.manual_reverse_review.v1",
                "status": "pass",
                **github_metadata("manual-review"),
                "manual_review": True,
                "reviewer": "authorized-reviewer",
                "review_date": "2026-05-04",
                "tools": ["IDA", "OllyDbg"],
                "open_vulnerabilities": 0,
                "open_findings": 0,
                "reviewed_indicators": {
                    "f5_or_decompiler_distortion": True,
                    "xref_or_callgraph_distortion": True,
                    "string_reference_distortion": True,
                    "debugger_or_breakpoint_behavior": True,
                },
            })
            write_github_verification(
                root,
                "docs/qa/reports/ida-ollydbg-github-actions-verification.json",
                ["docs/qa/reports/ida-ollydbg-review.json"],
                "manual-review",
            )

            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False), live_github_verification(root, "manual-review"):
                [result] = plan_completion_audit.hard_acceptance_results(
                    root,
                    [("IDA/OllyDbg", "automated indicators and human reverse-engineering review must pass")],
                )

        self.assertEqual(result.status, "pass")

    def test_ci_hard_acceptance_does_not_pass_on_workflow_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github/workflows").mkdir(parents=True)
            (root / ".github/workflows/platform-windows.yml").write_text("name: platform-windows\n", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs/CI_SECRETS.md").write_text("secrets only\n", encoding="utf-8")
            (root / "acceptance.sh").write_text("#!/bin/sh\n", encoding="utf-8")

            [result] = plan_completion_audit.hard_acceptance_results(root, [("CI", "Windows/macOS runners and secrets")])

        self.assertEqual(result.status, "blocker")
        self.assertIn("generated artifact/report evidence", "; ".join(result.notes))

    def test_android_generated_report_without_emulator_still_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src/platform/android").mkdir(parents=True)
            (root / "tests/platform").mkdir(parents=True)
            (root / "docs/qa/reports").mkdir(parents=True)
            (root / "tests/platform/android_emulator_plan.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "tests/platform/android_environment_check.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "docs/qa/reports/AndroidEmulator.md").write_text("passed\n", encoding="utf-8")

            [result] = plan_completion_audit.hard_acceptance_results(
                root,
                [("Android", "protected APK or .so must run in an emulator")],
            )

        self.assertEqual(result.status, "blocker")
        self.assertIn("emulator execution", "; ".join(result.notes))

    def test_android_release_strength_gate_requires_secret_signed_ci_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = {
                "status": "pass",
                "github_actions": True,
                "ci_execution": True,
                **github_metadata("platform-android"),
                "release_signing_secret_used": True,
                "signing_key_scope": "github_secret_keystore",
                "manifest_debuggable": False,
                "protected_payload_embedded_in_jni": True,
                "protected_sample_asset_packaged": False,
                "apk_forbidden_plaintext_hits": [],
                "jni_symbol_plaintext_hits": [],
                "core_logic_consistent": True,
            }
            write_json(root / "docs/qa/reports/android-apk-smoke.json", report)
            so_report = {
                "status": "pass",
                "github_actions": True,
                "ci_execution": True,
                **github_metadata("platform-android"),
                "emulator_execution": True,
                "protected_so_loaded": True,
                "core_logic_consistent": True,
            }
            write_json(root / "docs/qa/reports/android-emulator-smoke.json", so_report)

            self.assertFalse(plan_completion_audit.android_release_strength_evidence_exists(root))

            write_github_verification(
                root,
                "docs/qa/reports/android-github-actions-verification.json",
                ["docs/qa/reports/android-apk-smoke.json", "docs/qa/reports/android-emulator-smoke.json"],
                "platform-android",
            )

            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False), live_github_verification(root, "platform-android"):
                self.assertTrue(plan_completion_audit.android_release_strength_evidence_exists(root))

            report["release_signing_secret_used"] = False
            write_json(root / "docs/qa/reports/android-apk-smoke.json", report)

            self.assertFalse(plan_completion_audit.android_release_strength_evidence_exists(root))

    def test_android_release_strength_gate_rejects_wrong_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = {
                "status": "pass",
                "github_actions": True,
                "ci_execution": True,
                **github_metadata("unrelated-workflow"),
                "release_signing_secret_used": True,
                "signing_key_scope": "github_secret_keystore",
                "manifest_debuggable": False,
                "protected_payload_embedded_in_jni": True,
                "protected_sample_asset_packaged": False,
                "apk_forbidden_plaintext_hits": [],
                "jni_symbol_plaintext_hits": [],
                "core_logic_consistent": True,
            }
            write_json(root / "docs/qa/reports/android-apk-smoke.json", report)
            so_report = {
                "status": "pass",
                "github_actions": True,
                "ci_execution": True,
                **github_metadata("unrelated-workflow"),
                "emulator_execution": True,
                "protected_so_loaded": True,
                "core_logic_consistent": True,
            }
            write_json(root / "docs/qa/reports/android-emulator-smoke.json", so_report)
            write_github_verification(
                root,
                "docs/qa/reports/android-github-actions-verification.json",
                ["docs/qa/reports/android-apk-smoke.json", "docs/qa/reports/android-emulator-smoke.json"],
                "unrelated-workflow",
            )

            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False), live_github_verification(root, "unrelated-workflow"):
                self.assertFalse(plan_completion_audit.android_release_strength_evidence_exists(root))

    def test_windows_gate_requires_github_actions_windows_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            acceptance = {
                "status": "pass",
                "ci_execution": True,
                "github_actions": True,
                **github_metadata("platform-windows"),
                "runner_os": "Windows",
                "smoke_exe_executed": True,
                "dll_load_executed": True,
                "artifacts": [
                    {"kind": "exe", "bytes": 1024, "path": "build/windows/vmp_platform_smoke.exe", "sha256": "b" * 64},
                    {"kind": "dll", "bytes": 2048, "path": "build/windows/vmp_platform.dll", "sha256": "c" * 64},
                ],
            }
            protected = {
                "status": "pass",
                "ci_execution": True,
                "github_actions": True,
                **github_metadata("platform-windows"),
                "runner_os": "Windows",
                "artifact_bytes": 4096,
                "artifact_sha256": "d" * 64,
                "behavior_cases_passed": 4,
                "forbidden_plaintext_hits": [],
            }
            write_json(root / "docs/qa/reports/windows-acceptance.json", acceptance)
            write_json(root / "docs/qa/reports/windows-protected-release.json", protected)
            write_github_verification(
                root,
                "docs/qa/reports/windows-github-actions-verification.json",
                [
                    "docs/qa/reports/windows-acceptance.json",
                    "docs/qa/reports/windows-protected-release.json",
                ],
                "platform-windows",
            )

            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False), live_github_verification(root, "platform-windows"):
                self.assertTrue(plan_completion_audit.windows_github_actions_evidence_exists(root))

            protected["github_run_id"] = "987654321"
            write_json(root / "docs/qa/reports/windows-protected-release.json", protected)

            self.assertFalse(plan_completion_audit.windows_github_actions_evidence_exists(root))

            protected["github_run_id"] = "123456789"
            protected["github_event_name"] = "pull_request"
            write_json(root / "docs/qa/reports/windows-protected-release.json", protected)

            self.assertFalse(plan_completion_audit.windows_github_actions_evidence_exists(root))

    def test_hostile_gate_requires_all_real_trigger_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_full_hostile_evidence(root)

            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False), live_github_verification(root, "platform-windows", "platform-android"):
                self.assertTrue(plan_completion_audit.hostile_full_coverage_exists(root))

            write_json(root / "docs/qa/reports/android-hostile-triggers.json", {
                "schema": "vmp.platform.android_hostile_triggers.v1",
                "status": "pass",
                "ci_execution": True,
                "github_actions": True,
                **github_metadata("platform-android"),
                "authorized_hostile_profile": True,
                "hostile_profile_id": "authorized-profile-1",
                "device": {
                    "adb_serial": "emulator-5554",
                    "abi": "x86_64",
                    "build_fingerprint": "test/fingerprint",
                },
                "missing_required_triggers": ["frida_or_hook_trigger"],
                "findings": [
                    {"category": "root", "signal": "su_or_magisk_path_present"},
                    {"category": "hook_framework", "signal": "lsposed_module_present"},
                ],
            })

            self.assertFalse(plan_completion_audit.hostile_full_coverage_exists(root))

    def test_hostile_gate_rejects_aggregate_without_platform_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_json(root / "docs/qa/reports/hostile-environment.json", {
                "schema": "vmp.qa.hostile_environment.v1",
                "status": "pass",
                "real_trigger_types": [
                    "windows_hardware_breakpoint",
                    "windows_memory_breakpoint",
                    "windows_dll_injection",
                    "android_root",
                    "android_xposed_lsposed",
                    "android_frida_hook",
                ],
            })

            self.assertFalse(plan_completion_audit.hostile_full_coverage_exists(root))

    def test_github_verification_rejects_pull_request_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = {
                "status": "pass",
                "github_actions": True,
                "ci_execution": True,
                **github_metadata("platform-android"),
            }
            report["github_event_name"] = "pull_request"
            write_json(root / "docs/qa/reports/android-apk-smoke.json", report)
            verification = {
                "schema": "vmp.qa.github_actions_verification.v1",
                "status": "pass",
                "github_api_verified": True,
                **github_metadata("platform-android"),
                "github_event_name": "pull_request",
                "run_status": "completed",
                "run_conclusion": "success",
                "evidence_reports": ["docs/qa/reports/android-apk-smoke.json"],
                "mismatches": [],
            }
            write_json(root / "docs/qa/reports/android-github-actions-verification.json", verification)

            self.assertFalse(plan_completion_audit.github_actions_verification_matches(
                root,
                "docs/qa/reports/android-github-actions-verification.json",
                [report],
                ["docs/qa/reports/android-apk-smoke.json"],
            ))

    def test_github_verification_requires_artifact_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = {
                "status": "pass",
                "github_actions": True,
                "ci_execution": True,
                **github_metadata("platform-android"),
            }
            write_json(root / "docs/qa/reports/android-apk-smoke.json", report)
            write_github_verification(
                root,
                "docs/qa/reports/android-github-actions-verification.json",
                ["docs/qa/reports/android-apk-smoke.json"],
                "platform-android",
            )
            verification_path = root / "docs/qa/reports/android-github-actions-verification.json"
            verification = json.loads(verification_path.read_text(encoding="utf-8"))
            verification.pop("artifact_name")
            write_json(verification_path, verification)

            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False), \
                mock.patch.object(plan_completion_audit, "fetch_github_run", return_value=github_api_run("platform-android")):
                self.assertFalse(plan_completion_audit.github_actions_verification_matches(
                    root,
                    "docs/qa/reports/android-github-actions-verification.json",
                    [report],
                    ["docs/qa/reports/android-apk-smoke.json"],
                    expected_workflow="platform-android",
                ))

    def test_android_hostile_gate_requires_device_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_full_hostile_evidence(root)
            report = json.loads((root / "docs/qa/reports/android-hostile-triggers.json").read_text(encoding="utf-8"))
            report["device"] = {}
            write_json(root / "docs/qa/reports/android-hostile-triggers.json", report)

            self.assertFalse(plan_completion_audit.android_hostile_full_coverage_exists(root))

    def test_vmprotect_tier_gate_requires_explicit_final_signoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_vmprotect_tier_reports(root, omit={"lowering", "crypto", "review"})

            self.assertFalse(plan_completion_audit.vmprotect_tier_evidence_exists(root))

            write_vmprotect_tier_reports(root)
            write_github_verification(
                root,
                "docs/qa/reports/vmprotect-tier-github-actions-verification.json",
                [
                    "docs/qa/reports/capability-matrix.json",
                    "docs/qa/reports/general-ir-lowering.json",
                    "docs/qa/reports/production-crypto-key-management.json",
                    "docs/qa/reports/vmprotect-tier-review.json",
                ],
                "vmprotect-tier",
            )

            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False), live_github_verification(root, "vmprotect-tier"):
                self.assertTrue(plan_completion_audit.vmprotect_tier_evidence_exists(root))

            write_json(root / "docs/qa/reports/capability-matrix.json", {
                "status": "blocked",
                "final_signoff_allowed": True,
            })

            self.assertFalse(plan_completion_audit.vmprotect_tier_evidence_exists(root))

    def test_vmprotect_tier_gate_rejects_each_missing_sidecar(self):
        for missing in ("lowering", "crypto", "review"):
            with self.subTest(missing=missing):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_vmprotect_tier_reports(root, omit={missing})

                    self.assertFalse(plan_completion_audit.vmprotect_tier_evidence_exists(root))

    def test_vmprotect_tier_gate_rejects_sidecar_field_failures(self):
        cases = (
            ("lowering", {"bounded_i32_only": True}),
            ("crypto", {"static_keys_present": True}),
            ("review", {"open_findings": 1}),
        )
        for report, patch in cases:
            with self.subTest(report=report):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    write_vmprotect_tier_reports(root, overrides={report: patch})
                    write_github_verification(
                        root,
                        "docs/qa/reports/vmprotect-tier-github-actions-verification.json",
                        [
                            "docs/qa/reports/capability-matrix.json",
                            "docs/qa/reports/general-ir-lowering.json",
                            "docs/qa/reports/production-crypto-key-management.json",
                            "docs/qa/reports/vmprotect-tier-review.json",
                        ],
                        "vmprotect-tier",
                    )

                    with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token"}, clear=False), live_github_verification(root, "vmprotect-tier"):
                        self.assertFalse(plan_completion_audit.vmprotect_tier_evidence_exists(root))


if __name__ == "__main__":
    unittest.main()
