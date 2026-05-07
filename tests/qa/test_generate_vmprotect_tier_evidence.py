import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class GenerateVMProtectTierEvidenceTests(unittest.TestCase):
    def test_generation_is_blocked_for_placeholder_pipeline_and_local_crypto(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_stage_manifest(root, placeholder_noops=True)
            write_source(root, bounded_i32=True, local_crypto=True, static_seed=True)

            result = run_generator(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("commercial-tier preconditions are not satisfied", result.stderr)
            capability = read_json(root / "docs/qa/reports/capability-matrix.json")
            lowering = read_json(root / "docs/qa/reports/general-ir-lowering.json")
            crypto = read_json(root / "docs/qa/reports/production-crypto-key-management.json")
            review = read_json(root / "docs/qa/reports/vmprotect-tier-review.json")
        self.assertEqual(capability["status"], "blocked")
        self.assertIs(capability["final_signoff_allowed"], False)
        self.assertEqual(lowering["status"], "blocked")
        self.assertIs(lowering["bounded_i32_only"], True)
        self.assertEqual(crypto["status"], "blocked")
        self.assertIs(crypto["production_crypto"], False)
        self.assertEqual(review["status"], "blocked")
        self.assertEqual(review["open_findings"], 1)

    def test_generation_can_pass_when_all_preconditions_are_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_stage_manifest(root, placeholder_noops=False)
            write_source(root, bounded_i32=False, local_crypto=False, static_seed=False)

            result = run_generator(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            capability = read_json(root / "docs/qa/reports/capability-matrix.json")
            lowering = read_json(root / "docs/qa/reports/general-ir-lowering.json")
            crypto = read_json(root / "docs/qa/reports/production-crypto-key-management.json")
            review = read_json(root / "docs/qa/reports/vmprotect-tier-review.json")
        self.assertEqual(capability["status"], "pass")
        self.assertIs(capability["final_signoff_allowed"], False)
        self.assertEqual(lowering["status"], "pass")
        self.assertIs(lowering["broad_ir_lowering"], True)
        self.assertIs(lowering["bounded_i32_only"], False)
        self.assertEqual(crypto["status"], "pass")
        self.assertIs(crypto["production_crypto"], True)
        self.assertIs(crypto["static_keys_present"], False)
        self.assertEqual(review["status"], "pass")
        self.assertEqual(review["open_findings"], 0)

    def test_trusted_vmprotect_workflow_allows_final_signoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_stage_manifest(root, placeholder_noops=False)
            write_source(root, bounded_i32=False, local_crypto=False, static_seed=False)

            result = run_generator(
                root,
                env={
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_WORKFLOW": "vmprotect-tier",
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
                    "GITHUB_RUN_ID": "123",
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_REF_NAME": "main",
                    "GITHUB_REF_PROTECTED": "true",
                    "GITHUB_SERVER_URL": "https://github.com",
                    "RUNNER_NAME": "runner",
                    "RUNNER_OS": "Linux",
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            capability = read_json(root / "docs/qa/reports/capability-matrix.json")
        self.assertEqual(capability["status"], "pass")
        self.assertIs(capability["final_signoff_allowed"], True)


def run_generator(root: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    merged_env = None if env is None else {**os.environ, **env}
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/audit/generate_vmprotect_tier_evidence.py"), "--root", str(root)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=merged_env,
    )


def write_stage_manifest(root: Path, *, placeholder_noops: bool) -> None:
    stages = [
        {"name": "vmp-ir-to-bytecode", "kind": "lowering", "implemented": True},
        {"name": "vmp-function-replacement", "kind": "replacement", "implemented": True},
    ]
    if placeholder_noops:
        stages.append({"name": "vmp-flatten", "kind": "placeholder_noop", "implemented": False})
    write_json(root / "tests/core/.llvm-out/vmp-stage-manifest.json", {
        "schema": "vmp.llvm.stage_manifest.v1",
        "stages": stages,
    })


def write_source(root: Path, *, bounded_i32: bool, local_crypto: bool, static_seed: bool) -> None:
    plugin_text = []
    if bounded_i32:
        plugin_text.append("bool supportsReplacementStub() { return true; }")
    if static_seed:
        plugin_text.append('constexpr char kDefaultRuntimeSeed[] = "test";')
    write_text(root / "src/core/llvm/VMPPassPlugin.cpp", "\n".join(plugin_text))

    crypto_text = "AEAD production seal"
    if local_crypto:
        crypto_text += "\nvoid xorStream();\nvoid stableHash64();"
    write_text(root / "src/core/Bytecode.cpp", crypto_text)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
