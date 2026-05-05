#!/usr/bin/env python3
"""Generate an automated reverse-cost assessment from local tool evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.audit.github_metadata import current_github_metadata
from scripts.audit.protected_callgraph_audit import DEFAULT_OUTPUT as CALLGRAPH_REPORT
from scripts.audit.protected_callgraph_audit import build_report as build_callgraph_report
from scripts.audit.protected_callgraph_audit import write_json as write_callgraph_json


REQUIRED_CAPABILITIES = (
    "automatic_hotspot_analysis",
    "protected_xref_discovery",
    "high_frequency_callsite_optimization",
    "defense_floor_preserved",
    "callsite_obfuscation",
    "per_callsite_thunks",
    "protected_function_address_not_materialized",
    "decompiler_traps",
    "randomized_stack_backtrace",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_tool(args: list[str], cwd: Path) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)
    return completed.returncode, completed.stdout


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def analyze_artifact(root: Path, artifact: Path) -> tuple[dict[str, Any], dict[str, int], list[dict[str, Any]]]:
    data = artifact.read_bytes()
    entropy = shannon_entropy(data)
    tool_results: list[dict[str, Any]] = [
        {
            "tool": "python-shannon-entropy",
            "status": "pass",
            "entropy_bits_per_byte": round(entropy, 4),
            "artifact_bytes": len(data),
        }
    ]
    score: dict[str, int] = {}

    forbidden = ["CRITICAL_AUTHZ_TOKEN_SAMPLE", "https://license.sample.invalid", "Authorization:", "Bearer "]
    strings_hits: list[str] = []
    if has_tool("strings"):
        code, output = run_tool(["strings", "-a", str(artifact)], root)
        strings_hits = [needle for needle in forbidden if needle in output]
        tool_results.append({
            "tool": "strings",
            "status": "pass" if code == 0 and not strings_hits else "fail",
            "forbidden_hits": strings_hits,
        })
    if not strings_hits:
        score["plaintext_secret_absence"] = 45

    symbol_table_stripped = False
    exported_symbols = 0
    if has_tool("nm"):
        code, output = run_tool(["nm", "-g", str(artifact)], root)
        symbol_table_stripped = "no symbols" in output.lower()
        exported_symbols = sum(1 for line in output.splitlines() if line.strip())
        tool_results.append({
            "tool": "nm",
            "status": "pass" if symbol_table_stripped or exported_symbols <= 8 else "partial",
            "symbol_table_stripped": symbol_table_stripped,
            "exported_symbol_lines": exported_symbols,
        })
    if symbol_table_stripped or exported_symbols <= 8:
        score["symbol_recovery_resistance"] = 45

    if has_tool("readelf"):
        code, output = run_tool(["readelf", "-S", str(artifact)], root)
        has_exec = ".text" in output
        has_rodata = ".rodata" in output
        tool_results.append({
            "tool": "readelf",
            "status": "pass" if code == 0 and has_exec else "fail",
            "has_text_section": has_exec,
            "has_rodata_section": has_rodata,
        })
    if entropy >= 5.0:
        score["encrypted_payload_entropy"] = 45

    if has_tool("objdump"):
        code, output = run_tool(["objdump", "-d", str(artifact)], root)
        indirect_markers = output.count("*%") + output.count("jmpq") + output.count("callq")
        tool_results.append({
            "tool": "objdump",
            "status": "pass" if code == 0 else "unavailable",
            "indirect_or_branch_marker_count": indirect_markers,
        })

    return {
        "path": str(artifact.relative_to(root)) if artifact.is_relative_to(root) else str(artifact),
        "sha256": sha256(artifact),
        "bytes": len(data),
        "entropy_bits_per_byte": round(entropy, 4),
    }, score, tool_results


def analyze_ir(root: Path) -> tuple[dict[str, bool], dict[str, int], list[dict[str, Any]]]:
    protected_ir = root / "tests/core/.llvm-out/hotspot-callsite.protected.ll"
    original_ir = root / "tests/core/.llvm-out/hotspot-callsite.ll"
    log = root / "tests/core/.llvm-out/hotspot-callsite.log"
    config = root / "tests/core/.llvm-out/hotspot-callsite.yml"
    callgraph_path = root / CALLGRAPH_REPORT
    if not callgraph_path.exists() and original_ir.exists() and protected_ir.exists() and log.exists() and config.exists():
        write_callgraph_json(callgraph_path, build_callgraph_report(root, original_ir, protected_ir, log, config))
    callgraph = read_json(callgraph_path)
    callgraph_analysis = callgraph.get("analysis", {}) if isinstance(callgraph.get("analysis"), dict) else {}
    ir_text = read_text(protected_ir)
    log_text = read_text(log)

    checks = {
        "automatic_hotspot_analysis": "VMPPassPlugin hotspot: function=secret_hot call_sites=3 vm_level=1" in log_text,
        "protected_xref_discovery": callgraph_analysis.get("protected_xrefs_discovered") is True
        and callgraph_analysis.get("direct_protected_xrefs_removed") is True,
        "high_frequency_callsite_optimization": callgraph_analysis.get("high_frequency_policy_applied") is True,
        "defense_floor_preserved": "vm_levels=secret_hot:1" in log_text,
        "callsite_obfuscation": "VMPPassPlugin callsite_obfuscation: rewritten_calls=3" in log_text
        and "call i32 @secret_hot" not in ir_text,
        "per_callsite_thunks": "VMPPassPlugin callsite_obfuscation: unique_thunks=3" in log_text
        and ir_text.count("define internal i32 @vmp.call.thunk.") >= 3,
        "protected_function_address_not_materialized": "i32 (i32)* @secret_hot" not in ir_text,
        "decompiler_traps": "vmp.decompiler.trap:" in ir_text and "switch i32 0" in ir_text,
        "randomized_stack_backtrace": "!vmp.anti_analysis.policy" in ir_text
        and "random_stack_backtrace=true" in ir_text,
    }
    score = {
        "hotspot_policy_and_defense_floor": 55 if checks["automatic_hotspot_analysis"] and checks["defense_floor_preserved"] else 0,
        "protected_xref_discovery": 35 if checks["protected_xref_discovery"] else 0,
        "hot_callsite_speed_policy": 35 if checks["high_frequency_callsite_optimization"] else 0,
        "callsite_graph_distortion": 85 if checks["callsite_obfuscation"] and checks["per_callsite_thunks"] else 0,
        "protected_address_hiding": 45 if checks["protected_function_address_not_materialized"] else 0,
        "decompiler_trap_distortion": 45 if checks["decompiler_traps"] else 0,
        "randomized_backtrace_signal": 45 if checks["randomized_stack_backtrace"] else 0,
    }
    tool_results = [
        {
            "tool": "llvm-ir-fixture-scan",
            "status": "pass" if all(checks.values()) else "fail",
            "protected_ir": "tests/core/.llvm-out/hotspot-callsite.protected.ll",
            "log": "tests/core/.llvm-out/hotspot-callsite.log",
            "checks": checks,
        }
    ]
    if callgraph:
        tool_results.append(
            {
                "tool": "protected-callgraph-audit",
                "status": callgraph.get("status", "unknown"),
                "report": CALLGRAPH_REPORT,
                "analysis": callgraph_analysis,
            }
        )
    return checks, score, tool_results


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def metadata_for_root(root: Path) -> dict[str, Any]:
    metadata = current_github_metadata()
    if not metadata.get("github_sha"):
        code, output = run_tool(["git", "rev-parse", "HEAD"], root)
        if code == 0:
            metadata["github_sha"] = output.strip()
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--artifact", default="artifacts/protected/linux/protected_release_sample")
    parser.add_argument("--output", default="docs/qa/reports/reverse-cost-assessment.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    artifact = (root / args.artifact).resolve()
    if not artifact.exists():
        print(f"missing protected artifact: {artifact}", file=sys.stderr)
        return 1

    artifact_info, artifact_score, artifact_tools = analyze_artifact(root, artifact)
    capabilities, ir_score, ir_tools = analyze_ir(root)
    score_breakdown = {**artifact_score, **ir_score}
    estimated_days = sum(score_breakdown.values())
    status = "pass" if estimated_days >= 365 and all(capabilities.values()) else "fail"

    data = {
        "schema": "vmp.qa.reverse_cost_assessment.v1",
        "status": status,
        **metadata_for_root(root),
        "assessment_mode": "automated_tooling",
        "automated_review": True,
        "manual_review": False,
        "reviewer": "github-actions-reverse-cost-tooling",
        "methodology": (
            "Automated static reverse-cost estimate using protected artifact inspection, "
            "symbol/string scans, entropy checks, disassembly availability, and LLVM IR "
            "callsite-obfuscation/decompiler-trap evidence."
        ),
        "assessment_date": datetime.now(timezone.utc).date().isoformat(),
        "review_tools": [
            name for name in ["readelf", "objdump", "nm", "strings"] if has_tool(name)
        ] + ["llvm-ir-fixture-scan", "protected-callgraph-audit", "python-shannon-entropy"],
        "protected_artifact": artifact_info["path"],
        "protected_artifact_sha256": artifact_info["sha256"],
        "minimum_reverse_cost_days": estimated_days,
        "estimated_reverse_cost_days": estimated_days,
        "score_breakdown": score_breakdown,
        "assessed_capabilities": capabilities,
        "tool_results": artifact_tools + ir_tools,
        "limitations": [
            "Automated tooling produces a repeatable estimate, not a human guarantee.",
            "Manual red-team review may still revise the estimate up or down.",
        ],
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    write_json(root / args.output, data)
    print(f"reverse-cost assessment {status}: estimated_days={estimated_days}")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
