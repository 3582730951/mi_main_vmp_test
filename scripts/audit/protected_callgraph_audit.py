#!/usr/bin/env python3
"""Audit protected-function xrefs and high-frequency callsite optimization."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_ORIGINAL_IR = "tests/core/.llvm-out/hotspot-callsite.ll"
DEFAULT_PROTECTED_IR = "tests/core/.llvm-out/hotspot-callsite.protected.ll"
DEFAULT_LOG = "tests/core/.llvm-out/hotspot-callsite.log"
DEFAULT_CONFIG = "tests/core/.llvm-out/hotspot-callsite.yml"
DEFAULT_OUTPUT = "docs/qa/reports/protected-callgraph.json"

NAME = r'(?:"(?P<quoted>[^"]+)"|(?P<plain>[A-Za-z_$.-][A-Za-z0-9_$.-]*))'
DEFINE_RE = re.compile(rf"^define\b.*@{NAME}\(")
CALL_RE = re.compile(rf"\bcall\b[^@]*@{NAME}\(")
HOTSPOT_RE = re.compile(
    r"^VMPPassPlugin hotspot: function=(?P<function>\S+) "
    r"call_sites=(?P<call_sites>\d+) vm_level=(?P<vm_level>\d+)$"
)
REWRITTEN_RE = re.compile(r"^VMPPassPlugin callsite_obfuscation: rewritten_calls=(?P<count>\d+)$")
UNIQUE_THUNKS_RE = re.compile(r"^VMPPassPlugin callsite_obfuscation: unique_thunks=(?P<count>\d+)$")


def matched_name(match: re.Match[str]) -> str:
    return match.group("quoted") or match.group("plain")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_ir(text: str) -> dict[str, Any]:
    functions: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    protected: set[str] = set()
    replaced: set[str] = set()
    hidden: set[str] = set()
    current: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        define = DEFINE_RE.search(line)
        if define:
            current = matched_name(define)
            functions.setdefault(current, {"name": current})
            if "!vmp.protect" in line:
                protected.add(current)
            if "!vmp.replaced" in line:
                replaced.add(current)
            if line.startswith("define hidden "):
                hidden.add(current)
        elif line == "}":
            current = None
            continue

        if current is None:
            continue
        for call in CALL_RE.finditer(line):
            edges.append({"caller": current, "callee": matched_name(call)})

    return {
        "functions": functions,
        "edges": edges,
        "protected_functions": sorted(protected),
        "replaced_functions": sorted(replaced),
        "hidden_functions": sorted(hidden),
    }


def parse_hotspot_config(text: str) -> dict[str, Any]:
    section = ""
    config: dict[str, Any] = {
        "enabled": False,
        "call_site_threshold": 3,
        "hot_vm_level": 1,
        "defense_floor": 1,
        "preserve_explicit_vm_level": True,
    }
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.endswith(":") and ":" not in line[:-1]:
            section = line[:-1]
            continue
        if section != "hotspot_analysis" or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        if key in {"call_site_threshold", "hot_vm_level", "defense_floor"}:
            try:
                config[key] = int(value)
            except ValueError:
                config[key] = value
        elif key in {"enabled", "preserve_explicit_vm_level"}:
            config[key] = value.lower() == "true"
    return config


def parse_log(text: str) -> dict[str, Any]:
    hotspots: dict[str, dict[str, int]] = {}
    rewritten_calls = 0
    unique_thunks = 0
    for line in text.splitlines():
        hotspot = HOTSPOT_RE.match(line.strip())
        if hotspot:
            hotspots[hotspot.group("function")] = {
                "call_sites": int(hotspot.group("call_sites")),
                "vm_level": int(hotspot.group("vm_level")),
            }
            continue
        rewritten = REWRITTEN_RE.match(line.strip())
        if rewritten:
            rewritten_calls = int(rewritten.group("count"))
            continue
        thunks = UNIQUE_THUNKS_RE.match(line.strip())
        if thunks:
            unique_thunks = int(thunks.group("count"))
    return {
        "hotspots": hotspots,
        "rewritten_calls": rewritten_calls,
        "unique_thunks": unique_thunks,
    }


def inbound_callers(edges: list[dict[str, str]], target: str) -> dict[str, int]:
    counts = Counter(edge["caller"] for edge in edges if edge["callee"] == target)
    return dict(sorted(counts.items()))


def count_inbound(edges: list[dict[str, str]], target: str) -> int:
    return sum(1 for edge in edges if edge["callee"] == target)


def build_report(root: Path, original_ir: Path, protected_ir: Path, log: Path, config: Path) -> dict[str, Any]:
    original = parse_ir(read_text(original_ir))
    protected = parse_ir(read_text(protected_ir))
    hotspot_config = parse_hotspot_config(read_text(config))
    log_data = parse_log(read_text(log))

    protected_functions = set(protected["protected_functions"])
    if not protected_functions:
        protected_functions = {
            function
            for function, detail in log_data["hotspots"].items()
            if detail.get("call_sites", 0) >= int(hotspot_config.get("call_site_threshold", 1))
        }

    function_reports = []
    total_original_direct = 0
    total_protected_direct = 0
    defense_floor = int(hotspot_config.get("defense_floor", 1))
    high_frequency_policy_applied = False
    defense_floor_preserved = True

    for function in sorted(protected_functions):
        original_count = count_inbound(original["edges"], function)
        protected_count = count_inbound(protected["edges"], function)
        total_original_direct += original_count
        total_protected_direct += protected_count
        hotspot = log_data["hotspots"].get(function, {})
        if hotspot:
            high_frequency_policy_applied = True
            defense_floor_preserved = defense_floor_preserved and int(hotspot.get("vm_level", 0)) >= defense_floor
        function_reports.append(
            {
                "name": function,
                "original_direct_callsite_count": original_count,
                "original_direct_callers": inbound_callers(original["edges"], function),
                "protected_direct_callsite_count": protected_count,
                "protected_direct_callers": inbound_callers(protected["edges"], function),
                "hidden_visibility": function in protected["hidden_functions"],
                "replaced": function in protected["replaced_functions"],
                "hotspot": {
                    "applied": bool(hotspot),
                    "call_sites": hotspot.get("call_sites"),
                    "vm_level": hotspot.get("vm_level"),
                    "defense_floor": defense_floor,
                    "speed_policy_without_defense_drop": bool(hotspot)
                    and int(hotspot.get("vm_level", 0)) >= defense_floor,
                },
            }
        )

    thunk_edges = [edge for edge in protected["edges"] if edge["callee"].startswith("vmp.call.thunk.")]
    analysis = {
        "protected_xrefs_discovered": total_original_direct > 0,
        "direct_protected_xrefs_removed": total_original_direct > 0 and total_protected_direct == 0,
        "high_frequency_policy_applied": high_frequency_policy_applied,
        "defense_floor_preserved": defense_floor_preserved,
        "per_callsite_thunks_preserved": log_data["unique_thunks"] >= total_original_direct > 0,
    }
    status = "pass" if all(analysis.values()) else "fail"
    return {
        "schema": "vmp.qa.protected_callgraph.v1",
        "status": status,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {
            "original_ir": original_ir.relative_to(root).as_posix() if original_ir.is_relative_to(root) else str(original_ir),
            "protected_ir": protected_ir.relative_to(root).as_posix()
            if protected_ir.is_relative_to(root)
            else str(protected_ir),
            "log": log.relative_to(root).as_posix() if log.is_relative_to(root) else str(log),
            "config": config.relative_to(root).as_posix() if config.is_relative_to(root) else str(config),
        },
        "hotspot_config": hotspot_config,
        "protected_functions": function_reports,
        "callsite_obfuscation": {
            "rewritten_calls": log_data["rewritten_calls"],
            "unique_thunks": log_data["unique_thunks"],
            "protected_thunk_call_edges": len(thunk_edges),
            "protected_thunk_targets": sorted({edge["callee"] for edge in thunk_edges}),
        },
        "analysis": analysis,
        "policy_note": (
            "The audit intentionally uses compiler IR evidence for authorized protector QA. "
            "It detects direct protected-function xrefs before replacement, verifies their removal after thunking, "
            "and checks that hot-callsite speed policy never drops below the configured defense floor."
        ),
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--original-ir", default=DEFAULT_ORIGINAL_IR)
    parser.add_argument("--protected-ir", default=DEFAULT_PROTECTED_IR)
    parser.add_argument("--log", default=DEFAULT_LOG)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = build_report(
        root,
        (root / args.original_ir).resolve(),
        (root / args.protected_ir).resolve(),
        (root / args.log).resolve(),
        (root / args.config).resolve(),
    )
    write_json(root / args.output, report)
    analysis = report["analysis"]
    print(
        "protected callgraph "
        f"{report['status']}: xrefs_discovered={analysis['protected_xrefs_discovered']} "
        f"direct_xrefs_removed={analysis['direct_protected_xrefs_removed']} "
        f"high_frequency_policy={analysis['high_frequency_policy_applied']}"
    )
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
