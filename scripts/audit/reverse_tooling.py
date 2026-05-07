#!/usr/bin/env python3
"""Optional adapters for GitHub-hosted reverse-analysis tooling.

The local gate must keep working without large reverse-engineering packages
installed. These adapters therefore report unavailable tools explicitly instead
of making optional dependencies part of the trusted acceptance base.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


GITHUB_TOOL_SOURCES: tuple[dict[str, str], ...] = (
    {
        "tool": "lief",
        "github": "https://github.com/lief-project/LIEF",
        "purpose": "Parse PE, ELF, and Mach-O metadata for protected artifact surface checks.",
    },
    {
        "tool": "capa",
        "github": "https://github.com/mandiant/capa",
        "purpose": "Scan executable capability patterns with the FLARE capa ruleset.",
    },
    {
        "tool": "angr",
        "github": "https://github.com/angr/angr",
        "purpose": "Optional CFG/callgraph exploration when the heavy Python analysis stack is installed.",
    },
    {
        "tool": "radare2",
        "github": "https://github.com/radareorg/radare2",
        "purpose": "Optional executable disassembly, xref, and function graph analysis backend.",
    },
    {
        "tool": "radare2-r2pipe",
        "github": "https://github.com/radareorg/radare2-r2pipe",
        "purpose": "Optional scriptable xref/callgraph extraction when radare2 is installed.",
    },
    {
        "tool": "rizin",
        "github": "https://github.com/rizinorg/rizin",
        "purpose": "Optional executable disassembly, xref, and function graph analysis backend.",
    },
    {
        "tool": "ghidra",
        "github": "https://github.com/NationalSecurityAgency/ghidra",
        "purpose": "Optional headless function, xref, and callgraph inventory backend.",
    },
    {
        "tool": "capa-rules",
        "github": "https://github.com/mandiant/capa-rules",
        "purpose": "Optional capability rule corpus used when capa is available.",
    },
    {
        "tool": "floss",
        "github": "https://github.com/mandiant/flare-floss",
        "purpose": "Optional recovered-string scan for stack, tight, decoded, and static strings.",
    },
)

FORBIDDEN_RECOVERED_STRINGS = (
    "CRITICAL_AUTHZ_TOKEN_SAMPLE",
    "https://license.sample.invalid",
    "Authorization:",
    "Bearer ",
    "VMPBC",
    "VMPSAM",
    "VMPIRL",
    "OLLVM",
    "libvmp",
    "vmp_platform",
    "vmp_smoke",
    "vmp-smoke",
    "com.vmp",
    "com/vmp",
    "VMPRELEA",
    "VMP Release",
    "VMP Smoke",
)

FLOSS_STRING_CATEGORIES = (
    "static_strings",
    "stack_strings",
    "tight_strings",
    "decoded_strings",
    "language_strings",
)


def python_module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def unavailable(tool: str, reason: str) -> dict[str, Any]:
    return {
        "tool": tool,
        "status": "unavailable",
        "reason": reason,
    }


def bounded_list(values: list[str], limit: int = 12) -> dict[str, Any]:
    return {
        "count": len(values),
        "sample": values[:limit],
        "truncated": len(values) > limit,
    }


def safe_iter(value: Any) -> list[Any]:
    if value is None:
        return []
    try:
        return list(value)
    except TypeError:
        return []


def object_name(value: Any) -> str:
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="backslashreplace")
    try:
        return str(value)
    except UnicodeDecodeError:
        return repr(value)


def object_address(value: Any) -> int | None:
    for attr in ("addr", "address", "offset"):
        raw = getattr(value, attr, None)
        if isinstance(raw, int):
            return raw
    if isinstance(value, int):
        return value
    return None


def bounded_edges(edges: list[dict[str, str]], limit: int = 12) -> dict[str, Any]:
    return {
        "count": len(edges),
        "sample": edges[:limit],
        "truncated": len(edges) > limit,
    }


def callgraph_metrics(edges: list[dict[str, str]], hot_threshold: int | None = None) -> dict[str, Any]:
    threshold = hot_threshold if hot_threshold is not None else int(os.environ.get("VMP_CALLGRAPH_HOT_THRESHOLD", "3"))
    callers = Counter(edge["caller"] for edge in edges if edge.get("caller"))
    callees = Counter(edge["callee"] for edge in edges if edge.get("callee"))
    hot_callees = [
        {"callee": callee, "call_sites": count}
        for callee, count in sorted(callees.items(), key=lambda item: (-item[1], item[0]))
        if count >= threshold
    ]
    return {
        "call_edge_count": len(edges),
        "unique_callers": len(callers),
        "unique_callees": len(callees),
        "max_out_degree": max(callers.values(), default=0),
        "max_in_degree": max(callees.values(), default=0),
        "hot_threshold": threshold,
        "high_frequency_callees": {
            "count": len(hot_callees),
            "sample": hot_callees[:12],
            "truncated": len(hot_callees) > 12,
        },
    }


def radare2_command() -> str | None:
    for name in ("r2", "radare2"):
        command = shutil.which(name)
        if command:
            return command
    return None


def rizin_command() -> str | None:
    for name in ("rizin", "rz"):
        command = shutil.which(name)
        if command:
            return command
    return None


def ghidra_headless_command() -> str | None:
    configured = os.environ.get("GHIDRA_HEADLESS")
    if configured and Path(configured).exists():
        return configured
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        candidate = Path(ghidra_home) / "support" / "analyzeHeadless"
        if candidate.exists():
            return str(candidate)
    return shutil.which("analyzeHeadless")


def analyze_with_lief(artifact: Path) -> dict[str, Any]:
    if not python_module_available("lief"):
        return unavailable("lief", "Python module is not installed")

    try:
        import lief  # type: ignore[import-not-found]

        binary = lief.parse(str(artifact))
    except Exception as error:  # pragma: no cover - exact LIEF failures are version-specific
        return {
            "tool": "lief",
            "status": "unavailable",
            "reason": f"parse failed: {error}",
        }
    if binary is None:
        return unavailable("lief", "artifact format was not recognized")

    sections = [object_name(section) for section in safe_iter(getattr(binary, "sections", None))]
    symbols = [object_name(symbol) for symbol in safe_iter(getattr(binary, "symbols", None))]
    imported = [object_name(function) for function in safe_iter(getattr(binary, "imported_functions", None))]
    exported = [object_name(function) for function in safe_iter(getattr(binary, "exported_functions", None))]
    libraries = [object_name(library) for library in safe_iter(getattr(binary, "libraries", None))]
    image_format = str(getattr(binary, "format", type(binary).__name__))

    return {
        "tool": "lief",
        "status": "pass" if len(exported) <= 8 else "partial",
        "format": image_format,
        "entrypoint": getattr(binary, "entrypoint", None),
        "sections": bounded_list(sections),
        "symbols": {"count": len(symbols)},
        "imports": bounded_list(imported),
        "exports": bounded_list(exported),
        "libraries": bounded_list(libraries),
    }


def run_command(args: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)
    return completed.returncode, completed.stdout


def parse_json_payload(output: str) -> Any:
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("[", "]"), ("{", "}")):
        start = output.find(opener)
        end = output.rfind(closer)
        if 0 <= start < end:
            try:
                return json.loads(output[start : end + 1])
            except json.JSONDecodeError:
                continue
    return None


def capa_command() -> list[str] | None:
    command = shutil.which("capa")
    if command:
        return [command]
    if python_module_available("capa"):
        return [sys.executable, "-m", "capa.main"]
    return None


def capa_rules_path() -> str | None:
    configured = os.environ.get("CAPA_RULES")
    if configured and Path(configured).exists():
        return configured
    default = Path("/tmp/capa-rules")
    if default.exists():
        return str(default)
    return None


def floss_command() -> list[str] | None:
    command = shutil.which("floss")
    if command:
        return [command]
    return None


def summarize_capa_json(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"matched_rules": bounded_list([]), "json_parse_error": True}

    rules = data.get("rules") if isinstance(data, dict) else None
    matched: list[str] = []
    if isinstance(rules, dict):
        for name, detail in rules.items():
            if isinstance(detail, dict) and detail.get("matches"):
                matched.append(str(name))
    elif isinstance(data, dict) and isinstance(data.get("matches"), dict):
        matched = [str(name) for name in data["matches"]]

    meta = data.get("meta") if isinstance(data, dict) and isinstance(data.get("meta"), dict) else {}
    return {
        "matched_rules": bounded_list(sorted(matched)),
        "analysis": meta.get("analysis", {}) if isinstance(meta, dict) else {},
    }


def floss_entry_string(entry: Any) -> str | None:
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return None
    for key in ("string", "value", "decoded_string"):
        value = entry.get(key)
        if isinstance(value, str):
            return value
    return None


def summarize_floss_json(text: str) -> dict[str, Any]:
    if not text.strip():
        return {
            "recovered_string_counts": {category: 0 for category in FLOSS_STRING_CATEGORIES},
            "total_recovered_strings": 0,
            "forbidden_recovered_hits": [],
            "empty_output": True,
            "raw_values_recorded": False,
        }

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {
            "recovered_string_counts": {},
            "total_recovered_strings": 0,
            "forbidden_recovered_hits": sorted(
                needle for needle in FORBIDDEN_RECOVERED_STRINGS if needle in text
            ),
            "json_parse_error": True,
            "raw_values_recorded": False,
        }

    strings_root = data.get("strings") if isinstance(data, dict) else None
    if not isinstance(strings_root, dict):
        return {
            "recovered_string_counts": {},
            "total_recovered_strings": 0,
            "forbidden_recovered_hits": [],
            "raw_values_recorded": False,
        }

    counts: dict[str, int] = {}
    hits: set[str] = set()
    for category in FLOSS_STRING_CATEGORIES:
        entries = strings_root.get(category, [])
        values = []
        for entry in safe_iter(entries):
            value = floss_entry_string(entry)
            if value is None:
                continue
            values.append(value)
            for needle in FORBIDDEN_RECOVERED_STRINGS:
                if needle in value:
                    hits.add(needle)
        counts[category] = len(values)

    return {
        "recovered_string_counts": counts,
        "total_recovered_strings": sum(counts.values()),
        "forbidden_recovered_hits": sorted(hits),
        "raw_values_recorded": False,
    }


def analyze_with_capa(root: Path, artifact: Path) -> dict[str, Any]:
    command = capa_command()
    if command is None:
        return unavailable("capa", "capa command or Python module is not installed")

    args = [*command, "-j"]
    rules = capa_rules_path()
    if rules:
        args.extend(["-r", rules])
    args.append(str(artifact))

    code, output = run_command(args, root, timeout=120)
    if code != 0:
        return {
            "tool": "capa",
            "status": "unavailable",
            "reason": "capa could not analyze this artifact",
            "exit_code": code,
            "output_excerpt": output[:800],
            "rules": rules,
        }

    return {
        "tool": "capa",
        "status": "pass",
        "rules": rules,
        **summarize_capa_json(output),
    }


def analyze_with_floss(root: Path, artifact: Path) -> dict[str, Any]:
    command = floss_command()
    if command is None:
        return unavailable("floss", "FLOSS command is not installed")

    max_bytes = int(os.environ.get("VMP_FLOSS_MAX_BYTES", "50000000"))
    try:
        artifact_size = artifact.stat().st_size
    except OSError as error:
        return unavailable("floss", f"artifact could not be stat'ed: {error}")
    if artifact_size > max_bytes:
        return unavailable("floss", f"artifact exceeds bounded string-recovery size limit: {artifact_size}>{max_bytes}")

    code, output = run_command([*command, "-j", str(artifact)], root, timeout=180)
    if code != 0:
        return {
            "tool": "floss",
            "status": "unavailable",
            "reason": "FLOSS could not analyze this artifact",
            "exit_code": code,
            "output_excerpt": output[:800],
        }

    summary = summarize_floss_json(output)
    hits = summary.get("forbidden_recovered_hits", [])
    total = int(summary.get("total_recovered_strings", 0))
    if hits:
        status = "fail"
    elif summary.get("json_parse_error") is True:
        return {
            "tool": "floss",
            "status": "unavailable",
            "reason": "FLOSS did not emit machine-readable JSON",
            "output_excerpt": output[:800],
            **summary,
        }
    elif total:
        status = "partial"
    else:
        status = "pass"
    return {
        "tool": "floss",
        "status": status,
        **summary,
    }


def r2_call_edges(functions: list[Any]) -> list[dict[str, str]]:
    by_offset: dict[int, str] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        offset = function.get("offset")
        name = function.get("name")
        if isinstance(offset, int) and isinstance(name, str):
            by_offset[offset] = name

    edges: list[dict[str, str]] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        caller = str(function.get("name") or hex(function.get("offset", 0)))
        for ref in safe_iter(function.get("callrefs")):
            if not isinstance(ref, dict):
                continue
            ref_type = str(ref.get("type", "")).lower()
            if ref_type and "call" not in ref_type and ref_type not in {"c", "code"}:
                continue
            target = None
            for key in ("addr", "to", "target", "jump"):
                value = ref.get(key)
                if isinstance(value, int):
                    target = value
                    break
            if target is None:
                continue
            callee = by_offset.get(target, hex(target))
            edges.append({"caller": caller, "callee": callee})
    return edges


def radare2_graph_edges(graph: Any) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    for function in safe_iter(graph):
        if not isinstance(function, dict):
            continue
        caller = function.get("name")
        if not isinstance(caller, str):
            continue
        for callee in safe_iter(function.get("imports")):
            if isinstance(callee, str):
                edges.append({"caller": caller, "callee": callee})
    return edges


def analyze_with_radare2(root: Path, artifact: Path) -> dict[str, Any]:
    command = radare2_command()
    if command is None:
        return unavailable("radare2-r2pipe", "radare2 command is not installed")

    code, output = run_command(
        [command, "-q", "-2", "-A", "-c", "aflj", "-c", "q", str(artifact)],
        root,
        timeout=120,
    )
    if code != 0:
        return {
            "tool": "radare2-r2pipe",
            "status": "unavailable",
            "reason": "radare2 could not analyze this artifact",
            "exit_code": code,
            "output_excerpt": output[:800],
        }

    functions = parse_json_payload(output)
    if not isinstance(functions, list):
        return {
            "tool": "radare2-r2pipe",
            "status": "unavailable",
            "reason": "radare2 did not emit a JSON function list",
            "output_excerpt": output[:800],
        }
    function_names = sorted(
        str(item.get("name"))
        for item in functions
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    )
    edges = r2_call_edges(functions)
    graph_code, graph_output = run_command(
        [command, "-q", "-2", "-A", "-c", "agCj", "-c", "q", str(artifact)],
        root,
        timeout=120,
    )
    graph_edges = radare2_graph_edges(parse_json_payload(graph_output)) if graph_code == 0 else []
    if graph_edges:
        edges = graph_edges
    return {
        "tool": "radare2-r2pipe",
        "status": "pass" if functions else "partial",
        "function_inventory": bounded_list(function_names),
        "call_edges": bounded_edges(edges),
        "callgraph_metrics": callgraph_metrics(edges),
    }


def analyze_with_rizin(root: Path, artifact: Path) -> dict[str, Any]:
    command = rizin_command()
    if command is None:
        return unavailable("rizin", "rizin command is not installed")

    code, output = run_command(
        [command, "-2", "-q", "-A", "-c", "aflj", "-c", "q", str(artifact)],
        root,
        timeout=120,
    )
    if code != 0:
        return {
            "tool": "rizin",
            "status": "unavailable",
            "reason": "rizin could not analyze this artifact",
            "exit_code": code,
            "output_excerpt": output[:800],
        }

    functions = parse_json_payload(output)
    if not isinstance(functions, list):
        return {
            "tool": "rizin",
            "status": "unavailable",
            "reason": "rizin did not emit a JSON function list",
            "output_excerpt": output[:800],
        }

    function_names = sorted(
        str(item.get("name"))
        for item in functions
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    )
    edges = r2_call_edges(functions)
    return {
        "tool": "rizin",
        "status": "pass" if functions else "partial",
        "function_inventory": bounded_list(function_names),
        "call_edges": bounded_edges(edges),
        "callgraph_metrics": callgraph_metrics(edges),
    }


def analyze_with_angr(artifact: Path) -> dict[str, Any]:
    if not python_module_available("angr"):
        return unavailable("angr", "Python module is not installed")

    max_bytes = int(os.environ.get("VMP_ANGR_MAX_BYTES", "5000000"))
    try:
        artifact_size = artifact.stat().st_size
    except OSError as error:
        return unavailable("angr", f"artifact could not be stat'ed: {error}")
    if artifact_size > max_bytes:
        return unavailable("angr", f"artifact exceeds bounded CFG size limit: {artifact_size}>{max_bytes}")

    try:
        import angr  # type: ignore[import-not-found]

        project = angr.Project(str(artifact), auto_load_libs=False)
        cfg = project.analyses.CFGFast(
            normalize=True,
            data_references=False,
            resolve_indirect_jumps=False,
        )
        function_manager = getattr(cfg.kb, "functions", None)
        values = getattr(function_manager, "values", None)
        functions = safe_iter(values()) if callable(values) else safe_iter(function_manager)
        callgraph = getattr(function_manager, "callgraph", None)
        raw_edges = safe_iter(callgraph.edges()) if callgraph is not None else []
    except Exception as error:  # pragma: no cover - exact angr failures are version-specific
        return {
            "tool": "angr",
            "status": "unavailable",
            "reason": f"CFGFast analysis failed: {error}",
        }

    function_names = sorted(object_name(function) for function in functions)
    edges: list[dict[str, str]] = []
    for edge in raw_edges:
        if isinstance(edge, (list, tuple)) and len(edge) >= 2:
            caller = object_address(edge[0])
            callee = object_address(edge[1])
            edges.append(
                {
                    "caller": hex(caller) if caller is not None else object_name(edge[0]),
                    "callee": hex(callee) if callee is not None else object_name(edge[1]),
                }
            )
    return {
        "tool": "angr",
        "status": "pass" if functions else "partial",
        "function_inventory": bounded_list(function_names),
        "call_edges": bounded_edges(edges),
        "callgraph_metrics": callgraph_metrics(edges),
    }


def analyze_with_ghidra(root: Path, artifact: Path) -> dict[str, Any]:
    command = ghidra_headless_command()
    if command is None:
        return unavailable("ghidra", "Ghidra analyzeHeadless command is not installed")

    script_dir = root / "scripts/audit/ghidra"
    script = script_dir / "ExportCallGraph.java"
    if not script.exists():
        return unavailable("ghidra", "Ghidra export script is missing")

    with tempfile.TemporaryDirectory(prefix="vmp-ghidra-") as tmp:
        tmp_path = Path(tmp)
        output = tmp_path / "callgraph.json"
        code, text = run_command(
            [
                command,
                str(tmp_path),
                "VmpReverseTooling",
                "-import",
                str(artifact),
                "-overwrite",
                "-scriptPath",
                str(script_dir),
                "-postScript",
                script.name,
                str(output),
                "-deleteProject",
            ],
            root,
            timeout=240,
        )
        if code != 0:
            return {
                "tool": "ghidra",
                "status": "unavailable",
                "reason": "Ghidra headless analysis failed",
                "exit_code": code,
                "output_excerpt": text[:800],
            }
        try:
            data = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            return {
                "tool": "ghidra",
                "status": "unavailable",
                "reason": f"Ghidra did not emit callgraph JSON: {error}",
                "output_excerpt": text[:800],
            }

    raw_functions = data.get("functions") if isinstance(data, dict) else []
    raw_edges = data.get("edges") if isinstance(data, dict) else []
    functions = sorted(str(item) for item in raw_functions if isinstance(item, str))
    edges = [
        {"caller": str(item["caller"]), "callee": str(item["callee"])}
        for item in raw_edges
        if isinstance(item, dict) and "caller" in item and "callee" in item
    ]
    return {
        "tool": "ghidra",
        "status": "pass" if functions else "partial",
        "function_inventory": bounded_list(functions),
        "call_edges": bounded_edges(edges),
        "callgraph_metrics": callgraph_metrics(edges),
    }


def external_callgraph_consensus(results: list[dict[str, Any]]) -> dict[str, Any]:
    callgraph_tools = {"radare2-r2pipe", "rizin", "angr", "ghidra"}
    available: list[str] = []
    hot_observations: list[dict[str, Any]] = []
    total_edges = 0
    total_functions = 0

    for result in results:
        tool = result.get("tool")
        if tool not in callgraph_tools or result.get("status") not in {"pass", "partial"}:
            continue
        metrics = result.get("callgraph_metrics")
        inventory = result.get("function_inventory")
        if not isinstance(metrics, dict):
            continue
        available.append(str(tool))
        total_edges += int(metrics.get("call_edge_count", 0))
        if isinstance(inventory, dict):
            total_functions += int(inventory.get("count", 0))
        hot = metrics.get("high_frequency_callees")
        samples = hot.get("sample", []) if isinstance(hot, dict) else []
        for sample in safe_iter(samples):
            if isinstance(sample, dict):
                hot_observations.append({"tool": str(tool), **sample})

    return {
        "status": "pass" if available else "unavailable",
        "tools_considered": sorted(callgraph_tools),
        "available_callgraph_backends": available,
        "backend_count": len(available),
        "total_functions_observed": total_functions,
        "total_call_edges_observed": total_edges,
        "high_frequency_callee_observations": {
            "count": len(hot_observations),
            "sample": hot_observations[:12],
            "truncated": len(hot_observations) > 12,
        },
    }


def collect_external_reverse_tooling(root: Path, artifact: Path) -> dict[str, Any]:
    results = [
        analyze_with_lief(artifact),
        analyze_with_capa(root, artifact),
        analyze_with_floss(root, artifact),
        analyze_with_radare2(root, artifact),
        analyze_with_rizin(root, artifact),
        analyze_with_angr(artifact),
        analyze_with_ghidra(root, artifact),
    ]
    callgraph_consensus = external_callgraph_consensus(results)
    score: dict[str, int] = {}
    lief = results[0]
    if lief.get("status") in {"pass", "partial"}:
        exports = lief.get("exports", {})
        if isinstance(exports, dict) and int(exports.get("count", 999)) <= 8:
            score["lief_format_surface_review"] = 25

    capa = results[1]
    if capa.get("status") == "pass":
        score["capa_capability_scan"] = 25
    floss = results[2]
    if floss.get("status") == "pass":
        score["floss_recovered_string_scan"] = 25
    radare2 = results[3]
    if radare2.get("status") in {"pass", "partial"}:
        score["radare2_callgraph_inventory"] = 25
    rizin = results[4]
    if rizin.get("status") in {"pass", "partial"}:
        score["rizin_callgraph_inventory"] = 25
    angr = results[5]
    if angr.get("status") in {"pass", "partial"}:
        score["angr_cfgfast_callgraph_inventory"] = 25
    ghidra = results[6]
    if ghidra.get("status") in {"pass", "partial"}:
        score["ghidra_callgraph_inventory"] = 25
    if callgraph_consensus.get("status") == "pass" and int(callgraph_consensus.get("total_call_edges_observed", 0)) > 0:
        score["external_callgraph_consensus"] = 25

    return {
        "tool_results": results,
        "score_breakdown": score,
        "available_tools": [str(item["tool"]) for item in results if item.get("status") != "unavailable"],
        "tool_sources": list(GITHUB_TOOL_SOURCES),
        "callgraph_consensus": callgraph_consensus,
    }
