#!/usr/bin/env python3
"""Scan release artifacts for avoidable VM/OLLVM/product surface markers."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from anti_analysis import ArtifactSurfacePolicy


DEFAULT_ARTIFACTS = (
    "artifacts/protected/linux/protected_release_sample",
    "samples/protected_chain/out/protected_sample.vmp",
    "build/windows-protected-cross/protected_release_sample.exe",
)

STANDARD_PE_SECTION_NAMES = (
    b".text",
    b".rdata",
    b".data",
    b".idata",
    b".pdata",
    b".xdata",
    b".reloc",
    b".rsrc",
    b".tls",
    b".edata",
)

STANDARD_ELF_SECTION_NAMES = (
    b".text",
    b".rodata",
    b".data",
    b".bss",
    b".dynamic",
    b".dynsym",
    b".dynstr",
    b".rela.dyn",
    b".rela.plt",
    b".plt",
    b".got",
    b".eh_frame",
    b".comment",
    b".symtab",
    b".strtab",
    b".shstrtab",
)


def run_tool(args: list[str], cwd: Path) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)
    return completed.returncode, completed.stdout.decode("utf-8", errors="replace")


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _as_sequence(value: Any) -> list[Any]:
    if callable(value):
        try:
            value = value()
        except TypeError:
            return []
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    try:
        return list(value)
    except TypeError:
        return []


def _names(value: Any, limit: int = 40) -> list[str]:
    names = []
    for item in _as_sequence(value):
        name = getattr(item, "name", item)
        if callable(name):
            try:
                name = name()
            except TypeError:
                name = str(item)
        if name is None:
            continue
        text = str(name)
        if text:
            names.append(text)
    return sorted(set(names))[:limit]


def lief_observations(artifact: Path) -> dict[str, Any]:
    if importlib.util.find_spec("lief") is None:
        return {
            "tool": "lief",
            "status": "unavailable",
            "install_hint": "python3 -m pip install lief",
        }
    try:
        import lief  # type: ignore[import-not-found]
    except Exception as error:
        return {"tool": "lief", "status": "unavailable", "detail": str(error)[:200]}
    try:
        binary = lief.parse(str(artifact))
    except Exception as error:
        return {"tool": "lief", "status": "error", "detail": str(error)[:200]}
    if binary is None:
        return {"tool": "lief", "status": "unsupported_format"}
    imported_functions = _names(getattr(binary, "imported_functions", []))
    exported_functions = _names(getattr(binary, "exported_functions", []))
    libraries = _names(getattr(binary, "libraries", []))
    sections = _names(getattr(binary, "sections", []), limit=80)
    return {
        "tool": "lief",
        "status": "observed",
        "format": str(getattr(binary, "format", "unknown")),
        "entrypoint": getattr(binary, "entrypoint", None),
        "import_count": len(imported_functions),
        "export_count": len(exported_functions),
        "library_count": len(libraries),
        "section_count": len(sections),
        "imported_functions_sample": imported_functions[:20],
        "exported_functions_sample": exported_functions[:20],
        "libraries": libraries,
        "sections_sample": sections[:30],
        "has_tls": bool(getattr(binary, "has_tls", False)),
    }


def capa_observations(root: Path, artifact: Path) -> dict[str, Any]:
    if not has_tool("capa"):
        return {
            "tool": "capa",
            "status": "unavailable",
            "install_hint": "python3 -m pip install flare-capa",
        }
    args = ["capa"]
    rules_path = os.environ.get("CAPA_RULES")
    rule_candidates = [
        Path(rules_path) if rules_path else None,
        root / "tools" / "capa-rules",
        Path("/tmp/capa-rules"),
    ]
    for candidate in rule_candidates:
        if candidate is not None and candidate.exists():
            args.extend(["-r", str(candidate)])
            break
    args.extend(["-j", str(artifact)])
    code, output = run_tool(args, root)
    if code != 0:
        return {"tool": "capa", "status": "error", "detail": output.strip()[:300]}
    try:
        data = json.loads(output)
    except json.JSONDecodeError as error:
        return {"tool": "capa", "status": "error", "detail": f"invalid JSON: {error}"}
    rules = data.get("rules", {}) if isinstance(data, dict) else {}
    rule_names = sorted(str(name) for name in rules.keys()) if isinstance(rules, dict) else []
    return {
        "tool": "capa",
        "status": "observed",
        "rule_count": len(rule_names),
        "rules_sample": rule_names[:30],
    }


def rizin_observations(root: Path, artifact: Path) -> dict[str, Any]:
    tool = next((name for name in ("rizin", "r2", "radare2") if has_tool(name)), None)
    if tool is None:
        return {
            "tool": "rizin/radare2",
            "status": "unavailable",
            "install_hint": "install rizin or radare2",
        }
    code, output = run_tool([tool, "-q", "-2", "-A", "-c", "aflj", "-c", "q", str(artifact)], root)
    if code != 0:
        return {"tool": tool, "status": "error", "detail": output.strip()[:300]}
    try:
        functions = json.loads(output) if output.strip() else []
    except json.JSONDecodeError as error:
        return {"tool": tool, "status": "error", "detail": f"invalid JSON: {error}"}
    if not isinstance(functions, list):
        functions = []
    named = [str(item.get("name", "")) for item in functions if isinstance(item, dict) and item.get("name")]
    return {
        "tool": tool,
        "status": "observed",
        "function_count": len(functions),
        "functions_sample": sorted(named)[:30],
    }


def external_tool_observations(root: Path, artifact: Path) -> dict[str, Any]:
    container = artifact.read_bytes()[:4]
    binary_like = container.startswith(b"\x7fELF") or container.startswith(b"MZ")
    observations: dict[str, Any] = {
        "lief": lief_observations(artifact),
    }
    if binary_like:
        observations["capa"] = capa_observations(root, artifact)
        observations["rizin"] = rizin_observations(root, artifact)
    else:
        observations["capa"] = {"tool": "capa", "status": "skipped", "reason": "non-executable container"}
        observations["rizin"] = {"tool": "rizin/radare2", "status": "skipped", "reason": "non-executable container"}
    return observations


def pe_observations(root: Path, artifact: Path) -> dict[str, Any]:
    if not artifact.exists() or not artifact.read_bytes().startswith(b"MZ"):
        return {}
    code, output = run_tool(["objdump", "-p", str(artifact)], root)
    if code != 0:
        return {"tool": "objdump", "status": "unavailable", "detail": output.strip()[:200]}
    import_dlls = []
    imported_names = []
    export_directory_present = False
    tls_directory_present = False
    in_import_table = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("The Import Tables"):
            in_import_table = True
            continue
        if stripped.startswith("The Function Table") or stripped.startswith("PE File Base Relocations"):
            in_import_table = False
        if stripped.startswith("Entry 0 "):
            parts = stripped.split()
            export_directory_present = len(parts) >= 4 and parts[3] != "00000000"
        if stripped.startswith("Entry 9 "):
            parts = stripped.split()
            tls_directory_present = len(parts) >= 4 and parts[3] != "00000000"
        if stripped.startswith("DLL Name:"):
            import_dlls.append(stripped.removeprefix("DLL Name:").strip())
        if in_import_table:
            parts = stripped.split()
            if len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]) and parts[1].isdigit():
                imported_names.append(parts[2])
    return {
        "tool": "objdump",
        "status": "observed",
        "export_directory_present": export_directory_present,
        "tls_directory_present": tls_directory_present,
        "import_dlls": sorted(set(import_dlls)),
        "import_count": len(imported_names),
        "note": "PE headers and CRT TLS/import directories are mandatory container/runtime observations; avoidable product markers are reported as findings.",
    }


def printable_pe_name(raw: bytes) -> str:
    stripped = raw.rstrip(b"\0")
    if not stripped:
        return ""
    if any(byte < 0x20 or byte > 0x7E for byte in stripped):
        return ""
    try:
        return stripped.decode("ascii")
    except UnicodeDecodeError:
        return ""


def pe_metadata_observations(artifact: Path) -> dict[str, Any]:
    data = artifact.read_bytes()
    if not data.startswith(b"MZ"):
        return {}
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return {"status": "error", "detail": "missing PE signature"}
        section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
        symbol_table = struct.unpack_from("<I", data, pe_offset + 12)[0]
        symbol_count = struct.unpack_from("<I", data, pe_offset + 16)[0]
        optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        section_table = pe_offset + 24 + optional_header_size
        if section_table + section_count * 40 > len(data):
            return {"status": "error", "detail": "invalid PE section table"}
        printable_sections = []
        standard_sections = []
        section_name_hex = []
        for index in range(section_count):
            raw_name = data[section_table + index * 40 : section_table + index * 40 + 8]
            section_name_hex.append(raw_name.hex())
            text = printable_pe_name(raw_name)
            if text:
                printable_sections.append(text)
                if text.encode("ascii").split(b"$", 1)[0] in STANDARD_PE_SECTION_NAMES:
                    standard_sections.append(text)
    except struct.error as error:
        return {"status": "error", "detail": str(error)}
    standard_string_hits = []
    for needle in STANDARD_PE_SECTION_NAMES:
        offset = data.find(needle)
        if offset >= 0:
            standard_string_hits.append({"pattern": needle.decode("ascii"), "offset": offset})
    return {
        "status": "observed",
        "section_count": section_count,
        "section_name_hex": section_name_hex,
        "printable_section_names": printable_sections,
        "standard_section_names": standard_sections,
        "coff_symbol_table_present": bool(symbol_table or symbol_count),
        "coff_symbol_table_offset": symbol_table,
        "coff_symbol_count": symbol_count,
        "standard_section_string_hits": standard_string_hits,
    }


def pe_metadata_findings(observations: dict[str, Any]) -> list[dict[str, Any]]:
    if observations.get("status") != "observed":
        return []
    findings: list[dict[str, Any]] = []
    if observations.get("printable_section_names"):
        findings.append(
            {
                "category": "pe_printable_section_name",
                "pattern": "printable PE section name",
                "offset": None,
                "evidence": observations["printable_section_names"],
            }
        )
    if observations.get("coff_symbol_table_present"):
        findings.append(
            {
                "category": "pe_coff_symbol_table",
                "pattern": "COFF symbol/string table",
                "offset": observations.get("coff_symbol_table_offset"),
                "evidence": {"symbol_count": observations.get("coff_symbol_count")},
            }
        )
    if observations.get("standard_section_string_hits"):
        findings.append(
            {
                "category": "pe_standard_section_string",
                "pattern": "standard PE section-name string",
                "offset": None,
                "evidence": observations["standard_section_string_hits"],
            }
        )
    return findings


def elf_observations(root: Path, artifact: Path) -> dict[str, Any]:
    if not artifact.exists() or not artifact.read_bytes().startswith(b"\x7fELF"):
        return {}
    code, output = run_tool(["readelf", "-Ws", str(artifact)], root)
    if code != 0:
        return {"tool": "readelf", "status": "unavailable", "detail": output.strip()[:200]}
    imports = []
    exports = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[0].rstrip(":").isdigit() is False:
            continue
        name = parts[7]
        bind = parts[4]
        ndx = parts[6]
        if ndx == "UND":
            imports.append(name)
        elif bind in {"GLOBAL", "WEAK"}:
            exports.append(name)
    return {
        "tool": "readelf",
        "status": "observed",
        "import_count": len(imports),
        "export_count": len(exports),
        "export_names": sorted(exports)[:20],
        "note": "ELF dynamic linker metadata is recorded separately from avoidable protected-surface markers.",
    }


def elf_metadata_observations(artifact: Path) -> dict[str, Any]:
    data = artifact.read_bytes()
    if not data.startswith(b"\x7fELF"):
        return {}
    elf_class = data[4] if len(data) > 4 else 0
    endian = data[5] if len(data) > 5 else 0
    if endian == 1:
        prefix = "<"
    elif endian == 2:
        prefix = ">"
    else:
        return {"status": "error", "detail": "unsupported ELF endian"}
    try:
        if elf_class == 2:
            e_shoff = struct.unpack_from(prefix + "Q", data, 40)[0]
            e_shentsize = struct.unpack_from(prefix + "H", data, 58)[0]
            e_shnum = struct.unpack_from(prefix + "H", data, 60)[0]
            e_shstrndx = struct.unpack_from(prefix + "H", data, 62)[0]
            class_name = "ELF64"
        elif elf_class == 1:
            e_shoff = struct.unpack_from(prefix + "I", data, 32)[0]
            e_shentsize = struct.unpack_from(prefix + "H", data, 46)[0]
            e_shnum = struct.unpack_from(prefix + "H", data, 48)[0]
            e_shstrndx = struct.unpack_from(prefix + "H", data, 50)[0]
            class_name = "ELF32"
        else:
            return {"status": "error", "detail": "unsupported ELF class"}
    except struct.error as error:
        return {"status": "error", "detail": str(error)}
    standard_string_hits = []
    for needle in STANDARD_ELF_SECTION_NAMES:
        offset = data.find(needle)
        if offset >= 0:
            standard_string_hits.append({"pattern": needle.decode("ascii"), "offset": offset})
    return {
        "status": "observed",
        "elf_class": class_name,
        "section_header_offset": e_shoff,
        "section_header_entry_size": e_shentsize,
        "section_header_count": e_shnum,
        "section_name_table_index": e_shstrndx,
        "section_header_table_present": bool(e_shoff and e_shentsize and e_shnum),
        "standard_section_string_hits": standard_string_hits,
    }


def elf_metadata_findings(observations: dict[str, Any]) -> list[dict[str, Any]]:
    if observations.get("status") != "observed":
        return []
    findings: list[dict[str, Any]] = []
    if observations.get("section_header_table_present"):
        findings.append(
            {
                "category": "elf_section_header_table",
                "pattern": "ELF section header table",
                "offset": observations.get("section_header_offset"),
                "evidence": {"section_header_count": observations.get("section_header_count")},
            }
        )
    if observations.get("standard_section_string_hits"):
        findings.append(
            {
                "category": "elf_standard_section_string",
                "pattern": "standard ELF section-name string",
                "offset": None,
                "evidence": observations["standard_section_string_hits"],
            }
        )
    return findings


def scan(root: Path, artifacts: list[str]) -> dict[str, Any]:
    policy = ArtifactSurfacePolicy.default()
    scanned = []
    missing = []
    total_findings = 0
    for relative in artifacts:
        path = root / relative
        if not path.exists():
            missing.append(relative)
            continue
        result = policy.scan_file(path)
        pe_metadata = pe_metadata_observations(path)
        elf_metadata = elf_metadata_observations(path)
        metadata_findings = pe_metadata_findings(pe_metadata) + elf_metadata_findings(elf_metadata)
        total_findings += len(result.findings) + len(metadata_findings)
        scanned.append(
            {
                "artifact": relative,
                "container": result.container,
                "mandatory_features": list(result.mandatory_features),
                "passed": result.passed and not metadata_findings,
                "findings": [
                    {
                        "category": finding.category.value,
                        "pattern": finding.pattern,
                        "offset": finding.offset,
                        "evidence": finding.evidence,
                    }
                    for finding in result.findings
                ],
                "metadata_findings": metadata_findings,
                "pe_observations": pe_observations(root, path),
                "pe_metadata_observations": pe_metadata,
                "elf_observations": elf_observations(root, path),
                "elf_metadata_observations": elf_metadata,
                "external_tool_observations": external_tool_observations(root, path),
            }
        )
    return {
        "schema": "vmp.qa.surface_minimization.v1",
        "status": "pass" if total_findings == 0 else "fail",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scanned_artifacts": scanned,
        "missing_artifacts": missing,
        "avoidable_surface_findings": total_findings,
        "policy_note": (
            "Mandatory executable-container signatures are observed, not treated as removable. "
            "This gate fails on avoidable product, VM, OLLVM, protected plaintext, explicit import-resolver markers, "
            "printable PE section names, COFF symbol tables, standard PE section-name string residue, "
            "ELF section headers, and standard ELF section-name string residue."
        ),
        "syscall_policy": {
            "status": "not_implemented_for_evasion",
            "note": (
                "The project does not add generic direct-syscall bypass stubs. Platform system access remains inside "
                "approved adapters or fixed runtime APIs under docs/SECURITY_POLICY.md."
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="docs/qa/reports/surface-minimization.json")
    parser.add_argument("--artifact", action="append", default=[], help="artifact path relative to root")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    artifacts = args.artifact or list(DEFAULT_ARTIFACTS)
    report = scan(root, artifacts)
    output = root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"surface minimization {report['status']}: avoidable_surface_findings={report['avoidable_surface_findings']}")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
