#!/usr/bin/env python3
"""Scan release artifacts for avoidable VM/OLLVM/product surface markers."""

from __future__ import annotations

import argparse
import json
import subprocess
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
        if in_import_table and "\t" in line and len(stripped.split()) >= 3:
            name = stripped.split()[-1]
            if name and name not in {"Name", "Bound-To"}:
                imported_names.append(name)
    return {
        "tool": "objdump",
        "status": "observed",
        "export_directory_present": export_directory_present,
        "tls_directory_present": tls_directory_present,
        "import_dlls": sorted(set(import_dlls)),
        "import_count": len(imported_names),
        "note": "PE headers and CRT TLS/import directories are mandatory container/runtime observations; avoidable product markers are reported as findings.",
    }


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
        total_findings += len(result.findings)
        scanned.append(
            {
                "artifact": relative,
                "container": result.container,
                "mandatory_features": list(result.mandatory_features),
                "passed": result.passed,
                "findings": [
                    {
                        "category": finding.category.value,
                        "pattern": finding.pattern,
                        "offset": finding.offset,
                        "evidence": finding.evidence,
                    }
                    for finding in result.findings
                ],
                "pe_observations": pe_observations(root, path),
                "elf_observations": elf_observations(root, path),
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
            "This gate fails on avoidable product, VM, OLLVM, protected plaintext, and explicit import-resolver markers."
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
