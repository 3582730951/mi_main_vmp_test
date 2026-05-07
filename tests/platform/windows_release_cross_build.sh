#!/usr/bin/env bash
set -euo pipefail

build_dir="${1:-build/windows-protected-cross}"
report_path="${2:-docs/qa/reports/windows-protected-cross-build.json}"
cc="${MINGW_CXX:-x86_64-w64-mingw32-g++}"
objdump="${MINGW_OBJDUMP:-x86_64-w64-mingw32-objdump}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "MinGW C++ compiler not found: $cc" >&2
  exit 40
fi
if ! command -v "$objdump" >/dev/null 2>&1; then
  echo "MinGW objdump not found: $objdump" >&2
  exit 41
fi

mkdir -p "$build_dir" "$(dirname "$report_path")"

# The Windows release artifact intentionally uses the same encrypted visible
# demo as the reverse-engineering showcase: it prints concrete behavior, then
# pauses on three getchar() calls, while keeping the demo text encrypted in the
# PE instead of leaving .rdata plaintext.
visible_report="$build_dir/protected_release_visible_demo.source.json"
bash tests/platform/windows_visible_demo_cross_build.sh "$build_dir" "$visible_report" >/dev/null
sample_copy="$build_dir/protected_sample.vmp"
exe="$build_dir/protected_release_sample.exe"
cp "$build_dir/protected_visible_demo.exe" "$exe"

"$objdump" -f "$exe" | grep -q 'pei-x86-64'
"$objdump" -p "$exe" >"$build_dir/protected_release_sample.exe.pe.txt"
strings_path="$build_dir/protected_release_sample.exe.strings.txt"
strings -a "$exe" >"$strings_path"

if grep -E 'visible windows protected demo|parse_status=failed|demo_function=authorized_sample_behavior|case %u|windows_getchar_pause=3|protected-sample-seed-v1|authorized_sample_behavior|CRITICAL_AUTHZ_TOKEN_SAMPLE|https://license\.sample\.invalid|Authorization:|Bearer |JNI_OnLoad|Java_|dlopen|dlsym|VMPBC|VMPSAM|VMPIRL|OLLVM|Mingw-w64 runtime failure|GCC: \\(GNU\\)|msvcrt\\.dll|printf|fprintf|vfprintf|getchar' "$strings_path"; then
  echo "Forbidden marker found in Windows protected release PE artifact" >&2
  exit 42
fi

python3 - "$report_path" "$exe" "$sample_copy" "$build_dir/protected_release_sample.exe.pe.txt" "$visible_report" <<'PY'
import json
import pathlib
import re
import subprocess
import sys

from scripts.audit.surface_minimization_audit import pe_metadata_findings, pe_metadata_observations

report = pathlib.Path(sys.argv[1])
exe = pathlib.Path(sys.argv[2])
sample = pathlib.Path(sys.argv[3])
pe_text = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8", errors="ignore")
visible_report = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
pe_metadata = pe_metadata_observations(exe)
metadata_findings = pe_metadata_findings(pe_metadata)
if metadata_findings:
    raise SystemExit(f"PE metadata minimization findings: {metadata_findings}")
strings = subprocess.run(["strings", "-a", str(exe)], check=False, text=True, stdout=subprocess.PIPE)
string_count = len(strings.stdout.splitlines())
import_dlls = []
imported_names = []
export_directory_present = False
import_directory_present = False
tls_directory_present = False
in_import_table = False
for line in pe_text.splitlines():
    stripped = line.strip()
    if stripped.startswith("The Import Tables"):
        in_import_table = True
        continue
    if stripped.startswith("The Function Table") or stripped.startswith("PE File Base Relocations"):
        in_import_table = False
    if stripped.startswith("Entry 0 "):
        parts = stripped.split()
        export_directory_present = len(parts) >= 4 and parts[3] != "00000000"
    if stripped.startswith("Entry 1 "):
        parts = stripped.split()
        import_directory_present = len(parts) >= 4 and parts[3] != "00000000"
    if stripped.startswith("Entry 9 "):
        parts = stripped.split()
        tls_directory_present = len(parts) >= 4 and parts[3] != "00000000"
    if stripped.startswith("DLL Name:"):
        import_dlls.append(stripped.removeprefix("DLL Name:").strip())
    if in_import_table:
        parts = stripped.split()
        if len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]) and parts[1].isdigit():
            imported_names.append(parts[2])
forbidden = [
    "visible windows protected demo",
    "parse_status=failed",
    "demo_function=authorized_sample_behavior",
    "case %u",
    "windows_getchar_pause=3",
    "protected-sample-seed-v1",
    "authorized_sample_behavior",
    "CRITICAL_AUTHZ_TOKEN_SAMPLE",
    "https://license.sample.invalid",
    "Authorization:",
    "Bearer ",
    "JNI_OnLoad",
    "Java_",
    "dlopen",
    "dlsym",
    "VMPBC",
    "VMPSAM",
    "VMPIRL",
    "OLLVM",
    "Mingw-w64 runtime failure",
    "GCC: (GNU)",
    "msvcrt.dll",
    "printf",
    "fprintf",
    "vfprintf",
    "getchar",
]
forbidden_hits = [needle for needle in forbidden if needle in strings.stdout]
report.write_text(json.dumps({
    "schema": "vmp.platform.windows_protected_cross_build.v1",
    "status": "partial",
    "ci_execution": False,
    "local_cross_compile": True,
    "release_mode": "visible_encrypted_console_demo",
    "visible_demo_strings_encrypted": True,
    "dynamic_string_protection": visible_report.get("dynamic_string_protection", {}),
    "windows_console_api_policy": visible_report.get("windows_console_api_policy", {}),
    "decoy_sections": visible_report.get("decoy_sections", {}),
    "section_names_randomized": visible_report.get("section_names_randomized") is True,
    "section_name_seed_fingerprint": visible_report.get("section_name_seed_fingerprint"),
    "section_name_hex": visible_report.get("section_name_hex", []),
    "windows_getchar_calls": 3,
    "wine_execution_status": visible_report.get("wine_execution_status", "unknown"),
    "wine_execution_note": visible_report.get("wine_execution_note"),
    "visible_demo_source_report": str(pathlib.Path(sys.argv[5])),
    "artifact": str(exe),
    "artifact_bytes": exe.stat().st_size,
    "embedded_sample": str(sample),
    "embedded_sample_bytes": sample.stat().st_size,
    "pe_format": "pei-x86-64",
    "pe_observations": {
        "export_directory_present": export_directory_present,
        "import_directory_present": import_directory_present,
        "tls_directory_present": tls_directory_present,
        "import_dlls": sorted(set(import_dlls)),
        "import_count": len(imported_names),
        "imports": sorted(set(imported_names)),
    },
    "pe_metadata_observations": pe_metadata,
    "pe_metadata_findings": metadata_findings,
    "strings_count": string_count,
    "forbidden_plaintext_hits": forbidden_hits,
    "blocking_note": "Generated protected PE artifact is a local cross-build of the encrypted visible console demo; GitHub Actions Windows execution is still required for hard acceptance.",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "windows protected release cross-build produced"
