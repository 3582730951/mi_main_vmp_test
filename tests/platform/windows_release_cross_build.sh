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

bash tests/integration/run_protected_sample_chain.sh >/dev/null
sample_copy="$build_dir/protected_sample.vmp"
cp samples/protected_chain/out/protected_sample.vmp "$sample_copy"

python3 - "$sample_copy" "$build_dir/protected_sample_blob.h" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
items = ", ".join(f"0x{byte:02x}" for byte in data)
pathlib.Path(sys.argv[2]).write_text(
    "#pragma once\n"
    "#include <cstddef>\n"
    "#include <cstdint>\n"
    f"static constexpr std::uint8_t kProtectedSampleBlob[] = {{{items}}};\n"
    f"static constexpr std::size_t kProtectedSampleBlobSize = {len(data)};\n",
    encoding="utf-8",
)
PY

exe="$build_dir/protected_release_sample.exe"
"$cc" -std=c++17 -O2 -s -DVMP_DISABLE_RUNTIME_ENTRY_EXPORTS=1 -DVMP_FREESTANDING_WINDOWS_ENTRY=1 \
  -fno-exceptions -fno-rtti -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
  -mno-stack-arg-probe \
  -fvisibility=hidden -fdata-sections -ffunction-sections \
  -I "$build_dir" -I src \
  tools/vmp/protected_release_main.cpp \
  -nostdlib -nostartfiles -Wl,--gc-sections -Wl,-e,mainCRTStartup -lkernel32 \
  -o "$exe"

"$objdump" -f "$exe" | grep -q 'pei-x86-64'
"$objdump" -p "$exe" >"$build_dir/protected_release_sample.exe.pe.txt"

if strings -a "$exe" | grep -E 'protected-sample-seed-v1|authorized_sample_behavior|CRITICAL_AUTHZ_TOKEN_SAMPLE|https://license\.sample\.invalid|Authorization:|Bearer |JNI_OnLoad|Java_|dlopen|dlsym|VMPBC|VMPSAM|VMPIRL|OLLVM'; then
  echo "Forbidden marker found in Windows protected release PE artifact" >&2
  exit 42
fi

python3 - "$report_path" "$exe" "$sample_copy" "$build_dir/protected_release_sample.exe.pe.txt" <<'PY'
import json
import pathlib
import re
import sys

report = pathlib.Path(sys.argv[1])
exe = pathlib.Path(sys.argv[2])
sample = pathlib.Path(sys.argv[3])
pe_text = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8", errors="ignore")
import_dlls = []
imported_names = []
export_directory_present = False
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
    if stripped.startswith("Entry 9 "):
        parts = stripped.split()
        tls_directory_present = len(parts) >= 4 and parts[3] != "00000000"
    if stripped.startswith("DLL Name:"):
        import_dlls.append(stripped.removeprefix("DLL Name:").strip())
    if in_import_table:
        parts = stripped.split()
        if len(parts) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]) and parts[1].isdigit():
            imported_names.append(parts[2])
report.write_text(json.dumps({
    "schema": "vmp.platform.windows_protected_cross_build.v1",
    "status": "partial",
    "ci_execution": False,
    "local_cross_compile": True,
    "artifact": str(exe),
    "artifact_bytes": exe.stat().st_size,
    "embedded_sample": str(sample),
    "embedded_sample_bytes": sample.stat().st_size,
    "pe_format": "pei-x86-64",
    "pe_observations": {
        "export_directory_present": export_directory_present,
        "tls_directory_present": tls_directory_present,
        "import_dlls": sorted(set(import_dlls)),
        "import_count": len(imported_names),
    },
    "forbidden_plaintext_hits": [],
    "blocking_note": "Generated protected PE artifact is local cross-build evidence only; GitHub Actions Windows execution is still required for hard acceptance.",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "windows protected release cross-build produced"
