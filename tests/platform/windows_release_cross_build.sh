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
"$cc" -std=c++17 -O2 -s -DVMP_DISABLE_RUNTIME_ENTRY_EXPORTS=1 -fvisibility=hidden -fdata-sections -ffunction-sections \
  -I "$build_dir" -I src \
  tools/vmp/protected_release_main.cpp \
  -Wl,--gc-sections \
  -o "$exe"

"$objdump" -f "$exe" | grep -q 'pei-x86-64'
"$objdump" -p "$exe" >"$build_dir/protected_release_sample.exe.pe.txt"

if strings -a "$exe" | grep -E 'protected-sample-seed-v1|authorized_sample_behavior|CRITICAL_AUTHZ_TOKEN_SAMPLE|https://license\.sample\.invalid|Authorization:|Bearer |JNI_OnLoad|Java_|dlopen|dlsym|VMPBC|VMPSAM|VMPIRL|OLLVM'; then
  echo "Forbidden marker found in Windows protected release PE artifact" >&2
  exit 42
fi

python3 - "$report_path" "$exe" "$sample_copy" <<'PY'
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
exe = pathlib.Path(sys.argv[2])
sample = pathlib.Path(sys.argv[3])
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
    "forbidden_plaintext_hits": [],
    "blocking_note": "Generated protected PE artifact is local cross-build evidence only; GitHub Actions Windows execution is still required for hard acceptance.",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "windows protected release cross-build produced"
