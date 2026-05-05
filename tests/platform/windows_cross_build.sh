#!/usr/bin/env bash
set -euo pipefail

build_dir="${1:-build/windows-cross}"
report_path="${2:-docs/qa/reports/windows-cross-build.json}"

cc="${MINGW_CC:-x86_64-w64-mingw32-gcc}"
objdump="${MINGW_OBJDUMP:-x86_64-w64-mingw32-objdump}"

if ! command -v "$cc" >/dev/null 2>&1; then
  echo "MinGW compiler not found: $cc" >&2
  exit 40
fi
if ! command -v "$objdump" >/dev/null 2>&1; then
  echo "MinGW objdump not found: $objdump" >&2
  exit 41
fi

mkdir -p "$build_dir" "$(dirname "$report_path")"

dll="$build_dir/mi_platform.dll"
exe="$build_dir/mi_platform_smoke.exe"

"$cc" -O2 -shared \
  -I src/platform \
  src/platform/platform_common.c src/platform/windows/windows_adapter.c \
  -Wl,--out-implib,"$build_dir/libmi_platform.dll.a" \
  -o "$dll"

"$cc" -O2 \
  -I src/platform \
  src/platform/platform_common.c src/platform/windows/windows_adapter.c src/platform/windows/windows_smoke.c \
  -o "$exe"

"$objdump" -f "$dll" | grep -q 'pei-x86-64'
"$objdump" -f "$exe" | grep -q 'pei-x86-64'
"$objdump" -p "$dll" >"$build_dir/mi_platform.dll.pe.txt"
"$objdump" -p "$exe" >"$build_dir/mi_platform_smoke.exe.pe.txt"

for artifact in "$dll" "$exe"; do
  if strings -a "$artifact" | grep -E 'passwd\.txt|GITHUB_PAT|REMOTE_PAT|CRITICAL_AUTHZ_TOKEN_SAMPLE|https://license\.sample\.invalid'; then
    echo "Forbidden marker found in Windows PE artifact: $artifact" >&2
    exit 42
  fi
  if strings -a "$artifact" | grep -E 'vmp_platform|libvmp|\.vmp|VMPPassPlugin|OLLVM'; then
    echo "Forbidden platform ABI marker found in Windows PE artifact: $artifact" >&2
    exit 43
  fi
done

python3 - "$report_path" "$dll" "$exe" <<'PY'
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
dll = pathlib.Path(sys.argv[2])
exe = pathlib.Path(sys.argv[3])
report.write_text(json.dumps({
    "schema": "vmp.platform.windows_cross_build.v1",
    "status": "partial",
    "ci_execution": False,
    "local_cross_compile": True,
    "artifacts": [
        {"path": str(dll), "kind": "dll", "bytes": dll.stat().st_size},
        {"path": str(exe), "kind": "exe", "bytes": exe.stat().st_size},
    ],
    "pe_format": "pei-x86-64",
    "forbidden_strings_present": False,
    "blocking_note": "Generated PE artifacts are local cross-build evidence only; Windows GitHub Actions execution is still required for hard acceptance."
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

echo "windows cross-build artifacts produced"
