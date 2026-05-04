#!/usr/bin/env bash
set -euo pipefail

build_dir="${1:-build/linux}"

mkdir -p "$build_dir"
if command -v cmake >/dev/null 2>&1; then
  cmake -S src/platform -B "$build_dir" -DPLATFORM_ADAPTER_TARGET=linux -DCMAKE_BUILD_TYPE=Release
  cmake --build "$build_dir" --config Release
else
  cc -O2 -fPIC -shared \
    -I src/platform \
    src/platform/platform_common.c src/platform/linux/linux_adapter.c \
    -Wl,-z,relro,-z,now \
    -o "$build_dir/libvmp_platform.so"
  cc -O2 -fPIE -pie \
    -I src/platform \
    src/platform/platform_common.c src/platform/linux/linux_adapter.c src/platform/linux/linux_smoke.c \
    -ldl -Wl,-z,relro,-z,now \
    -o "$build_dir/vmp_platform_smoke"
fi

so_path="$(find "$build_dir" -type f \( -name 'libvmp_platform.so' -o -name 'vmp_platform.so' \) | head -n 1)"
if [[ -z "$so_path" ]]; then
  echo "Linux .so artifact was not produced" >&2
  exit 30
fi

"$build_dir/vmp_platform_smoke" "$so_path"

readelf -h "$build_dir/vmp_platform_smoke" >/dev/null
readelf -d "$so_path" >/dev/null
readelf -l "$build_dir/vmp_platform_smoke" | grep -q 'GNU_RELRO'
readelf -l "$so_path" | grep -q 'GNU_RELRO'
readelf -d "$build_dir/vmp_platform_smoke" | grep -Eq 'BIND_NOW|FLAGS.*NOW'
readelf -d "$so_path" | grep -Eq 'BIND_NOW|FLAGS.*NOW'

if command -v scanelf >/dev/null 2>&1; then
  scanelf -e "$build_dir/vmp_platform_smoke" "$so_path" >/dev/null
fi

if strings -a "$so_path" | grep -E 'passwd\.txt|GITHUB_PAT|REMOTE_PAT'; then
  echo "Forbidden marker found in Linux artifact" >&2
  exit 31
fi

echo "linux acceptance passed"
