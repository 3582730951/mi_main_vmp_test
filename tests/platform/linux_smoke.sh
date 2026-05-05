#!/usr/bin/env bash
set -euo pipefail

build_dir="${1:-build/linux}"

mkdir -p "$build_dir"
rm -f "$build_dir/libvmp_platform.so" "$build_dir/vmp_platform.so" "$build_dir/vmp_platform_smoke"
if command -v cmake >/dev/null 2>&1; then
  cmake -S src/platform -B "$build_dir" -DPLATFORM_ADAPTER_TARGET=linux -DCMAKE_BUILD_TYPE=Release
  cmake --build "$build_dir" --config Release
else
  cc -O2 -fPIC -shared \
    -I src/platform \
    src/platform/platform_common.c src/platform/linux/linux_adapter.c \
    -Wl,-z,relro,-z,now \
    -o "$build_dir/libmi_platform.so"
  cc -O2 -fPIE -pie \
    -I src/platform \
    src/platform/platform_common.c src/platform/linux/linux_adapter.c src/platform/linux/linux_smoke.c \
    -ldl -Wl,-z,relro,-z,now \
    -o "$build_dir/mi_platform_smoke"
fi

so_path="$(find "$build_dir" -type f \( -name 'libmi_platform.so' -o -name 'mi_platform.so' \) | head -n 1)"
if [[ -z "$so_path" ]]; then
  echo "Linux .so artifact was not produced" >&2
  exit 30
fi
smoke_path="$(find "$build_dir" -type f -name 'mi_platform_smoke' | head -n 1)"
if [[ -z "$smoke_path" ]]; then
  echo "Linux smoke executable was not produced" >&2
  exit 33
fi

"$smoke_path" "$so_path"

readelf -h "$smoke_path" >/dev/null
readelf -d "$so_path" >/dev/null
readelf -l "$smoke_path" | grep -q 'GNU_RELRO'
readelf -l "$so_path" | grep -q 'GNU_RELRO'
readelf -d "$smoke_path" | grep -Eq 'BIND_NOW|FLAGS.*NOW'
readelf -d "$so_path" | grep -Eq 'BIND_NOW|FLAGS.*NOW'
if readelf -Ws "$so_path" | grep -E 'vmp_platform_|vmp_|VMP|OLLVM'; then
  echo "Forbidden platform ABI marker found in Linux .so symbol table" >&2
  exit 32
fi

if command -v scanelf >/dev/null 2>&1; then
  scanelf -e "$smoke_path" "$so_path" >/dev/null
fi

if strings -a "$so_path" | grep -E 'passwd\.txt|GITHUB_PAT|REMOTE_PAT'; then
  echo "Forbidden marker found in Linux artifact" >&2
  exit 31
fi
for artifact in "$smoke_path" "$so_path"; do
  if strings -a "$artifact" | grep -E 'vmp_platform|libvmp|VMPPassPlugin|OLLVM|\.vmp'; then
    echo "Forbidden platform marker found in Linux artifact" >&2
    exit 34
  fi
done

echo "linux acceptance passed"
