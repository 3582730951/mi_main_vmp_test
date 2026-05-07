#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT}/build/ios-logic-local"
CLANG="${CLANG:-clang-14}"
LLVM_AR="${LLVM_AR:-llvm-ar-14}"
LLVM_STRIP="${LLVM_STRIP:-llvm-strip-14}"
LD64_LLD="${LD64_LLD:-ld64.lld-14}"

if ! command -v "${CLANG}" >/dev/null 2>&1; then
  echo "missing ${CLANG}; install clang-14 or set CLANG=/path/to/clang" >&2
  exit 50
fi
if ! command -v "${LLVM_AR}" >/dev/null 2>&1; then
  echo "missing ${LLVM_AR}; install llvm-ar-14 or set LLVM_AR=/path/to/llvm-ar" >&2
  exit 51
fi

mkdir -p "${BUILD_DIR}"
"${CLANG}" -target arm64-apple-ios -ffreestanding -fvisibility=hidden \
  -I "${ROOT}/src/platform" \
  -c "${ROOT}/src/platform/ios/ios_adapter.c" \
  -o "${BUILD_DIR}/ios_adapter.o"
"${CLANG}" -target arm64-apple-ios -ffreestanding -fvisibility=hidden \
  -I "${ROOT}/src/platform" \
  -c "${ROOT}/src/platform/platform_common.c" \
  -o "${BUILD_DIR}/platform_common.o"
"${LLVM_AR}" rcs "${BUILD_DIR}/libmi_platform.a" \
  "${BUILD_DIR}/ios_adapter.o" \
  "${BUILD_DIR}/platform_common.o"
if command -v "${LLVM_STRIP}" >/dev/null 2>&1; then
  "${LLVM_STRIP}" -x "${BUILD_DIR}/libmi_platform.a"
fi

python3 "${ROOT}/scripts/audit/macho_metadata_audit.py" \
  --root "${ROOT}" \
  --artifact "build/ios-logic-local/libmi_platform.a" \
  --output "docs/qa/reports/ios-macho-metadata.json"

if command -v "${LD64_LLD}" >/dev/null 2>&1; then
  cat >"${BUILD_DIR}/ios_entry.c" <<'EOF'
int main(void) { return 0; }
EOF
  "${CLANG}" -target arm64-apple-ios -ffreestanding -fvisibility=hidden \
    -c "${BUILD_DIR}/ios_entry.c" \
    -o "${BUILD_DIR}/ios_entry.o"
  "${LD64_LLD}" \
    -arch arm64 \
    -platform_version ios 12.0 12.0 \
    -e _main \
    -dead_strip \
    -no_function_starts \
    -no_data_in_code_info \
    -no_encryption \
    -rename_section __TEXT __text __TEXT __tx \
    -o "${BUILD_DIR}/ios_min_exec" \
    "${BUILD_DIR}/ios_entry.o"
  if command -v "${LLVM_STRIP}" >/dev/null 2>&1; then
    "${LLVM_STRIP}" -x "${BUILD_DIR}/ios_min_exec"
  fi
  python3 - "${BUILD_DIR}/ios_min_exec" <<'PY'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
if data[:4] == b"\xcf\xfa\xed\xfe" and len(data) >= 32:
    command_count = struct.unpack_from("<I", data, 16)[0]
    cursor = 32

    def read_name(offset):
        return bytes(data[offset : offset + 16]).split(b"\0", 1)[0]

    def write_name(offset, value):
        if len(value) > 16:
            raise ValueError(f"Mach-O name is too long: {value!r}")
        data[offset : offset + 16] = value + b"\0" * (16 - len(value))

    segment_renames = {
        b"__PAGEZERO": b"__P",
        b"__TEXT": b"__T",
        b"__LINKEDIT": b"__L",
    }
    section_renames = {
        b"__text": b"_x",
        b"__tx": b"_x",
    }

    for _ in range(command_count):
        if cursor + 8 > len(data):
            break
        command, command_size = struct.unpack_from("<II", data, cursor)
        if command_size < 8 or cursor + command_size > len(data):
            break
        if command == 0x19 and command_size >= 72:
            segment_name = read_name(cursor + 8)
            if segment_name in segment_renames:
                write_name(cursor + 8, segment_renames[segment_name])
            section_count = struct.unpack_from("<I", data, cursor + 64)[0]
            section_cursor = cursor + 72
            for _ in range(section_count):
                if section_cursor + 80 > cursor + command_size:
                    break
                section_name = read_name(section_cursor)
                section_segment_name = read_name(section_cursor + 16)
                if section_name in section_renames:
                    write_name(section_cursor, section_renames[section_name])
                if section_segment_name in segment_renames:
                    write_name(section_cursor + 16, segment_renames[section_segment_name])
                section_cursor += 80
        if command == 0x22 | 0x80000000 and command_size >= 48:
            export_offset, export_size = struct.unpack_from("<II", data, cursor + 40)
            if export_offset and export_size and export_offset + export_size <= len(data):
                data[export_offset : export_offset + export_size] = b"\0" * export_size
            struct.pack_into("<II", data, cursor + 40, 0, 0)
        elif command == 0x2 and command_size >= 24:
            _, _, string_offset, string_size = struct.unpack_from("<IIII", data, cursor + 8)
            if string_offset and string_size and string_offset + string_size <= len(data):
                data[string_offset : string_offset + string_size] = b"\0" * string_size
            struct.pack_into("<IIII", data, cursor + 8, 0, 0, 0, 0)
        elif command == 0xB and command_size >= 80:
            data[cursor + 8 : cursor + 80] = b"\0" * 72
        elif command == 0x1B and command_size >= 24:
            data[cursor + 8 : cursor + 24] = b"\0" * 16
        cursor += command_size
    path.write_bytes(data)
PY
  python3 "${ROOT}/scripts/audit/macho_metadata_audit.py" \
    --root "${ROOT}" \
    --artifact "build/ios-logic-local/ios_min_exec" \
    --output "docs/qa/reports/ios-macho-linked-minimal.json"
  cp "${BUILD_DIR}/ios_min_exec" "${BUILD_DIR}/ios_min_exec_strict"
  python3 - "${BUILD_DIR}/ios_min_exec_strict" <<'PY'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
if data[:4] == b"\xcf\xfa\xed\xfe" and len(data) >= 32:
    command_count = struct.unpack_from("<I", data, 16)[0]
    cursor = 32
    for _ in range(command_count):
        if cursor + 8 > len(data):
            break
        command, command_size = struct.unpack_from("<II", data, cursor)
        if command_size < 8 or cursor + command_size > len(data):
            break
        if command == 0xE and command_size >= 12:
            name_offset = struct.unpack_from("<I", data, cursor + 8)[0]
            start = cursor + name_offset
            end = cursor + command_size
            if cursor <= start < end:
                data[start:end] = b"\0" * (end - start)
                data[start:start + 3] = b"/d\0"
        cursor += command_size
    path.write_bytes(data)
PY
  python3 "${ROOT}/scripts/audit/macho_metadata_audit.py" \
    --root "${ROOT}" \
    --artifact "build/ios-logic-local/ios_min_exec_strict" \
    --output "docs/qa/reports/ios-macho-linked-strict-zero-strings.json"
fi

echo "local iOS Mach-O metadata audit passed"
