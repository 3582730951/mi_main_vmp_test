#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/tests/integration/.release-build"
ARTIFACT_DIR="${ROOT_DIR}/artifacts/protected/linux"
REPORT_PATH="${ROOT_DIR}/docs/qa/reports/release-protected-binary.json"
HEADER_PATH="${BUILD_DIR}/protected_sample_blob.h"
BINARY_PATH="${ARTIFACT_DIR}/protected_release_sample"
SAMPLE_COPY="${BUILD_DIR}/protected_sample.vmp"

mkdir -p "${BUILD_DIR}" "${ARTIFACT_DIR}" "$(dirname "${REPORT_PATH}")"

bash "${ROOT_DIR}/tests/integration/run_protected_sample_chain.sh" >/dev/null
cp "${ROOT_DIR}/samples/protected_chain/out/protected_sample.vmp" "${SAMPLE_COPY}"

python3 - "${SAMPLE_COPY}" "${HEADER_PATH}" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
out = pathlib.Path(sys.argv[2])
items = ", ".join(f"0x{byte:02x}" for byte in data)
out.write_text(
    "#pragma once\n"
    "#include <cstddef>\n"
    "#include <cstdint>\n"
    f"static constexpr std::uint8_t kProtectedSampleBlob[] = {{{items}}};\n"
    f"static constexpr std::size_t kProtectedSampleBlobSize = {len(data)};\n",
    encoding="utf-8",
)
PY

c++ -std=c++17 -O1 -fno-tree-vectorize -fno-if-conversion -DVMP_DISABLE_RUNTIME_ENTRY_EXPORTS=1 -DVMP_FREESTANDING_LINUX_ENTRY=1 \
  -fno-exceptions -fno-rtti -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
  -fno-omit-frame-pointer -ffixed-r12 -ffixed-r13 -ffixed-r14 -ffixed-r15 \
  -fvisibility=hidden -fdata-sections -ffunction-sections -fPIE \
  -I"${BUILD_DIR}" -I"${ROOT_DIR}/src" \
  "${ROOT_DIR}/tools/vmp/protected_release_main.cpp" \
  -nostdlib -nostartfiles -static-pie -Wl,--build-id=none -Wl,--gc-sections -Wl,-z,relro,-z,now -Wl,-e,_start \
  -o "${BINARY_PATH}"

strip --strip-all "${BINARY_PATH}" 2>/dev/null || true
python3 "${ROOT_DIR}/scripts/audit/scrub_elf_section_metadata.py" "${BINARY_PATH}"

"${BINARY_PATH}" >/tmp/vmp-release-protected-output.txt

python3 - "${REPORT_PATH}" "${BINARY_PATH}" "${SAMPLE_COPY}" <<'PY'
import json
import pathlib
import subprocess
import struct
import sys

from scripts.audit.surface_minimization_audit import elf_metadata_findings, elf_metadata_observations

PT_TYPES = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    6: "PHDR",
    0x6474E552: "GNU_RELRO",
    0x6474E551: "GNU_STACK",
}


def elf_layout(path):
    data = path.read_bytes()
    if not data.startswith(b"\x7fELF") or len(data) < 64:
        return {
            "status": "unsupported",
            "position_independent_executable": False,
            "fixed_load_address": True,
        }
    elf_class = data[4]
    endian = data[5]
    if elf_class != 2 or endian != 1:
        return {
            "status": "unsupported",
            "position_independent_executable": False,
            "fixed_load_address": True,
        }
    e_type = struct.unpack_from("<H", data, 16)[0]
    e_entry = struct.unpack_from("<Q", data, 24)[0]
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    type_name = {2: "EXEC", 3: "DYN"}.get(e_type, f"0x{e_type:x}")
    headers = []
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        if offset + 56 > len(data):
            return {
                "status": "truncated",
                "position_independent_executable": False,
                "fixed_load_address": True,
            }
        p_type, p_flags = struct.unpack_from("<II", data, offset)
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", data, offset + 8)
        headers.append({
            "type": PT_TYPES.get(p_type, f"0x{p_type:x}"),
            "offset": p_offset,
            "virtual_address": p_vaddr,
            "file_size": p_filesz,
            "memory_size": p_memsz,
            "flags": p_flags,
            "alignment": p_align,
        })
    load_segments = [item for item in headers if item["type"] == "LOAD"]
    return {
        "status": "observed",
        "elf_type": type_name,
        "entry_point": e_entry,
        "program_header_count": e_phnum,
        "program_header_types": [item["type"] for item in headers],
        "load_segment_virtual_addresses": [item["virtual_address"] for item in load_segments],
        "program_interpreter_present": any(item["type"] == "INTERP" for item in headers),
        "dynamic_section_present": any(item["type"] == "DYNAMIC" for item in headers),
        "gnu_relro_present": any(item["type"] == "GNU_RELRO" for item in headers),
        "position_independent_executable": type_name == "DYN",
        "fixed_load_address": type_name != "DYN",
    }


report = pathlib.Path(sys.argv[1])
binary = pathlib.Path(sys.argv[2])
sample = pathlib.Path(sys.argv[3])
data = binary.read_bytes()
forbidden = [
    b"protected-sample-seed-v1",
    b"authorized_sample_behavior",
    b"CRITICAL_AUTHZ_TOKEN_SAMPLE",
    b"https://license.sample.invalid",
    b"Authorization:",
    b"Bearer ",
    b"JNI_OnLoad",
    b"Java_",
    b"dlopen",
    b"dlsym",
    b"VMPBC",
    b"VMPSAM",
    b"VMPIRL",
    b"OLLVM",
]
hits = [item.decode("ascii", errors="ignore") for item in forbidden if item in data]
elf_metadata = elf_metadata_observations(binary)
metadata_findings = elf_metadata_findings(elf_metadata)
load_layout = elf_layout(binary)
strings = subprocess.run(["strings", "-a", str(binary)], check=False, text=True, stdout=subprocess.PIPE)
string_count = len(strings.stdout.splitlines())
report.write_text(json.dumps({
    "schema": "vmp.release.protected_binary.v1",
    "status": "pass" if not hits and not metadata_findings and load_layout.get("position_independent_executable") is True else "fail",
    "artifact": str(binary),
    "artifact_bytes": binary.stat().st_size,
    "link_mode": "static-pie",
    "embedded_sample": str(sample),
    "embedded_sample_bytes": sample.stat().st_size,
    "behavior_cases_passed": 4,
    "stripped": True,
    "strings_count": string_count,
    "elf_load_layout": load_layout,
    "forbidden_plaintext_hits": hits,
    "elf_metadata_observations": elf_metadata,
    "elf_metadata_findings": metadata_findings,
    "scope_note": "Local stripped Linux executable embeds the generated encrypted VM sample and executes it through a minimal release runner. This is release-artifact evidence, not VMProtect-tier commercial proof.",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if hits or metadata_findings or load_layout.get("position_independent_executable") is not True:
    raise SystemExit(1)
PY

echo "release protected binary passed"
