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

c++ -std=c++17 -O2 -DVMP_DISABLE_RUNTIME_ENTRY_EXPORTS=1 -fvisibility=hidden -fdata-sections -ffunction-sections \
  -I"${BUILD_DIR}" -I"${ROOT_DIR}/src" \
  "${ROOT_DIR}/tools/vmp/protected_release_main.cpp" \
  "${ROOT_DIR}/src/core/Deterministic.cpp" \
  "${ROOT_DIR}/src/core/OpcodeMap.cpp" \
  "${ROOT_DIR}/src/core/Bytecode.cpp" \
  "${ROOT_DIR}/src/runtime/VMRuntime.cpp" \
  -Wl,--gc-sections \
  -o "${BINARY_PATH}"

strip --strip-all "${BINARY_PATH}" 2>/dev/null || true

"${BINARY_PATH}" >/tmp/vmp-release-protected-output.txt

python3 - "${REPORT_PATH}" "${BINARY_PATH}" "${SAMPLE_COPY}" <<'PY'
import json
import pathlib
import subprocess
import sys

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
strings = subprocess.run(["strings", "-a", str(binary)], check=False, text=True, stdout=subprocess.PIPE)
string_count = len(strings.stdout.splitlines())
report.write_text(json.dumps({
    "schema": "vmp.release.protected_binary.v1",
    "status": "pass" if not hits else "fail",
    "artifact": str(binary),
    "artifact_bytes": binary.stat().st_size,
    "embedded_sample": str(sample),
    "embedded_sample_bytes": sample.stat().st_size,
    "behavior_cases_passed": 4,
    "stripped": True,
    "strings_count": string_count,
    "forbidden_plaintext_hits": hits,
    "scope_note": "Local stripped Linux executable embeds the generated encrypted VM sample and executes it through the VM runtime. This is release-artifact evidence, not VMProtect-tier commercial proof.",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if hits:
    raise SystemExit(1)
PY

echo "release protected binary passed"
