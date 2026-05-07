#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/tests/integration/.build"
OUT_DIR="${ROOT_DIR}/samples/protected_chain/out"

mkdir -p "${BUILD_DIR}"
rm -rf "${OUT_DIR}"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${ROOT_DIR}/src" \
  "${ROOT_DIR}/tools/vmp/protected_sample.cpp" \
  "${ROOT_DIR}/src/core/Deterministic.cpp" \
  "${ROOT_DIR}/src/core/OpcodeMap.cpp" \
  "${ROOT_DIR}/src/core/ProtectionConfig.cpp" \
  "${ROOT_DIR}/src/core/Bytecode.cpp" \
  "${ROOT_DIR}/src/core/IRLoweringSkeleton.cpp" \
  "${ROOT_DIR}/src/runtime/VMRuntime.cpp" \
  -o "${BUILD_DIR}/protected_sample"

"${BUILD_DIR}/protected_sample" build "${OUT_DIR}" >/dev/null
"${BUILD_DIR}/protected_sample" verify "${OUT_DIR}/protected_sample.vmp"
"${BUILD_DIR}/protected_sample" report "${OUT_DIR}/protected_sample.vmp" "${OUT_DIR}"

python3 - "${OUT_DIR}" <<'PY'
import json
import pathlib
import sys

out_dir = pathlib.Path(sys.argv[1])
artifact = (out_dir / "protected_sample.vmp").read_bytes()
behavior = json.loads((out_dir / "behavior.json").read_text())
strings = json.loads((out_dir / "strings.json").read_text())
randomness = json.loads((out_dir / "randomness.json").read_text())

def printable_runs(data, min_length=4):
    runs = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
            continue
        if len(current) >= min_length:
            runs.append(bytes(current))
        current.clear()
    if len(current) >= min_length:
        runs.append(bytes(current))
    return runs

assert behavior["schema"] == "vmp.sample.behavior.v1"
assert behavior["consistent"] is True
assert len(behavior["cases"]) >= 4
assert all(case["baseline"] == case["protected"] for case in behavior["cases"])
assert all(case["status"] == "Ok" for case in behavior["cases"])

assert strings["schema"] == "vmp.sample.strings.v1"
assert strings["critical_strings_absent"] is True
assert all(check["present"] is False for check in strings["checks"])
assert printable_runs(artifact) == []

assert randomness["schema"] == "vmp.sample.randomness.v1"
assert randomness["payload_bytes"] > 0
assert randomness["unique_opcode_bytes"] >= 12
assert randomness["deterministic_rebuild_match"] is True
assert randomness["alternate_seed_changes_opcode_map"] is True
PY

echo "protected sample chain passed"
