#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/tests/core/.build"
mkdir -p "${BUILD_DIR}"

c++ -std=c++17 -Wall -Wextra -Werror \
  -I"${ROOT_DIR}/src" \
  "${ROOT_DIR}/tests/core/core_tests.cpp" \
  "${ROOT_DIR}/src/core/Deterministic.cpp" \
  "${ROOT_DIR}/src/core/OpcodeMap.cpp" \
  "${ROOT_DIR}/src/core/ProtectionConfig.cpp" \
  "${ROOT_DIR}/src/core/Bytecode.cpp" \
  "${ROOT_DIR}/src/core/IRLoweringSkeleton.cpp" \
  "${ROOT_DIR}/src/runtime/VMRuntime.cpp" \
  "${ROOT_DIR}/src/runtime/NestedVM.cpp" \
  -o "${BUILD_DIR}/core_tests"

"${BUILD_DIR}/core_tests"
