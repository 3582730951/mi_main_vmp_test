#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/tests/integration/.build"
OUT_DIR="${ROOT_DIR}/samples/protected_chain/out"
DEMO_OUTPUT="${OUT_DIR}/visible_demo.txt"

bash "${ROOT_DIR}/tests/integration/run_protected_sample_chain.sh" >/dev/null

"${BUILD_DIR}/protected_sample" demo "${OUT_DIR}/protected_sample.vmp" | tee "${DEMO_OUTPUT}"

grep -q 'demo_function=authorized_sample_behavior(left, right)' "${DEMO_OUTPUT}"
grep -q 'case 1: left=7 right=11 baseline=23142 protected=23142 vm_status=Ok match=yes' "${DEMO_OUTPUT}"
grep -q 'case 4: left=4294967295 right=1437226410 baseline=2857764015 protected=2857764015 vm_status=Ok match=yes' "${DEMO_OUTPUT}"
grep -q 'artifact_printable_string_runs=0' "${DEMO_OUTPUT}"
grep -q 'artifact_plaintext_markers=absent' "${DEMO_OUTPUT}"
