#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/tests/integration/.build"
OUT_DIR="${ROOT_DIR}/samples/protected_chain/out"
REPORT="${ROOT_DIR}/docs/qa/reports/performance-sample.json"

"${ROOT_DIR}/tests/integration/run_protected_sample_chain.sh" >/dev/null

"${BUILD_DIR}/protected_sample" benchmark \
  "${OUT_DIR}/protected_sample.vmp" \
  "${REPORT}" \
  "${VMP_BENCHMARK_ITERATIONS:-2000}"

python3 - "${REPORT}" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert report["schema"] == "vmp.sample.performance.v1"
assert report["status"] == "pass"
assert report["iterations"] > 0
assert report["cases_per_iteration"] == 4
assert report["baseline_ns"] > 0
assert report["protected_ns"] > 0
assert report["overhead_ratio"] > 0
assert report["artifact_bytes"] > 0
assert report["defense_priority"] is True
PY

echo "protected sample benchmark passed"
