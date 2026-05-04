#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

tests/core/run_core_tests.sh
tests/core/run_llvm_plugin_test.sh
tests/integration/run_protected_sample_chain.sh
tests/integration/run_release_protected_binary.sh
bash tests/performance/protected_sample_benchmark.sh
tests/platform/run_all_local.sh
python3 tests/platform/hostile_environment_report.py
python3 scripts/audit/capability_matrix.py

python3 scripts/audit/acceptance_audit.py --runs 3 --tests
printf '%s\n' 'local acceptance passed; final sign-off also requires ./final_acceptance.sh'
