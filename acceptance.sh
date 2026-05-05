#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

bash tests/core/run_core_tests.sh
bash tests/core/run_llvm_plugin_test.sh
bash tests/integration/run_protected_sample_chain.sh
bash tests/integration/run_release_protected_binary.sh
bash tests/performance/protected_sample_benchmark.sh
bash tests/platform/run_all_local.sh
python3 tests/platform/hostile_environment_report.py
python3 scripts/audit/capability_matrix.py

python3 scripts/audit/acceptance_audit.py --runs 3 --tests
printf '%s\n' 'local acceptance passed; final sign-off also requires ./final_acceptance.sh'
