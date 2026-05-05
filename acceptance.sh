#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

external_audit_reports="
docs/qa/reports/android-apk-smoke.json
docs/qa/reports/android-emulator-smoke.json
docs/qa/reports/android-environment.json
docs/qa/reports/android-github-actions-verification.json
docs/qa/reports/android-hostile-triggers.json
docs/qa/reports/android-hostile-github-actions-verification.json
docs/qa/reports/capability-matrix.json
docs/qa/reports/general-ir-lowering.json
docs/qa/reports/hostile-environment.json
docs/qa/reports/ida-ollydbg-review.json
docs/qa/reports/ida-ollydbg-github-actions-verification.json
docs/qa/reports/performance-sample.json
docs/qa/reports/production-crypto-key-management.json
docs/qa/reports/release-protected-binary.json
docs/qa/reports/vmprotect-tier-review.json
docs/qa/reports/vmprotect-tier-github-actions-verification.json
docs/qa/reports/windows-acceptance.json
docs/qa/reports/windows-github-actions-verification.json
docs/qa/reports/windows-hostile-triggers.json
docs/qa/reports/windows-hostile-github-actions-verification.json
docs/qa/reports/windows-protected-release.json
"

audit_backup="$(mktemp -d)"
audit_restored=0
restore_external_audit_reports() {
  if [ "$audit_restored" -eq 1 ]; then
    return
  fi
  for report in $external_audit_reports; do
    if [ -f "$audit_backup/$report" ]; then
      mkdir -p "$(dirname "$report")"
      cp "$audit_backup/$report" "$report"
    else
      rm -f "$report"
    fi
  done
  audit_restored=1
}
cleanup() {
  status=$?
  restore_external_audit_reports
  rm -rf "$audit_backup"
  exit "$status"
}
trap cleanup EXIT

for report in $external_audit_reports; do
  if [ -f "$report" ]; then
    mkdir -p "$audit_backup/$(dirname "$report")"
    cp "$report" "$audit_backup/$report"
    rm -f "$report"
  fi
done

bash tests/core/run_core_tests.sh
bash tests/core/run_llvm_plugin_test.sh
bash tests/integration/run_protected_sample_chain.sh
bash tests/integration/run_release_protected_binary.sh
python3 scripts/audit/surface_minimization_audit.py --root .
bash tests/performance/protected_sample_benchmark.sh
bash tests/platform/run_all_local.sh
python3 tests/platform/hostile_environment_report.py
python3 scripts/audit/capability_matrix.py

python3 scripts/audit/acceptance_audit.py --runs 3 --tests
restore_external_audit_reports
printf '%s\n' 'local acceptance passed; final sign-off also requires ./final_acceptance.sh'
