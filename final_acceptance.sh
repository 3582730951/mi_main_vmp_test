#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

evidence_backup="$(mktemp -d)"
restored=0
final_audit_passed=0
cleanup() {
  status=$?
  restore_all
  restore_final_outputs
  rm -rf "$evidence_backup"
  exit "$status"
}
trap cleanup EXIT

preserve_report() {
  report="$1"
  if [ -f "$report" ]; then
    mkdir -p "$evidence_backup/$(dirname "$report")"
    cp "$report" "$evidence_backup/$report"
  fi
}

restore_report() {
  report="$1"
  if [ -f "$evidence_backup/$report" ]; then
    mkdir -p "$(dirname "$report")"
    cp "$evidence_backup/$report" "$report"
  else
    rm -f "$report"
  fi
}

restore_final_outputs() {
  if [ "$final_audit_passed" -eq 1 ]; then
    return
  fi
  for report in $final_outputs; do
    restore_report "$report"
  done
}

restore_all() {
  if [ "$restored" -eq 1 ]; then
    return
  fi
  for report in $external_reports; do
    restore_report "$report"
  done
  restored=1
}

external_reports="
docs/qa/reports/android-apk-smoke.json
docs/qa/reports/android-emulator-smoke.json
docs/qa/reports/android-github-actions-verification.json
docs/qa/reports/android-hostile-triggers.json
docs/qa/reports/android-hostile-github-actions-verification.json
docs/qa/reports/capability-matrix.json
docs/qa/reports/general-ir-lowering.json
docs/qa/reports/hostile-environment.json
docs/qa/reports/ida-ollydbg-review.json
docs/qa/reports/ida-ollydbg-github-actions-verification.json
docs/qa/reports/objective-completion-audit.json
docs/qa/reports/production-crypto-key-management.json
docs/qa/reports/reverse-cost-assessment.json
docs/qa/reports/vmprotect-tier-review.json
docs/qa/reports/vmprotect-tier-github-actions-verification.json
docs/qa/reports/windows-acceptance.json
docs/qa/reports/windows-github-actions-verification.json
docs/qa/reports/windows-hostile-triggers.json
docs/qa/reports/windows-hostile-github-actions-verification.json
docs/qa/reports/windows-protected-release.json
"

final_outputs="
docs/qa/FinalSignOff.md
docs/qa/reports/hostile-environment.json
docs/qa/reports/objective-completion-audit.json
"

for report in $external_reports; do
  preserve_report "$report"
done
for report in $final_outputs; do
  preserve_report "$report"
done

./acceptance.sh

restore_all

python3 scripts/audit/objective_completion_audit.py --root .
python3 scripts/audit/reverse_cost_gate.py --root .
VMP_REQUIRE_LIVE_GITHUB_VERIFICATION=1 python3 scripts/audit/finalize_external_evidence.py --root .
VMP_REQUIRE_LIVE_GITHUB_VERIFICATION=1 python3 scripts/audit/plan_completion_audit.py --root . --write-doc --json
final_audit_passed=1
