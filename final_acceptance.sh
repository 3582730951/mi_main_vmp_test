#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

evidence_backup="$(mktemp -d)"
restored=0
cleanup() {
  status=$?
  restore_all
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

for report in $external_reports; do
  preserve_report "$report"
done

for report in $external_reports; do
  rm -f "$report"
done

./acceptance.sh

restore_all

python3 scripts/audit/reverse_cost_gate.py --root .
python3 scripts/audit/finalize_external_evidence.py --root .
python3 scripts/audit/plan_completion_audit.py --root . --write-doc --json
