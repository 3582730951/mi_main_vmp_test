# Final Sign-Off

Status: **blocked pending reverse-cost assessment**.

Strict completion audit: pass for the existing external evidence set, but the
current final gate also requires a commit-bound reverse-cost assessment report
with `minimum_reverse_cost_days >= 365`.

| Gate | Evidence |
|---|---|
| Windows CI | `docs/qa/reports/windows-github-actions-verification.json` |
| Windows hostile triggers | `docs/qa/reports/windows-hostile-github-actions-verification.json` |
| Android APK/JNI and native .so | `docs/qa/reports/android-github-actions-verification.json` |
| Android hostile triggers | `docs/qa/reports/android-hostile-github-actions-verification.json` |
| IDA/OllyDbg review | `docs/qa/reports/ida-ollydbg-github-actions-verification.json` |
| VMProtect-tier review | `docs/qa/reports/vmprotect-tier-github-actions-verification.json` |
| Aggregate hostile environment | `docs/qa/reports/hostile-environment.json` |
| Reverse-cost assessment | `docs/qa/reports/reverse-cost-assessment.json` |

Open vulnerabilities: 0
Open findings: 1 pending external reverse-cost evidence
