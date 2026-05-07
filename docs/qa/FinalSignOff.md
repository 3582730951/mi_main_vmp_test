# Final Sign-Off

Status: **blocked**.

Strict completion audit: blocked.

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
| Literal objective completion | `docs/qa/reports/objective-completion-audit.json` |

Open blockers:

- `docs/qa/reports/capability-matrix.json` reports local VMProtect-tier implementation preconditions pass, but trusted vmprotect-tier GitHub provenance/final sign-off evidence is incomplete.
- VMProtect-tier evidence is not satisfied by the strict completion gate.
