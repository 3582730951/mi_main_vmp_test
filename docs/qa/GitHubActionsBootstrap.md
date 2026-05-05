# GitHub Actions Bootstrap

Target repository: `https://github.com/3582730951/mi_main_vmp_test`

This repository is used only for trusted GitHub Actions evidence. Do not commit
or upload `passwd.txt`. Configure secrets through GitHub Encrypted Secrets.

## Pre-Push Checks

From `/workspace`:

```bash
git init
git remote add origin https://github.com/3582730951/mi_main_vmp_test.git
git status --short
git check-ignore passwd.txt
```

`git check-ignore passwd.txt` must print `passwd.txt`. If it does not, stop and
fix `.gitignore` before staging files.

## Required Secrets

Configure these repository secrets before running the Android release workflow:

- `ANDROID_KEYSTORE_B64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

Use GitHub Encrypted Secrets. Do not store these values in repository files.

## Push

```bash
git add . ':!passwd.txt'
git commit -m "bootstrap protection acceptance workflows"
git branch -M main
git push -u origin main
```

If the remote already has history, pull or create a new branch first; do not use
destructive force-push commands unless you have intentionally decided to replace
the remote contents.

## Workflows To Run

After the push, run these workflows from a protected branch using
`workflow_dispatch` or a trusted `push` event:

- `.github/workflows/platform-windows.yml`
- `.github/workflows/platform-android-plan.yml`
- `.github/workflows/vmprotect-tier.yml`
- `.github/workflows/manual-review.yml`
- `.github/workflows/reverse-cost.yml`

The strict audit requires completed successful non-`pull_request` runs and
artifact-backed verification sidecars. Local JSON files alone are not accepted.

## Required Artifacts

Download and preserve the workflow artifacts containing these reports:

- `docs/qa/reports/windows-acceptance.json`
- `docs/qa/reports/windows-protected-release.json`
- `docs/qa/reports/windows-github-actions-verification.json`
- `docs/qa/reports/windows-hostile-triggers.json`
- `docs/qa/reports/windows-hostile-github-actions-verification.json`
- `docs/qa/reports/android-emulator-smoke.json`
- `docs/qa/reports/android-apk-smoke.json`
- `docs/qa/reports/android-github-actions-verification.json`
- `docs/qa/reports/android-hostile-triggers.json`
- `docs/qa/reports/android-hostile-github-actions-verification.json`
- `docs/qa/reports/ida-ollydbg-review.json`
- `docs/qa/reports/ida-ollydbg-github-actions-verification.json`
- `docs/qa/reports/general-ir-lowering.json`
- `docs/qa/reports/production-crypto-key-management.json`
- `docs/qa/reports/vmprotect-tier-review.json`
- `docs/qa/reports/vmprotect-tier-github-actions-verification.json`
- `docs/qa/reports/reverse-cost-assessment.json`

Then rerun:

```bash
./final_acceptance.sh
```
