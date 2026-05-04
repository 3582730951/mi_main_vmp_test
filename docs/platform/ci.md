# Platform CI and Secrets

## Batch Coverage

- T130: Move repository credentials, signing assets, and tokens into GitHub Encrypted Secrets.
- T131: Remote setup must use local credential helpers or GitHub Actions secret injection; do not read plaintext credential files in CI.
- T132: Windows gate builds the adapter, executes the smoke binary, loads the DLL, scans PE artifacts, and runs the protected release sample through `tests/platform/windows_protected_release.ps1`. Hard acceptance still requires captured GitHub Actions run evidence.
- T133: Android emulator gate runs `tests/platform/android_ci_emulator_smoke.sh`, uploads APK/`.so` smoke reports, and can move to self-hosted runners if GitHub-hosted runners are insufficient.
- T134: macOS/iOS gate performs compile/static/logical checks only.
- T135: PRs should require the platform gates that match touched paths.

## Required Secret Placeholders

- `PLATFORM_WINDOWS_SIGNING_CERT`
- `PLATFORM_WINDOWS_SIGNING_PASSWORD`
- `ANDROID_KEYSTORE_B64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`
- `APPLE_CERTIFICATE_P12_B64`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_PROVISIONING_PROFILE_B64`
- `REMOTE_REPOSITORY_TOKEN`

Workflows may reference these names through `${{ secrets.NAME }}` but must never echo their values.
Signing secrets are optional until signed package workflows are implemented. They must be attached only to the step that signs a release artifact, not exposed as job-level `env` for pull-request smoke jobs.

References:

- GitHub-hosted runners: https://docs.github.com/actions/using-github-hosted-runners/about-github-hosted-runners
- GitHub-hosted runner labels: https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners
- Self-hosted runners: https://docs.github.com/actions/hosting-your-own-runners
