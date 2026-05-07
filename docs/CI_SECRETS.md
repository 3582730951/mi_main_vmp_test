# CI Secrets And Credential Migration

`passwd.txt` must not be used directly by CI. It is a local migration source only. The migration owner must transfer each required value into GitHub Encrypted Secrets through the GitHub UI or CLI from a trusted workstation, then delete or quarantine the local source according to the project's credential-retention policy.

## Required Secret Names

| Secret | Purpose | Used By |
|---|---|---|
| `VMP_CI_PAT` | Optional private dependency or repository access token | Manual setup, never echoed |
| `ANDROID_KEYSTORE_B64` | Android release keystore encoded for CI; required for final Android release-strength evidence | Android packaging workflow |
| `ANDROID_KEYSTORE_PASSWORD` | Android keystore password; required with `ANDROID_KEYSTORE_B64` for final Android release-strength evidence | Android packaging workflow |
| `ANDROID_KEY_ALIAS` | Android signing alias; required when the keystore has more than one alias | Android packaging workflow |
| `ANDROID_KEY_PASSWORD` | Android key password; required when it differs from `ANDROID_KEYSTORE_PASSWORD` | Android packaging workflow |
| `PLATFORM_WINDOWS_SIGNING_CERT` | Optional Windows signing certificate for future signed PE artifacts | Windows packaging workflow |
| `PLATFORM_WINDOWS_SIGNING_PASSWORD` | Optional Windows signing password | Windows packaging workflow |
| `APPLE_CERTIFICATE_P12_B64` | Optional Apple signing certificate for future signed iOS builds | macOS/iOS workflow |
| `APPLE_CERTIFICATE_PASSWORD` | Optional Apple certificate password | macOS/iOS workflow |
| `APPLE_PROVISIONING_PROFILE_B64` | Optional provisioning profile for future iOS device testing | macOS/iOS workflow |

## Workflow Rules

1. Workflows may reference credentials only as `${{ secrets.SECRET_NAME }}`.
2. Workflows must not contain literal tokens, passwords, private keys, certificate blobs, or copied contents from `passwd.txt`.
3. Jobs must not run `cat passwd.txt`, `sed passwd.txt`, `grep passwd.txt`, or equivalent commands that print secret material.
4. CI logs must mask secrets by relying on GitHub Secrets masking and by avoiding explicit echo statements.
5. Pull request jobs must not pass signing secrets or release credentials into checked-out repository scripts; release-signing steps must run only on trusted events such as `workflow_dispatch` or protected-branch `push`.
6. Workflows must use `permissions: contents: read` unless a job has a documented reason for broader permissions.
7. Optional signing secrets must be scoped to the signing step that consumes them, not set as job-level environment variables.

## Migration Checklist

| Step | Status Evidence |
|---|---|
| Inventory required secret names without printing values | This document's required secret table |
| Add values to GitHub Encrypted Secrets | GitHub repository or organization settings screenshot/log, not stored here |
| Update workflows to use `${{ secrets.* }}` only | `.github/workflows/*.yml` audit |
| Run secret hygiene audit | `scripts/audit/run_audit.sh` or equivalent |
| Rotate any value that was printed or committed | Incident record outside repository |

## Local Handling

The repository may contain a local `passwd.txt` during migration, but automated checks must treat it as sensitive. Tests may verify that workflows do not read it; tests must not inspect or print the file contents.

## CI Gate Policy

Protected branches must require:

- Linux local/unit audit gate;
- Windows build/protect/run workflow for Windows deliverables;
- Android emulator workflow for Android deliverables;
- macOS/iOS logical workflow for iOS design deliverables;
- three consecutive automated audit passes before final sign-off.
