# Platform Acceptance Matrix

| Batch | Gate | Command |
|---|---|---|
| 8 | Windows build/protect/run skeleton | `pwsh tests/platform/windows_acceptance.ps1` on Windows CI; local partial PE artifact check: `tests/platform/windows_cross_build.sh` |
| 9 | Linux ELF and `.so` smoke | `tests/platform/linux_smoke.sh` |
| 10 | Android emulator workflow plan | `tests/platform/android_emulator_plan.sh` |
| 11 | iOS logical no-runtime-codegen check | `tests/platform/ios_logic_check.sh` |
| 12 | CI secrets and platform gates | GitHub Actions workflows under `.github/workflows/` |

Protection steps are placeholders until the LLVM core protector CLI is merged. When available, each gate should insert protection between build and run, then compare protected and unprotected behavior reports. The local Windows cross-build report is not a replacement for the required GitHub Actions Windows execution gate.
