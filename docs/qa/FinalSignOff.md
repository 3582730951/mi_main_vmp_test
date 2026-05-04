# Final Sign-Off

Status: **blocked, not signed off**.

The main_agent cannot honestly sign off the full `plan/1.txt` objective as complete. The repository now contains the local implementation skeletons, platform adapters, sample protected artifact, reports, and a three-run automated QA audit that passes. The stricter completion audit still fails because several hard acceptance items require evidence that is not available in this workspace.

## Passing Evidence

| Area | Evidence |
|---|---|
| Three-run local automated audit | `./acceptance.sh` passed three deterministic audit runs. This is not final sign-off; `./final_acceptance.sh` remains blocked by strict completion audit requirements. |
| Three comprehensive reviews | `docs/qa/reviews/review-1-core.md`, `docs/qa/reviews/review-2-platform-evidence.md`, and `docs/qa/reviews/review-3-audit-closure.md` record zero open vulnerabilities and zero open findings for the reviewed local scopes. |
| Parallel agent execution | `docs/qa/agent-runs/parallel-review-and-hardening.md` records multi-agent parallel review/hardening work and confirms no `passwd.txt` access. |
| Core VM skeleton | `tests/core/run_core_tests.sh` passed. |
| LLVM New PM plugin | `tests/core/run_llvm_plugin_test.sh` built `VMPPassPlugin.so`, loaded it through `opt-14`, verified transformed IR, split selected CFG blocks, materialized bytecode globals, and replaced selected zero-, one-, two-, three-, and four-argument `i32` sample functions with runtime-entry stubs. |
| Local protected sample | `tests/integration/run_protected_sample_chain.sh` passed. |
| Local release protected binary | `tests/integration/run_release_protected_binary.sh` produced `artifacts/protected/linux/protected_release_sample`; `docs/qa/reports/release-protected-binary.json` reports four VM behavior cases passed and no configured forbidden plaintext hits. |
| Protected sample behavior | `samples/protected_chain/out/behavior.json` reports protected and baseline behavior match. |
| Protected sample string scan | `samples/protected_chain/out/strings.json` reports configured critical strings absent. |
| Protected sample randomness | `samples/protected_chain/out/randomness.json` reports deterministic rebuild and alternate-seed opcode-map change. |
| Local platform checks | `tests/platform/run_all_local.sh` passed Linux and iOS logical checks. |
| Windows PE cross-build | `tests/platform/windows_cross_build.sh` produced local `pei-x86-64` `.dll/.exe` artifacts and `docs/qa/reports/windows-cross-build.json`. |
| Windows protected PE cross-build | `tests/platform/windows_release_cross_build.sh` produced local `pei-x86-64` protected sample `.exe` evidence and `docs/qa/reports/windows-protected-cross-build.json`. The Windows workflow now runs `tests/platform/windows_protected_release.ps1` on `windows-latest` and uploads the generated report/artifacts when CI is available. |
| Windows hostile trigger CI path | `tests/platform/windows_hostile_trigger_report.ps1` is wired into the Windows workflow to collect controlled page-guard and module-load trigger evidence when a real Windows runner is available. This is not a substitute for external debugger, non-self hardware breakpoint, or external DLL injection evidence. |
| Android environment audit | `tests/platform/android_environment_check.sh` produced `docs/qa/reports/android-environment.json` showing SDK, NDK, emulator, AVD, and system-image availability. |
| Android native `.so` emulator smoke | `tests/platform/android_emulator_smoke.sh` produced `docs/qa/reports/android-emulator-smoke.json`; the x86_64 `.so` was pushed to the emulator, loaded with `dlopen`, and returned consistent core logic. |
| Android APK/JNI emulator smoke | `tests/platform/android_apk_smoke.sh` produced `docs/qa/reports/android-apk-smoke.json`; the non-debuggable APK installed on the emulator, Java/JNI returned `sum=42`, and the generated `protected_sample.vmp` was embedded in `libvmp_smoke_jni.so` and executed four consistent VM behavior cases inside Android. The Android workflow now calls `tests/platform/android_ci_emulator_smoke.sh`, uses Android signing secrets only on trusted non-PR events, and requires `docs/qa/reports/android-github-actions-verification.json` before release-strength evidence can pass. |
| Android hostile baseline probes | `tests/platform/android_hostile_trigger_report.sh` records baseline root, Magisk, Xposed/LSPosed, and Frida process/package/property probes on a booted emulator. The report is intentionally blocked unless real hostile trigger environments are present. |
| Hostile-environment policy report | `tests/platform/hostile_environment_report.py` produced `docs/qa/reports/hostile-environment.json` for synthetic policy triggers, Linux local trigger evidence, Android emulator baseline findings, and normal false-positive count. |
| Linux hostile trigger report | `tests/platform/linux_hostile_trigger_report.py` produced `docs/qa/reports/linux-hostile-triggers.json` with real local `LD_PRELOAD` mapping and tracer detection evidence. |
| Anti-analysis policy tests | Pytest-style anti-analysis functions passed under `PYTHONPATH=src`. |
| Secret hygiene | Automated audit skips `passwd.txt`, scans workflows, and found no secret findings. |

## Blocking Evidence

| Requirement | Blocker |
|---|---|
| Android hard acceptance | Local emulator smoke evidence now exists, including non-debuggable APK install, JNI execution, both ABI libraries, and Android execution of the generated protected VM sample embedded inside the JNI `.so`. It still does not prove signed production release protection because the required GitHub Actions API verification sidecar is absent, and it still lacks full LLVM lowering and hostile-environment trigger coverage. |
| Windows hard acceptance | Local PE `.dll/.exe` and protected sample cross-build evidence exists, and the workflow is wired to build/run the protected sample and collect controlled hostile-trigger evidence on `windows-latest`, but no actual GitHub Actions run log has produced and executed protected artifacts yet. |
| Aggregate CI hard acceptance | Workflow and secret-hygiene wiring exists, but strict hard acceptance now requires generated non-Linux runner reports with GitHub Actions API verification sidecars; local workflow files alone are not enough. |
| IDA/OllyDbg hard acceptance | Automated anti-analysis/string indicators exist, but `docs/qa/reports/ida-ollydbg-review.json` is absent; manual reverse-engineering review evidence is required before this can be signed off as hard-pass. |
| Dynamic hostile-environment acceptance | Synthetic policy trigger coverage, partial Linux real trigger evidence, and Android emulator root/debuggable baseline trigger findings exist, but no generated report proves real Windows external hardware breakpoint/DLL injection or Android Xposed/LSPosed/root/Frida/hook trigger behavior on target platforms. |
| VMProtect-tier commercial claim | Current implementation now has a loadable LLVM New PM plugin that derives executable VM runtime stubs for narrow `i32` zero-, one-, two-, three-, and four-argument functions with straight-line local alloca/load/store, repeated loads from a definite local store, branch-condition loads whose defining store is on the entry-to-branch prefix, single-slot branch/merge local stores with a definite store on every lowered path, add/sub/mul/and/or/xor/select expressions, `zext`/`sext` from supported `icmp i32` predicates to `i32`, narrow `trunc i32` to `i1`/`i8`/`i16` followed by `zext`/`sext` back to `i32` or through a wider integer and safely truncated back to `i32`, constant `shl`/`lshr`/`ashr` shifts with shift amounts in `0..31`, masked dynamic shifts, `eq`/`ne`/`sgt`/`slt`/`sge`/`sle`/`ugt`/`ult`/`uge`/`ule` acyclic branch trees and select conditions, simple PHI return merges, and direct internal `ordinary_add` host-call cases including multiple linear calls with preserved intermediate results, local-stack stores fed by select/call values, and simple branch-return host-call paths; nested VM branch targets are rebased when serialized, pre-existing bytecode globals must match a fresh lowering of the current body and be pass-marked immutable private globals before reuse, and replacement refreshes bytecode metadata to the actual generated global. Unmasked dynamic shifts, constant shifts outside `0..31`, poison-generating `nuw`/`nsw`/`exact` arithmetic or shift flags, unsupported integer casts outside the narrow trunc-extension and safe wide-round-trip pattern, reserved opaque-dispatch name collisions, pre-existing outline-name collisions, loops or irreducible control flow, uninitialized branch-local loads, loads outside the lowered store path or branch prefix, stale or mutable pre-seeded bytecode globals, local memory combined with PHI shapes, global stores, and observable side-effecting IR remain native. It links lowered functions through runtime-owned C entry points, reports unsupported selected functions explicitly, and has local sample-chain plus stripped release-binary evidence. It still lacks broad IR lowering, production cryptography, and platform-proven combined protection evidence. |

## Required To Sign Off

1. Connect a GitHub repository with a Windows runner and capture protected execution workflow logs plus live GitHub Actions verification sidecars.
2. Promote the Android smoke path from local skeleton evidence to protected release artifacts and add hostile-environment trigger reports.
3. Extend the LLVM New PM plugin beyond the current bounded `i32` replacement stubs into general selected-function lowering and production cryptography.
4. Produce hostile-environment trigger reports for each required Windows and Android platform signal, plus non-self hardware and memory breakpoint cases.
5. Re-run `./final_acceptance.sh`.

The exact external reports and fields required by the strict audit are listed in
`docs/qa/ExternalEvidenceRequest.md`.

Until those are complete, T155 remains blocked.
