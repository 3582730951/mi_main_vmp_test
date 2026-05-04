# Task Matrix

`plan/1.txt` is the execution baseline. This file turns the plan into owner-scoped work packages and records prohibited modification areas so parallel agents can work without changing shared interfaces accidentally.

## Global Rules

| Rule | Requirement |
|---|---|
| Ownership | Agents modify only their assigned directories unless main_agent explicitly expands scope. |
| Interface freeze | `docs/specs/BytecodeSpec.md`, `docs/specs/VMRuntimeABI.md`, and `docs/specs/ProtectionConfig.md` are frozen interfaces after Batch 1. |
| Secrets | `passwd.txt` may exist only as a local migration source. Its contents must not be printed, committed, copied into docs, or written into workflows. |
| Evidence | Each task needs a file artifact and an automated or documented acceptance check. |
| Manual review | Manual review items from the plan are tracked as future work and are not required in this phase. |

## Batch 0

| Task | Owner | Output | Acceptance | Prohibited Changes |
|---|---|---|---|---|
| T000 | main_agent | `plan/1.txt` | Plan exists and is treated as baseline | Do not rewrite plan scope without user approval |
| T001 | main_agent | `docs/ARCHITECTURE.md` | Architecture defines IR core, runtime, platform adapters, and anti-analysis boundary | None |
| T002 | main_agent | `docs/TASKS.md` | Every plan task is mapped to owner/scope/acceptance | None |
| T003 | main_agent | `docs/SECURITY_POLICY.md` | Authorized-use boundary and prohibited behavior are explicit | None |
| T004 | main_agent | `docs/CI_SECRETS.md` | Secret migration and workflow usage rules are explicit | Must not include secret values |
| T005 | main_agent | `docs/references/OFFICIAL_SOURCES.md` | Official source list covers LLVM, PE/COFF, Android NDK, GitHub Actions, and Apple/iOS | Prefer primary sources |

## Batch 1

| Task | Owner | Output | Acceptance | Prohibited Changes |
|---|---|---|---|---|
| T010 | llvm_core_agent | `docs/specs/PassPipelineSpec.md` | Pass order is fixed | Platform directories |
| T011 | llvm_core_agent | `docs/specs/BytecodeSpec.md` | Register model, opcode categories, chunk format, and encryption metadata are fixed | Platform directories |
| T012 | llvm_core_agent | `docs/specs/VMRuntimeABI.md` | VM context, handler table, call/return/exception bridge are fixed | Platform directories |
| T013 | main_agent | `docs/specs/ProtectionConfig.md` | `protect.yml` fields are fixed | Core/runtime implementation without owner coordination |
| T014 | qa_agent | `docs/specs/Acceptance.md` | Automated acceptance metrics are fixed | Core ABI specs |

## Implementation Batches

| Batch | Tasks | Owner(s) | Primary Scope | Acceptance Evidence |
|---|---|---|---|---|
| 2 LLVM/OLLVM | T020-T029 | llvm_core_agent, qa_agent | `src/core/`, `tests/core/` | Plugin/config/pass tests and reports |
| 3 Single VMP | T030-T037 | llvm_core_agent, qa_agent | `src/runtime/`, `tests/core/` | Behavior tests and baseline performance report |
| 4 Randomization | T040-T046 | llvm_core_agent, qa_agent | `src/runtime/`, `tests/core/`, `docs/qa/` | Multi-seed randomness validation |
| 5 Nested VM | T050-T056 | llvm_core_agent, qa_agent | `src/runtime/`, `tests/core/` | Level 1/2/3 behavior tests |
| 6 Static anti-analysis | T060-T067 | anti_analysis_agent, qa_agent | `src/anti_analysis/`, `tests/anti_analysis/`, `docs/qa/` | String scan and static-analysis report |
| 7 Dynamic analysis | T070-T080 | anti_analysis_agent, platform agents, qa_agent | `src/anti_analysis/`, `src/platform/`, `tests/platform/` | Detection trigger and false-positive reports |
| 8 Windows | T090-T097 | windows_agent, qa_agent | `src/platform/windows/`, `.github/workflows/` | Windows CI build/protect/run result |
| 9 Linux | T100-T106 | linux_agent, qa_agent | `src/platform/linux/`, `tests/platform/linux/` | Local Linux protected ELF/`.so` smoke result |
| 10 Android | T110-T117 | android_agent, qa_agent | `src/platform/android/`, `.github/workflows/` | Emulator APK/`.so` smoke result |
| 11 iOS | T120-T126 | ios_agent, qa_agent | `src/platform/ios/`, `docs/platform/ios/` | Logical no-JIT/signing/Mach-O review |
| 12 CI/secrets | T130-T135 | main_agent, qa_agent | `docs/CI_SECRETS.md`, `.github/workflows/`, `scripts/audit/` | Secret hygiene audit and CI gate policy |
| 13 Performance | T140-T144 | llvm_core_agent, anti_analysis_agent, qa_agent | `tests/qa/`, `docs/qa/` | Benchmark report and defense-preserving optimization notes |
| 14 Final | T150-T155 | qa_agent, main_agent | `docs/qa/`, generated reports | Complete evidence checklist and final sign-off decision |

## Interface Change Process

1. The agent proposing an interface change records the reason, affected tests, and migration impact.
2. main_agent decides whether the change is allowed.
3. Specs are updated before implementation lands.
4. QA updates acceptance checks so stale implementations fail visibly.

## Current Phase Notes

The initial repository is empty apart from `plan/1.txt`, `setup-codex.sh`, and local `passwd.txt`. This phase creates the baseline implementation and automated gates. Platform hard gates that require GitHub-hosted runners, Android emulators, or Apple signing infrastructure remain blocked until those environments are connected and their logs are captured.
