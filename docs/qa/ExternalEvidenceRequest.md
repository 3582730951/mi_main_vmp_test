# External Evidence Request

The local workspace passes the automated acceptance audit, but final sign-off is
blocked until target-platform evidence is produced outside this container. Do
not read or upload `passwd.txt`; use GitHub Encrypted Secrets and workflow
artifacts only.

## Required Windows Evidence

Run `.github/workflows/platform-windows.yml` on a real `windows-latest` or
self-hosted Windows runner and preserve these reports as workflow artifacts:

- `docs/qa/reports/windows-acceptance.json`
- `docs/qa/reports/windows-protected-release.json`
- `docs/qa/reports/windows-github-actions-verification.json`
- `docs/qa/reports/windows-hostile-triggers.json`
- `docs/qa/reports/windows-hostile-github-actions-verification.json`

The strict completion audit expects Windows CI evidence to include:

- `status: "pass"` for acceptance and protected release reports;
- `ci_execution: true`;
- `github_actions: true`;
- trusted GitHub event metadata from the same non-`pull_request` run:
  `github_run_id`, `github_run_attempt`, `github_run_url`,
  `github_repository`, `github_sha`, `github_workflow`, `github_event_name`,
  `github_ref`, `github_ref_name`, and `github_ref_protected`;
- `github_workflow: "platform-windows"`;
- `runner_os: "Windows"`;
- protected `.exe` execution success;
- `.dll` load success;
- positive-byte `.exe`, `.dll`, and protected `.exe` artifacts with SHA-256
  hashes;
- `windows-github-actions-verification.json` with `github_api_verified: true`
  for the same non-`pull_request` run and evidence report paths, with
  `github_actions_runtime: true`, `github_ref_protected: true`, empty
  `pull_requests`, matching `head_repository`, exact
  `expected_workflow: "platform-windows"` and
  `expected_workflow_path: ".github/workflows/platform-windows.yml"`,
  `artifact_name: "windows-protected-release-evidence"`, `report_sha256`
  hashes for the verified reports, `max_run_age_days: 30`, and no mismatches
  other than the provisional `api:run_not_completed` marker emitted inside the
  still-running workflow. The strict completion audit rechecks the run against
  the live GitHub Actions API, requires the final run to be completed and
  successful, downloads the named workflow artifact, and verifies the sidecar
  and reports byte-for-byte before accepting the evidence;
- four protected behavior cases passed;
- no forbidden plaintext hits.

Windows hostile-environment evidence remains incomplete unless external trigger
reports cover non-self hardware breakpoints, memory/page breakpoints, external
debugger attachment, and external DLL injection. A passing
`windows-hostile-triggers.json` must include `status: "pass"`,
`schema: "vmp.platform.windows_hostile_triggers.v1"`, `ci_execution: true`,
`github_actions: true`, `github_workflow: "platform-windows"`,
`runner_os: "Windows"`, the trusted GitHub metadata listed above, an empty
`missing_required_external_triggers` list, true
`non_self_hardware_breakpoint_observed`, `memory_page_breakpoint_observed`,
`external_debugger_observed`, and `external_dll_injection_observed` fields,
`findings` signals covering hardware, memory/page, debugger, and DLL/injection
classes, plus
`windows-hostile-github-actions-verification.json` for the same
non-`pull_request` run.

## Required Android Evidence

Run `.github/workflows/platform-android-plan.yml` with these GitHub Secrets set:

- `ANDROID_KEYSTORE_B64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

Preserve these reports/artifacts:

- `docs/qa/reports/android-environment.json`
- `docs/qa/reports/android-emulator-smoke.json`
- `docs/qa/reports/android-apk-smoke.json`
- `docs/qa/reports/android-github-actions-verification.json`
- `docs/qa/reports/android-hostile-triggers.json`
- `docs/qa/reports/android-hostile-github-actions-verification.json`
- `build/android-apk-smoke/vmp-smoke.apk`
- packaged `libvmp_platform.so` and `libvmp_smoke_jni.so` for `x86_64` and `arm64-v8a`

The strict completion audit expects Android release-strength evidence to include:

- `status: "pass"`;
- `github_actions: true`;
- `ci_execution: true`;
- trusted GitHub event metadata from the same non-`pull_request` run:
  `github_run_id`, `github_run_attempt`, `github_run_url`,
  `github_repository`, `github_sha`, `github_workflow`, `github_event_name`,
  `github_ref`, `github_ref_name`, and `github_ref_protected`;
- `github_workflow: "platform-android"`;
- `release_signing_secret_used: true`;
- `signing_key_scope: "github_secret_keystore"`;
- `manifest_debuggable: false`;
- `protected_payload_embedded_in_jni: true`;
- `protected_sample_asset_packaged: false`;
- empty `apk_forbidden_plaintext_hits`;
- empty `jni_symbol_plaintext_hits`;
- `core_logic_consistent: true`;
- the paired `android-emulator-smoke.json` report must also come from the same
  `platform-android` run, with `github_actions: true`, `ci_execution: true`,
  passing emulator execution, protected `.so` load, and matching run metadata.
- `android-github-actions-verification.json` with `github_api_verified: true`
  for the same non-`pull_request` run and both Android smoke evidence paths,
  with `github_actions_runtime: true`, `github_ref_protected: true`, empty
  `pull_requests`, matching `head_repository`, exact
  `expected_workflow: "platform-android"` and
  `expected_workflow_path: ".github/workflows/platform-android-plan.yml"`,
  `artifact_name: "android-emulator-smoke-evidence"`, `report_sha256` entries
  for `android-apk-smoke.json` and `android-emulator-smoke.json`,
  `max_run_age_days: 30`, and no mismatches other than the provisional
  `api:run_not_completed` marker emitted inside the still-running workflow. The
  strict completion audit rechecks the final run through the live GitHub Actions
  API, downloads the named artifact, and verifies the sidecar and reports before
  accepting the evidence.

Android hostile-environment evidence remains incomplete unless real trigger
reports cover root, Xposed/LSPosed, Frida, and hook behavior. The imported
`android-hostile-triggers.json` must have `status: "pass"`, an empty
`missing_required_triggers` list, `schema:
"vmp.platform.android_hostile_triggers.v1"`, `github_actions: true`,
`ci_execution: true`, the trusted GitHub metadata listed above,
`github_workflow: "platform-android"`,
`authorized_hostile_profile: true`, a non-empty `hostile_profile_id`, device
metadata from the hostile run, and findings for all three Android classes:

- root: `su`/Magisk path or command evidence, insecure build/boot properties,
  root-manager package/process evidence, or Magisk/Zygisk mount evidence;
- Xposed/LSPosed: XP-family package/process/property or known module path
  evidence;
- Frida/hook: Frida process/package, Frida/Gum socket, or default Frida TCP
  listener evidence.

It must also be accompanied by
`docs/qa/reports/android-hostile-github-actions-verification.json` with
`github_api_verified: true` for the same non-`pull_request` run and
`docs/qa/reports/android-hostile-triggers.json` as an evidence report, with
`github_actions_runtime: true`, `github_ref_protected: true`, empty
`pull_requests`, matching `head_repository`, exact Android workflow name/path,
`artifact_name: "android-emulator-smoke-evidence"`, `report_sha256` for
`android-hostile-triggers.json`, `max_run_age_days: 30`, and artifact-backed
live API revalidation.

## Required IDA/OllyDbg Evidence

Preserve a manual reverse-engineering review report at:

- `docs/qa/reports/ida-ollydbg-review.json`
- `docs/qa/reports/ida-ollydbg-github-actions-verification.json`

The strict completion audit expects:

- `schema: "vmp.qa.manual_reverse_review.v1"`;
- `status: "pass"`;
- `manual_review: true`;
- non-empty `reviewer` and `review_date`;
- `tools` containing both `IDA` and `OllyDbg`;
- `open_vulnerabilities: 0`;
- `open_findings: 0`;
- `reviewed_indicators.f5_or_decompiler_distortion: true`;
- `reviewed_indicators.xref_or_callgraph_distortion: true`;
- `reviewed_indicators.string_reference_distortion: true`;
- `reviewed_indicators.debugger_or_breakpoint_behavior: true`.

This report must come from an authorized human review of the generated protected
artifacts. Automated local indicators alone are not enough for this hard gate.
The review report must include trusted GitHub event metadata from the same
non-`pull_request` run: `github_run_id`, `github_run_attempt`,
`github_run_url`, `github_repository`, `github_sha`, `github_workflow`,
`github_event_name`, `github_ref`, `github_ref_name`, and
`github_ref_protected`, with `github_workflow: "manual-review"`. It must be accompanied by
`ida-ollydbg-github-actions-verification.json` with `github_api_verified: true`,
`github_actions_runtime: true`, exact
`expected_workflow_path: ".github/workflows/manual-review.yml"`,
`artifact_name: "manual-review-evidence"`, protected-ref metadata,
`report_sha256` for `ida-ollydbg-review.json`, `max_run_age_days: 30`, and
artifact-backed live API revalidation before accepting the report.

## Required VMProtect-Tier Evidence

`docs/qa/reports/capability-matrix.json` must not set `status: "pass"` or
`final_signoff_allowed: true` until evidence exists for:

- general selected-function LLVM IR lowering, not only bounded `i32` stubs;
- production cryptography/key management;
- code virtualization, mutation, combined protection, string hiding, import hiding,
  anti-debug, anti-injection, and anti-tamper on release artifacts;
- platform-proven protected execution on Linux, Windows, and Android.

The strict completion audit also expects these sidecar reports before the
VMProtect-tier hard gate can pass:

- `docs/qa/reports/general-ir-lowering.json` with
  `schema: "vmp.qa.general_ir_lowering.v1"`, `status: "pass"`,
  `broad_ir_lowering: true`, and `bounded_i32_only: false`;
- `docs/qa/reports/production-crypto-key-management.json` with
  `schema: "vmp.qa.production_crypto_key_management.v1"`, `status: "pass"`,
  `production_crypto: true`, `static_keys_present: false`, and
  `key_rotation_supported: true`;
- `docs/qa/reports/vmprotect-tier-review.json` with
  `schema: "vmp.qa.vmprotect_tier_review.v1"`, `status: "pass"`,
  `manual_review: true`, `open_vulnerabilities: 0`, `open_findings: 0`,
  all required protection capabilities set to `true`, and Linux, Windows, and
  Android listed in `platforms_proven`.

All four VMProtect-tier reports must include trusted GitHub event metadata from
the same non-`pull_request` run: `github_run_id`, `github_run_attempt`,
`github_run_url`, `github_repository`, `github_sha`, `github_workflow`,
`github_event_name`, `github_ref`, `github_ref_name`, and
`github_ref_protected`, with `github_workflow: "vmprotect-tier"`. They must also be accompanied by
`docs/qa/reports/vmprotect-tier-github-actions-verification.json` with
`github_api_verified: true`, `github_actions_runtime: true`,
exact `expected_workflow_path: ".github/workflows/vmprotect-tier.yml"`,
`artifact_name: "vmprotect-tier-evidence"`, protected-ref metadata, empty
`pull_requests`, matching `head_repository`, `report_sha256` hashes for all
four reports, `max_run_age_days: 30`, and no mismatches other than the
provisional in-run marker. The strict completion audit rechecks the final run
through the live GitHub Actions API, downloads the named artifact, and verifies
the sidecar and reports before accepting the evidence.

## Required Reverse-Cost Evidence

The user-requested "minimum one year reverse cost" claim is not accepted from
local tests, manifests, or implementation effort alone. Final sign-off requires
a commit-bound assessment report preserved at:

- `docs/qa/reports/reverse-cost-assessment.json`

The report must use `schema: "vmp.qa.reverse_cost_assessment.v1"` and include:

- `status: "pass"`;
- either `manual_review: true` from an external reviewer or
  `assessment_mode: "automated_tooling"` with `automated_review: true` and
  non-empty `tool_results`/`score_breakdown`;
- non-empty `reviewer`, `methodology`, `assessment_date`, and `review_tools`;
- `github_sha` matching the checked-out commit being signed off;
- `protected_artifact_sha256` for the assessed protected release artifact;
- `minimum_reverse_cost_days` greater than or equal to `365`;
- `assessed_capabilities` with these booleans set to `true`:
  `automatic_hotspot_analysis`, `defense_floor_preserved`,
  `callsite_obfuscation`, `per_callsite_thunks`,
  `protected_function_address_not_materialized`, `decompiler_traps`, and
  `randomized_stack_backtrace`.

`./final_acceptance.sh` runs `scripts/audit/reverse_cost_gate.py` after the
strict plan audit and fails if this report is missing, stale, or estimates less
than 365 days.

For the automated path, run `.github/workflows/reverse-cost.yml` on the target
commit and import the `reverse-cost-evidence` artifact. That workflow rebuilds
the protected sample, scans the protected binary with command-line analysis
tools, verifies the LLVM call-site/decompiler-trap evidence, generates the
assessment report, and runs the same reverse-cost gate.

## Recheck Commands

After importing the external reports/artifacts into the workspace, run:

```sh
./final_acceptance.sh
```

`final_acceptance.sh` preserves the imported external report files while it runs
the local acceptance gate, restores them even if the local gate fails, removes
listed external reports that were absent before the run, and then runs the
strict completion audit. Set `GITHUB_TOKEN` for the strict audit so live GitHub
Actions API and artifact revalidation can run.

Only if the strict completion audit has no blockers may `T155` be signed off.
