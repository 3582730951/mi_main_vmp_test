# Automated Acceptance Specification

This specification defines the local QA gate for `qa_agent` scope. It is based on `plan/1.txt` and intentionally excludes manual IDA, OllyDbg, and human reverse-engineering review. Manual review can be added by another owner, but it is not required by this automated gate. This local gate is not final sign-off for the full plan.

## Gate Command

Run the full local gate from the repository root:

```sh
./acceptance.sh
```

The runner executes core, integration, platform, performance, surface-minimization, and report-generation checks once, then executes the deterministic automated audit three times. All three audit runs must pass and produce consistent counts for task coverage, workflow findings, secret hygiene findings, string-policy findings, surface-minimization findings, and test inventory.

For final sign-off, run the strict gate instead:

```sh
./final_acceptance.sh
```

`final_acceptance.sh` preserves imported external evidence reports, runs the local gate, restores those reports, runs `scripts/audit/objective_completion_audit.py --root .`, runs `scripts/audit/reverse_cost_gate.py --root .`, regenerates `docs/qa/FinalSignOff.md` with `scripts/audit/finalize_external_evidence.py --root .`, and then runs `scripts/audit/plan_completion_audit.py --root . --write-doc --json`. It must fail while any literal objective item remains blocked, Windows/Android GitHub Actions evidence, VMProtect-tier sidecars, manual reverse-engineering evidence, or the commit-bound reverse-cost assessment are absent. When external GitHub evidence is imported, the strict audit needs `GITHUB_TOKEN` so it can recheck verification sidecars against the live GitHub Actions API.

## Automated Checks

| Area | Automated acceptance |
|---|---|
| Plan coverage | Parse `plan/1.txt`, discover all `T000` style tasks, and verify every `qa_agent` task is referenced by QA acceptance documentation. |
| Docs/tasks coverage | Verify this spec exists, QA coverage docs exist, and QA-owned task references are represented in `docs/specs/Acceptance.md` or `docs/qa/**`. |
| Secrets hygiene | Scan repository text files except `passwd.txt` itself. The gate must not read, print, hash, or depend on `passwd.txt` contents. No committed file may contain likely GitHub PATs, private keys, or sensitive assignments. |
| Workflow secret references | Scan `.github/workflows/**` when present. Workflows must not reference `passwd.txt`, raw PAT/token/password values, or sensitive environment values outside `${{ secrets.* }}`. |
| String policy | Protected release artifacts must not contain business-critical strings, API names, JNI names, authorization fields, URLs, or key material in plaintext. Until protected artifacts exist, the gate verifies that the string policy is documented and reports zero scanned artifacts. |
| Surface minimization | Generate `docs/qa/reports/surface-minimization.json` from release artifacts. The report must show zero avoidable product, VM, OLLVM, protected plaintext, and explicit import-resolver markers. Mandatory PE/ELF/APK container signatures are recorded as observations rather than treated as removable. |
| Objective completion | Generate `docs/qa/reports/objective-completion-audit.json` and fail final acceptance unless every literal objective item is `pass`. The report must map each prompt item to concrete artifacts and verification commands. |
| Protected callgraph | Generate `docs/qa/reports/protected-callgraph.json` from LLVM IR evidence. The report must show that direct xrefs to protected functions are discovered before replacement, removed after callsite thunking, and that high-frequency callsite optimization preserves the configured defense floor. |
| Available tests | Verify there is at least one automated QA test under `tests/qa/**`, at least one audit script under `scripts/audit/**`, and runnable test commands are discoverable. |
| Performance report | Generate `docs/qa/reports/performance-sample.json` from the protected sample benchmark. The report must include baseline/protected runtime, overhead ratio, artifact size, and `defense_priority: true`. |

## QA Task Coverage

The automated gate tracks the following QA-owned tasks from `plan/1.txt`:

| Task | Automated acceptance scope |
|---|---|
| T014 | Acceptance spec exists and defines Android, Windows CI, iOS logic, string, analysis, and performance criteria without manual review as a gate dependency. |
| T029 | OLLVM pass tests are discoverable when implementation lands. |
| T036 | Behavior tests are discoverable when protected samples land. |
| T037 | Baseline performance reporting location and command are discoverable when benchmarks land. |
| T046 | Randomness validation tests are discoverable when seed-controlled outputs land. |
| T056 | Nested VM behavior tests are discoverable when VM levels land. |
| T067 | Automated anti-analysis/string metrics are documented; manual IDA/OllyDbg review is excluded from this local gate. |
| T080 | Dynamic-analysis validation slots are documented for detection trigger and false-positive reports. |
| T097 | Windows CI acceptance is checked through workflow secret hygiene and future workflow/test inventory. |
| T106 | Linux acceptance slots are documented for behavior and string checks. |
| T116 | Android emulator acceptance slots are documented for APK or `.so` smoke tests. |
| T117 | Android hostile-environment acceptance slots are documented for root, XP/LSPosed, Frida, and hook checks. |
| T126 | iOS logical acceptance slots are documented without requiring real-device execution. |
| T132 | Windows GitHub Actions workflow audit is enabled when workflows are present. |
| T133 | Android emulator CI plan is represented as an automated workflow/test inventory requirement when workflows land. |
| T134 | macOS/iOS logic CI plan is represented as an automated workflow/test inventory requirement when workflows land. |
| T140 | Performance benchmark suite must become discoverable under tests or scripts when implementation lands. |
| T144 | Performance acceptance must be represented by machine-readable report checks when reports land. |
| T150 | Protected sample inventory must become discoverable when samples land. |
| T151 | Behavior report must become machine-checkable when protected samples land. |
| T152 | String report must be generated by automated scanning for protected artifacts. |
| T153 | Anti-analysis report must use automated indicators in this gate; manual review remains out of scope. |
| T154 | Hostile environment report must become machine-checkable when platform harnesses land. |

## Artifact String Policy

For release protected binaries, the string scanner fails on plaintext occurrences from these categories:

- Business-critical strings and product secrets.
- API names used for dynamic resolution policy violations.
- JNI names and Java/Kotlin native bridge names.
- Authorization fields, bearer tokens, license keys, and key material.
- URLs, callback hosts, and endpoint paths that are not explicitly allowlisted.

The scanner must operate on generated protected artifacts only. It must never use `passwd.txt` as input and must not print secret-bearing strings found during scanning; reports use file paths, categories, and counts.

## Artifact Surface Policy

The surface-minimization audit separates mandatory executable container features
from avoidable protector signatures. PE, ELF, APK/ZIP headers, dynamic-linker
metadata, and CRT startup artifacts can be observed in reports because removing
them would make the platform loader reject the file. The gate fails on avoidable
markers such as ASCII VM container magic, OLLVM/product names, protected seed or
business strings, and explicit import-resolver API names in protected release
artifacts.

When available in the runner, the surface and reverse-cost reports also record
optional LIEF, capa, radare2/r2pipe, Rizin/radare2, and angr observations so
import/export, capability, function inventory, and callgraph checks can be
cross-checked by common open-source analysis tooling.

The syscall policy is intentionally conservative: the project records that
generic direct-syscall substitution is not implemented for evasion. Required
system interaction must remain in approved platform adapters or fixed runtime
APIs under `docs/SECURITY_POLICY.md`. The objective audit also verifies that
platform adapter source stays self-contained, release artifacts minimize
import/export/TLS surface, and the only direct syscall in release source is the
fixed Linux x86_64 `exit` path used by the CRT-free runner.

The protected-program stability gate requires behavior equivalence for the
generated protected sample, a local Linux release runner that executes all four
cases, Windows protected-release execution from GitHub Actions evidence,
Android emulator APK/JNI and native smoke evidence, and iOS no-JIT/Mach-O logic
evidence.
