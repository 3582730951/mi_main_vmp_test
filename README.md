# Defensive LLVM IR VMP

This workspace follows `plan/1.txt`: a defensive, authorization-only LLVM IR protection pipeline with OLLVM-style mutation, bytecode virtualization, nested VM runtime policy, platform adapters, and automated acceptance gates.

The repository is intentionally explicit about boundaries. Anti-debug, anti-injection, root, hook, string hiding, and tamper checks are defensive integrity signals for owned or authorized software only. The project does not implement persistence, kernel hiding, security-product bypasses, credential theft, or unauthorized access.

## Layout

```text
docs/                 Architecture, task matrix, security policy, specs, QA reports
src/core/             Config parsing and LLVM/pass pipeline support
src/runtime/          Portable bytecode VM runtime
src/anti_analysis/    Defensive environment and exposure checks
src/platform/         Windows, Linux, Android, and iOS adapters
tests/                Unit, smoke, platform, and audit tests
scripts/audit/        Automated acceptance audit gate
.github/workflows/    Platform CI gates
examples/             Example protection configuration
```

## Key Documents

- `docs/ARCHITECTURE.md`
- `docs/TASKS.md`
- `docs/SECURITY_POLICY.md`
- `docs/CI_SECRETS.md`
- `docs/specs/ProtectionConfig.md`
- `docs/references/OFFICIAL_SOURCES.md`

## Acceptance

Manual reverse-engineering review from the original plan is not required in this phase. The added gate is three consecutive automated audit passes. Platform hard gates still require their corresponding environments: Windows GitHub Actions, Android emulator, and macOS/iOS logical CI.

Run the local audit after implementation files are present:

```bash
scripts/audit/run_three_pass_audit.sh
```
