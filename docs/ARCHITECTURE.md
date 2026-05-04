# Architecture

This repository implements a defensive LLVM IR protection pipeline for software owned by, or explicitly authorized for, the operator. The design goal is layered protection: IR normalization and OLLVM-style mutation, bytecode virtualization, nested runtime dispatch, platform adapters, and measurable acceptance gates.

The system is divided into four bounded layers:

1. **IR core**: LLVM New PM pass plugin, protection configuration parser, function selection, IR normalization, mutation passes, and IR-to-bytecode lowering.
2. **VM runtime**: portable bytecode metadata, encrypted chunks, deterministic seed-based opcode maps, handler dispatch, nested VM policy, call/return bridges, and integrity state.
3. **Anti-analysis layer**: defensive environment checks, string/API exposure policy, junk-template metadata, and platform-neutral detection results. This layer reports hostile or suspicious conditions to the runtime; it does not implement persistence, kernel hooks, security-product bypasses, or stealth.
4. **Platform adapters**: PE/COFF, ELF, Android NDK/JNI, and iOS/Mach-O integration logic. Platform code owns calling conventions, initialization, packaging, symbol policy, and CI wiring.

## Layer Contracts

| Layer | Owns | Must Not Own |
|---|---|---|
| IR core | LLVM pass order, protected function selection, lowering decisions, opcode metadata | OS-specific initialization, credentials, CI secrets |
| VM runtime | VM context, handler table, chunk encryption/decryption, nested VM dispatch | Business logic, platform package signing, debugger-specific UI behavior |
| Anti-analysis | Detection abstractions and policy outputs | Malicious evasion, persistence, kernel-mode hiding, disabling security tools |
| Platform adapters | ABI bridges, loaders, sections, signing/package flow, smoke tests | Core bytecode ABI changes without main_agent approval |
| QA | Acceptance scripts, reports, audit gates, behavior/string/performance checks | Manual sign-off gates for this phase |

## Core Flow

```text
protect.yml
  -> config parser
  -> function marker
  -> normalize
  -> OLLVM passes
  -> VM lowering
  -> nested VM planning
  -> anti-analysis hook insertion
  -> platform adapter/link/package
  -> automated acceptance
```

The frozen pass order is specified in `docs/specs/PassPipelineSpec.md`. The bytecode format is specified in `docs/specs/BytecodeSpec.md`. Runtime ABI details are specified in `docs/specs/VMRuntimeABI.md`. User-facing protection configuration is specified in `docs/specs/ProtectionConfig.md`.

## VM Runtime Model

The portable runtime exposes:

| Component | Purpose |
|---|---|
| `VMContext` | Register file, VM stack, flags, return slot, platform bridge pointer, integrity status |
| `BytecodeChunk` | Per-function encrypted bytecode, seed metadata, opcode map id, platform salt id |
| `HandlerTable` | Runtime mapping from randomized opcode values to semantic handlers |
| `CallBridge` | Controlled transition from VM bytecode to unprotected local or external calls |
| `ReturnBridge` | ABI-stable return path from VM execution to the original caller |
| `ExceptionBridge` | Future extension point for platform exception/unwind behavior |

Nested VM levels are policy-driven:

| `vm_level` | Behavior |
|---|---|
| `1` | VM1 executes business bytecode directly. |
| `2` | VM0 decrypts/selects chunks and dispatches VM1. |
| `3` | VM2 adds control-flow and handler integrity checks around VM0/VM1. |

## Platform Boundaries

| Platform | Current Acceptance Mode |
|---|---|
| Linux | Local build and smoke tests are expected where toolchains are available. |
| Windows | Build/protect/run must be represented by GitHub Actions and validated on a Windows runner before final hard acceptance. |
| Android | NDK/JNI logic and packaging must be present; emulator execution is required for final hard acceptance. |
| iOS | Current phase is logical validation: Mach-O runtime design, signing/resigning flow, no-JIT compatibility, and metadata exposure policy. Real-device execution is not a hard gate in this phase. |

## Security Boundary

This project is not a malware evasion framework. Anti-debug, anti-injection, root, hook, and tamper checks are only used to protect owned or authorized software and to support integrity decisions inside the protected runtime. The repository must not include code or instructions for:

- persistence or covert auto-start;
- kernel rootkits or kernel-mode hiding;
- disabling, bypassing, or tampering with security products;
- credential theft or unauthorized access;
- unauthorized bypass of platform policy, DRM, or third-party protections.

## Acceptance Strategy

Automated acceptance is additive. Passing a unit test, workflow syntax check, or audit script does not by itself prove commercial-grade protection. The final sign-off must map every plan item to concrete evidence: source files, generated reports, executable test output, CI status, and known gaps.

The local automated gate excludes manual reverse-engineering review as a proxy signal. The strict completion audit must keep the original IDA/OllyDbg hard acceptance blocked until manual review evidence is imported, and separately records three independent comprehensive review closures for the user-requested multi-agent review gate.
