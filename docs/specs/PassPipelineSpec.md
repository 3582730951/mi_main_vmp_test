# LLVM IR VMP Pass Pipeline Specification

Status: frozen skeleton for tasks T010 and T020-T028.

This project is for protecting owned or explicitly authorized software. The core pipeline must not implement persistence, stealth, credential access, kernel rootkits, or bypasses of security products.

## Pipeline Order

The LLVM New PM pipeline is fixed in this order:

1. `vmp-config-load`
   - Read `protect.yml`.
   - Validate `profile`, `seed`, `vm_level`, and protected function selectors.
   - Emit a deterministic configuration report.
2. `vmp-function-marker`
   - Mark functions selected by config.
   - Attach metadata: function hash, VM level, profile, and OLLVM strengths.
3. `vmp-ir-normalize`
   - Canonicalize integer operations, compares, branches, returns, and simple memory operations.
   - Remove lowering ambiguity where LLVM semantics allow multiple equivalent forms.
4. OLLVM-style transforms, in this exact order:
   - `vmp-block-split`
   - `vmp-flatten`
   - `vmp-bogus-branch`
   - `vmp-instruction-substitution`
   - `vmp-const-string-encryption`
5. `vmp-ir-to-bytecode`
   - Lower supported normalized IR into VM bytecode.
   - Unsupported IR must be diagnosed, marked unsupported, and left native instead of being partially replaced.
6. `vmp-opcode-randomize`
   - Build deterministic per-build and per-function opcode maps from seed material.
7. `vmp-bytecode-encrypt`
   - Serialize bytecode chunks.
   - Encrypt each chunk with a per-function key.
8. `vmp-nesting`
   - Apply `vm_level` policy:
     - `1`: VM1 business bytecode only.
     - `2`: VM0 decrypt/select + VM1 business bytecode.
     - `3`: VM0 + VM1 + VM2 integrity/control checks.
9. `vmp-anti-analysis-hooks`
   - Insert only abstract hook calls owned by the anti-analysis interface.
   - Platform-specific detection logic belongs to platform agents, not this core pipeline.
10. `vmp-function-replacement`
    - Replace selected functions with VM entry stubs.
    - Preserve ABI-visible call and return behavior.
11. `vmp-report`
    - Emit selected functions, VM levels, opcode-map hash, chunk hashes, and unsupported constructs.

## Determinism

Given the same source IR, config, platform salt, and seed, all core outputs must be byte-for-byte reproducible. Changing the seed or function identity must change:

- opcode byte assignment,
- handler order,
- bytecode encryption nonce/key stream,
- polymorphic lowering choices where enabled.

## Failure Policy

The pipeline fails closed by refusing partial or unsafe replacement on:

- unsupported IR in a selected function, which is diagnosed, marked unsupported, and left native,
- invalid `vm_level`,
- missing seed in non-development profiles,
- opcode collisions,
- bytecode authentication failure,
- ABI mismatch between lowering and runtime,
- runtime-entry symbol collisions or pre-existing runtime-entry declarations with incompatible type, linkage, attributes, or calling convention.

## Current Skeleton Coverage

The repository currently provides deterministic config parsing, opcode-map generation, bytecode chunks, encrypted/authenticated payloads, VM dispatch, nested policy primitives, and a loadable LLVM New PM plugin. The plugin lowers bounded `i32` runtime-entry stubs for functions with zero, one, two, three, or four `i32` arguments, covering straight-line local alloca/load/store, repeated loads from a definite local store, branch-condition loads whose defining store is on the entry-to-branch prefix, single-slot branch/merge local stores with a definite store on every lowered path, add/sub/mul/and/or/xor/select expressions, `zext`/`sext` from supported `icmp i32` predicates to `i32`, narrow `trunc i32` to `i1`/`i8`/`i16` followed by `zext`/`sext` back to `i32` or through a wider integer and safely truncated back to `i32`, constant `shl`/`lshr`/`ashr` shifts with shift amounts in `0..31`, dynamic shifts whose amount is proven safe by an `and i32 ..., 31` mask, `eq`/`ne`/`sgt`/`slt`/`sge`/`sle`/`ugt`/`ult`/`uge`/`ule` branch trees and select conditions, simple PHI return merges, and direct internal `ordinary_add` host-call cases including multiple linear calls with preserved intermediate results, local-stack stores fed by select/call values, and simple branch-return host-call paths. Nested acyclic conditional trees are lowered with absolute VM jump targets rebased when paths are merged. Pre-existing bytecode globals are reused only after the current function body is re-lowered, the generated artifact matches byte-for-byte, and the global is pass-marked, immutable, private, non-TLS, non-interposable, and in the default address space; replacement refreshes `!vmp.bytecode` metadata to the actual runtime stub global. Unmasked dynamic shifts, constant shifts outside `0..31`, poison-generating `nuw`/`nsw`/`exact` arithmetic or shift flags, unsupported integer casts outside the narrow trunc-extension and safe wide-round-trip pattern, reserved opaque-dispatch name collisions, pre-existing outline-name collisions, loops or irreducible control flow, uninitialized branch-local loads, loads whose defining store is outside the lowered return path or branch prefix, stale or mutable pre-seeded bytecode globals, local memory combined with PHI shapes, global stores, and observable side-effecting IR are marked unsupported instead of replaced. Broad LLVM IR lowering, production cryptography, and platform-proven release replacement are still outside the current skeleton coverage.
