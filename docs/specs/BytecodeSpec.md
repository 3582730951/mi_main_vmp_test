# Bytecode Specification

Status: frozen skeleton for tasks T011, T030-T034, and T040-T045.

All bytecode is generated only for owned or explicitly authorized software.

## Register Model

- 16 general-purpose 64-bit virtual registers: `r0` through `r15`.
- `r0` is the default return register.
- `zf` is the zero flag used by conditional branches.
- The VM stack is a bounded byte vector owned by `VMContext`.
- Host pointers are represented as opaque 64-bit values. Dereference policy is runtime/platform-owned.

## Instruction Encoding

Each serialized instruction is 12 bytes:

| Offset | Size | Field |
|---|---:|---|
| 0 | 1 | randomized opcode byte |
| 1 | 1 | `dst` register or small index |
| 2 | 1 | `src0` register |
| 3 | 1 | `src1` register |
| 4 | 8 | little-endian immediate |

The randomized opcode byte is decoded by the per-function opcode map. Opcode byte `0x00` is reserved and must not encode a real semantic operation.

## Semantic Opcodes

| Semantic | Meaning |
|---|---|
| `Nop` | No operation. |
| `LoadImm` | `r[dst] = imm`. |
| `Mov` | `r[dst] = r[src0]`. |
| `Load` | `r[dst] = stack[imm..imm+8)`. |
| `Store` | `stack[imm..imm+8) = r[src0]`. |
| `Add` | `r[dst] = r[src0] + r[src1]`. |
| `Sub` | `r[dst] = r[src0] - r[src1]`. |
| `Mul` | `r[dst] = r[src0] * r[src1]`. |
| `And` | `r[dst] = r[src0] & r[src1]`. |
| `Or` | `r[dst] = r[src0] | r[src1]`. |
| `Xor` | `r[dst] = r[src0] ^ r[src1]`. |
| `Shl` | `r[dst] = uint32(r[src0]) << (uint32(r[src1]) & 31)`, stored as low32. |
| `LShr` | `r[dst] = uint32(r[src0]) >> (uint32(r[src1]) & 31)`, stored as low32. |
| `AShr` | `r[dst] = int32(r[src0]) >> (uint32(r[src1]) & 31)`, stored as low32. |
| `CmpEq` | `zf = (low32(r[src0]) == low32(r[src1]))`. |
| `CmpNe` | `zf = (low32(r[src0]) != low32(r[src1]))`. |
| `CmpSgt` | `zf = (int32(r[src0]) > int32(r[src1]))`. |
| `CmpSge` | `zf = (int32(r[src0]) >= int32(r[src1]))`. |
| `CmpSle` | `zf = (int32(r[src0]) <= int32(r[src1]))`. |
| `CmpUgt` | `zf = (uint32(r[src0]) > uint32(r[src1]))`. |
| `CmpUge` | `zf = (uint32(r[src0]) >= uint32(r[src1]))`. |
| `CmpUle` | `zf = (uint32(r[src0]) <= uint32(r[src1]))`. |
| `Select` | `r[dst] = zf ? r[src0] : r[src1]`. |
| `Jump` | `pc = imm`. |
| `JumpIfZero` | If `zf`, `pc = imm`, else continue. |
| `CallHost` | Call host bridge id `dst`; `r[src0]` and `r[src1]` are copied to host argument scratch registers `r14` and `r15`, and the host return value is written to `r0`. |
| `CheckIntegrity` | Invoke the active chunk integrity hook; fail closed if no encrypted chunk is active, no hook is installed, or the hook rejects the chunk. |
| `Ret` | Return `r[src0]`. |
| `Halt` | Stop without changing return value. |

## Chunk Format

The in-memory chunk object contains:

- magic: `VMPBC1`
- version: `1`
- VM level: `1`, `2`, or `3`
- function hash: stable 64-bit function identity
- platform salt: stable 64-bit platform/build salt
- nonce: 64-bit per-chunk nonce
- encrypted payload: serialized instructions
- authentication tag: keyed 64-bit integrity tag over metadata, opcode map, and ciphertext

The current skeleton stores the chunk as a structured C++ object instead of fixing a file container. A later object/section writer must preserve the same fields.

## Key Derivation

Per-function key material is derived from:

- global seed string,
- stable function hash,
- platform salt,
- VM level,
- purpose label.

Same inputs must reproduce identical chunks. Different seed, function hash, or platform salt must produce different ciphertext and opcode maps.

## Encryption and Integrity

The skeleton uses a deterministic stream cipher interface and keyed tag suitable for unit-testable build reproducibility. The keyed tag covers chunk metadata, the per-function opcode map, and encrypted payload bytes. Before production release, `main_agent` must approve the concrete cryptographic primitive and threat model. Runtime behavior is fail-closed: decrypting a tampered chunk or opcode map returns an error and does not dispatch.

## Polymorphic Lowering

Lowering may emit equivalent bytecode sequences for the same IR operation. The choice must be deterministic from seed material and must not change observable program behavior.

The current LLVM plugin maps each supported local `i32 alloca` to one 8-byte VM stack slot and caps the runtime-entry local stack subset at 32 slots (256 bytes). Loads require a definite prior store on the lowered return path or on the entry-to-branch prefix for branch conditions; straight-line repeated loads, branch-condition loads with dead stores outside the executed prefix, and the single-slot branch/merge shape where every lowered path stores before the merge load are allowed. Loads defined before a later branch-local store are rejected instead of being re-associated with the later store. Constant `i32` shifts are lowered only when the shift amount is in `0..31`, and dynamic shift amounts are lowered only when the IR proves the amount is masked with `and i32 ..., 31`. Compare results can be lowered through `zext i1 ... to i32` or `sext i1 ... to i32` when the operand is a supported `icmp i32`; narrow `trunc i32` to `i1`, `i8`, or `i16` followed by `zext`/`sext` back to `i32`, or by `zext`/`sext` to a wider integer and a final trunc back to `i32`, is lowered through masks or sign-extending shift pairs. Acyclic nested conditional trees are serialized into VM branches with rebased absolute jump targets. Local stack stores may be fed by supported `select` expressions or direct internal `ordinary_add` host-call bridge values when `ordinary_add` is a non-interposable local definition with an exact side-effect-free `i32 add` body. Pre-existing bytecode globals are reused only when they are pass-marked immutable private globals in the default address space and their initializer bytes match a fresh lowering of the current function body; function replacement refreshes `!vmp.bytecode` metadata to the actual generated global. Other integer casts remain unsupported. Unmasked dynamic shifts and poison-generating `nuw`/`nsw`/`exact` arithmetic or shift flags remain unsupported to avoid widening LLVM poison semantics. Unsigned `ult` predicates are lowered by swapping operands into `CmpUgt`. This convention is intentionally narrower than the VM instruction set: pointer escapes, global memory, atomics, volatile access, loops or irreducible control flow, reserved opaque-dispatch name collisions, pre-existing outline-name collisions, uninitialized branch-local loads, unsupported integer casts, stale or mutable pre-seeded bytecode globals, and local stack memory combined with PHI shapes remain unsupported and are left native.

The runtime artifact parser is intentionally fail-closed on opcode-map width mismatches, duplicate or zero opcode-map bytes, and runtime container magic. Adding semantic opcodes or changing config seed material requires regenerating `VMPIRL4` blobs and generated platform headers instead of reusing stale artifacts.
