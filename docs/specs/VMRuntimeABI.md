# VM Runtime ABI Specification

Status: frozen skeleton for tasks T012, T033-T035, and T050-T056.

The runtime ABI is defensive software-protection infrastructure for owned or explicitly authorized binaries.

## VM Layers

- VM0: outer runtime. Authorizes execution, decrypts chunks, chooses VM profile, and creates VM1 context.
- VM1: business bytecode interpreter.
- VM2: control and integrity VM. Verifies handler map, chunk metadata, and cross-VM state when `vm_level == 3`.

`vm_level` policy:

- `1`: VM1 only.
- `2`: VM0 + VM1.
- `3`: VM0 + VM1 + VM2.

Invalid levels fail closed.

## VMContext

Required fields:

- `regs[16]`: 64-bit virtual registers.
- `pc`: instruction index.
- `zf`: zero flag.
- `return_value`: 64-bit VM result.
- `halted`: dispatcher stop flag.
- bounded stack bytes.
- host-call table keyed by 8-bit bridge id.
- policy hooks for VM0/VM2.
- read-only active encrypted chunk view during encrypted-chunk execution.

The context is caller-owned for embedding and testability. Copies and moves of a context do not carry the active encrypted chunk view. Runtime entry points must avoid hidden global mutable state except immutable handler tables.

## Handler Table

The handler table maps semantic opcodes to implementation functions. Runtime dispatch decodes randomized opcode bytes through the per-function opcode map before handler lookup.

Handler order may be randomized for layout diversity, but semantic behavior must remain stable.

## Call Bridge

`CallHost` uses a bridge callback:

```text
uint64_t callback(VMContext&, uint8_t bridge_id)
```

The callback owns argument marshaling policy for the current platform ABI. If no callback exists for the bridge id, dispatch fails closed.
The current portable bridge copies `r[src0]` and `r[src1]` into scratch registers `r14` and `r15` before invoking the callback, then stores the callback return value in `r0`.
The VM restores dispatcher state, VM data state, policy hooks, and the host-call table after the callback returns, then commits only the callback return value to `r0`. Host bridges therefore cannot skip a subsequent integrity check by mutating `pc`, `halted`, `zf`, registers, stack, hooks, or bridge tables.

## Return Bridge

`Ret` copies the selected virtual register into `return_value` and halts VM1. Function replacement stubs must marshal `return_value` back to the native ABI without changing caller-visible behavior.

The portable runtime-entry shim currently exposes `i32` return stubs for zero,
one, two, three, and four `i32` arguments. Native arguments are copied into VM
registers `r1`, `r2`, `r3`, and `r4` respectively before dispatch.

## Runtime Artifact

The LLVM runtime-entry artifact starts with `VMPIRL4\0`, followed by a little-endian total artifact length, chunk metadata, a configuration seed-material hash, authenticated opcode-map bytes, payload length, and encrypted payload. Runtime-entry stubs pass both the byte pointer and the generated array length; parsing requires that external length to match the embedded total length before reading variable-sized opcode-map and payload sections. The parser rejects zero or duplicate opcode-map bytes and does not embed the raw configured seed string.

## Exception Bridge

The skeleton reports runtime failures as structured status codes. Platform adapters may translate these into exceptions only when the target language/ABI already requires that behavior. Unwinding through VM frames is not allowed until an explicit exception mapping is implemented.

## Policy Hooks

Policy hooks are abstract and platform-neutral:

- authorize chunk execution,
- observe dispatch start/finish,
- validate VM2 integrity,
- inspect cross-VM state transitions.

For direct embedding, `vm_level == 3` requires a `validateIntegrity` hook and fails closed before VM1 dispatch when the hook is absent or rejects the chunk. `CheckIntegrity` bytecode executes only while an encrypted chunk is active. It calls `validateIntegrity` with the active chunk and fails closed when no active chunk exists, no hook is installed, or the hook rejects the chunk. A VM level 3 chunk that also contains `CheckIntegrity` invokes the hook during VM2 pre-dispatch validation and again at the explicit bytecode check.

The portable C runtime-entry shim installs a structural default integrity hook so generated `vm_level == 3` artifacts can execute without platform-specific anti-analysis code. Platform adapters may replace this with stricter local policy.

Platform agents may implement these hooks. Core LLVM/VM files must not contain platform-specific anti-debug, anti-injection, root, or hook detection logic.
