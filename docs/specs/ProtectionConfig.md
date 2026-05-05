# Protection Configuration Spec

`protect.yml` is the stable user-facing configuration for the protection pipeline. The parser must reject unknown required fields, invalid enum values, and unsafe profiles.

## Top-Level Schema

```yaml
version: 1
seed: "hex-or-text-seed"
profile: hardened
targets:
  - name: "license_core"
    match: "function:license_check"
    vm_level: 3
    ollvm:
      split: true
      flatten: true
      bogus_branches: true
      substitution: true
      const_string_encryption: true
    anti_analysis:
      debug: true
      hardware_breakpoints: true
      memory_breakpoints: true
      injection: true
      hooks: true
      root_or_jailbreak: platform
    strings:
      critical:
        - "LICENSE_KEY"
        - "https://license.example.invalid"
platforms:
  windows:
    import_hiding: true
    tls_init: true
  linux:
    symbol_strip: safe
    pie_relro: true
  android:
    abi: ["arm64-v8a", "x86_64"]
    jni_registration: dynamic
  ios:
    no_jit: true
    metadata_policy: reduce
hotspot_analysis:
  enabled: true
  call_site_threshold: 2
  hot_vm_level: 1
  defense_floor: 1
callsite_obfuscation:
  enabled: true
  indirect_thunks: true
  hash_resolver: true
  jump_table: true
  per_callsite_thunks: true
  hide_exports: true
decompiler_traps:
  enabled: true
  intensity: 2
random_stack_backtrace:
  randomized: true
  min_interval_ms: 250
  jitter_ms: 750
  max_frames: 16
```

## Required Fields

| Field | Type | Requirement |
|---|---|---|
| `version` | integer | Must be `1` for this spec. |
| `seed` | string | Non-empty. Same seed must reproduce opcode maps and bytecode layout. Different seeds should produce measurable differences. |
| `profile` | enum | `balanced`, `hardened`, or `paranoid`. Default policy favors defense over performance. |
| `targets` | list | At least one protected function target. |
| `targets[].name` | string | Stable report name. |
| `targets[].match` | string | Function selector. Initial supported format is `function:<symbol-or-ir-name>`. |
| `targets[].vm_level` | integer | `1`, `2`, or `3`. |

## Automatic Hotspot Policy

`hotspot_analysis` enables static call-site counting in the LLVM pass. A selected
function whose direct call-site count reaches `call_site_threshold` is tagged as
`!vmp.hotspot`. When the function does not have an explicit per-function
`vm_level`, the pass may use `hot_vm_level`, but never below `defense_floor`.
Explicit `targets[].vm_level` values are preserved by default, so a security
critical function remains at its configured strength even when it is hot.

## Call-Site Obfuscation

`callsite_obfuscation` rewrites direct calls to replaced protected functions
through private hash-named thunks. For VM-replaced functions, the thunks resolve
the protected bytecode payload through a hash-keyed resolver and private jump
slot, then enter the VM runtime directly instead of materializing the protected
function address at the call site.
`per_callsite_thunks` gives each rewritten call site a distinct thunk,
resolver key, and jump slot, so repeated calls to the same protected function do
not collapse to one obvious call-graph hub.
`hide_exports` sets protected functions to hidden visibility where the platform
linkage permits it; ABI owners should keep public exports out of this mode.

## Decompiler And Stack Traps

`decompiler_traps` inserts opaque false branches and switch-shaped dead blocks
around runtime-entry stubs. `random_stack_backtrace` configures passive,
jittered stack-summary sampling for anti-analysis policy code; captured frames
are sanitized metadata and must not be logged with secrets.

## OLLVM Options

| Field | Default | Meaning |
|---|---|---|
| `split` | `true` | Split basic blocks before later mutation. |
| `flatten` | `true` | Convert selected CFGs to dispatcher form. |
| `bogus_branches` | `true` | Insert opaque branch structures that preserve behavior. |
| `substitution` | `true` | Replace arithmetic/logical operations with seeded equivalents. |
| `const_string_encryption` | `true` | Encrypt configured constants and critical strings. |

## Anti-Analysis Options

| Field | Values | Meaning |
|---|---|---|
| `debug` | boolean | Enable platform debugger detection. |
| `hardware_breakpoints` | boolean | Enable detection for externally-set hardware breakpoints where supported. |
| `memory_breakpoints` | boolean | Enable guard-page or suspicious memory breakpoint checks where supported. |
| `injection` | boolean | Enable abnormal module and preload checks. |
| `hooks` | boolean | Enable hook-framework and inline-hook indicators. |
| `root_or_jailbreak` | `false`, `true`, `platform` | Enable mobile hostile-environment checks. |

## Profiles

| Profile | VM Default | Anti-Analysis Default | Performance Policy |
|---|---|---|---|
| `balanced` | `1` | Debug and injection checks | Lower overhead but keeps string protection |
| `hardened` | `2` | Debug, injection, hooks, breakpoint checks | Default; defense takes priority |
| `paranoid` | `3` | All supported checks | Accepts size and latency growth |

## Validation Rules

1. `vm_level: 3` requires nested VM support to be compiled.
2. `android.jni_registration: dynamic` requires an Android adapter capable of dynamic native registration.
3. `ios.no_jit` must remain `true`; runtime-generated executable code is not allowed for iOS.
4. Critical strings must be passed to QA string scanners and must not appear in protected release artifacts.
5. Unknown platform keys are warnings. Unknown top-level keys are errors.

## Report Fields

The protector should emit a machine-readable report containing:

- configuration version and normalized profile;
- selected functions and VM level;
- seed fingerprint, never the raw secret seed if configured sensitive;
- enabled OLLVM and anti-analysis passes;
- per-function bytecode chunk ids;
- string-policy scan targets;
- warnings, skipped functions, and platform constraints.
