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
