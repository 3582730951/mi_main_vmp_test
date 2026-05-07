# Protection Capability Showcase

Generated: `2026-05-07T18:32:00.646577Z`

The project demonstrates local VM bytecode lowering/replacement, protected-callsite thunking, xref removal, decompiler-trap markers, strict release string/import minimization, a hardened Windows visible demo, and automated reverse-cost evidence.

Not claimed: This report does not claim complete VMProtect-tier commercial coverage for arbitrary programs.

| Capability | Status | Key Evidence | Main Limit |
| --- | --- | --- | --- |
| `vm_bytecode_lowering_and_function_replacement` | `partial` | selected=75; lowered=58; replaced=58; unsupported=17; implemented_stages=15 | placeholder_noop_stages=[] |
| `protected_xref_and_callgraph_distortion` | `demonstrated` | direct_xrefs_removed=True; rewritten_calls=3; unique_thunks=3; direct_call_after=False | The automated proof is IR-level and report-level; binary-level manual review remains a separate evidence source. |
| `anti_decompiler_trap_and_f5_distortion` | `partial` | trap_label=True; opaque_switch=True; ida_review=pass; plugin_recovery_risk=True | Current traps raise reverse cost but are not enough to claim resilience against stronger IDA plugin automation. |
| `string_plaintext_hiding` | `partial` | strict_zero_strings=True; windows_release_demo_encrypted=True; visible_forbidden_absent=True; generic_const_string_pass=True | Generic LLVM const-string encryption is implemented for private/internal constant byte arrays. |
| `dynamic_string_runtime_decryption` | `demonstrated` | chunked=True; full_plaintext_buffer=False; two_pass_tag=True; release_chunked=True | This protects generated visible-demo text at runtime; the LLVM const-string pass now covers private/internal constant byte arrays. |
| `strict_import_export_tls_surface_minimization` | `demonstrated` | surface=pass; linux_imports=0; windows_imports=4; windows_tls=False | The Windows release artifact is now the encrypted visible console demo, so fixed Kernel32 console imports are expected. |
| `windows_api_call_minimization_policy` | `demonstrated` | mode=minimal_fixed_kernel32_console_api; direct_syscalls=False; batched_write=True; imports=4 | The accepted Windows visible release minimizes and batches fixed console API use; it does not enable direct Windows syscall stubs or syscall-number harvesting. |
| `pe_section_name_randomization` | `demonstrated` | release_randomized=True; decoys=4; distinct=9; high_bit=9; zero_padded=0 | This prevents fixed section-name scripts from keying on stable names, but it does not randomize the whole PE layout. |
| `windows_visible_protected_demo` | `demonstrated` | getchar_calls=3; printable_strings=98; forbidden_hits=0; wine=skipped | Wine execution is optional in this Linux environment; if unavailable, the evidence is cross-build plus static PE scan. |
| `runtime_stability` | `demonstrated` | release=pass; behavior_cases=4; forbidden_hits=0 | The local release runner validates the protected sample behavior, not arbitrary application workloads. |
| `reverse_cost_automation` | `demonstrated` | status=pass; reverse_cost_days=570 | Automated reverse-cost scoring is repeatable evidence, not a substitute for a human red-team guarantee. |
| `anti_debug_injection_tamper_review_scope` | `reviewed` | hostile=pass; scope=linux_windows_android; tier_review=pass | Hostile trigger and VMProtect-tier review files are provenance-sensitive; local-only reproduction must not be called final sign-off. |

## Blockers And Limits

- placeholder_noop_stages=[]
- accepted Windows release does not enable syscall-only I/O; direct Windows syscall stubs remain outside the release gate by policy
- full broad LLVM IR virtualization is not proven; unsupported functions remain native by policy
- IDA plugin recovery remains a real residual risk until flattening, production crypto, and broader binary-level anti-decompiler validation are implemented.
