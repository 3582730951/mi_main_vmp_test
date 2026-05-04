# Junk Template Catalog

The catalog in `src/anti_analysis/junk_templates.py` describes templates without
emitting code. Compiler and platform agents can consume these descriptions after
ABI interfaces are frozen.

Each template defines:

- a stable `template_id`
- the template class
- intended insertion points
- behavior-preserving invariants
- forbidden behaviors
- an estimated cost unit

Current classes map to plan tasks:

- T060: `IRREDUCIBLE_CFG`
- T061: `VM_STUB_JUNK`
- T062: `HANDLER_JUNK`
- T063: `FAKE_OPCODE_HANDLER`
- T064: `FAKE_XREF_LAYOUT`

All template entries explicitly forbid persistence, privilege escalation,
stealth, process injection, credential access, network activity, destructive
behavior, and platform probing.
