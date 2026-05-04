# Anti-Analysis Defensive Policy

This area covers plan tasks T060-T080 and T143 for the anti-analysis agent.
The implementation is policy-only and passive by design.

## Scope

- T060-T064: junk-template descriptions for irreducible CFG, VM stubs, handlers,
  fake handlers, and fake xref layout.
- T065-T066: release string scanner policy for protected business/API/JNI/license/
  URL/secret strings and delayed-decrypt acceptance.
- T070-T080: platform-independent environment-detection abstractions for debugger,
  hardware breakpoint, memory breakpoint, injection, root, and hook indicators.
- T143: cost controls so high-cost checks are rate-limited by trigger point and
  frequency.

## Safety Boundary

The module does not implement persistence, stealth installation, privilege
escalation, injection, kernel behavior, security-product bypass, active host
probing, or destructive responses. Platform agents may collect platform-specific
signals, but they must pass sanitized observations into `PassiveEnvironmentDetector`.

Allowed response actions are limited to:

- `report`
- `degrade_protection_checks`
- `deny_protected_execution`

## Acceptance

Release artifacts pass the string policy only when protected strings have zero
findings. Environment detections are accepted only as typed findings from
caller-provided observations. Cost control must prevent repeated high-cost checks
from running more frequently than the configured budget.
