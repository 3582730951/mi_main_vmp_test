# iOS Platform Logical Design

## Batch Coverage

- T120: `src/platform/ios/ios_adapter.c` models an arm64 runtime adapter compiled into the app or framework.
- T121: Xcode/Clang integration runs protection before archive signing and after native compilation inputs are finalized.
- T122: Selector and metadata exposure must be reduced by limiting ObjC/Swift bridging at protected boundaries.
- T123: The runtime interprets existing protected bytecode and does not generate executable pages at runtime.
- T124: Signing happens after protection, packaging, and symbol map generation.
- T125: Crash maps are emitted as sidecars that map protected offsets to protection reports.
- T126: Current acceptance is logical review plus macOS build/static checks; physical-device execution is out of scope for this batch.
- T127: GitHub Actions emits `ios-macho-metadata` evidence from
  `scripts/audit/macho_metadata_audit.py`, using a built-in Mach-O/fat/ar parser
  plus optional `otool`, `llvm-objdump`, and LIEF observations when available.

## Signing Flow

1. Build native objects or libraries for iOS arm64.
2. Apply protection to eligible native code and emit crash/protection maps.
3. Link the final app or framework.
4. Sign with Xcode-managed identities or CI-provided signing assets from GitHub Secrets.
5. Archive notarization/export metadata without logging secrets.

## Constraints

The design assumes no runtime executable-memory generation, no private entitlement dependency, and no mutation after code signing.

Mach-O metadata minimization is report-only in this batch. Segment names, load
commands, symbol tables, and code-signature records are observed because mutating
them can break linking, loading, or Apple signing. Strict mode exists only for
controlled experiments.

References:

- Apple Code Signing Services: https://developer.apple.com/documentation/security/code-signing-services
- Apple code-signing overview: https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html
- Apple Mach-O overview: https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html
- Apple JIT entitlement reference: https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.security.cs.allow-jit
