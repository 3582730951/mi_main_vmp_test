# Windows Platform Adapter

## Batch Coverage

- T090: `src/platform/windows/windows_adapter.c` exposes the runtime ABI probe for x64 calling-convention validation.
- T091: `src/platform/CMakeLists.txt` can build a Windows executable and DLL.
- T092: Import resolution is reserved for hashed lookup. The skeleton does not import sensitive APIs by name.
- T093: TLS/init ordering is represented by an explicit `vmp_platform_init` entry point; a TLS callback can be added after the runtime ABI freezes.
- T094: A `.vmp$init` marker reserves the section-layout hook for bytecode/runtime metadata.
- T095: Crash/PDB map handling is documented as a report sidecar generated during protection.
- T096: `.github/workflows/platform-windows.yml` builds and runs the smoke binary on GitHub-hosted Windows.
- T097/T154 support: `tests/platform/windows_hostile_trigger_report.ps1` records controlled Windows debugger, page-guard, and module-load observations on the Windows runner. It does not satisfy the external hardware-breakpoint or external DLL-injection hard gate by itself.

## Acceptance

Run:

```powershell
tests/platform/windows_acceptance.ps1
tests/platform/windows_hostile_trigger_report.ps1
```

The workflow must build, protect when the core protector is available, execute the protected `.exe`, load the `.dll`, and scan release artifacts for forbidden markers. Credentials must come from GitHub Encrypted Secrets only.

Hard Windows acceptance requires real reports from `.github/workflows/platform-windows.yml` on a GitHub-hosted Windows runner:

- `docs/qa/reports/windows-acceptance.json` must show `github_actions: true`, `runner_os: Windows`, matching GitHub run metadata, successful smoke `.exe` execution, successful `.dll` `LoadLibrary`, and positive-byte `.exe`/`.dll` artifacts.
- `docs/qa/reports/windows-protected-release.json` must come from the same non-`pull_request` GitHub Actions run, show protected sample execution with all four behavior cases passing, record a positive-byte protected `.exe` with SHA-256 hash, and have no forbidden plaintext hits.
- Both reports must agree on `github_run_id`, `github_run_url`, `github_repository`, `github_sha`, `github_workflow`, and `github_event_name`, and `docs/qa/reports/windows-github-actions-verification.json` must show live GitHub API verification for those report paths. PR runs may exercise smoke coverage, but they do not satisfy final Windows hard acceptance.
- Local `windows-*-cross-build.json` reports remain partial evidence only and must not be treated as the protected Windows execution gate.
