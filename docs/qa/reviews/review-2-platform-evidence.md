# Comprehensive Review 2: Platform Evidence And Hostile Gates

Reviewer: platform-evidence review agent

Scope: Windows and Android workflows, platform evidence reports, hostile-environment aggregation, strict provenance checks, and CI credential exposure boundaries.

Review status: pass

Open vulnerabilities: 0

Open findings: 0

Closed checks:

- Android signing material is not passed into the `pull_request` workflow step; release-signing environment values are isolated to trusted non-PR events.
- Windows hard evidence now requires matching non-PR GitHub run metadata, artifact SHA-256 hashes, and a live GitHub Actions API verification sidecar.
- Android hostile evidence now requires CI run metadata, an authorized hostile profile marker, complete root/Xposed-or-LSPosed/Frida-or-hook findings, and a GitHub Actions API verification sidecar.
- GitHub Actions verification sidecars now require `schema: vmp.qa.github_actions_verification.v1`, trusted non-PR event type, GitHub Actions runtime generation, protected ref metadata, expected workflow names, completed/successful run status, non-stale run age, empty mismatches, report SHA-256 hashes, and current-run metadata matching the verified reports.
- Strict audit consumers recheck verification sidecars against the live GitHub Actions API before accepting imported Windows/Android evidence; local JSON alone is not enough.
- Dynamic hostile coverage no longer trusts the aggregate `hostile-environment.json` alone; it requires Windows and Android hostile trigger sidecars with GitHub API provenance.
- Android release-strength workflow validation now runs the semantic `android_release_strength_evidence_exists` gate after live provenance verification.
- Local emulator, local cross-build, and synthetic hostile reports remain classified as partial evidence and do not satisfy hard acceptance.

External blockers not counted as review findings:

- Windows GitHub Actions run artifacts are still absent from this workspace.
- Android release-signing and authorized hostile-device artifacts are still absent from this workspace.
- Windows external hostile triggers and Android root/Xposed-or-LSPosed/Frida-or-hook triggers still require real target-platform evidence.

Verification:

- `./acceptance.sh`
- `python3 -m unittest tests.qa.test_plan_completion_audit tests.qa.test_acceptance_audit tests.qa.test_github_actions_verifier`
