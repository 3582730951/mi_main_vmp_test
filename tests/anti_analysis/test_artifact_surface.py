from pathlib import Path

from anti_analysis import ArtifactSurfacePolicy, SurfaceCategory


def test_surface_policy_finds_vm_and_ollvm_markers() -> None:
    policy = ArtifactSurfacePolicy.default()
    result = policy.scan_bytes(Path("fixture.bin"), b"MZ....VMPBC1....OLLVM")

    assert not result.passed
    assert result.container == "pe"
    assert "pe_headers" in result.mandatory_features
    assert [finding.category for finding in result.findings] == [
        SurfaceCategory.VM_MARKER,
        SurfaceCategory.OLLVM_MARKER,
    ]


def test_surface_policy_accepts_nonprintable_markers() -> None:
    policy = ArtifactSurfacePolicy.default()
    result = policy.scan_bytes(Path("fixture.bin"), b"\x7fELF\x9d\xe4\xb1\xa7\xc8\x5f\x23\x01")

    assert result.passed
    assert result.container == "elf"
    assert result.findings == ()


def test_surface_policy_finds_protected_plaintext_and_import_resolver_names() -> None:
    policy = ArtifactSurfacePolicy.default()
    result = policy.scan_bytes(Path("fixture.bin"), b"seed protected-sample-seed-v1 uses GetProcAddress")

    assert not result.passed
    assert [finding.category for finding in result.findings] == [
        SurfaceCategory.PROTECTED_PLAINTEXT,
        SurfaceCategory.IMPORT_RESOLVER_NAME,
    ]


def test_surface_policy_finds_fixed_windows_api_names() -> None:
    policy = ArtifactSurfacePolicy.default()
    result = policy.scan_bytes(Path("fixture.bin"), b"KERNEL32.dll imports ExitProcess")

    assert not result.passed
    assert [finding.category for finding in result.findings] == [
        SurfaceCategory.IMPORT_RESOLVER_NAME,
        SurfaceCategory.IMPORT_RESOLVER_NAME,
    ]
