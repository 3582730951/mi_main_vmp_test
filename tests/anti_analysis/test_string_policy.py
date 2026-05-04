from pathlib import Path

from anti_analysis import ProtectedStringClass, StringScannerPolicy


def test_default_policy_finds_protected_strings() -> None:
    policy = StringScannerPolicy.default()
    result = policy.scan_bytes(Path("fixture.bin"), b"prefix JNI_OnLoad suffix https://example.test")

    assert not result.passed
    assert [finding.string_class for finding in result.findings] == [
        ProtectedStringClass.JNI,
        ProtectedStringClass.URL,
    ]


def test_policy_passes_when_terms_are_not_plaintext() -> None:
    policy = StringScannerPolicy.default()
    result = policy.scan_bytes(Path("fixture.bin"), b"prefix JN1_0nL0ad suffix hxxps://example.test")

    assert result.passed
    assert result.findings == ()


def test_policy_allows_project_specific_business_terms() -> None:
    policy = StringScannerPolicy.default().with_patterns(
        ProtectedStringClass.BUSINESS,
        ("payment_risk_model",),
    )

    result = policy.scan_bytes(Path("fixture.bin"), b"contains payment_risk_model")

    assert not result.passed
    assert result.findings[0].string_class == ProtectedStringClass.BUSINESS
