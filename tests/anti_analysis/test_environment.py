from anti_analysis import (
    DetectionCategory,
    EnvironmentObservation,
    EnvironmentPolicy,
    PassiveEnvironmentDetector,
    Severity,
)


def test_detector_classifies_only_present_observations() -> None:
    detector = PassiveEnvironmentDetector()
    observations = (
        detector.debugger_stub("debug_port", True, "windows_agent", 0.9),
        detector.injection_stub("unexpected_module", False, "windows_agent", 1.0),
    )

    findings = detector.evaluate(observations)

    assert len(findings) == 1
    assert findings[0].category == DetectionCategory.DEBUGGER
    assert findings[0].severity == Severity.HOSTILE
    assert findings[0].action == "deny_protected_execution"


def test_policy_thresholds_are_configurable() -> None:
    detector = PassiveEnvironmentDetector(EnvironmentPolicy(suspicious_threshold=0.25, hostile_threshold=0.75))

    findings = detector.evaluate((detector.hook_stub("inline_hook_shape", True, "android_agent", 0.5),))

    assert findings[0].severity == Severity.SUSPICIOUS
    assert findings[0].action == "degrade_protection_checks"


def test_all_stub_categories_are_data_only_observations() -> None:
    detector = PassiveEnvironmentDetector()
    observations = (
        detector.debugger_stub("attached", True, "linux_agent", 0.8),
        detector.hardware_breakpoint_stub("dr_register", True, "windows_agent", 0.8),
        detector.memory_breakpoint_stub("guard_page", True, "windows_agent", 0.8),
        detector.injection_stub("preload", True, "linux_agent", 0.8),
        detector.root_stub("su_path", True, "android_agent", 0.8),
        detector.hook_stub("xposed_class", True, "android_agent", 0.8),
    )

    assert {observation.category for observation in observations} == set(DetectionCategory)
    assert all(isinstance(observation, EnvironmentObservation) for observation in observations)


def test_invalid_confidence_is_rejected() -> None:
    try:
        EnvironmentObservation(DetectionCategory.ROOT, "su_path", True, "android_agent", 1.5)
    except ValueError:
        return
    raise AssertionError("expected invalid confidence to raise ValueError")
