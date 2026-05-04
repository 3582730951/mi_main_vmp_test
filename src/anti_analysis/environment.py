"""Passive environment-detection abstractions.

Platform agents collect observations. This module classifies those observations
without performing active host inspection or bypass behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class DetectionCategory(str, Enum):
    DEBUGGER = "debugger"
    HARDWARE_BREAKPOINT = "hardware_breakpoint"
    MEMORY_BREAKPOINT = "memory_breakpoint"
    INJECTION = "injection"
    ROOT = "root"
    HOOK_FRAMEWORK = "hook_framework"


class Severity(str, Enum):
    INFO = "info"
    SUSPICIOUS = "suspicious"
    HOSTILE = "hostile"


@dataclass(frozen=True)
class EnvironmentObservation:
    category: DetectionCategory
    signal: str
    present: bool
    source: str
    confidence: float = 1.0
    details: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@dataclass(frozen=True)
class DetectionFinding:
    category: DetectionCategory
    severity: Severity
    signal: str
    source: str
    confidence: float
    action: str
    details: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EnvironmentPolicy:
    """Classification thresholds and allowed response actions."""

    suspicious_threshold: float = 0.55
    hostile_threshold: float = 0.85
    allowed_actions: tuple[str, ...] = ("report", "degrade_protection_checks", "deny_protected_execution")

    def classify(self, observation: EnvironmentObservation) -> DetectionFinding | None:
        if not observation.present:
            return None
        if observation.confidence >= self.hostile_threshold:
            severity = Severity.HOSTILE
            action = "deny_protected_execution"
        elif observation.confidence >= self.suspicious_threshold:
            severity = Severity.SUSPICIOUS
            action = "degrade_protection_checks"
        else:
            severity = Severity.INFO
            action = "report"
        if action not in self.allowed_actions:
            action = "report"
        return DetectionFinding(
            category=observation.category,
            severity=severity,
            signal=observation.signal,
            source=observation.source,
            confidence=observation.confidence,
            action=action,
            details=observation.details,
        )


class PassiveEnvironmentDetector:
    """Convert sanitized platform observations into policy findings."""

    def __init__(self, policy: EnvironmentPolicy | None = None) -> None:
        self.policy = policy or EnvironmentPolicy()

    def evaluate(self, observations: tuple[EnvironmentObservation, ...]) -> tuple[DetectionFinding, ...]:
        findings = [self.policy.classify(observation) for observation in observations]
        return tuple(finding for finding in findings if finding is not None)

    def debugger_stub(self, signal: str, present: bool, source: str, confidence: float) -> EnvironmentObservation:
        return EnvironmentObservation(DetectionCategory.DEBUGGER, signal, present, source, confidence)

    def injection_stub(self, signal: str, present: bool, source: str, confidence: float) -> EnvironmentObservation:
        return EnvironmentObservation(DetectionCategory.INJECTION, signal, present, source, confidence)

    def root_stub(self, signal: str, present: bool, source: str, confidence: float) -> EnvironmentObservation:
        return EnvironmentObservation(DetectionCategory.ROOT, signal, present, source, confidence)

    def hook_stub(self, signal: str, present: bool, source: str, confidence: float) -> EnvironmentObservation:
        return EnvironmentObservation(DetectionCategory.HOOK_FRAMEWORK, signal, present, source, confidence)

    def hardware_breakpoint_stub(
        self,
        signal: str,
        present: bool,
        source: str,
        confidence: float,
    ) -> EnvironmentObservation:
        return EnvironmentObservation(DetectionCategory.HARDWARE_BREAKPOINT, signal, present, source, confidence)

    def memory_breakpoint_stub(
        self,
        signal: str,
        present: bool,
        source: str,
        confidence: float,
    ) -> EnvironmentObservation:
        return EnvironmentObservation(DetectionCategory.MEMORY_BREAKPOINT, signal, present, source, confidence)
