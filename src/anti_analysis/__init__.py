"""Defensive anti-analysis policy abstractions.

This package intentionally contains policy and passive classification only.
Platform-specific probing belongs in platform adapters and must feed sanitized
observations into these interfaces.
"""

from .cost_control import CostController, CostWindow, DetectionBudget
from .environment import (
    DetectionCategory,
    DetectionFinding,
    EnvironmentObservation,
    EnvironmentPolicy,
    PassiveEnvironmentDetector,
    Severity,
)
from .junk_templates import JunkTemplate, JunkTemplateCatalog, TemplateClass
from .string_policy import (
    ProtectedStringClass,
    ScanFinding,
    StringScannerPolicy,
    StringScanResult,
)
from .artifact_surface import (
    ArtifactSurfacePolicy,
    SurfaceCategory,
    SurfaceFinding,
    SurfaceScanResult,
)
from .stack_backtrace import RandomizedBacktracePolicy, RandomizedBacktraceSampler, StackFrameSummary

__all__ = [
    "CostController",
    "CostWindow",
    "DetectionBudget",
    "DetectionCategory",
    "DetectionFinding",
    "EnvironmentObservation",
    "EnvironmentPolicy",
    "PassiveEnvironmentDetector",
    "Severity",
    "JunkTemplate",
    "JunkTemplateCatalog",
    "TemplateClass",
    "ProtectedStringClass",
    "ScanFinding",
    "StringScannerPolicy",
    "StringScanResult",
    "ArtifactSurfacePolicy",
    "SurfaceCategory",
    "SurfaceFinding",
    "SurfaceScanResult",
    "RandomizedBacktracePolicy",
    "RandomizedBacktraceSampler",
    "StackFrameSummary",
]
