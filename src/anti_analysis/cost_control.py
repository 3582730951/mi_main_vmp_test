"""Cost controls for anti-analysis checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import monotonic


class CostWindow(str, Enum):
    STARTUP = "startup"
    PER_FUNCTION = "per_function"
    PERIODIC = "periodic"
    ON_SIGNAL = "on_signal"


@dataclass(frozen=True)
class DetectionBudget:
    name: str
    max_calls: int
    window_seconds: float
    cost_units: int = 1
    window: CostWindow = CostWindow.PERIODIC

    def __post_init__(self) -> None:
        if self.max_calls < 1:
            raise ValueError("max_calls must be positive")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.cost_units < 1:
            raise ValueError("cost_units must be positive")


@dataclass
class _Bucket:
    started_at: float
    calls: int = 0


@dataclass
class CostController:
    """Small in-memory rate limiter for high-cost detection hooks."""

    budgets: dict[str, DetectionBudget]
    _buckets: dict[str, _Bucket] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "CostController":
        return cls(
            {
                "debugger": DetectionBudget("debugger", max_calls=4, window_seconds=60.0, window=CostWindow.PERIODIC),
                "injection": DetectionBudget("injection", max_calls=2, window_seconds=60.0, window=CostWindow.ON_SIGNAL),
                "root": DetectionBudget("root", max_calls=1, window_seconds=300.0, window=CostWindow.STARTUP),
                "hook": DetectionBudget("hook", max_calls=2, window_seconds=60.0, window=CostWindow.ON_SIGNAL),
            }
        )

    def allow(self, name: str, now: float | None = None) -> bool:
        budget = self.budgets[name]
        current = monotonic() if now is None else now
        bucket = self._buckets.get(name)
        if bucket is None or current - bucket.started_at >= budget.window_seconds:
            self._buckets[name] = _Bucket(started_at=current, calls=1)
            return True
        if bucket.calls >= budget.max_calls:
            return False
        bucket.calls += 1
        return True
