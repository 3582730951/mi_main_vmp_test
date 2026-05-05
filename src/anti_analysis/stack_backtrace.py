"""Randomized stack backtrace sampling policy.

The sampler captures sanitized Python stack metadata at jittered intervals. It
does not print frames, inspect secrets, or decide enforcement by itself; platform
adapters can use the returned frame summary as one passive signal.
"""

from __future__ import annotations

from dataclasses import dataclass
from random import Random
from time import monotonic
from traceback import extract_stack


@dataclass(frozen=True)
class StackFrameSummary:
    filename: str
    function: str
    line: int


@dataclass(frozen=True)
class RandomizedBacktracePolicy:
    min_interval_seconds: float = 0.25
    jitter_seconds: float = 0.75
    max_frames: int = 16

    def __post_init__(self) -> None:
        if self.min_interval_seconds <= 0:
            raise ValueError("min_interval_seconds must be positive")
        if self.jitter_seconds < 0:
            raise ValueError("jitter_seconds must be non-negative")
        if self.max_frames < 1:
            raise ValueError("max_frames must be positive")


class RandomizedBacktraceSampler:
    """Capture stack summaries at randomized times within a bounded budget."""

    def __init__(self, policy: RandomizedBacktracePolicy | None = None, seed: int | None = None) -> None:
        self.policy = policy or RandomizedBacktracePolicy()
        self._random = Random(seed)
        self._next_due = 0.0
        self._schedule_next(0.0)

    @property
    def next_due(self) -> float:
        return self._next_due

    def _schedule_next(self, now: float) -> None:
        jitter = self._random.uniform(0.0, self.policy.jitter_seconds)
        self._next_due = now + self.policy.min_interval_seconds + jitter

    def maybe_capture(self, now: float | None = None) -> list[StackFrameSummary] | None:
        current = monotonic() if now is None else now
        if current < self._next_due:
            return None
        frames = extract_stack(limit=self.policy.max_frames + 1)[:-1]
        self._schedule_next(current)
        return [
            StackFrameSummary(filename=frame.filename, function=frame.name, line=frame.lineno)
            for frame in frames[-self.policy.max_frames :]
        ]
