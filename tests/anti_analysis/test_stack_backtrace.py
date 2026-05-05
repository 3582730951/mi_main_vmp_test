from anti_analysis import RandomizedBacktracePolicy, RandomizedBacktraceSampler


def test_randomized_backtrace_sampler_waits_until_due() -> None:
    sampler = RandomizedBacktraceSampler(
        RandomizedBacktracePolicy(min_interval_seconds=10.0, jitter_seconds=0.0, max_frames=4),
        seed=7,
    )

    assert sampler.next_due == 10.0
    assert sampler.maybe_capture(now=9.0) is None
    frames = sampler.maybe_capture(now=10.0)
    assert frames is not None
    assert 1 <= len(frames) <= 4
    assert frames[-1].function == "test_randomized_backtrace_sampler_waits_until_due"
    assert sampler.next_due == 20.0


def test_randomized_backtrace_policy_rejects_invalid_budget() -> None:
    try:
        RandomizedBacktracePolicy(min_interval_seconds=0.0)
    except ValueError:
        pass
    else:
        raise AssertionError("zero interval should be rejected")
