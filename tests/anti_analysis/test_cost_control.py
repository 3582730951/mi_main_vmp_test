from anti_analysis import CostController, DetectionBudget


def test_cost_controller_allows_within_budget_and_blocks_after() -> None:
    controller = CostController({"debugger": DetectionBudget("debugger", max_calls=2, window_seconds=10.0)})

    assert controller.allow("debugger", now=100.0)
    assert controller.allow("debugger", now=101.0)
    assert not controller.allow("debugger", now=102.0)


def test_cost_controller_resets_after_window() -> None:
    controller = CostController({"hook": DetectionBudget("hook", max_calls=1, window_seconds=10.0)})

    assert controller.allow("hook", now=100.0)
    assert not controller.allow("hook", now=105.0)
    assert controller.allow("hook", now=111.0)
