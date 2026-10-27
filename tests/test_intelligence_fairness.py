"""Original catch-up keeps bounded turns and fresh downstream processing."""
import threading
import time

import pytest

from sapientia import intelligence as core
from sapientia import (
    intelligence_findings,
    intelligence_story_reconcile,
    source_registry,
)
from sapientia.runtime import Runtime
from tests.test_backend_upgrade import actor
from tests.test_backend_upgrade import lab as _backend_lab
from tests.test_intelligence import policy, seed

lab = _backend_lab


class Clock:
    def __init__(self):
        self.value = time.monotonic()

    def __call__(self):
        return self.value

    def advance(self, amount):
        self.value += amount


def stage_spies(monkeypatch, clock, *, real_outbox=False):
    seen = {}
    def deadline_stage(name):
        def stage(*args, **kwargs):
            seen[name] = {**kwargs, "slice": kwargs["deadline"]-clock()}
            clock.advance(.07)
            return 1
        return stage
    def budget_stage(name):
        def stage(*args, **kwargs):
            seen[name] = kwargs
            clock.advance(.07)
            return {"completed": 1}
        return stage
    if not real_outbox:
        monkeypatch.setattr(core, "_outbox", deadline_stage("originals"))
    monkeypatch.setattr(core, "_legacy", deadline_stage("legacy"))
    monkeypatch.setattr(core, "_composites", deadline_stage("composites"))
    monkeypatch.setattr(intelligence_findings, "run_due", budget_stage("findings"))
    monkeypatch.setattr(intelligence_story_reconcile, "run_due", budget_stage("relationships"))
    return seen


@pytest.mark.parametrize("original_budget,budget,expected", [(None, .25, .25), (None, 2., 2.), (1., .25, 1.), (9., .25, 1.), (0., .25, .05)])
def test_independent_original_slice_preserves_defaults_bounds_and_other_stage_turns(monkeypatch, original_budget, budget, expected):
    clock = Clock()
    seen = stage_spies(monkeypatch, clock)
    monkeypatch.setattr(core.time, "monotonic", clock)
    result = core.run_due(object(), budget=budget, original_budget=original_budget, max_runs=999, include_ml=False)
    assert seen["originals"]["slice"] == pytest.approx(expected)
    assert seen["originals"]["maximum"] == 32
    assert seen["legacy"]["slice"] == pytest.approx(budget)
    assert seen["composites"]["slice"] == pytest.approx(budget)
    assert seen["findings"]["budget"] == budget and seen["relationships"]["budget"] == budget
    assert result["originals"] == 1 and result["legacy_signals"] == 1 and result["composites"] == 1
    assert result["finding_signals"] == {"completed": 1} and result["relationship_jobs"] == {"completed": 1}


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), -float("inf"), True, "1"])
def test_original_slice_rejects_nonfinite_or_ambiguous_configuration_before_processing(invalid, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("Invalid budget must not begin an original turn")
    monkeypatch.setattr(core, "_outbox", unexpected)
    with pytest.raises(ValueError, match="finite number"):
        core.run_due(object(), original_budget=invalid)


@pytest.mark.parametrize("original_budget,expected", [(None, 2), (1., 7)])
def test_longer_original_slice_advances_real_ancestry_and_cases_without_skipping_other_stages(lab, monkeypatch, original_budget, expected):
    policy(lab, "A", case_adapter={"entity_field": "host", "risk_score": 40, "severity": "high", "cooldown": 0})
    seed(lab, stages=("A",)*12)
    clock = Clock()
    seen = stage_spies(monkeypatch, clock, real_outbox=True)
    authority = core._authority
    def measured(db, row, **kwargs):
        result = authority(db, row, **kwargs)
        clock.advance(.15)
        return result
    monkeypatch.setattr(core, "_authority", measured)
    monkeypatch.setattr(core.time, "monotonic", clock)
    result = core.run_due(lab, budget=.25, original_budget=original_budget, max_runs=8, include_ml=False)
    assert result["originals"] == expected
    assert set(seen) == {"legacy", "composites", "findings", "relationships"}
    assert seen["legacy"]["slice"] == pytest.approx(.25) and seen["composites"]["slice"] == pytest.approx(.25)
    with lab.control() as db:
        originals = [row[0] for row in db.execute("SELECT event_id FROM intelligence_event_phases WHERE analysis_completed_at IS NOT NULL ORDER BY event_id")]
        assert set(originals) == {"event-"+str(i) for i in range(expected)}
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE kind='observation'").fetchone()[0] == expected
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE kind='atomic'").fetchone()[0] == expected
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] > 0


def test_one_second_turn_keeps_32_original_cap_and_fresh_revoked_source_exclusion(lab, monkeypatch):
    policy(lab, "A", case_adapter={"entity_field": "host", "risk_score": 40, "severity": "high", "cooldown": 0})
    source, _ = seed(lab, stages=("A",)*40)
    source_registry.revoke(lab, actor(), source["id"], 1)
    monkeypatch.setattr(core.time, "monotonic", Clock())
    result = core.run_due(lab, budget=.25, original_budget=1., max_runs=8, include_ml=False)
    assert result["originals"] == 32
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_event_phases WHERE outcome='excluded'").fetchone()[0] == 32
        assert db.execute("SELECT count(*) FROM intelligence_signals").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0


def test_cancelled_original_catchup_never_consumes_or_publishes(lab):
    policy(lab, "A")
    seed(lab, stages=("A",)*3)
    cancel = threading.Event()
    cancel.set()
    result = core.run_due(lab, budget=.25, original_budget=1., max_runs=8, cancel=cancel, include_ml=False)
    assert result["originals"] == 0 and result["composites"] == 0
    with lab.control() as db:
        assert db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='events'").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM intelligence_signals").fetchone()[0] == 0


def test_background_runtime_uses_only_original_one_second_slice(monkeypatch):
    instance = Runtime.__new__(Runtime)
    from sapientia.pipeline_dispatch import Dispatch
    instance.dispatch = Dispatch()
    instance.store = object()
    instance.stop = threading.Event()
    instance.intelligence_result = {}
    calls = []
    def turn(store, **kwargs):
        calls.append(kwargs)
        instance.stop.set()
        return {"originals": 1}
    monkeypatch.setattr(core, "run_due", turn)
    instance.intelligence_loop()
    assert len(calls) == 1
    assert calls[0]["original_budget"] == 1. and calls[0]["budget"] == .25
    assert calls[0]["max_runs"] == 2 and calls[0]["include_ml"] is False
    assert calls[0]["cancel"] is instance.stop
