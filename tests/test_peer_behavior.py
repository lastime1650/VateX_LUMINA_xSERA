"""Actual stored baseline and held-out synthetic peer evaluation contracts."""
import copy

import pytest

from sapientia import behavior, peer_behavior
from tests.test_behavior import store, actor, definition, event, START, BUCKET


def train(store, counts=None, groups=None, minimum=2):
    counts=counts or {name:[2]*7 for name in ("alice","bob","carol","dave")}
    rows=[]
    for name,days in counts.items():
        for day,count in enumerate(days):
            rows.extend(event(f"train-{name}-{day}-{i}",START+day*BUCKET+12*3600+i,user=name) for i in range(count))
    store.ingest("a",rows); store.flush()
    groups=groups or {name:"workstation-user" for name in counts}
    return behavior.train(store,actor(),definition(count_method="peer_robust_mad",peer_groups=groups,peer_min_entities=minimum))


def evaluate(store, baseline, count=10):
    end=definition()["end"]
    store.ingest("a",[event(f"eval-{i}",end+12*3600+i) for i in range(count)])
    store.flush()
    return behavior.evaluate(store,actor(),baseline["id"],end,end+BUCKET)


def test_peer_model_finds_deviation_when_target_training_was_high(store):
    baseline=train(store,{"alice":[100]*7,"bob":[2]*7,"carol":[2]*7,"dave":[2]*7})
    result=evaluate(store,baseline)
    signal=next(a for a in result["anomalies"] if a["type"]=="peer_volume")
    assert signal["count"]==10 and signal["peer"]["median"]==2
    assert "alice" not in signal["peer"]["peer_entities"]
    assert signal["peer"]["peer_denominator"]==3
    assert signal["peer"]["probability_calibrated"] is False
    assert signal["evidence"][0]["event_id"].startswith("eval-")


def test_single_poisoned_peer_does_not_raise_robust_center(store):
    baseline=train(store,{"alice":[2]*7,"bob":[2]*7,"carol":[2]*7,"dave":[100]*7})
    result=evaluate(store,baseline)
    assert next(a for a in result["anomalies"] if a["type"]=="peer_volume")["peer"]["median"]==2
    assert result["quality"]["malicious_training_contamination_excluded"] is False


def test_review_required_training_peer_is_excluded_with_reason(store):
    baseline=train(store,{"alice":[2]*7,"bob":[2]*7,"carol":[2]*7,"dave":[2,2,100,100,100,2,2]})
    result=evaluate(store,baseline)
    p=next(a for a in result["anomalies"] if a["type"]=="peer_volume")["peer"]
    assert "dave" in p["excluded_entities"] and p["peer_denominator"]==2


def test_separate_roles_do_not_become_a_global_population(store):
    baseline=train(store,groups={"alice":"unique","bob":"other","carol":"other","dave":"other"})
    result=evaluate(store,baseline)
    assert not any(a["type"]=="peer_volume" for a in result["anomalies"])
    assert result["seasonal_warmup"][0]["reason"]=="peer_scope_or_population_not_ready"


def test_benign_peer_volume_does_not_create_attack_signal(store):
    baseline=train(store)
    result=evaluate(store,baseline,2)
    assert result["anomalies"]==[]


def test_training_is_immutable_after_late_events(store):
    baseline=train(store)
    digest=baseline["digest"]
    store.ingest("a",[event("late",START+12*3600,user="bob")]); store.flush()
    evaluate(store,baseline)
    assert behavior.get(store,actor(),baseline["id"])["digest"]==digest


@pytest.mark.parametrize("minimum",[True,1,1001,"3"])
def test_peer_population_rejects_untyped_or_unready_minimum(minimum):
    with pytest.raises(ValueError):
        peer_behavior.configure({"count_method":"peer_robust_mad","peer_groups":{"a":"role"},"peer_min_entities":minimum})


def test_peer_scope_cannot_be_read_by_another_tenant(store):
    baseline=train(store)
    with pytest.raises(KeyError):
        behavior.get(store,actor("analyst_b","b"),baseline["id"])


def test_peer_signal_reaches_shared_case_governance_without_retraining(store):
    from sapientia import detection_automation as da
    import json

    baseline=train(store)
    evaluate(store,baseline)
    end=definition()["end"]+BUCKET
    schedule=da.save_schedule(store,actor(),{"name":"Peer scheduled","kind":"behavior","baseline_id":baseline["id"],"interval":BUCKET,"lookback":BUCKET,"enabled":True,
                                           "case_adapter":{"entity_field":"raw.security.user","risk_score":60}})
    with store.control() as db:
        db.execute("UPDATE analysis_schedules SET next_run=? WHERE id=?",(end,schedule["id"]))
    assert da.run_due(store,end+1,budget=5)==1
    with store.control() as db:
        row=db.execute("SELECT evidence FROM risk_contributions").fetchone()
        assert row is not None
        evidence=json.loads(row[0])
        assert any(a["type"]=="peer_volume" for a in evidence["analysis"]["baseline_anomalies"])
        assert db.execute("SELECT count(*) FROM detection_governance_decisions WHERE policy_id=?",("analysis:"+schedule["id"],)).fetchone()[0]>=1
    assert behavior.get(store,actor(),baseline["id"])["digest"]==baseline["digest"]


def test_analysis_registration_precedes_first_case_and_survives_restart_backfill(store):
    from sapientia import detector_ops, detection_automation as da
    from sapientia.storage import ConflictError

    baseline=train(store)
    schedule=da.save_schedule(store,actor(),{"name":"Peer declaration","kind":"behavior","baseline_id":baseline["id"],"interval":BUCKET,"lookback":BUCKET,"enabled":True,
                                           "case_adapter":{"entity_field":"raw.security.user","risk_score":60}})
    identifier="analysis:"+schedule["id"]
    with store.control() as db:
        assert detector_ops.policy(db,actor(),identifier)["indexes"]=='["public"]'
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0
        db.execute("DELETE FROM detector_registry")
    detector_ops.initialize(store)
    with store.control() as db:
        assert detector_ops.policy(db,actor(),identifier)["version"]==1
    da.toggle_schedule(store,actor(),schedule["id"],False,1)
    with store.control() as db:
        with pytest.raises(ConflictError):
            detector_ops.policy(db,actor(),identifier)
    da.toggle_schedule(store,actor(),schedule["id"],True,2)
    with store.control() as db:
        assert detector_ops.policy(db,actor(),identifier)["version"]==3

