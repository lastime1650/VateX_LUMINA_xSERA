"""Actual GRU sequence learning, immutable source partition and approval tests."""
import copy
from datetime import datetime
import importlib.util
import json
import math
import struct

import pytest

from sapientia import access, auth, connector_runtime, cpu_ml_runtime, cpu_sequence, cpu_sequence_features, principal, source_registry
from sapientia.storage import CapacityError, ConflictError, Settings, Store
from tools.sequence_scenarios import generate
from sapientia.cpu_sequence_worker import calibration_threshold


def _observed_score_cut(scores, labels):
    def rank(cut):
        measured = cpu_sequence.confusion(scores, labels, cut)
        return measured["f1"], -measured["false_positive"], cut
    return max(sorted({0., 1., *scores}), key=rank)


def test_calibration_only_midpoint_retains_objective_and_score_margin():
    scores, labels = [.02, .09, .999909, .999970], [0, 0, 1, 1]
    observed = _observed_score_cut(scores, labels)
    cut = calibration_threshold(scores, labels)
    assert observed == .999909 and .09 < cut < .999909
    assert [score >= cut for score in scores] == [score >= observed for score in scores]
    perturbed = [score-1e-6 for score in scores]
    assert perturbed == sorted(perturbed)
    assert cpu_sequence.confusion(perturbed, labels, observed)["false_negative"] == 1
    assert cpu_sequence.confusion(perturbed, labels, cut)["accuracy"] == 1
    assert calibration_threshold(list(reversed(scores)), list(reversed(labels))) == cut
    # Tied, overlapping classes use the winning predicted partition rather
    # than true-label extrema, which cannot define a separation here.
    overlap, truth = [.1, .7, .7, .9], [0, 0, 1, 1]
    chosen = calibration_threshold(overlap, truth)
    assert chosen == pytest.approx(.4)
    assert [score >= chosen for score in overlap] == [score >= _observed_score_cut(overlap, truth) for score in overlap]


@pytest.mark.parametrize("scores,labels,expected", [
    ([0., 0.], [0, 1], 0.), ([.4, .4], [0, 1], .2), ([1., 1.], [0, 1], .5),
    ([.2, .3], [0, 0], .65), ([.2, .3], [1, 1], .1),
])
def test_calibration_midpoint_uniform_and_bounded_edges(scores, labels, expected):
    cut = calibration_threshold(scores, labels)
    assert cut == pytest.approx(expected) and 0 <= cut <= 1
    assert [score >= cut for score in scores] == [score >= _observed_score_cut(scores, labels) for score in scores]


def test_calibration_midpoint_adjacent_float32_and_float64_boundaries():
    lower = struct.unpack("!f", struct.pack("!I", 0x3F000000))[0]
    upper = struct.unpack("!f", struct.pack("!I", 0x3F000001))[0]
    cut = calibration_threshold([lower, upper], [0, 1])
    assert lower < cut < upper
    assert cpu_sequence.confusion([lower, upper], [0, 1], cut)["accuracy"] == 1
    # Adjacent Python floats have no interior representative: preserve the
    # inclusive upper cut instead of rounding onto the negative boundary.
    adjacent = math.nextafter(.5, 1.)
    assert calibration_threshold([.5, adjacent], [0, 1]) == adjacent
    for invalid in (float("nan"), float("inf"), -float("inf"), -.01, 1.01):
        with pytest.raises(ValueError, match="Finite bounded"):
            calibration_threshold([.2, invalid], [0, 1])


def actor(name="trainer", indexes=None):
    return {"name": name, "tenant": "a", "role": "admin" if name == "admin" else "analyst", "allowed_indexes": ["*"] if indexes is None else indexes}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    cpu_sequence.initialize(value)
    for name in ("trainer", "reviewer", "admin"):
        auth.create_user(value, name, "Actual-GRU-test-password-2026", "admin" if name == "admin" else "analyst", "a")
    yield value
    value.close()


def seed_dataset(store):
    source = source_registry.save(store, actor("admin"), {"index": "public", "product": "json", "account": "sequence-test", "realm": "synthetic", "credential_ref": "env:SAPIENTIA_CONNECTOR_SEQUENCE_TEST", "version": 0})
    scenarios = generate(variants_per_family=4, base_time=1791910000)
    dataset = {"training": [], "calibration": [], "holdout": []}
    events = []
    for scenario in scenarios:
        identifiers = []
        for position, incoming in enumerate(scenario["events"]):
            data = incoming["data"]
            identifier = scenario["scenario_id"] + "-" + str(position)
            identifiers.append(identifier)
            events.append({"event_id": identifier, "event_time": datetime.fromisoformat(data["@timestamp"]).timestamp(),
                           "host": scenario["host_group"], "index": "public", "source": "sequence-test", "raw": {
                               "xdr": {"data": data}}})
        split = {"train": "training", "validation": "calibration", "heldout": "holdout"}[scenario["split"]]
        dataset[split].append({"scenario_id": scenario["scenario_id"], "family": scenario["family"], "host_group": scenario["host_group"], "label": scenario["label"], "event_ids": identifiers})
    for offset in range(0, len(events), 500):
        connector_runtime.intake(store, actor("admin"), source["id"], {"version": 1, "events": events[offset:offset+500], "cursor": str(offset), "checkpoint_version": offset//500})
    while store.flush():
        pass
    return {"name": "Real masked CPU sequence", "indexes": ["public"], "reviewed_dataset": True, "epochs": 15, **dataset}


def test_real_gru_masks_order_learning_and_reused_cpu_process():
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    def rows(count, noise=0.):
        values, labels = [], []
        for i in range(count):
            # Same first/last values and unordered multiset; transition order
            # is the only class distinction. Variable lengths require masking.
            tokens = [0, 1, 0, 1, 0] if i % 2 else [0, 0, 1, 1, 0]
            if (i//2) % 2:
                tokens += [0]
            values.append([[noise if token == 0 else 1-noise] for token in tokens])
            labels.append(i % 2)
        return values, labels
    train, labels = rows(64)
    calibration, calibration_labels = rows(16, .01)
    trained = cpu_ml_runtime.request({"operation": "sequence_train", "feature_count": 1, "training": train, "training_labels": labels,
        "calibration": calibration, "calibration_labels": calibration_labels, "epochs": 30}, timeout=30)
    assert "worker_error" not in trained
    assert trained["metrics"]["input_tensor_shape"] == [64, 6, 1]
    assert trained["metrics"]["padded_steps"] == 32
    assert trained["metrics"]["training_loss"] < trained["metrics"]["initial_training_loss"]
    heldout, held_labels = rows(20, .02)
    request = {"operation": "sequence_infer", "feature_count": 1, "weights": json.loads(json.dumps(trained["weights"])),
               "pooled_weights": trained["pooled_weights"], "sequences": heldout}
    result = cpu_ml_runtime.request(request)
    assert result["worker_reused"] and result["worker_pid"] == trained["worker_pid"]
    assert cpu_sequence.confusion(result["scores"], held_labels, trained["threshold"])["accuracy"] >= .9
    assert cpu_sequence.confusion(result["pooled_scores"], held_labels, trained["pooled_threshold"])["accuracy"] == .5
    alone = cpu_ml_runtime.request({**request, "sequences": heldout[:1]})
    assert alone["scores"][0] == pytest.approx(result["scores"][0], abs=1e-6)
    assert result["order_sensitivity_mean_abs_delta"] > .05
    with pytest.raises(CapacityError, match="deadline"):
        cpu_ml_runtime.request({"operation": "status"}, timeout=.000001)
    restarted = cpu_ml_runtime.request({"operation": "status"}, timeout=30)
    assert restarted["available"] and restarted["worker_generation"] > result["worker_generation"]
    assert restarted["device"] == "cpu" and restarted["threads"] == 1
    assert "runtime_limits" in restarted
    if restarted["runtime_limits"].get("os_enforced") and restarted["runtime_limits"]["method"] == "windows_job":
        assert restarted["runtime_limits"]["memory_bytes"] == 2*1024**3
        assert restarted["runtime_limits"]["max_processes"] == 1
        assert restarted["runtime_limits"]["kill_on_job_close"]


def test_scoped_originals_disjoint_holdout_review_and_frozen_replay(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    dataset = seed_dataset(store)
    leaked = copy.deepcopy(dataset)
    leaked["holdout"][0]["family"] = leaked["training"][0]["family"]
    with pytest.raises(ValueError, match="disjoint"):
        cpu_sequence.train(store, actor(), leaked)
    spoofed = copy.deepcopy(dataset)
    spoofed["holdout"][0]["host_group"] = "a forged host"
    with pytest.raises(ValueError, match="actual host"):
        cpu_sequence.train(store, actor(), spoofed)
    candidate = cpu_sequence.train(store, actor(), dataset)
    assert candidate["status"] == "completed" and not candidate["active"]
    assert candidate["metrics"]["input_tensor_shape"] == [64, 12, len(cpu_sequence.FEATURES)]
    assert candidate["metrics"]["holdout_seen_during_training"] is False
    with pytest.raises(ConflictError, match="held-out"):
        cpu_sequence.activate(store, actor("reviewer"), candidate["id"], "Independent reviewed candidate")
    evaluation = cpu_sequence.evaluate(store, actor("reviewer"), candidate["id"])
    assert evaluation["metrics"]["samples"] == 16 and evaluation["holdout_used_for_threshold"] is False
    assert evaluation["unordered_baseline_metrics"]["samples"] == 16
    with pytest.raises(PermissionError, match="creator"):
        cpu_sequence.activate(store, actor(), candidate["id"], "Self approval forbidden")
    active = cpu_sequence.activate(store, actor("reviewer"), candidate["id"], "Independent review of actual held-out confusion and source scopes")
    assert active["active"] and cpu_sequence.compatible_models(store, actor(), ["public"])[0]["id"] == candidate["id"]
    windows = [{"event_ids": scenario["event_ids"]} for scenario in dataset["holdout"][:2]]
    result = cpu_sequence.infer_sequences(store, actor(), windows, model_id=candidate["id"])
    assert result["worker_reused"] and result["input_tensor_shape"] == [2, 12, len(cpu_sequence.FEATURES)]
    assert all(item["event_ids"] == window["event_ids"] for item, window in zip(result["results"], windows))
    with principal.transaction(store, actor(), write=True) as (db, current):
        assert cpu_sequence.validate_publication(store, db, current, candidate["id"], candidate["digest"], 1)["active"]
        row = db.execute("SELECT definition,snapshot FROM cpu_sequence_models WHERE id=?", (candidate["id"],)).fetchone()
        definition, snapshot = json.loads(row["definition"]), json.loads(row["snapshot"])
    extracted = cpu_sequence.inspect_sequences(store, actor(), windows, ["public"])
    first = cpu_sequence.frozen_infer(definition, snapshot, candidate["digest"], [w["features"] for w in extracted])
    second = cpu_sequence.frozen_infer(definition, snapshot, candidate["digest"], [w["features"] for w in extracted])
    assert first == second and first["scores"] == pytest.approx([r["score"] for r in result["results"]], abs=1e-7)
    access.set_for_user(store, actor("admin"), "reviewer", ["private"])
    with principal.transaction(store, actor(), write=True) as (db, current), pytest.raises(PermissionError, match="reviewer"):
        cpu_sequence.validate_publication(store, db, current, candidate["id"], candidate["digest"], 1)
    with pytest.raises(KeyError):
        cpu_sequence.infer_sequences(store, actor(indexes=["private"]), windows, model_id=candidate["id"])


def test_missing_semantic_fields_are_explicit_and_labels_are_not_features():
    event = {"event_time": 1700000000, "raw": {"xdr": {"data": {"event": {"action": "process_created", "category": "process"},
        "process": {"command_line": "powershell.exe -EncodedCommand ABC", "depth": 3}, "label": "attack", "family": "secret-truth"}}}}
    original = cpu_sequence_features.extract(event)
    other = copy.deepcopy(event)
    other["raw"]["xdr"]["data"].update(label="normal", family="another truth", scenario_id="never a feature")
    assert original == cpu_sequence_features.extract(other)
    named = dict(zip(cpu_sequence.FEATURES, original))
    assert named["command_encoded"] == 1 and named["missing_network_dest"] == 1
    assert named["missing_process_depth"] == 0 and all(0 <= value <= 1 for value in original)
    with pytest.raises(ValueError, match="strictly increasing"):
        cpu_sequence_features.vectors([event, event])
