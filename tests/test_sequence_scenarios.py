import copy
from collections import Counter

import pytest


def test_live_replay_preserves_trusted_device_binding_and_new_incarnation():
    from tools.sequence_lab import _live_copy
    from tools.sequence_scenarios import generate
    from sapientia.xdr_bridge import parse_event
    scenario = next(s for s in generate(2, base_time=1791932400) if s["split"] == "heldout")
    replay = _live_copy(scenario, 0, 1791932400)
    for original, event in zip(scenario["events"], replay["events"]):
        parse_event(event, "agent", replay["index"], expected_host=scenario["host_group"])
        assert event["data"]["host"]["id"] == scenario["host_group"]
        assert event["data"]["host"]["boot_id"] != original["data"]["host"]["boot_id"]
        assert event["id"] != original["id"]
    assert scenario["events"][0]["data"]["host"]["boot_id"] == "boot-"+scenario["host_group"]

from tools.sequence_scenarios import generate, validate


@pytest.fixture(scope="module")
def corpus():
    return generate(base_time=1791932400)


def test_dataset_contains_more_than_1000_sequences_with_separate_partitions(corpus):
    info = validate(corpus)
    assert info["scenario_count"] == 1536
    assert info["event_count"] == 18432
    assert info["family_host_time_disjoint"] is True
    assert info["partitions"]["heldout"]["labels"] == {"normal": 128, "attack": 128}


def _observable_stage(data):
    # Identity is for grouping, not a prediction feature. Equal bags prevent a
    # class-correlated command length, depth or port from making this test easy.
    return repr((data["event"], {k: data["process"][k] for k in ("name", "command_line", "depth")},
                 data.get("destination"), data.get("network"), data.get("file"),
                 data.get("registry"), data.get("dns"), data.get("email"), data.get("cloud")))


def test_attack_and_benign_pairs_require_transition_context(corpus):
    for normal, attack in zip(corpus[::2], corpus[1::2]):
        assert normal["label"] == "normal" and attack["label"] == "attack"
        assert normal["profile"] == attack["profile"]
        assert normal["family"] == attack["family"]
        assert normal["host_group"] != attack["host_group"]
        bags = [Counter(_observable_stage(e["data"]) for e in s["events"]) for s in (normal, attack)]
        assert bags[0] == bags[1]
        assert _observable_stage(normal["events"][0]["data"]) == _observable_stage(attack["events"][0]["data"])
        assert _observable_stage(normal["events"][-1]["data"]) == _observable_stage(attack["events"][-1]["data"])
        assert [e["data"]["event"]["action"] for e in normal["events"]] != [e["data"]["event"]["action"] for e in attack["events"]]


def test_source_telemetry_does_not_contain_review_labels_or_split(corpus):
    forbidden = {"label", "family", "split", "scenario_id", "truth"}
    def check(value):
        if isinstance(value, dict):
            assert not forbidden.intersection(value)
            for child in value.values(): check(child)
        elif isinstance(value, list):
            for child in value: check(child)
    for scenario in corpus:
        check(scenario["events"])


def test_partition_validator_rejects_host_or_family_leakage(corpus):
    altered = copy.deepcopy(corpus)
    heldout = next(s for s in altered if s["split"] == "heldout")
    heldout["family"] = altered[0]["family"]
    with pytest.raises(ValueError, match="Partition leakage"):
        validate(altered)


def test_corpus_is_reproducible_and_different_seed_changes_original_ids(corpus):
    assert validate(generate(base_time=1791932400))["dataset_digest"] == validate(corpus)["dataset_digest"]
    assert generate(variants_per_family=2, seed=7, base_time=1791932400)[0]["events"][0]["id"] != corpus[0]["events"][0]["id"]
