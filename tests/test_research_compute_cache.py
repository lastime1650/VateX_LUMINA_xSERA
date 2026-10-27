"""Pure reuse cannot retain authority or let mutable callers change results."""

import copy
from decimal import Decimal

import pytest

from sapientia import evidence_scope
from sapientia import research_behavior as research
from sapientia import research_compute_cache as cache
from sapientia import research_features_v2 as features_v2
from sapientia import research_fusion_v2 as fusion_v2
from tests.test_research_behavior import event


@pytest.fixture(autouse=True)
def clean_cache():
    cache.clear()
    yield
    cache.clear()


def test_actual_input_bytes_and_namespace_control_pure_reuse():
    calls = []

    def calculate():
        calls.append(True)
        return {"nested": [{"value": 1}], "scores": [0.25, 1.0]}

    first = cache.compute("feature", {"raw": {"field": "original"}}, calculate)
    first["nested"][0]["value"] = 9
    second = cache.compute("feature", {"raw": {"field": "original"}}, calculate)
    assert second["nested"][0]["value"] == 1 and len(calls) == 1
    second["scores"].append(99)
    assert cache.compute("feature", {"raw": {"field": "original"}}, calculate)["scores"] == [0.25, 1.0]
    cache.compute("feature", {"raw": {"field": "changed"}}, calculate)
    cache.compute("other-contract", {"raw": {"field": "original"}}, calculate)
    assert len(calls) == 3
    assert all(cache.status()[key] is False for key in ("authority_cached", "predictions_cached", "raw_facts_cached"))


def test_entry_and_byte_limits_evict_without_changing_values(monkeypatch):
    monkeypatch.setattr(cache, "MAX_ENTRIES", 2)
    monkeypatch.setattr(cache, "MAX_BYTES", 30)
    for i in range(4):
        assert cache.compute("test", i, lambda i=i: [i, "123456"]) == [i, "123456"]
    assert cache.status()["entries"] <= 2 and cache.status()["bytes"] <= 30
    before = cache.status()["entries"]
    assert cache.compute("large", 0, lambda: "x" * 100) == "x" * 100
    assert cache.status()["entries"] == before


def test_fast_facts_copy_preserves_json_numbers_and_mutation_independence():
    value = {"one": {"raw": {"unicode": "한글", "list": [True, None, 2**63, -0.0, 1.25]}}}
    actual = evidence_scope._copy_facts(value)
    assert actual == copy.deepcopy(value)
    assert type(actual["one"]["raw"]["list"][2]) is int
    actual["one"]["raw"]["list"].append("mutation")
    assert len(value["one"]["raw"]["list"]) == 5


@pytest.mark.parametrize("odd", [(1, 2), {1: "integer-key"}, Decimal("1.25")])
def test_internal_non_json_types_use_lossless_deepcopy_fallback(odd):
    result = evidence_scope._copy_facts({"odd": odd})
    assert result == {"odd": odd} and type(result["odd"]) is type(odd)


def test_internal_alias_and_cycle_are_preserved_by_fallback():
    shared = [1]
    value = {"a": shared, "b": shared}
    result = evidence_scope._copy_facts(value)
    assert result["a"] is result["b"] and result["a"] is not shared
    cycle = []; cycle.append(cycle)
    result = evidence_scope._copy_facts(cycle)
    assert result[0] is result


def test_only_exact_known_019_pair_is_compatible_and_tags_are_not_rewritten():
    feature, fusion = next(iter(research.KNOWN_V2_COMPATIBILITY))
    old = {"feature_contract_digest": feature, "fusion": {"schema": "xsera.research-fusion.v2", "contract_digest": fusion}}
    saved = copy.deepcopy(old)
    assert research._compatible_snapshot(old) and old == saved
    for key, value in (("feature_contract_digest", "f"*64), ("fusion", {"schema": "xsera.research-fusion.v2", "contract_digest": research.research_fusion_v2.CONTRACT_DIGEST})):
        changed = copy.deepcopy(old); changed[key] = value
        assert not research._compatible_snapshot(changed)


@pytest.mark.parametrize("v2", [False, True])
def test_effective_input_keys_preserve_vectors_and_exclude_only_unused_fields(v2, monkeypatch):
    row = event(1)
    snapshot = {"fusion": {"schema": fusion_v2.SCHEMA}} if v2 else {}
    original = features_v2.features if v2 else research.event_features
    calculated = []

    def measured(value):
        calculated.append(True)
        return original(value)

    if v2:
        monkeypatch.setattr(features_v2, "features", measured)
    else:
        monkeypatch.setattr(research, "event_features", measured)
    assert research._features(snapshot, row) == original(row)
    same = copy.deepcopy(row)
    same.update(event_id="different", event_time=1, host="different")
    same["raw"].update(campaign="unused", ground_truth="unused", padding="x"*10000)
    assert research._features(snapshot, same) == original(same) and len(calculated) == 1
    changed = copy.deepcopy(row); changed["raw"]["command_line"] = "powershell -enc YQ=="
    assert research._features(snapshot, changed) == original(changed) and len(calculated) == 2
    changed["projection"]["process"]["start_identity"] = ""
    assert research._features(snapshot, changed) == original(changed) and len(calculated) == 3
    assert fusion_v2._metadata(row)["identity"] is not None
    assert fusion_v2._metadata(changed)["identity"] is None
