"""Accuracy accounting, blind-input separation and real offline Case path."""

import copy
import json

import pytest

from tools import detection_benchmark as benchmark


def test_confusion_counts_and_intervals_do_not_use_case_resolution_as_truth():
    rows = [
        {"label": "malicious", "detected": True, "case_count": 2},
        {"label": "malicious", "detected": False, "case_count": 0},
        {"label": "benign", "detected": True, "case_count": 1},
        {"label": "benign", "detected": False, "case_count": 0},
    ]
    result = benchmark.metrics(rows)
    assert [result[k] for k in ("tp", "fp", "fn", "tn")] == [1, 1, 1, 1]
    assert result["precision"]["value"] == result["recall"]["value"] == 0.5
    assert result["attack_case_fragmentation"]["mean_cases_per_attack"] == 1
    low, high = result["precision"]["wilson_95_interval"]
    assert 0 < low < 0.5 < high < 1


def test_perfect_small_sample_does_not_claim_certain_zero_false_positive_rate():
    one = benchmark.proportion(0, 1)
    assert one["value"] == 0 and one["wilson_95_interval"][1] > 0.7
    assert benchmark.proportion(0, 0)["value"] is None
    assert benchmark.proportion(0, 0)["wilson_95_interval"] is None


@pytest.mark.parametrize("a,b", [(True, 1), (1, True), (-1, 10), (11, 10), (1.0, 2)])
def test_uncertainty_requires_real_integer_denominators(a, b):
    with pytest.raises(ValueError):
        benchmark.proportion(a, b)


def small_corpus(tmp_path):
    original, _ = benchmark.load_corpus(benchmark.DEFAULT_CORPUS)
    corpus = copy.deepcopy(original)
    corpus["cases"] = corpus["cases"][:2]
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    return path


def test_public_twin_corpus_does_not_leak_labels_into_event_data():
    corpus, _ = benchmark.load_corpus(benchmark.DEFAULT_CORPUS)
    assert (
        len(corpus["cases"]) == 24
        and not corpus["provenance"]["independently_hidden_holdout"]
    )
    for row in corpus["cases"]:
        for event in row["events"]:
            assert not benchmark._ground_truth_keys(event["data"])
            assert event["data"]["user"]["name"] == "qualification-user"


def test_nested_ground_truth_and_duplicate_scenarios_fail_before_state_creation(
    tmp_path,
):
    path = small_corpus(tmp_path)
    corpus = json.loads(path.read_text())
    corpus["cases"][0]["events"][0]["data"]["event"]["label"] = "malicious"
    path.write_text(json.dumps(corpus))
    with pytest.raises(ValueError, match="Ground-truth"):
        benchmark.load_corpus(path)
    del corpus["cases"][0]["events"][0]["data"]["event"]["label"]
    corpus["cases"][1]["id"] = corpus["cases"][0]["id"]
    path.write_text(json.dumps(corpus))
    with pytest.raises(ValueError, match="Duplicate"):
        benchmark.load_corpus(path)


def test_accuracy_runner_uses_actual_intake_index_and_case_records(tmp_path):
    corpus = small_corpus(tmp_path)
    report = benchmark.run_benchmark(
        corpus, tmp_path / "owned-data", templates=["R-WIN-001"]
    )
    assert report["event_count"] == 2 and report["completed_detectors"] == 1
    assert report["scenario_count"] == 2 and report["errors"] == []
    # Identical rule-visible encoded commands have different external truths:
    # this deliberately reports a real false positive rather than tuning labels.
    assert report["metrics"]["tp"] == 1 and report["metrics"]["fp"] == 1
    assert report["metrics"]["precision"]["value"] == 0.5
    assert report["actual_unique_cases_created"] == report["metrics"]["case_count"] == 2
    assert report["metrics"]["actual_unique_cases_created"] == 2
    assert report["metrics"]["case_attribution_count"] == 2
    assert all(
        row["matched_detector_ids"] == ["R-WIN-001"] for row in report["outcomes"]
    )
    assert (tmp_path / "owned-data" / ".qa-synthetic-only").is_file()
    assert report["execution"]["server_started"] is False
    assert report["execution"]["sample_commands_executed"] is False
    assert report["execution"]["native_sensor_exercised"] is False


def test_existing_data_and_wrong_freeze_are_rejected_without_reuse(tmp_path):
    corpus = small_corpus(tmp_path)
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "preserve.txt").write_text("preserve")
    with pytest.raises(ValueError, match="existing data"):
        benchmark.run_benchmark(corpus, existing, templates=["R-WIN-001"])
    assert (existing / "preserve.txt").read_text() == "preserve"
    with pytest.raises(ValueError, match="snapshot differs"):
        benchmark.run_benchmark(
            corpus,
            tmp_path / "never-created",
            templates=["R-WIN-001"],
            expected_freeze={},
        )
    assert not (tmp_path / "never-created").exists()


def test_ground_truth_event_id_filter_is_not_an_accuracy_detector(tmp_path):
    path = tmp_path / "overfit.json"
    path.write_text(
        json.dumps(
            {
                "schema": "xsera.benchmark-detectors.v1",
                "policies": [
                    {
                        "id": "overfit",
                        "definition": {
                            "name": "Known event-ID overfit",
                            "entity_field": "host",
                            "steps": [
                                {
                                    "filters": [
                                        {
                                            "field": "event_id",
                                            "op": "eq",
                                            "value": "known-malicious-fixture",
                                        }
                                    ]
                                }
                            ],
                        },
                    }
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="fixture event IDs"):
        benchmark.freeze_detectors(policies_path=path)


def test_no_duplicate_detector_ids_and_no_simultaneous_template_policy_modes(tmp_path):
    with pytest.raises(ValueError, match="Duplicate"):
        benchmark.freeze_detectors(["R-WIN-001", "R-WIN-001"])
    with pytest.raises(ValueError, match="Choose"):
        benchmark.freeze_detectors(["R-WIN-001"], tmp_path / "unused")


def test_write_freeze_never_reads_corpus_or_creates_evaluation_state(
    tmp_path, monkeypatch
):
    def unexpected_read(_path):
        raise AssertionError("Freeze creation must not inspect ground truth")

    monkeypatch.setattr(benchmark, "load_corpus", unexpected_read)
    destination = tmp_path / "freeze.json"
    assert (
        benchmark.main(
            [
                "--write-freeze",
                str(destination),
                "--template",
                "R-WIN-001",
                "--corpus",
                str(tmp_path / "unread.json"),
            ]
        )
        == 0
    )
    freeze = json.loads(destination.read_text(encoding="utf-8"))
    assert freeze["detector_sha256"] == benchmark.digest(freeze["detectors"])
    assert freeze["sources"] == benchmark.source_snapshot()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["freeze.json"]


def test_temporal_boundary_corpus_preserves_subminute_gap_precision(tmp_path):
    path = small_corpus(tmp_path)
    corpus = json.loads(path.read_text())
    corpus["cases"][0]["events"][0]["offset_seconds"] = -122.25
    corpus["cases"][1]["events"][0]["offset_seconds"] = -123.25
    path.write_text(json.dumps(corpus))
    loaded, _ = benchmark.load_corpus(path)
    assert loaded["cases"][0]["events"][0]["offset_seconds"] == -122.25
    corpus["cases"][0]["events"][0]["offset_seconds"] = -601
    path.write_text(json.dumps(corpus))
    with pytest.raises(ValueError, match="offset -600"):
        benchmark.load_corpus(path)


def test_shared_host_is_attributed_to_original_evidence_not_host_presence(tmp_path):
    path = small_corpus(tmp_path)
    corpus = json.loads(path.read_text())
    for scenario in corpus["cases"]:
        scenario["host_group"] = "shared-contract-host"
    corpus["cases"][1]["events"][0]["data"]["process"]["command_line"] = (
        "powershell.exe -NoProfile Get-Date"
    )
    path.write_text(json.dumps(corpus))
    result = benchmark.run_benchmark(
        path, tmp_path / "shared-data", templates=["R-WIN-001"]
    )
    assert result["errors"] == []
    assert len({row["host"] for row in result["outcomes"]}) == 1
    assert result["outcomes"][0]["detected"] is True
    assert result["outcomes"][1]["detected"] is False
    assert result["metrics"]["tp"] == 1 and result["metrics"]["tn"] == 1
    assert result["cross_scenario_cases"] == []


def test_shared_case_counts_once_but_retains_each_attack_attribution():
    rows = [
        {
            "label": "malicious",
            "detected": True,
            "case_count": 1,
            "case_ids": ["one-case"],
        },
        {
            "label": "malicious",
            "detected": True,
            "case_count": 1,
            "case_ids": ["one-case"],
        },
        {"label": "benign", "detected": False, "case_count": 0, "case_ids": []},
    ]
    result = benchmark.metrics(rows, actual_unique_cases_created=1)
    assert result["case_count"] == result["actual_unique_cases_created"] == 1
    assert (
        result["case_attribution_count"] == result["legacy_case_attribution_count"] == 2
    )
    assert result["attack_case_fragmentation"]["case_count"] == 1
    assert result["attack_case_fragmentation"]["case_attribution_count"] == 2
    assert result["attack_case_fragmentation"]["mean_cases_per_attack"] == 1
    cohort = benchmark.metrics(rows)
    assert cohort["case_count"] == 1 and cohort["actual_unique_cases_created"] is None


def test_case_total_is_unknown_without_ids_and_not_inferred_from_attributions():
    result = benchmark.metrics(
        [{"label": "malicious", "detected": True, "case_count": 2}]
    )
    assert (
        result["case_count"] is None and result["actual_unique_cases_created"] is None
    )
    assert result["case_attribution_count"] == 2
    with pytest.raises(ValueError, match="nonnegative integer"):
        benchmark.metrics([], actual_unique_cases_created=True)
