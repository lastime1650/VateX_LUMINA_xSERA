from sapientia import log_footprint


def test_nested_capacity_includes_search_parquet_and_temp_without_exposing_names(tmp_path):
    for relative, count in (("control.sqlite3", 3), ("log-search/terms.sqlite3", 11),
                            ("log-segments/a.parquet", 17), ("events.duckdb.tmp/a", 5),
                            ("collector-spool/a", 7), ("unknown/a", 13)):
        target = tmp_path / relative
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(b"x" * count)
    sample = log_footprint.status(tmp_path)
    assert sample["complete"] is True
    assert sample["measured_bytes"] == 56
    assert sample["components"]["search_indexes_and_snapshots"] == 11
    assert sample["components"]["parquet_segments"] == 17
    assert sample["components"]["temporary"] == 5
    assert "a.parquet" not in str(sample)
    # Other callers cannot tamper with a cached observation.
    sample["components"]["root_files"] = 100
    (tmp_path / "control.sqlite3").write_bytes(b"extra")
    cached = log_footprint.status(tmp_path)
    assert cached["components"]["root_files"] == 3
    assert cached["measured_bytes"] == 56
    assert cached["age_seconds"] >= 0


def test_metadata_limit_is_explicit_incomplete_prefix(tmp_path):
    for number in range(5):
        (tmp_path / str(number)).write_bytes(b"123")
    sample = log_footprint.status(tmp_path, max_entries=2)
    assert sample["complete"] is False
    assert sample["entries_observed"] == 2
    assert sample["measured_bytes"] == 6


def test_missing_directory_is_unavailable_not_complete_zero(tmp_path):
    sample = log_footprint.status(tmp_path / "missing")
    assert sample["complete"] is False
    assert sample["metadata_errors"] == 1


def test_directory_link_does_not_include_external_files(tmp_path):
    import os

    import pytest

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private-data").write_bytes(b"x" * 1000)
    root = tmp_path / "data"
    root.mkdir()
    try:
        os.symlink(outside, root / "linked", target_is_directory=True)
    except OSError:
        pytest.skip("OS does not permit symbolic link creation")
    sample = log_footprint.status(root)
    assert sample["measured_bytes"] == 0
    assert sample["complete"] is False
    assert sample["skipped_links"] == 1
    root_link = tmp_path / "root-link"
    os.symlink(outside, root_link, target_is_directory=True)
    linked_sample = log_footprint.status(root_link)
    assert linked_sample["measured_bytes"] == 0
    assert linked_sample["complete"] is False
    assert linked_sample["skipped_links"] == 1
