"""Actual inert JSON-line cursor preservation, rotation and bounded parsing."""

import json

import pytest

from tools.forward_analysis_sensor import read_one


def test_complete_line_identity_is_stable_and_partial_line_is_not_consumed(tmp_path):
    target = tmp_path / "sensor.jsonl"
    target.write_bytes(b'{"time":1}\n{"time":2}')
    first = read_one(target, 0, "binding")
    assert first == read_one(target, 0, "binding")
    assert first["event"]["log"] == {"time": 1}
    assert read_one(target, first["offset"], "binding") is None
    with target.open("ab") as stream:
        stream.write(b"\n")
    second = read_one(target, first["offset"], "binding")
    assert second["event"]["log"] == {"time": 2}
    assert second["event"]["id"] != first["event"]["id"]


def test_large_malformed_or_non_object_line_is_not_silently_skipped(tmp_path):
    target = tmp_path / "sensor.jsonl"
    for value in (b"x" * 49153 + b"\n", b"invalid\n", b"[]\n"):
        target.write_bytes(value)
        with pytest.raises(ValueError):
            read_one(target, 0, "binding")


def test_truncated_file_restarts_at_explicit_source_offset(tmp_path):
    target = tmp_path / "sensor.jsonl"
    target.write_text(json.dumps({"ts": 1}) + "\n")
    result = read_one(target, 5000, "binding", "conn")
    assert (
        result["event"]["kind"] == "conn" and result["offset"] == target.stat().st_size
    )


def test_replaced_or_copy_truncated_log_is_detected_inside_open_handle(tmp_path):
    target = tmp_path / "sensor.jsonl"
    target.write_text('{"id":"old"}\n')
    first = read_one(target, 0, "binding")
    target.write_text('{"id":"new"}\n{"other":"longer-than-before"}\n')
    changed = read_one(
        target,
        first["offset"],
        "binding",
        expected_identity=first["identity"],
        expected_anchor=first["anchor"],
    )
    assert changed["event"]["log"] == {"id": "new"}
    assert changed["event"]["id"] != first["event"]["id"]
    target.unlink()
    target.write_text('{"new_inode":true}\n')
    replaced = read_one(
        target, first["offset"], "binding", expected_identity="definitely-an-old-inode"
    )
    assert replaced["event"]["log"] == {"new_inode": True}
