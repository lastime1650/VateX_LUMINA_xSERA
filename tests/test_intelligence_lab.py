"""The substantial paced HTTPS scenario is an explicit standalone lab run."""

import json
from pathlib import Path

import pytest

from tools.intelligence_lab import ORDER, isolated_paths, plan


def test_paced_plan_exact_counts_disjoint_labels_and_source_identities():
    events,truth,base=plan(seed=17,base_time=1700000040)
    assert list(events)==list(ORDER) and all(len(rows)==50 for rows in events.values())
    assert len(truth)==200
    assert "scenario_label" not in json.dumps(events)
    for profile,rows in events.items():
        assert len({e["id"] for e in rows})==50
        labels=[r for r in truth if r["profile"]==profile]
        assert all(r["scenario_label"]=="benign" for r in labels[:25])
        assert sum(r["scenario_label"]=="malicious" for r in labels[25:])==5
        assert max(r["reported_time"] for r in labels[:25])<base+120
        assert min(r["reported_time"] for r in labels[25:])>=base+120
    for profile in ("windows","linux"):
        assert events[profile][25]["data"]["process"]["guid"]==events[profile][45]["data"]["process"]["guid"]
        assert events[profile][25]["data"]["process"]["start_identity"]==events[profile][45]["data"]["process"]["start_identity"]
        assert len(events[profile][25]["data"]["process"]["command_line"])<=8192
    assert events==plan(seed=17,base_time=1700000040)[0]


def test_paced_lab_refuses_production_paths(tmp_path):
    production=Path(__file__).resolve().parents[1]/"data"
    with pytest.raises(ValueError,match="production"):
        isolated_paths(production,tmp_path/"result.json")
    with pytest.raises(ValueError,match="production"):
        isolated_paths(tmp_path,production/"result.json")
