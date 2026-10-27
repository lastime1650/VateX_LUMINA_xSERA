import time

import pytest

from sapientia import access, attack_catalog, auth
from sapientia.storage import CapacityError, Settings, Store, encode


@pytest.fixture
def case_material(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    for name, tenant in [("owner", "a"), ("other", "b")]:
        auth.create_user(
            store, name, "Synthetic-attack-context-password-2026", "admin", tenant
        )
    actor = {"name": "owner", "tenant": "a", "role": "admin"}
    now = time.time()
    with store.control() as db:
        db.execute(
            "INSERT INTO incidents(id,tenant,entity,entity_field,name,created,updated,status) VALUES('case','a','qa-host','host','Synthetic full case',?,?,'new')",
            (now, now),
        )
        for i in range(60):
            evidence = {
                "mitre": ["T1059.001"] if i < 59 else ["T1562.001", "T9999"],
                "severity": "low" if i < 59 else "critical",
                "event_ids": ["event-" + str(i)],
            }
            db.execute(
                "INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    str(i),
                    "a",
                    "case",
                    "policy-" + str(i),
                    "qa-host",
                    "host",
                    now + i,
                    15 if i < 59 else 90,
                    encode(evidence),
                    encode(["public"]),
                ),
            )
    yield store, actor
    store.close()


def test_licensed_catalog_tactic_order_and_historical_techniques():
    info = attack_catalog.metadata()
    assert (
        info["version"] == "19.2"
        and info["technique_count"] == 858
        and info["tactic_count"] == 15
    )
    listing = attack_catalog.listing(limit=200)
    assert listing["tactics"][0]["shortname"] == "reconnaissance"
    assert all(
        not row["revoked"] and not row["deprecated"] for row in listing["techniques"]
    )
    all_items = attack_catalog.listing(include_inactive=True, limit=200)
    assert all_items["total"] == 858
    match = attack_catalog.technique("T1059.001", detail=True)
    assert (
        "TA0002" in match["tactics"]
        and "Windows" in match["platforms"]
        and match["is_subtechnique"]
    )
    assert (
        attack_catalog.technique("T1562.001")["deprecated"]
        or attack_catalog.technique("T1562.001")["revoked"]
    )
    match["tactics"].clear()
    assert attack_catalog.technique("T1059.001")["tactics"]
    with pytest.raises(ValueError):
        attack_catalog.listing(tactic="bad")


def test_full_authorized_case_score_no_page_bias_or_replay_inflation(case_material):
    store, actor = case_material
    result = attack_catalog.attack_context(store, actor, "case")
    assert result["contribution_count"] == result["evidence_event_count"] == 60
    assert result["severity"] == "critical" and result["threat_score"] == 90
    assert result["hosts"] == ["qa-host"]
    assert result["score_definition"]["id"] == "case-evidence-max-v1"
    known = next(row for row in result["techniques"] if row["id"] == "T1059.001")
    assert (
        known["contribution_count"] == 59
        and len(known["evidence_event_ids"]) == 59
        and known["score"] == 15
    )
    unknown = next(row for row in result["techniques"] if row["id"] == "T9999")
    assert not unknown["known"] and unknown["url"] is None
    assert len(result["warnings"]) == 2
    with store.control() as db:
        row = dict(
            db.execute("SELECT * FROM risk_contributions WHERE id='59'").fetchone()
        )
        row["id"] = "duplicate-evidence"
        db.execute(
            "INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
            tuple(row.values()),
        )
    repeated = attack_catalog.attack_context(store, actor, "case")
    assert repeated["threat_score"] == 90 and repeated["evidence_event_count"] == 60


def test_case_context_current_scope_cross_tenant_and_revocation(case_material):
    store, actor = case_material
    with pytest.raises(KeyError):
        attack_catalog.attack_context(
            store, {"name": "other", "tenant": "b", "role": "admin"}, "case"
        )
    restricted = {**actor, "allowed_indexes": ["private"]}
    with pytest.raises(KeyError):
        attack_catalog.attack_context(store, restricted, "case")
    access.set_for_user(store, actor, "owner", ["private"])
    with pytest.raises(KeyError):
        attack_catalog.attack_context(store, actor, "case")


def test_large_complete_case_source_keeps_full_summary_without_page_bias(case_material):
    store, actor = case_material
    with store.control() as db:
        db.execute(
            "UPDATE risk_contributions SET evidence=? WHERE id='0'",
            (
                encode(
                    {"event_ids": ["event-0"], "mitre": ["T1059.001"], "severity": "low",
                     "padding": "x" * (2 * 1024 * 1024)}
                ),
            ),
        )
    result = attack_catalog.attack_context(store, actor, "case")
    assert result["contribution_count"] == result["evidence_event_count"] == 60
    assert result["threat_score"] == 90 and result["severity"] == "critical"
    technique = next(item for item in result["techniques"] if item["id"] == "T1059.001")
    assert technique["contribution_count"] == 59 and len(technique["evidence_event_ids"]) == 59


def test_oversized_visible_attack_context_refuses_partial_score(case_material):
    store, actor = case_material
    now = time.time()
    with store.control() as db:
        for position in range(700):
            # Each contribution keeps the supported32-original shape. The
            # complete visible summary, rather than unrelated source padding,
            # exceeds the separate ATT&CK response budget.
            event_ids = [f"large-{position:04}-{slot:02}-" + "x"*96 for slot in range(32)]
            db.execute("INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
                (f"large-contribution-{position}", actor["tenant"], "case", f"large-policy-{position}",
                 "qa-host", "host", now, 15, encode({"event_ids":event_ids,"mitre":["T1059.001"],"severity":"low"}), encode(["public"])))
    with pytest.raises(CapacityError, match="Complete ATT&CK case context"):
        attack_catalog.attack_context(store, actor, "case")
