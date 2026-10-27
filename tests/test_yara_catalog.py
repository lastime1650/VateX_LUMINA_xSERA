"""Real upstream bytes, license exclusions, quality filters and engine checks."""
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from sapientia import yara_catalog
from tools import import_yara_catalog as importer


def test_packaged_counts_are_actual_namespaced_rules_not_files_or_private_helpers():
    summary = yara_catalog.verify(compile_rules=True)
    assert summary["file_count"] == 991
    assert summary["rule_count"] == 2285
    assert summary["public_rule_count"] == 2276
    assert summary["private_helper_count"] == 9
    assert summary["compilation"]["status"] == "completed", summary["compilation"]
    assert summary["compilation"]["rule_count"] == summary["rule_count"]
    assert summary["compilation"]["public_rule_count"] == summary["public_rule_count"]
    assert summary["compilation"]["harmless_matches"] == []
    assert not summary["automatic_response"] and not summary["malware_accuracy_measured"]
    assert sum(s["included_files"] for s in summary["sources"]) == summary["file_count"]
    assert sum(s["scanned_files"]-s["included_files"] for s in summary["sources"]) == summary["excluded_file_count"]


def test_every_shipped_rule_is_manifested_pinned_exact_upstream_blob_and_unchanged():
    entries = yara_catalog.inventory()
    root = Path(str(yara_catalog._root()))
    actual = {p.relative_to(root).as_posix() for p in (root/"rules").rglob("*") if p.suffix.lower() in {".yar", ".yara"}}
    assert actual == {entry["file_path"] for entry in entries}
    assert len({entry["sha256"] for entry in entries}) == len(entries)
    for entry in entries:
        body = (root/entry["file_path"]).read_bytes()
        assert body == entry["source"].encode("utf-8")
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        assert hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest() == entry["upstream_git_blob"]
        assert len(body) <= 32768
        assert not importer.FORBIDDEN.search(entry["source"])
        assert entry["commit"] in entry["upstream_url"]
        assert entry["license_review"]["accepted"] and entry["quality_review"]["accepted"]
        assert importer.license_review(entry["source"], entry["license"], entry["rules"])["accepted"], entry["upstream_path"]
        assert entry["rule_count"] == len(entry["rules"])
        assert entry["validation"]["compile_and_harmless_probe_passed"]


def test_noncommercial_and_different_license_sources_are_absent_even_as_stale_files():
    manifest = json.loads(yara_catalog._bytes("manifest.json"))
    excluded = {(e["source_id"], e["upstream_path"]): e for e in manifest["excluded"]}
    for path in ("yara/crime_xbash.yar", "yara/apt_royalroad.yar", "yara/apt_pulsesecure.yar"):
        row = excluded[("signature_base", path)]
        assert row["reason"] in {"restricted_license_cue", "different_or_unrecognized_license_override"}
        assert not yara_catalog._root().joinpath("rules", "signature_base", *Path(path).parts).is_file()
    assert any(e["reason"] == "constant_size_or_header_only" for e in manifest["excluded"])
    assert any(e["reason"] == "informational_or_test_rule" for e in manifest["excluded"])


@pytest.mark.parametrize("text,expected", [
    ('rule A { meta: license="Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE" condition:true }', True),
    ('rule A { meta: license="https://creativecommons.org/licenses/by-nc/4.0/" condition:true }', False),
    ('/* License: https://creativecommons.org/licenses/by-nc/4.0/ */ rule A {condition:true}', False),
    ('/* MIT License */ rule A {condition:true}', False),
    ('/* The 2-Clause BSD License */ rule A {condition:true}', False),
    ('// These rules use the two-clause BSD license\nrule A {condition:true}', False),
    ('/* Redistribution and use in source and binary forms ... */ rule A {condition:true}', False),
    ('rule A {meta: license="GPL-2.0" condition:true}', False),
    ('rule A {meta: license="unknown-terms" condition:true}', False),
])
def test_rule_and_comment_license_override_review_is_conservative(text, expected):
    assert importer.license_review(text, "DRL-1.1")["accepted"] is expected


@pytest.mark.parametrize("condition,accepted", [
    ("true", False), ("filesize < 10MB", False), ("uint16(0) == 0x5a4d", False),
    ("uint16(0)==0x5a4d and filesize<1MB and $a", True), ("$a", True),
])
def test_default_quality_excludes_constant_size_header_only_not_string_detection(condition, accepted):
    text = 'rule Meaningful { strings: $a="distinct benign qualification marker" condition: '+condition+' }'
    rules = [{"identifier": "Meaningful", "private": False, "meta": {}}]
    assert importer.quality_review(text, rules)["accepted"] is accepted
    private = [{"identifier": "Meaningful", "private": True, "meta": {}}]
    assert importer.quality_review(text, private)["accepted"]


def test_runtime_results_preserve_original_author_on_a_real_harmless_positive_oracle():
    import yara
    entry = next(e for e in yara_catalog.inventory() if e["upstream_path"] == "yara/expl_log4j_cve_2021_44228.yar")
    rules = yara.compile(source=entry["source"], includes=False, error_on_warning=True)
    # Only an inert path fragment, no executable, URL, shell command or network.
    body = b"An inert test record containing /Basic/Command/Base64/ as plain text."
    hits = rules.match(data=body, timeout=1)
    chosen = next(hit for hit in hits if hit.rule == "EXPL_JNDI_Exploit_Patterns_Dec21_1")
    assert chosen.meta["author"] == "Florian Roth (Nextron Systems)"
    assert chosen.meta["author"] in entry["authors"] and entry["license"] == "DRL-1.1"
    assert rules.match(data=b"A different harmless test record.", timeout=1) == []


def _copy_manifest_notice_and_one_source(tmp_path):
    root = Path(str(yara_catalog._root()))
    manifest = json.loads((root/"manifest.json").read_bytes())
    paths = ["manifest.json", *[s["license_file"] for s in manifest["sources"]], manifest["entries"][0]["file_path"]]
    for path in paths:
        target = tmp_path/path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/path, target)
    return manifest["entries"][0]


def test_source_or_license_tamper_fails_closed_and_return_values_do_not_mutate_catalog(tmp_path, monkeypatch):
    entry = _copy_manifest_notice_and_one_source(tmp_path)
    original = yara_catalog.get(entry["id"])
    original["rules"][0]["meta"]["author"] = "caller mutation"
    assert yara_catalog.get(entry["id"])["rules"][0]["meta"].get("author") != "caller mutation"
    monkeypatch.setattr(yara_catalog, "_root", lambda: tmp_path)
    assert yara_catalog.get(entry["id"])["sha256"] == entry["sha256"]
    path = tmp_path/entry["file_path"]
    path.write_bytes(path.read_bytes()+b"\n// changed")
    with pytest.raises(yara_catalog.CatalogIntegrityError, match="source hash"):
        yara_catalog.get(entry["id"])
    manifest = json.loads((tmp_path/"manifest.json").read_bytes())
    notice = tmp_path/manifest["sources"][0]["license_file"]
    notice.write_bytes(b"license replaced")
    with pytest.raises(yara_catalog.CatalogIntegrityError, match="notice hash"):
        yara_catalog.get(entry["id"])


def test_manifest_mutation_and_path_traversal_cannot_replace_pinned_catalog(tmp_path, monkeypatch):
    _copy_manifest_notice_and_one_source(tmp_path)
    manifest_path = tmp_path/"manifest.json"
    data = json.loads(manifest_path.read_bytes())
    data["entries"][0]["file_path"] = "../outside.yar"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(yara_catalog, "_root", lambda: tmp_path)
    with pytest.raises(yara_catalog.CatalogIntegrityError, match="manifest hash"):
        yara_catalog.inventory()
    for value in ("../outside", "/absolute", "C:/private", "rules\\private"):
        with pytest.raises(yara_catalog.CatalogIntegrityError):
            yara_catalog._path(value)
    with pytest.raises(KeyError):
        yara_catalog.get("../outside")


def test_real_validator_requires_no_external_variables_and_never_treats_unavailable_as_clean():
    answer = importer.validate_source('rule NeedsExternal {condition: unavailable_external}')
    assert answer["status"] == "failed" and "undefined identifier" in answer["reason"]
    answer = importer.validate_source('rule Invalid {condition: }')
    assert answer["status"] == "failed"
