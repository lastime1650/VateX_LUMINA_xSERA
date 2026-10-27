"""Real YARA, GUI builder, revision authority and evidence-preserving CRUD."""

import json
import os
import subprocess
import time
import uuid

import pytest
from test_xdr_advanced_api import create_artifact, login

from sapientia import access, auth
from sapientia import yara_manager as yara
from sapientia.storage import CapacityError, ConflictError, encode

pytest_plugins = ("test_xdr_advanced_api",)


MARKER = 'rule Harmless { strings: $a = "Harmless API signature sample" condition: $a }'


def actor(name="requester", role="admin"):
    return {"name": name, "tenant": "a", "role": role, "allowed_indexes": ["*"]}


def custom(**changes):
    return {
        "name": "Harmless test rule",
        "source": MARKER,
        "indexes": ["public"],
        "enabled": True,
        "description": "Synthetic harmless bytes only",
        **changes,
    }


def collection(client, *, process=False):
    identifier, sha = create_artifact(client)
    store, case = client.app.state.store, client.app.state.qualification["case"]
    command = uuid.uuid4().hex
    action = {"type": "collect_artifact", "path": "/lab/harmless.bin", "sha256": sha}
    if process:
        action.update(
            source="process_executable",
            path=r"C:\QA\harmless.bin",
            process_guid="synthetic-process",
            pid=123,
            start_identity="windows:1234567890",
            max_bytes=32 * 1024 * 1024,
        )
    with store.control() as db:
        db.execute(
            "UPDATE endpoint_artifacts SET command_id=? WHERE id=?",
            (command, identifier),
        )
        db.execute(
            "INSERT INTO endpoint_responses(id,tenant,incident_id,agent_id,host,index_name,requester,scope,request_id,request_digest,evidence_event_id,case_version,action,reason,state,created,expires) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                command,
                "a",
                case["id"],
                "api-agent",
                "api-host",
                "public",
                "requester",
                encode(["public"]),
                uuid.uuid4().hex,
                "fixture",
                "api-lease",
                case["version"],
                encode(action),
                "Synthetic collection fixture",
                "completed",
                time.time(),
                time.time() + 300,
            ),
        )
    return identifier


def approved(client, source=MARKER):
    store = client.app.state.store
    saved = yara.save_rule(store, actor(), custom(source=source))
    yara.review_rule(
        store, actor("approver"), saved["id"], 1, True, "Harmless fixture reviewed"
    )
    return saved["id"]


def test_real_multiline_compile_and_namespaced_scan():
    source = 'rule Test_Marker {\n strings:\n $a = "XSERA_YARA_HARMLESS"\n condition:\n $a\n}\n'
    checked = yara.validate(source)
    assert checked["status"] == "completed" and checked["rule_count"] == 1
    result = yara._worker({"one": source, "two": source}, body=b"XSERA_YARA_HARMLESS")
    assert result["status"] == "completed" and result["rule_count"] == 2
    assert {m["namespace"] for m in result["matches"]} == {"one", "two"}
    clean = yara._worker({"one": source}, body=b"unrelated harmless content")
    assert clean["status"] == "completed" and not clean["matches"]
    assert yara.validate("rule bad { condition: }")["status"] == "failed"


def test_isolated_yara_runtime_is_the_actual_direct_child(tmp_path):
    from sapientia.yara_runtime import isolated_command

    result = subprocess.run(
        isolated_command(
            "import json,os,yara;print(json.dumps({'parent':os.getppid(),'version':yara.__version__}))"
        ),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=5,
        check=True,
    )
    assert json.loads(result.stdout)["parent"] == os.getpid()
    assert json.loads(result.stdout)["version"] == "4.5.4"
    marker = tmp_path / "must-not-survive-timeout.txt"
    script = (
        "import pathlib,time;time.sleep(1);pathlib.Path("
        + repr(str(marker))
        + ").write_text('orphan')"
    )
    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run(
            isolated_command(script), capture_output=True, timeout=0.1, check=False
        )
    time.sleep(1.1)
    assert not marker.exists()


@pytest.mark.parametrize("environment_value", ["0", "false"])
def test_isolated_runtime_keeps_imported_dependency_files_unchanged(tmp_path, monkeypatch, environment_value):
    from sapientia import yara_runtime

    packages = tmp_path / "site-packages"
    dependency = packages / "temporary_analysis_dependency"
    dependency.mkdir(parents=True)
    (dependency / "__init__.py").write_text("from .worker import value\n", encoding="utf-8")
    (dependency / "worker.py").write_text("value = 42\n", encoding="utf-8")
    monkeypatch.setattr(yara_runtime.site, "getsitepackages", lambda: [str(packages)])
    before = {path.relative_to(tmp_path).as_posix(): path.read_bytes()
              for path in tmp_path.rglob("*") if path.is_file()}
    command = yara_runtime.isolated_command(
        "import json,sys,temporary_analysis_dependency as dependency;"
        "print(json.dumps({'dont_write_bytecode':sys.dont_write_bytecode,"
        "'isolated':sys.flags.isolated,'value':dependency.value,'file':dependency.__file__}))"
    )
    assert command[1:3] == ["-I", "-B"]
    result = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", timeout=5,
        check=True, cwd=tmp_path,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": environment_value,
             "PYTHONPYCACHEPREFIX": str(tmp_path / "must-not-create-cache")},
    )
    loaded = json.loads(result.stdout)
    assert loaded["dont_write_bytecode"] is True and loaded["isolated"] == 1
    assert loaded["value"] == 42 and os.path.samefile(loaded["file"], dependency / "__init__.py")
    after = {path.relative_to(tmp_path).as_posix(): path.read_bytes()
             for path in tmp_path.rglob("*") if path.is_file()}
    assert after == before
    assert not list(tmp_path.rglob("__pycache__"))
    assert not list(tmp_path.rglob("*.pyc"))
    assert not (tmp_path / "must-not-create-cache").exists()


@pytest.mark.parametrize(
    "source",
    [
        'include "elsewhere.yar"',
        'import "pe" rule t {condition: true}',
        "rule t {condition:true}\x00",
    ],
)
def test_rule_modules_includes_nul_rejected(source):
    with pytest.raises(ValueError):
        yara.validate(source)


def test_gui_builder_escapes_text_and_applies_format_size():
    data = {
        "name": "GUI_Test",
        "strings": [{"kind": "text", "value": 'marker"\\end', "nocase": True}],
        "match": "all",
        "format": "elf",
        "max_bytes": 1024,
        "description": 'GUI 한국어 설명 "인용" \\ 경로',
    }
    result = yara.build_rule(data)
    assert result["validation"]["status"] == "completed"
    assert not yara._worker({"test": result["source"]}, body=b'marker"\\end')["matches"]
    assert yara._worker({"test": result["source"]}, body=b'\x7fELFmarker"\\end')[
        "matches"
    ]
    assert not yara._worker(
        {"test": result["source"]}, body=b'\x7fELFmarker"\\end' + b"0" * 1024
    )["matches"]
    result = yara.build_rule(
        {
            **data,
            "strings": [{"kind": "hex", "value": "58 53 ?? 52 41"}],
            "format": "any",
        }
    )
    assert yara._worker({"test": result["source"]}, body=b"XSERA")["matches"]
    unicode_rule = yara.build_rule(
        {**data, "strings": [{"kind": "text", "value": "무해한_검증"}], "format": "any"}
    )
    assert unicode_rule["validation"]["status"] == "completed"
    assert yara._worker({"test": unicode_rule["source"]}, body="무해한_검증".encode())[
        "matches"
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "bad; injection"},
        {"strings": [{"kind": "hex", "value": "?? ??"}]},
        {"strings": [{"kind": "text", "value": "x", "nocase": "true"}]},
        {"max_bytes": True},
    ],
)
def test_gui_builder_rejects_ambiguous_input(changes):
    with pytest.raises(ValueError):
        yara.build_rule(
            {
                "name": "Rule",
                "strings": [{"kind": "text", "value": "marker"}],
                "match": "all",
                "format": "any",
                "max_bytes": 1024,
                **changes,
            }
        )


def test_rule_crud_peer_review_stale_revision_history_and_tenant(client):
    store = client.app.state.store
    saved = yara.save_rule(store, actor(), custom())
    assert saved["state"] == "pending" and saved["revision"] == 1
    with pytest.raises(PermissionError):
        yara.review_rule(store, actor(), saved["id"], 1, True, "No self review")
    checked = yara.review_rule(
        store, actor("approver"), saved["id"], 1, True, "Independent review"
    )
    assert checked["effective_state"] == "active"
    changed = yara.save_rule(
        store,
        actor(),
        custom(
            expected_revision=1, source=MARKER.replace("Harmless {", "Harmless_2 {")
        ),
        saved["id"],
    )
    assert (
        changed["state"] == "pending"
        and changed["approver"] is None
        and changed["revision"] == 2
    )
    with pytest.raises(ConflictError):
        yara.delete_rule(store, actor(), saved["id"], 1, "Stale")
    deleted = yara.delete_rule(store, actor(), saved["id"], 2, "Remove test rule")
    assert deleted["state"] == "deleted" and deleted["revision"] == 3
    restored = yara.restore_rule(store, actor(), saved["id"], 3)
    assert restored["state"] == "pending" and restored["revision"] == 4
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM yara_rule_history WHERE id=?", (saved["id"],)
            ).fetchone()[0]
            == 5
        )
    with pytest.raises(KeyError):
        yara.get_rule(store, {**actor("foreign"), "tenant": "b"}, saved["id"])


def test_scope_permissions_are_current_and_review_revocation_invalidates(client):
    store = client.app.state.store
    identifier = approved(client)
    access.set_for_user(store, actor(), "approver", ["other"])
    assert (
        yara.get_rule(store, actor(), identifier)["effective_state"]
        == "authority_changed"
    )
    access.set_for_user(store, actor(), "requester", ["other"])
    with pytest.raises(KeyError):
        yara.get_rule(store, actor(), identifier)
    with pytest.raises(PermissionError):
        yara.save_rule(store, actor(), custom())


def test_user_named_release_does_not_bypass_rule_authority(client):
    store = client.app.state.store
    auth.create_user(
        store, "release", "Synthetic-YARA-release-name-user-2026", "admin", "a"
    )
    saved = yara.save_rule(store, actor("release"), custom())
    yara.review_rule(store, actor("approver"), saved["id"], 1, True, "Peer review")
    assert yara.get_rule(store, actor(), saved["id"])["effective_state"] == "active"
    access.set_for_user(store, actor(), "release", ["other"])
    assert (
        yara.get_rule(store, actor(), saved["id"])["effective_state"]
        == "authority_changed"
    )


def test_scan_matches_case_signal_unknown_no_match_and_deletion_preserves_runs(client):
    store = client.app.state.store
    identifier = approved(client)
    artifact = collection(client)
    run = yara.scan_artifact(store, actor(), artifact, rule_ids=[identifier])
    assert (
        run["verdict"] == "suspicious"
        and run["signal_id"]
        and not run["sample_executed"]
    )
    assert (
        run["matches"][0]["source_sha256"]
        == yara.get_rule(store, actor(), identifier)["sha256"]
    )
    assert run["matches"][0]["author"] == "requester"
    nonmatch = approved(
        client, MARKER.replace("Harmless API signature sample", "ABSENT_MARKER_123456")
    )
    negative = yara.scan_artifact(store, actor(), artifact, rule_ids=[nonmatch])
    assert negative["verdict"] == "unknown" and negative["signal_id"] is None
    yara.delete_rule(store, actor(), identifier, 1, "No longer applicable")
    assert yara.list_runs(store, actor())["total"] == 2
    with pytest.raises(ConflictError):
        yara.scan_artifact(store, actor(), artifact, rule_ids=[identifier])
    assert len(yara.list_artifacts(store, actor())["items"]) == 1
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 1
        signal = json.loads(
            db.execute(
                "SELECT body FROM intelligence_signals WHERE id=?", (run["signal_id"],)
            ).fetchone()[0]
        )
        assert not signal["automatic_endpoint_authorization"]


def test_scan_fails_publication_if_rules_or_source_authority_change(
    client, monkeypatch
):
    store = client.app.state.store
    identifier, artifact = approved(client), collection(client)
    original = yara._worker

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        yara.delete_rule(store, actor(), identifier, 1, "Concurrent deletion")
        return result

    monkeypatch.setattr(yara, "_worker", mutate)
    with pytest.raises(ConflictError, match="changed during"):
        yara.scan_artifact(store, actor(), artifact, rule_ids=[identifier])
    assert yara.list_runs(store, actor())["items"] == []


def test_worker_missing_timeout_and_malformed_output_do_not_claim_clean(monkeypatch):
    monkeypatch.setattr(yara.importlib.util, "find_spec", lambda name: None)
    assert yara.validate(MARKER)["status"] == "unavailable"
    monkeypatch.setattr(yara.importlib.util, "find_spec", lambda name: object())

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("synthetic-worker", 1)

    monkeypatch.setattr(yara.subprocess, "run", timeout)
    assert yara.validate(MARKER)["status"] == "timeout"
    monkeypatch.setattr(
        yara.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            [],
            0,
            '{"status":"completed","matches":[{"namespace":"foreign","rule":"x"}]}',
            "",
        ),
    )
    assert yara.validate(MARKER)["status"] == "failed"
    assert yara._gate.acquire(False)
    try:
        with pytest.raises(CapacityError):
            yara.validate(MARKER)
    finally:
        yara._gate.release()


def test_automatic_requested_process_only_and_idempotent(client):
    store = client.app.state.store
    approved(client)
    collection(client, process=False)
    artifact = collection(client, process=True)
    assert yara.run_due(store) == 1
    assert yara.run_due(store) == 0
    assert yara.list_runs(store, actor())["items"][0]["artifact_id"] == artifact


@pytest.mark.parametrize("failure", ["failed", "timeout", "unavailable"])
def test_automatic_inspection_failure_is_not_a_completed_scan(
    client, monkeypatch, failure
):
    store = client.app.state.store
    artifact = collection(client, process=True)
    monkeypatch.setattr(
        yara,
        "_worker",
        lambda *args, **kwargs: {
            "status": failure,
            "matches": [],
            "error": "Synthetic unavailable/failed engine",
        },
    )
    assert yara.run_due(store) == 0
    with store.control() as db:
        row = db.execute(
            "SELECT * FROM yara_auto_jobs WHERE artifact_id=?", (artifact,)
        ).fetchone()
        assert row["state"] == failure and row["result_id"] and row["error"]
        run = yara.get_run(store, actor(), row["result_id"])
        assert (
            run["status"] == failure
            and run["verdict"] == "unknown"
            and run["signal_id"] is None
        )


def test_automatic_oversized_selection_is_terminal_with_an_explicit_reason(
    client, monkeypatch
):
    store = client.app.state.store
    artifact = collection(client, process=True)

    def oversized(*args, **kwargs):
        raise yara._SourceBudgetError("Choose fewer YARA rule files")

    monkeypatch.setattr(yara, "scan_artifact", oversized)
    assert yara.run_due(store) == 0
    with store.control() as db:
        row = db.execute(
            "SELECT state,error FROM yara_auto_jobs WHERE artifact_id=?", (artifact,)
        ).fetchone()
        assert row["state"] == "excluded" and "Choose fewer" in row["error"]
    assert yara.run_due(store) == 0


def test_http_builder_crud_validation_roles_and_catalog(client):
    response = client.get("/api/yara/status")
    assert response.status_code == 200 and response.json()["runtime_available"]
    assert not response.json()["sample_execution"]
    rows = client.get("/api/yara/rules", params={"origin": "builtin", "limit": 2})
    assert rows.status_code == 200 and rows.json()["total"] > 0
    assert "source" not in rows.json()["items"][0]
    saved = client.post("/api/yara/rules", json=custom())
    assert saved.status_code == 201, saved.text
    identifier = saved.json()["id"]
    assert (
        client.post(
            "/api/yara/validate", json={"source": "rule invalid { condition: }"}
        ).json()["status"]
        == "failed"
    )
    assert (
        client.put(
            "/api/yara/rules/" + identifier, json=custom(expected_revision=0)
        ).status_code
        == 400
    )
    login(client, "reader")
    assert client.get("/api/yara/rules/" + identifier).status_code == 200
    assert client.post("/api/yara/rules", json=custom()).status_code == 403
    assert client.post("/api/yara/validate", json={"source": MARKER}).status_code == 403
    login(client, "foreign")
    assert client.get("/api/yara/rules/" + identifier).status_code == 404


def test_builtin_override_delete_restore_is_tenant_local(client):
    store = client.app.state.store
    builtin = yara.list_rules(store, actor(), origin="builtin", limit=1)["items"][0]
    original = yara.get_rule(store, actor(), builtin["id"])
    deleted = yara.delete_rule(store, actor(), builtin["id"], 1, "Tenant opt out")
    assert deleted["revision"] == 2 and deleted["state"] == "deleted"
    other = yara.get_rule(store, {**actor("foreign"), "tenant": "b"}, builtin["id"])
    assert other["effective_state"] == "active"
    restored = yara.restore_rule(store, actor(), builtin["id"], 2)
    assert restored["effective_state"] == "active" and restored["revision"] == 3
    assert restored["sha256"] == original["sha256"]
