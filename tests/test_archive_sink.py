import base64
import hashlib
import io
import json
import os
import time
import uuid
from datetime import timedelta

import pytest

from sapientia import archive_sink, backup_stream
from sapientia.archive_sink import (
    ArchiveFetchError,
    ArchivePublishError,
    fetch_bundle,
    publish_bundle,
)


@pytest.fixture
def encrypted(tmp_path):
    source = tmp_path / "snapshot"
    source.mkdir()
    hashes = {}
    for name, value in [("control.sqlite3", b"private source content" * 100), ("events.duckdb", b"private events" * 100)]:
        (source / name).write_bytes(value)
        hashes[name] = hashlib.sha256(value).hexdigest()
    (source / "manifest.json").write_text(json.dumps({"schema": 2, "sha256": hashes}), encoding="utf-8")
    destination = tmp_path / "encrypted"
    metadata = backup_stream.encrypt_snapshot(source, destination, "test-only-archive-passphrase", chunk_size=1024)
    return destination, metadata


@pytest.fixture
def config():
    return {"bucket": "organization-archives", "prefix": "lumina/backups", "region": "ap-northeast-2",
            "endpoint": None, "mode": "COMPLIANCE", "retention_days": 90,
            "expected_bucket_owner": "123456789012"}


class FakeS3:
    def __init__(self, *, versioning="Enabled", locking="Enabled", mismatch=None, fail_at=None, lost_ack=False, mutate=None):
        self.versioning, self.locking = versioning, locking
        self.mismatch, self.fail_at, self.lost_ack = mismatch, fail_at, lost_ack
        self.mutate = mutate
        self.objects, self.calls = {}, []

    def get_bucket_versioning(self, **kwargs):
        self.calls.append(("versioning", kwargs))
        return {"Status": self.versioning}

    def get_object_lock_configuration(self, **kwargs):
        self.calls.append(("locking", kwargs))
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": self.locking}}

    def put_object(self, **kwargs):
        self.calls.append(("put", {key: value for key, value in kwargs.items() if key != "Body"}))
        assert kwargs["IfNoneMatch"] == "*"
        assert "BypassGovernanceRetention" not in kwargs
        key = kwargs["Key"]
        if key in self.objects:
            raise RuntimeError("precondition failed")
        if self.fail_at and key.endswith(self.fail_at) and not self.lost_ack:
            raise RuntimeError("injected network failure")
        if self.mutate:
            self.mutate(key)
        # Real Body is a seekable file stream, never a whole-bundle byte string.
        assert hasattr(kwargs["Body"], "read") and not isinstance(kwargs["Body"], bytes)
        blocks = []
        while block := kwargs["Body"].read(512):
            blocks.append(block)
        data = b"".join(blocks)
        version = uuid.uuid4().hex
        self.objects[key] = {"data": data, "version": version, "request": kwargs}
        if self.fail_at and key.endswith(self.fail_at) and self.lost_ack:
            raise RuntimeError("lost acknowledgement")
        return {"VersionId": version}

    def head_object(self, **kwargs):
        self.calls.append(("head", kwargs))
        value = self.objects[kwargs["Key"]]
        assert kwargs.get("VersionId", value["version"]) == value["version"]
        assert kwargs["ChecksumMode"] == "ENABLED"
        request = value["request"]
        head = {"VersionId": value["version"], "ContentLength": len(value["data"]),
                "ChecksumSHA256": base64.b64encode(hashlib.sha256(value["data"]).digest()).decode(),
                "ObjectLockMode": request["ObjectLockMode"],
                "ObjectLockRetainUntilDate": request["ObjectLockRetainUntilDate"],
                "ServerSideEncryption": request["ServerSideEncryption"]}
        if self.mismatch:
            self.mismatch(head, kwargs["Key"])
        return head

    def get_object(self, **kwargs):
        self.calls.append(("get", kwargs))
        value = self.objects[kwargs["Key"]]
        assert kwargs["VersionId"] == value["version"]
        assert kwargs["ChecksumMode"] == "ENABLED"
        return {"Body": io.BytesIO(value["data"]), "VersionId": value["version"],
                "ContentLength": len(value["data"]),
                "ChecksumSHA256": base64.b64encode(hashlib.sha256(value["data"]).digest()).decode()}


def test_all_objects_version_pinned_locked_and_commit_last(encrypted, config):
    directory, metadata = encrypted
    client = FakeS3()
    result = publish_bundle(directory, config, client=client)
    assert result["state"] == "committed" and result["commit_state"] == "verified"
    assert result["confirmed_objects"] == result["attempted_objects"] == metadata["chunks"] + 4
    assert result["chunks"] == metadata["chunks"]
    assert result["restoration_verified"] is False and result["local_data_immutable"] is False
    assert result["qualification"] == "standard_aws_deployment_not_qualified"
    assert list(client.objects)[-1] == result["commit"]["key"]
    marker = json.loads(client.objects[result["commit"]["key"]]["data"])
    assert marker["inventory"] == result["inventory"]
    rows = [json.loads(line) for line in client.objects[result["inventory"]["key"]]["data"].splitlines()]
    assert len(rows) == metadata["chunks"] + 2
    for row in rows:
        remote = client.objects[row["key"]]
        assert row["version_id"] == remote["version"]
        assert row["sha256"] == hashlib.sha256(remote["data"]).hexdigest()
        assert b"private source content" not in remote["data"]
        assert b"private events" not in remote["data"]
    for method, request in client.calls:
        assert request["ExpectedBucketOwner"] == config["expected_bucket_owner"]
        assert request["Bucket"] == config["bucket"]
        if method == "put":
            assert request["ChecksumAlgorithm"] == "SHA256"
            assert request["ObjectLockMode"] == "COMPLIANCE"


def test_retry_uses_new_uuid_namespace_without_overwriting(encrypted, config):
    client = FakeS3()
    first = publish_bundle(encrypted[0], config, client=client)
    second = publish_bundle(encrypted[0], config, client=client)
    assert first["prefix"] != second["prefix"]
    assert first["bundle_id"] == second["bundle_id"]
    assert len(client.objects) == first["confirmed_objects"] * 2


@pytest.mark.parametrize("field,value", [
    ("bucket", "../escape"), ("bucket", "127.0.0.1"), ("bucket", "directory--x-s3"),
    ("prefix", "../escape"), ("prefix", "good//bad"), ("prefix", "a\\b"),
    ("region", ""), ("retention_days", True), ("retention_days", 0), ("mode", "BYPASS"),
    ("expected_bucket_owner", "unknown"), ("endpoint", "http://remote.example"),
    ("endpoint", "https://user:secret@example.com"), ("endpoint", "https://example.com/path"),
    ("endpoint", "https://example.com?secret=bad"), ("endpoint", "https://exam\nple.com"),
])
def test_configuration_is_exact_and_fails_before_remote_calls(encrypted, config, field, value):
    client = FakeS3()
    config[field] = value
    with pytest.raises(ValueError):
        publish_bundle(encrypted[0], config, client=client)
    assert not client.calls


def test_credentials_and_production_http_configuration_are_rejected(config):
    with pytest.raises(ValueError, match="credentials"):
        archive_sink.validate_config({**config, "aws_secret_access_key": "forbidden"})
    config["endpoint"] = "http://localhost:9000"
    with pytest.raises(ValueError, match="HTTPS"):
        archive_sink.validate_config(config)
    assert archive_sink.validate_config(config, injected_client=True)["endpoint"] == config["endpoint"]


@pytest.mark.parametrize("field,value", [("versioning", "Suspended"), ("locking", "Disabled")])
def test_bucket_prerequisites_required_before_any_upload(encrypted, config, field, value):
    client = FakeS3(**{field: value})
    with pytest.raises(ArchivePublishError) as failed:
        publish_bundle(encrypted[0], config, client=client)
    assert failed.value.report["state"] == "preflight_failed"
    assert failed.value.report["attempted_objects"] == 0
    assert not client.objects


@pytest.mark.parametrize("field,value", [
    ("VersionId", "another-version"), ("ChecksumSHA256", "wrong-checksum"),
    ("ContentLength", 1), ("ObjectLockMode", "GOVERNANCE"),
    ("ServerSideEncryption", "aws:kms"), ("DeleteMarker", True),
    ("ObjectLockRetainUntilDate", None),
])
def test_readback_mismatch_never_reports_commit_success(encrypted, config, field, value):
    client = FakeS3(mismatch=lambda head, key: head.update({field: value}))
    with pytest.raises(ArchivePublishError) as failed:
        publish_bundle(encrypted[0], config, client=client)
    report = failed.value.report
    assert report["state"] == "partial" and report["confirmed_objects"] == 0
    assert report["uncertain_key"].endswith("header.json")
    assert report["commit_state"] == "not_attempted"
    assert not any(key.endswith("commit.json") for key in client.objects)


def test_shorter_retention_is_rejected(encrypted, config):
    client = FakeS3(mismatch=lambda head, key: head.update(ObjectLockRetainUntilDate=head["ObjectLockRetainUntilDate"]-timedelta(seconds=1)))
    with pytest.raises(ArchivePublishError, match="readback"):
        publish_bundle(encrypted[0], config, client=client)


@pytest.mark.parametrize("member,lost_ack", [("chunks/00000000.bin", False), ("commit.json", True)])
def test_partial_and_uncertain_commit_are_explicit_without_deletion(encrypted, config, member, lost_ack):
    client = FakeS3(fail_at=member, lost_ack=lost_ack)
    with pytest.raises(ArchivePublishError) as failed:
        publish_bundle(encrypted[0], config, client=client)
    report = failed.value.report
    assert report["state"] == "partial" and report["uncertain_key"].endswith(member)
    assert report["attempted_objects"] == report["confirmed_objects"] + 1
    assert report["commit_state"] == ("attempted_unconfirmed" if lost_ack else "not_attempted")
    assert client.objects and all(method != "delete" for method, _ in client.calls)
    if lost_ack:
        assert any(key.endswith("commit.json") for key in client.objects)


@pytest.mark.parametrize("invalid", ["extra", "hole", "oversized", "bad_header", "hardlink"])
def test_bad_bundle_paths_structure_and_links_fail_before_network(encrypted, config, invalid):
    directory, _ = encrypted
    if invalid == "extra":
        (directory / "untrusted.txt").write_text("no", encoding="utf-8")
    elif invalid == "hole":
        (directory / "chunks" / "00000000.bin").unlink()
    elif invalid == "oversized":
        (directory / "chunks" / "00000000.bin").write_bytes(b"X" * 1041)
    elif invalid == "bad_header":
        header = json.loads((directory / "header.json").read_text())
        header["schema"] = 1
        (directory / "header.json").write_text(json.dumps(header), encoding="utf-8")
    else:
        os.link(directory / "manifest.enc", directory.parent / "linked-manifest")
    client = FakeS3()
    with pytest.raises(ValueError):
        publish_bundle(directory, config, client=client)
    assert not client.calls


def test_ciphertext_mutation_between_hash_and_transmission_is_not_committed(encrypted, config):
    directory = encrypted[0]
    def mutate(key):
        if key.endswith("chunks/00000000.bin"):
            path = directory / "chunks" / "00000000.bin"
            value = path.read_bytes()
            path.write_bytes(bytes([value[0] ^ 1]) + value[1:])
    client = FakeS3(mutate=mutate)
    with pytest.raises(ArchivePublishError):
        publish_bundle(directory, config, client=client)
    assert not any(key.endswith("commit.json") for key in client.objects)


def test_governance_reports_privileged_bypass_limit(encrypted, config):
    config["mode"] = "GOVERNANCE"
    result = publish_bundle(encrypted[0], config, client=FakeS3())
    assert result["state"] == "committed" and result["governance_bypass_possible"] is True


def test_commit_head_lock_mismatch_leaves_commit_unconfirmed(encrypted, config):
    def mismatch(head, key):
        if key.endswith("commit.json"):
            head["ObjectLockMode"] = "GOVERNANCE"
    client = FakeS3(mismatch=mismatch)
    with pytest.raises(ArchivePublishError) as failed:
        publish_bundle(encrypted[0], config, client=client)
    assert failed.value.report["commit_state"] == "attempted_unconfirmed"
    assert failed.value.report["uncertain_key"].endswith("commit.json")


def test_fetch_pins_every_version_and_preserves_encrypted_bundle(encrypted, config, tmp_path):
    client = FakeS3()
    published = publish_bundle(encrypted[0], config, client=client)
    destination = tmp_path / "fetched"
    result = fetch_bundle(config, published["commit"]["key"], destination, client=client, commit_version=published["commit"]["version_id"])
    assert result["state"] == "fetched" and result["entrypoint_pinned_by_caller"] is True
    assert result["downloaded_objects"] == published["confirmed_objects"]
    assert result["passphrase_restore_required"] and not result["restoration_verified"]
    for path in encrypted[0].rglob("*"):
        if path.is_file():
            assert (destination / path.relative_to(encrypted[0])).read_bytes() == path.read_bytes()
    for method, request in client.calls:
        if method == "get":
            assert request["VersionId"]
            assert request["ExpectedBucketOwner"] == config["expected_bucket_owner"]
    assert not list(tmp_path.glob(".archive-fetch-*"))


def test_fetch_without_explicit_version_reports_current_entrypoint_pin(encrypted, config, tmp_path):
    client = FakeS3()
    published = publish_bundle(encrypted[0], config, client=client)
    result = fetch_bundle(config, published["commit"]["key"], tmp_path / "fetched", client=client)
    assert result["entrypoint_pinned_by_caller"] is False
    assert result["commit_version"] == published["commit"]["version_id"]


@pytest.mark.parametrize("key", ["other/" + "a" * 32 + "/commit.json", "lumina/backups/../commit.json", "lumina/backups/" + "a" * 32 + "/header.json", "lumina/backups/" + "a" * 31 + "/commit.json"])
def test_fetch_rejects_commit_keys_outside_exact_namespace(config, tmp_path, key):
    client = FakeS3()
    with pytest.raises(ValueError):
        fetch_bundle(config, key, tmp_path / "fetched", client=client)
    assert not client.calls and not (tmp_path / "fetched").exists()


def test_fetch_never_overwrites_existing_destination(encrypted, config, tmp_path):
    client = FakeS3()
    published = publish_bundle(encrypted[0], config, client=client)
    destination = tmp_path / "existing"
    destination.mkdir()
    calls = len(client.calls)
    with pytest.raises(ValueError):
        fetch_bundle(config, published["commit"]["key"], destination, client=client)
    assert len(client.calls) == calls and list(destination.iterdir()) == []


@pytest.mark.parametrize("failure", ["truncated", "tampered", "wrong_version", "wrong_checksum", "network"])
def test_download_failure_cleans_private_stage_without_final_directory(encrypted, config, tmp_path, failure):
    client = FakeS3()
    published = publish_bundle(encrypted[0], config, client=client)
    original = client.get_object
    def get(**kwargs):
        response = original(**kwargs)
        if kwargs["Key"].endswith("chunks/00000000.bin"):
            if failure == "network":
                raise RuntimeError("download interrupted")
            if failure == "wrong_version":
                response["VersionId"] = "unrequested-version"
            elif failure == "wrong_checksum":
                response["ChecksumSHA256"] = "wrong-checksum"
            else:
                data = response["Body"].read()
                response["Body"].close()
                response["Body"] = io.BytesIO(data[:-1] if failure == "truncated" else bytes([data[0] ^ 1])+data[1:])
        return response
    client.get_object = get
    destination = tmp_path / "failed"
    with pytest.raises(ArchiveFetchError) as failed:
        fetch_bundle(config, published["commit"]["key"], destination, client=client)
    assert failed.value.report["state"] == "failed_no_destination_published"
    assert not destination.exists() and not list(tmp_path.glob(".archive-fetch-*"))


@pytest.mark.parametrize("failure", ["mode", "expired", "wrong_owner", "wrong_commit_version"])
def test_fetch_requires_owner_exact_version_and_active_lock(encrypted, config, tmp_path, failure):
    client = FakeS3()
    published = publish_bundle(encrypted[0], config, client=client)
    original = client.head_object
    def head(**kwargs):
        if failure == "wrong_owner":
            raise RuntimeError("access denied: expected bucket owner mismatch")
        value = original(**kwargs)
        if failure == "mode":
            value["ObjectLockMode"] = "GOVERNANCE"
        elif failure == "expired":
            value["ObjectLockRetainUntilDate"] -= timedelta(days=91)
        elif failure == "wrong_commit_version":
            value["VersionId"] = "wrong-version"
        return value
    client.head_object = head
    destination = tmp_path / "failed"
    with pytest.raises(ArchiveFetchError):
        fetch_bundle(config, published["commit"]["key"], destination, client=client, commit_version=published["commit"]["version_id"])
    assert not destination.exists()


def rewrite_remote_manifest(client, published, transform_marker=None, transform_rows=None):
    commit = client.objects[published["commit"]["key"]]
    marker = json.loads(commit["data"])
    if transform_rows:
        inventory = client.objects[marker["inventory"]["key"]]
        rows = [json.loads(line) for line in inventory["data"].splitlines()]
        transform_rows(rows)
        inventory["data"] = b"".join(backup_stream._json(row)+b"\n" for row in rows)
        marker["inventory"]["size"] = len(inventory["data"])
        marker["inventory"]["sha256"] = hashlib.sha256(inventory["data"]).hexdigest()
    if transform_marker:
        transform_marker(marker)
    commit["data"] = backup_stream._json(marker)


@pytest.mark.parametrize("field,value", [("format", 1), ("chunks", True), ("members", 1), ("bundle_id", "wrong"), ("publish_id", "a" * 32), ("extra", "invalid")])
def test_fetch_rejects_malformed_commit_even_with_consistent_transport_hash(encrypted, config, tmp_path, field, value):
    client = FakeS3()
    published = publish_bundle(encrypted[0], config, client=client)
    rewrite_remote_manifest(client, published, transform_marker=lambda marker: marker.update({field: value}))
    destination = tmp_path / "failed"
    with pytest.raises(ArchiveFetchError, match="commit manifest"):
        fetch_bundle(config, published["commit"]["key"], destination, client=client)
    assert not destination.exists()


@pytest.mark.parametrize("failure", ["path", "key", "duplicate", "missing", "oversized", "version"])
def test_fetch_member_receipts_cannot_escape_reorder_or_exceed_budgets(encrypted, config, tmp_path, failure):
    client = FakeS3()
    published = publish_bundle(encrypted[0], config, client=client)
    def change(rows):
        if failure == "path":
            rows[0]["member"] = "../escape"
        elif failure == "key":
            rows[0]["key"] = "another-namespace/header.json"
        elif failure == "duplicate":
            rows[1] = rows[0]
        elif failure == "missing":
            rows.pop()
        elif failure == "oversized":
            rows[0]["size"] = 4097
        else:
            rows[0]["version_id"] = "null"
    rewrite_remote_manifest(client, published, transform_rows=change)
    destination = tmp_path / "failed"
    with pytest.raises(ArchiveFetchError):
        fetch_bundle(config, published["commit"]["key"], destination, client=client)
    assert not destination.exists() and not (tmp_path / "escape").exists()


def test_fake_remote_roundtrip_then_passphrase_restore_real_hot_sealed_and_queue(config, tmp_path):
    from sapientia import backup
    from sapientia.storage import Settings, Store

    source = Store(Settings(tmp_path / "source", min_free_bytes=0))
    try:
        source.ingest("a", [{"event_id": "sealed", "message": "archive evidence"}])
        source.flush()
        source.segments.seal(now=time.time()+35*86400)
        source.ingest("a", [{"event_id": "hot"}])
        source.flush()
        source.ingest("a", [{"event_id": "queued"}])
        snapshot = tmp_path / "consistent-snapshot"
        backup.backup_online(source, snapshot)
    finally:
        source.close()
    encrypted, fetched, restored = tmp_path / "encrypted", tmp_path / "fetched", tmp_path / "restored"
    passphrase = "test-only-roundtrip-passphrase"
    backup_stream.encrypt_snapshot(snapshot, encrypted, passphrase)
    client = FakeS3()
    publication = publish_bundle(encrypted, config, client=client)
    fetched_result = fetch_bundle(config, publication["commit"]["key"], fetched, client=client, commit_version=publication["commit"]["version_id"])
    assert fetched_result["restoration_verified"] is False
    backup_stream.restore_bundle(fetched, restored, passphrase)
    clone = Store(Settings(restored, min_free_bytes=0))
    try:
        clone.flush()
        result = clone.search("a", {"query": "* | stats count"})
        assert result["rows"] == [{"count": 3}]
        assert clone.segments.status("a")["tiers"]["archive"]["events"] == 1
        assert clone.segments.verify(deep=True)["valid"] is True
    finally:
        clone.close()


def test_remote_exception_details_are_not_in_safe_failure_report(encrypted, config):
    client = FakeS3()
    def reject(**kwargs):
        raise ValueError("private-provider-detail-must-not-be-logged")
    client.put_object = reject
    with pytest.raises(ArchivePublishError) as failed:
        publish_bundle(encrypted[0], config, client=client)
    assert "private-provider-detail" not in str(failed.value)
    assert "private-provider-detail" not in repr(failed.value.report)
    assert failed.value.report["state"] == "partial"
