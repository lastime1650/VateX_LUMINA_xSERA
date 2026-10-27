"""Optional S3 Object Lock publisher for already-encrypted format-2 bundles.

No credential, passphrase, bucket configuration, deletion, or retention bypass
API is provided. boto3>=1.40,<2 is an optional operator-installed dependency;
its normal server-side credential provider chain is used. Local fake-client
tests do not qualify a standard AWS deployment. The local log store is not
made immutable by publishing a remotely retained backup.

Official contracts: AWS API PutObject, HeadObject, GetBucketVersioning,
GetObjectLockConfiguration and the S3 Object Lock user guide.
"""

import base64
import hashlib
import ipaddress
import os
import re
import shutil
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from . import backup_stream as bundle

CONFIG_KEYS = {"bucket", "prefix", "region", "endpoint", "mode", "retention_days", "expected_bucket_owner"}
QUALIFICATION = "standard_aws_deployment_not_qualified"
RECEIPT_KEYS = {"member", "key", "version_id", "sha256", "size", "mode", "retain_until"}
MAX_RECEIPT_LINE = 4096
MAX_INVENTORY_BYTES = (bundle.MAX_CHUNKS + 2) * MAX_RECEIPT_LINE
MAX_FETCH_BYTES = bundle.MAX_CHUNKS * (bundle.CHUNK_BYTES + 16) + bundle.MAX_MANIFEST_BYTES + 4112


class ArchivePublishError(RuntimeError):
    """Publication failed; report identifies partial/uncertain retained objects."""

    def __init__(self, message, report):
        super().__init__(message)
        self.report = dict(report)


class ArchiveFetchError(RuntimeError):
    """Remote encrypted bundle was not published to the destination."""

    def __init__(self, message, report):
        super().__init__(message)
        self.report = dict(report)


def validate_config(config, *, injected_client=False):
    if not isinstance(config, dict) or set(config) != CONFIG_KEYS:
        raise ValueError("Archive config requires exactly bucket,prefix,region,endpoint,mode,retention_days,expected_bucket_owner; credentials are forbidden")
    result = dict(config)
    bucket = result["bucket"]
    if (not isinstance(bucket, str) or not 3 <= len(bucket) <= 63
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", bucket)
            or ".." in bucket or ".-" in bucket or "-." in bucket
            or bucket.endswith(("--x-s3", "-s3alias", "--ol-s3", ".mrap", "--table-s3"))
            or bucket.startswith(("xn--", "sthree-", "amzn-s3-demo-"))):
        raise ValueError("Archive requires a general-purpose S3 bucket name")
    try:
        ipaddress.ip_address(bucket)
    except ValueError:
        pass
    else:
        raise ValueError("Bucket name cannot be an IP address")
    prefix = result["prefix"]
    if (not isinstance(prefix, str) or not 1 <= len(prefix) <= 512
            or any(not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}", part)
                   or part in {".", ".."} for part in prefix.split("/"))):
        raise ValueError("Archive prefix must contain bounded safe path components")
    if not isinstance(result["region"], str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", result["region"]):
        raise ValueError("Explicit AWS region is required")
    endpoint = result["endpoint"]
    if endpoint is not None:
        if not isinstance(endpoint, str) or len(endpoint) > 2048 or re.search(r"[\s\\\x00-\x1f]", endpoint):
            raise ValueError("Invalid archive endpoint")
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError:
            raise ValueError("Invalid archive endpoint") from None
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/") or port == 0):
            raise ValueError("Endpoint must be an origin without credentials, path, query or fragment")
        local_test = injected_client and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not local_test:
            raise ValueError("HTTPS is mandatory; HTTP loopback is only allowed with an injected test client")
    if result["mode"] not in ("COMPLIANCE", "GOVERNANCE"):
        raise ValueError("Object Lock mode must be COMPLIANCE or GOVERNANCE")
    if type(result["retention_days"]) is not int or not 1 <= result["retention_days"] <= 36500:
        raise ValueError("Archive retention_days must be 1..36500")
    if not isinstance(result["expected_bucket_owner"], str) or not re.fullmatch(r"\d{12}", result["expected_bucket_owner"]):
        raise ValueError("Expected bucket owner must be a 12-digit AWS account ID")
    return result


def _client(config):
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        raise RuntimeError("Optional S3 publishing requires boto3>=1.40,<2; no AWS publication has been attempted") from None
    try:
        value = boto3.session.Session().client(
            "s3", region_name=config["region"], endpoint_url=config["endpoint"],
            use_ssl=True, verify=True,
            config=Config(connect_timeout=5, read_timeout=60, retries={"total_max_attempts": 3, "mode": "standard"}),
        )
    except Exception:  # noqa: BLE001 - Sanitize all external credential-provider/SDK exception details.
        raise RuntimeError("Cannot initialize the optional server-side AWS credential provider/client") from None
    # An AWS_ENDPOINT_URL environment override must not silently disable TLS.
    if urlsplit(value.meta.endpoint_url).scheme != "https":
        raise ValueError("Effective SDK archive endpoint must use HTTPS")
    return value


def _inspect(source):
    source = bundle._root(source)
    names = set()
    for path in source.iterdir():
        names.add(path.name)
        if len(names) > 3:
            raise ValueError("Unexpected encrypted bundle member")
    if names != {"header.json", "manifest.enc", "chunks"}:
        raise ValueError("Encrypted bundle must contain only header.json,manifest.enc,chunks")
    header_bytes = bundle._read(source / "header.json", 4096)
    header = bundle._load(header_bytes)
    bundle._header(header)
    manifest = bundle._regular(source / "manifest.enc")
    if not 16 <= manifest.st_size <= bundle.MAX_MANIFEST_BYTES + 16:
        raise ValueError("Encrypted manifest size is invalid")
    chunks = bundle._root(source / "chunks")
    count, maximum = 0, -1
    for path in chunks.iterdir():
        if not re.fullmatch(r"[a-f0-9]{8}\.bin", path.name):
            raise ValueError("Unexpected encrypted chunk path")
        number = int(path.stem, 16)
        metadata = bundle._regular(path)
        if number >= bundle.MAX_CHUNKS or not 16 <= metadata.st_size <= header["chunk_bytes"] + 16:
            raise ValueError("Encrypted chunk exceeds format-2 bounds")
        count += 1
        maximum = max(maximum, number)
        if count > bundle.MAX_CHUNKS:
            raise ValueError("Encrypted bundle has too many chunks")
    if maximum + 1 != count:
        raise ValueError("Encrypted chunk sequence must be contiguous from zero")
    return source, header, header_bytes, count


def _digest(stream, maximum=None):
    digest, size = hashlib.sha256(), 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        if maximum is not None and size > maximum:
            raise ValueError("Bundle member grew beyond its format-2 size bound")
        digest.update(block)
    stream.seek(0)
    return digest.hexdigest(), size


def _remote(operation, **kwargs):
    try:
        return operation(**kwargs)
    except Exception:  # noqa: BLE001 - External SDK/endpoint failures must not expose request or credential details.
        # SDK/provider/custom endpoint error messages are not safe diagnostics.
        raise RuntimeError("Remote S3 operation failed") from None


def _confirm(client, common, key, version, sha256, size, mode, until):
    if not isinstance(version, str) or not 1 <= len(version) <= 1024 or version == "null":
        raise ValueError("Object version ID was not returned")
    head = _remote(client.head_object, **common, Key=key, VersionId=version, ChecksumMode="ENABLED")
    actual_until = head.get("ObjectLockRetainUntilDate")
    expected_checksum = base64.b64encode(bytes.fromhex(sha256)).decode("ascii")
    if (head.get("VersionId") != version or head.get("DeleteMarker", False)
            or head.get("ContentLength") != size
            or head.get("ChecksumSHA256") != expected_checksum
            or head.get("ObjectLockMode") != mode
            or not isinstance(actual_until, datetime) or actual_until.tzinfo is None
            or actual_until < until or head.get("ServerSideEncryption") != "AES256"):
        raise ValueError("Remote version, checksum, length, encryption or Object Lock readback did not match")
    return {"key": key, "version_id": version, "sha256": sha256, "size": size,
            "mode": mode, "retain_until": actual_until.astimezone(UTC).isoformat()}


def publish_bundle(bundle_dir, config, *, client=None):
    """Stream a format-2 bundle to a fresh, version-pinned Object Lock prefix.

    Success requires HEAD verification of every object and the last commit
    marker. The bounded metadata journal pins all chunk version IDs. No cleanup
    is attempted after failure: locked partial objects may remain billable.
    This function has no passphrase and cannot re-authenticate existing AEAD
    ciphertext; a separate restore test establishes plaintext recoverability.
    """
    config = validate_config(config, injected_client=client is not None)
    source, header, header_bytes, chunks = _inspect(bundle_dir)
    client = _client(config) if client is None else client
    publish_id = uuid.uuid4().hex
    prefix = config["prefix"] + "/" + publish_id
    until = (datetime.now(UTC) + timedelta(days=config["retention_days"])).replace(microsecond=0)
    common = {"Bucket": config["bucket"], "ExpectedBucketOwner": config["expected_bucket_owner"]}
    report = {"state": "preflight", "bucket": config["bucket"], "prefix": prefix,
              "publish_id": publish_id, "bundle_id": header["bundle_id"], "attempted_objects": 0,
              "confirmed_objects": 0, "uncertain_key": None, "commit_state": "not_attempted",
              "mode": config["mode"], "retain_until": until.isoformat(),
              "qualification": QUALIFICATION, "restoration_verified": False,
              "local_data_immutable": False}

    def put(stream, member, sha256, size):
        key = prefix + "/" + member
        report["attempted_objects"] += 1
        report["uncertain_key"] = key
        checksum = base64.b64encode(bytes.fromhex(sha256)).decode("ascii")
        response = _remote(client.put_object,
            **common, Key=key, Body=stream, ContentLength=size, IfNoneMatch="*",
            ChecksumAlgorithm="SHA256", ChecksumSHA256=checksum,
            ObjectLockMode=config["mode"], ObjectLockRetainUntilDate=until,
            ServerSideEncryption="AES256", ContentType="application/octet-stream",
        )
        receipt = _confirm(client, common, key, response.get("VersionId"), sha256, size, config["mode"], until)
        report["confirmed_objects"] += 1
        report["uncertain_key"] = None
        return {"member": member, **receipt}

    def file_put(path, member):
        before = bundle._regular(path)
        maximum = (4096 if member == "header.json" else bundle.MAX_MANIFEST_BYTES + 16
                   if member == "manifest.enc" else header["chunk_bytes"] + 16)
        if before.st_size > maximum:
            raise ValueError("Bundle member grew beyond its format-2 size bound")
        with path.open("rb") as stream:
            if bundle._identity(os.fstat(stream.fileno())) != bundle._identity(before):
                raise ValueError("Bundle member changed before streaming")
            digest, size = _digest(stream, maximum)
            if bundle._identity(os.fstat(stream.fileno())) != bundle._identity(before):
                raise ValueError("Bundle member changed while hashing")
            if member == "header.json" and digest != hashlib.sha256(header_bytes).hexdigest():
                raise ValueError("Bundle header changed after validation")
            receipt = put(stream, member, digest, size)
            if (bundle._identity(os.fstat(stream.fileno())) != bundle._identity(before)
                    or bundle._identity(bundle._regular(path)) != bundle._identity(before)):
                raise ValueError("Bundle member changed while streaming")
        return receipt

    try:
        if _remote(client.get_bucket_versioning, **common).get("Status") != "Enabled":
            raise ValueError("Remote bucket versioning must be Enabled")
        lock = _remote(client.get_object_lock_configuration, **common).get("ObjectLockConfiguration", {})
        if lock.get("ObjectLockEnabled") != "Enabled":
            raise ValueError("Remote bucket Object Lock must be Enabled")
        report["state"] = "publishing"
        with tempfile.TemporaryFile(mode="w+b") as journal:
            for member in ("header.json", "manifest.enc"):
                receipt = file_put(source / member, member)
                journal.write(bundle._json(receipt) + b"\n")
            for number in range(chunks):
                member = f"chunks/{number:08x}.bin"
                receipt = file_put(source / member, member)
                journal.write(bundle._json(receipt) + b"\n")
            journal.flush()
            journal.seek(0)
            digest, size = _digest(journal)
            inventory = put(journal, "members.ndjson", digest, size)
        marker = bundle._json({"schema": 1, "format": 2, "bundle_id": header["bundle_id"],
                              "publish_id": publish_id, "chunks": chunks, "members": chunks + 2,
                              "inventory": inventory, "mode": config["mode"], "retain_until": until.isoformat(),
                              "ciphertext_authentication": "requires_separate_passphrase_restore_test"})
        with tempfile.TemporaryFile(mode="w+b") as stream:
            stream.write(marker)
            stream.seek(0)
            report["commit_state"] = "attempted_unconfirmed"
            commit = put(stream, "commit.json", hashlib.sha256(marker).hexdigest(), len(marker))
        report.update(state="committed", commit_state="verified", commit=commit, inventory=inventory,
                      chunks=chunks, encrypted_bundle=True,
                      governance_bypass_possible=config["mode"] == "GOVERNANCE")
        return report
    except Exception as exc:  # noqa: BLE001 - Preserve sanitized partial-publication state for every failure.
        report["state"] = "partial" if report["attempted_objects"] else "preflight_failed"
        # Do not include remote exception strings, which can contain request or
        # endpoint details. The report deliberately contains no credentials.
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        raise ArchivePublishError("Archive publication failed: " + reason, report) from None


def _retention_date(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid archive retention date")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("Invalid archive retention date") from None
    if result.tzinfo is None:
        raise ValueError("Archive retention date must include a timezone")
    return result.astimezone(UTC)


def _receipt(value, prefix, member, maximum, mode, until):
    if not isinstance(value, dict) or set(value) != RECEIPT_KEYS:
        raise ValueError("Invalid archive member receipt")
    if (value["member"] != member or value["key"] != prefix + "/" + member
            or not isinstance(value["version_id"], str) or not 1 <= len(value["version_id"]) <= 1024
            or value["version_id"] == "null"
            or not isinstance(value["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["sha256"])
            or type(value["size"]) is not int or not 1 <= value["size"] <= maximum
            or value["mode"] != mode or _retention_date(value["retain_until"]) < until):
        raise ValueError("Archive member key, version, checksum, size or retention is invalid")
    return value


def _download(client, common, receipt, destination, mode, until):
    _confirm(client, common, receipt["key"], receipt["version_id"], receipt["sha256"], receipt["size"], mode, until)
    if shutil.disk_usage(destination.parent).free < receipt["size"] + 16 * 1024 * 1024:
        raise ValueError("Insufficient private staging disk space")
    response = _remote(client.get_object, **common, Key=receipt["key"], VersionId=receipt["version_id"], ChecksumMode="ENABLED")
    body = response.get("Body")
    try:
        expected = base64.b64encode(bytes.fromhex(receipt["sha256"])).decode("ascii")
        if (body is None or response.get("VersionId") != receipt["version_id"]
                or response.get("ContentLength") != receipt["size"]
                or response.get("ChecksumSHA256") != expected or response.get("DeleteMarker", False)):
            raise ValueError("Remote GET version, size or checksum did not match the pinned receipt")
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        actual, total = hashlib.sha256(), 0
        with os.fdopen(descriptor, "wb") as output:
            while block := _remote(lambda: body.read(1024 * 1024)):
                if not isinstance(block, bytes):
                    raise ValueError("Archive GET must return a byte stream")  # noqa: TRY004 - Invalid archive stream data is a validation failure; preserve the ValueError contract.
                total += len(block)
                if total > receipt["size"]:
                    raise ValueError("Remote object exceeds its pinned size")
                actual.update(block)
                output.write(block)
            if total != receipt["size"] or actual.hexdigest() != receipt["sha256"]:
                raise ValueError("Downloaded object SHA256 or size did not match")
            output.flush()
            os.fsync(output.fileno())
        return total
    finally:
        if body is not None:
            _remote(body.close)


def fetch_bundle(config, commit_key, destination_new_dir, *, client=None, commit_version=None):
    """Fetch a locked version-pinned encrypted bundle without decrypting it.

    Supply the publication receipt's commit_version to pin the entry point.
    Without it, only the currently observed commit version is pinned: Object
    Lock protects existing versions but does not prevent new object versions.
    Passphrase-authenticated restore_bundle is a separate required operation.
    """
    config = validate_config(config, injected_client=client is not None)
    pattern = re.escape(config["prefix"]) + r"/([a-f0-9]{32})/commit\.json"
    match = re.fullmatch(pattern, commit_key) if isinstance(commit_key, str) else None
    if not match:
        raise ValueError("Commit key must be config.prefix/<32hex UUID>/commit.json")
    if commit_version is not None and (not isinstance(commit_version, str)
            or not 1 <= len(commit_version) <= 1024 or commit_version == "null"
            or any(ord(char) < 32 or ord(char) > 126 for char in commit_version)):
        raise ValueError("Invalid pinned commit version")
    destination = bundle._root(destination_new_dir, new=True)
    client = _client(config) if client is None else client
    common = {"Bucket": config["bucket"], "ExpectedBucketOwner": config["expected_bucket_owner"]}
    prefix = commit_key.rsplit("/", 1)[0]
    report = {"state": "fetching", "bucket": config["bucket"], "commit_key": commit_key,
              "commit_version": commit_version, "entrypoint_pinned_by_caller": commit_version is not None,
              "downloaded_objects": 0, "bytes": 0, "qualification": QUALIFICATION,
              "restoration_verified": False, "passphrase_restore_required": True,
              "local_data_immutable": False}
    try:
        if _remote(client.get_bucket_versioning, **common).get("Status") != "Enabled":
            raise ValueError("Remote bucket versioning must be Enabled")
        if _remote(client.get_object_lock_configuration, **common).get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise ValueError("Remote bucket Object Lock must be Enabled")
        params = {"VersionId": commit_version} if commit_version is not None else {}
        head = _remote(client.head_object, **common, Key=commit_key, ChecksumMode="ENABLED", **params)
        try:
            digest = base64.b64decode(head.get("ChecksumSHA256", ""), validate=True)
        except (ValueError, TypeError):
            raise ValueError("Commit SHA256 is missing or invalid") from None
        until = head.get("ObjectLockRetainUntilDate")
        if (len(digest) != 32 or not isinstance(until, datetime) or until.tzinfo is None
                or until <= datetime.now(UTC) or head.get("ObjectLockMode") != config["mode"]
                or type(head.get("ContentLength")) is not int or not 1 <= head["ContentLength"] <= 65536
                or (commit_version is not None and head.get("VersionId") != commit_version)):
            raise ValueError("Commit is not an active bounded locked object version")
        receipt = {"key": commit_key, "version_id": head.get("VersionId"), "sha256": digest.hex(), "size": head["ContentLength"]}
        report["commit_version"] = receipt["version_id"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        bundle._no_links(destination.parent)
        with tempfile.TemporaryDirectory(prefix=".archive-fetch-", dir=destination.parent) as directory:
            temporary = Path(directory)
            bundle._private_directory(temporary, created=True)
            commit_path = temporary / "commit.json"
            report["bytes"] += _download(client, common, receipt, commit_path, config["mode"], until)
            report["downloaded_objects"] += 1
            marker = bundle._load(bundle._read(commit_path, 65536))
            fields = {"schema", "format", "bundle_id", "publish_id", "chunks", "members", "inventory", "mode", "retain_until", "ciphertext_authentication"}
            if (not isinstance(marker, dict) or set(marker) != fields
                    or type(marker["schema"]) is not int or marker["schema"] != 1
                    or type(marker["format"]) is not int or marker["format"] != 2
                    or marker["publish_id"] != match.group(1)
                    or not isinstance(marker["bundle_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", marker["bundle_id"])
                    or type(marker["chunks"]) is not int or not 0 <= marker["chunks"] <= bundle.MAX_CHUNKS
                    or type(marker["members"]) is not int or marker["members"] != marker["chunks"] + 2
                    or marker["mode"] != config["mode"]
                    or marker["ciphertext_authentication"] != "requires_separate_passphrase_restore_test"):
                raise ValueError("Invalid archive commit manifest shape or publication identity")
            required_until = _retention_date(marker["retain_until"])
            if required_until > until or required_until <= datetime.now(UTC):
                raise ValueError("Commit retention does not match its locked version")
            inventory = _receipt(marker["inventory"], prefix, "members.ndjson", MAX_INVENTORY_BYTES, config["mode"], required_until)
            inventory_path = temporary / "members.ndjson"
            report["bytes"] += _download(client, common, inventory, inventory_path, config["mode"], required_until)
            report["downloaded_objects"] += 1
            encrypted = temporary / "bundle"
            encrypted.mkdir(mode=0o700)
            bundle._private_directory(encrypted, created=True)
            (encrypted / "chunks").mkdir(mode=0o700)
            bundle._private_directory(encrypted / "chunks", created=True)
            count, encrypted_bytes = 0, 0
            with inventory_path.open("rb") as journal:
                while line := journal.readline(MAX_RECEIPT_LINE + 1):
                    if len(line) > MAX_RECEIPT_LINE or not line.endswith(b"\n") or count >= marker["members"]:
                        raise ValueError("Archive receipt journal exceeds its line or member budget")
                    member = "header.json" if count == 0 else "manifest.enc" if count == 1 else f"chunks/{count-2:08x}.bin"
                    maximum = 4096 if count == 0 else bundle.MAX_MANIFEST_BYTES + 16 if count == 1 else bundle.CHUNK_BYTES + 16
                    item = _receipt(bundle._load(line), prefix, member, maximum, config["mode"], required_until)
                    encrypted_bytes += item["size"]
                    if encrypted_bytes > MAX_FETCH_BYTES:
                        raise ValueError("Archive bundle exceeds the total format-2 byte budget")
                    report["bytes"] += _download(client, common, item, encrypted / member, config["mode"], required_until)
                    report["downloaded_objects"] += 1
                    count += 1
            if count != marker["members"]:
                raise ValueError("Archive receipt journal is incomplete")
            _, header, _, actual_chunks = _inspect(encrypted)
            if header["bundle_id"] != marker["bundle_id"] or actual_chunks != marker["chunks"]:
                raise ValueError("Downloaded encrypted bundle identity or chunk count does not match")
            bundle._sync_directory(encrypted / "chunks")
            bundle._sync_directory(encrypted)
            bundle._publish(encrypted, destination)
        report.update(state="fetched", fetched=True, encrypted_bundle=True, format=2,
                      bundle_id=marker["bundle_id"], destination=str(destination), chunks=actual_chunks,
                      governance_bypass_possible=config["mode"] == "GOVERNANCE")
        return report
    except Exception as exc:  # noqa: BLE001 - Every download/SDK failure must return sanitized state after staging cleanup.
        report["state"] = "failed_no_destination_published"
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        raise ArchiveFetchError("Archive fetch failed: " + reason, report) from None
