"""Signed offline install boundaries without services, native effects or network."""

import base64
import csv
import hashlib
import io
import os
import platform
import shutil
import stat
import sys
import tempfile
import zipfile
from collections import Counter
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from sapientia import backup, release_integrity
from sapientia.locking import ProcessLock
from sapientia.storage import Settings, Store
from tests.signing_support import (
    release_signer,  # noqa: F401 -- Explicit pytest fixture.
)
from tools import deploy_release as deploy


@pytest.fixture(scope="module")
def private_installer_parent():
    """Use an owned drive-root tree: this host's shared Temp is writable by others."""
    if os.name != "nt":
        yield None
        return
    root = Path(tempfile.mkdtemp(prefix="xsera-installer-qa-", dir=Path.cwd().anchor))
    try:
        security = deploy._WindowsAcl()
        for ancestor in root.parents:
            security.check_ancestor(ancestor)
        security.protect(root)
        security.require_private(root, root=True)
        yield root
    finally:
        shutil.rmtree(root)


@pytest.fixture
def tmp_path(tmp_path, private_installer_parent):
    if private_installer_parent is None:
        return tmp_path
    result = private_installer_parent / tmp_path.name
    result.mkdir()
    return result


def set_owned_test_dacl(path, entries):
    """Only called on new synthetic ACL test paths, never existing user data."""
    security = deploy._WindowsAcl()
    c, w = security.c, security.w
    descriptor, dacl = c.c_void_p(), c.c_void_p()
    present, defaulted = w.BOOL(), w.BOOL()
    text = "D:P" + entries
    assert security.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text, 1, c.byref(descriptor), None
    )
    try:
        assert (
            security.api.GetSecurityDescriptorDacl(
                descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted)
            )
            and present
        )
        assert (
            security.api.SetNamedSecurityInfoW(
                str(path), 1, 0x80000004, None, None, dacl, None
            )
            == 0
        )
    finally:
        security.kernel.LocalFree(descriptor)
    return security


def readable_owned_parent(path):
    path.mkdir()
    security = deploy._WindowsAcl()
    return set_owned_test_dacl(
        path,
        f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;OICI;GR;;;BU)",
    )


def site_at(environment):
    return environment / (
        "Lib/site-packages"
        if os.name == "nt"
        else f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    )


@pytest.fixture
def signed_bundle(tmp_path, release_signer):  # noqa: F811 -- Explicit imported fixture.
    bundle, environment = tmp_path / "bundle", tmp_path / "environment"
    (bundle / "wheelhouse").mkdir(parents=True)
    members = {
        "demo/__init__.py": b"VERSION = '1.0'\n",
        "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
        "demo/_vendor/nested-2.0.dist-info/RECORD": b"vendored metadata\n",
    }
    records = io.StringIO()
    writer = csv.writer(records)
    for name, value in members.items():
        encoded = (
            base64.urlsafe_b64encode(hashlib.sha256(value).digest())
            .decode()
            .rstrip("=")
        )
        writer.writerow([name, "sha256=" + encoded, str(len(value))])
        path = deploy.child(site_at(environment), name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    writer.writerow(["demo-1.0.dist-info/RECORD", "", ""])
    with zipfile.ZipFile(
        bundle / "wheelhouse/demo-1.0-py3-none-any.whl", "w"
    ) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
        archive.writestr("demo-1.0.dist-info/RECORD", records.getvalue())
    (site_at(environment) / "demo-1.0.dist-info/RECORD").write_text(
        "pip generated record"
    )
    (bundle / "requirements.txt").write_text("demo==1.0\n")
    files = {
        path.relative_to(bundle).as_posix(): {
            "bytes": path.stat().st_size,
            "sha256": deploy.digest_file(path),
        }
        for path in bundle.rglob("*")
        if path.is_file()
    }
    manifest = release_integrity.sign(
        {
            "schema": deploy.SCHEMA,
            "profile": "cpu-observe",
            "version": "1.0",
            "release_sequence": 20,
            "target": {
                "system": platform.system().lower(),
                "machine": platform.machine().lower(),
                "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            },
            "files": files,
            "wheel": "wheelhouse/demo-1.0-py3-none-any.whl",
            "requirements_lock": "requirements.txt",
        }
    )
    deploy.atomic(bundle / "release-manifest.json", manifest)
    return bundle, release_signer["trust_file"], manifest, environment


@pytest.mark.parametrize("mutation", ["unsigned", "revoked", "member", "extra"])
def test_bundle_verification_refuses_unsigned_revoked_or_replaced_inputs(
    signed_bundle, mutation
):
    bundle, trust, manifest, _ = signed_bundle
    assert deploy.verify_bundle(bundle, trust) == manifest
    if mutation == "unsigned":
        manifest.pop("signature")
        deploy.atomic(bundle / "release-manifest.json", manifest)
    elif mutation == "revoked":
        value = deploy.read_json(trust)
        value["revoked_key_ids"] = [manifest["signature"]["key_id"]]
        deploy.atomic(trust, value)
    elif mutation == "member":
        (bundle / "requirements.txt").write_text("other==1.0\n")
    else:
        (bundle / "unlisted.py").write_text("raise RuntimeError('never execute')")
    with pytest.raises((ValueError, PermissionError)):
        deploy.verify_bundle(bundle, trust)


@pytest.mark.parametrize(
    "name",
    [
        "extra.py",
        "extra.pth",
        "extra.pyc",
        "demo/__pycache__/extra.cpython-313.pyc",
        "extra.dll",
        "extra.so",
        "extra.txt",
    ],
)
def test_installed_inventory_refuses_unlisted_importable_or_untracked_content(
    signed_bundle, name
):
    bundle, _, manifest, environment = signed_bundle
    assert deploy.verify_installed(bundle, manifest, environment)["verified_files"] == 3
    path = site_at(environment) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"unlisted")
    with pytest.raises(PermissionError, match="unlisted"):
        deploy.verify_installed(bundle, manifest, environment)


def test_signed_library_byte_tamper_is_not_hidden_by_generated_record(signed_bundle):
    bundle, _, manifest, environment = signed_bundle
    (site_at(environment) / "demo/__init__.py").write_text("tampered")
    with pytest.raises(PermissionError, match="differs"):
        deploy.verify_installed(bundle, manifest, environment)


def ready_update(tmp_path, signed_bundle):
    bundle, trust, manifest, environment = signed_bundle
    root = tmp_path / "deployment"
    root.mkdir()
    deploy.atomic(
        root / "deployment.json",
        {"schema": deploy.STATE_SCHEMA, "profile": "cpu-observe"},
    )
    (root / "transactions").mkdir()
    (root / "data/old").mkdir(parents=True)
    (root / "data/new").mkdir(parents=True)
    (root / "data/old/accepted.json").write_text('{"records":1}')
    (root / "data/new/accepted.json").write_text('{"records":1}')
    (root / "releases").mkdir()
    environment.rename(root / "releases/new")
    previous = {
        "schema": deploy.STATE_SCHEMA,
        "transaction": "0" * 32,
        "environment": "releases/old",
        "data": "data/old",
        "highest_release_sequence": 19,
    }
    deploy.atomic(root / "active.json", previous)
    journal = {
        "id": "1" * 32,
        "phase": "ready",
        "previous": previous,
        "environment": "releases/new",
        "data": "data/new",
        "version": manifest["version"],
        "release_sequence": manifest["release_sequence"],
        "bundle": str(bundle),
        "trust_file": str(trust),
        "manifest_digest": hashlib.sha256(deploy.canonical(manifest)).hexdigest(),
        "data_digest": deploy.data_digest(root / "data/new"),
        "previous_data_digest": deploy.data_digest(root / "data/old"),
    }
    deploy.atomic(root / "transactions" / (journal["id"] + ".json"), journal)
    return root, journal


@pytest.mark.parametrize("change", ["late-record", "missing-pin", "held-service-lock"])
def test_activation_cannot_discard_source_changes_or_ignore_live_service(
    tmp_path, signed_bundle, change
):
    root, journal = ready_update(tmp_path, signed_bundle)
    if change == "late-record":
        (root / "data/old/accepted.json").write_text('{"records":2}')
    elif change == "missing-pin":
        journal.pop("previous_data_digest")
        deploy.atomic(root / "transactions" / (journal["id"] + ".json"), journal)
    if change == "held-service-lock":
        with (
            closing(ProcessLock(root / "data/old/service.lock")),
            pytest.raises(RuntimeError, match="operation is active"),
        ):
            deploy.activate(root, journal["id"])
    else:
        with pytest.raises(PermissionError, match="Previous data changed"):
            deploy.activate(root, journal["id"])
    assert deploy.active(root) == journal["previous"]
    assert (
        deploy.read_json(root / "transactions" / (journal["id"] + ".json"))["phase"]
        == "ready"
    )


def test_activation_accepts_exact_snapshot_and_is_idempotent(tmp_path, signed_bundle):
    root, journal = ready_update(tmp_path, signed_bundle)
    result = deploy.activate(root, journal["id"])
    assert result["cpu_only"] and result["native_response"] == "blocked"
    assert result["data"] == "data/new"
    assert deploy.activate(root, journal["id"]) == result


@pytest.mark.parametrize("state", ["ready", "active"])
def test_recovery_rechecks_installed_bytes_before_marking_success(
    tmp_path, signed_bundle, state
):
    root, journal = ready_update(tmp_path, signed_bundle)
    if state == "active":
        deploy.activate(root, journal["id"])
    (site_at(root / "releases/new") / "demo/__init__.py").write_text("tampered")
    before = deploy.read_json(root / "transactions" / (journal["id"] + ".json"))
    with pytest.raises(PermissionError, match="differs"):
        deploy.recover(root, journal["id"])
    assert deploy.read_json(root / "transactions" / (journal["id"] + ".json")) == before


def test_backup_source_fingerprint_is_captured_under_held_service_lock(
    tmp_path, monkeypatch
):
    source = tmp_path / "owned-source"
    store = Store(Settings(source, min_free_bytes=0))
    store.close()
    real_hash = backup.sha256
    seen = []

    def checked_hash(path):
        if Path(path).is_relative_to(source):
            with pytest.raises(RuntimeError, match="already in use"):
                ProcessLock(source / "service.lock")
            seen.append(Path(path).name)
        return real_hash(path)

    monkeypatch.setattr(backup, "sha256", checked_hash)
    result = backup.backup(source, tmp_path / "snapshot", include_source_digest=True)
    assert seen and result["source_data_digest"] == deploy.data_digest(source)
    assert "source_data_digest" not in deploy.read_json(
        tmp_path / "snapshot/manifest.json"
    )
    default = backup.backup(source, tmp_path / "default-snapshot")
    assert "source_data_digest" not in default


def test_launch_preserves_only_explicit_signing_configuration_and_forces_observe(
    monkeypatch,
):
    settings = {
        "SAPIENTIA_AGENT_SIGNING_KEY_FILE": "external-private-file-fixture",
        "SAPIENTIA_AGENT_ENDPOINT_URL": "https://127.0.0.1",
        "SAPIENTIA_AGENT_CA_FILE": "external-public-ca-fixture",
    }
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", "0")
    monkeypatch.setenv("SAPIENTIA_UNTRUSTED_TEST_FLAG", "1")
    monkeypatch.setenv("SERA_AGENT_REQUIRE_SIGNED_PACKAGE", "0")
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    assert not (set(settings) & deploy.environment().keys())
    launch = deploy.environment(launch=True)
    assert {key: launch[key] for key in settings} == settings
    assert "SAPIENTIA_UNTRUSTED_TEST_FLAG" not in launch
    assert launch["SAPIENTIA_BLOCK_NATIVE_RESPONSE"] == "1"
    assert launch["SERA_AGENT_REQUIRE_SIGNED_PACKAGE"] == "1"
    assert launch["CUDA_VISIBLE_DEVICES"] == ""


def test_stage_accepts_only_offline_hash_locked_wheels_without_target_pip(
    tmp_path, signed_bundle, monkeypatch
):
    bundle, trust, manifest, original_environment = signed_bundle
    calls, builders = [], []

    class Builder:
        def __init__(self, **options):
            builders.append(options)

        def create(self, directory):
            site_at(directory).parent.mkdir(parents=True)
            shutil.copytree(site_at(original_environment), site_at(directory))

    def run(arguments, **_options):
        values = list(map(str, arguments))
        calls.append(values)
        if "pip" in values:
            return ""
        data = Path(values[-1])
        data.mkdir(parents=True)
        (data / "synthetic-health.json").write_text('{"complete":true}')
        return '{"version":"1.0","cases":0,"users":0}'

    monkeypatch.setattr(deploy.venv, "EnvBuilder", Builder)
    monkeypatch.setattr(deploy, "run", run)
    result = deploy.stage(bundle, trust, tmp_path / "managed")
    assert result["phase"] == "ready" and result["version"] == manifest["version"]
    assert builders == [{"with_pip": False, "clear": False, "symlinks": False}]
    install = next(values for values in calls if "install" in values)
    assert install[:6] == [sys.executable, "-I", "-B", "-m", "pip", "--python"]
    assert all(
        flag in install
        for flag in (
            "--no-index",
            "--only-binary=:all:",
            "--require-hashes",
            "--no-compile",
        )
    )
    assert "--no-deps" not in install
    # A second operation is the real Windows regression boundary: Python's
    # mode=0700 child DACL must not invalidate the next activation preflight.
    if os.name == "nt":
        security = deploy._WindowsAcl()
        managed = tmp_path / "managed"
        for item in (managed, *managed.rglob("*")):
            security.require_private(item)
    assert deploy.activate(tmp_path / "managed", result["id"])["transaction"] == result["id"]


def test_plain_path_uses_one_fresh_lstat_per_component_on_every_call(
    tmp_path, monkeypatch
):
    target = tmp_path / "missing-parent" / "missing-leaf"
    calls = Counter()
    actual_lstat = Path.lstat

    def lstat(path):
        calls[path] += 1
        return actual_lstat(path)

    def forbidden_probe(_path):
        raise AssertionError("plain_path must not add exists/is_symlink probes")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", lstat)
        patch.setattr(Path, "exists", forbidden_probe)
        patch.setattr(Path, "is_symlink", forbidden_probe)
        assert deploy.plain_path(target) == target
        assert deploy.plain_path(target) == target
    assert calls == Counter({path: 2 for path in (target, *target.parents)})


@pytest.mark.parametrize("location", ["leaf", "parent"])
def test_plain_path_rejects_actual_dangling_links(tmp_path, location):
    link = tmp_path / "dangling"
    try:
        link.symlink_to(tmp_path / "nonexistent-target", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip(
            "This account cannot create a symlink; mocked link/reparse tests remain mandatory"
        )
    assert not link.exists() and link.is_symlink()
    target = link if location == "leaf" else link / "nonexistent-child"
    with pytest.raises(ValueError, match="links or reparse"):
        deploy.plain_path(target)


@pytest.mark.parametrize("location", ["leaf", "parent"])
@pytest.mark.parametrize("kind", ["symlink", "reparse"])
def test_plain_path_rejects_link_metadata_even_when_leaf_does_not_exist(
    tmp_path, monkeypatch, location, kind
):
    parent = tmp_path / "parent"
    target = parent / "leaf"
    selected = target if location == "leaf" else parent
    actual_lstat = Path.lstat

    def lstat(path):
        if path == selected:
            return SimpleNamespace(
                st_mode=(stat.S_IFLNK if kind == "symlink" else stat.S_IFDIR) | 0o700,
                st_file_attributes=0x400 if kind == "reparse" else 0,
            )
        return actual_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValueError, match="links or reparse"):
        deploy.plain_path(target)


def test_plain_path_does_not_treat_denied_ancestor_as_missing(tmp_path, monkeypatch):
    parent = tmp_path / "denied"
    target = parent / "new-leaf"
    actual_lstat = Path.lstat

    def lstat(path):
        if path == parent:
            raise PermissionError("denied ancestor")
        return actual_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(PermissionError, match="denied ancestor"):
        deploy.plain_path(target)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_private_destination_closes_inherited_read_access_before_data_creation(
    tmp_path,
):
    parent = tmp_path / "harmless-readable-parent"
    security = readable_owned_parent(parent)
    root = parent / "managed"
    # A user-precreated destination may inherit public read access even on
    # Python versions that already special-case mode=0700 for new directories.
    root.mkdir()
    before = security.inspect(root)
    assert any(entry["sid"] == "S-1-5-32-545" for entry in before["grants"])
    assert deploy._prepare_destination(root) == root
    protected = security.require_private(root, root=True)
    assert protected["owner"] == security.current
    assert {entry["sid"] for entry in protected["grants"]} == {
        security.current,
        "S-1-5-18",
    }
    data = root / "data"
    data.mkdir()
    synthetic = data / "synthetic-credentials.json"
    synthetic.write_text('{"synthetic":true}')
    security.require_private(data)
    security.require_private(synthetic)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_existing_recognized_data_is_secured_by_inheritance(tmp_path):
    parent = tmp_path / "harmless-readable-parent"
    security = readable_owned_parent(parent)
    root = parent / "managed"
    root.mkdir()
    deploy.atomic(
        root / "deployment.json",
        {"schema": deploy.STATE_SCHEMA, "profile": "cpu-observe"},
    )
    data = root / "data"
    data.mkdir()
    original = data / "synthetic-db.json"
    original.write_text('{"synthetic-records":3}')
    assert any(
        entry["sid"] == "S-1-5-32-545" for entry in security.inspect(original)["grants"]
    )
    with deploy.operation(root):
        security.require_private(original)
    assert original.read_text() == '{"synthetic-records":3}'


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_unmanaged_nonempty_destination_is_untouched_including_acl(tmp_path):
    security = readable_owned_parent(tmp_path / "unmanaged")
    root = tmp_path / "unmanaged"
    (root / "unrelated.txt").write_text("preserve")
    before = security.inspect(root)
    with (
        pytest.raises(ValueError, match="Unmanaged nonempty"),
        deploy.operation(root),
    ):
        pytest.fail("Must not acquire a lock in an unmanaged tree")
    assert security.inspect(root) == before
    assert [item.name for item in root.iterdir()] == ["unrelated.txt"]
    assert (root / "unrelated.txt").read_text() == "preserve"


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
@pytest.mark.parametrize("inherit_only", [False, True])
def test_explicit_future_or_current_broad_access_fails_closed(tmp_path, inherit_only):
    root = deploy._prepare_destination(tmp_path / "managed")
    deploy.atomic(
        root / "deployment.json",
        {"schema": deploy.STATE_SCHEMA, "profile": "cpu-observe"},
    )
    child = root / "releases"
    child.mkdir()
    security = deploy._WindowsAcl()
    flags = "OICIIO" if inherit_only else "OICI"
    set_owned_test_dacl(
        child, f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;{flags};GR;;;WD)"
    )
    with (
        pytest.raises(PermissionError, match="another account access"),
        deploy.operation(root),
    ):
        pytest.fail("Public descendant grants must prevent staging")
    assert not (root / ".deployment.lock").exists()


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_acl_apply_failure_prevents_venv_data_and_lock_creation(
    tmp_path, signed_bundle, monkeypatch
):
    root = tmp_path / "managed"

    def fail(_security, _path):
        raise PermissionError("injected ACL failure")

    monkeypatch.setattr(deploy._WindowsAcl, "protect", fail)
    monkeypatch.setattr(
        deploy.venv, "EnvBuilder", lambda **_kw: pytest.fail("Must secure before venv")
    )
    with pytest.raises(PermissionError, match="injected ACL failure"):
        deploy.stage(signed_bundle[0], signed_bundle[1], root)
    assert root.is_dir() and not list(root.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_unsafe_ancestor_and_shared_identity_refuse_before_acl_changes(
    tmp_path, monkeypatch
):
    parent = tmp_path / "unsafe-parent"
    security = readable_owned_parent(parent)
    set_owned_test_dacl(
        parent, f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)"
    )
    root = parent / "empty"
    with pytest.raises(PermissionError, match="untrusted replacement"):
        deploy._prepare_destination(root)
    assert not list(root.iterdir())
    safe = deploy._prepare_destination(tmp_path / "safe")
    deploy.atomic(
        safe / "deployment.json",
        {"schema": deploy.STATE_SCHEMA, "profile": "cpu-observe"},
    )
    original = tmp_path / "harmless-original"
    original.write_text("synthetic")
    (safe / "shared-file").hardlink_to(original)
    before = security.inspect(original)
    monkeypatch.setattr(
        deploy._WindowsAcl,
        "protect",
        lambda *_a: pytest.fail("Do not propagate into shared identities"),
    )
    with pytest.raises(ValueError, match="shared file identities"):
        deploy._prepare_destination(safe)
    assert security.inspect(original) == before


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_existing_public_write_access_is_rejected_before_inheritance_changes(
    tmp_path, monkeypatch
):
    root = deploy._prepare_destination(tmp_path / "managed")
    deploy.atomic(
        root / "deployment.json",
        {"schema": deploy.STATE_SCHEMA, "profile": "cpu-observe"},
    )
    child = root / "data"
    child.mkdir()
    security = deploy._WindowsAcl()
    set_owned_test_dacl(
        child, f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;OICI;FW;;;WD)"
    )
    monkeypatch.setattr(
        deploy._WindowsAcl,
        "protect",
        lambda *_a: pytest.fail("Refuse mutable tree before propagation"),
    )
    with pytest.raises(PermissionError, match="untrusted mutation"):
        deploy._prepare_destination(root)
    assert not (root / ".deployment.lock").exists()


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_new_private_layout_normalizes_python_mode700_before_descendant_creation(
    tmp_path, monkeypatch
):
    root = deploy._prepare_destination(tmp_path / "managed")
    observed = []
    protect = deploy._WindowsAcl.protect

    def inspect_new(security, path):
        assert path.is_dir() and not any(path.iterdir())
        observed.append((path, security.inspect(path)))
        protect(security, path)

    monkeypatch.setattr(deploy._WindowsAcl, "protect", inspect_new)
    target = deploy.private_directory(root, "release_payloads/new/wheelhouse")
    assert [path for path, _ in observed] == [
        root / "release_payloads", root / "release_payloads/new", target
    ]
    security = deploy._WindowsAcl()
    for path, _ in observed:
        state = security.require_private(path, root=True)
        assert state["owner"] == security.current
        assert {entry["sid"] for entry in state["grants"]} == {
            security.current, "S-1-5-18"
        }
    (target / "inert.txt").write_text("synthetic")
    security.require_private(target / "inert.txt")


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
@pytest.mark.parametrize("inherit_only", [False, True])
def test_private_layout_never_repairs_preexisting_unsafe_directory(
    tmp_path, monkeypatch, inherit_only
):
    root = deploy._prepare_destination(tmp_path / "managed")
    existing = root / "backups"
    existing.mkdir(mode=0o700)
    security = deploy._WindowsAcl()
    flags = "OICIIO" if inherit_only else "OICI"
    set_owned_test_dacl(
        existing, f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;{flags};GR;;;WD)"
    )
    before = security.inspect(existing)
    monkeypatch.setattr(
        deploy._WindowsAcl, "protect",
        lambda *_a: pytest.fail("Existing unsafe directory must never be normalized"),
    )
    with pytest.raises(PermissionError, match="another account access"):
        deploy.private_directory(root, "backups", exist_ok=True)
    assert security.inspect(existing) == before and not list(existing.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_private_layout_creation_race_is_existing_not_new_authority(tmp_path, monkeypatch):
    root = deploy._prepare_destination(tmp_path / "managed")
    target = root / "backups"
    mkdir = Path.mkdir
    security = deploy._WindowsAcl()
    observed = []

    def lose_creation(path, *args, **kwargs):
        if path == target:
            mkdir(path, mode=0o700)
            set_owned_test_dacl(
                path, f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;OICI;GR;;;WD)"
            )
            observed.append(security.inspect(path))
            raise FileExistsError("Synthetic simultaneous creator")
        return mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", lose_creation)
    monkeypatch.setattr(
        deploy._WindowsAcl, "protect",
        lambda *_a: pytest.fail("Losing creator cannot normalize another directory"),
    )
    with pytest.raises(PermissionError, match="another account access"):
        deploy.private_directory(root, "backups", exist_ok=True)
    assert security.inspect(target) == observed[0]


@pytest.mark.skipif(os.name != "nt", reason="Native Windows ACL contract")
def test_new_private_layout_protection_failure_leaves_no_content(tmp_path, monkeypatch):
    root = deploy._prepare_destination(tmp_path / "managed")

    def deny(*_args):
        raise PermissionError("Synthetic new-directory protection failure")

    monkeypatch.setattr(deploy._WindowsAcl, "protect", deny)
    with pytest.raises(PermissionError, match="new-directory protection failure"):
        deploy.private_directory(root, "backups/new")
    assert (root / "backups").is_dir() and not list((root / "backups").iterdir())
