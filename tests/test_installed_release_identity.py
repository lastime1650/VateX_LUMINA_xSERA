"""Installed source pins are checked against real files, never a raw digest hint."""

import base64
import copy
import hashlib
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sapientia import auth
from sapientia import qualification_registry as qr
from sapientia import release_manifest as rm
from sapientia.storage import Settings, Store


class Entry(str):
    def __new__(cls, name, raw=None):
        value = super().__new__(cls, name)
        value.hash = (None if raw is None else SimpleNamespace(
            mode="sha256", value=base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")))
        return value


@pytest.fixture
def installed(tmp_path, monkeypatch):
    root = tmp_path / "site-packages"
    package = root / "sapientia"
    package.mkdir(parents=True)
    files = {"sapientia/__init__.py": b'__version__ = "0.20.0"\n',
             "sapientia/release_manifest.py": Path(rm.__file__).read_bytes(),
             "sapientia/web/index.html": b"<title>owned fixture</title>"}
    for name, raw in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    identity = {"schema": rm.SCHEMA, "release": rm.__version__, "wire_version": rm.WIRE_VERSION,
                "control_version": rm.CONTROL_VERSION,
                "files": {**{name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
                          "pyproject.toml": "a" * 64, "setup.py": "b" * 64}}
    document = {**identity, "source_digest": rm.digest(identity), "source_bytes": 12345,
                "native_qualified": False, "code_signed": False}
    marker = root / ("vatex_lumina_xsera-" + rm.__version__ + ".dist-info") / rm.INSTALLED_MANIFEST
    marker.parent.mkdir()
    distribution = SimpleNamespace(version=rm.__version__, files=[], locate_file=lambda name: root / str(name))
    def rewrite(value=None, *, raw=None, record=True):
        content = rm.canonical(document if value is None else value) if raw is None else raw
        marker.write_bytes(content)
        if record:
            distribution.files = [Entry(name) for name in files] + [Entry(marker.relative_to(root).as_posix(), content)]
    rewrite()
    monkeypatch.setattr(rm, "__file__", str(package / "release_manifest.py"))
    monkeypatch.setattr(rm.importlib.metadata, "distribution", lambda name: distribution)
    return SimpleNamespace(root=root, package=package, marker=marker, distribution=distribution,
                           document=document, rewrite=rewrite)


def test_current_editable_source_retains_full_manifest_identity():
    assert rm.current_identity() == rm.build()


def test_installed_identity_checks_inventory_and_files_on_each_call(installed):
    assert rm.current_identity() == installed.document
    target = installed.package / "web/index.html"
    original = target.read_bytes()
    target.write_bytes(original + b"tamper")
    with pytest.raises(ValueError, match="differs"):
        rm.current_identity()
    target.write_bytes(original)
    assert rm.current_identity()["source_digest"] == installed.document["source_digest"]


@pytest.mark.parametrize("mode", ["missing_marker", "missing_record", "missing_runtime", "extra_runtime",
                                  "record_mismatch", "foreign_owner", "version", "copied_inventory"])
def test_missing_extra_copied_or_foreign_metadata_cannot_fallback(installed, mode):
    if mode == "missing_marker":
        installed.marker.unlink()
    elif mode == "missing_record":
        installed.distribution.files = [p for p in installed.distribution.files if str(p).startswith("sapientia/")]
    elif mode == "missing_runtime":
        (installed.package / "web/index.html").unlink()
    elif mode == "extra_runtime":
        (installed.package / "unexpected.py").write_text("pass", encoding="utf-8")
    elif mode == "record_mismatch":
        installed.marker.write_bytes(installed.marker.read_bytes() + b" ")
    elif mode == "foreign_owner":
        installed.distribution.locate_file = lambda name: installed.root.parent / "foreign" / str(name)
    elif mode == "version":
        installed.distribution.version = "0.19.0"
    else:
        changed = copy.deepcopy(installed.document)
        changed["files"]["sapientia/web/index.html"] = "f" * 64
        identity = {key: changed[key] for key in ("schema", "release", "wire_version", "control_version", "files")}
        changed["source_digest"] = rm.digest(identity)
        installed.rewrite(changed)
    # Even a plausible project file in site-packages must not permit fallback.
    (installed.root / "pyproject.toml").write_text(
        '[project]\nname="vatex-lumina-xsera"\nversion="0.20.0"\n', encoding="utf-8")
    with pytest.raises((ValueError, FileNotFoundError)):
        rm.current_identity()


@pytest.mark.parametrize("mode", ["duplicate", "nan", "deep", "oversize", "digest", "path", "typed_version", "unknown"])
def test_inventory_json_and_canonical_contract_are_strict(installed, mode):
    if mode == "duplicate":
        installed.rewrite(raw=b'{"schema":"xsera.release-manifest.v1","schema":"duplicate"}')
    elif mode == "nan":
        installed.rewrite(raw=b'{"source_bytes":NaN}')
    elif mode == "deep":
        installed.rewrite(raw=b"[" * 2000 + b"]" * 2000)
    elif mode == "oversize":
        installed.rewrite(raw=b" " * (rm.MAX_INSTALLED_MANIFEST_BYTES + 1))
    else:
        changed = copy.deepcopy(installed.document)
        if mode == "digest":
            changed["source_digest"] = "0" * 64
        elif mode == "path":
            changed["files"]["sapientia/../outside.py"] = "f" * 64
        elif mode == "typed_version":
            changed["wire_version"] = True
        else:
            changed["publisher_authenticated"] = True
        installed.rewrite(changed)
    with pytest.raises(ValueError):
        rm.current_identity()


def test_runtime_hardlink_is_not_a_second_trusted_identity(installed):
    target = installed.package / "web/index.html"
    linked = installed.root.parent / "shared.html"
    try:
        linked.hardlink_to(target)
        with pytest.raises(ValueError, match="unshared"):
            rm.current_identity()
    finally:
        linked.unlink(missing_ok=True)


def test_signed_qualification_source_pin_and_virtual_scope(installed, tmp_path):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keys = tmp_path / "independent-qualification-keys.json"
    keys.write_text(json.dumps({"independent-qa": base64.b64encode(public).decode()}), encoding="utf-8")
    store = Store(Settings(tmp_path / "qualification-store", min_free_bytes=0, qualification_keys=keys))
    try:
        auth.create_user(store, "qa-admin", "Synthetic-qualification-fixture-password", "admin", "default")
        actor = {"name": "qa-admin", "tenant": "default", "role": "admin"}
        now = time.time()
        document = {"schema": qr.SCHEMA, "signer": "independent-qa", "tenant": "default", "indexes": ["public"],
                    "source_digest": installed.document["source_digest"], "package_digest": "b" * 64,
                    "config_digest": "c" * 64, "tool_digest": "d" * 64, "platform": "virtual-windows",
                    "capability": "simulation", "native": False, "passed": True,
                    "checks": [{"name": "owned-runtime", "passed": True, "artifact_digest": "e" * 64}],
                    "created": now - 1, "expires": now + 60}
        def envelope(value):
            return {"document": value, "signature": base64.b64encode(key.sign(rm.canonical(value))).decode()}
        saved = qr.record(store, actor, envelope(document))
        assert saved["native"] is False and saved["passed"] is True
        with store.control() as db:
            assert db.execute("SELECT source_digest FROM qualification_manifests WHERE id=?", (saved["id"],)).fetchone()[0] == document["source_digest"]
        with pytest.raises(ValueError, match="another source"):
            qr.record(store, actor, envelope({**document, "source_digest": "a" * 64}))
        forged = envelope(document)
        forged["document"] = {**document, "native": True}
        with pytest.raises(PermissionError):
            qr.record(store, actor, forged)
        keys.write_text("{}", encoding="utf-8")
        with pytest.raises(PermissionError):
            qr.record(store, actor, envelope(document))
    finally:
        store.close()


def test_serve_explicitly_passes_independent_qualification_key_file(tmp_path, monkeypatch):
    import uvicorn

    from sapientia import __main__ as cli
    from sapientia import api

    captured = {}
    def create_app(settings):
        captured["settings"] = settings
        return object()
    monkeypatch.setattr(api, "create_app", create_app)
    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: None)
    keys = tmp_path / "independent-public-keys.json"
    monkeypatch.setattr(sys, "argv", ["sapientia", "--data", str(tmp_path / "unused"),
                                    "serve", "--qualification-keys", str(keys)])
    cli.main()
    assert captured["settings"].qualification_keys == keys
    assert not (tmp_path / "unused").exists()


def test_release_http_uses_canonical_principal_and_installed_inventory(installed, tmp_path):
    from fastapi.testclient import TestClient

    from sapientia.api import create_app

    app = create_app(Settings(tmp_path / "http-store", min_free_bytes=0), background=False)
    password = "Synthetic-release-http-fixture-password"
    auth.create_user(app.state.store, "release-admin", password, "admin", "default")
    try:
        with TestClient(app) as client:
            assert client.get("/api/v2/release").status_code == 401
            login = client.post("/api/login", json={"name": "release-admin", "password": password})
            assert login.status_code == 200
            response = client.get("/api/v2/release")
            assert response.status_code == 200 and response.json() == installed.document
    finally:
        if not app.state.store.closed:
            app.state.runtime.close()
            app.state.store.close()
