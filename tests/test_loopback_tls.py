import os
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from tools import configure_loopback_tls as tls
from tools.configure_loopback_tls import configure


def test_local_ca_server_chain_and_existing_key_preservation(tmp_path):
    paths = configure(tmp_path / "private-tls")
    originals = {name: path.read_bytes() for name, path in paths.items()}
    ca = x509.load_pem_x509_certificate(originals["ca.pem"])
    server = x509.load_pem_x509_certificate(originals["server.pem"])
    server.verify_directly_issued_by(ca)
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert not server.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert b"PRIVATE KEY" not in originals["ca.pem"]
    ssl.create_default_context(cafile=paths["ca.pem"])
    configure(tmp_path / "private-tls")
    assert {name: path.read_bytes() for name, path in paths.items()} == originals


def test_partial_local_tls_is_never_silently_rotated(tmp_path):
    directory = tmp_path / "private-tls"
    directory.mkdir()
    tls._private_directory(directory, created=True)
    (directory / "ca.key").write_bytes(b"preserved existing private material")
    with pytest.raises(ValueError, match="Partial TLS"):
        configure(directory)
    assert (directory / "ca.key").read_bytes() == b"preserved existing private material"


def test_mismatched_ca_is_rejected(tmp_path):
    paths = configure(tmp_path / "first")
    other = configure(tmp_path / "second")
    paths["ca.pem"].write_bytes(other["ca.pem"].read_bytes())
    with pytest.raises(ValueError):
        configure(tmp_path / "first")


def test_encrypted_server_key_fails_without_password_prompt(tmp_path):
    paths = configure(tmp_path / "private-tls")
    key = serialization.load_pem_private_key(
        paths["server.key"].read_bytes(), password=None
    )
    paths["server.key"].write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"fixture-password"),
        )
    )
    started = time.monotonic()
    with pytest.raises(ssl.SSLError):
        configure(tmp_path / "private-tls")
    assert time.monotonic() - started < 2


def strict_handshake(paths):
    errors = []
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(paths["server.pem"], paths["server.key"])
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)

    def serve_once():
        try:
            peer, _ = listener.accept()
            with server_context.wrap_socket(peer, server_side=True) as stream:
                stream.sendall(b"strict-ok")
        except (OSError, ssl.SSLError) as error:
            errors.append(error)
        finally:
            listener.close()

    worker = threading.Thread(target=serve_once)
    worker.start()
    context = ssl.create_default_context(cafile=str(paths["ca.pem"]))
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    try:
        with (
            socket.create_connection(
                ("127.0.0.1", listener.getsockname()[1]), timeout=3
            ) as peer,
            context.wrap_socket(peer, server_hostname="127.0.0.1") as stream,
        ):
            assert stream.recv(32) == b"strict-ok"
    finally:
        worker.join(timeout=4)
    assert not worker.is_alive() and not errors


def test_native_strict_tls_handshake_requires_no_verification_bypass(tmp_path):
    strict_handshake(configure(tmp_path / "tls"))


def test_explicit_legacy_metadata_repair_preserves_private_keys_and_validity(tmp_path):
    paths = configure(tmp_path / "tls")
    signer = serialization.load_pem_private_key(
        paths["ca.key"].read_bytes(), password=None
    )
    keys = {name: paths[name].read_bytes() for name in ("ca.key", "server.key")}
    originals = {}
    for name in ("ca.pem", "server.pem"):
        original = x509.load_pem_x509_certificate(paths[name].read_bytes())
        originals[name] = original
        builder = (
            x509.CertificateBuilder()
            .subject_name(original.subject)
            .issuer_name(original.issuer)
            .public_key(original.public_key())
            .serial_number(original.serial_number)
            .not_valid_before(original.not_valid_before_utc)
            .not_valid_after(original.not_valid_after_utc)
        )
        for extension in original.extensions:
            if not isinstance(
                extension.value,
                (x509.SubjectKeyIdentifier, x509.AuthorityKeyIdentifier),
            ):
                builder = builder.add_extension(extension.value, extension.critical)
        paths[name].write_bytes(
            builder.sign(signer, hashes.SHA256()).public_bytes(
                serialization.Encoding.PEM
            )
        )
    with pytest.raises(ValueError, match="--repair-strict"):
        configure(tmp_path / "tls")
    configure(tmp_path / "tls", repair_strict=True)
    assert keys == {name: paths[name].read_bytes() for name in keys}
    for name, original in originals.items():
        restored = x509.load_pem_x509_certificate(paths[name].read_bytes())
        assert restored.serial_number == original.serial_number
        assert restored.not_valid_after_utc == original.not_valid_after_utc
    strict_handshake(paths)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows TLS directory DACL verification")
def test_fresh_tls_and_repeat_have_exact_process_user_and_system_acl(tmp_path):
    from tools.deploy_release import _WindowsAcl

    directory = tmp_path / "fresh-private-tls"
    paths = configure(directory)
    security = _WindowsAcl()
    state = security.require_private(directory, root=True)
    assert state["owner"] == security.current
    assert {entry["sid"] for entry in state["grants"]} == {
        security.current, "S-1-5-18"
    }
    for path in paths.values():
        security.require_private(path)
    originals = {name: path.read_bytes() for name, path in paths.items()}
    assert configure(directory) == paths
    assert security.inspect(directory) == state
    assert {name: path.read_bytes() for name, path in paths.items()} == originals


@pytest.mark.skipif(os.name != "nt", reason="Native Windows TLS directory DACL verification")
@pytest.mark.parametrize("inherit_only", [False, True])
def test_existing_unsafe_tls_directory_preserves_acl_and_partial_key(tmp_path, inherit_only):
    from tests.test_deploy_release_security import set_owned_test_dacl
    from tools.deploy_release import _WindowsAcl

    directory = tmp_path / "existing-unsafe-tls"
    directory.mkdir(mode=0o700)
    (directory / "ca.key").write_bytes(b"synthetic existing key must be preserved")
    security = _WindowsAcl()
    flags = "OICIIO" if inherit_only else "OICI"
    set_owned_test_dacl(
        directory,
        f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;{flags};GR;;;WD)",
    )
    before = security.inspect(directory)
    with pytest.raises(PermissionError, match="another account access"):
        configure(directory)
    assert security.inspect(directory) == before
    assert (directory / "ca.key").read_bytes() == b"synthetic existing key must be preserved"
    assert {path.name for path in directory.iterdir()} == {"ca.key"}


@pytest.mark.skipif(os.name != "nt", reason="Native Windows TLS directory creation race")
def test_tls_creation_race_never_normalizes_existing_unsafe_directory(tmp_path, monkeypatch):
    from tests.test_deploy_release_security import set_owned_test_dacl
    from tools.deploy_release import _WindowsAcl

    directory = tmp_path / "racing-tls"
    security = _WindowsAcl()
    mkdir, observed = Path.mkdir, []

    def race(path, *args, **kwargs):
        if path == directory:
            mkdir(path, mode=0o700)
            set_owned_test_dacl(
                path,
                f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;OICI;GR;;;WD)",
            )
            (path / "ca.key").write_bytes(b"concurrent creator material")
            observed.append(security.inspect(path))
            raise FileExistsError("Synthetic concurrent TLS directory creator")
        return mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", race)
    with pytest.raises(PermissionError, match="another account access"):
        configure(directory)
    assert security.inspect(directory) == observed[0]
    assert (directory / "ca.key").read_bytes() == b"concurrent creator material"
    assert {path.name for path in directory.iterdir()} == {"ca.key"}


def test_tls_protection_failure_creates_no_key_or_certificate(tmp_path, monkeypatch):
    directory, generations = tmp_path / "failed-private-tls", []

    def deny(path, *, created):
        assert path == directory and created is True
        assert not list(path.iterdir())
        raise PermissionError("Synthetic TLS directory protection failure")

    def unexpected_key_generation(*args, **kwargs):
        generations.append(True)
        raise AssertionError("TLS key generation must follow successful protection")

    monkeypatch.setattr(tls, "_private_directory", deny)
    monkeypatch.setattr(tls.ec, "generate_private_key", unexpected_key_generation)
    with pytest.raises(PermissionError, match="protection failure"):
        configure(directory)
    assert not generations and not list(directory.iterdir())
