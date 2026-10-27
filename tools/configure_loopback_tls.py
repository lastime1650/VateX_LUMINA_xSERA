"""Provision a private local CA and loopback server certificate, never QA keys."""

import argparse
import ipaddress
import os
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sapientia.backup import _private_directory
from sapientia.endpoint_agent.Agent.response import _no_links


def _identifiers_present(cert):
    try:
        cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    except x509.ExtensionNotFound:
        return False
    return True


def _with_identifiers(cert, signer, issuer_key):
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(cert.serial_number)
        .not_valid_before(cert.not_valid_before_utc)
        .not_valid_after(cert.not_valid_after_utc)
    )
    for extension in cert.extensions:
        if not isinstance(
            extension.value, (x509.SubjectKeyIdentifier, x509.AuthorityKeyIdentifier)
        ):
            builder = builder.add_extension(
                extension.value, critical=extension.critical
            )
    return (
        builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(cert.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key),
            critical=False,
        )
        .sign(signer, hashes.SHA256())
    )


def _replace_certificate(path, cert):
    fd, temporary = tempfile.mkstemp(prefix=".strict-tls-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(cert.public_bytes(serialization.Encoding.PEM))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def configure(directory, *, repair_strict=False):
    directory = Path(directory).absolute()
    parent = directory
    while not parent.exists():
        parent = parent.parent
    _no_links(parent)
    try:
        directory.mkdir(mode=0o700, parents=True)
    except FileExistsError:
        created = False
    else:
        created = True
    _no_links(directory)
    _private_directory(directory, created=created)
    paths = {
        name: directory / name
        for name in ("ca.pem", "ca.key", "server.pem", "server.key")
    }
    existing = [path.exists() for path in paths.values()]
    if any(existing):
        if not all(existing):
            raise ValueError(
                "Partial TLS material requires explicit operator recovery; existing keys preserved"
            )
        for path in paths.values():
            _no_links(path)
            if not path.is_file() or path.stat().st_nlink != 1:
                raise ValueError("TLS material must be ordinary private files")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            paths["server.pem"], paths["server.key"], password=lambda: ""
        )
        cert = x509.load_pem_x509_certificate(paths["server.pem"].read_bytes())
        ca = x509.load_pem_x509_certificate(paths["ca.pem"].read_bytes())
        try:
            cert.verify_directly_issued_by(ca)
        except InvalidSignature as exc:
            raise ValueError(
                "Server certificate does not match the preserved local CA"
            ) from exc
        ca_key = serialization.load_pem_private_key(
            paths["ca.key"].read_bytes(), password=None
        )
        if ca_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != ca.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ValueError("Local CA key mismatch; operator recovery required")
        if (
            not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or ipaddress.ip_address("127.0.0.1")
            not in cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.IPAddress)
        ):
            raise ValueError(
                "TLS material must be a loopback server certificate and local CA"
            )
        if max(cert.not_valid_before_utc, ca.not_valid_before_utc) > datetime.now(UTC):
            raise ValueError("TLS certificate is not valid yet")
        if min(cert.not_valid_after_utc, ca.not_valid_after_utc) <= datetime.now(UTC):
            raise ValueError("Loopback certificate expired; operator renewal required")
        if not _identifiers_present(ca) or not _identifiers_present(cert):
            if not repair_strict:
                raise ValueError(
                    "Legacy TLS identifiers missing; explicit --repair-strict required, keys preserved"
                )
            expected = x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, "Vatex LUMINA local endpoint CA"
                    )
                ]
            )
            if ca.subject != expected or ca.issuer != expected:
                raise ValueError(
                    "Strict repair is limited to this helper's local self-signed CA"
                )
            ca.verify_directly_issued_by(ca)
            # Preserve private keys, issuer, serials, validity, SAN and usages.
            # Only public certificate metadata changes; enrolled strict clients
            # must receive the repaired CA certificate before connecting.
            fixed_ca = _with_identifiers(ca, ca_key, ca_key.public_key())
            fixed_server = _with_identifiers(cert, ca_key, ca_key.public_key())
            fixed_server.verify_directly_issued_by(fixed_ca)
            _replace_certificate(paths["ca.pem"], fixed_ca)
            _replace_certificate(paths["server.pem"], fixed_server)
        return paths
    now = datetime.now(UTC)
    ca_key, server_key = (
        ec.generate_private_key(ec.SECP256R1()),
        ec.generate_private_key(ec.SECP256R1()),
    )
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Vatex LUMINA local endpoint CA")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    values = {
        "ca.pem": ca.public_bytes(serialization.Encoding.PEM),
        "server.pem": server.public_bytes(serialization.Encoding.PEM),
        "ca.key": ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "server.key": server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    }
    for name, body in values.items():
        with paths[name].open("xb") as stream:
            stream.write(body)
    return paths


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--repair-strict",
        action="store_true",
        help="Add missing SKI/AKI to legacy local certificates while preserving every private key",
    )
    args = parser.parse_args()
    configure(args.directory, repair_strict=args.repair_strict)
    print("Private loopback TLS material ready; CA keys are never packaged for agents.")
