"""Server-side package manifest signing with an externally provisioned key."""

import base64
import os
import stat
from pathlib import Path

from .endpoint_agent.Agent.package_integrity import canonical


def _windows_protected(path, *, secret):
    """Inspect the existing key ACL without launching a shell or changing it."""
    import ctypes
    from ctypes import wintypes

    advapi, kernel = (
        ctypes.WinDLL("advapi32", use_last_error=True),
        ctypes.WinDLL("kernel32", use_last_error=True),
    )
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]

    def sid_text(pointer):
        value = ctypes.c_wchar_p()
        if not advapi.ConvertSidToStringSidW(pointer, ctypes.byref(value)):
            raise PermissionError("Package signing identity ACL is unavailable")
        try:
            return value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, ctypes.c_void_p))

    token = wintypes.HANDLE()
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise PermissionError("Package signing process identity is unavailable")
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        user = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, user, needed, ctypes.byref(needed)):
            raise PermissionError("Package signing process identity is unavailable")
        current = sid_text(
            ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p)).contents.value
        )
    finally:
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle(token)
    trusted = {
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        current,
    }
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    error = advapi.GetNamedSecurityInfoW(
        str(path),
        1,
        5,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if error:
        raise PermissionError("Package signing key ACL is unavailable")
    try:
        if not owner or sid_text(owner) not in trusted or not dacl:
            raise PermissionError("Package signing key has an untrusted owner or ACL")
        size = (wintypes.DWORD * 3)()
        advapi.GetAclInformation.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_int,
        ]
        advapi.GetAce.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        if not advapi.GetAclInformation(dacl, size, ctypes.sizeof(size), 2):
            raise PermissionError("Package signing key ACL is unavailable")
        rights = 0xD0156 | 0x50000000 | (0x80000001 if secret else 0)
        for index in range(size[0]):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise PermissionError("Package signing key ACL is unavailable")
            header = ctypes.string_at(ace, 4)
            if header[0] == 1 or header[1] & 8:
                continue
            if header[0] != 0:
                raise PermissionError("Unsupported package signing key ACL grant")
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            sid = sid_text(ace.value + 8)
            if mask & rights and sid not in trusted | {"S-1-3-4"}:
                raise PermissionError(
                    "Package signing key is accessible to an untrusted account"
                )
    finally:
        kernel.LocalFree(descriptor)


def _configured_key():
    configured = os.environ.get("SAPIENTIA_AGENT_SIGNING_KEY_FILE")
    if not configured:
        raise ValueError("External signing key is not configured")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = Path(configured)
    if not path.is_absolute() or path.resolve().is_relative_to(
        Path(__file__).resolve().parent.parent
    ):
        raise ValueError("Package signing key must be outside the installed release")
    if (
        path.is_symlink()
        or getattr(os.lstat(path), "st_file_attributes", 0) & 0x400
        or path.stat().st_size > 16384
    ):
        raise ValueError("Invalid external package signing key")
    for entry in path.parents:
        if (
            entry.is_symlink()
            or getattr(os.lstat(entry), "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("Package signing key path must not contain links")
    if os.name == "nt":
        _windows_protected(path, secret=True)
        _windows_protected(path.parent, secret=False)
    if os.name != "nt" and (
        stat.S_IMODE(path.stat().st_mode) & 0o077
        or stat.S_IMODE(path.parent.stat().st_mode) & 0o022
    ):
        raise ValueError(
            "External package signing key must be private and administrator-protected"
        )
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Package manifest signing requires Ed25519")  # noqa: TRY004 -- Configuration admission reports ValueError.
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return key, public


def public_identity():
    import hashlib

    _, public = _configured_key()
    return {
        "key_id": hashlib.sha256(public).hexdigest()[:32],
        "public_key": public.hex(),
    }


def sign(manifest, *, development_fixture=False):
    if type(development_fixture) is not bool:
        raise ValueError("Development fixture mode must be explicit boolean")
    if development_fixture:
        if (
            manifest.get("schema") != "sera.agent.package.v1"
            or manifest.get("distribution_profile") != "development_fixture"
            or any(
                name in manifest.get("files", {})
                for name in ("enrollment.token", "deployment.json", "ca.pem")
            )
        ):
            raise ValueError(
                "Unsigned development fixture cannot contain a scoped deployment"
            )
        return manifest
    if not os.environ.get("SAPIENTIA_AGENT_SIGNING_KEY_FILE"):
        raise ValueError(
            "Production agent distribution requires an externally provisioned signing key"
        )
    import hashlib

    key, public = _configured_key()

    key_id = hashlib.sha256(public).hexdigest()[:32]
    result = {
        **manifest,
        "package_signature": "Ed25519 pinned external trust; not OS code signing",
    }
    result["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "value": base64.b64encode(key.sign(canonical(result))).decode("ascii"),
    }
    return result


def trust_export(expected_key_id, approval):
    identity = public_identity()
    if identity["key_id"] != expected_key_id:
        raise ValueError("Configured signing identity changed after independent review")
    return {
        "schema": "xsera.agent.trust.v1",
        "keys": {identity["key_id"]: identity["public_key"]},
        "revoked_key_ids": [],
        "approval": approval,
        "bootstrap": "Independently verify the fingerprint and provision this public file outside the package; never auto-trust a downloaded archive",
    }


def status():
    configured = bool(os.environ.get("SAPIENTIA_AGENT_SIGNING_KEY_FILE"))
    result = {
        "configured": configured,
        "algorithm": "Ed25519" if configured else None,
        "os_code_signature": False,
        "hardware_attestation": False,
        "trust_bootstrap": "Operator must independently pin the public key outside the archive",
        "production_required": True,
        "unsigned_distribution_allowed": False,
        "external_ca_certification": "unavailable_not_performed",
    }
    if configured:
        try:
            result["key_id"] = sign({"probe": True})["signature"]["key_id"]
            result["available"] = True
        except (OSError, ValueError, TypeError):
            result.update(available=False, reason="configured_signing_key_unavailable")
    else:
        result.update(available=False, reason="external_signing_key_not_configured")
    return result
