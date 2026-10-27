"""Protect plaintext databases and credentials before creating the first file."""

import os

import pytest

from sapientia import auth, backup
from sapientia.storage import Settings, Store


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "source"
    store = Store(Settings(path, min_free_bytes=0))
    auth.create_user(store, "qa_admin", "Synthetic-private-backup-2026")
    store.close()
    (path / "secrets.key").write_bytes(os.urandom(32))
    return path


def test_backup_and_restore_protect_empty_directory_before_any_copy(
    source, tmp_path, monkeypatch
):
    protected = []
    original = backup._private_directory

    def protect(path, **options):
        assert path.is_dir() and not any(path.iterdir())
        assert options == {"created": True}
        original(path, **options)
        protected.append(path)

    monkeypatch.setattr(backup, "_private_directory", protect)
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    backup.backup(source, snapshot)
    backup.restore(snapshot, restored)
    assert protected == [snapshot, restored]
    assert (restored / "secrets.key").read_bytes() == (
        source / "secrets.key"
    ).read_bytes()


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_permission_failure_writes_no_plaintext(
    source, tmp_path, monkeypatch, operation
):
    snapshot = tmp_path / "snapshot"
    if operation == "restore":
        backup.backup(source, snapshot)
    destination = tmp_path / "denied"

    def deny(_, **_options):
        raise OSError("Synthetic permission-setting failure")

    monkeypatch.setattr(backup, "_private_directory", deny)
    with pytest.raises(OSError, match="permission-setting"):
        if operation == "backup":
            backup.backup(source, destination)
        else:
            backup.restore(snapshot, destination)
    assert destination.is_dir() and not any(destination.iterdir())


def windows_dacl(path):
    import ctypes
    from ctypes import wintypes

    advapi, kernel = (
        ctypes.WinDLL("advapi32", use_last_error=True),
        ctypes.WinDLL("kernel32", use_last_error=True),
    )
    getter = advapi.GetFileSecurityW
    getter.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    getter.restype = wintypes.BOOL
    size = wintypes.DWORD()
    getter(str(path), 4, None, 0, ctypes.byref(size))
    assert size.value > 0
    descriptor = ctypes.create_string_buffer(size.value)
    assert getter(str(path), 4, descriptor, size, ctypes.byref(size))
    converter = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
    converter.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    converter.restype = wintypes.BOOL
    rendered = wintypes.LPWSTR()
    assert converter(descriptor, 1, 4, ctypes.byref(rendered), None)
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = (
        [ctypes.c_void_p],
        ctypes.c_void_p,
    )
    try:
        return rendered.value
    finally:
        kernel.LocalFree(rendered)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows DACL verification")
def test_windows_plaintext_directories_and_files_have_only_system_owner_aces(
    source, tmp_path
):
    from tools.deploy_release import _WindowsAcl

    security = _WindowsAcl()
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    backup.backup(source, snapshot)
    backup.restore(snapshot, restored)
    for path in (snapshot, restored):
        assert windows_dacl(path).startswith("D:P")
        for item in (
            path,
            path / "control.sqlite3",
            path / "events.duckdb",
            path / "secrets.key",
        ):
            dacl = windows_dacl(item)
            assert dacl.count("(") == 2
            assert ";;;SY)" in dacl
            assert ";;;OW)" not in dacl and ";;;BA)" not in dacl
            state = security.require_private(item)
            assert {entry["sid"] for entry in state["grants"]} == {
                security.current, "S-1-5-18"
            }


@pytest.mark.skipif(os.name != "nt", reason="Native Windows owner/DACL verification")
def test_new_admin_owned_owner_rights_directory_gets_exact_process_user(tmp_path):
    import ctypes

    from tools.deploy_release import _WindowsAcl

    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip("Administrator-owner fixture needs a local administrator")
    path = tmp_path / "new-backup"
    path.mkdir(mode=0o700)
    security = _WindowsAcl()
    c, w = security.c, security.w
    descriptor, owner, dacl = c.c_void_p(), c.c_void_p(), c.c_void_p()
    present, defaulted = w.BOOL(), w.BOOL()
    assert security.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)",
        1, c.byref(descriptor), None,
    )
    try:
        assert security.api.GetSecurityDescriptorOwner(
            descriptor, c.byref(owner), c.byref(defaulted)
        )
        assert security.api.GetSecurityDescriptorDacl(
            descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted)
        ) and present
        assert security.api.SetNamedSecurityInfoW(
            str(path), 1, 0x80000005, owner, None, dacl, None
        ) == 0
    finally:
        security.kernel.LocalFree(descriptor)
    before = security.inspect(path)
    assert before["owner"] == "S-1-5-32-544"
    assert {entry["sid"] for entry in before["grants"]} == {
        "S-1-5-18", "S-1-5-32-544", "S-1-3-4"
    }
    with pytest.raises(PermissionError, match="another account access"):
        backup._private_directory(path)
    assert security.inspect(path) == before
    # The test itself just created this empty directory. This explicit creator
    # authority is never inferred from a preexisting directory's ACL or name.
    backup._private_directory(path, created=True)
    state = security.require_private(path, root=True)
    assert state["owner"] == security.current
    assert {entry["sid"] for entry in state["grants"]} == {
        security.current, "S-1-5-18"
    }
    (path / "inert-secret.txt").write_text("synthetic")
    security.require_private(path / "inert-secret.txt")
    backup._private_directory(path)  # Already private, nonempty: inspect only.
    assert security.inspect(path) == state


@pytest.mark.skipif(os.name != "nt", reason="Native Windows DACL verification")
@pytest.mark.parametrize("created", [False, True])
def test_backup_protection_never_repairs_existing_unsafe_nonempty_path(tmp_path, created):
    from tools.deploy_release import _WindowsAcl

    path = tmp_path / "preexisting-unsafe"
    path.mkdir(mode=0o700)
    (path / "preserved.txt").write_text("preserve")
    security = _WindowsAcl()
    before = security.inspect(path)
    with pytest.raises(PermissionError):
        backup._private_directory(path, created=created)
    assert security.inspect(path) == before
    assert (path / "preserved.txt").read_text() == "preserve"


def test_backup_directory_creation_authority_is_explicit_boolean(tmp_path):
    path = tmp_path / "empty"
    path.mkdir()
    with pytest.raises(ValueError, match="boolean"):
        backup._private_directory(path, created=1)
    assert not list(path.iterdir())
