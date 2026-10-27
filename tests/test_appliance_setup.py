from fastapi.testclient import TestClient

from sapientia.api import create_app
from sapientia.storage import Settings


def test_remote_enrollment_requires_explicit_https(tmp_path):
    app = create_app(
        Settings(tmp_path, min_free_bytes=0, appliance_setup=True), background=False
    )
    with TestClient(
        app, base_url="http://appliance", client=("192.0.2.10", 1234)
    ) as client:
        assert (
            client.post(
                "/api/setup",
                json={"name": "admin", "password": "Long-test-password-2026"},
            ).status_code
            == 403
        )
    app = create_app(
        Settings(tmp_path, min_free_bytes=0, appliance_setup=True), background=False
    )
    with TestClient(
        app, base_url="https://appliance", client=("192.0.2.10", 1234)
    ) as client:
        assert (
            client.post(
                "/api/setup",
                json={"name": "admin", "password": "Long-test-password-2026"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/setup",
                json={"name": "admin2", "password": "Long-test-password-2026"},
            ).status_code
            == 400
        )


def test_remote_https_setup_disabled_by_default(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(
        app, base_url="https://appliance", client=("192.0.2.10", 1234)
    ) as client:
        assert (
            client.post(
                "/api/setup",
                json={"name": "admin", "password": "Long-test-password-2026"},
            ).status_code
            == 403
        )
