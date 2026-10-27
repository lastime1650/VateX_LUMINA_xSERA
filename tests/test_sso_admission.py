import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from sapientia.api import create_app
from sapientia.storage import Settings


class Provider:
    def start(self):
        return {"authorization_url": "https://idp.example/authorize", "browser_token": "browser", "expires_in": 300}

    def callback(self, *args):
        raise ValueError("Invalid test callback")

    def complete_mfa(self, *args):
        raise ValueError("Invalid test authenticator")


def test_sso_start_and_callback_rate_limits_cannot_be_bypassed_with_proxy_headers(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    app.state.oidc = Provider()
    with TestClient(app) as client:
        for number in range(20):
            assert client.get("/api/sso/start", follow_redirects=False, headers={"X-Forwarded-For": f"198.51.100.{number}"}).status_code == 303
            assert client.get("/api/sso/callback?state=test&code=test").status_code == 400
        start = client.get("/api/sso/start", follow_redirects=False)
        callback = client.get("/api/sso/callback?state=test&code=test")
        assert start.status_code == callback.status_code == 429
        assert start.headers["retry-after"] == "60"


def test_sso_mfa_has_its_own_twelve_attempt_limit(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    app.state.oidc = Provider()
    with TestClient(app) as client:
        for _ in range(12):
            assert client.post("/api/sso/mfa", json={"otp": "000000"}).status_code == 400
        assert client.post("/api/sso/mfa", json={"otp": "000000"}).status_code == 429
        assert client.get("/api/sso/start", follow_redirects=False).status_code == 303


def test_sso_network_work_has_four_slots_and_failures_release_them(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    entered, release = threading.Event(), threading.Event()
    lock = threading.Lock()

    class Blocking(Provider):
        active, peak = 0, 0

        def start(self):
            with lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
                if self.active == 4:
                    entered.set()
            try:
                if not release.wait(5):
                    raise ValueError("Timed out waiting for isolated test release")
                raise ValueError("Simulated provider failure")
            finally:
                with lock:
                    self.active -= 1

    provider = Blocking()
    app.state.oidc = provider
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=4) as executor:
        pending = [executor.submit(client.get, "/api/sso/start", follow_redirects=False) for _ in range(4)]
        try:
            assert entered.wait(3)
            busy = client.get("/api/sso/start", follow_redirects=False)
            assert busy.status_code == 503 and busy.headers["retry-after"] == "5"
        finally:
            release.set()
        assert [future.result(timeout=5).status_code for future in pending] == [400] * 4
        assert provider.peak == 4
        app.state.oidc = Provider()
        # Every failed worker released its slot; later work can proceed.
        assert client.get("/api/sso/start", follow_redirects=False).status_code == 303
