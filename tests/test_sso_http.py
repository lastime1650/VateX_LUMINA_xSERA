from fastapi.testclient import TestClient

from sapientia import auth
from sapientia.api import create_app
from sapientia.storage import Settings


def test_sso_disabled_and_cookie_bound_mfa_http_flow(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(app) as client:
        assert client.get("/api/sso/status").json() == {"enabled": False}
        assert client.get("/api/sso/start").status_code == 404
        auth.create_user(
            app.state.store, "sso_user", "Synthetic-SSO-test-password-2026"
        )

        class Provider:
            def start(self):
                return {
                    "authorization_url": "https://identity.example/authorize?state=test-state",
                    "browser_token": "browser-proof",
                    "expires_in": 300,
                }

            def callback(self, state, code, browser):
                assert (state, code, browser) == (
                    "test-state",
                    "test-code",
                    "browser-proof",
                )
                return {
                    "mfa_required": True,
                    "challenge": "secret-challenge",
                    "expires_in": 180,
                }

            def complete_mfa(self, challenge, browser, otp):
                assert (challenge, browser, otp) == (
                    "secret-challenge",
                    "browser-proof",
                    "123456",
                )
                return auth.login(
                    app.state.store, "sso_user", "Synthetic-SSO-test-password-2026"
                )

        app.state.oidc = Provider()
        start = client.get("/api/sso/start", follow_redirects=False)
        assert (
            start.status_code == 303 and "identity.example" in start.headers["location"]
        )
        assert (
            "HttpOnly" in start.headers["set-cookie"]
            and "SameSite=lax" in start.headers["set-cookie"]
        )
        callback = client.get(
            "/api/sso/callback?state=test-state&code=test-code", follow_redirects=False
        )
        assert callback.headers["location"] == "/?sso_mfa=1"
        assert "secret-challenge" not in callback.headers["location"]
        assert "HttpOnly" in callback.headers["set-cookie"]
        blocked = client.post(
            "/api/sso/mfa",
            headers={"Origin": "https://attacker.example"},
            json={"otp": "123456"},
        )
        assert blocked.status_code == 403
        finished = client.post("/api/sso/mfa", json={"otp": "123456"})
        assert finished.status_code == 200 and "token" not in finished.json()
        assert (
            "HttpOnly" in finished.headers["set-cookie"]
            and "SameSite=strict" in finished.headers["set-cookie"]
        )
        assert client.get("/api/me").json()["name"] == "sso_user"
