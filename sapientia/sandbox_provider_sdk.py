"""Provider-owned HTTPS worker for the opt-in signed sandbox exchange.

Pass an Ed25519 key from the provider's credential vault and an analysis callback
backed by that provider's real engine/service. This SDK does not execute sample
bytes, contain a malware ML model, or send samples to a hard-coded vendor. The
server only exposes samples after explicit, peer-approved access was enabled.
"""

import base64
import copy
import hashlib
import json
import math
import re
import secrets
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import endpoint_artifacts, sandbox_provider
from .storage import encode

PREFIX = "/api/xdr/advanced/provider-exchange"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Provider SDK refuses redirects")


class HTTPSTransport:
    def __init__(self, base_url, ca_file=None):
        self.base_url = _url(base_url)
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirect(),
        )

    def post(self, path, payload):
        if (
            not path.startswith(PREFIX + "/")
            or ".." in path
            or "?" in path
            or "#" in path
        ):
            raise ValueError("Provider SDK only uses its exact exchange paths")
        body = encode(payload).encode()
        if len(body) > 256 * 1024:
            raise ValueError("Provider request exceeds 256 KiB")
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                result = response.read(endpoint_artifacts.MAX_BYTES + 1)
                if len(result) > endpoint_artifacts.MAX_BYTES:
                    raise ValueError("Provider response exceeds bounded artifact size")
                return result, dict(response.headers)
        except urllib.error.HTTPError as exc:
            raise ValueError(
                f"Provider exchange rejected with HTTP {exc.code}"
            ) from None


def _url(value):
    if not isinstance(value, str):
        raise TypeError("Provider SDK requires an HTTPS base URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(char.isspace() for char in value)
    ):
        raise ValueError(
            "Provider SDK requires a bare HTTPS origin without credentials or redirects"
        )
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid provider HTTPS port") from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid provider HTTPS port")
    return value.rstrip("/")


class SandboxProviderWorker:
    def __init__(
        self,
        base_url,
        tenant,
        profile_id,
        key_id,
        private_key,
        *,
        ca_file=None,
        transport=None,
    ):
        self.base_url = _url(base_url)
        for item in (tenant, profile_id, key_id):
            if not isinstance(item, str) or not 1 <= len(item) <= 128:
                raise ValueError(
                    "Provider worker requires bounded tenant/profile/key identifiers"
                )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError(
                "Provider worker requires its actual Ed25519 signing credential"
            )
        self.tenant, self.profile_id, self.key_id = tenant, profile_id, key_id
        self.private_key = private_key
        # A transport injection supports in-process protocol tests. Production
        # defaults enforce CA/hostname verification, no proxy and no redirect.
        self.transport = transport or HTTPSTransport(self.base_url, ca_file)

    def credential(self, action, request_id="", data=None):
        payload = {
            "protocol": sandbox_provider.ACCESS_PROTOCOL,
            "tenant": self.tenant,
            "profile_id": self.profile_id,
            "key_id": self.key_id,
            "action": action,
            "request_id": request_id,
            "body_sha256": hashlib.sha256(
                encode(data).encode() if data is not None else b""
            ).hexdigest(),
            "nonce": secrets.token_hex(32),
            "issued_at": time.time(),
        }
        return {
            **payload,
            "signature": base64.b64encode(
                self.private_key.sign(encode(payload).encode())
            ).decode(),
        }

    def poll(self):
        body, _ = self.transport.post(
            PREFIX + "/poll", {"credential": self.credential("poll")}
        )
        if len(body) > 128 * 1024:
            raise ValueError("Provider manifest list exceeds 128 KiB")
        data = json.loads(body)
        if (
            not isinstance(data, dict)
            or data.get("protocol") != sandbox_provider.ACCESS_PROTOCOL
            or not isinstance(data.get("jobs"), list)
            or len(data["jobs"]) > 20
        ):
            raise ValueError("Invalid provider pending-job response")
        for manifest in data["jobs"]:
            self._manifest(manifest)
        return data["jobs"]

    def _manifest(self, manifest):
        if (
            not isinstance(manifest, dict)
            or manifest.get("protocol") != sandbox_provider.PROTOCOL
            or manifest.get("tenant") != self.tenant
            or manifest.get("profile_id") != self.profile_id
            or manifest.get("key_id") != self.key_id
            or manifest.get("provider_sample_pull_enabled") is not True
        ):
            raise ValueError(
                "Manifest is not bound to this opted-in provider credential"
            )
        for key in ("sha256", "nonce", "profile_digest"):
            if not isinstance(manifest.get(key), str) or not re.fullmatch(
                r"[0-9a-f]{64}", manifest[key]
            ):
                raise ValueError("Provider manifest has an invalid exact digest/nonce")
        if not isinstance(manifest.get("request_id"), str) or not re.fullmatch(
            r"[0-9a-f-]{36}", manifest["request_id"]
        ):
            raise ValueError("Provider manifest requires an exact request UUID")
        for key in ("created", "expires"):
            if type(manifest.get(key)) not in (int, float) or not math.isfinite(
                manifest[key]
            ):
                raise ValueError("Provider manifest time must be finite")
        if (
            not manifest["created"] <= time.time() < manifest["expires"]
            or manifest["expires"] - manifest["created"] > 86400
        ):
            raise ValueError("Provider manifest expired or has an invalid interval")

    def sample(self, manifest):
        self._manifest(manifest)
        path = PREFIX + "/" + manifest["request_id"] + "/sample"
        body, headers = self.transport.post(
            path, {"credential": self.credential("sample", manifest["request_id"])}
        )
        normalized = {key.lower(): value for key, value in headers.items()}
        if (
            len(body) > endpoint_artifacts.MAX_BYTES
            or hashlib.sha256(body).hexdigest() != manifest["sha256"]
            or normalized.get("x-sample-sha256") != manifest["sha256"]
        ):
            raise ValueError(
                "Provider sample bytes do not match the exact request digest"
            )
        return body

    def complete(self, manifest, analysis):
        self._manifest(manifest)
        if not isinstance(analysis, dict) or set(analysis) != {
            "provider_job_id",
            "verdict",
            "report",
        }:
            raise ValueError(
                "Analysis callback must return provider_job_id/verdict/report"
            )
        payload = {
            key: manifest[key]
            for key in (
                "protocol",
                "request_id",
                "nonce",
                "tenant",
                "artifact_id",
                "sha256",
                "provider",
                "key_id",
            )
        }
        payload.update(
            **analysis,
            report_digest=hashlib.sha256(
                encode(analysis["report"]).encode()
            ).hexdigest(),
            observed_at=time.time(),
        )
        result = {
            **payload,
            "signature": base64.b64encode(
                self.private_key.sign(encode(payload).encode())
            ).decode(),
        }
        sandbox_provider._result(
            result
        )  # Validate bounded protocol before any submission.
        body, _ = self.transport.post(
            PREFIX + "/" + manifest["request_id"] + "/result",
            {
                "credential": self.credential(
                    "complete", manifest["request_id"], result
                ),
                "result": result,
            },
        )
        receipt = json.loads(body)
        if (
            receipt.get("id") != manifest["request_id"]
            or receipt.get("state") != "completed_attested"
            or receipt.get("result", {}).get("provider_signature_verified") is not True
        ):
            raise ValueError(
                "Provider completion did not return the exact verified receipt"
            )
        return receipt

    def run_once(self, analyze):
        if not callable(analyze):
            raise TypeError("Provider worker requires a real analysis callback")
        receipts = []
        for manifest in self.poll():
            sample = self.sample(manifest)
            try:
                analysis = analyze(sample, copy.deepcopy(manifest))
            except Exception as exc:  # noqa: BLE001 - Record failed analysis; never manufacture a clean verdict.
                analysis = {
                    "provider_job_id": "failed-" + manifest["request_id"],
                    "verdict": "failed",
                    "report": {
                        "summary": "Provider callback failed: " + type(exc).__name__,
                        "findings": [],
                    },
                }
            receipts.append(self.complete(manifest, analysis))
        return receipts
