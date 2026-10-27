"""Synthetic endpoint-to-case qualification over real loopback HTTP/TLS.

No production URL or existing data directory is accepted. A fresh private,
explicitly marked store is created on every invocation. The retained service
serves TLS agent traffic on 8788 and the same application's browser UI on 8790.
Only bootstrap identities are created offline; workflows use the public API.
Credentials are written to a private file, never the report or command line.
"""

import argparse
import asyncio
import csv
import hashlib
import importlib.util
import io
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import time
import traceback
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import httpx

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.qualification import certificate

STAGING = Path(__file__).resolve().parents[1]
WORK = STAGING.parent
WORKSPACE = WORK.parent
TLS_PORT = 8788
UI_PORT = 8790
MARKER = ".qa-synthetic-only"
BASE = f"https://127.0.0.1:{TLS_PORT}"
UI_BASE = f"http://127.0.0.1:{UI_PORT}"


def private_directory(path):
    path.mkdir(parents=False, exist_ok=False)
    if os.name == "nt":
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
        )
        sid = next(csv.reader(io.StringIO(result.stdout.strip())))[1]
        subprocess.run(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
            ],
            check=True,
            capture_output=True,
        )
    else:
        path.chmod(0o700)


def valid_directory(path):
    path = path.resolve()
    if (
        path.parent != WORK.resolve()
        or not path.name.startswith("security-flow-")
        or not (path / MARKER).is_file()
        or (path / MARKER).read_text(encoding="utf-8") != "synthetic-only\n"
    ):
        raise ValueError("Only a newly marked private qualification directory is valid")
    return path


def ensure_free(port):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))


def serve(directory):
    """Child process owns one Store and two listeners, with one lifespan."""
    import uvicorn

    from sapientia import auth
    from sapientia.api import create_app
    from sapientia.storage import Settings

    directory = valid_directory(directory)
    for key in ("SAPIENTIA_XDR_CONFIG", "SAPIENTIA_SOAR_CONFIG"):
        os.environ.pop(key, None)
    os.environ["SAPIENTIA_AGENT_ENDPOINT_URL"] = BASE
    os.environ["SAPIENTIA_AGENT_CA_FILE"] = str(directory / "test-cert.pem")
    os.environ.pop("SAPIENTIA_AGENT_ALLOW_LOOPBACK_HTTP", None)
    details = json.loads((directory / "credentials.json").read_text(encoding="utf-8"))
    data = directory / "data"
    data.mkdir(exist_ok=True)
    (data / MARKER).write_text("synthetic-only\n", encoding="utf-8")
    app = create_app(Settings(data, min_free_bytes=0, workers=2))
    with app.state.store.control() as db:
        configured = bool(db.execute("SELECT 1 FROM users LIMIT 1").fetchone())
    if not configured:
        for name in ("qa_admin", "qa_other_admin"):
            person = details["accounts"][name]
            auth.create_user(
                app.state.store,
                name,
                person["password"],
                person["role"],
                person["tenant"],
            )
    common = {"host": "127.0.0.1", "proxy_headers": False, "access_log": False}
    primary = uvicorn.Server(
        uvicorn.Config(
            app,
            port=TLS_PORT,
            ssl_certfile=str(directory / "test-cert.pem"),
            ssl_keyfile=str(directory / "test-key.pem"),
            **common,
        )
    )
    browser = uvicorn.Server(
        uvicorn.Config(app, port=UI_PORT, lifespan="off", **common)
    )

    async def both():
        primary_task = asyncio.create_task(primary.serve())
        browser_task = asyncio.create_task(browser.serve())
        try:
            while not (directory / "stop").exists():
                if primary_task.done() or browser_task.done():
                    raise RuntimeError("A qualification listener stopped unexpectedly")
                await asyncio.sleep(0.1)
        finally:
            browser.should_exit = True
            await browser_task
            primary.should_exit = True
            await primary_task

    asyncio.run(both())


class Service:
    def __init__(self, directory):
        self.directory = directory
        self.process = None
        self.log = None
        self.starts = []
        self.context = ssl.create_default_context(
            cafile=str(directory / "test-cert.pem")
        )

    def start(self):
        ensure_free(TLS_PORT)
        ensure_free(UI_PORT)
        (self.directory / "stop").unlink(missing_ok=True)
        self.log = (self.directory / "server.log").open("ab")
        env = os.environ.copy()
        for key in ("SAPIENTIA_XDR_CONFIG", "SAPIENTIA_SOAR_CONFIG"):
            env.pop(key, None)
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(Path(__file__).resolve()),
                "--serve",
                str(self.directory),
            ],
            cwd=STAGING,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        deadline = time.monotonic() + 25
        with httpx.Client(verify=self.context, trust_env=False, timeout=1) as client:
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError(
                        "Isolated server exited; inspect its private log"
                    )
                try:
                    response = client.get(BASE + "/api/bootstrap")
                    if response.status_code == 200:
                        self.starts.append({"pid": self.process.pid, "at": time.time()})
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
        self.stop()
        raise TimeoutError("Isolated server did not become ready")

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            (self.directory / "stop").write_text("stop\n", encoding="utf-8")
            try:
                self.process.wait(timeout=40)
            except subprocess.TimeoutExpired:
                # This PID was created by this exact Service, never a looked-up PID.
                self.process.terminate()
                self.process.wait(timeout=10)
                raise RuntimeError(
                    "Isolated qualification server failed graceful shutdown"
                )
        if self.log:
            self.log.close()
            self.log = None


class Qualification:
    def __init__(self, directory, service, details):
        self.directory, self.service, self.details = directory, service, details
        self.clients = {}
        self.checks = []
        self.scenarios = []
        self.endpoint_agents = {}
        self.agent_packages = []
        self.with_agents = False
        self.start = int(time.time()) - 180
        self.end = self.start + 120

    def record(self, name, **evidence):
        self.checks.append({"name": name, "passed": True, **evidence})
        print(json.dumps({"check": name, "passed": True}), flush=True)

    def request(self, client, method, path, *, expected=200, **kwargs):
        try:
            response = client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise AssertionError(
                f"{method} {path.split('?')[0]}: transport {type(exc).__name__}"
            ) from None
        if response.status_code != expected:
            # Never print bodies: validation adapters may contain input secrets.
            raise AssertionError(
                f"{method} {path.split('?')[0]}: HTTP {response.status_code}, expected {expected}"
            )
        return response

    def json(self, client, method, path, **kwargs):
        return self.request(client, method, path, **kwargs).json()

    def login(self, name):
        old = self.clients.pop(name, None)
        if old:
            old.close()
        client = httpx.Client(
            base_url=BASE,
            verify=self.service.context,
            trust_env=False,
            timeout=10,
            follow_redirects=False,
            headers={"Origin": BASE},
        )
        self.clients[name] = client
        person = self.details["accounts"][name]
        session = self.json(
            client,
            "POST",
            "/api/login",
            json={"name": name, "password": person.get("initial", person["password"])},
        )
        client.headers["X-CSRF-Token"] = session["csrf"]
        if session["must_change"]:
            self.request(client, "GET", "/api/playbooks", expected=403)
            self.json(
                client,
                "POST",
                "/api/me/password",
                json={"current": person["initial"], "password": person["password"]},
            )
            person.pop("initial", None)
            session = self.json(
                client,
                "POST",
                "/api/login",
                json={"name": name, "password": person["password"]},
            )
            client.headers["X-CSRF-Token"] = session["csrf"]
        assert (
            session["role"] == person["role"] and session["tenant"] == person["tenant"]
        )
        return client

    def wait(self, client, path, predicate, seconds=12, **kwargs):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = self.json(client, "GET", path, **kwargs)
            if predicate(value):
                return value
            time.sleep(0.1)
        raise TimeoutError(f"Timed out waiting for public API state: {path}")

    def accounts(self):
        admin = self.login("qa_admin")
        self.login("qa_other_admin")
        # New local users really pass the API's required initial password change.
        # Login attempts are per-IP bounded, so bootstrap avoids redundant logins.
        for name in ("qa_analyst", "qa_approver", "qa_viewer", "qa_windows_reader"):
            person = self.details["accounts"][name]
            self.json(
                admin,
                "POST",
                "/api/users",
                json={
                    "name": name,
                    "password": person["initial"],
                    "role": person["role"],
                },
            )
            self.json(
                admin,
                "PUT",
                f"/api/users/{name}/indexes",
                json={"allowed_indexes": person["indexes"]},
            )
            self.login(name)
        self.record(
            "http_accounts_current_roles_tenant_indexes_and_required_password_change"
        )

    def event(self, ident, host, os_type, guid, at, action, *, pid=400, parent=None):
        process = {
            "guid": guid,
            "pid": pid,
            "name": "synthetic-review.exe"
            if os_type == "windows"
            else "synthetic-review",
            "command_line": "SYNTHETIC RECORD ONLY; no command or OS action executed",
        }
        if parent:
            process["parent"] = {"guid": parent}
        data = {
            "@timestamp": datetime.fromtimestamp(self.start + at, UTC).isoformat(),
            "host": {"id": host, "os": {"type": os_type}},
            "process": process,
            "user": {"name": "synthetic_operator"},
            "event": {
                "action": action,
                "severity": "high" if action == "credential_access" else "info",
            },
            "test": {"synthetic": True, "scenario": "security-flow-qualification"},
        }
        if action == "network_connection":
            data["source"] = {"ip": "192.0.2.10", "port": 53000}
            data["destination"] = {"ip": "198.51.100.20", "port": 443}
        return {"id": ident, "data": data}

    def rows(self, os_type):
        host = "QA-" + os_type.upper() + "-01"
        child, root = os_type + "-child-guid", os_type + "-root-guid"
        make = lambda ident, at, action, **kw: self.event(
            os_type + "-" + ident, host, os_type, child, at, action, parent=root, **kw
        )
        # Deliberately receive network, credential, child, parent in reverse time order.
        positive = [
            make("network", 30, "network_connection"),
            make("credential", 20, "credential_access"),
            make("process", 10, "process_created"),
            self.event(
                os_type + "-root", host, os_type, root, 0, "process_created", pid=100
            ),
            self.event(
                os_type + "-old-process",
                host,
                os_type,
                os_type + "-old-guid",
                2,
                "process_created",
                pid=400,
            ),
            self.event(
                os_type + "-old-end",
                host,
                os_type,
                os_type + "-old-guid",
                3,
                "process_terminated",
                pid=400,
            ),
        ]
        benign = [
            self.event(
                os_type + "-benign-process",
                host + "-BENIGN",
                os_type,
                "benign-guid",
                5,
                "process_created",
            ),
            self.event(
                os_type + "-benign-network",
                host + "-BENIGN",
                os_type,
                "benign-guid",
                30,
                "network_connection",
            ),
        ]
        wrong_order = [
            self.event(
                os_type + "-reversed-process",
                host + "-REVERSED",
                os_type,
                "reversed-guid",
                40,
                "process_created",
            ),
            self.event(
                os_type + "-reversed-credential",
                host + "-REVERSED",
                os_type,
                "reversed-guid",
                10,
                "credential_access",
            ),
            self.event(
                os_type + "-reversed-network",
                host + "-REVERSED",
                os_type,
                "reversed-guid",
                20,
                "network_connection",
            ),
        ]
        return host, positive, benign + wrong_order

    def module(self, name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        previous = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous
        return module

    def archive(self, response, platform, host=None):
        """Verify authenticated ZIP checksums before loading its local runtime."""
        blob = response.content
        assert len(blob) <= 2 * 1024 * 1024
        digest = hashlib.sha256(blob).hexdigest()
        assert response.headers["X-Package-SHA256"] == digest
        directory = self.directory / ("package-" + uuid.uuid4().hex)
        directory.mkdir()
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            names = archive.namelist()
            assert len(names) == len(set(names)) and len(names) <= 32
            for info in archive.infolist():
                name = info.filename
                target = (directory / name).resolve()
                assert target.is_relative_to(directory) and not Path(name).is_absolute()
                assert not info.is_dir() and info.file_size <= 1024 * 1024
                assert (info.external_attr >> 16) & 0o170000 != 0o120000
            manifest = json.loads(archive.read("manifest.json"))
            assert set(names) == set(manifest["files"]) | {"manifest.json"}
            for name, expected in manifest["files"].items():
                assert hashlib.sha256(archive.read(name)).hexdigest() == expected
            archive.extractall(directory)
        verifier = self.module(
            "qa_package_verify_" + uuid.uuid4().hex, directory / "verify_package.py"
        )
        verifier.verify(directory)
        assert manifest["platform"] == platform and not manifest["containment"]
        if host is None:
            assert not {"enrollment.token", "deployment.json", "ca.pem"} & set(names)
        else:
            assert (
                json.loads((directory / "deployment.json").read_text())["host"] == host
            )
        self.agent_packages.append(
            {
                "platform": platform,
                "host": host,
                "zip_sha256": digest,
                "files": len(names),
                "manifest_verified": True,
                "independent_signature": False,
            }
        )
        return directory

    def provision(self, platform, host, index, owner="qa_admin"):
        client = self.clients[owner]
        deployment = self.json(
            client,
            "POST",
            "/api/xdr/agents/deployments",
            expected=201,
            json={
                "platform": platform,
                "host": host,
                "index": index,
                "ttl_seconds": 600,
            },
        )
        assert "token" not in deployment and "credential" not in deployment
        foreign = (
            "qa_admin"
            if self.details["accounts"][owner]["tenant"] != "default"
            else "qa_other_admin"
        )
        self.request(
            self.clients[foreign],
            "POST",
            deployment["package_url"],
            json={},
            expected=404,
        )
        response = self.request(client, "POST", deployment["package_url"], json={})
        directory = self.archive(response, platform, host)
        definition = json.loads(
            (directory / "deployment.json").read_text(encoding="utf-8")
        )
        assert definition["endpoint_url"] == BASE and definition["index"] == index
        token = (directory / "enrollment.token").read_text(encoding="ascii")
        core = self.module(
            "qa_downloaded_agent_" + uuid.uuid4().hex, directory / "Agent" / "core.py"
        )
        config = {
            "state_dir": str(directory / "state"),
            "endpoint_url": BASE,
            "ca_file": str(directory / "ca.pem"),
            "tenant": definition["tenant"],
            "host": host,
            "send_batch_size": 200,
        }
        with httpx.Client(base_url=UI_BASE, trust_env=False, timeout=5) as insecure:
            self.request(
                insecure,
                "POST",
                "/api/agent/register",
                json={"enrollment_token": token, "version": core.VERSION},
                expected=403,
            )
        with httpx.Client(
            base_url=BASE, verify=self.service.context, trust_env=False, timeout=5
        ) as anonymous:
            self.request(
                anonymous,
                "POST",
                "/api/agent/register",
                json={
                    "enrollment_token": token,
                    "version": core.VERSION,
                    "tenant": "qa_other",
                },
                expected=400,
            )
        configured = subprocess.run(
            [
                sys.executable,
                "-I",
                str(directory / "configure.py"),
                "--directory",
                str(directory),
                "--deployment",
                str(directory / "deployment.json"),
                "--token-file",
                str(directory / "enrollment.token"),
                "--ca-file",
                str(directory / "ca.pem"),
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        assert json.loads(configured.stdout)["enrolled"]
        config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
        assert (
            config["tenant"] == definition["tenant"]
            and config["host"] == host
            and config["index"] == index
        )
        identity = {
            k: v
            for k, v in json.loads(
                (directory / "state" / "identity.json").read_text(encoding="utf-8")
            ).items()
            if k != "credential"
        }
        assert identity["host"] == host and identity["tenant"] == definition["tenant"]
        with httpx.Client(
            base_url=BASE, verify=self.service.context, trust_env=False, timeout=5
        ) as anonymous:
            self.request(
                anonymous,
                "POST",
                "/api/agent/register",
                json={"enrollment_token": token, "version": core.VERSION},
                expected=401,
            )
        secret_identity = json.loads(
            (directory / "state" / "identity.json").read_text(encoding="utf-8")
        )
        actor = httpx.Client(
            base_url=BASE,
            verify=self.service.context,
            trust_env=False,
            timeout=10,
            headers={
                "Authorization": "Bearer " + secret_identity["credential"],
            },
        )
        self.clients["agent-" + identity["agent_id"]] = actor
        public = {
            **identity,
            "platform": platform,
            "index": index,
            "deployment_id": deployment["id"],
        }
        self.endpoint_agents[host] = {
            "core": core,
            "config": config,
            "client": actor,
            "public": public,
        }
        self.request(client, "POST", deployment["package_url"], json={}, expected=409)
        return self.endpoint_agents[host]

    def agents(self):
        """Use the downloaded shared runtime, not an invented agent wire format."""
        status = self.json(
            self.clients["qa_admin"], "GET", "/api/xdr/agents/distribution"
        )
        assert (
            status["deployment_enabled"]
            and not status["containment"]
            and not status["remote_commands"]
        )
        self.request(
            self.clients["qa_analyst"],
            "POST",
            "/api/xdr/agents/deployments",
            json={},
            expected=403,
        )
        self.request(
            self.clients["qa_viewer"],
            "GET",
            "/api/xdr/agents/packages/windows",
            expected=403,
        )
        for platform in ("windows", "linux"):
            generic = self.request(
                self.clients["qa_analyst"],
                "GET",
                "/api/xdr/agents/packages/" + platform,
            )
            self.archive(generic, platform)
            host, _, _ = self.rows(platform)
            for candidate in (host, host + "-BENIGN", host + "-REVERSED"):
                self.provision(platform, candidate, "endpoint_" + platform)
        listed = self.json(self.clients["qa_admin"], "GET", "/api/xdr/agents")["agents"]
        assert len(listed) == 6 and all(
            "credential" not in a and "credential_digest" not in a for a in listed
        )
        visible = self.json(
            self.clients["qa_windows_reader"], "GET", "/api/xdr/agents"
        )["agents"]
        assert len(visible) == 3 and all(
            a["index"] == "endpoint_windows" for a in visible
        )
        assert (
            self.json(self.clients["qa_other_admin"], "GET", "/api/xdr/agents")[
                "agents"
            ]
            == []
        )
        self.record(
            "downloaded_windows_linux_packages_manifest_sha256_and_secret_free_generic_packages",
            packages=8,
        )
        self.record(
            "one_time_https_registration_six_bound_agents_and_tenant_index_scoped_inventory"
        )
        self.with_agents = True

    def deliver(self, records, index):
        if not self.with_agents:
            body = {"format": "agent", "index": index, "events": records}
            admitted = self.json(
                self.clients["qa_analyst"],
                "POST",
                "/api/xdr/intake",
                json=body,
                expected=202,
            )
            retry = self.json(
                self.clients["qa_analyst"],
                "POST",
                "/api/xdr/intake",
                json=body,
                expected=202,
            )
            assert retry["accepted"] == 0 and retry["duplicate"] == len(records)
            return admitted
        grouped = {}
        for row in records:
            grouped.setdefault(row["data"]["host"]["id"], []).append(row)
        accepted = 0
        for host, rows in grouped.items():
            endpoint = self.endpoint_agents[host]
            core, config = endpoint["core"], endpoint["config"]
            instance = core.Agent(config, None)
            instance.queue.add_many(rows)
            assert instance.queue.size() == len(rows)
            instance.queue.close()
            instance = core.Agent(config, None)
            observed = []
            post = instance.transport.post

            def lost_ack(route, body, credential=None, post=post, observed=observed):
                ack = post(route, body, credential)
                observed.append(
                    {
                        "accepted": ack["accepted"],
                        "duplicate": ack["duplicate"],
                        "durable": ack["durable"],
                        "searchable": ack["searchable"],
                    }
                )
                raise ConnectionError(
                    "SYNTHETIC lost ACK after real durable server admission"
                )

            instance.transport.post = lost_ack
            try:
                instance.flush()
            except ConnectionError:
                pass
            else:
                raise AssertionError(
                    "Synthetic lost-ACK simulation did not interrupt delivery"
                )
            assert instance.queue.size() == len(rows) and observed[0][
                "accepted"
            ] == len(rows)
            assert observed[0]["durable"] and not observed[0]["searchable"]
            instance.queue.close()
            instance = core.Agent(config, None)
            observed_retry = []
            retry_post = instance.transport.post

            def capture_retry(
                route,
                body,
                credential=None,
                retry_post=retry_post,
                observed_retry=observed_retry,
            ):
                ack = retry_post(route, body, credential)
                observed_retry.append(
                    {"accepted": ack["accepted"], "duplicate": ack["duplicate"]}
                )
                return ack

            instance.transport.post = capture_retry
            assert instance.transport.context.minimum_version >= ssl.TLSVersion.TLSv1_2
            assert instance.flush() == len(rows) and instance.queue.size() == 0
            assert observed_retry == [{"accepted": 0, "duplicate": len(rows)}]
            instance.transport.post = retry_post
            heartbeat = instance.heartbeat()
            assert heartbeat["capabilities"] == [] and instance.poll() is None
            instance.queue.close()
            self.request(
                endpoint["client"],
                "POST",
                "/api/agent/ingest",
                json={"events": rows, "index": "private"},
                expected=400,
            )
            other_host = json.loads(json.dumps(rows[:1]))
            other_host[0]["data"]["host"]["id"] = host + "-SPOOF"
            self.request(
                endpoint["client"],
                "POST",
                "/api/agent/ingest",
                json={"events": other_host},
                expected=401,
            )
            changed = json.loads(json.dumps(rows[:1]))
            changed[0]["data"]["event"]["action"] = "changed_content"
            self.request(
                endpoint["client"],
                "POST",
                "/api/agent/ingest",
                json={"events": changed},
                expected=409,
            )
            self.request(
                endpoint["client"],
                "POST",
                "/api/agent/poll",
                json={},
                headers={"X-Forwarded-Proto": "https"},
                expected=403,
            )
            with httpx.Client(base_url=UI_BASE, trust_env=False, timeout=5) as insecure:
                self.request(
                    insecure,
                    "POST",
                    "/api/agent/heartbeat",
                    json={"health": {}},
                    expected=403,
                )
            accepted += len(rows)
        return {"durable": True, "searchable": False, "accepted": accepted}

    def input(self):
        analyst, admin = self.clients["qa_analyst"], self.clients["qa_admin"]
        with httpx.Client(
            base_url=BASE, verify=self.service.context, trust_env=False
        ) as anonymous:
            self.request(anonymous, "POST", "/api/xdr/intake", json={}, expected=401)
        self.request(
            self.clients["qa_viewer"], "POST", "/api/xdr/intake", json={}, expected=403
        )
        token = analyst.headers.pop("X-CSRF-Token")
        try:
            self.request(analyst, "POST", "/api/xdr/intake", json={}, expected=403)
        finally:
            analyst.headers["X-CSRF-Token"] = token
        self.request(
            analyst,
            "POST",
            "/api/xdr/intake",
            json={},
            headers={"Origin": "https://example.invalid"},
            expected=403,
        )
        self.record("xdr_intake_anonymous_viewer_csrf_origin_guards")
        self.expected_total = 0
        for os_type in ("windows", "linux"):
            host, positive, negative = self.rows(os_type)
            index = "endpoint_" + os_type
            body = {"format": "agent", "index": index, "events": positive + negative}
            admitted = self.deliver(body["events"], index)
            assert admitted["durable"] and not admitted["searchable"]
            self.expected_total += len(body["events"])
            changed = json.loads(json.dumps(body))
            changed["events"][0]["data"]["event"]["action"] = "changed_content"
            self.request(analyst, "POST", "/api/xdr/intake", json=changed, expected=409)
            self.scenarios.append(
                {
                    "os": os_type,
                    "host": host,
                    "index": index,
                    "events": len(body["events"]),
                    "negative_hosts": [host + "-BENIGN", host + "-REVERSED"],
                }
            )
        denied = {
            "format": "agent",
            "index": "private",
            "events": [
                self.event(
                    "denied-private",
                    "QA-DENIED",
                    "windows",
                    "denied-guid",
                    1,
                    "process_created",
                )
            ],
        }
        self.request(analyst, "POST", "/api/xdr/intake", json=denied, expected=403)
        self.record(
            "endpoint_durable_admission_exact_retry_content_conflict_and_private_index_denial",
            events=self.expected_total,
        )
        if self.with_agents:
            self.record(
                "actual_downloaded_agent_queue_restart_lost_ack_retry_heartbeat_poll_and_host_index_https_binding",
                agents=6,
                events=self.expected_total,
            )
        params = {"start": self.start - 1, "end": self.end}
        telemetry = self.wait(
            analyst,
            "/api/xdr/telemetry",
            lambda x: x["total"] == self.expected_total,
            params=params,
        )
        assert telemetry["returned"] == self.expected_total
        for item in self.scenarios:
            tree = self.json(
                analyst,
                "GET",
                "/api/xdr/process-tree",
                params={**params, "host": item["host"]},
            )
            reused = [n for n in tree["nodes"] if n["pid"] == 400]
            assert len(reused) == 2 and len({n["guid"] for n in reused}) == 2
            child = next(
                n for n in tree["nodes"] if n["guid"] == item["os"] + "-child-guid"
            )
            root = next(
                n for n in tree["nodes"] if n["guid"] == item["os"] + "-root-guid"
            )
            assert child["parent"] == root["id"] and not root["placeholder"]
        self.record("out_of_order_parent_resolution_and_pid_reuse_stable_guids")
        # A separate tenant can own an identical host and source ID without
        # crossing the local user's tenant. The data's tenant text is untrusted.
        other = self.clients["qa_other_admin"]
        body = {
            "format": "agent",
            "index": "endpoint_windows",
            "events": [
                self.event(
                    "other-tenant",
                    "QA-WINDOWS-01",
                    "windows",
                    "other-secret-guid",
                    5,
                    "process_created",
                )
            ],
        }
        body["events"][0]["data"]["tenant"] = "default"
        self.json(other, "POST", "/api/xdr/intake", json=body, expected=202)
        self.wait(other, "/api/xdr/telemetry", lambda x: x["total"] == 1, params=params)
        assert (
            self.json(analyst, "GET", "/api/xdr/telemetry", params=params)["total"]
            == self.expected_total
        )
        windows = self.json(
            self.clients["qa_windows_reader"],
            "GET",
            "/api/xdr/telemetry",
            params=params,
        )
        assert windows["total"] == 11 and all(
            r["index_name"] == "endpoint_windows" for r in windows["rows"]
        )
        self.record("tenant_spoof_ignored_and_current_index_scoped_telemetry")
        # Keep admin referenced for later exact-index grants and audit checks.
        assert self.json(admin, "GET", "/api/me")["role"] == "admin"

    def detect(self):
        analyst = self.clients["qa_analyst"]
        for item in self.scenarios:
            definition = {
                "name": "SYNTHETIC " + item["os"] + " process / credential / network",
                "entity_field": "host",
                "window": 600,
                "interval": 30,
                "cooldown": 600,
                "risk_score": 70,
                "severity": "high",
                "mitre": ["T1003"],
                "steps": [
                    {
                        "name": action,
                        "filters": [
                            {"field": "index", "op": "eq", "value": item["index"]},
                            {"field": "source", "op": "eq", "value": "aegis-xdr"},
                            {"field": "raw.action", "op": "eq", "value": action},
                        ],
                    }
                    for action in (
                        "process_created",
                        "credential_access",
                        "network_connection",
                    )
                ],
            }
            preview = self.json(
                analyst,
                "POST",
                "/api/detections/preview",
                json={"definition": definition, "end": self.end},
            )
            assert (
                preview["match_count"] == 1
                and preview["matches"][0]["entity"] == item["host"]
            )
            assert not preview["persisted"]
            item["policy_id"] = self.json(
                analyst, "POST", "/api/detections", json=definition, expected=201
            )["id"]
        incidents = self.wait(analyst, "/api/incidents", lambda rows: len(rows) == 2)
        assert {r["entity"] for r in incidents} == {x["host"] for x in self.scenarios}
        for item in self.scenarios:
            item["incident_id"] = next(
                r["id"] for r in incidents if r["entity"] == item["host"]
            )
            self.json(
                analyst,
                "PATCH",
                f"/api/detections/{item['policy_id']}",
                json={"enabled": False, "version": 1},
            )
            detail = self.json(analyst, "GET", f"/api/incidents/{item['incident_id']}")
            assert detail["total_count"] == 1
            item["evidence_event_ids"] = detail["contributions"][0]["evidence"][
                "event_ids"
            ]
            assert len(item["evidence_event_ids"]) == 3
            self.request(
                self.clients["qa_other_admin"],
                "GET",
                f"/api/incidents/{item['incident_id']}/workspace",
                expected=404,
            )
        linux = next(x for x in self.scenarios if x["os"] == "linux")
        self.request(
            self.clients["qa_windows_reader"],
            "GET",
            f"/api/incidents/{linux['incident_id']}/workspace",
            expected=404,
        )
        self.record(
            "real_scheduler_ordered_correlation_two_cases_negative_controls_and_evidence",
            cases=2,
            negative_cases=0,
        )

    def request_runs(self):
        analyst = self.clients["qa_analyst"]
        for item in self.scenarios:
            case = "/api/incidents/" + item["incident_id"]
            self.json(
                analyst,
                "PUT",
                case + "/workspace",
                json={
                    "version": 0,
                    "priority": "high",
                    "due_at": time.time() + 3600,
                    "tags": ["synthetic", item["os"]],
                },
            )
            task = self.json(
                analyst,
                "POST",
                case + "/actions",
                json={
                    "request_id": item["os"] + "-task",
                    "action": {
                        "type": "add_task",
                        "title": "Review synthetic process/credential/network evidence",
                        "mandatory": True,
                        "assignee": "qa_analyst",
                    },
                },
            )
            self.request(
                analyst,
                "POST",
                case + "/actions",
                json={
                    "request_id": item["os"] + "-premature-close",
                    "action": {
                        "type": "set_status",
                        "status": "resolved",
                        "note": "SYNTHETIC required review still incomplete",
                    },
                },
                expected=409,
            )
            self.json(
                analyst,
                "PATCH",
                case + f"/tasks/{task['id']}",
                json={
                    "version": 1,
                    "status": "done",
                    "assignee": "qa_analyst",
                    "due_at": None,
                },
            )
            bookmark = {
                "event_id": item["evidence_event_ids"][0],
                "label": "SYNTHETIC original event evidence",
            }
            self.json(analyst, "POST", case + "/bookmarks", json=bookmark)
            assert self.json(analyst, "POST", case + "/bookmarks", json=bookmark)[
                "duplicate"
            ]
            book = {
                "name": "SYNTHETIC approved local " + item["os"] + " case resolution",
                "version": 0,
                "steps": [
                    {
                        "id": "review_note",
                        "action": {
                            "type": "add_note",
                            "note": "SYNTHETIC evidence reviewed after independent approval. No OS command or containment executed.",
                        },
                    },
                    {
                        "id": "followup",
                        "action": {
                            "type": "add_task",
                            "title": "SYNTHETIC optional follow-up",
                            "mandatory": False,
                            "assignee": "qa_analyst",
                        },
                    },
                    {
                        "id": "triage",
                        "action": {
                            "type": "set_status",
                            "status": "triage",
                            "note": "SYNTHETIC approved local case triage",
                        },
                    },
                    {
                        "id": "resolve",
                        "action": {
                            "type": "set_status",
                            "status": "resolved",
                            "note": "SYNTHETIC analyst reviewed all mandatory evidence tasks. No endpoint isolation claim.",
                        },
                    },
                ],
            }
            saved = self.json(analyst, "POST", "/api/playbooks", json=book)
            item["playbook_id"] = saved["id"]
            request = {
                "incident_id": item["incident_id"],
                "request_id": item["os"] + "-stable-run",
            }
            run_path = f"/api/playbooks/{saved['id']}/runs"
            run = self.json(analyst, "POST", run_path, json=request)
            item["run_id"] = run["id"]
            assert run["state"] == "pending_approval"
            assert self.json(analyst, "POST", run_path, json=request)["duplicate"]
            self.request(
                analyst,
                "POST",
                case + "/actions",
                json={
                    "request_id": run["id"] + ":review_note",
                    "action": {
                        "type": "add_note",
                        "note": "SYNTHETIC forged approval receipt must be rejected",
                    },
                },
                expected=400,
            )
            other = next(x for x in self.scenarios if x is not item)
            self.request(
                analyst,
                "POST",
                run_path,
                json={**request, "incident_id": other["incident_id"]},
                expected=409,
            )
            self.request(
                analyst,
                "POST",
                f"/api/playbook-runs/{run['id']}/approve",
                json={},
                expected=403,
            )
            self.request(
                self.clients["qa_viewer"],
                "POST",
                f"/api/playbook-runs/{run['id']}/approve",
                json={},
                expected=403,
            )
            self.request(
                self.clients["qa_other_admin"],
                "GET",
                f"/api/playbook-runs/{run['id']}",
                expected=404,
            )
            if item["os"] == "linux":
                self.request(
                    self.clients["qa_windows_reader"],
                    "POST",
                    f"/api/playbook-runs/{run['id']}/approve",
                    json={},
                    expected=404,
                )
            book["version"] = 1
            book["steps"] = [
                {
                    "id": "future_revision",
                    "action": {
                        "type": "add_note",
                        "note": "SYNTHETIC future revision must not execute in existing run",
                    },
                }
            ]
            assert (
                self.json(analyst, "PUT", f"/api/playbooks/{saved['id']}", json=book)[
                    "version"
                ]
                == 2
            )
        time.sleep(0.8)  # Allow multiple real scheduler ticks while unapproved.
        for item in self.scenarios:
            space = self.json(
                analyst, "GET", f"/api/incidents/{item['incident_id']}/workspace"
            )
            assert (
                space["notes_total"] == 0
                and len(space["tasks"]) == 1
                and space["incident"]["status"] == "new"
            )
            pending = self.json(analyst, "GET", f"/api/playbook-runs/{item['run_id']}")
            assert pending["state"] == "pending_approval" and all(
                s["attempts"] == 0 for s in pending["steps"]
            )
        self.record(
            "mandatory_task_gate_idempotent_bookmarks_runs_self_viewer_cross_tenant_approval_denial"
        )
        self.record(
            "unapproved_runs_have_no_side_effect_after_real_scheduler_ticks_and_immutable_revision"
        )

    def restart(self, stage):
        sessions = {
            name: {
                "cookies": httpx.Cookies(client.cookies),
                "headers": dict(client.headers),
            }
            for name, client in self.clients.items()
        }
        for client in self.clients.values():
            client.close()
        self.service.stop()
        self.service.start()
        self.clients = {
            name: httpx.Client(
                base_url=BASE,
                verify=self.service.context,
                trust_env=False,
                timeout=10,
                follow_redirects=False,
                **settings,
            )
            for name, settings in sessions.items()
        }
        for endpoint in self.endpoint_agents.values():
            endpoint["client"] = self.clients["agent-" + endpoint["public"]["agent_id"]]
        # Durable sessions survive clean restart; no extra credential requests.
        for name in ("qa_analyst", "qa_approver", "qa_admin"):
            assert self.json(self.clients[name], "GET", "/api/me")["name"] == name
        self.record("clean_restart_" + stage, start_count=len(self.service.starts))

    def execute(self):
        self.restart("pending_approval_durable")
        analyst, approver = self.clients["qa_analyst"], self.clients["qa_approver"]
        for item in self.scenarios:
            path = f"/api/playbook-runs/{item['run_id']}"
            assert self.json(analyst, "GET", path)["state"] == "pending_approval"
            approval = self.json(approver, "POST", path + "/approve", json={})
            assert (
                approval["state"] == "queued" and len(approval["approval_digest"]) == 64
            )
            complete = self.wait(
                analyst,
                path,
                lambda x: x["state"] in {"completed", "failed", "unknown"},
            )
            assert complete["state"] == "completed"
            assert (
                complete["revision"] == 1 and complete["approved_by"] == "qa_approver"
            )
            assert len(complete["steps"]) == 4 and all(
                s["attempts"] == 1 and s["state"] == "completed"
                for s in complete["steps"]
            )
            self.request(approver, "POST", path + "/approve", json={}, expected=409)
            space = self.json(
                analyst, "GET", f"/api/incidents/{item['incident_id']}/workspace"
            )
            assert (
                space["incident"]["status"] == "resolved" and space["notes_total"] == 1
            )
            assert (
                len(space["tasks"]) == 2
                and sum(t["mandatory"] for t in space["tasks"]) == 1
            )
            assert "future revision" not in space["notes"][0]["note"]
            item["final_status"] = "resolved"
            item["steps_completed_once"] = 4
        self.record(
            "different_active_analyst_approval_runtime_four_local_actions_and_resolved",
            completed_runs=2,
        )
        self.restart("completed_resolution_durable")
        analyst = self.clients["qa_analyst"]
        time.sleep(0.6)
        for item in self.scenarios:
            run = self.json(analyst, "GET", f"/api/playbook-runs/{item['run_id']}")
            space = self.json(
                analyst, "GET", f"/api/incidents/{item['incident_id']}/workspace"
            )
            assert run["state"] == "completed" and all(
                s["attempts"] == 1 for s in run["steps"]
            )
            assert (
                space["notes_total"] == 1
                and len(space["tasks"]) == 2
                and space["incident"]["status"] == "resolved"
            )
        summary = self.json(
            analyst,
            "GET",
            "/api/console/summary",
            params={"start": self.start - 1, "end": time.time() + 1},
        )
        audit = self.json(self.clients["qa_admin"], "GET", "/api/audit/integrity")
        assert audit["valid"]
        self.summary = summary
        self.audit = {key: audit[key] for key in ("valid", "count") if key in audit}
        self.record(
            "resolved_cases_completed_steps_and_no_duplicate_local_side_effect_after_restart"
        )
        self.record("audit_digest_chain_valid", **self.audit)

    def final_guards(self):
        analyst, admin = self.clients["qa_analyst"], self.clients["qa_admin"]
        for item in self.scenarios:
            case = "/api/incidents/" + item["incident_id"]
            space = self.json(analyst, "GET", case + "/workspace")
            mandatory = next(t for t in space["tasks"] if t["mandatory"])
            self.request(
                analyst,
                "POST",
                case + "/actions",
                json={
                    "request_id": item["os"] + "-closed-new-work",
                    "action": {
                        "type": "add_task",
                        "title": "SYNTHETIC must reopen closed case first",
                        "mandatory": True,
                    },
                },
                expected=409,
            )
            self.request(
                analyst,
                "PATCH",
                case + f"/tasks/{mandatory['id']}",
                json={
                    "version": mandatory["version"],
                    "status": "open",
                    "assignee": "qa_analyst",
                    "due_at": None,
                },
                expected=409,
            )
            assert (
                self.json(analyst, "GET", case + "/workspace")["incident"]["status"]
                == "resolved"
            )
        self.record(
            "closed_case_required_work_creation_reopening_and_forged_soar_receipt_rejected"
        )
        if not self.with_agents:
            return
        # A real TLS connection must fail without the private run's public CA.
        try:
            with httpx.Client(trust_env=False, timeout=3) as untrusted:
                untrusted.get(BASE + "/api/bootstrap")
        except httpx.ConnectError:
            pass
        else:
            raise AssertionError(
                "Synthetic TLS certificate unexpectedly trusted by system CA"
            )
        owner = "qa_enrollment_admin"
        self.details["accounts"][owner] = {
            "role": "admin",
            "tenant": "default",
            "indexes": ["*"],
            "initial": secrets.token_urlsafe(24),
            "password": secrets.token_urlsafe(24),
        }
        person = self.details["accounts"][owner]
        self.json(
            admin,
            "POST",
            "/api/users",
            json={"name": owner, "password": person["initial"], "role": "admin"},
        )
        self.login(owner)
        endpoint = self.provision("windows", "QA-OWNER-REVOKED", "_endpoint", owner)
        self.json(
            endpoint["client"],
            "POST",
            "/api/agent/heartbeat",
            json={"health": {"synthetic": True}},
        )
        self.json(
            admin, "PUT", f"/api/users/{owner}/indexes", json={"allowed_indexes": []}
        )
        self.request(
            endpoint["client"],
            "POST",
            "/api/agent/heartbeat",
            json={"health": {}},
            expected=401,
        )
        self.json(
            admin,
            "PUT",
            f"/api/users/{owner}/indexes",
            json={"allowed_indexes": ["_endpoint"]},
        )
        self.json(
            endpoint["client"],
            "POST",
            "/api/agent/heartbeat",
            json={"health": {"synthetic": True}},
        )
        self.json(admin, "DELETE", "/api/xdr/agents/" + endpoint["public"]["agent_id"])
        self.request(
            endpoint["client"], "POST", "/api/agent/poll", json={}, expected=401
        )
        with httpx.Client(
            base_url=BASE, verify=self.service.context, trust_env=False, timeout=5
        ) as no_agent:
            self.request(
                no_agent, "POST", "/api/agent/ingest", json={"events": []}, expected=401
            )
            self.request(
                no_agent,
                "POST",
                "/api/agent/heartbeat",
                json={"health": {}},
                headers={"Authorization": "Bearer " + "invalid" * 8},
                expected=401,
            )
        secondary = self.provision(
            "linux", "QA-OTHER-TENANT-BOUND", "_endpoint", "qa_other_admin"
        )
        self.request(
            secondary["client"],
            "POST",
            "/api/agent/ingest",
            json={
                "events": [
                    self.event(
                        "cross-tenant-agent-spoof",
                        "QA-WINDOWS-01",
                        "windows",
                        "foreign-guid",
                        0,
                        "process_created",
                    )
                ]
            },
            expected=401,
        )
        foreign = self.json(self.clients["qa_other_admin"], "GET", "/api/xdr/agents")[
            "agents"
        ]
        assert len(foreign) == 1 and foreign[0]["tenant"] == "_qa_other"
        assert all(
            a["tenant"] == "default"
            for a in self.json(admin, "GET", "/api/xdr/agents")["agents"]
        )
        self.record(
            "verified_tls_untrusted_ca_rejection_live_enrollment_owner_scope_and_dedicated_credential_revocation"
        )
        self.record(
            "agent_http_forwarded_header_missing_invalid_credentials_and_extra_tenant_index_fields_rejected"
        )
        self.record(
            "downloaded_configurator_cli_actual_tls_enrollment_and_server_valid_underscore_tenant_index"
        )

    def aggregates(self):
        summary = self.json(
            self.clients["qa_analyst"],
            "GET",
            "/api/console/summary",
            params={"start": self.start - 1, "end": time.time() + 1},
        )
        cases, issues = summary["cases"], summary["issues"]
        assert summary["telemetry"]["event_count"] == 22
        assert (
            cases["total"]
            == cases["resolved"]
            == cases["response_modes"]["completed"]
            == 2
        )
        assert cases["open"] == cases["false_positive"] == 0
        assert cases["response_outcomes"] == [
            {"response_mode": "completed", "status": "resolved", "count": 2}
        ]
        assert (
            cases["response_actions"]["soar"] == 8
            and cases["response_actions"]["manual"] == 2
        )
        assert (
            issues["correlation_evidence"]["total"] == 2
            and issues["combined_total"] is None
        )
        assert issues["saved_search_findings"]["total"] == 0
        audit = self.json(self.clients["qa_admin"], "GET", "/api/audit/integrity")
        assert audit["valid"]
        self.audit = {key: audit[key] for key in ("valid", "count") if key in audit}
        self.summary = summary
        self.record(
            "final_full_population_summary_two_resolved_cases_eight_soar_actions_separate_issue_counts_and_valid_audit",
            **self.audit,
        )

    def close(self):
        for client in self.clients.values():
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--report", type=Path, default=WORK / "security-flow-report.json"
    )
    parser.add_argument(
        "--stop-after",
        action="store_true",
        help="Stop only the service created by this run",
    )
    parser.add_argument(
        "--with-agents",
        action="store_true",
        help="Require the new packaged per-agent protocol",
    )
    args = parser.parse_args(argv)
    if args.serve:
        serve(args.serve)
        return 0
    report_path = args.report.resolve()
    if not (
        report_path.is_relative_to(WORK)
        or report_path.is_relative_to(WORKSPACE / "outputs")
    ):
        parser.error("Report must be within workspace work/ or outputs/")
    ensure_free(TLS_PORT)
    ensure_free(UI_PORT)
    directory = WORK / ("security-flow-" + uuid.uuid4().hex)
    private_directory(directory)
    (directory / MARKER).write_text("synthetic-only\n", encoding="utf-8")
    certificate(directory)
    roles = {
        "qa_admin": ("admin", "default", ["*"]),
        "qa_other_admin": ("admin", "_qa_other", ["*"]),
        "qa_analyst": ("analyst", "default", ["endpoint_windows", "endpoint_linux"]),
        "qa_approver": ("analyst", "default", ["endpoint_windows", "endpoint_linux"]),
        "qa_viewer": ("viewer", "default", ["endpoint_windows", "endpoint_linux"]),
        "qa_windows_reader": ("analyst", "default", ["endpoint_windows"]),
    }
    details = {
        "synthetic_only": True,
        "tls_url": BASE,
        "browser_url": UI_BASE,
        "accounts": {
            name: {
                "role": role,
                "tenant": tenant,
                "indexes": indexes,
                "password": secrets.token_urlsafe(24),
                **(
                    {"initial": secrets.token_urlsafe(24)}
                    if "admin" not in name
                    else {}
                ),
            }
            for name, (role, tenant, indexes) in roles.items()
        },
    }
    credentials_path = directory / "credentials.json"
    credentials_path.write_text(json.dumps(details, indent=2), encoding="utf-8")
    service = Service(directory)
    trial = Qualification(directory, service, details)
    report = {
        "schema": "vatex.security-flow-qualification.v1",
        "synthetic_only": True,
        "live_accessed": False,
        "transport": {
            "api": BASE,
            "certificate_verified": True,
            "browser": UI_BASE,
            "browser_agent_routes_expected": "HTTPS-only",
        },
        "limitations": [
            "Synthetic sensor records; no OS process, attack, isolation or containment executed",
            "Downloaded Windows/Linux shared agent runtime ran on the current test host with synthetic endpoint envelopes; native Event Log, /proc, audit and OS service installation were not exercised",
            "Local case actions only; no external webhook configured",
            "Clean process restarts verify durability, not power-loss durability or host failover",
            "The browser helper is loopback HTTP; actual endpoint credentials are only used over verified TLS",
            "An intermittent first cross-origin TLS POST using artificial Connection: close disconnected while ordinary pooled requests returned HTTP403; fail-closed transport observation, not fixed or an authorization bypass (work/security-flow-origin-repro.json)",
        ],
        "passed": False,
        "started_at": time.time(),
    }
    try:
        service.start()
        trial.accounts()
        # Save only inside the private directory after initial password changes.
        credentials_path.write_text(json.dumps(details, indent=2), encoding="utf-8")
        if args.with_agents:
            trial.agents()
        trial.input()
        trial.detect()
        trial.request_runs()
        trial.execute()
        trial.final_guards()
        trial.aggregates()
        report["passed"] = True
        report["console_summary"] = trial.summary
        report["audit"] = trial.audit
        report["agent_protocol"] = {
            "tested": args.with_agents,
            "wire_transport": "verified TLS",
            "downloaded_shared_runtime_executed": args.with_agents,
            "native_windows_linux_os_collectors_executed": False,
            "packages": trial.agent_packages,
            "agents": [a["public"] for a in trial.endpoint_agents.values()],
        }
    except Exception as exc:  # noqa: BLE001 - Persist a redacted failed-run report.
        report["failure"] = {
            "type": type(exc).__name__,
            "stage": trial.checks[-1]["name"] if trial.checks else "startup",
            "message": str(exc)
            if isinstance(exc, (AssertionError, TimeoutError, NotImplementedError))
            else "Inspect private server log and qualification source; no input secrets emitted",
            "frames": [
                {
                    "file": Path(frame.filename).name,
                    "line": frame.lineno,
                    "function": frame.name,
                }
                for frame in traceback.extract_tb(exc.__traceback__)
            ],
        }
    finally:
        trial.close()
        credentials_path.write_text(json.dumps(details, indent=2), encoding="utf-8")
        if args.stop_after or not report["passed"]:
            service.stop()
        report.update(
            {
                "checks": trial.checks,
                "scenarios": trial.scenarios,
                "server_starts": service.starts,
                "finished_at": time.time(),
                "server_retained": bool(
                    service.process and service.process.poll() is None
                ),
                "private_credentials_file": str(credentials_path),
            }
        )
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "checks": len(trial.checks),
                "report": str(report_path),
                "server_retained": report["server_retained"],
            }
        ),
        flush=True,
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
