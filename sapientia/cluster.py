"""Compare-and-append replicated transactions over a quorum JetStream journal.

Application nodes materialize identical control state; each owns its analytical
files. A transaction is published with the exact prior journal sequence. A
concurrent writer gets a conflict, never an unfenced local-only commit. SQLite
applies statements and the replay checkpoint in one FULL-synchronous transaction.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

import nats
from nats.js.api import DiscardPolicy, StorageType, StreamConfig
from nats.js.errors import APIError, NotFoundError

from .storage import CapacityError, ConflictError, encode

LOG = logging.getLogger("sapientia.cluster")
MAX_COMMAND = 8 * 1024 * 1024


@contextmanager
def _locked(lock, deadline=None):
    if deadline is None:
        lock.acquire()
    elif not lock.acquire(timeout=max(0, deadline - time.monotonic())):
        raise CapacityError("Replica lock deadline exceeded")
    try:
        yield
    finally:
        lock.release()


def _database_deadline(db, deadline):
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CapacityError("Replica database deadline exceeded")
        db.execute("PRAGMA busy_timeout=" + str(max(1, int(remaining * 1000))))
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)


class Bridge:
    def __init__(self, config):
        self.config = config
        self.stream = "SAP_" + config["cluster_id"].upper()
        self.subject = "sapientia." + config["cluster_id"] + ".transactions"
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(
            target=self.loop.run_forever, name="sapientia-quorum-client", daemon=True
        )
        self.thread.start()
        try:
            self.call(self.connect(), timeout=40)
        except Exception:
            if getattr(self, "nc", None):
                self.call(self.nc.close(), timeout=5)
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(5)
            raise

    def call(self, coroutine, timeout=12):
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        try:
            return future.result(timeout)
        except Exception:
            future.cancel()
            raise

    async def connect(self):
        context = None
        if any(urlsplit(s).scheme == "tls" for s in self.config["servers"]):
            context = ssl.create_default_context(cafile=self.config.get("ca"))
            if self.config.get("cert"):
                context.load_cert_chain(self.config["cert"], self.config["key"])
        self.nc = await nats.connect(
            servers=self.config["servers"],
            name="sapientia-" + self.config["node_id"],
            token=os.environ.get(self.config.get("token_env", "SAPIENTIA_NATS_TOKEN")),
            tls=context,
            connect_timeout=3,
            max_reconnect_attempts=-1,
            reconnect_time_wait=1,
            pending_size=MAX_COMMAND * 2,
        )
        self.js = self.nc.jetstream(timeout=3)
        deadline = time.monotonic() + 25
        while True:
            try:
                await self.js.account_info()
                break
            except nats.errors.TimeoutError:
                if time.monotonic() > deadline:
                    raise
                await asyncio.sleep(0.25)
        self.js = self.nc.jetstream(timeout=8)
        deadline = time.monotonic() + 25
        while True:
            try:
                try:
                    info = await self.js.stream_info(self.stream)
                except NotFoundError:
                    info = await self.js.add_stream(
                        StreamConfig(
                            name=self.stream,
                            subjects=[self.subject],
                            storage=StorageType.FILE,
                            num_replicas=self.config["replicas"],
                            discard=DiscardPolicy.NEW,
                            max_bytes=self.config.get(
                                "journal_max_bytes", 50 * 1024**3
                            ),
                            max_msg_size=MAX_COMMAND,
                            deny_delete=True,
                            deny_purge=True,
                        )
                    )
                break
            except (nats.errors.TimeoutError, APIError) as exc:
                transient = isinstance(exc, nats.errors.TimeoutError) or getattr(
                    exc, "err_code", None
                ) in {10005, 10008, 10058, 10059, 10075}
                if not transient or time.monotonic() > deadline:
                    raise
                await asyncio.sleep(0.25)
        if (
            info.config.num_replicas != self.config["replicas"]
            or info.config.storage != StorageType.FILE
            or info.config.discard != DiscardPolicy.NEW
            or info.config.max_age
            or info.config.subjects != [self.subject]
            or not info.config.deny_delete
            or not info.config.deny_purge
        ):
            raise RuntimeError(
                "Journal configuration violates replication/replay invariants"
            )
        if info.state.messages and info.state.first_seq != 1:
            raise RuntimeError(
                "Truncated journal requires a verified checkpoint restore"
            )

    async def publish(self, payload, expected, message_id):
        return await self.js.publish(
            self.subject,
            payload,
            headers={
                "Nats-Expected-Last-Sequence": str(expected),
                "Nats-Msg-Id": message_id,
            },
        )

    def append(self, payload, expected, message_id, timeout=12):
        if len(payload) > MAX_COMMAND:
            raise CapacityError("Replicated transaction exceeds 8 MiB")
        try:
            ack = self.call(
                self.publish(payload, expected, message_id), timeout=timeout
            )
            if ack.seq != expected + 1:
                raise RuntimeError("Unexpected journal acknowledgement sequence")
            return ack.seq
        except APIError as exc:
            if exc.err_code in {10071, 10100}:
                raise ConflictError(
                    "Cluster state changed concurrently; refresh and retry"
                ) from exc
            raise CapacityError("Quorum journal refused the transaction") from exc
        except ConflictError:
            raise
        except Exception as exc:
            # The commit may have succeeded before a timeout. Replay resolves it;
            # callers retry stable event IDs, never assume an uncertain write failed.
            raise CapacityError(
                "Quorum acknowledgement unavailable; retry stable event IDs"
            ) from exc

    async def read_available(self, operation, budget=10):
        # Recovery can briefly route reads to an unready leader. Retrying a
        # read is safe; this must NEVER be reused to blindly retry publications.
        deadline = time.monotonic() + budget
        delay = 0.1
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CapacityError("Journal read recovery deadline exceeded")
            try:
                return await asyncio.wait_for(operation(), timeout=min(3, remaining))
            except APIError as exc:
                if exc.code != 503 and exc.err_code not in {
                    10005,
                    10008,
                    10058,
                    10059,
                    10075,
                }:
                    raise
            except (
                nats.errors.TimeoutError,
                nats.errors.NoRespondersError,
                TimeoutError,
            ):
                pass
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CapacityError(
                    "Journal read unavailable; retry after broker recovery"
                )
            await asyncio.sleep(min(delay, remaining))
            delay = min(delay * 2, 0.75)

    def last_sequence(self, timeout=10):
        return self.call(
            self.read_available(
                lambda: self.js.stream_info(self.stream), budget=timeout
            ),
            timeout=timeout,
        ).state.last_seq

    def get(self, sequence, timeout=10):
        return self.call(
            self.read_available(
                lambda: self.js.get_msg(self.stream, seq=sequence), budget=timeout
            ),
            timeout=timeout,
        ).data

    def close(self):
        async def shutdown():
            try:
                await self.nc.close()
            except (ConnectionError, OSError):
                # Pinned nats-py sets CLOSED before flushing pending socket bytes.
                # Broker loss can make that flush fail before transport cleanup.
                if not self.nc.is_closed:
                    raise
            finally:
                transport = getattr(self.nc, "_transport", None)
                if transport is not None:
                    transport.close()
                tasks = [
                    task
                    for task in asyncio.all_tasks()
                    if task is not asyncio.current_task()
                ]
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        try:
            self.call(shutdown(), timeout=5)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(5)
            self.loop.close()


class Recorder:
    def __init__(self, db):
        self.db, self.statements = db, []

    def execute(self, sql, params=()):
        command = sql.lstrip().split(None, 1)[0].upper()
        if command in {"INSERT", "UPDATE", "DELETE", "REPLACE"}:
            self.statements.append({"sql": sql, "params": list(params), "many": False})
        elif command not in {"SELECT", "PRAGMA", "BEGIN", "WITH"}:
            raise ValueError("Cluster runtime disallows unversioned schema changes")
        return self.db.execute(sql, params)

    def executemany(self, sql, params):
        if sql.lstrip().split(None, 1)[0].upper() not in {
            "INSERT",
            "UPDATE",
            "DELETE",
            "REPLACE",
        }:
            raise ValueError("Invalid replicated batch")
        params = [list(p) for p in params]
        self.statements.append({"sql": sql, "params": params, "many": True})
        return self.db.executemany(sql, params)

    def __getattr__(self, name):
        if name in {"commit", "rollback", "cursor", "executescript"}:
            raise RuntimeError(
                "Bypassing replicated transaction boundaries is prohibited"
            )
        return getattr(self.db, name)


class Replica:
    def __init__(self, store, config_path):
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        for field in ("node_id", "cluster_id"):
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", config.get(field, "")):
                raise ValueError("Invalid cluster/node identifier")
        if config.get("replicas") not in {1, 3, 5}:
            raise ValueError("Quorum journal replica count must be 1, 3, or 5")
        servers = config.get("servers")
        if not isinstance(servers, list) or not servers:
            raise ValueError("Cluster servers required")
        for server in servers:
            url = urlsplit(server)
            if url.username or url.password or url.scheme not in {"nats", "tls"}:
                raise ValueError("Use token environment and nats/tls server URLs")
            if (
                url.hostname not in {"127.0.0.1", "localhost", "::1"}
                and url.scheme != "tls"
            ):
                raise ValueError("Remote replication requires verified TLS")
        key = os.environ.get(config.get("signing_key_env", "SAPIENTIA_CLUSTER_KEY"), "")
        if len(key.encode()) < 32:
            raise ValueError("Cluster signing key must contain at least 32 bytes")
        self.config, self.store, self.key = config, store, key.encode()
        self.stop = threading.Event()
        self.last_error, self.last_sync = None, None
        self.thread = None
        with store.control(local=True) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS replica_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),cluster_id TEXT NOT NULL,sequence INTEGER NOT NULL,digest TEXT NOT NULL)"
            )
            prior = db.execute("SELECT * FROM replica_state").fetchone()
            if prior and prior["cluster_id"] != config["cluster_id"]:
                raise ValueError("Data directory belongs to a different cluster")
            if not prior:
                if db.execute(
                    "SELECT 1 FROM users UNION ALL SELECT 1 FROM receipts LIMIT 1"
                ).fetchone():
                    raise ValueError(
                        "Joining requires a fresh directory or a verified cluster checkpoint"
                    )
                db.execute(
                    "INSERT INTO replica_state VALUES(1,?,0,?)",
                    (config["cluster_id"], "0" * 64),
                )
        self.bridge = Bridge(config)
        self.catch_up()

    def state(self, db):
        row = db.execute(
            "SELECT sequence,digest FROM replica_state WHERE singleton=1"
        ).fetchone()
        return row["sequence"], row["digest"]

    def pack(self, previous, digest, statements):
        command = {
            "version": 1,
            "cluster_id": self.config["cluster_id"],
            "previous_sequence": previous,
            "previous_digest": digest,
            "id": str(uuid.uuid4()),
            "statements": statements,
        }
        data = encode(command).encode()
        signature = hmac.new(self.key, data, hashlib.sha256).hexdigest()
        return (
            encode({"command": command, "signature": signature}).encode(),
            signature,
            command["id"],
        )

    def decode(self, payload):
        if len(payload) > MAX_COMMAND:
            raise RuntimeError("Journal command exceeds the replay limit")
        value = json.loads(payload)
        command, signature = value["command"], value["signature"]
        actual = hmac.new(
            self.key, encode(command).encode(), hashlib.sha256
        ).hexdigest()
        if (
            not hmac.compare_digest(signature, actual)
            or command.get("cluster_id") != self.config["cluster_id"]
            or command.get("version") != 1
        ):
            raise RuntimeError("Journal authentication/version mismatch")
        return command, signature

    def catch_up(self, target=None, deadline=None):
        with (
            _locked(self.store.write_lock, deadline),
            self.store.control(local=True) as db,
        ):
            _database_deadline(db, deadline)

            def remaining():
                budget = 10 if deadline is None else deadline - time.monotonic()
                if budget <= 0:
                    raise CapacityError("Replica catch-up deadline exceeded")
                return budget

            target = (
                self.bridge.last_sequence(timeout=remaining())
                if target is None
                else target
            )
            sequence, digest = self.state(db)
            if target < sequence:
                raise CapacityError(
                    "Journal leader is catching up to the acknowledged local checkpoint"
                )
            while sequence < target:
                payload = self.bridge.get(sequence + 1, timeout=remaining())
                command, signature = self.decode(payload)
                if (
                    command["previous_sequence"] != sequence
                    or command["previous_digest"] != digest
                ):
                    raise RuntimeError(
                        "Journal continuity failure; stop and restore a verified checkpoint"
                    )
                _database_deadline(db, deadline)
                db.execute("BEGIN IMMEDIATE")
                try:
                    for statement in command["statements"]:
                        sql = statement["sql"]
                        if sql.lstrip().split(None, 1)[0].upper() not in {
                            "INSERT",
                            "UPDATE",
                            "DELETE",
                            "REPLACE",
                        }:
                            raise RuntimeError("Unversioned replicated schema command")
                        method = db.executemany if statement["many"] else db.execute
                        method(sql, statement["params"])
                    sequence += 1
                    digest = signature
                    db.execute(
                        "UPDATE replica_state SET sequence=?,digest=? WHERE singleton=1",
                        (sequence, digest),
                    )
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
        self.last_sync = time.time()
        return target

    @contextmanager
    def control(self, deadline=None):
        with _locked(self.store.write_lock, deadline):
            try:
                self.catch_up(deadline=deadline)
            except (RuntimeError, ValueError):
                raise
            except Exception as exc:
                raise CapacityError("Replication catch-up unavailable") from exc
            with self.store.control(local=True) as db:
                _database_deadline(db, deadline)
                previous, digest = self.state(db)
                recorder = Recorder(db)
                try:
                    yield recorder
                    if recorder.statements:
                        payload, signature, message_id = self.pack(
                            previous, digest, recorder.statements
                        )
                        timeout = (
                            12 if deadline is None else deadline - time.monotonic()
                        )
                        if timeout <= 0:
                            raise CapacityError("Replica transaction deadline exceeded")
                        sequence = self.bridge.append(
                            payload, previous, message_id, timeout=timeout
                        )
                        db.execute(
                            "UPDATE replica_state SET sequence=?,digest=? WHERE singleton=1",
                            (sequence, signature),
                        )
                    db.commit()
                except Exception:
                    db.rollback()
                    raise

    def barrier(self, timeout=10):
        # A committed no-op is a linearization point, unlike a possibly stale
        # follower's stream-info response. CAS failures are safe to retry here.
        deadline = time.monotonic() + timeout
        for _ in range(5):
            try:
                with self.control(deadline=deadline) as proxy:
                    previous, digest = self.state(proxy.db)
                    payload, signature, message_id = self.pack(previous, digest, [])
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise CapacityError("Replica read barrier deadline exceeded")
                    sequence = self.bridge.append(
                        payload, previous, message_id, timeout=remaining
                    )
                    proxy.db.execute(
                        "UPDATE replica_state SET sequence=?,digest=? WHERE singleton=1",
                        (sequence, signature),
                    )
                return sequence
            except ConflictError:
                continue
        raise CapacityError("Cluster is busy; retry the read barrier")

    def _pending(self, db, tenant=None, allowed_indexes=None):
        from .query import index_predicate

        predicate, args = index_predicate(allowed_indexes)
        where, values = ("", []) if tenant is None else (" WHERE tenant=?", [tenant])
        return db.execute(
            "SELECT count(*) FROM (SELECT json_extract(payload,'$.index') AS index_name FROM queue"
            + where
            + ") WHERE "
            + predicate,
            [*values, *args],
        ).fetchone()[0]

    @staticmethod
    def _retention_pending(db, tenant=None):
        return db.execute(
            "SELECT count(*) FROM retention_intents i LEFT JOIN retention_applied a ON a.id=i.id WHERE a.id IS NULL"
            + (" AND i.tenant=?" if tenant is not None else ""),
            [tenant] if tenant is not None else [],
        ).fetchone()[0]

    def readiness(
        self, min_sequence=0, *, tenant=None, allowed_indexes=None, timeout=1
    ):
        """Observed replay/index readiness; serving still requires a quorum barrier.

        Stream-info alone may be stale during a broker election. It is never a
        substitute for read_barrier, and this probe does not publish a command.
        """
        if type(min_sequence) is not int or min_sequence < 0:
            raise ValueError("Minimum replica sequence must be a nonnegative integer")
        deadline = time.monotonic() + max(0.001, min(10, timeout))
        error, target = None, None
        try:
            target = self.bridge.last_sequence(
                timeout=max(0.001, deadline - time.monotonic())
            )
        except Exception as exc:  # noqa: BLE001 - Status probes report unavailable infrastructure without serving data.
            error = type(exc).__name__
        with self.store.control(local=True) as db:
            sequence, _ = self.state(db)
            pending = self._pending(db, tenant, allowed_indexes)
            retention = self._retention_pending(db, tenant)
        ready = (
            target is not None
            and sequence == target
            and sequence >= min_sequence
            and pending == 0
            and retention == 0
            and not self.last_error
        )
        return {
            "ready": ready,
            "node_id": self.config["node_id"],
            "dataset_id": "cluster_" + self.config["cluster_id"],
            "replica_set": self.config["cluster_id"],
            "applied_sequence": sequence,
            "journal_sequence": target,
            "journal_lag": None if target is None else target - sequence,
            "pending_index_events": pending,
            "minimum_sequence": min_sequence,
            "pending_retention_intents": retention,
            "quorum_verified": False,
            "requires_read_barrier": True,
            "error": error or self.last_error,
        }

    def read_barrier(
        self, min_sequence=0, *, tenant=None, allowed_indexes=None, timeout=10
    ):
        """Fence a read at an acknowledged journal sequence; refuse index backlog.

        Catch-up synchronizes control state, not the independent DuckDB files.
        This intentionally refuses a read until the selected scope has drained.
        It never flushes, changes membership or elects an application writer.
        """
        if type(min_sequence) is not int or min_sequence < 0:
            raise ValueError("Minimum replica sequence must be a nonnegative integer")
        deadline = time.monotonic() + timeout
        sequence = self.barrier(timeout=max(0.001, deadline - time.monotonic()))
        if sequence < min_sequence:
            raise CapacityError("Replica is behind the required journal sequence")
        with (
            _locked(self.store.flush_lock, deadline),
            _locked(self.store.write_lock, deadline),
            self.store.control(local=True) as db,
        ):
            _database_deadline(db, deadline)
            current, _ = self.state(db)
            pending = self._pending(db, tenant, allowed_indexes)
            retention = self._retention_pending(db, tenant)
        if pending or retention:
            raise CapacityError(
                "Replica analytical index is not ready; pending admitted events or retention"
            )
        if time.monotonic() >= deadline:
            raise CapacityError("Replica read barrier deadline exceeded")
        return {
            "ready": True,
            "node_id": self.config["node_id"],
            "dataset_id": "cluster_" + self.config["cluster_id"],
            "replica_set": self.config["cluster_id"],
            "applied_sequence": current,
            "barrier_sequence": sequence,
            "pending_index_events": 0,
            "pending_retention_intents": 0,
            "quorum_verified": True,
            "requires_read_barrier": False,
        }

    def start(self):
        self.thread = threading.Thread(
            target=self.loop, name="sapientia-replica", daemon=True
        )
        self.thread.start()

    def loop(self):
        while not self.stop.wait(0.1):
            try:
                self.catch_up()
                self.last_error = None
            except Exception as exc:  # noqa: BLE001 - Background replication records failures for readiness diagnostics.
                self.last_error = type(exc).__name__
                LOG.warning("Replication is pending: %s", self.last_error)

    def status(self):
        with self.store.control(local=True) as db:
            sequence, digest = self.state(db)
        return {
            "node_id": self.config["node_id"],
            "cluster_id": self.config["cluster_id"],
            "replicas": self.config["replicas"],
            "applied_sequence": sequence,
            "last_sync": self.last_sync,
            "error": self.last_error,
            "mode": "replicated-full-copy",
            "digest": digest,
        }

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(15)
            if self.thread.is_alive():
                raise RuntimeError("Replication worker has not stopped")
        self.bridge.close()
