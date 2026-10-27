"""Opt-in, signed, offline behavioral policies; event-time reactive protection.

This user-mode engine does not claim kernel interception or pre-execution AV.
Its executor is the same locally allowlisted, identity-checked typed responder.
An interrupted side effect is never automatically retried.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import time
import uuid
from pathlib import Path
from urllib.parse import quote

SCHEMA = "vatex.lumina.defense.v1"
MAX_BUNDLE = 1024 * 1024
FIELDS = {
    "event.action",
    "event.code",
    "event.provider",
    "host.os.type",
    "process.name",
    "process.executable",
    "process.command_line",
    "process.parent.name",
    "process.access.mask",
    "file.path",
    "file.hash.sha256",
    "registry.path",
    "dns.question.name",
    "destination.ip",
    "destination.port",
    "source.ip",
    "source.port",
    "driver.path",
    "dll.path",
    "user.name",
    "powershell.script_block",
    "memory.rwx_region_count",
    "memory.anonymous_executable_region_count",
}
OPS = {"eq", "contains", "startswith", "endswith", "in", "gte", "gt", "exists"}


def canonical(document):
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _file_stamp(stat):
    """Identify the opened bytes, including an atomic replacement with equal mtime."""
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate policy JSON key")
        result[key] = value
    return result


def _field(data, name):
    for part in name.split("."):
        if not isinstance(data, dict) or part not in data:
            return None
        data = data[part]
    return data


def _scalar(value):
    return (
        (type(value) is str and len(value) <= 8192)
        or type(value) is bool
        or (type(value) in (int, float) and math.isfinite(value))
    )


def _conditions(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 12:
        raise ValueError("Policy requires 1..12 bounded conditions")
    for c in values:
        if not isinstance(c, dict) or set(c) - {"field", "op", "value", "ignore_case"}:
            raise ValueError("Invalid policy condition")
        if c.get("field") not in FIELDS or c.get("op") not in OPS:
            raise ValueError("Unsupported local policy field/operator")
        if "ignore_case" in c and type(c["ignore_case"]) is not bool:
            raise ValueError("ignore_case must be boolean")
        value, op = c.get("value"), c["op"]
        if op == "exists":
            if type(value) is not bool:
                raise ValueError("exists requires boolean")
        elif op == "in":
            if (
                not isinstance(value, list)
                or not 1 <= len(value) <= 32
                or not all(_scalar(v) for v in value)
            ):
                raise ValueError("in requires bounded scalar list")
        elif op in {"gte", "gt"}:
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError("Numeric operator requires finite number")
        elif op in {"contains", "startswith", "endswith"}:
            if not isinstance(value, str) or not value or len(value) > 8192:
                raise ValueError("String condition requires nonempty bounded string")
        elif not _scalar(value):
            raise ValueError("Equality requires scalar")


def validate(document, config, now):
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "tenant",
        "host",
        "agent_id",
        "index",
        "revision",
        "issued_at",
        "expires_at",
        "rules",
    }:
        raise ValueError("Invalid signed policy document")
    if document["schema"] != SCHEMA or any(
        not isinstance(config.get(field), str)
        or not config[field]
        or document[field] != config[field]
        for field in ("tenant", "host", "agent_id", "index")
    ):
        raise ValueError("Policy schema/tenant/host/agent/index binding mismatch")
    if type(document["revision"]) is not int or not 1 <= document["revision"] <= 2**53:
        raise ValueError("Policy revision required")
    start, end = document["issued_at"], document["expires_at"]
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in (start, end)):
        raise ValueError("Policy times must be finite")
    if not start <= now + 300 or not start < end <= start + 30 * 86400 or end <= now:
        raise ValueError("Policy expired, future-issued or lifetime exceeds 30 days")
    rules = document["rules"]
    if not isinstance(rules, list) or len(rules) > 256:
        raise ValueError("At most 256 local rules")
    ids = set()
    for r in rules:
        if not isinstance(r, dict) or set(r) - {
            "id",
            "name",
            "enabled",
            "conditions",
            "exceptions",
            "action",
            "severity",
            "mitre",
        }:
            raise ValueError("Invalid local rule")
        if (
            not isinstance(r.get("id"), str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", r["id"])
            or r["id"] in ids
        ):
            raise ValueError("Unique bounded rule ID required")
        ids.add(r["id"])
        if type(r.get("enabled", False)) is not bool or r.get(
            "action", "observe"
        ) not in {"observe", "terminate_process", "quarantine_file", "allow_execution"}:
            raise ValueError("Invalid local action/enabled")
        if r.get("severity", "medium") not in {
            "info",
            "low",
            "medium",
            "high",
            "critical",
        }:
            raise ValueError("Invalid local severity")
        if (
            not isinstance(r.get("name", r["id"]), str)
            or not 1 <= len(r.get("name", r["id"])) <= 120
        ):
            raise ValueError("Invalid local rule name")
        tags = r.get("mitre", [])
        if (
            not isinstance(tags, list)
            or len(tags) > 16
            or not all(
                isinstance(v, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", v)
                for v in tags
            )
        ):
            raise ValueError("Invalid ATT&CK tags")
        _conditions(r.get("conditions"))
        exceptions = r.get("exceptions", [])
        if not isinstance(exceptions, list) or len(exceptions) > 16:
            raise ValueError("At most 16 local exception groups")
        for group in exceptions:
            _conditions(group)
    return document


def matches(data, conditions):
    for c in conditions:
        value, expected, op = _field(data, c["field"]), c["value"], c["op"]
        if op == "exists":
            hit = (value is not None) == expected
        elif value is None:
            hit = False
        elif op == "in":
            hit = any(
                type(value) is type(v)
                and (
                    value.casefold() == v.casefold()
                    if isinstance(value, str) and c.get("ignore_case", True)
                    else value == v
                )
                for v in expected
            )
        elif isinstance(value, str) and isinstance(expected, str):
            if c.get("ignore_case", True):
                value, expected = value.casefold(), expected.casefold()
            if op == "eq":
                hit = value == expected
            elif op == "contains":
                hit = expected in value
            elif op == "startswith":
                hit = value.startswith(expected)
            elif op == "endswith":
                hit = value.endswith(expected)
            else:
                hit = False
        elif op in {"gte", "gt"}:
            hit = (
                type(value) in (int, float)
                and math.isfinite(value)
                and (value >= expected if op == "gte" else value > expected)
            )
        else:
            hit = op == "eq" and type(value) is type(expected) and value == expected
        if not hit:
            return False
    return True


def _cache_policy_revision(config, key, revision, digest):
    """Persist only kernel cache trust; never open/create the reactive effect ledger.

    An existing reactive policy high-water mark is read through a read-only
    connection. The kernel cache's separate trust table then fences publication
    across restarts, including a crash before the verified JSON is replaced.
    """
    directory = Path(config["state_dir"])
    if not directory.is_absolute() or not directory.is_dir():
        raise PermissionError("Private existing absolute kernel cache state required")
    for path in (directory, *directory.parents):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PermissionError("Kernel policy cache paths may not contain links")
    if os.name != "nt":
        info = directory.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError(
                "Kernel cache state must be service-owned and private"
            )
    trust = hashlib.sha256(bytes.fromhex(key)).hexdigest()

    def check(old):
        if old and (revision < old[0] or revision == old[0] and digest != old[1]):
            raise ValueError("Kernel cached policy rollback or same-revision conflict")

    reactive = directory / "defense.sqlite3"
    if reactive.exists() or reactive.is_symlink():
        info = reactive.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise PermissionError(
                "Existing reactive policy trust database is not ordinary"
            )
        with sqlite3.connect(
            "file:"
            + quote(str(reactive.absolute()).replace("\\", "/"), safe="/:")
            + "?mode=ro",
            uri=True,
            timeout=0.2,
        ) as db:
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='policy_state'"
            ).fetchone()
            if exists:
                check(
                    db.execute(
                        "SELECT revision,digest FROM policy_state WHERE key=?", (trust,)
                    ).fetchone()
                )
    path = directory / "kernel-policy.sqlite3"
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise PermissionError("Kernel cache trust database is not ordinary")
    with sqlite3.connect(path, timeout=0.2) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute(
            "CREATE TABLE IF NOT EXISTS trust(key TEXT PRIMARY KEY,revision INTEGER,digest TEXT)"
        )
        check(
            db.execute(
                "SELECT revision,digest FROM trust WHERE key=?", (trust,)
            ).fetchone()
        )
        db.execute(
            "INSERT INTO trust VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET revision=excluded.revision,digest=excluded.digest",
            (trust, revision, digest),
        )
    if os.name != "nt":
        os.chmod(path, 0o600)


class Defense:
    def __init__(self, config, response_module, clock=time.time):
        self.config, self.response, self.clock = config, response_module, clock
        self.settings = config.get("defense", {})
        self.policy, self.digest, self.db = None, None, None
        self.bundle_stamp = None
        self.error = None
        self.coverage_error = None
        self.counters = {"evaluated": 0, "matched": 0, "succeeded": 0, "unknown": 0}
        if (
            not isinstance(self.settings, dict)
            or self.settings.get("enabled") is not True
        ):
            return
        try:
            self._load()
        except Exception as exc:  # noqa: BLE001 -- optional local protection must fail closed without stopping collection
            self.error = type(exc).__name__ + ": " + str(exc)[:240]

    def _load(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = self.settings.get("public_key")
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", key):
            raise ValueError("Pinned independent Ed25519 public key required")
        filename = self.settings.get("bundle_file")
        if (
            not isinstance(filename, str)
            or not Path(filename).is_absolute()
            or Path(filename).is_symlink()
        ):
            raise ValueError("Absolute non-symlink policy file required")
        with Path(filename).open("rb") as stream:
            stamp = _file_stamp(os.fstat(stream.fileno()))
            blob = stream.read(MAX_BUNDLE + 1)
            if _file_stamp(os.fstat(stream.fileno())) != stamp:
                raise ValueError("Policy file changed while reading")
        if len(blob) > MAX_BUNDLE:
            raise ValueError("Policy exceeds 1 MiB")
        bundle = json.loads(blob.decode("utf-8"), object_pairs_hook=_pairs)
        if (
            not isinstance(bundle, dict)
            or set(bundle) != {"document", "signature"}
            or not isinstance(bundle["signature"], str)
            or not re.fullmatch(r"[0-9a-fA-F]{128}", bundle["signature"])
        ):
            raise ValueError("Invalid signed bundle")
        body = canonical(bundle["document"])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(bundle["signature"]), body
        )
        document = validate(bundle["document"], self.config, self.clock())
        directory = Path(self.config["state_dir"])
        directory.mkdir(parents=True, exist_ok=True)
        if self.db:
            self.db.close()
        self.db = sqlite3.connect(directory / "defense.sqlite3", timeout=2)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS policy_state(key TEXT PRIMARY KEY,revision INTEGER,digest TEXT)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS local_effects(id TEXT PRIMARY KEY,state TEXT,event TEXT,created REAL,source_digest TEXT NOT NULL)"
        )
        digest = hashlib.sha256(body).hexdigest()
        trust = hashlib.sha256(bytes.fromhex(key)).hexdigest()
        old = self.db.execute(
            "SELECT revision,digest FROM policy_state WHERE key=?", (trust,)
        ).fetchone()
        if old and (
            document["revision"] < old["revision"]
            or document["revision"] == old["revision"]
            and digest != old["digest"]
        ):
            raise ValueError("Local policy rollback or same-revision content conflict")
        with self.db:
            self.db.execute(
                "INSERT INTO policy_state VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET revision=excluded.revision,digest=excluded.digest",
                (trust, document["revision"], digest),
            )
        self.policy, self.digest = document, digest
        # An update may replace the pathname during verification. Keep the
        # identity of the file we read so the next batch reloads that update.
        self.bundle_stamp = stamp
        self.error = None

    def update(self, bundle, *, cache_only=False):
        """Verify/publish; opt-in kernel caching never enables reactive execution.

        Ordinary reactive publication still does not access SQLite. A kernel
        cache-only publication writes its independent anti-rollback trust table
        and reads any prior reactive policy high-water mark without modifying it.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if type(cache_only) is not bool:
            raise ValueError("cache_only must be boolean")
        if (
            cache_only
            and self.config.get("kernel_prevention", {}).get("enabled") is not True
        ):
            raise PermissionError("Kernel cache requires explicit local kernel opt-in")
        if self.settings.get("enabled") is not True and not cache_only:
            return False
        if not isinstance(bundle, dict) or set(bundle) != {"document", "signature"}:
            raise ValueError("Invalid defense update bundle")
        key = self.settings.get("public_key")
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", key):
            raise ValueError("Pinned independent release key required")
        signature = bundle.get("signature")
        if not isinstance(signature, str) or not re.fullmatch(
            r"[0-9a-fA-F]{128}", signature
        ):
            raise ValueError("Invalid release signature")
        body = canonical(bundle["document"])
        if len(body) > MAX_BUNDLE - 256:
            raise ValueError("Defense update exceeds limit")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(signature), body
        )
        doc = validate(bundle["document"], self.config, self.clock())
        if self.policy:
            if doc["revision"] < self.policy["revision"]:
                raise ValueError("Policy update rollback refused")
            if doc["revision"] == self.policy["revision"]:
                if hashlib.sha256(body).hexdigest() != self.digest:
                    raise ValueError("Same-revision content conflict")
                if not cache_only:
                    return False
        path = Path(self.settings["bundle_file"])
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("Absolute non-symlink policy path required")
        path.parent.mkdir(parents=True, exist_ok=True)
        if cache_only:
            for ancestor in (path, *path.parents):
                if ancestor == path and not ancestor.exists():
                    continue
                info = ancestor.lstat()
                if (
                    stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & 0x400
                ):
                    raise PermissionError(
                        "Kernel policy cache paths may not contain links"
                    )
            _cache_policy_revision(
                self.config, key, doc["revision"], hashlib.sha256(body).hexdigest()
            )
        temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            with temp.open("x", encoding="utf-8") as stream:
                stream.write(canonical(bundle).decode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                os.chmod(temp, 0o600)
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
        return True

    def health(self):
        state = (
            "degraded"
            if self.error or self.coverage_error
            else "active"
            if self.policy and self.clock() < self.policy["expires_at"]
            else "expired"
            if self.policy
            else "disabled"
        )
        return {
            "state": state,
            "revision": self.policy["revision"] if self.policy else None,
            "rule_count": sum(r.get("enabled", False) for r in self.policy["rules"])
            if self.policy
            else 0,
            "policy_sha256": self.digest,
            "error": self.error or self.coverage_error,
            "last_batch_coverage_incomplete": self.coverage_error is not None,
            "reactive_user_mode": True,
            "kernel_pre_execution_protection": False,
            "engine": "signed_single_event_behavioral_conditions",
            "independent_malware_classifier": False,
            "evaluation_work": "durable_event_rule_cursor_in_agent_spool",
            **self.counters,
        }

    def _target(self, data, action):
        if action == "terminate_process":
            p = data.get("process", {})
            if (
                not isinstance(p, dict)
                or type(p.get("pid")) is not int
                or not p.get("guid")
                or not p.get("start_identity")
            ):
                raise ValueError("Exact native process identity required")
            return {
                "type": action,
                "pid": p["pid"],
                "process_guid": p["guid"],
                "start_identity": p["start_identity"],
            }
        f = data.get("file", {})
        hashes = f.get("hash", {}) if isinstance(f, dict) else {}
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        if (
            not isinstance(f, dict)
            or not f.get("path")
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", digest)
        ):
            raise ValueError("Canonical file path and SHA256 evidence required")
        return {
            "type": action,
            "path": f["path"],
            "sha256": f["hash"]["sha256"].lower(),
        }

    def evaluate_resumable(self, event, *, cursor=0, policy_digest=None):
        """Resume a durable event/rule work item without replaying an effect.

        The queue stores this cursor only after output records are durable.
        Changed policies restart evaluation; local_effects still fences each
        signed revision/rule/source identity independently.
        """
        if type(cursor) is not int or not 0 <= cursor <= 256:
            raise ValueError("Bounded local evaluation rule cursor required")
        records = self.evaluate(
            [event], _resume_rule=cursor, _resume_digest=policy_digest
        )
        ready = bool(
            self.policy and not self.error and self.clock() < self.policy["expires_at"]
        )
        return {
            "events": records,
            "cursor": getattr(self, "evaluation_cursor", 0),
            "policy_digest": self.digest,
            "complete": ready and self.evaluation_cursor is None,
        }

    def evaluate(self, events, *, _resume_rule=0, _resume_digest=None):
        self.evaluation_cursor = 0
        if self.settings.get("enabled") is True:
            try:
                if (
                    _file_stamp(Path(self.settings["bundle_file"]).stat())
                    != self.bundle_stamp
                ):
                    self._load()
            except Exception as exc:  # noqa: BLE001 -- invalid replacement must disable effects, not collection
                self.error = type(exc).__name__ + ": " + str(exc)[:240]
        if not self.policy or self.error or self.clock() >= self.policy["expires_at"]:
            return []
        if _resume_digest != self.digest:
            _resume_rule = 0
        # A prior incomplete batch is observable, but must not disable future
        # valid batches using the same verified policy.
        self.coverage_error = None
        if not isinstance(events, list) or len(events) > 2000:
            self.coverage_error = "Local evaluation batch bound exceeded"
            return []
        deadline, extra = time.monotonic() + 2, []
        history_count = self.db.execute(
            "SELECT count(*) FROM local_effects"
        ).fetchone()[0]
        for original in events:
            if not isinstance(original, dict):
                continue
            data = original.get("data")
            host = data.get("host") if isinstance(data, dict) else None
            if (
                not isinstance(data, dict)
                or not isinstance(host, dict)
                or host.get("id") != self.config["host"]
                or not isinstance(original.get("id"), str)
            ):
                continue
            event_data = data.get("event")
            if (
                not isinstance(event_data, dict)
                or event_data.get("module") == "local_defense"
            ):
                continue
            self.counters["evaluated"] += 1
            for rule_index, rule in enumerate(self.policy["rules"]):
                if rule_index < _resume_rule:
                    continue
                if time.monotonic() > deadline or len(extra) >= 200:
                    self.evaluation_cursor = rule_index
                    self.coverage_error = (
                        "Local evaluation budget exhausted; coverage incomplete"
                    )
                    return extra
                if (
                    not rule.get("enabled", False)
                    or rule.get("action") == "allow_execution"
                    or not matches(data, rule["conditions"])
                    or any(matches(data, group) for group in rule.get("exceptions", []))
                ):
                    continue
                identifier = hashlib.sha256(
                    canonical([self.digest, rule["id"], original["id"]])
                ).hexdigest()
                source_digest = hashlib.sha256(canonical(original)).hexdigest()
                old = self.db.execute(
                    "SELECT state,event,source_digest FROM local_effects WHERE id=?",
                    (identifier,),
                ).fetchone()
                if old and old["source_digest"] != source_digest:
                    self.error = "Source event ID content conflict"
                    return extra
                if old and old["state"] == "completed":
                    extra.append(json.loads(old["event"]))
                    continue
                action = rule.get("action", "observe")
                # Permanent execution/investigation history has no lifetime count ceiling.
                if old:
                    outcome = {
                        "success": False,
                        "executed": None,
                        "code": "unknown_after_restart",
                        "detail": "Local effect marker has no final receipt; action will not replay",
                    }
                    self.counters["unknown"] += 1
                elif action == "observe":
                    outcome = {"success": True, "executed": False, "code": "observed"}
                else:
                    try:
                        target = self._target(data, action)
                    except (ValueError, TypeError, KeyError) as exc:
                        outcome = {
                            "success": False,
                            "executed": False,
                            "code": "identity_unavailable",
                            "detail": str(exc),
                        }
                    else:
                        try:
                            with self.response.Lock(self.config["state_dir"]):
                                # Commit before side effect. A crash becomes unknown.
                                with self.db:
                                    self.db.execute(
                                        "INSERT INTO local_effects VALUES(?,'executing',NULL,?,?)",
                                        (identifier, self.clock(), source_digest),
                                    )
                                outcome = self.response.execute(
                                    target,
                                    self.config["host"],
                                    self.config.get("response", {}),
                                )
                        except Exception as exc:  # noqa: BLE001 -- any post-marker failure has an unknown effect and cannot replay
                            started = (
                                self.db.execute(
                                    "SELECT 1 FROM local_effects WHERE id=?",
                                    (identifier,),
                                ).fetchone()
                                is not None
                            )
                            outcome = {
                                "success": False,
                                "executed": None if started else False,
                                "code": "effect_unconfirmed"
                                if started
                                else "local_executor_busy_or_unavailable",
                                "detail": type(exc).__name__,
                            }
                result = copy.deepcopy(data)
                result["event"] = {
                    "module": "local_defense",
                    "action": "local_detection",
                    "severity": rule.get("severity", "medium"),
                }
                result["local_defense"] = {
                    "rule_id": rule["id"],
                    "rule_name": rule.get("name", rule["id"]),
                    "policy_sha256": self.digest,
                    "revision": self.policy["revision"],
                    "source_event_id": original["id"],
                    "action": action,
                    "mitre": rule.get("mitre", []),
                    "outcome": outcome,
                    "reactive_user_mode": True,
                    "verdict_basis": "signed_behavioral_rule_match",
                    "independently_attested_malware": False,
                }
                record = {"id": "local-defense-" + identifier, "data": result}
                with self.db:
                    self.db.execute(
                        "INSERT INTO local_effects VALUES(?,'completed',?,?,?) ON CONFLICT(id) DO UPDATE SET state='completed',event=excluded.event",
                        (
                            identifier,
                            json.dumps(record, ensure_ascii=False, allow_nan=False),
                            self.clock(),
                            source_digest,
                        ),
                    )
                history_count += int(old is None)
                self.counters["matched"] += 1
                self.counters["succeeded"] += int(
                    outcome.get("executed") is True and outcome.get("success") is True
                )
                extra.append(record)
        self.evaluation_cursor = None
        return extra

    def close(self):
        if self.db:
            self.db.close()
