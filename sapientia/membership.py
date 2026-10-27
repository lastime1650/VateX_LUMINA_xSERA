"""Version-bound appliance membership. The Master alone allocates Slave ranks.

Membership and data-plane readiness are deliberately separate: an enrollment
never claims that historical logs or journal replicas are already synchronized.
"""

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import __version__, auth
from .storage import CapacityError, ConflictError, encode

# Stable membership wire identifier; visible product branding is in brand.py.
PRODUCT = "vatex-sapientia-siem"
PROTOCOL = 1


def initialize(store):
    # Install before journal replay, so membership transactions have their schema
    # on every replica, including a newly materialized node.
    with store.control(local=True) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS appliance_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL,product TEXT NOT NULL,version TEXT NOT NULL,protocol INTEGER NOT NULL,master_node TEXT NOT NULL,master_url TEXT NOT NULL,master_pin TEXT,password_hash TEXT NOT NULL,next_ordinal INTEGER NOT NULL,generation INTEGER NOT NULL,created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS appliance_members(group_id TEXT NOT NULL,node_id TEXT NOT NULL,ordinal INTEGER NOT NULL,url TEXT NOT NULL,certificate_pin TEXT,version TEXT NOT NULL,state TEXT NOT NULL,joined REAL NOT NULL,PRIMARY KEY(group_id,node_id),UNIQUE(group_id,ordinal));
        """)
        columns = {r[1] for r in db.execute("PRAGMA table_info(appliance_members)")}
        if "credential" not in columns:
            db.execute("ALTER TABLE appliance_members ADD COLUMN credential TEXT")
        if "last_seen" not in columns:
            db.execute("ALTER TABLE appliance_members ADD COLUMN last_seen REAL")
        for name in ("enrollment_digest", "enrollment_credential"):
            if name not in columns:
                db.execute("ALTER TABLE appliance_members ADD COLUMN " + name + " TEXT")


def node_identifier(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        raise ValueError("잘못된 장비 ID") from None
    return value


def origin(value):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("장비 주소가 필요합니다")
    url = urllib.parse.urlsplit(value)
    try:
        port = url.port
    except ValueError:
        raise ValueError("유효한 장비 포트가 필요합니다") from None
    if (
        url.scheme not in {"http", "https"}
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("경로·자격증명 없는 HTTPS 장비 주소를 입력하세요")
    loopback = url.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        pass
    if url.scheme == "http" and not loopback:
        raise ValueError("원격 장비 연결에는 HTTPS가 필요합니다")
    host = url.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    default_port = 443 if url.scheme == "https" else 80
    suffix = ":" + str(port) if port is not None and port != default_port else ""
    return url.scheme + "://" + host + suffix


def fingerprint(value):
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError("인증서 지문이 잘못되었습니다")  # noqa: TRY004 - API validation uses ValueError.
    value = value.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("SHA256 인증서 지문은 64자리 16진수여야 합니다")
    return value


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp = tempfile.mkstemp(prefix=".membership-", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encode(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class PinnedHTTPS(urllib.request.HTTPSHandler):
    """Verify the operator-supplied certificate pin before transmitting secrets."""

    def __init__(self, pin):
        super().__init__()
        self.pin = pin

    def https_open(self, request):
        import http.client

        pin = self.pin

        class Connection(http.client.HTTPSConnection):
            def connect(self):
                super().connect()
                actual = hashlib.sha256(
                    self.sock.getpeercert(binary_form=True)
                ).hexdigest()
                if not hmac.compare_digest(actual, pin):
                    self.sock.close()
                    raise ssl.SSLCertVerificationError(
                        "장비 인증서 지문이 일치하지 않습니다"
                    )

        # Pin verification replaces public CA discovery for device certificates;
        # it is mandatory and runs in connect(), before any HTTP headers/body.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return self.do_open(Connection, request, context=context)


def request_peer(address, path, data=None, pin=None):
    address = origin(address)
    handlers = [NoRedirect(), urllib.request.ProxyHandler({})]
    if pin:
        handlers.append(PinnedHTTPS(fingerprint(pin)))
    opener = urllib.request.build_opener(*handlers)
    payload = encode(data).encode() if data is not None else None
    request = urllib.request.Request(
        address + path, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with opener.open(request, timeout=12) as response:
            raw = response.read(256 * 1024 + 1)
            if len(raw) > 256 * 1024:
                raise ValueError("장비 응답 크기 초과")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("잘못된 장비 응답")  # noqa: TRY004 - API validation uses ValueError.
            return value
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read(8192)).get(
                "detail", "장비 연결 요청이 거부되었습니다"
            )
        except (ValueError, AttributeError):
            detail = "장비 연결 요청이 거부되었습니다"
        raise ValueError(str(detail)[:300]) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CapacityError(
            "장비에 연결할 수 없습니다. 주소·인증서·관리망을 확인하세요"
        ) from exc


class Membership:
    def __init__(self, store, transport=request_peer):
        self.store = store
        self.transport = transport
        self.file = store.path / "node-membership.json"
        self.enrollment_file = store.path / ".membership-enrollment.json"
        self.lock = threading.RLock()
        if not self.file.exists():
            atomic_json(self.file, {"node_id": str(uuid.uuid4()), "mode": "standalone"})
        self.node = json.loads(self.file.read_text(encoding="utf-8"))
        node_identifier(self.node.get("node_id"))
        if self.node.get("mode") not in {"standalone", "master", "slave"}:
            raise ValueError("손상된 장비 가입 설정. 백업 복구가 필요합니다")
        with store.control(local=True) as db:
            group = db.execute(
                "SELECT * FROM appliance_groups WHERE master_node=?",
                (self.node["node_id"],),
            ).fetchone()
        # Recover a Master creation interrupted between SQLite commit and file
        # rename. A committed group must never be silently replaced by a new one.
        if group and self.node["mode"] == "standalone":
            recovered = {
                "node_id": self.node["node_id"],
                "mode": "master",
                "group_id": group["id"],
                "master_url": group["master_url"],
                "master_pin": group["master_pin"],
                "ordinal": 0,
            }
            atomic_json(self.file, recovered)
            self.node = recovered

    def public_members(self, db, group_id):
        return [
            dict(row)
            for row in db.execute(
                "SELECT node_id,ordinal,url,certificate_pin,version,state,joined,last_seen FROM appliance_members WHERE group_id=? ORDER BY ordinal",
                (group_id,),
            )
        ]

    def discovery(self):
        result = {
            "product": PRODUCT,
            "version": __version__,
            "protocol": PROTOCOL,
            "node_id": self.node["node_id"],
            "mode": self.node["mode"],
        }
        if self.node["mode"] != "standalone":
            result.update(
                {k: self.node[k] for k in ("group_id", "master_url", "master_pin")}
            )
            result["ordinal"] = self.node["ordinal"]
        return result

    def status(self):
        descriptor = self.discovery()
        if self.node["mode"] == "standalone":
            return {
                **descriptor,
                "role": "Standalone",
                "members": [],
                "data_replication_ready": False,
            }
        if self.node["mode"] == "master":
            with self.store.control() as db:
                group = db.execute(
                    "SELECT name,next_ordinal,generation FROM appliance_groups WHERE id=?",
                    (self.node["group_id"],),
                ).fetchone()
                if not group:
                    raise ConflictError(
                        "Master 가입 기록을 찾을 수 없습니다. 백업 복구가 필요합니다"
                    )
                members = self.public_members(db, self.node["group_id"])
            descriptor.update(dict(group))
        else:
            members = self.node.get("members", [])
        # An enrolled group alone never enables, or proves, data-plane readiness.
        return {
            **descriptor,
            "role": "Master"
            if self.node["ordinal"] == 0
            else "Slave " + str(self.node["ordinal"]),
            "members": members,
            "membership_last_sync": self.node.get("membership_last_sync"),
            "data_replication_ready": False,
            "replication": self.store.replica.status() if self.store.replica else None,
            "safety": "장비 가입 제어면입니다. 가입만으로 로그·계정·정책이 복제되지 않습니다. 네트워크 단절 시 임의 Master 승격 금지.",
        }

    def create(self, who, data):
        if set(data) - {"name", "address", "password", "certificate_pin"}:
            raise ValueError("알 수 없는 클러스터 설정")
        name = data.get("name")
        password = data.get("password")
        if not isinstance(name, str) or not 1 <= len(name) <= 80:
            raise ValueError("클러스터 이름은 1..80자입니다")
        if not isinstance(password, str) or not 16 <= len(password) <= 128:
            raise ValueError("클러스터 암호는 16..128자입니다")
        address = origin(data.get("address"))
        pin = fingerprint(data.get("certificate_pin"))
        group_id = uuid.uuid4().hex
        password_hash = auth.PASSWORDS.hash(password)
        with self.lock, self.store.write_lock, self.store.control() as db:
            if (
                self.node["mode"] != "standalone"
                or db.execute("SELECT 1 FROM appliance_groups LIMIT 1").fetchone()
            ):
                raise ConflictError("이 장비는 이미 클러스터에 등록되어 있습니다")
            if self.store.replica:
                raise ConflictError(
                    "기존 복제 배포는 장비 가입 방식으로 별도 마이그레이션해야 합니다"
                )
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO appliance_groups VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    group_id,
                    name,
                    PRODUCT,
                    __version__,
                    PROTOCOL,
                    self.node["node_id"],
                    address,
                    pin,
                    password_hash,
                    1,
                    1,
                    time.time(),
                ),
            )
            db.execute(
                "INSERT INTO appliance_members(group_id,node_id,ordinal,url,certificate_pin,version,state,joined) VALUES(?,?,?,?,?,?,?,?)",
                (
                    group_id,
                    self.node["node_id"],
                    0,
                    address,
                    pin,
                    __version__,
                    "enrolled",
                    time.time(),
                ),
            )
            self.store.audit(
                db,
                who["tenant"],
                who["name"],
                "cluster.master.create",
                {"group_id": group_id, "name": name},
            )
        descriptor = {
            "node_id": self.node["node_id"],
            "mode": "master",
            "group_id": group_id,
            "master_url": address,
            "master_pin": pin,
            "ordinal": 0,
        }
        atomic_json(self.file, descriptor)
        self.node = descriptor
        return self.status()

    def accept(self, data):
        allowed = {
            "product",
            "version",
            "protocol",
            "node_id",
            "address",
            "certificate_pin",
            "password",
        }
        if (
            not isinstance(data, dict)
            or not allowed <= set(data)
            or set(data) - allowed - {"enrollment_nonce", "credential"}
        ):
            raise ValueError("잘못된 가입 요청")
        nonce = data.get("enrollment_nonce")
        proof = data.get("credential")
        for value in (nonce, proof):
            if value is not None and (
                not isinstance(value, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", value)
            ):
                raise ValueError("잘못된 장비 가입 증명")
        if (
            data["product"] != PRODUCT
            or data["version"] != __version__
            or data["protocol"] != PROTOCOL
        ):
            raise ConflictError(
                "동일한 제품·정확히 동일한 버전·가입 프로토콜만 연결할 수 있습니다"
            )
        node_id = node_identifier(data["node_id"])
        if (
            not isinstance(data["password"], str)
            or not 16 <= len(data["password"]) <= 128
        ):
            raise ValueError("잘못된 클러스터 암호")
        address = origin(data["address"])
        pin = fingerprint(data["certificate_pin"])
        if self.node["mode"] == "slave":
            # A Slave routes registration to the authoritative Master. It never
            # invents a local rank, including when Master connectivity is lost.
            return self.transport(
                self.node["master_url"],
                "/api/cluster/peer/join",
                data,
                self.node.get("master_pin"),
            )
        if self.node["mode"] != "master":
            raise ConflictError("대상 장비에서 먼저 Master를 구성하세요")
        with self.store.control() as db:
            group = db.execute(
                "SELECT * FROM appliance_groups WHERE id=?", (self.node["group_id"],)
            ).fetchone()
        if not group:
            raise ConflictError("Master 가입 기록이 없습니다")
        if not auth.check_password(group["password_hash"], data["password"]):
            raise ValueError("클러스터 암호가 일치하지 않습니다")
        credential = None
        with self.lock, self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT * FROM appliance_members WHERE group_id=? AND node_id=?",
                (group["id"], node_id),
            ).fetchone()
            if prior:
                if (
                    prior["ordinal"] == 0
                    or prior["url"] != address
                    or prior["certificate_pin"] != pin
                ):
                    raise ConflictError(
                        "기존 장비 ID의 주소·인증서가 다릅니다. 무단 교체를 허용하지 않습니다"
                    )
                ordinal = prior["ordinal"]
                if prior["state"] == "recovery_required":
                    if nonce is None:
                        raise ConflictError(
                            "복구 가입에는 새 장비 가입 증명이 필요합니다"
                        )
                    credential = secrets.token_urlsafe(48)
                elif (
                    proof
                    and prior["credential"]
                    and hmac.compare_digest(prior["credential"], auth.digest(proof))
                ):
                    # A normal retry never rotates a functioning member's key.
                    credential = proof
                elif (
                    nonce
                    and prior["enrollment_digest"]
                    and prior["enrollment_credential"]
                    and hmac.compare_digest(
                        prior["enrollment_digest"], auth.digest(nonce)
                    )
                ):
                    from . import mfa

                    credential = mfa.decrypt(
                        self.store,
                        "membership:" + node_id,
                        prior["enrollment_credential"],
                    )
                elif nonce is not None or proof is not None:
                    raise ConflictError(
                        "기존 장비의 개별 가입 증명이 일치하지 않습니다"
                    )
                # A legacy duplicate can discover its original rank, but the
                # shared password must not retrieve or replace the individual key.
            else:
                ordinal = db.execute(
                    "SELECT next_ordinal FROM appliance_groups WHERE id=?",
                    (group["id"],),
                ).fetchone()[0]
                if ordinal > 31:
                    raise CapacityError("장비 가입 한도 32대에 도달했습니다")
                if db.execute(
                    "SELECT 1 FROM appliance_members WHERE group_id=? AND url=?",
                    (group["id"], address),
                ).fetchone():
                    raise ConflictError("같은 주소의 장비가 이미 등록되어 있습니다")
                db.execute(
                    "INSERT INTO appliance_members(group_id,node_id,ordinal,url,certificate_pin,version,state,joined) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        group["id"],
                        node_id,
                        ordinal,
                        address,
                        pin,
                        __version__,
                        "enrolled",
                        time.time(),
                    ),
                )
                db.execute(
                    "UPDATE appliance_groups SET next_ordinal=next_ordinal+1,generation=generation+1 WHERE id=?",
                    (group["id"],),
                )
                self.store.audit(
                    db,
                    "default",
                    "cluster-master",
                    "cluster.slave.enroll",
                    {"group_id": group["id"], "node_id": node_id, "ordinal": ordinal},
                )
                credential = secrets.token_urlsafe(48)
            if credential and (not prior or prior["state"] == "recovery_required"):
                from . import mfa

                db.execute(
                    "UPDATE appliance_members SET credential=?,last_seen=?,state='enrolled',enrollment_digest=?,enrollment_credential=? WHERE group_id=? AND node_id=?",
                    (
                        auth.digest(credential),
                        time.time(),
                        auth.digest(nonce) if nonce else None,
                        mfa.encrypt(self.store, "membership:" + node_id, credential)
                        if nonce
                        else None,
                        group["id"],
                        node_id,
                    ),
                )
            members = self.public_members(db, group["id"])
        response = {
            "product": PRODUCT,
            "version": __version__,
            "protocol": PROTOCOL,
            "group_id": group["id"],
            "master_url": group["master_url"],
            "master_pin": group["master_pin"],
            "ordinal": ordinal,
            "members": members,
            "data_replication_ready": False,
        }
        if credential:
            response["credential"] = credential
        else:
            response["recovery_required"] = True
        return response

    def recover_member(self, who, node_id):
        """Explicit administrative revocation, separate from shared-password retries."""
        if who.get("role") != "admin" or who.get("tenant") != "default":
            raise PermissionError("장비 복구에는 기본 테넌트 관리자가 필요합니다")
        node_identifier(node_id)
        if self.node["mode"] != "master":
            raise ConflictError("Master에서 장비 복구를 수행하세요")
        with self.lock, self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            administrator = db.execute(
                "SELECT role,disabled FROM users WHERE name=? AND tenant='default'",
                (who["name"],),
            ).fetchone()
            if (
                not administrator
                or administrator["disabled"]
                or administrator["role"] != "admin"
            ):
                raise PermissionError("활성 기본 테넌트 관리자가 필요합니다")
            member = db.execute(
                "SELECT ordinal FROM appliance_members WHERE group_id=? AND node_id=?",
                (self.node["group_id"], node_id),
            ).fetchone()
            if not member or member["ordinal"] == 0:
                raise ValueError("복구할 Slave 장비를 찾을 수 없습니다")
            db.execute(
                "UPDATE appliance_members SET credential=NULL,enrollment_digest=NULL,enrollment_credential=NULL,state='recovery_required' WHERE group_id=? AND node_id=?",
                (self.node["group_id"], node_id),
            )
            self.store.audit(
                db,
                "default",
                who["name"],
                "cluster.slave.recovery",
                {"node_id": node_id},
            )
        return {"node_id": node_id, "recovery_required": True}

    def validate_response(self, response, address, pin):
        if (
            response.get("product") != PRODUCT
            or response.get("version") != __version__
            or response.get("protocol") != PROTOCOL
            or type(response.get("ordinal")) is not int
            or not 1 <= response["ordinal"] <= 31
            or not re.fullmatch(r"[a-f0-9]{32}", str(response.get("group_id", "")))
        ):
            raise ConflictError("Master의 제품·버전·가입 응답이 잘못되었습니다")
        master = origin(response.get("master_url"))
        master_pin = fingerprint(response.get("master_pin"))
        members = response.get("members")
        if not isinstance(members, list) or not 2 <= len(members) <= 32:
            raise ValueError("잘못된 장비 목록")
        ranks = set()
        identities = set()
        addresses = set()
        for member in members:
            if not isinstance(member, dict):
                raise ValueError("잘못된 장비 목록")  # noqa: TRY004 - API validation uses ValueError.
            rank = member.get("ordinal")
            identity = node_identifier(member.get("node_id"))
            url = origin(member.get("url"))
            if (
                type(rank) is not int
                or not 0 <= rank <= 31
                or rank in ranks
                or identity in identities
                or url in addresses
                or member.get("version") != __version__
            ):
                raise ValueError("중복되거나 버전이 다른 가입 장비")
            ranks.add(rank)
            identities.add(identity)
            addresses.add(url)
            if rank == 0 and (
                url != master
                or fingerprint(member.get("certificate_pin")) != master_pin
            ):
                raise ValueError("Master 신원이 일치하지 않습니다")
        own = [m for m in members if m["node_id"] == self.node["node_id"]]
        if (
            0 not in ranks
            or len(own) != 1
            or own[0]["ordinal"] != response["ordinal"]
            or own[0]["url"] != address
            or fingerprint(own[0].get("certificate_pin")) != pin
        ):
            raise ValueError("자신의 가입 기록을 검증할 수 없습니다")
        return master, master_pin

    def peer_status(self, data):
        if not isinstance(data, dict) or set(data) != {
            "group_id",
            "node_id",
            "credential",
        }:
            raise ValueError("잘못된 장비 인증 요청")
        if self.node["mode"] != "master" or data["group_id"] != self.node["group_id"]:
            raise ConflictError("이 장비는 요청 그룹의 Master가 아닙니다")
        node_identifier(data["node_id"])
        if not isinstance(data["credential"], str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{32,128}", data["credential"]
        ):
            raise ValueError("잘못된 장비 인증")
        with self.lock, self.store.write_lock, self.store.control() as db:
            member = db.execute(
                "SELECT * FROM appliance_members WHERE group_id=? AND node_id=?",
                (data["group_id"], data["node_id"]),
            ).fetchone()
            if (
                not member
                or not member["credential"]
                or not hmac.compare_digest(
                    member["credential"],
                    hashlib.sha256(data["credential"].encode()).hexdigest(),
                )
            ):
                raise ValueError("장비 인증이 일치하지 않습니다")
            db.execute(
                "UPDATE appliance_members SET last_seen=?,enrollment_digest=NULL,enrollment_credential=NULL WHERE group_id=? AND node_id=?",
                (time.time(), data["group_id"], data["node_id"]),
            )
            members = self.public_members(db, data["group_id"])
        return {
            "product": PRODUCT,
            "version": __version__,
            "protocol": PROTOCOL,
            "group_id": self.node["group_id"],
            "master_url": self.node["master_url"],
            "master_pin": self.node["master_pin"],
            "ordinal": member["ordinal"],
            "members": members,
        }

    def refresh(self):
        with self.lock:
            if self.node["mode"] != "slave":
                return self.status()
            response = self.transport(
                self.node["master_url"],
                "/api/cluster/peer/status",
                {k: self.node[k] for k in ("group_id", "node_id", "credential")},
                self.node.get("master_pin"),
            )
            own = next(
                m for m in self.node["members"] if m["node_id"] == self.node["node_id"]
            )
            self.validate_response(response, own["url"], own.get("certificate_pin"))
            if (
                response["group_id"] != self.node["group_id"]
                or response["master_url"] != self.node["master_url"]
                or response["master_pin"] != self.node["master_pin"]
                or response["ordinal"] != self.node["ordinal"]
            ):
                raise ConflictError("가입 그룹의 신원 변경을 거부했습니다")
            updated = {
                **self.node,
                "members": response["members"],
                "membership_last_sync": time.time(),
            }
            atomic_json(self.file, updated)
            self.node = updated
            return self.status()

    def join(self, who, data):
        if set(data) - {"peer", "peer_pin", "address", "certificate_pin", "password"}:
            raise ValueError("알 수 없는 가입 설정")
        with self.lock:
            if self.node["mode"] != "standalone":
                raise ConflictError("이 장비는 이미 클러스터에 등록되어 있습니다")
            if self.store.replica:
                raise ConflictError("기존 복제 배포는 별도 마이그레이션이 필요합니다")
            peer = origin(data.get("peer"))
            address = origin(data.get("address"))
            pin = fingerprint(data.get("certificate_pin"))
            if peer == address:
                raise ValueError("자기 자신을 가입 대상으로 사용할 수 없습니다")
            password = data.get("password")
            if not isinstance(password, str) or not 16 <= len(password) <= 128:
                raise ValueError("Master에 설정한 클러스터 암호가 필요합니다")
            enrollment = {
                "peer": peer,
                "peer_pin": fingerprint(data.get("peer_pin")),
                "address": address,
                "certificate_pin": pin,
            }
            if self.enrollment_file.exists():
                pending = json.loads(self.enrollment_file.read_text(encoding="utf-8"))
                if any(pending.get(k) != v for k, v in enrollment.items()):
                    raise ConflictError(
                        "이전 가입 재시도의 장비 주소가 다릅니다. 관리자 복구가 필요합니다"
                    )
                nonce = pending.get("enrollment_nonce")
                if not isinstance(nonce, str) or not re.fullmatch(
                    r"[A-Za-z0-9_-]{43,128}", nonce
                ):
                    raise ValueError("손상된 장비 가입 증명")
            else:
                nonce = secrets.token_urlsafe(48)
                atomic_json(
                    self.enrollment_file, {**enrollment, "enrollment_nonce": nonce}
                )
            response = self.transport(
                peer,
                "/api/cluster/peer/join",
                {
                    "product": PRODUCT,
                    "version": __version__,
                    "protocol": PROTOCOL,
                    "node_id": self.node["node_id"],
                    "address": address,
                    "certificate_pin": pin,
                    "password": password,
                    "enrollment_nonce": nonce,
                },
                fingerprint(data.get("peer_pin")),
            )
            master, master_pin = self.validate_response(response, address, pin)
            if (
                not isinstance(response.get("credential"), str)
                or not 32 <= len(response["credential"]) <= 128
            ):
                raise ValueError("가입 인증이 잘못되었습니다")
            descriptor = {
                "node_id": self.node["node_id"],
                "mode": "slave",
                "group_id": response["group_id"],
                "master_url": master,
                "master_pin": master_pin,
                "ordinal": response["ordinal"],
                "members": response["members"],
                "credential": response["credential"],
                "membership_last_sync": time.time(),
            }
            atomic_json(self.file, descriptor)
            self.node = descriptor
            self.enrollment_file.unlink(missing_ok=True)
            with self.store.write_lock, self.store.control() as db:
                self.store.audit(
                    db,
                    who["tenant"],
                    who["name"],
                    "cluster.slave.join",
                    {
                        "group_id": response["group_id"],
                        "ordinal": response["ordinal"],
                        "via": peer,
                    },
                )
            return self.status()
