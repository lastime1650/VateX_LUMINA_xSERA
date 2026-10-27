"""Bounded offline file inspection and managed signature verdicts.

Samples are never executed. PE/ELF features are observations, not malware proof.
Signatures have explicit source/revision/expiry/peer approval. Optional real
YARA runs in a timed child interpreter with includes/import modules disabled.
External sandbox jobs remain pending until an explicit provider result is
submitted. Opt-in provider SDK sample pull requires peer-approved scoped trust;
an unavailable provider is never reported as a clean scan.
"""

import base64
import hashlib
import importlib.util
import json
import math
import re
import struct
import subprocess
import sys
import time
import uuid
from collections import Counter

from . import endpoint_artifacts, principal
from . import evidence_scope as evidence
from .storage import CapacityError, ConflictError, encode

MAX_BYTES = endpoint_artifacts.MAX_BYTES
MAX_SIGNATURES = 64
YARA_TIMEOUT = 3


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS file_signature_bundles(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,name TEXT NOT NULL,indexes TEXT NOT NULL,
          version INTEGER NOT NULL,requester TEXT NOT NULL,approver TEXT NOT NULL,
          state TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,expires REAL NOT NULL,
          definition TEXT NOT NULL,digest TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS file_signature_history(
          tenant TEXT NOT NULL,id TEXT NOT NULL,version INTEGER NOT NULL,action TEXT NOT NULL,
          actor TEXT NOT NULL,at REAL NOT NULL,record TEXT NOT NULL,
          PRIMARY KEY(tenant,id,version,action));
        CREATE TABLE IF NOT EXISTS file_verdict_runs(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,
          artifact_id TEXT NOT NULL,sha256 TEXT NOT NULL,indexes TEXT NOT NULL,
          actor TEXT NOT NULL,created REAL NOT NULL,result TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS file_verdict_case ON file_verdict_runs(tenant,incident_id,created);
        CREATE TABLE IF NOT EXISTS file_sandbox_jobs(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,
          artifact_id TEXT NOT NULL,sha256 TEXT NOT NULL,indexes TEXT NOT NULL,
          provider TEXT NOT NULL,requester TEXT NOT NULL,state TEXT NOT NULL,
          created REAL NOT NULL,expires REAL NOT NULL,finished REAL,result TEXT);
        """)
    from . import sandbox_provider

    sandbox_provider.initialize(store)


def _range(body, offset, length, label):
    if (
        type(offset) is not int
        or type(length) is not int
        or offset < 0
        or length < 0
        or offset + length > len(body)
    ):
        raise ValueError(f"Truncated or out-of-bounds {label}")
    return memoryview(body)[offset : offset + length]


def _pe(body):
    _range(body, 0, 64, "DOS header")
    offset = struct.unpack_from("<I", body, 0x3C)[0]
    _range(body, offset, 24, "PE signature/COFF header")
    if bytes(_range(body, offset, 4, "PE signature")) != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    machine, count, timestamp, _, _, optional_size, flags = struct.unpack_from(
        "<HHIIIHH", body, offset + 4
    )
    if not 1 <= count <= 96:
        raise ValueError("PE section count outside Windows loader bound")
    optional = _range(body, offset + 24, optional_size, "PE optional header")
    if optional_size < 68:
        raise ValueError("Truncated PE optional header")
    magic = struct.unpack_from("<H", optional, 0)[0]
    minimum = 96 if magic == 0x10B else 112 if magic == 0x20B else None
    if minimum is None or optional_size < minimum:
        raise ValueError("Unsupported or truncated PE32/PE32+ optional header")
    entrypoint = struct.unpack_from("<I", optional, 16)[0]
    directories = struct.unpack_from("<I", optional, minimum - 4)[0]
    if directories > 16 or minimum + directories * 8 > optional_size:
        raise ValueError("PE data directory count exceeds optional header")
    section_offset = offset + 24 + optional_size
    _range(body, section_offset, count * 40, "PE section table")
    sections = []
    warnings = []
    for number in range(count):
        pos = section_offset + number * 40
        name = (
            bytes(_range(body, pos, 8, "section name"))
            .split(b"\0", 1)[0]
            .decode("ascii", "replace")
        )
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", body, pos + 8
        )
        characteristics = struct.unpack_from("<I", body, pos + 36)[0]
        _range(body, raw_offset, raw_size, "PE raw section")
        writable, executable = (
            bool(characteristics & 0x80000000),
            bool(characteristics & 0x20000000),
        )
        if writable and executable:
            warnings.append("writable_executable_section")
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "rva": rva,
                "raw_size": raw_size,
                "raw_offset": raw_offset,
                "writable": writable,
                "executable": executable,
            }
        )
    imports, import_error = [], None
    if directories > 1:
        import_rva, import_size = struct.unpack_from("<II", optional, minimum + 8)
        if import_rva or import_size:
            try:
                imports = _pe_imports(
                    body, sections, import_rva, import_size, magic == 0x20B
                )
            except (ValueError, struct.error) as exc:
                import_error = str(exc)[:256]
    return {
        "format": "pe",
        "bits": 64 if magic == 0x20B else 32,
        "machine": machine,
        "timestamp": timestamp,
        "entrypoint_rva": entrypoint,
        "characteristics": flags,
        "sections": sections,
        "warnings": sorted(set(warnings)),
        "authenticode_verified": False,
        "imports": imports,
        "import_parse_status": "incomplete" if import_error else "completed",
        "import_parse_error": import_error,
    }


def _pe_imports(body, sections, rva, size, wide):
    """Bounded static import directory, not an executable loader or trust check."""
    if not rva or not 20 <= size <= 65536:
        raise ValueError("PE import directory requires a bounded nonempty range")

    def offset(address, length):
        candidates = [
            s
            for s in sections
            if s["rva"] <= address and address + length <= s["rva"] + s["raw_size"]
        ]
        if len(candidates) != 1:
            raise ValueError("Import RVA is unmapped or overlaps multiple raw sections")
        result = candidates[0]["raw_offset"] + address - candidates[0]["rva"]
        _range(body, result, length, "PE import mapping")
        return result

    name_budget = 65536

    def name(address):
        nonlocal name_budget
        result = bytearray()
        for i in range(257):
            name_budget -= 1
            if name_budget < 0:
                raise ValueError(
                    "Combined PE import names exceed 64 KiB inspection budget"
                )
            character = body[offset(address + i, 1)]
            if character == 0:
                if not result or any(value < 32 or value > 126 for value in result):
                    raise ValueError(
                        "PE import name is empty or not bounded printable ASCII"
                    )
                return result.decode("ascii")
            result.append(character)
        raise ValueError("PE import name exceeds 256 bytes")

    result, terminated = [], False
    width, fmt = (8, "<Q") if wide else (4, "<I")
    for descriptor in range(min(size // 20, 129)):
        pos = offset(rva + descriptor * 20, 20)
        thunk, timestamp, forwarder, library, first = struct.unpack_from(
            "<IIIII", body, pos
        )
        if not any((thunk, timestamp, forwarder, library, first)):
            terminated = True
            break
        if len(result) >= 128:
            raise ValueError("PE import library count exceeds 128")
        symbols, symbol_terminated = [], False
        for symbol in range(513):
            entry = struct.unpack_from(
                fmt, body, offset((thunk or first) + symbol * width, width)
            )[0]
            if entry == 0:
                symbol_terminated = True
                break
            if len(symbols) >= 512:
                raise ValueError("PE import symbol count exceeds 512 per library")
            symbols.append(
                {"ordinal": entry & 0xFFFF}
                if entry & (1 << (width * 8 - 1))
                else {"name": name(entry + 2)}
            )
        if not symbol_terminated:
            raise ValueError("PE import thunk table has no bounded terminator")
        result.append({"library": name(library), "symbols": symbols})
        if sum(len(row["symbols"]) for row in result) > 2048:
            raise ValueError("Combined PE import symbols exceed 2048")
    if not terminated:
        raise ValueError("PE import directory has no bounded terminator")
    return result


def static_indicators(static):
    """Explainable observations; neither a trained model nor malware probability."""
    findings = []
    for warning in static.get("warnings", []):
        findings.append(
            {
                "kind": "structural_observation",
                "indicator": warning,
                "meaning": "Can occur in benign software; insufficient alone for a malicious verdict.",
            }
        )
    names = {
        symbol["name"].lower()
        for library in static.get("imports", [])
        for symbol in library["symbols"]
        if "name" in symbol
    }
    for identifier, required in (
        (
            "remote_memory_and_thread_imports",
            {"virtualallocex", "writeprocessmemory", "createremotethread"},
        ),
        ("process_memory_read_imports", {"openprocess", "readprocessmemory"}),
    ):
        if required <= names:
            findings.append(
                {
                    "kind": "static_import_capability",
                    "indicator": identifier,
                    "evidence": sorted(required),
                    "meaning": "Imported APIs show potential capability, not observed execution or malicious intent.",
                }
            )
    return {
        "schema": "xsera.static-observations.v1",
        "findings": findings,
        "feature_coverage_complete": static.get("parse_status") != "malformed"
        and static.get("import_parse_status") != "incomplete",
        "trained_ml": False,
        "malware_probability": None,
        "automatic_response": False,
        "verdict_without_managed_signatures_or_attested_provider": "unknown",
    }


def _elf(body):
    _range(body, 0, 16, "ELF identity")
    if body[4] not in {1, 2} or body[5] not in {1, 2} or body[6] != 1:
        raise ValueError("Unsupported ELF class/byte-order/version")
    bits, order = (32 if body[4] == 1 else 64), ("<" if body[5] == 1 else ">")
    header_format = order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    header_size = 52 if bits == 32 else 64
    _range(body, 0, header_size, "ELF header")
    (
        etype,
        machine,
        version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phsize,
        phnum,
        shsize,
        shnum,
        shstr,
    ) = struct.unpack_from(header_format, body, 16)
    if version != 1 or ehsize != header_size or phnum > 1024 or shnum > 4096:
        raise ValueError("Invalid or unsupported extended ELF header counts")
    min_ph, min_sh = (32, 40) if bits == 32 else (56, 64)
    if phnum and phsize < min_ph or shnum and shsize < min_sh:
        raise ValueError("ELF table entry size is too small")
    _range(body, phoff, phnum * phsize, "ELF program table")
    _range(body, shoff, shnum * shsize, "ELF section table")
    if shnum and shstr >= shnum:
        raise ValueError("ELF string-table index exceeds section count")
    segments, warnings = [], []
    for number in range(phnum):
        pos = phoff + number * phsize
        if bits == 32:
            ptype, file_offset, address, _, file_size, mem_size, pflags, alignment = (
                struct.unpack_from(order + "IIIIIIII", body, pos)
            )
        else:
            ptype, pflags, file_offset, address, _, file_size, mem_size, alignment = (
                struct.unpack_from(order + "IIQQQQQQ", body, pos)
            )
        _range(body, file_offset, file_size, "ELF segment data")
        if file_size > mem_size:
            raise ValueError("ELF segment file size exceeds memory size")
        if pflags & 1 and pflags & 2:
            warnings.append("writable_executable_segment")
        segments.append(
            {
                "type": ptype,
                "offset": file_offset,
                "virtual_address": address,
                "file_size": file_size,
                "memory_size": mem_size,
                "flags": pflags,
                "alignment": alignment,
            }
        )
    return {
        "format": "elf",
        "bits": bits,
        "byte_order": "little" if order == "<" else "big",
        "machine": machine,
        "type": etype,
        "entrypoint": entry,
        "flags": flags,
        "segments": segments,
        "section_count": shnum,
        "warnings": sorted(set(warnings)),
    }


def inspect_bytes(body):
    if not isinstance(body, bytes) or len(body) > MAX_BYTES:
        raise ValueError(
            "Sample must be immutable bytes within the artifact size limit"
        )
    digest = hashlib.sha256(body).hexdigest()
    counts = Counter(body)
    entropy = (
        -sum(
            (count / len(body)) * math.log2(count / len(body))
            for count in counts.values()
        )
        if body
        else 0
    )
    result = {
        "sha256": digest,
        "bytes": len(body),
        "entropy_bits_per_byte": round(entropy, 4),
        "sample_executed": False,
        "ml_classification": None,
    }
    try:
        if body.startswith(b"MZ"):
            result.update(_pe(body))
        elif body.startswith(b"\x7fELF"):
            result.update(_elf(body))
        else:
            result.update(
                format="script" if body.startswith(b"#!") else "data", warnings=[]
            )
            if result["format"] == "script":
                result["interpreter_line"] = body.split(b"\n", 1)[0][:256].decode(
                    "utf-8", "replace"
                )
        result["parse_status"] = (
            "valid_header"
            if result["format"] in {"pe", "elf"}
            else "not_executable_header"
        )
    except (ValueError, struct.error) as exc:
        result.update(
            format="pe" if body.startswith(b"MZ") else "elf",
            parse_status="malformed",
            warnings=["invalid_or_truncated_executable_header"],
            parse_error=str(exc)[:256],
        )
    result["static_observations"] = static_indicators(result)
    return result


def _signature(item):
    if not isinstance(item, dict) or set(item) - {
        "id",
        "name",
        "kind",
        "value",
        "verdict",
        "format",
        "source",
        "offset",
    }:
        raise ValueError("Unknown managed signature property")
    kind = evidence.choice(
        item.get("kind"), {"sha256", "literal", "yara"}, "signature kind"
    )
    evidence.choice(
        item.get("verdict"), {"suspicious", "malicious", "benign"}, "signature verdict"
    )
    evidence.choice(
        item.get("format", "any"),
        {"any", "pe", "elf", "script", "data"},
        "signature format",
    )
    result = {
        key: evidence.text(item.get(key), key, 2000 if key == "source" else 128)
        for key in ("id", "name", "source")
    }
    value = item.get("value")
    if kind == "sha256":
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("SHA256 signature requires lowercase digest")
        if "offset" in item:
            raise ValueError("Hash signatures do not accept offsets")
    elif kind == "literal":
        if not isinstance(value, str) or not re.fullmatch(
            r"(?:[0-9a-fA-F]{2}){4,1024}", value
        ):
            raise ValueError("Literal signature requires 4..1024 bytes encoded as hex")
        if "offset" in item:
            result["offset"] = evidence.integer(item["offset"], "offset", 0, MAX_BYTES)
    else:
        if (not isinstance(value, str) or not value.strip()
                or len(value.encode("utf-8")) > 32768
                or any(ord(c) < 32 and c not in "\n\r\t" for c in value)):
            raise ValueError("YARA source requires bounded UTF-8 text")
        if re.search(r"\b(?:include|import)\b", value):
            raise ValueError("Managed YARA disables includes and imported modules")
        if "offset" in item:
            raise ValueError("YARA signatures encode offsets in their rule")
    if item["verdict"] == "benign" and kind != "sha256":
        raise ValueError("Benign allowlisting requires an exact whole-file SHA256")
    return {
        **result,
        "kind": kind,
        "value": value,
        "verdict": item["verdict"],
        "format": item.get("format", "any"),
    }


def _bundle(row):
    result = dict(row)
    result["indexes"] = json.loads(result["indexes"])
    result["definition"] = json.loads(result["definition"])
    result["effective_state"] = (
        "expired" if result["expires"] <= time.time() else result["state"]
    )
    return result


def _visible_bundle(db, actor, identifier):
    row = db.execute(
        "SELECT * FROM file_signature_bundles WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise KeyError("Signature bundle not found")
    return row


def save_bundle(store, who, data, identifier=None):
    if not isinstance(data, dict) or set(data) - {
        "name",
        "indexes",
        "expires",
        "signatures",
        "version",
    }:
        raise ValueError("Unknown signature bundle property")
    name = evidence.text(data.get("name"), "bundle name", 128)
    scope = evidence.indexes(data.get("indexes"))
    version = evidence.integer(data.get("version", 0), "version", 0, 2**31 - 1)
    now = time.time()
    expires = evidence.number(data.get("expires"), "expires", now + 1, now + 90 * 86400)
    raw = data.get("signatures")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_SIGNATURES:
        raise ValueError("Bundle requires 1..64 managed signatures")
    signatures = [_signature(item) for item in raw]
    if len({row["id"] for row in signatures}) != len(signatures):
        raise ValueError("Duplicate signature ID")
    definition = {"signatures": signatures}
    encoded = encode(definition)
    if len(encoded.encode()) > 128 * 1024:
        raise ValueError("Signature bundle exceeds 128 KiB")
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], scope):
            raise PermissionError("Signature scope exceeds permission")
        old = _visible_bundle(db, actor, identifier) if identifier else None
        if (old["version"] if old else 0) != version:
            raise ConflictError("Signature bundle revision changed")
        # Durable inventory/history has no lifetime record-count ceiling.
        identifier = identifier or str(uuid.uuid4())
        db.execute(
            "INSERT INTO file_signature_bundles VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,indexes=excluded.indexes,version=excluded.version,requester=excluded.requester,approver=excluded.approver,state=excluded.state,updated=excluded.updated,expires=excluded.expires,definition=excluded.definition,digest=excluded.digest",
            (
                identifier,
                actor["tenant"],
                name,
                encode(scope),
                version + 1,
                actor["name"],
                "",
                "pending",
                now,
                now,
                expires,
                encoded,
                digest,
            ),
        )
        result = _bundle(_visible_bundle(db, actor, identifier))
        db.execute(
            "INSERT INTO file_signature_history VALUES(?,?,?,?,?,?,?)",
            (
                actor["tenant"],
                identifier,
                version + 1,
                "save",
                actor["name"],
                now,
                encode(result),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.signature_bundle.save",
            {"id": identifier, "version": version + 1, "digest": digest},
        )
        return result


def review_bundle(store, who, identifier, version, approve, reason):
    evidence.integer(version, "version", 1, 2**31 - 1)
    if type(approve) is not bool:
        raise ValueError("approve must be boolean")
    evidence.text(reason, "review reason", 2000)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = _visible_bundle(db, actor, identifier)
        if (
            row["version"] != version
            or row["state"] != "pending"
            or row["expires"] <= time.time()
        ):
            raise ConflictError(
                "Signature revision is stale, expired or already reviewed"
            )
        if actor["name"] == row["requester"]:
            raise PermissionError("A different administrator must review signatures")
        requester = principal.current(
            db,
            {"name": row["requester"], "tenant": actor["tenant"], "role": "admin"},
            ("admin",),
        )
        if not principal.contains(
            requester["allowed_indexes"], json.loads(row["indexes"])
        ):
            raise PermissionError("Signature requester permissions changed")
        now = time.time()
        db.execute(
            "UPDATE file_signature_bundles SET state=?,approver=?,updated=? WHERE id=?",
            ("active" if approve else "rejected", actor["name"], now, identifier),
        )
        result = _bundle(_visible_bundle(db, actor, identifier))
        db.execute(
            "INSERT INTO file_signature_history VALUES(?,?,?,?,?,?,?)",
            (
                actor["tenant"],
                identifier,
                version,
                "approve" if approve else "reject",
                actor["name"],
                now,
                encode({**result, "review_reason": reason}),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.signature_bundle.review",
            {
                "id": identifier,
                "version": version,
                "approve": approve,
                "reason": reason,
            },
        )
        return result


def _active(db, row):
    scope = json.loads(row["indexes"])
    if (
        row["state"] != "active"
        or row["expires"] <= time.time()
        or row["requester"] == row["approver"]
    ):
        return False
    for name in (row["requester"], row["approver"]):
        try:
            actor = principal.current(
                db, {"name": name, "tenant": row["tenant"], "role": "admin"}, ("admin",)
            )
        except PermissionError:
            return False
        if not principal.contains(actor["allowed_indexes"], scope):
            return False
    return True


YARA_CHILD = """import base64,json,sys
request=json.load(sys.stdin)
try:
 import yara
except ImportError:
 print(json.dumps({'status':'unavailable','matches':[]}));sys.exit(0)
try:
 rules=yara.compile(source=request['source'],includes=False,error_on_warning=True)
 result=rules.match(data=base64.b64decode(request['body']),timeout=1)
 print(json.dumps({'status':'completed','matches':[str(item.rule) for item in result][:64]}))
except Exception as exc:
 print(json.dumps({'status':'failed','matches':[],'error':str(exc)[:256]}))
"""


def yara_scan(source, body, *, timeout=YARA_TIMEOUT):
    _signature(
        {
            "id": "scan",
            "name": "scan",
            "kind": "yara",
            "value": source,
            "verdict": "suspicious",
            "source": "explicit managed YARA",
        }
    )
    if not isinstance(body, bytes) or len(body) > MAX_BYTES:
        raise ValueError("Bounded immutable sample bytes required")
    timeout = evidence.number(timeout, "YARA child timeout", 0.01, YARA_TIMEOUT)
    if importlib.util.find_spec("yara") is None:
        return {
            "status": "unavailable",
            "matches": [],
            "reason": "Install the optional trusted yara-python runtime to enable real YARA; no substitute engine was used",
        }
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-c", YARA_CHILD],
            input=encode({"source": source, "body": base64.b64encode(body).decode()}),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "matches": [], "deadline_seconds": timeout}
    if completed.returncode or len(completed.stdout) > 32768:
        return {
            "status": "failed",
            "matches": [],
            "reason": "YARA child failed or exceeded output bound",
        }
    try:
        result = json.loads(completed.stdout)
    except (ValueError, TypeError):
        return {
            "status": "failed",
            "matches": [],
            "reason": "YARA child returned invalid JSON",
        }
    if (
        not isinstance(result, dict)
        or result.get("status") not in {"unavailable", "failed", "completed"}
        or not isinstance(result.get("matches"), list)
        or len(result["matches"]) > 64
        or any(
            not isinstance(item, str) or len(item) > 128 for item in result["matches"]
        )
    ):
        return {
            "status": "failed",
            "matches": [],
            "reason": "YARA child result failed typed validation",
        }
    return result


def evaluate_signatures(body, signatures):
    static = inspect_bytes(body)
    if not isinstance(signatures, list) or len(signatures) > MAX_SIGNATURES:
        raise ValueError("At most 64 signatures may be evaluated")
    matches, errors = [], []
    until = time.monotonic() + 5
    for raw in signatures:
        signature = _signature(raw)
        remaining = until - time.monotonic()
        if remaining < 0.01:
            errors.append(
                {
                    "signature_id": signature["id"],
                    "status": "timeout",
                    "matches": [],
                    "reason": "Combined signature scan exceeded five-second wall budget",
                }
            )
            continue
        if signature["format"] not in {"any", static["format"]}:
            continue
        if signature["kind"] == "sha256":
            found = static["sha256"] == signature["value"]
        elif signature["kind"] == "literal":
            needle = bytes.fromhex(signature["value"])
            found = (
                body[signature["offset"] : signature["offset"] + len(needle)] == needle
                if "offset" in signature
                else needle in body
            )
        else:
            result = yara_scan(
                signature["value"], body, timeout=min(YARA_TIMEOUT, remaining)
            )
            if result["status"] != "completed":
                errors.append({"signature_id": signature["id"], **result})
                continue
            found = bool(result["matches"])
        if found:
            matches.append(
                {
                    "id": signature["id"],
                    "name": signature["name"],
                    "kind": signature["kind"],
                    "verdict": signature["verdict"],
                    "source": signature["source"],
                }
            )
    verdict = (
        "malicious"
        if any(row["verdict"] == "malicious" for row in matches)
        else "suspicious"
        if any(row["verdict"] == "suspicious" for row in matches)
        else "known_benign_hash"
        if any(row["verdict"] == "benign" for row in matches)
        else "unknown"
    )
    return {
        "static": static,
        "signature_matches": matches,
        "signature_errors": errors,
        "verdict": verdict,
        "coverage_complete": not errors
        and static["static_observations"]["feature_coverage_complete"],
        "signature_coverage_complete": not errors,
        "meaning": "Managed signature match, not independently attested malware verdict. No match is unknown, not clean.",
        "sample_executed": False,
    }


def analyze_artifact(store, who, artifact_id, bundle_ids=None):
    if bundle_ids is not None and (
        not isinstance(bundle_ids, list) or len(bundle_ids) > 16
    ):
        raise ValueError("At most 16 unique signature bundle IDs are supported")
    if bundle_ids is not None:
        for identifier in bundle_ids:
            evidence.text(identifier, "bundle id")
        if len(set(bundle_ids)) != len(bundle_ids):
            raise ValueError("Signature bundle IDs must be unique")
    with principal.transaction(store, who, ("admin", "analyst")) as (_, admitted_actor):
        pass
    body, _, digest = endpoint_artifacts.download(store, admitted_actor, artifact_id)
    if len(body) > MAX_BYTES:
        raise ValueError("Legacy signature analysis supports at most 2 MiB; use the dedicated YARA process-artifact analyzer for larger executables")
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        artifact = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (actor["tenant"], artifact_id),
        ).fetchone()
        principal.incident(db, actor, artifact["incident_id"])
        rows = db.execute(
            "SELECT * FROM file_signature_bundles WHERE tenant=? ORDER BY id",
            (actor["tenant"],),
        ).fetchall()
        # Durable inventory/history has no lifetime record-count ceiling.
        selected = [
            row
            for row in rows
            if (bundle_ids is None or row["id"] in bundle_ids)
            and principal.contains(actor["allowed_indexes"], json.loads(row["indexes"]))
            and artifact["index_name"] in json.loads(row["indexes"])
        ]
        if bundle_ids is not None and {row["id"] for row in selected} != set(
            bundle_ids
        ):
            raise KeyError(
                "A signature bundle is unavailable in the complete artifact scope"
            )
        if any(not _active(db, row) for row in selected):
            if bundle_ids is not None:
                raise ConflictError(
                    "Explicit bundle is unapproved, expired or its authorities changed"
                )
            selected = [row for row in selected if _active(db, row)]
        if len(selected) > 16:
            raise CapacityError("Choose at most 16 signature bundles")
        snapshots = [
            {"id": row["id"], "version": row["version"], "digest": row["digest"]}
            for row in selected
        ]
        signatures = [
            signature
            for row in selected
            for signature in json.loads(row["definition"])["signatures"]
        ]
        if len(signatures) > MAX_SIGNATURES:
            raise CapacityError("Combined signatures exceed 64; select fewer bundles")
    result = evaluate_signatures(body, signatures)
    with principal.transaction(store, actor, ("admin", "analyst"), write=True) as (
        db,
        fresh,
    ):
        principal.incident(db, fresh, artifact["incident_id"])
        current = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (fresh["tenant"], artifact_id),
        ).fetchone()
        if (
            not current
            or current["state"] != "complete"
            or current["sha256"] != digest
            or not principal.contains(fresh["allowed_indexes"], [current["index_name"]])
        ):
            raise ConflictError("Artifact changed during analysis")
        for snapshot in snapshots:
            row = _visible_bundle(db, fresh, snapshot["id"])
            if (
                not _active(db, row)
                or row["version"] != snapshot["version"]
                or row["digest"] != snapshot["digest"]
            ):
                raise ConflictError(
                    "Signature authority/revision changed during analysis"
                )
        # Durable inventory/history has no lifetime record-count ceiling.
        identifier = str(uuid.uuid4())
        result.update(
            id=identifier,
            artifact_id=artifact_id,
            incident_id=current["incident_id"],
            bundles=snapshots,
        )
        db.execute(
            "INSERT INTO file_verdict_runs VALUES(?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                fresh["tenant"],
                current["incident_id"],
                artifact_id,
                digest,
                encode([current["index_name"]]),
                fresh["name"],
                time.time(),
                encode(result),
            ),
        )
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "file.artifact.analyze",
            {
                "id": identifier,
                "artifact_id": artifact_id,
                "sha256": digest,
                "verdict": result["verdict"],
                "sample_executed": False,
            },
        )
        return result


def list_bundles(store, who):
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT * FROM file_signature_bundles WHERE tenant=? ORDER BY updated DESC,id",
            (actor["tenant"],),
        ).fetchall()
        result = []
        for row in rows:
            if not principal.contains(
                actor["allowed_indexes"], json.loads(row["indexes"])
            ):
                continue
            item = _bundle(row)
            if item["effective_state"] == "active" and not _active(db, row):
                item["effective_state"] = "authority_changed"
            result.append(item)
        return result


def revoke_bundle(store, who, identifier, version, reason):
    evidence.integer(version, "version", 1, 2**31 - 1)
    evidence.text(reason, "revocation reason", 2000)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = _visible_bundle(db, actor, identifier)
        if row["version"] != version or row["state"] == "revoked":
            raise ConflictError("Signature bundle changed or was already revoked")
        now = time.time()
        db.execute(
            "UPDATE file_signature_bundles SET state='revoked',updated=? WHERE id=?",
            (now, identifier),
        )
        result = _bundle(_visible_bundle(db, actor, identifier))
        db.execute(
            "INSERT INTO file_signature_history VALUES(?,?,?,?,?,?,?)",
            (
                actor["tenant"],
                identifier,
                version,
                "revoke",
                actor["name"],
                now,
                encode({**result, "revocation_reason": reason}),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.signature_bundle.revoke",
            {"id": identifier, "version": version, "reason": reason},
        )
        return result


def case_verdicts(store, who, incident_id):
    with principal.transaction(store, who) as (db, actor):
        principal.incident(db, actor, incident_id)
        rows = db.execute(
            "SELECT * FROM file_verdict_runs WHERE tenant=? AND incident_id=? ORDER BY created DESC,id",
            (actor["tenant"], incident_id),
        ).fetchall()
        # Permanent execution/investigation history has no lifetime count ceiling.
        return [
            json.loads(row["result"])
            for row in rows
            if principal.contains(actor["allowed_indexes"], json.loads(row["indexes"]))
        ]


def request_sandbox(store, who, artifact_id, provider, *, ttl=3600):
    """Create an explicit pending external job. This sends no sample off-host."""
    evidence.text(provider, "provider name", 128)
    evidence.integer(ttl, "ttl", 60, 86400)
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        artifact = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (actor["tenant"], artifact_id),
        ).fetchone()
        if not artifact or not principal.contains(
            actor["allowed_indexes"], [artifact["index_name"]]
        ):
            raise KeyError("Artifact not found")
        principal.incident(db, actor, artifact["incident_id"])
        if artifact["state"] != "complete":
            raise ConflictError("Sandbox job requires a completed artifact")
        if artifact["total_bytes"] > MAX_BYTES:
            raise ValueError("Legacy sandbox supports at most 2 MiB; large process executables remain local to the dedicated YARA analyzer")
        # Durable inventory/history has no lifetime record-count ceiling.
        identifier, now = str(uuid.uuid4()), time.time()
        db.execute(
            "INSERT INTO file_sandbox_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                actor["tenant"],
                artifact["incident_id"],
                artifact_id,
                artifact["sha256"],
                encode([artifact["index_name"]]),
                provider,
                actor["name"],
                "pending_external",
                now,
                now + ttl,
                None,
                None,
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.sandbox.request",
            {"id": identifier, "provider": provider, "sample_sent": False},
        )
        return {
            "id": identifier,
            "state": "pending_external",
            "provider": provider,
            "sha256": artifact["sha256"],
            "sample_sent": False,
            "expires": now + ttl,
        }


def complete_sandbox(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {
        "sha256",
        "provider",
        "provider_job_id",
        "verdict",
        "report_digest",
        "observed_at",
        "reason",
    }:
        raise ValueError(
            "External completion requires exact digest/provider/job/verdict/report/time/reason fields"
        )
    evidence.choice(
        data["verdict"],
        {"malicious", "suspicious", "benign", "unknown", "failed"},
        "sandbox verdict",
    )
    for key in ("sha256", "report_digest"):
        if not isinstance(data[key], str) or not re.fullmatch(
            r"[0-9a-f]{64}", data[key]
        ):
            raise ValueError("External result requires exact lowercase SHA256 digests")
    for key in ("provider", "provider_job_id", "reason"):
        evidence.text(data[key], key, 2000)
    observed = evidence.number(data["observed_at"], "observed_at", 0, time.time())
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = db.execute(
            "SELECT * FROM file_sandbox_jobs WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if not row or not principal.contains(
            actor["allowed_indexes"], json.loads(row["indexes"])
        ):
            raise KeyError("Sandbox job not found")
        principal.incident(db, actor, row["incident_id"])
        if db.execute(
            "SELECT 1 FROM file_sandbox_attestations WHERE tenant=? AND job_id=?",
            (actor["tenant"], identifier),
        ).fetchone():
            raise ValueError(
                "An attested job requires the signed provider result protocol; claim downgrade forbidden"
            )
        if row["state"] != "pending_external" or row["expires"] <= time.time():
            raise ConflictError("Sandbox job already completed or expired")
        if (
            data["sha256"] != row["sha256"]
            or data["provider"] != row["provider"]
            or observed < row["created"]
        ):
            raise ValueError(
                "External result does not bind this exact sample/provider/job interval"
            )
        result = {
            **data,
            "attribution": "administrator-imported external provider claim",
            "provider_signature_verified": False,
            "sample_executed_by_xsera": False,
        }
        db.execute(
            "UPDATE file_sandbox_jobs SET state='completed_external_claim',finished=?,result=? WHERE id=?",
            (time.time(), encode(result), identifier),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.sandbox.external_result",
            {
                "id": identifier,
                "verdict": data["verdict"],
                "provider_signature_verified": False,
            },
        )
        return {"id": identifier, "state": "completed_external_claim", "result": result}


def sandbox_job(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        row = db.execute(
            "SELECT * FROM file_sandbox_jobs WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if not row or not principal.contains(
            actor["allowed_indexes"], json.loads(row["indexes"])
        ):
            raise KeyError("Sandbox job not found")
        principal.incident(db, actor, row["incident_id"])
        result = dict(row)
        result["indexes"] = json.loads(result["indexes"])
        result["result"] = json.loads(result["result"]) if result["result"] else None
        result["effective_state"] = (
            "expired"
            if result["state"] in {"pending_external", "pending_attested"}
            and result["expires"] <= time.time()
            else result["state"]
        )
        result["sample_sent_by_xsera"] = (
            db.execute(
                "SELECT 1 FROM file_sandbox_sample_exports WHERE tenant=? AND job_id=?",
                (actor["tenant"], identifier),
            ).fetchone()
            is not None
        )
        binding = db.execute(
            "SELECT * FROM file_sandbox_attestations WHERE tenant=? AND job_id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        result["attestation"] = dict(binding) if binding else None
        return result
