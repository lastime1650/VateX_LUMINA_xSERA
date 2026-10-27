"""Current-principal scoped product/account/realm source authority."""

import json
import re
import time
import uuid

from . import migrations, principal
from .storage import ConflictError, encode

IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}\Z")
PRODUCTS = frozenset({"cisco_asa", "fortigate", "windows", "linux", "cloudtrail", "json",
                      "suricata", "zeek", "falco", "tetragon", "osquery", "entra_signin", "m365_audit"})


def text(value):
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise ValueError("Bounded source identity required")
    return value


def initialize(store):
    migrations.apply_store(store, "source_registry", [
        "CREATE TABLE IF NOT EXISTS source_registry(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,index_name TEXT NOT NULL,product TEXT NOT NULL,account TEXT NOT NULL,realm TEXT NOT NULL,credential_ref TEXT NOT NULL,definition TEXT NOT NULL,version INTEGER NOT NULL,state TEXT NOT NULL,updated REAL NOT NULL)",
        "CREATE INDEX IF NOT EXISTS source_registry_scope ON source_registry(tenant,index_name,id)"])


def save(store, who, data, identifier=None):
    if not isinstance(data, dict) or set(data) != {"index", "product", "account", "realm", "credential_ref", "version"}:
        raise ValueError("Exact source registry fields required")
    for key in ("index", "product", "account", "realm", "credential_ref"):
        text(data[key])
    if data["product"] not in PRODUCTS:
        raise ValueError("Product parser is unavailable")
    if not re.fullmatch(r"env:SAPIENTIA_CONNECTOR_[A-Z0-9_]{1,128}", data["credential_ref"]):
        raise ValueError("Use an explicit connector environment reference, never a secret value")
    if type(data["version"]) is not int or data["version"] < 0:
        raise ValueError("Source version required")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], [data["index"]]):
            raise PermissionError("Source index outside current scope")
        previous = None
        if identifier:
            previous = visible(db, actor, identifier)
        if (previous and previous["version"] != data["version"]) or (not previous and data["version"] != 0):
            raise ConflictError("Source registry revision changed")
        identifier = identifier or uuid.uuid4().hex
        version = data["version"] + 1
        definition = {key: value for key, value in data.items() if key != "version"}
        db.execute("INSERT INTO source_registry VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET index_name=excluded.index_name,product=excluded.product,account=excluded.account,realm=excluded.realm,credential_ref=excluded.credential_ref,definition=excluded.definition,version=excluded.version,state='active',updated=excluded.updated",
                   (identifier, actor["tenant"], actor["name"], data["index"], data["product"], data["account"], data["realm"], data["credential_ref"], encode(definition), version, "active", time.time()))
        store.audit(db, actor["tenant"], actor["name"], "source.registry.save", {"id": identifier, "version": version})
        return {"id": identifier, **definition, "version": version, "state": "active"}


def visible(db, actor, identifier):
    row = db.execute("SELECT * FROM source_registry WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
        raise KeyError("Source not found")
    return row


def get(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        row = visible(db, actor, identifier)
        return {"id": row["id"], **json.loads(row["definition"]), "version": row["version"], "state": row["state"]}


def revoke(store, who, identifier, version):
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = visible(db, actor, identifier)
        if type(version) is not int or row["version"] != version:
            raise ConflictError("Source registry revision changed")
        db.execute("UPDATE source_registry SET state='revoked',version=version+1,updated=? WHERE id=?", (time.time(), identifier))
        store.audit(db, actor["tenant"], actor["name"], "source.registry.revoke", {"id": identifier})


def listing(store, who):
    with principal.transaction(store, who) as (db, actor):
        return [{"id": r["id"], **json.loads(r["definition"]), "version": r["version"], "state": r["state"]}
                for r in db.execute("SELECT * FROM source_registry WHERE tenant=? ORDER BY id", (actor["tenant"],))
                if principal.contains(actor["allowed_indexes"], [r["index_name"]])]


def native_origin(db, tenant, agent_id, identifiers):
    """Called only after credential-bound endpoint proof validation, same TX."""
    agent=db.execute("SELECT a.*,d.platform,d.owner AS source_owner FROM endpoint_agents a JOIN endpoint_deployments d ON d.id=a.deployment_id WHERE a.tenant=? AND a.id=?",(tenant,agent_id)).fetchone()
    if not agent or agent["revoked"] or agent["platform"] not in {"windows","linux"}:
        raise PermissionError("Current enrolled source authority required")
    identifier="agent:"+agent_id
    old=db.execute("SELECT * FROM source_registry WHERE id=?",(identifier,)).fetchone()
    if old and (old["state"]!="active" or old["tenant"]!=tenant or old["account"]!=agent["host"] or old["index_name"]!=agent["index_name"] or old["product"]!=agent["platform"] or old["realm"]!="agent:"+tenant or old["owner"]!=agent["source_owner"]):
        raise PermissionError("Enrolled source was revoked or rebound")
    revision=old["version"] if old else 1
    if old and json.loads(old["definition"]).get("agent_version")!=agent["version"]:
        revision+=1
    definition={"id":identifier,"index":agent["index_name"],"product":agent["platform"],"account":agent["host"],"realm":"agent:"+tenant,"credential_ref":"env:SAPIENTIA_CONNECTOR_NATIVE","version":revision,"agent_version":agent["version"]}
    db.execute("INSERT INTO source_registry VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET definition=excluded.definition,version=excluded.version,updated=excluded.updated",
               (identifier,tenant,agent["source_owner"],agent["index_name"],agent["platform"],agent["host"],definition["realm"],definition["credential_ref"],encode(definition),revision,"active",time.time()))
    for ident in identifiers:
        proof=db.execute("SELECT * FROM endpoint_event_receipts WHERE tenant=? AND event_id=? AND agent_id=?",(tenant,ident,agent_id)).fetchone()
        if not proof:
            raise PermissionError("Native source proof missing")
        old_proof=db.execute("SELECT * FROM source_event_receipts WHERE tenant=? AND event_id=?",(tenant,ident)).fetchone()
        if old_proof and (old_proof["source_id"]!=identifier or old_proof["receipt_digest"]!=proof["receipt_digest"]):
            raise ConflictError("Native/generic source collision")
        db.execute("INSERT OR IGNORE INTO source_event_receipts(tenant,event_id,source_id,source_version,index_name,receipt_digest,received,source_definition) VALUES(?,?,?,?,?,?,?,?)",
                   (tenant,ident,identifier,revision,agent["index_name"],proof["receipt_digest"],proof["received"],encode(definition)))
