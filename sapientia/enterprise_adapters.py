"""Tenant-bound Microsoft identity/mail audit intake, preserving vendor originals.

Graph signIn payloads omit tenant ID: the collector must wrap each original with
the authenticated token tenant. This is a source assertion, not native attestation.
No identities are merged using display names, IPs or mail addresses.
"""
import copy
import datetime
import ipaddress
import re

from .storage import encode, normalize

GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


def text(value, name, maximum=1024):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
        raise ValueError("Bounded vendor field required: " + name)
    return value


def timestamp(value):
    text(value, "UTC timestamp", 64)
    parsed = datetime.datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError("Explicit UTC timestamp required")
    return parsed.timestamp()


def address(value):
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    # Office reports [IPv6]:port or IPv4:port; preserve other reported names raw.
    match = re.fullmatch(r"\[([^\]]+)\]:([0-9]{1,5})|([0-9.]+):([0-9]{1,5})", value)
    if match:
        host, port = (match[1], match[2]) if match[1] else (match[3], match[4])
        if 1 <= int(port) <= 65535:
            try:
                return str(ipaddress.ip_address(host))
            except ValueError:
                pass
    return None


def decode(item, source):
    if not isinstance(item, dict) or len(encode(item).encode()) > 60000:
        raise ValueError("One bounded Microsoft audit envelope required")
    product = source["product"]
    if product == "entra_signin":
        if set(item) != {"tenant_id", "record"} or not isinstance(item["record"], dict):
            raise ValueError("Graph signIn needs authenticated tenant_id and original record")
        record = item["record"]
        tenant = item["tenant_id"]
        event_id = text(record.get("id"), "signIn.id", 256)
        occurred = timestamp(record.get("createdDateTime"))
        user_id = record.get("userId")
        if not isinstance(user_id, str) or not GUID.fullmatch(user_id):
            raise ValueError("Graph userId GUID required")
        user = text(record.get("userPrincipalName"), "userPrincipalName")
        status = record.get("status")
        if not isinstance(status, dict) or type(status.get("errorCode")) is not int:
            raise ValueError("Typed Graph signIn status required")
        action, outcome = "user_signin", "success" if status["errorCode"] == 0 else "failure"
        ip = address(record.get("ipAddress"))
    elif product == "m365_audit":
        record = item
        tenant = record.get("OrganizationId")
        event_id = text(record.get("Id"), "audit Id", 256)
        occurred = timestamp(record.get("CreationTime"))
        action = text(record.get("Operation"), "Operation", 128)
        text(record.get("Workload"), "Workload", 128)
        if type(record.get("RecordType")) is not int or record["RecordType"] < 1:
            raise ValueError("Typed audit RecordType required")
        user = text(record.get("UserId"), "UserId")
        # UserId may be an email/name; it does not establish stable user identity.
        user_id = record.get("UserKey")
        user_id = user_id if isinstance(user_id, str) and GUID.fullmatch(user_id) else None
        status = record.get("ResultStatus")
        outcome = "success" if status in ("Succeeded", "Success", "True", "0") else "failure" if status in ("Failed", "False") else "observed"
        ip = address(record.get("ClientIP"))
    else:
        raise ValueError("Unsupported enterprise product")
    if not isinstance(tenant, str) or not GUID.fullmatch(tenant):
        raise ValueError("Microsoft tenant GUID required")
    if tenant.lower() != source["account"].lower():
        raise PermissionError("Microsoft tenant differs from registered source")
    sec = {"action": action, "outcome": outcome, "user": user}
    if ip:
        sec["src_ip"] = ip
    data = {"event": {"action": action}, "user": {"id": user_id},
            "enterprise": {"tenant_id": tenant.lower(), "reported_only": True}}
    if product == 'm365_audit':
        parameters = record.get('Parameters', [])
        if parameters is not None and not isinstance(parameters, list):
            raise ValueError('Mailbox audit Parameters must be an array')
        forwarding = []
        for parameter in parameters or []:
            if (isinstance(parameter, dict) and parameter.get('Name') in {
                'ForwardTo', 'RedirectTo', 'ForwardAsAttachmentTo', 'ForwardingSmtpAddress', 'ForwardingAddress'
            } and isinstance(parameter.get('Value'), str) and parameter['Value'].strip()):
                forwarding.append(text(parameter['Value'], 'forwarding value'))
        data['enterprise']['mail_forwarding_configured'] = bool(forwarding)
        data['enterprise']['reported_forwarding_values'] = forwarding[:32]
    raw = {product: copy.deepcopy(record), "security": sec, "xdr": {"data": data}}
    return normalize({"event_id": product+":"+tenant.lower()+":"+event_id,
                      "event_time": occurred, "index": source["index_name"],
                      "source": product, "sourcetype": "microsoft:"+product,
                      "host": tenant.lower(), "severity": "info", "message": product+" "+action, "raw": raw})


def starter(store, who, identifier):
    from . import principal, source_registry
    with principal.transaction(store, who, ('admin', 'analyst')) as (db, actor):
        source = source_registry.visible(db, actor, identifier)
        if source['state'] != 'active' or source['product'] not in {'entra_signin', 'm365_audit', 'cloudtrail'}:
            raise ValueError('Active supported enterprise source required')
        predicates = [{'field': 'projection.source_id', 'op': 'eq', 'value': identifier},
                      {'field': 'projection.source_version', 'op': 'eq', 'value': source['version']}]
        if source['product'] == 'entra_signin':
            name = 'Entra reported high-risk sign-in'
            predicates.append({'field': 'raw.entra_signin.riskLevelAggregated', 'op': 'eq', 'value': 'high'})
            techniques = ['T1078']
        elif source['product'] == 'm365_audit':
            name = 'Microsoft 365 mailbox forwarding rule change'
            predicates.extend([{'field': 'raw.m365_audit.Workload', 'op': 'eq', 'value': 'Exchange'},
                               {'field': 'raw.m365_audit.Operation', 'op': 'in', 'value': ['New-InboxRule', 'Set-InboxRule', 'Set-Mailbox']},
                               {'field': 'raw.xdr.data.enterprise.mail_forwarding_configured', 'op': 'eq', 'value': True}])
            techniques = ['T1114.003']
        else:
            name = 'AWS IAM credential or trust change'
            predicates.extend([{'field': 'raw.cloudtrail.eventSource', 'op': 'eq', 'value': 'iam.amazonaws.com'},
                               {'field': 'raw.cloudtrail.eventName', 'op': 'in', 'value': ['CreateAccessKey', 'UpdateAssumeRolePolicy', 'AttachUserPolicy']}])
            techniques = ['T1098']
        return {'name': name, 'kind': 'atomic', 'indexes': [source['index_name']], 'version': 0, 'enabled': True,
                'severity': 'medium', 'confidence_grade': 'reported_enterprise_activity_review_required', 'filters': predicates,
                'case_adapter': {'entity_field': 'host', 'risk_score': 25, 'severity': 'medium', 'mitre': techniques, 'cooldown': 300}}
