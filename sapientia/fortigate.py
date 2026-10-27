"""Bounded FortiOS key=value traffic/UTM adapter; no inferred asset ownership."""

import ipaddress
import math
import re
import time
from datetime import datetime

from . import pipeline, principal
from .storage import normalize

TOKEN = re.compile(r'([A-Za-z][A-Za-z0-9_]{0,63})=("(?:[^"\\\r\n]|\\["\\])*"|[^\s"=]+)(?:\s+|$)')
MAPPING = 'fortigate-kv-v1'


def parse(text):
    if not isinstance(text, str) or not 1 <= len(text) <= 32768:
        raise ValueError('FortiGate log must be 1..32768 characters')
    fields, cursor = {}, 0
    text = text.strip()
    while cursor < len(text):
        match = TOKEN.match(text, cursor)
        if match is None:
            raise ValueError('Malformed FortiGate key=value log')
        key, value = match.group(1, 2)
        if key in fields or len(fields) >= 128:
            raise ValueError('Duplicate or excessive FortiGate fields')
        if value.startswith('"'):
            value = re.sub(r'\\(["\\])', r'\1', value[1:-1])
        fields[key] = value
        cursor = match.end()
    if fields.get('type') not in {'traffic', 'utm', 'event'} or not fields.get('devid'):
        raise ValueError('FortiGate type and device serial are required')
    return fields


def timestamp(fields):
    if 'eventtime' in fields:
        try:
            value = int(fields['eventtime'])
        except ValueError:
            raise ValueError('Invalid FortiGate eventtime') from None
        if not 0 <= value <= int((time.time() + 86400) * 10**9):
            raise ValueError('FortiGate eventtime outside supported range')
        # FortiOS emits either epoch seconds or integer nanoseconds.
        if value >= 10**17:
            value /= 10**9
    elif all(k in fields for k in ('date', 'time', 'tz')):
        try:
            value = datetime.strptime(
                fields['date'] + 'T' + fields['time'] + fields['tz'],
                '%Y-%m-%dT%H:%M:%S%z',
            ).timestamp()
        except ValueError:
            raise ValueError('FortiGate date/time requires a valid timezone') from None
    else:
        raise ValueError('FortiGate eventtime or date/time/tz required')
    if not math.isfinite(value) or not 0 <= value <= time.time() + 86400:
        raise ValueError('FortiGate eventtime outside supported range')
    return value


def envelope(item, index):
    if not isinstance(item, dict) or set(item) != {'id', 'log'}:
        raise ValueError('FortiGate event requires only id and log')
    fields = parse(item['log'])
    security = {'schema': 'sapientia-security', 'version': 1, 'mapping': MAPPING, 'provenance': {}}
    for source, target in [('srcip', 'src_ip'), ('dstip', 'dest_ip')]:
        if source in fields:
            try:
                address = ipaddress.ip_address(fields[source])
            except ValueError:
                raise ValueError('Invalid FortiGate IP field') from None
            if address.is_unspecified:
                continue  # Preserve raw value, but do not invent an entity identity.
            security[target] = str(address.ipv4_mapped) if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else str(address)
            security['provenance'][target] = ['raw.fortigate.' + source]
    for name in ('srcport', 'dstport', 'policyid', 'sessionid', 'sentbyte', 'rcvdbyte'):
        if name in fields:
            try:
                value = int(fields[name])
            except ValueError:
                raise ValueError('Invalid FortiGate integer field') from None
            if value < 0 or (name in {'srcport', 'dstport'} and value > 65535):
                raise ValueError('Invalid FortiGate integer range')
            fields[name] = value
    action = fields.get('action')
    if action and fields['type'] in {'traffic', 'utm'}:
        security['action'] = 'network_connection'
        security['provenance']['action'] = ['raw.fortigate.action']
        if action in {'deny', 'block', 'blocked', 'dropped'}:
            security['outcome'] = 'blocked'
        elif action in {'accept', 'allow', 'close'}:
            security['outcome'] = 'observed'
    return normalize({
        'event_id': item['id'], 'event_time': timestamp(fields),
        'source': 'fortigate', 'sourcetype': 'fortigate:kv',
        'host': fields.get('devname', fields['devid']),
        'severity': {'emergency': 'critical', 'alert': 'high', 'critical': 'critical',
                     'error': 'high', 'warning': 'medium', 'notice': 'info',
                     'information': 'info', 'debug': 'debug'}.get(fields.get('level'), 'info'),
        'message': item['log'], 'index': index,
        'raw': {'fortigate': fields, 'security': security},
    })


def intake(store, actor, data):
    if not isinstance(data, dict) or set(data) != {'index', 'events'}:
        raise ValueError('FortiGate intake requires index and events only')
    events = data['events']
    if not isinstance(events, list) or not 1 <= len(events) <= 1000:
        raise ValueError('FortiGate batch must contain 1..1000 events')
    index = data['index']
    records = [envelope(item, index) for item in events]
    with store.write_lock:
        with store.control() as db:
            current = principal.current(db, actor, ('admin', 'analyst'))
            policies = pipeline.for_ingest(db, current['tenant'])
            for record in records:
                routed, _ = pipeline.apply(record, policies.get(record['source']))
                if not principal.contains(current['allowed_indexes'], sorted({index, routed['index']})):
                    raise PermissionError('FortiGate index or parser route exceeds current permissions')
        return store.ingest(
            current['tenant'], records, current['name'],
            allowed_indexes=current['allowed_indexes'],
            authorization=lambda db: principal.current(db, actor, ('admin', 'analyst'))['allowed_indexes'],
        )


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool

    @app.post('/api/fortigate/intake', status_code=202)
    async def ingest(request: Request):
        actor = who(request, ('admin', 'analyst'))
        return await run_in_threadpool(intake, store, actor, await body(request))
