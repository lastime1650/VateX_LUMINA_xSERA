import time

import pytest
from fastapi.testclient import TestClient

from sapientia import access, auth, pipeline
from sapientia.api import create_app
from sapientia.storage import Settings

PASSWORD = 'FortiGate-isolated-QA-only-2026'


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    store = app.state.store
    for name, role, tenant, indexes in [
        ('administrator', 'admin', 'a', ['*']),
        ('network_reader', 'analyst', 'a', ['network']),
        ('viewer', 'viewer', 'a', ['network']),
        ('other', 'admin', 'b', ['*']),
    ]:
        auth.create_user(store, name, PASSWORD, role, tenant)
        access.set_for_user(store, {'name': 'administrator' if tenant == 'a' else 'other',
                                   'role': 'admin', 'tenant': tenant}, name, indexes)
    with TestClient(app) as client:
        yield client


def login(client, name):
    result = client.post('/api/login', json={'name': name, 'password': PASSWORD})
    assert result.status_code == 200
    client.headers['X-CSRF-Token'] = result.json()['csrf']


def body():
    return {'index': 'network', 'events': [{'id': 'fixed', 'log':
        f'eventtime={int(time.time())} devid=FGT-QA type=traffic srcip=192.0.2.1 '
        'dstip=198.51.100.1 action=accept sessionid=100 policyid=1 level=notice'}]}


def count(client, table):
    assert table in {'receipts', 'queue'}
    with client.app.state.store.control() as db:
        return db.execute('SELECT count(*) FROM ' + table).fetchone()[0]


def test_fortigate_auth_roles_exact_index_csrf_and_no_partial_admission(client):
    payload = body()
    assert client.post('/api/fortigate/intake', json=payload).status_code == 401
    login(client, 'viewer')
    assert client.post('/api/fortigate/intake', json=payload).status_code == 403
    login(client, 'network_reader')
    csrf = client.headers.pop('X-CSRF-Token')
    assert client.post('/api/fortigate/intake', json=payload).status_code == 403
    client.headers['X-CSRF-Token'] = csrf
    payload['index'] = 'private'
    assert client.post('/api/fortigate/intake', json=payload).status_code == 403
    payload['index'] = 'network'
    payload['events'].append({'id': 'invalid', 'log': 'broken'})
    assert client.post('/api/fortigate/intake', json=payload).status_code == 400
    assert count(client, 'receipts') == count(client, 'queue') == 0


def test_fortigate_real_intake_retry_content_conflict_and_tenant_binding(client):
    login(client, 'network_reader')
    payload = body()
    result = client.post('/api/fortigate/intake', json=payload)
    assert result.status_code == 202 and result.json()['accepted'] == 1
    duplicate = client.post('/api/fortigate/intake', json=payload)
    assert duplicate.status_code == 202 and duplicate.json()['duplicate'] == 1
    payload['events'][0]['log'] += ' msg=changed'
    assert client.post('/api/fortigate/intake', json=payload).status_code == 409
    login(client, 'other')
    assert client.post('/api/fortigate/intake', json=payload).status_code == 202
    assert count(client, 'receipts') == 2


def test_parser_cannot_route_network_only_user_into_private_index(client):
    actor = {'name': 'administrator', 'role': 'admin', 'tenant': 'a', 'allowed_indexes': ['*']}
    pipeline.save(client.app.state.store, actor, 'fgt-private', {
        'version': 0,
        'definition': {'source': 'fortigate', 'route_index': 'private', 'enabled': True},
    })
    login(client, 'network_reader')
    assert client.post('/api/fortigate/intake', json=body()).status_code == 403
    assert count(client, 'receipts') == 0
