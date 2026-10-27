"""Tenant/source-bound identity/mail intake into native detection and Case."""
# ruff: noqa: F811 - imported disposable Store fixture.
import json

import pytest

from sapientia import (
    connector_runtime,
    enterprise_adapters,
    intelligence,
    source_registry,
)
from tests.test_backend_upgrade import actor, lab  # noqa: F401 - owned Store fixture.

TENANT = '00000000-0000-4000-8000-000000000001'
USER = '00000000-0000-4000-8000-000000000002'


def signin():
    return {'tenant_id': TENANT, 'record': {'id': 'signin-test-01', 'createdDateTime': '2026-10-16T01:00:00Z',
            'userId': USER, 'userPrincipalName': 'analyst@example.test', 'ipAddress': '192.0.2.10',
            'status': {'errorCode': 0}, 'riskLevelAggregated': 'high'}}


def audit():
    return {'Id': 'mail-test-01', 'CreationTime': '2026-10-16T01:00:01Z', 'OrganizationId': TENANT,
            'RecordType': 1, 'Operation': 'New-InboxRule', 'UserId': 'analyst@example.test',
            'Workload': 'Exchange', 'ClientIP': '[2001:db8::1]:443', 'ResultStatus': 'Succeeded',
            'Parameters': [{'Name': 'ForwardTo', 'Value': 'external@example.test'}]}


def source(store, product):
    return source_registry.save(store, actor(), {'index': 'public', 'product': product, 'account': TENANT,
        'realm': 'virtual-lab', 'credential_ref': 'env:SAPIENTIA_CONNECTOR_ENTERPRISE', 'version': 0})


@pytest.mark.parametrize('product,event', [('entra_signin', signin), ('m365_audit', audit)])
def test_real_receipt_projection_atomic_and_case(lab, product, event):
    s = source(lab, product)
    definition = enterprise_adapters.starter(lab, actor(), s['id'])
    policy = intelligence.save_policy(lab, actor(), definition)
    intelligence.review_policy(lab, actor('peer'), policy['id'], {'version': 1, 'approve': True, 'reason': 'Reviewed vendor originals and source tenant authority'})
    batch = {'version': 1, 'events': [event()], 'cursor': 'page-1', 'checkpoint_version': 0}
    result = connector_runtime.intake(lab, actor(), s['id'], batch)
    assert result['accepted'] == 1
    assert connector_runtime.intake(lab, actor(), s['id'], batch)['duplicate'] == 1
    lab.flush()
    for _ in range(4):
        intelligence.run_due(lab, original_budget=2, budget=2, max_runs=4, include_ml=False)
    with lab.control() as db:
        signal = db.execute("SELECT body FROM intelligence_signals WHERE kind='atomic' AND rule_id=?", (policy['id'],)).fetchone()
        assert signal is not None
        body = json.loads(signal[0])
        assert body['automatic_endpoint_authorization'] is False
        assert db.execute('SELECT count(*) FROM incidents').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM endpoint_responses').fetchone()[0] == 0
    assert result['native_capture_proven'] is False


def test_foreign_tenant_and_ambiguous_identity_are_not_merged(lab):
    s = source(lab, 'entra_signin')
    forged = signin()
    forged['tenant_id'] = '00000000-0000-4000-8000-000000000099'
    with pytest.raises(PermissionError):
        enterprise_adapters.decode(forged, {**s, 'index_name': 'public'})
    mail = enterprise_adapters.decode(audit(), {**source(lab, 'm365_audit'), 'index_name': 'public'})
    assert mail['raw']['xdr']['data']['user']['id'] is None
    assert mail['raw']['security']['src_ip'] == '2001:db8::1'
    assert mail['raw']['m365_audit'] == audit()


@pytest.mark.parametrize('change', [lambda r:r.update(status={'errorCode':'0'}), lambda r:r.update(userId='email@example.test'), lambda r:r.update(createdDateTime='2026-10-16T01:00:00')])
def test_malformed_vendor_contract_fails_closed(lab, change):
    row=signin();change(row['record'])
    with pytest.raises(ValueError):
        enterprise_adapters.decode(row,{**source(lab,'entra_signin'),'index_name':'public'})


def test_source_revoke_prevents_admission(lab):
    s=source(lab,'m365_audit')
    source_registry.revoke(lab,actor(),s['id'],1)
    with pytest.raises(Exception, match='Source version/authority changed'):
        connector_runtime.intake(lab,actor(),s['id'],{'version':1,'events':[audit()],'cursor':'revoked','checkpoint_version':0})
