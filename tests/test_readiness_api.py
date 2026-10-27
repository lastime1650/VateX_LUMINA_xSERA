"""Readiness routes expose only current tenant scope and enforce review roles."""
# ruff: noqa: F811 - imported disposable HTTP fixture.
from tests.test_api import client, sign_in  # noqa: F401


def test_routes_auth_scope_and_read_only_controls(client):
    paths=('/api/ops/qualification/status','/api/ops/source-slo','/api/ops/pipeline')
    for path in paths:
        assert client.get(path).status_code==401
    sign_in(client,'viewer','viewer')
    for path in paths:
        response=client.get(path)
        assert response.status_code==200,response.text
    assert client.get('/api/ops/pipeline').json()['dispatch']=={'durable_poll_fallback':True}
    assert client.post('/api/ops/qualification/plans',json={'name':'Unauthorized','indexes':['main'],'kind':'response_twin','expected_revision':0}).status_code==403
    assert client.get('/api/ops/integrity/status').status_code==403
    assert client.get('/api/research/runs/missing/trace').status_code==404
    assert client.get('/api/intelligence/signals/missing/evidence').status_code==404
    assert client.get('/api/intelligence/signals/missing/evidence?count=33').status_code==400
    shell=client.get('/').text
    assert 'console_readiness.js' in shell


def test_source_and_enterprise_starter_scope(client):
    sign_in(client)
    result=client.post('/api/v2/sources',json={'index':'enterprise','product':'m365_audit','account':'00000000-0000-4000-8000-000000000001','realm':'virtual-lab','credential_ref':'env:SAPIENTIA_CONNECTOR_ENTERPRISE','version':0})
    assert result.status_code==201,result.text
    identifier=result.json()['id']
    starter=client.get('/api/ops/enterprise/sources/'+identifier+'/starter')
    assert starter.status_code==200,starter.text
    assert any(f['field']=='projection.source_version' and f['value']==1 for f in starter.json()['filters'])
    assert any(f['field'].endswith('mail_forwarding_configured') for f in starter.json()['filters'])
    sign_in(client,'foreign','admin','another')
    assert client.get('/api/ops/enterprise/sources/'+identifier+'/starter').status_code==404
    assert client.get('/api/ops/source-slo').json()['items']==[]
