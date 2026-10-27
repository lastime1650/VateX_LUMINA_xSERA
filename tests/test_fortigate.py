import time

import pytest

from sapientia import fortigate


def sample(**fields):
    body = {'eventtime': str(int(time.time()) * 10**9), 'devid': 'FGT-QA', 'devname': 'qa-fw',
            'type': 'traffic', 'subtype': 'forward', 'srcip': '192.0.2.10',
            'dstip': '198.51.100.20', 'srcport': '1234', 'dstport': '443',
            'action': 'deny', 'sessionid': '123', 'policyid': '10', 'level': 'warning'}
    body.update(fields)
    return ' '.join(f'{key}="{value}"' for key, value in body.items())


def test_fortigate_preserves_firewall_identity_and_canonical_ips():
    item = fortigate.envelope({'id': '1', 'log': sample()}, 'firewall')
    assert item['host'] == 'qa-fw'
    assert item['raw']['security']['src_ip'] == '192.0.2.10'
    assert item['raw']['security']['outcome'] == 'blocked'
    assert item['raw']['fortigate']['sessionid'] == 123
    assert item['severity'] == 'medium'
    assert abs(item['event_time'] - time.time()) < 2


@pytest.mark.parametrize('text', [
    sample() + ' srcip=192.0.2.20', sample() + ' unexpected',
    'type=traffic devid="unfinished', sample(srcip='not-ip'),
    sample(dstport='65536'), sample(eventtime='bad'), sample(eventtime='-1'), sample(eventtime='9' * 400),
], ids=['duplicate-srcip', 'unexpected-fragment', 'unterminated-quote', 'invalid-srcip',
        'invalid-dstport', 'invalid-time', 'negative-time', 'oversized-time'])
def test_invalid_fortigate_records_fail_without_partial_mapping(text):
    with pytest.raises(ValueError):
        fortigate.envelope({'id': '1', 'log': text}, 'firewall')


def test_fields_do_not_promote_firewall_source_ip_to_host():
    fields = fortigate.parse(sample(msg='hello world'))
    assert fields['msg'] == 'hello world'
    item = fortigate.envelope({'id': '1', 'log': sample()}, 'network')
    assert item['host'] != item['raw']['security']['src_ip']


def test_fortigate_seconds_and_timezone_timestamp():
    fields = fortigate.parse(sample(eventtime='1700000000'))
    assert fortigate.timestamp(fields) == 1700000000
    assert fortigate.timestamp({'date': '2023-11-15', 'time': '07:13:20', 'tz': '+0900'}) == 1700000000


def test_system_login_is_not_classified_as_network_connection():
    item = fortigate.envelope({'id': 'system-login', 'log': sample(type='event', subtype='system', action='login')}, 'network')
    assert 'action' not in item['raw']['security']
