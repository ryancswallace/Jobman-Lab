#!/usr/bin/env python3
"""Pure, one-time synthetic API authentication-master rotation plan."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rotation_runtime', HERE / 'dashboard-multisource-runtime.py')
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
need, sha, encoded = r.need, r.sha, r.encoded
REVISION = 8
HOSTS = ('pg01', 'control01', 'storage01')
ROLES = ('api', 'worker', 'broker')
API_ROOT = '/etc/jobman-dashboard-api-lab'
KEY_FILE = API_ROOT + '/authentication-rotation-v1.key'
KEY_ID = 'lab-auth-rotation-v1'
DRAFT = API_ROOT + '/authentication-rotation-v1.json'
BASE = '/etc/jobman-dashboard-auth-rotation-lab'
RECOVERY_BEFORE = '/etc/jobman-dashboard-operator-lab/scale-recovery.json'
RECOVERY_AFTER = BASE + '/recovery.json'
OPERATOR = '/etc/jobman-dashboard-operator-lab/config.json'
PRIVILEGED_DSN = '/etc/jobman-dashboard-app-lab/database-url'
CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'
FILES = ('dashboard-auth-rotation-plan.py', 'dashboard-auth-rotation-guest.py', 'rotate-dashboard-auth.py', 'dashboard-multisource-runtime.py')
HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
SOURCES = {'72000000-0000-4000-8000-000000000001': 'e633cf92-258d-48ff-965a-fda88d68ef3a',
           '72000000-0000-4000-8000-000000000002': 'a4f0e2ab-7323-4c90-9510-1f073c660f06'}


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json_key'); result[key] = value
        return result
    need(isinstance(raw, bytes) and 0 < len(raw) <= 4 << 20, 'json_bound')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'json_constant'))


def unb64(value):
    need(isinstance(value, str) and len(value) <= 2 << 20, 'base64_bound')
    raw = base64.b64decode(value, validate=True)
    need(0 < len(raw) <= 1 << 20, 'decoded_bound'); return raw


def decimal(value, positive=False):
    return isinstance(value, str) and re.fullmatch('[1-9][0-9]{0,18}' if positive else '(0|[1-9][0-9]{0,18})', value) and int(value) <= (1 << 63) - 1


def stable_database(value):
    need(set(value) == {'ledger', 'databaseOID', 'hold', 'sources', 'rolesSHA256'}, 'database_shape')
    ledger = value['ledger']
    need(len(ledger) == 18 and [x['name'].split('_', 1)[0] for x in ledger] == ['migrations/%06d' % n for n in range(1, 19)] and
         all(set(x) == {'name', 'sha256'} and re.fullmatch(r'migrations/[0-9]{6}_[a-z_]+\.sql', x['name']) and HEX.fullmatch(x['sha256']) for x in ledger), 'schema_ledger')
    need(decimal(value['databaseOID'], True) and HEX.fullmatch(value['rolesSHA256']), 'database_identity')
    need(len(value['sources']) == 2 and {s['deploymentId']: s['controlInstanceId'] for s in value['sources']} == SOURCES, 'source_identity')
    for source in value['sources']:
        need(set(source) == {'deploymentId', 'controlInstanceId', 'recoveryEpoch', 'namespaceIds', 'configurationRevision', 'state', 'generation', 'lastPosition', 'openGaps', 'unfinishedRecoveries'}, 'source_shape')
        need(source['state'] == 'active' and type(source['configurationRevision']) is int and source['configurationRevision'] == REVISION and
             source['recoveryEpoch'] == '1' and decimal(source['generation'], True) and decimal(source['lastPosition']) and
             type(source['openGaps']) is int and source['openGaps'] == 0 and type(source['unfinishedRecoveries']) is int and source['unfinishedRecoveries'] == 0, 'source_not_ready')
        ns = source['namespaceIds']
        need(isinstance(ns, list) and len(ns) == (12 if source['deploymentId'].endswith('1') else 7) and len(set(ns)) == len(ns) and all(UUID.fullmatch(n) for n in ns), 'source_scope')
    hold = value['hold']
    need(set(hold) == {'held', 'generation', 'suppressRecordedThrough'} and hold['held'] is False and decimal(hold['generation'], True) and
         (hold['suppressRecordedThrough'] is None or isinstance(hold['suppressRecordedThrough'], str)), 'delivery_hold')
    return value


def database_continuity(before, after):
    stable_database(before); stable_database(after)
    old, new = copy.deepcopy(before), copy.deepcopy(after)
    for prior, current in zip(old['sources'], new['sources']):
        need(prior['deploymentId'] == current['deploymentId'], 'source_order')
        for field in ('generation', 'lastPosition'):
            need(int(current.pop(field)) >= int(prior.pop(field)), 'feed_regressed')
    need(old == new, 'database_authority_changed')


def transform(raw):
    value = decode(raw)
    need(value.get('publicOrigin') == 'https://dashboard.lab.test:8443' and value.get('listen') == '10.77.0.10:8443' and value.get('oidc', {}).get('issuer') == 'https://oidc.lab.test:8443/realms/jobman-lab', 'synthetic_api_boundary')
    need(type(value.get('configurationRevision')) is int and value['configurationRevision'] == REVISION, 'configuration_revision')
    encryption = value.get('encryption', {})
    need(set(encryption) == {'keyId', 'keyFile'} and isinstance(encryption['keyId'], str) and 1 <= len(encryption['keyId']) <= 64 and encryption['keyId'] != KEY_ID and
         encryption['keyFile'].startswith(API_ROOT + '/') and encryption['keyFile'] != KEY_FILE, 'previous_authentication_key')
    need(value.get('logCursorKeyFile', '').startswith(API_ROOT + '/') and value.get('reports', {}).get('policyKeyFile', '').startswith(API_ROOT + '/') and
         value.get('notifications', {}).get('tokenEncryption', {}).get('current', {}).get('keyFile', '').startswith(API_ROOT + '/') and
         not value.get('notifications', {}).get('previousTokenKeys'), 'dedicated_purpose_keys_required')
    before = copy.deepcopy(value); value['encryption'] = {'keyId': KEY_ID, 'keyFile': KEY_FILE}
    # A legacy master must not also appear as any purpose, TLS or database key.
    need(encoded(before).count(encryption['keyFile'].encode()) == 1, 'authentication_key_reused')
    return encoded(value)


def make(snapshot, commit, implementation):
    need(COMMIT.fullmatch(commit) and set(implementation) == set(FILES) and all(HEX.fullmatch(v) for v in implementation.values()), 'implementation_pin')
    need(set(snapshot) == {'format', 'capturedAt', 'hosts'} and snapshot['format'] == 1 and type(snapshot['capturedAt']) is int and set(snapshot['hosts']) == set(HOSTS), 'snapshot_shape')
    database = stable_database(snapshot['hosts']['pg01']['database'])
    controls = None
    for role in ROLES:
        host, root, uid, _, unit, binary, _ = r.SPECS[role]
        value = snapshot['hosts'][host]['roles'][role]; config = decode(unb64(value['config']))
        process = value['process']
        need(process['binary'] == '/opt/jobman-dashboard-lab/releases/' + commit + '/bin/' + binary and process['uid'] == uid and
             process['unit'] == unit and HEX.fullmatch(process['binarySHA256']) and process['unitSHA256'] == sha(unb64(value['unit'])) and
             decimal(process['pid'], True) and decimal(process['startedMonotonic'], True) and UUID.fullmatch(process['bootId']), 'process_identity')
        need(config.get('configurationRevision') == REVISION and type(config['configurationRevision']) is int and
             len(config['controls']) == 2 and {s['id']: s['expectedInstanceId'] for s in config['controls']} == SOURCES, 'configuration_sources')
        for control in config['controls']:
            need(control['origin'] == 'https://10.77.0.21:' + ('18443' if control['id'].endswith('1') else '28443'), 'source_origin')
            source = next(s for s in database['sources'] if s['deploymentId'] == control['id'])
            need(sorted(control['namespaceIds']) == sorted(source['namespaceIds']), 'configuration_scope')
        if role == 'worker': controls = config['controls']
    api = snapshot['hosts']['storage01']['roles']['api']; before = unb64(api['config']); after = transform(before)
    old_key = decode(before)['encryption']['keyFile']
    need(api['materials'][old_key]['bytes'] == 32, 'previous_key_length')
    recovery = snapshot['hosts']['storage01']['recovery']
    recovery_before = unb64(recovery['config']); expected = decode(before)
    expected['databaseURLFile'] = PRIVILEGED_DSN; expected['controls'] = controls; expected.pop('observability', None)
    # The scale activation draft is immutable evidence; only its exact pinned
    # old static root may differ from a subsequent candidate-only API upgrade.
    old_web = decode(recovery_before).get('webRoot')
    need(isinstance(old_web, str) and re.fullmatch('/opt/jobman-dashboard-lab/releases/[0-9a-f]{40}/web', old_web), 'recovery_static_root')
    expected['webRoot'] = old_web
    need(decode(recovery_before) == expected, 'recovery_identity')
    recovery_after = transform(recovery_before)
    return {'format': 1, 'scenario': 'dashboard-api-authentication-rotation', 'synthetic': True, 'revision': commit,
            'configurationRevision': REVISION, 'keyId': KEY_ID, 'keyFile': KEY_FILE, 'recoveryFile': RECOVERY_AFTER,
            'snapshot': snapshot, 'implementationSHA256': implementation,
            'beforeConfigSHA256': sha(before), 'afterConfigSHA256': sha(after), 'afterConfig': base64.b64encode(after).decode(),
            'beforeRecoverySHA256': sha(recovery_before), 'afterRecoverySHA256': sha(recovery_after), 'afterRecovery': base64.b64encode(recovery_after).decode()}


def validate(plan):
    need(isinstance(plan, dict) and plan == make(plan['snapshot'], plan['revision'], plan['implementationSHA256']), 'plan_recomputed')
