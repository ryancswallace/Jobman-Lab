#!/usr/bin/env python3
"""Bounded offline planning for an isolated Dashboard backup/restore exercise.

No guest access, credential reads, SQL, service actions or backup claims occur.
A later reviewed driver must collect and compare actual live snapshot evidence.
"""
import copy
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat

spec = importlib.util.spec_from_file_location('restore_shared', Path(__file__).with_name('dashboard-split-plan.py'))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
require, decode, encoded, sha = shared.require, shared.decode, shared.encoded, shared.sha
PRIMARY = {'api': '/etc/jobman-dashboard-api-lab', 'worker': '/etc/jobman-dashboard-worker-lab'}
ROOTS = {role: '/etc/jobman-dashboard-restore-' + role + '-lab' for role in ('api', 'worker', 'operator')}
DATABASE = 'jobman_dashboard_restore'
REPORT_ROOT = '/var/lib/jobman-dashboard-restore-reports-lab'
PUBLIC_ORIGIN = 'https://dashboard.lab.test:38443'
IDENTITIES = {'api': {'name': 'jobman-dash-restore-api', 'uid': 21909, 'gid': 21909},
              'worker': {'name': 'jobman-dash-restore-worker', 'uid': 21910, 'gid': 21910},
              'reader': {'name': 'jobman-dash-restore-readers', 'gid': 21911}}
COMPONENTS = {'api': ['api'], 'worker': ['ingestion', 'notifications', 'reports'], 'operator': ['operator']}
SOURCES = {'72000000-0000-4000-8000-000000000001': 'https://10.77.0.21:18443',
           '72000000-0000-4000-8000-000000000002': 'https://10.77.0.21:28443'}
PUBLIC_CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'
ISSUER = 'https://oidc.lab.test:8443/realms/jobman-lab'
LIMITS = {'databaseBytes': 1 << 30, 'dumpBytes': 1 << 30, 'reportBytes': 1 << 30,
          'reportFiles': 10000, 'materialFiles': 128, 'materialBytes': 32 << 20,
          'fileBytes': 1 << 20, 'primaryStoppedSeconds': 180, 'dumpSeconds': 90,
          'restoreSeconds': 180, 'reserveBytes': 256 << 20, 'replayPagesPerStep': 50,
          'maximumReplayPages': 1000, 'cloneLifetimeHours': 24}
DECIMAL = re.compile(r'[1-9][0-9]{0,18}\Z')


def decimal(value):
    return isinstance(value, str) and DECIMAL.fullmatch(value) and int(value) <= (1 << 63) - 1


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 40 and value.endswith('Z'), 'UTC timestamp required')
    parsed = datetime.fromisoformat(value[:-1] + '+00:00')
    require(parsed.tzinfo == timezone.utc, 'UTC timestamp required')
    return parsed


def private_read(path, maximum=256 << 10):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'Real absolute input path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
                0 < before.st_size <= maximum, 'Private bounded operator input required')
        raw = stream.read(maximum + 1)
        after, named = os.fstat(stream.fileno()), path.lstat()
        require(len(raw) == before.st_size and (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) ==
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size) and
                (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino), 'Input changed while reading')
        return raw


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def directory(path):
    previous = os.umask(0o077)
    try:
        path.mkdir(mode=0o700)
    finally:
        os.umask(previous)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(fd, 0o700)
        os.fsync(fd)
    finally:
        os.close(fd)


def file_references(value, result=None):
    result = {} if result is None else result
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith('File'):
                require(isinstance(item, str) and item.startswith('/') and str(PurePosixPath(item)) == item and
                        '..' not in PurePosixPath(item).parts and len(item) <= 512, 'Unsafe file reference')
                if key not in ('databaseURLFile', 'operatorConfigFile'):
                    result[item] = True
            else:
                file_references(item, result)
    elif isinstance(value, list):
        for item in value:
            file_references(item, result)
    return result


def binding(control):
    namespaces = control.get('namespaceIds', [])
    require(isinstance(namespaces, list) and 1 <= len(namespaces) <= 320 and
            len(set(namespaces)) == len(namespaces) and all(shared.UUID.fullmatch(n) for n in namespaces), 'Invalid namespace set')
    require(control.get('id') in SOURCES and control.get('origin') == SOURCES[control['id']] and
            shared.UUID.fullmatch(control.get('expectedInstanceId', '')), 'Unapproved synthetic source')
    for key in ('serviceId', 'delegationKeyId', 'audience'):
        require(isinstance(control.get(key), str) and 0 < len(control[key]) <= 256, 'Source identity missing')
    return {'deploymentId': control['id'], 'controlInstanceId': control['expectedInstanceId'],
            'namespaceIds': sorted(namespaces)}


def validate(api, worker, snapshot, metadata):
    require(api.get('publicOrigin') == 'https://dashboard.lab.test:8443' and api.get('listen') == '10.77.0.10:8443', 'Only primary Lab API supported')
    require(api.get('oidc', {}).get('issuer') == ISSUER and worker.get('identityIssuer') == ISSUER, 'Synthetic identity issuer differs')
    require(api.get('events') == {'enabled': True, 'deliveryHold': False} and worker.get('deliveryHold', False) is False,
            'Primary must be explicitly active; never release its hold during planning')
    require(worker.get('components') == ['ingestion', 'notifications', 'reports', 'retention'], 'Unexpected primary worker responsibilities')
    for role, config in (('api', api), ('worker', worker)):
        require(config.get('databaseURLFile') == PRIMARY[role] + '/database-url', 'Primary database configuration differs')
        require(config.get('reports', {}).get('objectRoot') == '/var/lib/jobman-dashboard-reports-lab' and
                config['reports'].get('objectAccess') == {'mode': 'shared_group', 'workerUid': 21905, 'readerGid': 21906}, 'Primary report storage differs')
        require(not config.get('notifications', {}).get('apns'), 'Provider-configured primary needs another reviewed recovery exercise')
    require(not any(worker.get('notifications', {}).get(k) for k in ('tokenEncryption', 'previousTokenKeys')), 'Worker holds unnecessary token material')
    revision = api.get('configurationRevision')
    require(type(revision) is int and 0 < revision < 1 << 63 and worker.get('configurationRevision') == revision, 'API/worker registry revisions differ')
    require(snapshot.get('formatVersion') == 1 and snapshot.get('synthetic') is True and
            snapshot.get('database') == 'jobman_dashboard' and snapshot.get('candidateRevision') == metadata['revision'] and
            snapshot.get('configurationRevision') == revision, 'Live snapshot identity differs')
    timestamp(snapshot.get('capturedAt'))
    require(snapshot.get('schema', {}).get('migrationCount') == 18 and shared.HEX.fullmatch(snapshot['schema'].get('ledgerSHA256', '')), 'Exact schema18 proof required')
    hold = snapshot.get('hold', {})
    require(hold.get('held') is False and decimal(hold.get('generation')), 'Primary active hold receipt required')
    if hold.get('suppressRecordedThrough'):
        timestamp(hold['suppressRecordedThrough'])
    api_controls, worker_controls = api.get('controls', []), worker.get('controls', [])
    require(1 <= len(api_controls) <= 2 and len(worker_controls) == len(api_controls), 'All configured Lab sources required')
    expected = sorted([binding(c) for c in api_controls], key=lambda c: c['deploymentId'])
    require(len({c['deploymentId'] for c in expected}) == len(expected) and expected ==
            sorted([binding(c) for c in worker_controls], key=lambda c: c['deploymentId']), 'API/worker source sets differ')
    observed = snapshot.get('sources', [])
    require(isinstance(observed, list) and len(observed) == len(expected), 'Retained feed/source set is incomplete')
    actual = []
    for item in observed:
        require(set(item) == {'deploymentId', 'controlInstanceId', 'recoveryEpoch', 'namespaceIds', 'configurationRevision', 'state'} and
                item['configurationRevision'] == revision and item['state'] == 'active' and decimal(item['recoveryEpoch']), 'Every current source feed must be active and pinned')
        actual.append({key: item[key] for key in ('deploymentId', 'controlInstanceId', 'namespaceIds')})
    require(sorted(actual, key=lambda c: c['deploymentId']) == expected, 'Exact live namespace/instance set differs')
    for config in (api, worker):
        brokers = config.get('logBrokers', [])
        require(isinstance(brokers, list) and 1 <= len(brokers) <= 4 and
                len({b['id'] for b in brokers}) == len(brokers), 'Bounded distinct broker set required')
        scopes = {entry['deploymentId']: set(entry['namespaceIds']) for entry in expected}
        for broker in brokers:
            require(broker.get('origin') == 'https://10.77.0.21:19443' and broker.get('deploymentId') in scopes and
                    isinstance(broker.get('namespaceIds'), list) and len(broker['namespaceIds']) > 0 and
                    set(broker['namespaceIds']) <= scopes[broker['deploymentId']], 'Broker source/scope differs')
        by_id = {b['id']: b for b in brokers}
        for mapping in config.get('logMappings', []):
            require(mapping.get('brokerId') in by_id and mapping.get('deploymentId') == by_id[mapping['brokerId']]['deploymentId'] and
                    shared.UUID.fullmatch(mapping.get('targetGenerationId', '')) and
                    isinstance(mapping.get('storeName'), str) and 0 < len(mapping['storeName']) <= 128 and
                    decimal(mapping.get('storeVersion')), 'Log mapping binding differs')
    require(api.get('logMappings') == worker.get('logMappings') and 1 <= len(api['logMappings']) <= 128, 'Complete report/log mapping set required')
    require(len({(m['deploymentId'], m['targetGenerationId'], m['storeName'], m['storeVersion']) for m in api['logMappings']}) == len(api['logMappings']), 'Duplicate log mappings')
    return revision, sorted(observed, key=lambda c: c['deploymentId'])


def configs(api, worker, snapshot, metadata):
    revision, sources = validate(api, worker, snapshot, metadata)
    generated, copies = {}, []
    inventory = snapshot.get('files', [])
    require(isinstance(inventory, list) and len(inventory) <= LIMITS['materialFiles'], 'Material inventory exceeds bound')
    by_path = {item['path']: item for item in inventory}
    require(len(by_path) == len(inventory), 'Duplicate material inventory')
    all_references = set()
    for role, original in (('api', api), ('worker', worker)):
        config = copy.deepcopy(original)
        references = file_references(config)
        replacement = {}
        for source in sorted(references):
            require(source.startswith(PRIMARY[role] + '/') or source == PUBLIC_CA, 'Role may not import another service private material')
            require(re.fullmatch(r'[A-Za-z0-9._-]{1,120}', PurePosixPath(source).name), 'Unsafe material name')
            require(source in by_path, 'Snapshot lacks referenced material')
            item = by_path[source]
            require(set(item) == {'path', 'sha256', 'bytes', 'uid', 'gid', 'mode'} and shared.HEX.fullmatch(item['sha256']) and
                    type(item['bytes']) is int and 0 < item['bytes'] <= LIMITS['fileBytes'], 'Material receipt invalid')
            expected_uid = 21904 if role == 'api' else 21905
            require((source == PUBLIC_CA and item['uid'] == 0 and item['gid'] == 0 and item['mode'] == '0644') or
                    (source != PUBLIC_CA and item['uid'] == expected_uid and item['gid'] == expected_uid and item['mode'] == '0600'), 'Material ownership changed')
            destination = ROOTS[role] + '/material/' + sha(source.encode())[:16] + '-' + PurePosixPath(source).name
            replacement[source] = destination
            copies.append(dict(item, role=role, destination=destination))
            all_references.add(source)
        def rewrite(value):
            if isinstance(value, dict):
                return {k: rewrite(v) for k, v in value.items()}
            if isinstance(value, list):
                return [rewrite(v) for v in value]
            return replacement.get(value, value) if isinstance(value, str) else value
        config = rewrite(config)
        config['databaseURLFile'] = ROOTS[role] + '/database-url'
        config['reports']['objectRoot'] = REPORT_ROOT
        config['reports']['objectAccess'] = {'mode': 'shared_group', 'workerUid': 21910, 'readerGid': 21911}
        config['observability'] = {'socketPath': '/run/jobman-dashboard-restore-' + role + '-lab/observe.sock'}
        if role == 'api':
            config['publicOrigin'], config['listen'] = PUBLIC_ORIGIN, '10.77.0.10:38443'
            config['events']['deliveryHold'] = True
            config['webRoot'] = '/opt/jobman-dashboard-lab/releases/' + metadata['revision'] + '/web'
        else:
            config['components'] = COMPONENTS['worker'][:]
            config['deliveryHold'] = True
        generated[role] = config
    require(set(by_path) == all_references and sum(v['bytes'] for v in inventory) <= LIMITS['materialBytes'], 'Extra or oversized backup material')
    # These exact private bytes determine reusable report redaction identity.
    for field in ('policyKeyFile', 'redactionFile'):
        left, right = api['reports'].get(field), worker['reports'].get(field)
        require(left in by_path and right in by_path and by_path[left]['sha256'] == by_path[right]['sha256'],
                'API/worker report policy bytes differ')
    generated['operator'] = {'schemaVersion': 1, 'databaseURLFile': ROOTS['operator'] + '/database-url',
                             'deployments': [{'id': s['deploymentId']} for s in sources]}
    recovery = copy.deepcopy(generated['api'])
    recovery['databaseURLFile'] = ROOTS['operator'] + '/recovery-database-url'
    recovery['controls'] = copy.deepcopy(generated['worker']['controls'])
    recovery['logBrokers'] = copy.deepcopy(generated['worker']['logBrokers'])
    recovery['logCursorKeyFile'] = generated['worker']['logCursorKeyFile']
    recovery.pop('observability', None)
    generated['recovery'] = recovery
    return generated, copies, sources, revision


def make_plan(metadata, archive_sha, inputs):
    require(shared.HEX.fullmatch(archive_sha), 'Expected candidate digest required')
    require(set(inputs) == {'api', 'worker', 'snapshot'}, 'Exactly API/worker and live state snapshots required')
    parsed = {k: decode(v) for k, v in inputs.items()}
    snapshot = parsed['snapshot']
    require(snapshot.get('apiSHA256') == sha(inputs['api']) and snapshot.get('workerSHA256') == sha(inputs['worker']), 'Snapshot/config CAS differs')
    generated, copies, sources, revision = configs(parsed['api'], parsed['worker'], snapshot, metadata)
    plan = {'formatVersion': 1, 'synthetic': True, 'applySupported': False,
            'scenario': 'isolated-dashboard-postgresql-restore', 'candidate': metadata,
            'archiveSHA256': archive_sha, 'configurationRevision': revision,
            'snapshotSHA256': sha(inputs['snapshot']), 'capturedAt': snapshot['capturedAt'],
            'inputSHA256': {k: sha(v) for k, v in inputs.items()}, 'sources': sources,
            'primary': {'database': 'jobman_dashboard', 'schema': snapshot['schema'], 'hold': snapshot['hold'],
                        'reportRoot': '/var/lib/jobman-dashboard-reports-lab'},
            'clone': {'database': DATABASE, 'schema': 'public', 'identities': IDENTITIES,
                      'roles': {r: DATABASE + '_' + r for r in ('ddl', 'api', 'worker', 'operator')},
                      'configRoots': ROOTS, 'reportRoot': REPORT_ROOT, 'publicOrigin': PUBLIC_ORIGIN,
                      'port': 38443, 'components': COMPONENTS, 'deliveryAllowed': False,
                      'providerCredentialsAllowed': False, 'startupHoldRequired': True},
            'limits': LIMITS, 'materialCopies': copies,
            'sourceIdentityPolicy': 'restore-original-role-specific-read-identities-no-registry-mutation',
            'recovery': {'externalCutoffRequired': True, 'allRetainedSourcesRequired': True,
                         'autoReplay': False, 'autoApply': False, 'autoResume': False},
            'phases': ['readonly-preflight', 'clone-provision', 'owned-scenario-baseline', 'coordinated-backup',
                       'post-backup-event-and-external-cutoff', 'restore-held', 'verify-restored',
                       'review-replay', 'review-apply', 'review-resume', 'post-restore-event', 'owned-cleanup']}
    return plan, generated


def capacity(database_bytes, report_bytes, material_bytes, pg_free, storage_free):
    require(all(type(v) is int and v >= 0 for v in (database_bytes, report_bytes, material_bytes, pg_free, storage_free)), 'Invalid capacity values')
    require(0 < database_bytes <= LIMITS['databaseBytes'] and report_bytes <= LIMITS['reportBytes'] and
            material_bytes <= LIMITS['materialBytes'], 'Backup exceeds reviewed bound')
    pg_required = 3 * database_bytes + LIMITS['dumpBytes'] + LIMITS['reserveBytes']
    storage_required = 2 * report_bytes + LIMITS['dumpBytes'] + (384 << 20) + material_bytes + LIMITS['reserveBytes']
    require(pg_free >= pg_required and storage_free >= storage_required, 'Insufficient backup/restore headroom')
    return {'pgRequiredBytes': pg_required, 'storageRequiredBytes': storage_required}
