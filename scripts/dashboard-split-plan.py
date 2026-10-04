#!/usr/bin/env python3
"""Pure, bounded planning for the isolated Dashboard API/worker cutover.

Never connects to a guest, loads credentials, starts a service or applies SQL.
The companion prepare command writes only a new private host staging directory.
"""
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

DEPLOYMENT = '72000000-0000-4000-8000-000000000001'
LEGACY = '/etc/jobman-dashboard-app-lab'
BROKER = '/etc/jobman-dashboard-broker-lab'
API = '/etc/jobman-dashboard-api-lab'
WORKER = '/etc/jobman-dashboard-worker-lab'
OPERATOR = '/etc/jobman-dashboard-operator-lab'
REPORT_OLD = '/var/lib/jobman-dashboard-app-lab/reports'
REPORT_NEW = '/var/lib/jobman-dashboard-reports-lab'
ROLE_COMPONENTS = {'api': ['api'], 'worker': ['ingestion', 'notifications', 'reports', 'retention'], 'operator': ['operator']}
IDENTITIES = {'api': {'name': 'jobman-dashboard-api', 'uid': 21904, 'gid': 21904},
              'worker': {'name': 'jobman-dashboard-worker', 'uid': 21905, 'gid': 21905},
              'reader': {'name': 'jobman-dashboard-report-readers', 'gid': 21906}}
READS = ['namespace.read', 'jobs.read', 'groups.read', 'targets.read', 'logs.read', 'artifacts.read', 'evidence.read', 'events.read']
WORKER_READS = ['namespace.read', 'jobs.read', 'logs.read', 'evidence.read', 'events.read']
HEX = re.compile(r'[0-9a-f]{64}\Z')
REVISION = re.compile(r'[0-9a-f]{40}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))


def read(path, maximum, private=False):
    path = Path(path)
    require(path.is_absolute(), 'Absolute path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, 'Bounded regular file required')
        if private:
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, 'Private operator-owned input required')
        raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size, 'File changed while reading')
        return raw


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def candidate_files(archive, expected):
    """Verify the exact reviewed candidate; never execute anything in it."""
    require(HEX.fullmatch(expected), 'Expected archive SHA256 required')
    raw = read(archive, 256 << 20)
    require(sha(raw) == expected, 'Candidate archive digest differs')
    files, total, top = {}, 0, None
    import io
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as source:
        for index, member in enumerate(source):
            path = PurePosixPath(member.name)
            require(index < 4096 and member.isfile() and not path.is_absolute() and len(path.parts) >= 2 and
                    '..' not in path.parts and '.' not in path.parts and '\\' not in member.name and
                    str(path) == member.name and len(member.name) <= 4096, 'Unsafe candidate member')
            if top is None:
                top = path.parts[0]
            require(path.parts[0] == top and 0 <= member.size <= 96 << 20, 'Candidate member bound differs')
            name = '/'.join(path.parts[1:])
            require(name not in files, 'Duplicate candidate member')
            total += member.size
            require(total <= 384 << 20, 'Expanded candidate bound exceeded')
            stream = source.extractfile(member)
            with stream:
                value = stream.read(member.size + 1)
            require(len(value) == member.size, 'Incomplete candidate member')
            files[name] = value
    require({'build.json', 'SHA256SUMS', 'bin/jobman-dashboard', 'bin/jobman-log-broker', 'web/index.html',
             'deploy/postgres/grants.py', 'deploy/postgres/grants.json'} <= files.keys(), 'Candidate lacks required components')
    metadata = decode(files['build.json'])
    require(metadata.get('formatVersion') == 1 and metadata.get('releaseState') == 'candidate' and
            metadata.get('os') == 'linux' and metadata.get('architecture') == 'arm64' and metadata.get('isa') == 'v8.0' and
            REVISION.fullmatch(metadata.get('revision', '')) and
            re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.[1-9][0-9]*', metadata.get('version', '')) and
            metadata.get('toolchains', {}).get('go') == 'go1.26.6', 'Candidate identity differs')
    require(top == 'jobman-dashboard_' + metadata['version'] + '_linux_arm64', 'Candidate directory differs')
    sums = {}
    for line in files['SHA256SUMS'].decode().splitlines():
        parts = line.split('  ', 1)
        require(len(parts) == 2 and HEX.fullmatch(parts[0]) and parts[1] not in sums, 'Invalid candidate checksums')
        sums[parts[1]] = parts[0]
    require(set(sums) == set(files) - {'SHA256SUMS'} and all(sha(files[name]) == value for name, value in sums.items()),
            'Candidate file checksum differs')
    for name in ('bin/jobman-dashboard', 'bin/jobman-log-broker'):
        value = files[name]
        require(value[:6] == b'\x7fELF\x02\x01' and value[18:20] == b'\xb7\x00', 'Candidate executable is not Linux arm64')
    grants = decode(files['deploy/postgres/grants.json'])
    require(grants.get('schemaMigration') == '000018_runtime_lock_privileges.sql', 'Candidate grants do not target schema18')
    return metadata, files


def validate_inputs(app, broker, fixture):
    require(fixture.get('synthetic') is True and fixture.get('endpoint') == 'https://10.77.0.21:18443' and
            UUID.fullmatch(fixture.get('instanceId', '')), 'Wrong synthetic source')
    namespaces = sorted(n['id'] for n in fixture['namespaces'])
    require(len(namespaces) == 2 and len(set(namespaces)) == 2 and all(UUID.fullmatch(n) for n in namespaces), 'Wrong namespaces')
    require(app.get('publicOrigin') == 'https://dashboard.lab.test:8443' and app.get('listen') == '10.77.0.10:8443' and
            app.get('databaseURLFile') == LEGACY + '/database-url' and app.get('encryption', {}).get('keyFile') == LEGACY + '/encryption-key' and
            app.get('reports', {}).get('objectRoot') == REPORT_OLD and app.get('events', {}).get('enabled') is True,
            'Existing combined runtime differs from supported split source')
    require(not app['reports'].get('objectAccess') and not app['reports'].get('policyKeyFile') and not app.get('logCursorKeyFile') and
            not app.get('notifications', {}).get('tokenEncryption') and not app.get('notifications', {}).get('apns'), 'Existing purpose key/profile state is unexpected')
    require(app.get('oidc', {}).get('issuer') == 'https://oidc.lab.test:8443/realms/jobman-lab', 'Wrong synthetic issuer')
    require(broker.get('publicOrigin') == 'https://10.77.0.21:19443' and broker.get('listen') == '10.77.0.21:19443' and
            broker.get('stateDirectory') == '/var/lib/jobman-dashboard-broker-lab', 'Wrong retained broker')
    for config in (app, broker):
        require(type(config.get('configurationRevision')) is int and 0 < config['configurationRevision'] < 1 << 62, 'Invalid config revision')
        controls = config.get('controls', [])
        require(len(controls) == 1 and controls[0].get('id') == DEPLOYMENT and controls[0].get('origin') == fixture['endpoint'] and
                controls[0].get('expectedInstanceId') == fixture['instanceId'] and sorted(controls[0].get('namespaceIds', [])) == namespaces,
                'Source registry binding differs')
    require(1 <= len(app.get('logMappings', [])) <= 64 and len(app['logMappings']) == len(broker.get('logRoots', [])), 'Incomplete mapping inventory')
    expected = {(m['deploymentId'], m['targetGenerationId'], m['storeName'], m['storeVersion']) for m in app['logMappings']}
    actual = {(m['deploymentId'], m['targetGenerationId'], m['storeName'], m['storeVersion']) for m in broker['logRoots']}
    require(expected == actual and len(expected) == len(app['logMappings']), 'App/broker mappings differ')
    require(all(m['root'] in ('/data/jobman/alice', '/data/jobman/alice/dashboard-execution') for m in broker['logRoots']), 'Unexpected physical store mapping')
    return namespaces


def service(role, kind):
    return 'dashboard-' + role + '-lab' + ('-broker' if kind == 'broker' else '')


def remap_paths(value, old, new):
    if isinstance(value, dict):
        return {key: remap_paths(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [remap_paths(item, old, new) for item in value]
    if isinstance(value, str) and value.startswith(old + '/'):
        return new + value[len(old):]
    return value


def configs(app, broker, fixture, revision, release_root):
    namespaces = validate_inputs(app, broker, fixture)
    require(revision == max(app['configurationRevision'], broker['configurationRevision']) + 1, 'Split revision must advance exactly once')
    api = remap_paths(copy.deepcopy(app), LEGACY, API)
    api['configurationRevision'] = revision
    api['webRoot'] = release_root + '/web'
    api['events']['deliveryHold'] = True
    api['reports'] = dict(api['reports'], objectRoot=REPORT_NEW,
                          objectAccess={'mode': 'shared_group', 'workerUid': 21905, 'readerGid': 21906},
                          policyKeyFile=API + '/report-policy.key')
    api['logCursorKeyFile'] = API + '/log-cursor.key'
    topics = copy.deepcopy(app.get('notifications', {}).get('deviceTopics', []))
    token_keys = [app['encryption']] + app.get('notifications', {}).get('previousTokenKeys', [])
    api['notifications'] = {'deviceTopics': topics, 'tokenEncryption': {
        'current': {'keyId': token_keys[0]['keyId'], 'keyFile': API + '/token-0.key'},
        'previous': [{'keyId': key['keyId'], 'keyFile': API + '/token-' + str(i) + '.key'} for i, key in enumerate(token_keys[1:], 1)]}}
    worker = {key: copy.deepcopy(api[key]) for key in ('configurationRevision', 'controls', 'logBrokers', 'logMappings', 'reports', 'logCursorKeyFile')}
    worker = remap_paths(worker, API, WORKER)
    worker.update(databaseURLFile=WORKER + '/database-url', components=ROLE_COMPONENTS['worker'],
                  identityIssuer=app['oidc']['issuer'], deliveryHold=True, notifications={'deviceTopics': topics})
    for role, config in (('api', api), ('worker', worker)):
        root = API if role == 'api' else WORKER
        for kind, entries in (('control', config['controls']), ('broker', config['logBrokers'])):
            require(len(entries) == 1, 'Only one isolated source/broker is supported by this initial plan')
            entry = entries[0]
            entry.update(serviceId=service(role, kind), delegationKeyId='split-' + role + '-' + kind + '-v1',
                         clientCertificateFile=root + '/' + kind + '-client.crt', clientKeyFile=root + '/' + kind + '-client.key',
                         delegationKeyFile=root + '/' + kind + '-signing-key.pem')
        config['observability'] = {'socketPath': '/run/jobman-dashboard-' + role + '-lab/observe.sock'}
    revised_broker = copy.deepcopy(broker)
    revised_broker['configurationRevision'] = revision
    revised_broker['observability'] = {'socketPath': '/run/jobman-dashboard-broker-lab/observe.sock'}
    require(len(revised_broker.get('services', [])) == 1, 'Unexpected preexisting broker callers')
    for role in ('api', 'worker'):
        revised_broker['services'].append({'keyId': 'split-' + role + '-broker-v1', 'serviceId': service(role, 'broker'),
            'audience': api['logBrokers'][0]['audience'], 'deploymentId': DEPLOYMENT, 'namespaceIds': namespaces,
            'clientCertificateFile': BROKER + '/' + role + '-client.crt', 'publicKeyFile': BROKER + '/' + role + '-signing-public.pem'})
    operator = {'schemaVersion': 1, 'databaseURLFile': OPERATOR + '/database-url', 'deployments': [{'id': DEPLOYMENT, 'name': 'Synthetic Dashboard Lab'}]}
    rollback = copy.deepcopy(app)
    rollback['configurationRevision'] = revision + 1
    rollback['webRoot'] = release_root + '/web'
    rollback['events']['deliveryHold'] = True
    recovery = copy.deepcopy(api)
    recovery['databaseURLFile'] = LEGACY + '/database-url'
    recovery['controls'] = copy.deepcopy(worker['controls'])
    recovery.pop('observability', None)
    return {'api': api, 'worker': worker, 'operator': operator, 'broker': revised_broker, 'rollback': rollback, 'recovery': recovery}


def unit(role, release_root):
    require(role in ('api', 'worker') and release_root.startswith('/opt/jobman-dashboard-lab/releases/'), 'Invalid service unit scope')
    root = API if role == 'api' else WORKER
    identity = IDENTITIES[role]['name']
    paths = ('ReadOnlyPaths=' if role == 'api' else 'ReadWritePaths=') + REPORT_NEW
    peer = WORKER if role == 'api' else API
    return f'''[Unit]
Description=Isolated Dashboard Lab {role}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={identity}
Group={identity}
SupplementaryGroups=jobman-dashboard-report-readers
WorkingDirectory={release_root}
ExecStartPre={release_root}/bin/jobman-dashboard --mode check-config --check-mode {role} --config {root}/config.json
ExecStart={release_root}/bin/jobman-dashboard --mode {role} --config {root}/config.json
Restart=on-failure
RestartSec=5s
TimeoutStopSec=90s
UMask=0077
RuntimeDirectory=jobman-dashboard-{role}-lab
RuntimeDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
{paths}
InaccessiblePaths=-{peer} -{LEGACY} -{BROKER} -{OPERATOR}
LimitNOFILE=4096
TasksMax=512

[Install]
WantedBy=multi-user.target
'''


def broker_unit(release_root):
    require(release_root.startswith('/opt/jobman-dashboard-lab/releases/'), 'Invalid broker release path')
    return f'''[Unit]
Description=Isolated Dashboard Lab NFS broker
Wants=network-online.target
After=network-online.target jobman-dashboard-lab-control.service

[Service]
Type=simple
User=jobman-dashboard-log
Group=jobman-dashboard-log
ExecStartPre={release_root}/bin/jobman-log-broker --mode check-config --config {BROKER}/config.json
ExecStart={release_root}/bin/jobman-log-broker --config {BROKER}/config.json
Restart=on-failure
RestartSec=5s
TimeoutStopSec=90s
RuntimeDirectory=jobman-dashboard-broker-lab
RuntimeDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/jobman-dashboard-broker-lab
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
'''


def make_plan(metadata, archive_sha, raw_inputs):
    values = {key: decode(raw) for key, raw in raw_inputs.items()}
    app, broker, fixture = (values[key] for key in ('app', 'broker', 'fixture'))
    validate_inputs(app, broker, fixture)
    release_root = '/opt/jobman-dashboard-lab/releases/' + metadata['revision']
    revision = max(app['configurationRevision'], broker['configurationRevision']) + 1
    generated = configs(app, broker, fixture, revision, release_root)
    return {'format': 'jobman.dashboard.lab-split/v1', 'synthetic': True, 'applies': False,
            'candidateSHA256': archive_sha, 'revision': metadata['revision'], 'version': metadata['version'],
            'sourceInstanceId': fixture['instanceId'], 'deploymentId': DEPLOYMENT,
            'configurationRevision': revision, 'releaseRoot': release_root, 'identities': IDENTITIES,
            'database': 'jobman_dashboard', 'schemaBefore': 17, 'schemaAfter': 18,
            'capacity': {'maximumDatabaseBytes': 1 << 30, 'maximumDumpBytes': 1 << 30, 'reserveBytes': 256 << 20,
                         'migrationDatabaseMultiplier': 2, 'dumpTimeoutSeconds': 120},
            'databaseRoles': {key: {'name': 'jobman_dashboard_' + key, 'components': components} for key, components in ROLE_COMPONENTS.items()},
            'inputSHA256': {key: sha(raw) for key, raw in raw_inputs.items()},
            'configSHA256': {key: sha(encoded(value)) for key, value in generated.items()},
            'hold': {'required': True, 'restoreCutoff': None, 'automaticResume': False},
            'requiredEventRecovery': {'reason': 'event_cursor_scope_changed', 'beforeServiceId': 'dashboard-lab',
                'afterServiceId': 'dashboard-worker-lab', 'automaticHeadReset': False, 'operatorConfiguration': 'configs/recovery.json'},
            'applyPrerequisites': ['fresh-guest-config-and-source-registry-sha-cas', 'unused-numeric-and-named-os-identities',
                'schema17-and-separate-role-preflight', 'verified-private-database-and-report-backups', 'persisted-no-cutoff-hold-receipt',
                'all-dashboard-processes-stopped', 'source-and-broker-client-csrs-signed-by-existing-trust',
                'legacy-purpose-key-export-and-compatibility-check', 'reviewed-exact-apply-plan'],
            'reportRootBefore': REPORT_OLD, 'reportRootAfter': REPORT_NEW,
            'rollback': {'schemaDowngrade': False, 'binaryRevision': metadata['revision'], 'configurationRevision': revision + 1,
                         'identity': 'jobman-dashboard-app', 'preserveNewObjects': True}}, generated
