#!/usr/bin/env python3
"""Pure plans for a new, isolated Dashboard install and same-schema rollback."""
import base64
import copy
import importlib.util
from pathlib import Path, PurePosixPath
import re

HERE = Path(__file__).resolve().parent
if 's' not in globals():
    spec = importlib.util.spec_from_file_location('install_archive', HERE/'dashboard-split-plan.py')
    s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
if 'b' not in globals():
    spec = importlib.util.spec_from_file_location('fault_plan', HERE/'dashboard-dependency-fault-plan.py')
    b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
need, sha, encoded, decode = b.need, b.sha, b.encoded, b.decode
FIX = '2e8f1b15c58889c52023d49d396fd600b31eecd2'
DATABASE = 'jobman_install_v1'
ROLES = {role: 'jobman_install_'+role for role in ('ddl', 'api', 'worker', 'operator')}
ROOTS = {role: '/etc/jobman-dashboard-install-'+role+'-lab' for role in ('api', 'worker', 'operator')}
USERS = {'api': ('jobman-dash-install-api', 21920), 'worker': ('jobman-dash-install-worker', 21921)}
READER = ('jobman-dash-install-readers', 21922)
UNITS = {role: 'jobman-dashboard-install-'+role+'-lab' for role in USERS}
REPORTS = '/var/lib/jobman-dashboard-install-reports-lab'
RELEASES = '/opt/jobman-dashboard-install-lab/releases'
CLIENT = 'jobman-dashboard-install-web-v1'
ORIGIN = 'https://dashboard.lab.test:48443'
ISSUER = 'https://oidc.lab.test:8443/realms/jobman-lab'
CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'
PRIMARY = {'api': ('/etc/jobman-dashboard-api-lab', 21904), 'worker': ('/etc/jobman-dashboard-worker-lab', 21905)}
COMPONENTS = {'api': ['api'], 'worker': ['ingestion', 'notifications', 'reports'], 'operator': ['operator']}
NEW_FILES = ('dashboard-install-plan.py', 'dashboard-install-guest.py', 'install-dashboard-fresh.py')
DEPENDENCIES = ('dashboard-split-plan.py', 'dashboard-dependency-fault-plan.py', 'dashboard-dependency-fault-guest.py',
                'dashboard-dependency-faults.py', 'dashboard-control-upgrade-plan.py', 'dashboard-control-upgrade-guest.py')
FILES = NEW_FILES + DEPENDENCIES
PHASE_HOST = {'stage': 'storage01', 'identity': 'control01', 'database': 'pg01', 'install': 'storage01',
              'migrate': 'storage01', 'grants': 'pg01', 'baseline': 'storage01', 'upgrade': 'storage01',
              'rollback': 'storage01', 'stop': 'storage01', 'retire-identity': 'control01'}
ORDER = tuple(PHASE_HOST)
MAX_PACKAGE = 128 << 20


def release(candidate):
    need(s.REVISION.fullmatch(candidate['revision']) and s.HEX.fullmatch(candidate['archiveSHA256']), 'candidate_identity')
    return RELEASES+'/'+candidate['revision']


def ledger(value):
    need(isinstance(value, list) and len(value) == 18 and len({r['name'] for r in value}) == 18 and
         value[-1]['name'] == 'migrations/000018_runtime_lock_privileges.sql' and
         all(set(r) == {'name', 'sha256'} and re.fullmatch(r'migrations/[0-9]{6}_[a-z_]+\.sql', r['name']) and
             s.HEX.fullmatch(r['sha256']) for r in value), 'schema_18_required')
    return value


def package(metadata, files, archive_sha, source_ledger):
    ledger(source_ledger)
    need(s.HEX.fullmatch(archive_sha) and metadata['releaseState'] == 'candidate' and
         metadata['architecture'] == 'arm64' and s.REVISION.fullmatch(metadata['revision']), 'candidate_metadata')
    need(len(files) <= 1024 and sum(map(len, files.values())) <= MAX_PACKAGE, 'candidate_size_bound')
    required = {'deploy/systemd/jobman-dashboard-api.service', 'deploy/systemd/jobman-dashboard-worker.service',
                'deploy/postgres/grants.py', 'deploy/postgres/grants.json', 'bin/jobman-dashboard', 'bin/jobman-log-broker',
                'web/index.html', 'build.json', 'SHA256SUMS'}
    need(required <= files.keys(), 'candidate_incomplete')
    return {'revision': metadata['revision'], 'version': metadata['version'], 'archiveSHA256': archive_sha,
            'files': {name: {'sha256': sha(raw), 'bytes': len(raw)} for name, raw in sorted(files.items())},
            'ledger': source_ledger, 'toolchains': metadata['toolchains']}


def pair(candidates):
    need(set(candidates) == {'baseline', 'upgrade'}, 'candidate_pair_required')
    a, z = candidates['baseline'], candidates['upgrade']
    need(a['revision'] != z['revision'] and ledger(a['ledger']) == ledger(z['ledger']), 'same_schema_distinct_pair')
    for c in candidates.values():
        release(c)
        need(0 < len(c['files']) <= 1024 and sum(row['bytes'] for row in c['files'].values()) <= MAX_PACKAGE,
             'candidate_bound')
        for name, row in c['files'].items():
            path = PurePosixPath(name)
            need(not path.is_absolute() and str(path) == name and '..' not in path.parts and len(path.parts) >= 1 and
                 re.fullmatch(r'[A-Za-z0-9_./-]{1,512}', name) and set(row) == {'sha256', 'bytes'} and
                 s.HEX.fullmatch(row['sha256']) and type(row['bytes']) is int and 0 <= row['bytes'] <= 96 << 20,
                 'candidate_member')
    return candidates


def client_spec(secret):
    need(s.HEX.fullmatch(secret), 'client_secret_shape')
    return {'clientId': CLIENT, 'name': 'Disposable Dashboard installation acceptance', 'enabled': True,
            'protocol': 'openid-connect', 'publicClient': False, 'clientAuthenticatorType': 'client-secret',
            'secret': secret, 'standardFlowEnabled': True, 'implicitFlowEnabled': False,
            'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False, 'fullScopeAllowed': False,
            'consentRequired': False, 'redirectUris': [ORIGIN+'/auth/callback'], 'webOrigins': [ORIGIN],
            'attributes': {'jobman.lab.owner': 'jobman-dashboard-install-v1', 'pkce.code.challenge.method': 'S256'},
            'protocolMappers': [
                {'name': 'dashboard-api-audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
                 'consentRequired': False, 'config': {'included.client.audience': 'jobman-dashboard-api',
                                                     'id.token.claim': 'false', 'access.token.claim': 'true'}},
                {'name': 'dashboard-immutable-directory-guid', 'protocol': 'openid-connect',
                 'protocolMapper': 'oidc-usermodel-attribute-mapper', 'consentRequired': False,
                 'config': {'user.attribute': 'dashboard_directory_guid', 'claim.name': 'directory_guid',
                            'jsonType.label': 'String', 'multivalued': 'false', 'id.token.claim': 'true',
                            'access.token.claim': 'true', 'userinfo.token.claim': 'true'}}]}


def references(value):
    found = set()
    def walk(v):
        if isinstance(v, dict):
            for key, item in v.items():
                if key.endswith('File'):
                    need(isinstance(item, str) and item.startswith('/') and str(PurePosixPath(item)) == item and
                         '..' not in PurePosixPath(item).parts, 'material_reference')
                    found.add(item)
                else: walk(item)
        elif isinstance(v, list):
            for item in v: walk(item)
    walk(value)
    return found


def generated_name(role, name):
    return ROOTS[role]+'/'+name


def configs(snapshot, candidates):
    original = snapshot['storage01']['configs']
    need(set(original) == {'api', 'worker'}, 'source_configs')
    need(original['api']['publicOrigin'] == 'https://dashboard.lab.test:8443' and
         original['api']['oidc']['issuer'] == ISSUER and original['worker']['identityIssuer'] == ISSUER,
         'existing_identity_origin')
    need(original['api']['events'] == {'enabled': True, 'deliveryHold': False} and
         original['worker'].get('deliveryHold', False) is False and
         original['api']['configurationRevision'] == original['worker']['configurationRevision'], 'existing_active_registry')
    need(original['api']['logMappings'] == original['worker']['logMappings'], 'mapping_roles_differ')
    feeds = {v['deploymentId']: v for v in snapshot['pg01']['preserved']['dashboard']['sources']}
    for role in USERS:
        controls = original[role]['controls']
        need(len(controls) == 2 and {c['id']: c['expectedInstanceId'] for c in controls} == b.SOURCE_IDS,
             'exact_existing_source_registry')
        for control in controls:
            expected_origin = 'https://10.77.0.21:'+('18443' if control['id'].endswith('1') else '28443')
            need(control['origin'] == expected_origin and len(control['namespaceIds']) == len(set(control['namespaceIds'])) and
                 set(control['namespaceIds']) == set(feeds[control['id']]['namespaceIds']), 'exact_existing_source_scope')
    copies, output = [], {}
    for role in USERS:
        source_root, uid = PRIMARY[role]
        value = copy.deepcopy(original[role])
        need(not value.get('notifications', {}).get('apns'), 'provider_credentials_forbidden')
        # Replace every application-purpose secret before enumerating references.
        value['configurationRevision'] = 1
        value['databaseURLFile'] = generated_name(role, 'database-url')
        value['notifications'] = {'deviceTopics': []}
        value['reports']['objectRoot'] = REPORTS
        value['reports']['objectAccess'] = {'mode': 'shared_group', 'workerUid': USERS['worker'][1], 'readerGid': READER[1]}
        value['reports']['policyKeyFile'] = generated_name(role, 'report-policy.key')
        value['logCursorKeyFile'] = generated_name(role, 'log-cursor.key')
        value['observability'] = {'socketPath': '/run/'+UNITS[role]+'/observe.sock'}
        if role == 'api':
            value['publicOrigin'], value['listen'] = ORIGIN, '10.77.0.10:48443'
            value['webRoot'] = release(candidates['baseline'])+'/web'
            value['encryption'] = {'keyId': 'install-auth-v1', 'keyFile': generated_name(role, 'auth.key')}
            value['oidc']['webClientId'] = CLIENT
            value['oidc']['webClientSecretFile'] = generated_name(role, 'web-secret')
        else:
            value['components'] = COMPONENTS['worker'][:]
            value['deliveryHold'] = False
        replacement = {}
        for path in references(value):
            if path.startswith(ROOTS[role]+'/'): continue
            need(path.startswith(source_root+'/') or path == CA, 'cross_role_material_forbidden')
            item = snapshot['storage01']['materials'].get(path)
            need(item and item['uid'] == (0 if path == CA else uid) and
                 item['mode'] == (0o644 if path == CA else 0o600) and 0 < item['bytes'] <= 1 << 20 and
                 s.HEX.fullmatch(item['sha256']), 'material_inventory')
            destination = ROOTS[role]+'/material/'+sha(path.encode())[:16]+'-'+PurePosixPath(path).name
            replacement[path] = destination
            copies.append(dict(item, source=path, destination=destination, role=role))
        def rewrite(v):
            if isinstance(v, dict): return {k: rewrite(x) for k, x in v.items()}
            if isinstance(v, list): return [rewrite(x) for x in v]
            return replacement.get(v, v) if isinstance(v, str) else v
        output[role] = rewrite(value)
    need(len(copies) <= 128, 'material_count')
    output['operator'] = {'schemaVersion': 1, 'databaseURLFile': ROOTS['operator']+'/database-url', 'deployments': [{'id': c['id']} for c in output['api']['controls']]}
    return output, sorted(copies, key=lambda x: x['destination'])


def unit(role, candidate, template):
    need(role in USERS and isinstance(template, bytes) and len(template) <= 32768, 'unit_template')
    text = template.decode()
    counts = {'/opt/jobman-dashboard/current': 3, '/etc/jobman-dashboard-'+role+'/config.json': 2,
              'User=jobman-dashboard-'+role: 1, 'Group=jobman-dashboard-'+role: 1,
              'SupplementaryGroups=jobman-dashboard-report-readers': 1,
              'RuntimeDirectory=jobman-dashboard-'+role: 1, '/var/lib/jobman-dashboard/reports': 1}
    need(all(text.count(k) == n for k, n in counts.items()) and 'TimeoutStopSec=90s\n' in text and
         'KillMode=control-group\n' in text and 'ProtectSystem=strict\n' in text, 'packaged_unit_semantics')
    replacements = {'/opt/jobman-dashboard/current': release(candidate),
                    '/etc/jobman-dashboard-'+role+'/config.json': ROOTS[role]+'/config.json',
                    'User=jobman-dashboard-'+role: 'User='+USERS[role][0],
                    'Group=jobman-dashboard-'+role: 'Group='+USERS[role][0],
                    'SupplementaryGroups=jobman-dashboard-report-readers': 'SupplementaryGroups='+READER[0],
                    'RuntimeDirectory=jobman-dashboard-'+role: 'RuntimeDirectory='+UNITS[role],
                    '/var/lib/jobman-dashboard/reports': REPORTS}
    for old, new in replacements.items(): text = text.replace(old, new)
    peer = 'worker' if role == 'api' else 'api'
    lines = text.splitlines()
    need(sum(line.startswith('InaccessiblePaths=') for line in lines) == 1, 'unit_private_boundary')
    paths = [ROOTS[peer], ROOTS['operator'], *[v[0] for v in PRIMARY.values()], '/etc/jobman-dashboard-operator-lab',
             '/etc/jobman-dashboard-restore-api-lab', '/etc/jobman-dashboard-restore-worker-lab',
             '/etc/jobman-dashboard-restore-operator-lab', '/etc/jobman-log-broker']
    lines = ['InaccessiblePaths='+' '.join('-'+x for x in paths) if line.startswith('InaccessiblePaths=') else line for line in lines]
    # Limit only the new disposable service's resources; retain package hardening.
    pos = lines.index('[Install]')
    lines[pos:pos] = ['MemoryMax='+('512M' if role == 'api' else '768M'), 'Environment=GOMAXPROCS=2', '']
    return ('\n'.join(lines)+'\n').encode()


def make(snapshot, candidates, units, hashes, operation, created, generated, grants):
    pair(candidates)
    need(set(snapshot) == {'control01', 'storage01', 'pg01'} and b.UUID.fullmatch(operation) and
         type(created) is int and set(hashes) == set(FILES) and all(s.HEX.fullmatch(x) for x in hashes.values()), 'plan_shape')
    need(snapshot['pg01']['unused'] is True and snapshot['storage01']['unused'] is True and
         snapshot['control01']['identity']['absent'] is True, 'fresh_targets_required')
    need(snapshot['storage01']['freeBytes'] >= 2 << 30 and snapshot['storage01']['memoryBytes'] >= 1536 << 20 and
         snapshot['pg01']['freeBytes'] >= 2 << 30 and snapshot['pg01']['connections'] >= 36, 'capacity_headroom')
    b.stable_database(snapshot['pg01']['preserved']['dashboard'])
    configs_value, copies = configs(snapshot, candidates)
    need(set(units) == {'baseline', 'upgrade'} and all(set(v) == set(USERS) for v in units.values()), 'unit_pair')
    for selected in units:
        for role, value in units[selected].items():
            need(len(base64.b64decode(value, validate=True)) <= 32768, 'unit_bound')
    need(set(generated) == {'auth', 'policy', 'cursor', 'web', 'ddl', 'api', 'worker', 'operator'} and
         all(s.HEX.fullmatch(v) for v in generated.values()), 'generated_secret_fingerprints')
    need(set(grants) == {'api', 'worker', 'operator'} and all(s.HEX.fullmatch(v) for v in grants.values()), 'grant_fingerprints')
    return {'format': 1, 'synthetic': True, 'operationId': operation, 'createdAt': created, 'postFixRevision': FIX,
            'snapshot': snapshot, 'candidates': candidates, 'units': units, 'configs': configs_value, 'copies': copies,
            'generatedSHA256': generated, 'grantSHA256': grants, 'implementationSHA256': hashes,
            'forbidden': ['primary-mutation', 'restore-clone-mutation', 'source-enrollment', 'delivery', 'old-client-edit',
                          'automatic-rollback', 'database-copy', 'migration-down', 'uncertain-retry']}


def validate(plan):
    need(plan == make(plan['snapshot'], plan['candidates'], plan['units'], plan['implementationSHA256'],
                     plan['operationId'], plan['createdAt'], plan['generatedSHA256'], plan['grantSHA256']), 'plan_reconstruction')
