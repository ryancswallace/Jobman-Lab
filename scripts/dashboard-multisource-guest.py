#!/usr/bin/env python3
"""Fixed Lab roles and phased additive multi-source deployment; invoked by pinned host."""
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import sys
import time

# The reviewed host bootstrap supplies only these two hash-bound modules.
if 'runtime' not in globals():
    import importlib.util
    def load(name):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
        value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
    runtime = load('dashboard-multisource-runtime')
    plan = load('dashboard-multisource-plan')
r = runtime
ROOT = Path('/var/lib/jobman-dashboard-multisource-operator')
SOURCE = Path(plan.SOURCE_ROOT)
PRIMARY_ROOT = Path('/etc/jobman-dashboard-lab/control-fixture')
CANDIDATE = 'b8f25afdd90f83b4602f32440a89e74dfa866b6c'
SOURCE_REVISION = 'd332a2b569333ae8aed9c2fc9ebc648d8eb5ba4e'
SOURCE_HASH = '38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e'
PHASES = ('preflight', 'materials', 'install', 'swap_state', 'apply', 'restart', 'verify', 'database', 'continuation_check', 'continuation_apply')
PREFIXES = {'api': 'dashboard', 'worker': 'worker', 'broker': 'broker'}


def jread(path, uid=0, maximum=1 << 20):
    return plan.decode(r.read(path, uid, maximum=maximum))


def directory(path):
    if not path.exists(): r.create_directory(path)
    r.private_directory(path)


def retained(path, raw):
    if path.exists(): r.need(r.read(path, 0) == raw, 'retained_receipt_changed')
    else: r.put(path, raw)


def lock(root, existing=False):
    path = root / '.lock'
    try:
        if existing: raise FileExistsError()
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    r.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'guest_lock_identity')
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception: os.close(fd); raise
    return fd


def input_value(p):
    r.need(os.geteuid() == 0 and sys.platform == 'linux', 'linux_root_required')
    r.need(p['phase'] in PHASES and p['host'] in ('storage01', 'control01', 'pg01') and os.uname().nodename.split('.')[0] == p['host'], 'guest_phase_boundary')
    r.need(re.fullmatch('[0-9a-f]{64}', p['executionId']) and re.fullmatch('[0-9a-f]{64}', p['reviewSHA256']), 'receipt_id')
    review = p['review']
    r.need(r.sha(r.encoded(review)) == p['reviewSHA256'] and review['synthetic'] is True and review['applies'] is False, 'review_binding')
    before = {key: base64.b64decode(value, validate=True) for key, value in p['before'].items()}
    after = {key: base64.b64decode(value, validate=True) for key, value in p['after'].items()}
    r.need(set(before) == set(after) == {'api', 'worker', 'broker', 'operator'} and all(0 < len(v) <= 1 << 20 for v in [*before.values(), *after.values()]), 'config_bounds')
    expected = plan.patch({key: plan.decode(value) for key, value in before.items()}, p['fixture'])
    r.need(len(review['files']) == 4 and {x['role'] for x in review['files']} == set(before), 'review_roles')
    for item in review['files']:
        role = item['role']
        r.need(item['path'] == plan.ROOTS[role] + '/config.json' and item['beforeSHA256'] == r.sha(before[role]) and item['afterSHA256'] == r.sha(after[role]) and after[role] == r.encoded(expected[role]), 'additive_config_mismatch')
    r.need(review['fixtureSHA256'] == r.sha(base64.b64decode(p['fixtureBytes'], validate=True)) and plan.decode(base64.b64decode(p['fixtureBytes'], validate=True)) == p['fixture'], 'fixture_binding')
    if p['host'] == 'pg01': r.need(p['phase'] == 'database', 'database_read_only_boundary')
    elif p['phase'] == 'materials': r.need(p['host'] == 'control01', 'materials_host')
    return before, after


def prepared_source(p):
    prepared = p['preparedSource']
    r.need(prepared.get('fixture') == p['fixture'] and 20 <= len(prepared['files']) <= 64, 'source_receipt_shape')
    allowed_single = {Path('/usr/local/libexec/jobman-dashboard-secondary/jobman-control'), Path('/usr/local/libexec/jobman-dashboard-secondary/jobman-control-lab-helper'), Path('/etc/jobman-dashboard-secondary/control-database-url'), Path('/etc/jobman-dashboard-secondary/fixture-input.json'), Path('/etc/systemd/system/jobman-dashboard-lab-control-secondary.service'), Path('/etc/systemd/system/jobman-dashboard-lab-directory-secondary.service')}
    for name, metadata in prepared['files'].items():
        path = Path(name)
        r.need(path in allowed_single or path.parent in (SOURCE, Path('/etc/jobman-dashboard-secondary/directory')), 'source_receipt_path')
        r.need(r.sha(r.read(path, metadata['uid'], metadata['mode'], 96 << 20)) == metadata['sha256'] and metadata['gid'] == metadata['uid'], 'source_prepared_file_changed')
    r.need(r.sha(r.read(SOURCE / 'fixture-info.json', 21907)) == p['review']['fixtureSHA256'], 'source_fixture_changed')


def service_start(unit, expected_uid=None, expected_executable=None):
    r.run(['systemctl', 'is-active', '--quiet', unit], 'preserved_service_not_active')
    data = dict(line.split('=', 1) for line in r.run(['systemctl', 'show', unit, '--property=MainPID', '--property=ExecMainStartTimestampMonotonic'], 'preserved_service_status').decode().splitlines())
    r.need(set(data) == {'MainPID', 'ExecMainStartTimestampMonotonic'} and all(v.isdigit() and int(v) > 0 for v in data.values()), 'preserved_service_start')
    pid = data['MainPID']; data['uid'] = Path('/proc', pid).stat().st_uid; data['exe'] = os.readlink('/proc/' + pid + '/exe')
    r.need(expected_uid is None or data['uid'] == expected_uid, 'preserved_service_uid')
    r.need(expected_executable is None or data['exe'] == expected_executable, 'preserved_service_executable')
    return data


def public_key(path):
    raw = r.run(['openssl', 'pkey', '-in', str(path), '-pubout', '-outform', 'DER'], 'source_public_key')
    r.need(len(raw) == 44 and raw[:12].hex() == '302a300506032b6570032100', 'ed25519_key_required')
    return base64.b64encode(raw[12:]).decode()


def public_source_ledger():
    # Installed public build metadata has root ownership and mode0644.
    return plan.decode(r.read(Path('/usr/local/libexec/jobman-dashboard-lab/source-current.json'), 0, 0o644))


def original_trust(before):
    path = Path(plan.decode(before['broker'])['clientTrustRootsFile'])
    r.need(path == Path('/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'), 'original_trust_path')
    # This exact public CA remains root-owned; never widen a private-file read.
    return r.read(path, 0, 0o644)


def source_snapshot(p):
    prepared_source(p)
    primary = public_source_ledger()
    r.need(primary['revision'] == SOURCE_REVISION and r.sha(r.read(Path('/usr/local/libexec/jobman-dashboard-lab/jobman-control'), 0, 0o755, 96 << 20)) == SOURCE_HASH, 'primary_source_binary_changed')
    processes = {unit: service_start(unit) for unit in ('jobman-control', 'jobman-keycloak')}
    processes['jobman-dashboard-lab-control'] = service_start('jobman-dashboard-lab-control', 21902, '/usr/local/libexec/jobman-dashboard-lab/jobman-control')
    processes['jobman-dashboard-lab-directory'] = service_start('jobman-dashboard-lab-directory', 21902, '/usr/local/libexec/jobman-dashboard-lab/jobman-control-lab-helper')
    processes['jobman-dashboard-lab-control-secondary'] = service_start('jobman-dashboard-lab-control-secondary', 21907, '/usr/local/libexec/jobman-dashboard-secondary/jobman-control')
    processes['jobman-dashboard-lab-directory-secondary'] = service_start('jobman-dashboard-lab-directory-secondary', 21908, '/usr/local/libexec/jobman-dashboard-secondary/jobman-control-lab-helper')
    caps = {}
    for key, uid, user, root, port, instance in [('primary', 21902, 'jobman-dashboard-source', PRIMARY_ROOT, 18443, plan.PRIMARY_INSTANCE), ('secondary', 21907, 'jobman-dashboard-source2', SOURCE, 28443, plan.SECONDARY_INSTANCE)]:
        response = plan.decode(r.run(['runuser', '-u', user, '--', 'curl', '--silent', '--fail', '--max-time', '4', '--cacert', str(root / 'fixture-ca.crt'), 'https://127.0.0.1:' + str(port) + '/v1/capabilities'], 'source_capabilities', timeout=5))['capabilities']
        r.need(response['instanceId'] == instance and response['recoveryEpoch'] == '1', 'source_identity_changed')
        caps[key] = {'instanceId': instance, 'recoveryEpoch': '1'}
    registry = jread(SOURCE / 'delegation.json', 21907)
    r.need(set(registry) == {'services'} and len(registry['services']) == 3, 'secondary_service_registry')
    ops = {'api': {'namespace.read', 'jobs.read', 'groups.read', 'targets.read', 'logs.read', 'artifacts.read', 'evidence.read', 'events.read'}, 'worker': {'namespace.read', 'jobs.read', 'logs.read', 'evidence.read', 'events.read'}, 'broker': {'namespace.read', 'logs.read'}}
    namespaces = sorted(x['id'] for x in p['fixture']['namespaces'])
    for role, prefix in PREFIXES.items():
        entry = plan.source_entry(role, namespaces)
        matches = [v for v in registry['services'] if v['serviceId'] == entry['serviceId'] and v['keyId'] == entry['delegationKeyId']]
        r.need(len(matches) == 1, 'secondary_registered_identity')
        item = matches[0]
        cert = SOURCE / (prefix + '-client.crt')
        der = r.run(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'], 'source_certificate')
        thumbprint = base64.urlsafe_b64encode(bytes.fromhex(r.sha(der))).decode().rstrip('=')
        r.need(item['enabled'] is True and item['audience'] == plan.SOURCE_AUDIENCE and sorted(item['namespaceIds']) == namespaces and set(item['operations']) == ops[role] and item['publicKey'] == public_key(SOURCE / (prefix + '-signing-key.pem')) and item['certificateThumbprints'] == [thumbprint], 'secondary_registered_grants')
        r.run(['openssl', 'verify', '-purpose', 'sslclient', '-CAfile', str(SOURCE / 'fixture-ca.crt'), str(cert)], 'source_certificate_chain')
    files = {str(root / name): r.sha(r.read(root / name, uid)) for root, uid in [(PRIMARY_ROOT, 21902), (SOURCE, 21907)] for name in ('control.env', 'delegation.json', 'directory.json', 'fixture-info.json', 'fixture-ca.crt')}
    return {'processes': processes, 'files': files, 'capabilities': caps}


def destination_names(role):
    common = ['secondary-control-ca.crt', 'secondary-control-client.crt', 'secondary-control-client.key', 'secondary-control-signing-key.pem']
    if role != 'broker': return common + ['secondary-broker-client.crt', 'secondary-broker-client.key', 'secondary-broker-signing-key.pem']
    return common + ['secondary-client-ca-bundle.crt'] + ['secondary-' + role + suffix for role in ('api', 'worker') for suffix in ('-client.crt', '-signing-public.pem')]


def role_snapshot(role, before):
    _, root, uid, user, _, _, _ = r.SPECS[role]
    info = Path(root).lstat()
    r.need(Path(root).resolve() == Path(root) and stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == uid and stat.S_IMODE(info.st_mode) == 0o700 and pwd.getpwnam(user).pw_uid == uid, 'role_directory')
    r.need(r.read(Path(root) / 'config.json', uid) == before, 'current_config_drift')
    process = r.process(role)
    r.need('/releases/' + CANDIDATE + '/bin/' in process['binary'], 'candidate_revision')
    r.observations(role, 6)
    for name in destination_names(role): r.need(not (Path(root) / name).exists() and not (Path(root) / name).is_symlink(), 'new_material_path_occupied')
    return process


def snapshot(p, before):
    roles = ['broker'] if p['host'] == 'control01' else ['api', 'worker']
    result = {'epoch': int(time.time()), 'roles': {role: role_snapshot(role, before[role]) for role in roles}}
    if p['host'] == 'control01':
        result['sources'] = source_snapshot(p)
        result['originalTrustSHA256'] = r.sha(original_trust(before))
    else:
        r.need(r.read(Path(plan.ROOTS['operator']) / 'config.json', 0) == before['operator'], 'operator_config_drift')
    return result


def make_materials(p, root, before):
    done = root / 'materials.json'
    if done.exists():
        value = jread(done, maximum=2 << 20); validate_materials(value)
        return value
    r.need(not (root / 'materials.pending.json').exists(), 'uncertain_material_generation')
    r.need(source_snapshot(p) == p['baseline']['control01']['sources'], 'source_changed_before_materials')
    original_ca = original_trust(before)
    r.need(r.sha(original_ca) == p['baseline']['control01']['originalTrustSHA256'], 'original_trust_changed')
    r.put(root / 'materials.pending.json', r.encoded({'executionId': p['executionId'], 'originalTrustSHA256': r.sha(original_ca)}))
    result = {role: {} for role in PREFIXES}
    for role, prefix in PREFIXES.items():
        for name, target in [('fixture-ca.crt', 'secondary-control-ca.crt'), (prefix + '-client.crt', 'secondary-control-client.crt'), (prefix + '-client.key', 'secondary-control-client.key'), (prefix + '-signing-key.pem', 'secondary-control-signing-key.pem')]:
            result[role][target] = base64.b64encode(r.read(SOURCE / name, 21907)).decode()
    secondary_ca = r.read(SOURCE / 'fixture-ca.crt', 21907)
    r.need(original_ca != secondary_ca and secondary_ca not in original_ca, 'secondary_ca_already_trusted')
    result['broker']['secondary-client-ca-bundle.crt'] = base64.b64encode(original_ca + (b'' if original_ca.endswith(b'\n') else b'\n') + secondary_ca).decode()
    work = root / 'generated'; r.create_directory(work)
    for role in ('api', 'worker'):
        key = work / (role + '-client.key'); csr = work / (role + '-client.csr'); cert = work / (role + '-client.crt'); signing = work / (role + '-signing-key.pem'); public = work / (role + '-signing-public.pem'); extensions = work / (role + '-extensions')
        r.put(extensions, b'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,clientAuth\n')
        r.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], 'generate_tls_key')
        r.run(['openssl', 'req', '-new', '-key', str(key), '-subj', '/CN=dashboard-' + role + '-secondary-broker-lab', '-out', str(csr)], 'generate_tls_request')
        r.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(SOURCE / 'fixture-ca.crt'), '-CAkey', str(SOURCE / 'fixture-ca.key'), '-set_serial', '0x' + secrets.token_hex(16), '-days', '7', '-extfile', str(extensions), '-out', str(cert)], 'sign_tls_leaf')
        r.run(['openssl', 'verify', '-purpose', 'sslclient', '-CAfile', str(SOURCE / 'fixture-ca.crt'), str(cert)], 'verify_tls_leaf')
        r.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(signing)], 'generate_delegation_key')
        r.run(['openssl', 'pkey', '-in', str(signing), '-pubout', '-out', str(public)], 'derive_delegation_public')
        for path in (key, csr, cert, signing, public):
            # OpenSSL modes differ for public outputs; all staging files remain private.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try: os.fchmod(fd, 0o600); os.fsync(fd)
            finally: os.close(fd)
        for source, name in [(key, 'secondary-broker-client.key'), (cert, 'secondary-broker-client.crt'), (signing, 'secondary-broker-signing-key.pem')]: result[role][name] = base64.b64encode(r.read(source, 0)).decode()
        result['broker']['secondary-' + role + '-client.crt'] = base64.b64encode(r.read(cert, 0)).decode()
        result['broker']['secondary-' + role + '-signing-public.pem'] = base64.b64encode(r.read(public, 0)).decode()
    validate_materials(result)
    r.sync(work); r.put(done, r.encoded(result)); return result


def validate_materials(value, roles=None):
    roles = set(PREFIXES) if roles is None else set(roles)
    r.need(set(value) == roles, 'material_roles')
    for role, files in value.items():
        r.need(set(files) == set(destination_names(role)), 'material_allowlist')
        for name, text in files.items():
            raw = base64.b64decode(text, validate=True)
            r.need(1 <= len(raw) <= 32768 and name == Path(name).name, 'material_bounds')
    if roles == set(PREFIXES):
        for role in ('api', 'worker'):
            r.need(value[role]['secondary-broker-client.crt'] == value['broker']['secondary-' + role + '-client.crt'], 'broker_certificate_pair')


def material_hashes(materials):
    validate_materials(materials)
    return {role: {name: r.sha(base64.b64decode(raw, validate=True)) for name, raw in files.items()} for role, files in materials.items()}


def check_config(role, binary, path):
    mode = r.SPECS[role][6]
    args = [binary, '--mode', 'check-config'] + ([] if role == 'broker' else ['--check-mode', mode]) + ['--config', str(path)]
    r.run(['runuser', '-u', r.SPECS[role][3], '--'] + args, 'validate_config_' + role, timeout=20)


def identity(p):
    manifest = p['materialHashes']; r.need(set(manifest) == set(PREFIXES), 'material_manifest_roles')
    for role, hashes in manifest.items():
        r.need(set(hashes) == set(destination_names(role)) and all(re.fullmatch('[0-9a-f]{64}', value) for value in hashes.values()), 'material_manifest_shape')
    for role, files in p['materials'].items():
        r.need({name: r.sha(base64.b64decode(raw, validate=True)) for name, raw in files.items()} == manifest[role], 'material_manifest_changed')
    return {'executionId': p['executionId'], 'reviewSHA256': p['reviewSHA256'], 'materialHashes': manifest}


def role_phase(p, role, root, before, after):
    uid = r.SPECS[role][2]; config_root = Path(plan.ROOTS[role]); config = config_root / 'config.json'
    stage = config_root / ('.multisource-' + p['executionId'] + '.json')
    expected = p['baseline'][p['host']]['roles'][role]
    if p['phase'] not in ('restart', 'verify'):
        r.need(r.process(role) == expected, 'runtime_changed')
    else:
        r.need(r.sha(r.read(Path(expected['binary']), 0, 0o755, 96 << 20)) == expected['binarySHA256'] and r.sha(r.read(Path('/etc/systemd/system') / (expected['unit'] + '.service'), 0, 0o644)) == expected['unitSHA256'], 'static_runtime_changed')
    marker = root / (role + '-install.json'); value = identity(p)
    if p['phase'] == 'install':
        r.need(r.read(config, uid) == before[role], 'config_changed_before_install')
        if marker.exists():
            r.need(jread(marker) == value and r.read(stage, uid) == after[role], 'install_receipt_changed')
        else:
            r.need(not (root / (role + '-install.pending.json')).exists(), 'uncertain_material_installation')
            r.put(root / (role + '-install.pending.json'), r.encoded(value))
            for name, text in p['materials'][role].items(): r.put(config_root / name, base64.b64decode(text, validate=True), uid)
            r.put(stage, after[role], uid); check_config(role, expected['binary'], stage)
            r.put(marker, r.encoded(value))
    r.need(jread(marker) == value, 'install_receipt_missing')
    for name, digest in value['materialHashes'][role].items(): r.need(r.sha(r.read(config_root / name, uid, maximum=32768)) == digest, 'installed_material_changed')
    current = r.read(config, uid)
    applied = root / (role + '-apply.json'); pending = root / (role + '-apply.pending.json')
    if p['phase'] == 'swap_state':
        if current == before[role]: r.need(r.read(stage, uid) == after[role], 'staged_config_changed'); return {'state': 'original'}
        r.need(current == after[role] and jread(pending) == value, 'unproven_installed_config'); return {'state': 'applied'}
    if p['phase'] == 'apply':
        if applied.exists(): r.need(current == after[role] and jread(applied) == value, 'completed_swap_changed')
        elif current == after[role]:
            r.need(jread(pending) == value and r.read(root / (role + '-before.json'), 0) == before[role], 'uncertain_swap_identity'); r.put(applied, r.encoded(value))
        else:
            r.need(current == before[role] and r.read(stage, uid) == after[role], 'swap_precondition')
            r.put(pending, r.encoded(value)); r.atomic_config(config, before[role], after[role], uid, root / (role + '-before.json'), p['executionId']); r.put(applied, r.encoded(value))
    if p['phase'] in ('restart', 'verify'):
        r.need(r.read(config, uid) == after[role] and jread(applied) == value, 'restart_config_unapplied')
        done = root / (role + '-restart.json'); uncertain = root / (role + '-restart.pending.json')
        if p['phase'] == 'restart':
            if not done.exists():
                if uncertain.exists():
                    prior = jread(uncertain); r.need(prior['identity'] == value, 'uncertain_restart_identity')
                    r.await_ready(role, 7, expected, timeout=40)
                    r.need(service_start(r.SPECS[role][4]) != prior['before'], 'uncertain_restart_no_new_process')
                else:
                    r.put(uncertain, r.encoded({'identity': value, 'before': service_start(r.SPECS[role][4])}))
                    r.run(['systemctl', 'restart', r.SPECS[role][4]], 'restart_' + role, timeout=40)
                r.await_ready(role, 7, expected, timeout=40); r.put(done, r.encoded(value))
            r.need(jread(done) == value, 'restart_receipt_changed')
        else: r.need(jread(done) == value, 'restart_receipt_missing')
        r.await_ready(role, 7, expected, timeout=10); check_config(role, expected['binary'], config)
    return {'role': role, 'phase': p['phase'], 'complete': True, 'afterSHA256': r.sha(after[role])}


def recovery_config(after):
    value = copy.deepcopy(plan.decode(after['api']))
    value['databaseURLFile'] = '/etc/jobman-dashboard-app-lab/database-url'
    value['controls'] = copy.deepcopy(plan.decode(after['worker'])['controls'])
    value.pop('observability', None)
    return r.encoded(value)


def operator_phase(p, root, before, after):
    path = Path(plan.ROOTS['operator']) / 'config.json'; value = {'reviewSHA256': p['reviewSHA256'], 'afterSHA256': r.sha(after['operator'])}
    if p['phase'] == 'install':
        target = Path(plan.ROOTS['operator']) / 'multisource-recovery.json'
        # New operator-only config; no runtime credentials or grants are widened.
        retained(target, recovery_config(after))
        r.run([p['baseline']['storage01']['roles']['api']['binary'], '--mode', 'check-config', '--check-mode', 'api', '--config', str(target)], 'validate_recovery_config', timeout=20)
    if p['phase'] == 'apply':
        pending = root / 'operator-apply.pending.json'; done = root / 'operator-apply.json'; current = r.read(path, 0)
        if done.exists(): r.need(jread(done) == value and current == after['operator'], 'operator_completed_swap_changed')
        elif current == after['operator']:
            r.need(jread(pending) == value and r.read(root / 'operator-before.json', 0) == before['operator'], 'operator_uncertain_swap'); r.put(done, r.encoded(value))
        else:
            r.need(current == before['operator'], 'operator_config_compare_and_swap'); r.put(pending, r.encoded(value)); r.atomic_config(path, before['operator'], after['operator'], 0, root / 'operator-before.json', p['executionId']); r.put(done, r.encoded(value))
    elif p['phase'] == 'verify':
        r.need(r.read(path, 0) == after['operator'] and jread(root / 'operator-apply.json') == value, 'operator_applied_config_changed')
        r.need(r.read(Path(plan.ROOTS['operator']) / 'multisource-recovery.json', 0) == recovery_config(after), 'operator_recovery_config_changed')


def database_snapshot():
    # Fixed local-container operator transport. No DSN/password/token rows leave SQL.
    sql = """SET statement_timeout='5s'; BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH bindings AS (SELECT * FROM dashboard_notification_device_bindings ORDER BY id LIMIT 201)
SELECT json_build_object('database',current_database(),
 'hold',(SELECT json_build_object('generation',generation,'held',held,'restoreRecordedThrough',restore_recorded_through) FROM dashboard_notification_delivery_control WHERE singleton),
 'identities',COALESCE((SELECT json_agg(json_build_object('deploymentId',deployment_id,'instanceId',control_instance_id,'epoch',recovery_epoch,'revision',configuration_revision) ORDER BY deployment_id) FROM dashboard_source_identities),'[]'::json),
 'feeds',COALESCE((SELECT json_agg(json_build_object('deploymentId',deployment_id,'namespaces',namespace_ids,'status',status,'generation',generation,'lastPosition',last_position,'lastError',last_error,'lastSuccessAt',last_success_at) ORDER BY deployment_id) FROM dashboard_event_feeds),'[]'::json),
 'unfinishedRecoveries',(SELECT count(*) FROM dashboard_event_recoveries WHERE status IN ('replaying','ready','quarantined')),
 'openGaps',(SELECT count(*) FROM dashboard_event_gaps WHERE resolved_at IS NULL),
 'bindingCount',(SELECT count(*) FROM bindings),
 'bindingSHA256',(SELECT CASE WHEN count(*)<=200 THEN encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(b)::text,E'\\n' ORDER BY id),''),'UTF8')),'hex') ELSE NULL END FROM bindings b));
COMMIT;"""
    raw = r.run(['podman', 'exec', '-i', '--user', 'postgres', 'jobman-postgres', 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'jobman_control', '-d', 'jobman_dashboard'], 'dashboard_database_snapshot', input_data=sql.encode(), timeout=8, maximum=65536)
    value = plan.decode(raw)
    r.need(value['database'] == 'jobman_dashboard' and value['bindingCount'] <= 200 and re.fullmatch('[0-9a-f]{64}', value['bindingSHA256']), 'dashboard_snapshot_bounds')
    source_sql = """SET statement_timeout='5s'; BEGIN READ ONLY; SELECT json_build_object('database',current_database(),'instanceId',(SELECT id::text FROM control_instance),'epoch',(SELECT restore_epoch::text FROM service_recovery_state),'migration',(SELECT max(version) FROM schema_migrations),'freshNamespaceProofs',(SELECT count(*) FROM namespace_directory_state WHERE last_verified_at>statement_timestamp()-interval '120 seconds')); COMMIT;"""
    value['secondary'] = plan.decode(r.run(['podman', 'exec', '-i', '--user', 'postgres', 'jobman-postgres', 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'jobman_control', '-d', 'jobman_dashboard_control_secondary'], 'secondary_database_snapshot', input_data=source_sql.encode(), timeout=8, maximum=16384))
    return value


PRIOR_IMPLEMENTATION = 'c993dcc1b92bf404def903f211862b406c41b3cdbbc4680ee2bcedea1fe82f35'
PRIOR_EXECUTION = '1bb641283d575e6df8003c6a5034e67254baae0957309def1d9393702140305b'


def continuation_values(p, after):
    r.need(p.get('previousImplementationSHA256') == PRIOR_IMPLEMENTATION and p['executionId'] == PRIOR_EXECUTION and p['implementationSHA256'] != PRIOR_IMPLEMENTATION, 'continuation_scope')
    new_recovery = recovery_config(after); old = plan.decode(new_recovery)
    old['databaseURLFile'] = '/etc/jobman-dashboard-lab/database-url'; old_recovery = r.encoded(old)
    old_binding = r.encoded({'executionId': p['executionId'], 'reviewSHA256': p['reviewSHA256'], 'implementationSHA256': PRIOR_IMPLEMENTATION})
    new_binding = r.encoded({'executionId': p['executionId'], 'reviewSHA256': p['reviewSHA256'], 'implementationSHA256': p['implementationSHA256']})
    identity = {'executionId': p['executionId'], 'reviewSHA256': p['reviewSHA256'], 'oldImplementationSHA256': PRIOR_IMPLEMENTATION, 'newImplementationSHA256': p['implementationSHA256'], 'oldRecoverySHA256': r.sha(old_recovery), 'newRecoverySHA256': r.sha(new_recovery)}
    return identity, old_recovery, new_recovery, old_binding, new_binding


def continuation_cas(path, before, after, backup, temporary):
    current = r.read(path, 0)
    if current == after:
        r.need(r.read(backup, 0) == before, 'continuation_cas_evidence'); return
    r.need(current == before, 'continuation_cas_drift')
    retained(backup, before); retained(temporary, after)
    r.need(r.read(path, 0) == before, 'continuation_cas_drift')
    os.replace(temporary, path); r.sync(path.parent)
    r.need(r.read(path, 0) == after, 'continuation_cas_postcondition')


def continue_install(p, before, after):
    r.need(p['host'] in ('control01', 'storage01') and (p['phase'] == 'continuation_check' or p.get('apply') is True), 'continuation_phase')
    value, old_recovery, new_recovery, old_binding, new_binding = continuation_values(p, after)
    root = ROOT / p['executionId']; r.private_directory(ROOT); r.private_directory(root)
    fd = lock(root, existing=True)
    try:
        binding = r.read(root / 'binding.json', 0)
        pending = root / 'continuation.pending.json'; complete = root / 'continuation.complete.json'
        if pending.exists(): r.need(jread(pending) == value, 'continuation_pending_changed')
        else: r.need(binding == old_binding, 'continuation_original_binding')
        r.need(binding in (old_binding, new_binding), 'continuation_binding_changed')
        roles = ['broker'] if p['host'] == 'control01' else ['api', 'worker']
        starts = {}
        for role in roles:
            uid = r.SPECS[role][2]; config_root = Path(plan.ROOTS[role]); expected = p['baseline'][p['host']]['roles'][role]
            r.need(r.process(role) == expected and r.read(config_root / 'config.json', uid) == before[role], 'continuation_active_runtime_changed')
            r.observations(role, 6); starts[role] = service_start(r.SPECS[role][4], uid, expected['binary'])
            r.need(jread(root / (role + '-install.json')) == identity(dict(p, materials={})), 'continuation_install_receipt')
            r.need(r.read(config_root / ('.multisource-' + p['executionId'] + '.json'), uid) == after[role], 'continuation_staged_config')
            for name, digest in p['materialHashes'][role].items():
                r.need(r.sha(r.read(config_root / name, uid, maximum=32768)) == digest, 'continuation_material_changed')
            for suffix in ('apply.json', 'apply.pending.json', 'restart.json', 'restart.pending.json'):
                r.need(not (root / (role + '-' + suffix)).exists() and not (root / (role + '-' + suffix)).is_symlink(), 'continuation_swap_already_started')
        if p['host'] == 'control01':
            r.need(source_snapshot(p) == p['baseline']['control01']['sources'] and r.sha(original_trust(before)) == p['baseline']['control01']['originalTrustSHA256'], 'continuation_source_changed')
        else:
            r.need(r.read(Path(plan.ROOTS['operator']) / 'config.json', 0) == before['operator'], 'continuation_operator_changed')
            for suffix in ('operator-apply.json', 'operator-apply.pending.json'):
                r.need(not (root / suffix).exists() and not (root / suffix).is_symlink(), 'continuation_operator_swap_started')
            draft = Path(plan.ROOTS['operator']) / 'multisource-recovery.json'; current = r.read(draft, 0)
            r.need(current == old_recovery or (pending.exists() and current == new_recovery and r.read(root / 'recovery-before-continuation.json', 0) == old_recovery), 'continuation_recovery_draft_changed')
        if complete.exists(): r.need(jread(complete) == value and binding == new_binding, 'continuation_completion_changed')
        if p['phase'] == 'continuation_check': return {'identity': value, 'processes': starts, 'complete': complete.exists()}
        r.need(starts == p['continuationProcesses'][p['host']], 'continuation_process_restarted')
        retained(pending, r.encoded(value))
        if p['host'] == 'storage01':
            continuation_cas(draft, old_recovery, new_recovery, root / 'recovery-before-continuation.json', draft.parent / ('.multisource-recovery-continuation-' + p['executionId'] + '.tmp'))
            r.run([p['baseline']['storage01']['roles']['api']['binary'], '--mode', 'check-config', '--check-mode', 'api', '--config', str(draft)], 'validate_continued_recovery_config', timeout=20)
        continuation_cas(root / 'binding.json', old_binding, new_binding, root / 'binding-before-continuation.json', root / 'binding-continuation.tmp')
        retained(complete, r.encoded(value)); return {'identity': value, 'processes': starts, 'complete': True}
    finally: os.close(fd)


def execute(p):
    before, after = input_value(p)
    if p['phase'] == 'database': return database_snapshot()
    if p['phase'] in ('continuation_check', 'continuation_apply'): return continue_install(p, before, after)
    if p['phase'] == 'preflight': return snapshot(p, before)
    r.need(p.get('apply') is True or p['phase'] in ('swap_state', 'verify'), 'explicit_apply_required')
    root = ROOT / p['executionId']
    if p['phase'] in ('swap_state', 'verify'):
        r.private_directory(ROOT); r.private_directory(root)
    else: directory(ROOT); directory(root)
    # Every mutation and replay is fenced by the exact host-reviewed execution.
    fd = lock(root, existing=p['phase'] in ('swap_state', 'verify'))
    try:
        binding = r.encoded({'executionId': p['executionId'], 'reviewSHA256': p['reviewSHA256'], 'implementationSHA256': p['implementationSHA256']})
        if p['phase'] in ('swap_state', 'verify'): r.need(r.read(root / 'binding.json', 0) == binding, 'execution_binding_changed')
        else: retained(root / 'binding.json', binding)
        if p['host'] == 'control01':
            r.need(source_snapshot(p) == p['baseline']['control01']['sources'], 'preserved_source_changed')
            r.need(r.sha(original_trust(before)) == p['baseline']['control01']['originalTrustSHA256'], 'original_trust_changed')
        if p['phase'] == 'materials': return make_materials(p, root, before)
        r.need(p['role'] in r.SPECS and r.SPECS[p['role']][0] == p['host'], 'fixed_role_host')
        validate_materials(p['materials'], [p['role']])
        result = role_phase(p, p['role'], root, before, after)
        # Worker materials are installed last, so only then can the root-only
        # recovery config resolve both worker source identities for validation.
        if (p['role'] == 'worker' and p['phase'] == 'install') or (p['role'] == 'api' and p['phase'] != 'install'):
            operator_phase(p, root, before, after)
        return result
    finally: os.close(fd)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        raw = sys.stdin.buffer.read((4 << 20) + 1); r.need(len(raw) <= 4 << 20, 'input_bounds')
        print(r.encoded(execute(plan.decode(raw))).decode(), end='')
    except r.Failure as error: raise SystemExit(error.code) from None
    except Exception: raise SystemExit('guest_phase_failed') from None
