#!/usr/bin/env python3
"""Fixed-host upgrade phases; only called through a hash-pinned reviewed driver."""
import base64
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import time
import urllib.request

if 'p' not in globals():
    spec = importlib.util.spec_from_file_location('candidate_plan', Path(__file__).with_name('dashboard-candidate-plan.py'))
    p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
r = p.r
BASE = Path('/var/lib/jobman-dashboard-candidate-upgrade')
RELEASES = Path('/opt/jobman-dashboard-lab/releases')


def put(path, raw, uid=0, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchown(output.fileno(), uid, uid); os.fchmod(output.fileno(), mode)
        output.write(raw); output.flush(); os.fsync(output.fileno())
    r.sync(path.parent)


def directory(path, mode=0o700):
    info = path.lstat()
    r.need(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
           stat.S_IMODE(info.st_mode) == mode, 'directory_identity')


def create(path, mode=0o700):
    path.mkdir(mode=mode); path.chmod(mode); directory(path, mode); r.sync(path.parent)


@contextmanager
def locked():
    if not BASE.exists(): create(BASE)
    directory(BASE)
    path = BASE / '.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.fchmod(fd, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        r.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'lock_identity')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def remaining(deadline, bound=5):
    left = deadline - time.monotonic()
    r.need(left > 0, 'readiness_deadline')
    return min(left, bound)


def properties(role, names, deadline):
    args = ['systemctl', 'show', r.SPECS[role][4]] + ['--property=' + name for name in names]
    raw = r.run(args, 'unit_properties', timeout=remaining(deadline), maximum=16384).decode()
    pairs = [line.split('=', 1) for line in raw.splitlines()]
    r.need(len(pairs) == len(names) and all(len(pair) == 2 for pair in pairs), 'unit_properties_shape')
    result = dict(pairs); r.need(set(result) == set(names), 'unit_properties_names')
    return result


def process(role, release, binary_sha, deadline):
    _, root, uid, _, _, binary, mode = r.SPECS[role]
    prop = properties(role, ['MainPID', 'ExecMainStartTimestampMonotonic', 'ActiveState', 'KillMode', 'TimeoutStopUSec', 'DropInPaths'], deadline)
    pid = prop['MainPID']
    r.need(prop['ActiveState'] == 'active' and pid.isdigit() and int(pid) > 1 and
           prop['ExecMainStartTimestampMonotonic'].isdigit() and int(prop['ExecMainStartTimestampMonotonic']) > 0 and
           prop['KillMode'] == 'control-group' and prop['TimeoutStopUSec'] in ('1min 30s', '90s') and not prop['DropInPaths'], 'active_process_policy')
    image = Path('/proc', pid, 'exe'); expected = Path(release, 'bin', binary)
    r.need(image.parent.stat().st_uid == uid and os.readlink(image) == str(expected), 'active_process_image')
    fd = os.open(image, os.O_RDONLY)
    try:
        actual, wanted = os.fstat(fd), expected.stat()
        r.need((actual.st_dev, actual.st_ino) == (wanted.st_dev, wanted.st_ino), 'active_image_inode')
    finally: os.close(fd)
    raw = r.read(expected, 0, 0o755, 96 << 20)
    r.need(r.sha(raw) == binary_sha, 'active_binary_digest')
    args = Path('/proc', pid, 'cmdline').read_bytes()
    expected_args = [str(expected)] + ([] if mode == 'broker' else ['--mode', mode]) + ['--config', root + '/config.json']
    r.need(args == b'\0'.join(a.encode() for a in expected_args) + b'\0', 'active_process_arguments')
    return {'pid': pid, 'startedMonotonic': prop['ExecMainStartTimestampMonotonic'],
            'bootId': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'uid': uid,
            'binary': str(expected), 'binarySHA256': binary_sha}


def observations(role, deadline):
    _, _, _, user, _, _, mode = r.SPECS[role]
    prefix = ['runuser', '-u', user, '--', 'curl', '--silent', '--fail', '--max-time', '2',
              '--unix-socket', '/run/jobman-dashboard-' + role + '-lab/observe.sock']
    for endpoint, state in [('livez', 'alive'), ('readyz', 'ready')]:
        result = p.decode(r.run(prefix + ['http://localhost/' + endpoint], 'role_readiness', timeout=remaining(deadline, 3)))
        r.need(result.get('state') == state and result.get('role') == mode, 'role_readiness_shape')
    text = r.run(prefix + ['http://localhost/metrics'], 'role_metrics', timeout=remaining(deadline, 3)).decode()
    r.need(re.findall(r'^jobman_dashboard_configuration_revision ([0-9]+)$', text, re.MULTILINE) == [str(p.REVISION)], 'loaded_revision')


def check_config(role, release, deadline):
    _, root, _, user, _, binary, mode = r.SPECS[role]
    args = ['runuser', '-u', user, '--', release + '/bin/' + binary, '--mode', 'check-config']
    if role != 'broker': args += ['--check-mode', mode]
    r.run(args + ['--config', root + '/config.json'], 'candidate_configuration', timeout=remaining(deadline, 10))


def ready(role, plan, timeout=30):
    deadline = time.monotonic() + timeout
    stage = 'process'
    while True:
        try:
            stage = 'process'
            value = process(role, p.NEW_ROOT, plan['candidateFiles']['bin/' + r.SPECS[role][5]]['sha256'], deadline)
            stage = 'configuration'; check_config(role, p.NEW_ROOT, deadline)
            stage = 'observability'; observations(role, deadline)
            return value
        except (ValueError, OSError):
            r.need(time.monotonic() < deadline, 'startup_' + stage)
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def refs(config):
    result = set()
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key.endswith('File'):
                    r.need(isinstance(item, str) and item.startswith('/'), 'material_reference'); result.add(item)
                else: walk(item)
        elif isinstance(value, list):
            for item in value: walk(item)
    walk(config); return sorted(result)


def file_proofs(config, root, uid):
    result = {}
    for name in refs(config):
        r.need(name.startswith(root + '/') or name == p.CA, 'material_role_boundary')
        mode, owner = (0o644, 0) if name == p.CA else (0o600, uid)
        raw = r.read(name, owner, mode)
        result[name] = {'sha256': r.sha(raw), 'bytes': len(raw), 'uid': owner, 'mode': mode}
    return result


def capabilities(control):
    r.need(control['origin'] in ('https://10.77.0.21:18443', 'https://10.77.0.21:28443'), 'control_origin')
    # Role-owned trust file already checked in the material inventory.
    trust = Path(control['trustRootsFile']).read_bytes()
    ctx = ssl.create_default_context(cadata=trust.decode()); ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx), NoRedirect())
    with opener.open(control['origin'] + '/v1/capabilities', timeout=5) as response:
        raw = response.read(65537); r.need(response.status == 200 and len(raw) <= 65536, 'capabilities_bound')
    value = p.decode(raw)['capabilities']
    r.need(value['instanceId'] == control['expectedInstanceId'] and re.fullmatch('[1-9][0-9]{0,18}', value['recoveryEpoch']), 'capabilities_identity')
    return {'deploymentId': control['id'], 'instanceId': value['instanceId'], 'recoveryEpoch': value['recoveryEpoch']}


def operator_proofs():
    result = {}
    for filename in (p.OPERATOR, *p.RECOVERIES):
        raw = r.read(filename, 0); config = p.decode(raw)
        materials = {}
        for name in refs(config):
            choices = [(root, uid) for _, root, uid, *_ in r.SPECS.values()] + [(str(Path(filename).parent), 0)]
            owner = next((uid for root, uid in choices if name.startswith(root + '/')), None)
            mode = 0o600
            if name == p.CA: owner, mode = 0, 0o644
            legacy_dsn = '/etc/jobman-dashboard-app-lab/database-url'
            if filename in p.RECOVERIES and name == legacy_dsn and config.get('databaseURLFile') == legacy_dsn:
                other_fields = dict(config); other_fields.pop('databaseURLFile')
                r.need(legacy_dsn not in refs(other_fields), 'legacy_database_reference_reused')
                owner, mode = 21903, 0o600
            r.need(owner is not None, 'operator_reference_boundary')
            content = r.read(name, owner, mode)
            materials[name] = {'sha256': r.sha(content), 'bytes': len(content), 'uid': owner, 'mode': mode}
        result[filename] = {'sha256': r.sha(raw), 'files': materials}
    return result


def host_snapshot(host):
    roles = {}
    for role in p.ROLES:
        current_host, root, uid, _, unit, binary, _ = r.SPECS[role]
        if current_host != host: continue
        config_raw = r.read(root + '/config.json', uid)
        unit_raw = r.read('/etc/systemd/system/' + unit + '.service', 0, 0o644, 16384)
        config = p.decode(config_raw)
        digest = r.sha(r.read(p.OLD_ROOT + '/bin/' + binary, 0, 0o755, 96 << 20))
        value = process(role, p.OLD_ROOT, digest, time.monotonic() + 10); observations(role, time.monotonic() + 10)
        roles[role] = {'config': base64.b64encode(config_raw).decode(), 'unit': base64.b64encode(unit_raw).decode(),
                       'process': value, 'materials': file_proofs(config, root, uid),
                       'capabilities': [capabilities(c) for c in config['controls']] if role == 'worker' else []}
    result = {'roles': roles}
    if host == 'storage01': result['operator'] = operator_proofs()
    return result


DATABASE_SQL = """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms';
SELECT json_build_object(
 'ledger',(SELECT json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name) FROM dashboard_schema_migrations),
 'databaseOID',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'hold',(SELECT json_build_object('generation',generation::text,'held',held,'suppressRecordedThrough',restore_recorded_through::text) FROM dashboard_notification_delivery_control WHERE singleton),
 'sources',(SELECT json_agg(json_build_object('deploymentId',f.deployment_id,'controlInstanceId',i.control_instance_id,
   'recoveryEpoch',i.recovery_epoch,'namespaceIds',f.namespace_ids,'configurationRevision',i.configuration_revision,'state',f.status,'generation',f.generation::text,'lastPosition',f.last_position::text,
   'openGaps',(SELECT count(*) FROM dashboard_event_gaps g WHERE g.deployment_id=f.deployment_id AND g.resolved_at IS NULL),
   'unfinishedRecoveries',(SELECT count(*) FROM dashboard_event_recoveries x WHERE x.deployment_id=f.deployment_id AND x.status IN('replaying','ready','quarantined')))
   ORDER BY f.deployment_id) FROM dashboard_event_feeds f FULL JOIN dashboard_source_identities i USING(deployment_id)),
 'roleProof',json_build_object(
   'roles',(SELECT json_agg(json_build_object('name',rolname,'super',rolsuper,'inherit',rolinherit,'createRole',rolcreaterole,'createDB',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,'bypassRLS',rolbypassrls,'limit',rolconnlimit) ORDER BY rolname) FROM pg_roles WHERE rolname IN('jobman_dashboard_ddl','jobman_dashboard_api','jobman_dashboard_worker','jobman_dashboard_operator')),
   'members',(SELECT coalesce(json_agg(json_build_object('role',r.rolname,'member',m.rolname,'admin',a.admin_option,'inherit',a.inherit_option,'set',a.set_option) ORDER BY r.rolname,m.rolname),'[]') FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member WHERE r.rolname IN('jobman_dashboard_ddl','jobman_dashboard_api','jobman_dashboard_worker','jobman_dashboard_operator') OR m.rolname IN('jobman_dashboard_ddl','jobman_dashboard_api','jobman_dashboard_worker','jobman_dashboard_operator')),
   'tables',(SELECT json_agg(json_build_object('name',c.relname,'owner',pg_get_userbyid(c.relowner),'acl',c.relacl::text) ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
   'columns',(SELECT coalesce(json_agg(json_build_object('table',c.relname,'column',a.attname,'acl',a.attacl::text) ORDER BY c.relname,a.attnum),'[]') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL),
   'functions',(SELECT coalesce(json_agg(json_build_object('oid',f.oid,'owner',pg_get_userbyid(f.proowner),'acl',f.proacl::text) ORDER BY f.oid),'[]') FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='public'),
   'defaults',(SELECT coalesce(json_agg(json_build_object('role',pg_get_userbyid(d.defaclrole),'namespace',d.defaclnamespace,'kind',d.defaclobjtype,'acl',d.defaclacl::text) ORDER BY d.oid),'[]') FROM pg_default_acl d),
   'database',(SELECT json_build_object('owner',pg_get_userbyid(datdba),'acl',datacl::text) FROM pg_database WHERE datname=current_database()),
   'schema',(SELECT json_build_object('owner',pg_get_userbyid(nspowner),'acl',nspacl::text) FROM pg_namespace WHERE nspname='public')));
COMMIT;
"""


def database():
    args = ['podman', 'exec', '-i', '--user', 'postgres', 'jobman-postgres', 'psql', '-X', '-q', '-A', '-t',
            '-U', 'jobman_control', '-v', 'ON_ERROR_STOP=1', '-d', 'jobman_dashboard']
    value = p.decode(r.run(args, 'database_snapshot', input_data=DATABASE_SQL.encode(), timeout=15, maximum=2 << 20))
    roles = value.pop('roleProof'); r.need(len(roles['roles']) == 4, 'database_roles_missing')
    value['rolesSHA256'] = r.sha(r.encoded(roles)); return p.stable_database(value)


def immutable_candidate(plan):
    root = Path(p.NEW_ROOT); directory(root, 0o755)
    expected = plan['candidateFiles']; names = set()
    directories = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != '.'}
    for path in root.rglob('*'):
        name = path.relative_to(root).as_posix()
        if path.is_dir() and not path.is_symlink():
            r.need(name in directories, 'unexpected_candidate_directory'); directory(path, 0o755); continue
        r.need(name in expected and not path.is_symlink(), 'unexpected_candidate_path'); names.add(name)
        item = expected[name]; raw = r.read(path, 0, item['mode'], 96 << 20)
        r.need(len(raw) == item['bytes'] and r.sha(raw) == item['sha256'], 'candidate_file_changed')
    r.need(names == set(expected), 'candidate_inventory')


def database_continuity(expected, actual):
    p.stable_database(expected); p.stable_database(actual)
    before, after = p.decode(r.encoded(expected)), p.decode(r.encoded(actual))
    for prior, current in zip(before['sources'], after['sources']):
        r.need(prior['deploymentId'] == current['deploymentId'], 'database_source_order')
        for name in ('generation', 'lastPosition'):
            old, new = prior.pop(name), current.pop(name)
            pattern = '[1-9][0-9]{0,18}' if name == 'generation' else '(0|[1-9][0-9]{0,18})'
            r.need(isinstance(old, str) and isinstance(new, str) and re.fullmatch(pattern, old) and re.fullmatch(pattern, new) and
                   int(new) >= int(old), 'database_feed_regressed')
    r.need(before == after, 'database_baseline_changed')


def authority(plan, host):
    if host == 'pg01':
        database_continuity(plan['database'], database()); return
    baseline = plan['snapshot']['hosts'][host]
    for role, value in baseline['roles'].items():
        _, root, uid, _, _, _, _ = r.SPECS[role]
        raw = r.read(root + '/config.json', uid)
        change = plan['changes'][role]
        r.need(r.sha(raw) in (change['beforeConfigSHA256'], change['afterConfigSHA256']), 'configuration_drift')
        r.need(file_proofs(p.decode(raw), root, uid) == value['materials'], 'material_drift')
        if role == 'worker': r.need([capabilities(c) for c in p.decode(raw)['controls']] == value['capabilities'], 'source_drift')
    if host == 'storage01': r.need(operator_proofs() == baseline['operator'], 'operator_material_drift')


def receipt(root, name, result):
    path = root / (name + '.json'); raw = r.encoded(result)
    if path.exists(): r.need(r.read(path, 0) == raw, 'receipt_changed')
    else: put(path, raw)


def intent(payload):
    plan = payload['plan']; p.validate(plan)
    digest = r.sha(r.encoded(plan))
    r.need(digest == payload['planSHA256'] and payload['apply'] is True, 'explicit_plan_apply')
    root = BASE / digest
    global_intent = {'planSHA256': digest, 'implementationSHA256': plan['implementationSHA256']}
    receipt(BASE, p.OPERATION_NAME, global_intent)
    if not root.exists(): create(root)
    directory(root); receipt(root, 'intent', global_intent)
    return root


def preflight(payload):
    plan, host = payload['plan'], payload['host']; p.validate(plan); authority(plan, host)
    if host != 'pg01':
        r.need(not Path(p.NEW_ROOT).exists() and not Path(p.NEW_ROOT).is_symlink(), 'candidate_already_exists')
        space = os.statvfs(RELEASES)
        r.need(space.f_bavail * space.f_frsize > sum(v['bytes'] for v in plan['candidateFiles'].values()) * 2 + (256 << 20), 'candidate_disk_headroom')
        for role, value in plan['snapshot']['hosts'][host]['roles'].items():
            r.need(process(role, p.OLD_ROOT, value['process']['binarySHA256'], time.monotonic() + 10) == value['process'], 'baseline_process_changed')
            r.need(r.sha(r.read('/etc/systemd/system/' + r.SPECS[role][4] + '.service', 0, 0o644, 16384)) == plan['changes'][role]['beforeUnitSHA256'], 'baseline_unit_changed')
    return {'planSHA256': payload['planSHA256'], 'host': host, 'preflightAt': int(time.time())}


def stage(payload, root):
    plan = payload['plan']; done = root / 'stage.json'
    if done.exists(): immutable_candidate(plan); return p.decode(r.read(done, 0))
    r.need(not (root / 'stage.pending.json').exists() and not Path(p.NEW_ROOT).exists(), 'stage_uncertain')
    authority(plan, payload['host']); directory(RELEASES, 0o755)
    archive = p.unb64(payload['archive'], 32 << 20); r.need(r.sha(archive) == p.ARCHIVE, 'archive_digest')
    receipt(root, 'stage.pending', {'planSHA256': payload['planSHA256']})
    archive_path = root / 'candidate.tar.gz'; put(archive_path, archive)
    metadata, files = p.split.candidate_files(archive_path, p.ARCHIVE)
    r.need(metadata == plan['candidate'] and {n: {'sha256': r.sha(v), 'bytes': len(v), 'mode': 0o755 if n.startswith('bin/') else 0o644} for n, v in files.items()} == plan['candidateFiles'], 'candidate_contents')
    create(Path(p.NEW_ROOT), 0o755)
    for name, raw in files.items():
        path = Path(p.NEW_ROOT) / name
        parents = []; parent = path.parent
        while parent != Path(p.NEW_ROOT): parents.append(parent); parent = parent.parent
        for parent in reversed(parents):
            if not parent.exists(): create(parent, 0o755)
            else: directory(parent, 0o755)
        put(path, raw, mode=plan['candidateFiles'][name]['mode'])
    immutable_candidate(plan)
    result = {'planSHA256': payload['planSHA256'], 'candidateRevision': p.NEW, 'archiveSHA256': p.ARCHIVE}
    receipt(root, 'stage', result); return result


def schema_check(plan):
    # This exact compiled binary checks all embedded migration digests before
    # using the existing read-only operator credential. No migrate/grants command.
    operator_proofs()
    r.run([p.NEW_ROOT + '/bin/jobman-dashboard', 'status', '--operator-config', p.OPERATOR], 'candidate_schema_check', timeout=12, maximum=1 << 20)
    return {'binarySHA256': plan['candidateFiles']['bin/jobman-dashboard']['sha256'], 'schema': '18', 'readOnly': True}


def change_file(root, label, path, before, after, uid, mode):
    pending, completed = root / (label + '.pending.json'), root / (label + '.json')
    proof = {'beforeSHA256': r.sha(before), 'afterSHA256': r.sha(after), 'path': str(path)}
    if completed.exists():
        r.need(p.decode(r.read(completed, 0)) == proof and r.read(path, uid, mode) == after, 'completed_change_drift'); return
    if pending.exists():
        r.need(p.decode(r.read(pending, 0)) == proof and r.read(path, uid, mode) == after, 'change_uncertain')
        receipt(root, label, proof); return
    r.need(r.read(path, uid, mode) == before, 'file_compare_and_swap')
    receipt(root, label + '.pending', proof)
    put(root / (label + '.backup'), before)
    temporary = path.parent / ('.candidate-' + root.name + '-' + label + '.tmp')
    put(temporary, after, uid, mode)
    r.need(r.read(path, uid, mode) == before, 'file_changed_before_rename')
    os.replace(temporary, path); r.sync(path.parent)
    r.need(r.read(path, uid, mode) == after, 'changed_file_verification'); receipt(root, label, proof)


def apply(payload, root):
    plan, host = payload['plan'], payload['host']; authority(plan, host); immutable_candidate(plan)
    r.need((root / 'stage.json').exists(), 'stage_receipt_required')
    for role, value in plan['snapshot']['hosts'][host]['roles'].items():
        r.need(process(role, p.OLD_ROOT, value['process']['binarySHA256'], time.monotonic() + 10) == value['process'], 'preapply_process_changed')
        check_config(role, p.NEW_ROOT, time.monotonic() + 12)
    if host == 'storage01': receipt(root, 'schema-check', schema_check(plan))
    for role, baseline in plan['snapshot']['hosts'][host]['roles'].items():
        _, config_root, uid, _, unit, _, _ = r.SPECS[role]
        change = plan['changes'][role]
        if role == 'api':
            change_file(root, role + '-config', Path(config_root) / 'config.json', p.unb64(baseline['config']), p.unb64(change['afterConfig']), uid, 0o600)
        change_file(root, role + '-unit', Path('/etc/systemd/system/' + unit + '.service'), p.unb64(baseline['unit'], 16384), p.unb64(change['afterUnit'], 16384), 0, 0o644)
    return {'planSHA256': payload['planSHA256'], 'host': host, 'filesApplied': True}


def loaded_units(plan, host):
    for role in plan['snapshot']['hosts'][host]['roles']:
        wanted = p.unit_lines(role, p.NEW_ROOT)
        names = ['ExecStart', 'ExecStartPre', 'WorkingDirectory', 'NeedDaemonReload', 'DropInPaths']
        values = properties(role, names, time.monotonic() + 5)
        r.need(values['NeedDaemonReload'] == 'no' and values['DropInPaths'] == '' and
               values['WorkingDirectory'] == wanted.get('WorkingDirectory', ''), 'loaded_unit_drift')
        for key in ('ExecStart', 'ExecStartPre'):
            expected = wanted[key]
            r.need('argv[]=' + expected + ' ;' in values[key] and p.OLD_ROOT not in values[key] and
                   values[key].count('argv[]=') == 1, 'loaded_command_drift')


def reload_units(plan, host, root, observe=False):
    proof = {'host': host, 'newRevision': p.NEW}
    if (root / 'reload.json').exists(): loaded_units(plan, host); return
    if not (root / 'reload.pending.json').exists():
        r.need(not observe, 'reload_not_previously_started')
        receipt(root, 'reload.pending', proof)
        r.run(['systemctl', 'daemon-reload'], 'daemon_reload', timeout=15)
    # Uncertain daemon-reload is never repeated; only prove already loaded bytes.
    loaded_units(plan, host); receipt(root, 'reload', proof)


def restart(payload, root):
    plan, host, role = payload['plan'], payload['host'], payload['role']
    r.need(role in plan['snapshot']['hosts'][host]['roles'], 'restart_role_host')
    authority(plan, host); immutable_candidate(plan)
    for name, change in plan['changes'].items():
        if r.SPECS[name][0] != host: continue
        r.need(r.sha(r.read('/etc/systemd/system/' + r.SPECS[name][4] + '.service', 0, 0o644, 16384)) == change['afterUnitSHA256'], 'all_units_applied')
        r.need(r.sha(r.read(r.SPECS[name][1] + '/config.json', r.SPECS[name][2])) == change['afterConfigSHA256'], 'all_configs_applied')
    reload_units(plan, host, root, payload.get('observeOnly', False))
    pending, done = root / (role + '-restart.pending.json'), root / (role + '-restart.json')
    baseline = plan['snapshot']['hosts'][host]['roles'][role]['process']
    if done.exists():
        result = p.decode(r.read(done, 0)); r.need(ready(role, plan) == result['process'], 'completed_restart_drift'); return result
    if pending.exists():
        r.need(p.decode(r.read(pending, 0)) == baseline, 'restart_pending_changed')
    else:
        r.need(not payload.get('observeOnly'), 'restart_not_previously_started')
        r.need(process(role, p.OLD_ROOT, baseline['binarySHA256'], time.monotonic() + 10) == baseline, 'restart_baseline_changed')
        receipt(root, role + '-restart.pending', baseline)
        r.run(['systemctl', 'restart', r.SPECS[role][4]], 'role_restart', timeout=100)
    # A lost reply can only observe a new running process, never restart again.
    current = ready(role, plan)
    r.need(current['bootId'] == baseline['bootId'] and current['pid'] != baseline['pid'] and int(current['startedMonotonic']) > int(baseline['startedMonotonic']), 'restart_generation_not_proven')
    result = {'planSHA256': payload['planSHA256'], 'role': role, 'process': current}
    receipt(root, role + '-restart', result); return result


def verify(payload, root):
    plan, host = payload['plan'], payload['host']; authority(plan, host)
    if host == 'pg01': return {'databaseUnchanged': True, 'planSHA256': payload['planSHA256']}
    immutable_candidate(plan); result = {}
    for role in plan['snapshot']['hosts'][host]['roles']:
        done = p.decode(r.read(root / (role + '-restart.json'), 0))
        r.need(ready(role, plan) == done['process'], 'verified_process_generation'); result[role] = done['process']
        change = plan['changes'][role]
        r.need(r.sha(r.read(r.SPECS[role][1] + '/config.json', r.SPECS[role][2])) == change['afterConfigSHA256'], 'verified_config')
        r.need(r.sha(r.read('/etc/systemd/system/' + r.SPECS[role][4] + '.service', 0, 0o644, 16384)) == change['afterUnitSHA256'], 'verified_unit')
    loaded_units(plan, host)
    if host == 'storage01': schema_check(plan)
    return {'planSHA256': payload['planSHA256'], 'host': host, 'processes': result, 'unchangedAuthority': True}


def execute(payload):
    host, phase = payload['host'], payload['phase']
    r.need(payload.get('transition') == p.TRANSITION, 'guest_transition_boundary')
    r.need(os.geteuid() == 0 and host in p.HOSTS and socket.gethostname().split('.')[0] == host, 'guest_host_identity')
    if phase == 'snapshot': return {'database': database()} if host == 'pg01' else host_snapshot(host)
    plan = payload['plan']; p.validate(plan)
    r.need(payload['planSHA256'] == r.sha(r.encoded(plan)), 'plan_digest')
    if phase == 'database-check':
        r.need(host == 'pg01', 'database_host_required'); authority(plan, host); return {'databaseUnchanged': True}
    if phase == 'preflight': return preflight(payload)
    r.need(phase in ('stage', 'apply', 'restart', 'verify') and payload.get('apply') is True, 'phase_requires_apply')
    if host == 'pg01':
        r.need(phase == 'verify', 'database_read_only_boundary'); return verify(payload, None)
    if payload.get('observeOnly'):
        directory(BASE); directory(BASE / payload['planSHA256'])
    with locked():
        root = intent(payload)
        if payload.get('observeOnly') and phase == 'stage':
            authority(plan, host); immutable_candidate(plan); return p.decode(r.read(root / 'stage.json', 0))
        if payload.get('observeOnly') and phase == 'apply':
            authority(plan, host); immutable_candidate(plan)
            r.read(root / 'stage.json', 0)
            if host == 'storage01': r.read(root / 'schema-check.json', 0)
            for role in plan['snapshot']['hosts'][host]['roles']:
                change = plan['changes'][role]
                r.need(r.sha(r.read(r.SPECS[role][1] + '/config.json', r.SPECS[role][2])) == change['afterConfigSHA256'], 'observed_apply_config')
                r.need(r.sha(r.read('/etc/systemd/system/' + r.SPECS[role][4] + '.service', 0, 0o644, 16384)) == change['afterUnitSHA256'], 'observed_apply_unit')
            return {'planSHA256': payload['planSHA256'], 'host': host, 'filesApplied': True}
        if phase == 'stage': return stage(payload, root)
        if phase == 'apply': return apply(payload, root)
        if phase == 'restart': return restart(payload, root)
        return verify(payload, root)
