#!/usr/bin/env python3
"""Reviewed fixed-host phases; API auth key only, with forward recovery."""
import base64
from contextlib import contextmanager
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import time
import urllib.request

if 'p' not in globals():
    spec = importlib.util.spec_from_file_location('rotation_plan', Path(__file__).with_name('dashboard-auth-rotation-plan.py'))
    p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
r = p.r
BASE = Path(p.BASE)
PRESERVED = ('jobman-control', 'jobman-keycloak', 'jobman-dashboard-lab-control', 'jobman-dashboard-lab-directory',
             'jobman-dashboard-lab-control-secondary', 'jobman-dashboard-lab-directory-secondary')


def remaining(deadline, maximum):
    if deadline is None: return maximum
    value = deadline - time.monotonic()
    r.need(value > 0, 'rotated_api_not_ready')
    return min(maximum, value)


def service(unit, deadline=None):
    raw = r.run(['systemctl', 'show', unit, '--property=MainPID', '--property=ExecMainStartTimestampMonotonic', '--property=ActiveState', '--property=DropInPaths'], 'service_identity', timeout=remaining(deadline, 5), maximum=16384).decode()
    value = dict(line.split('=', 1) for line in raw.splitlines())
    r.need(value['ActiveState'] == 'active' and p.decimal(value['MainPID'], True) and p.decimal(value['ExecMainStartTimestampMonotonic'], True) and value['DropInPaths'] == '', 'service_not_active')
    remaining(deadline, 5)
    return value


def process(role, deadline=None):
    _, root, uid, _, unit, binary, _ = r.SPECS[role]
    generation = service(unit, deadline); pid = generation['MainPID']
    r.need(Path('/proc', pid).stat().st_uid == uid, 'process_owner')
    executable = Path(os.readlink('/proc/' + pid + '/exe'))
    r.need(re.fullmatch('/opt/jobman-dashboard-lab/releases/[0-9a-f]{40}/bin/' + binary, str(executable)), 'process_binary_path')
    value = {'binary': str(executable), 'binarySHA256': r.sha(r.read(executable, 0, 0o755, 96 << 20)),
             'unitSHA256': r.sha(r.read(Path('/etc/systemd/system') / (unit + '.service'), 0, 0o644)), 'uid': uid, 'unit': unit}
    args = [value['binary']] + ([] if role == 'broker' else ['--mode', role]) + ['--config', r.SPECS[role][1] + '/config.json']
    r.need(Path('/proc', pid, 'cmdline').read_bytes() == b'\0'.join(s.encode() for s in args) + b'\0', 'process_arguments')
    image, name = Path('/proc', pid, 'exe').stat(), Path(value['binary']).stat()
    r.need((image.st_dev, image.st_ino) == (name.st_dev, name.st_ino), 'process_image_inode')
    remaining(deadline, 5)
    return dict(value, pid=pid, startedMonotonic=generation['ExecMainStartTimestampMonotonic'], bootId=Path('/proc/sys/kernel/random/boot_id').read_text().strip())


def refs(config):
    values = set()
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key.endswith('File'):
                    r.need(isinstance(item, str) and item.startswith('/'), 'material_reference'); values.add(item)
                else: walk(item)
        elif isinstance(value, list):
            for item in value: walk(item)
    walk(config); return sorted(values)


def materials(config, role=None):
    result = {}
    for name in refs(config):
        if name == p.CA: uid, mode = 0, 0o644
        elif role:
            _, root, uid, *_ = r.SPECS[role]
            r.need(name.startswith(root + '/'), 'role_material_boundary'); mode = 0o600
        else:
            choices = [(root, uid) for _, root, uid, *_ in r.SPECS.values()] + [('/etc/jobman-dashboard-operator-lab', 0)]
            uid = next((uid for root, uid in choices if name.startswith(root + '/')), None); mode = 0o600
            if name == p.PRIVILEGED_DSN and config.get('databaseURLFile') == name:
                remaining = dict(config); remaining.pop('databaseURLFile')
                r.need(name not in refs(remaining), 'privileged_dsn_reused'); uid = 21903
            r.need(uid is not None, 'operator_material_boundary')
        raw = r.read(name, uid, mode)
        result[name] = {'sha256': r.sha(raw), 'bytes': len(raw), 'uid': uid, 'mode': mode}
    return result


def capabilities(controls):
    result = []
    for control in controls:
        r.need(control['origin'] in ('https://10.77.0.21:18443', 'https://10.77.0.21:28443'), 'capability_origin')
        ctx = ssl.create_default_context(cadata=r.read(control['trustRootsFile'], 21905).decode()); ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl): return None
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx), NoRedirect())
        with client.open(control['origin'] + '/v1/capabilities', timeout=5) as response:
            raw = response.read(65537); r.need(response.status == 200 and len(raw) <= 65536, 'capability_bound')
        value = p.decode(raw)['capabilities']
        r.need(value['instanceId'] == p.SOURCES[control['id']] and value['recoveryEpoch'] == '1', 'capability_identity')
        result.append({'deploymentId': control['id'], 'instanceId': value['instanceId'], 'recoveryEpoch': value['recoveryEpoch']})
    return result


def snapshot(host):
    if host == 'pg01': return {'database': database()}
    result = {'roles': {}}
    for role in p.ROLES:
        current_host, root, uid, _, unit, _, _ = r.SPECS[role]
        if current_host != host: continue
        raw = r.read(root + '/config.json', uid); config = p.decode(raw)
        value = process(role); r.observations(role, p.REVISION)
        result['roles'][role] = {'config': base64.b64encode(raw).decode(), 'unit': base64.b64encode(r.read('/etc/systemd/system/' + unit + '.service', 0, 0o644)).decode(),
                                 'process': value, 'materials': materials(config, role)}
    if host == 'storage01':
        recovery = r.read(p.RECOVERY_BEFORE, 0)
        result['recovery'] = {'config': base64.b64encode(recovery).decode(), 'materials': materials(p.decode(recovery))}
        raw = r.read(p.OPERATOR, 0); result['operator'] = {'sha256': r.sha(raw), 'materials': materials(p.decode(raw))}
        result['capabilities'] = capabilities(p.decode(p.unb64(result['roles']['worker']['config']))['controls'])
    else: result['preserved'] = {unit: service(unit) for unit in PRESERVED}
    return result


def current_materials(plan, role, raw):
    before = plan['snapshot']['hosts'][r.SPECS[role][0]]['roles'][role]['materials']
    expected = dict(before)
    if role == 'api' and r.sha(raw) == plan['afterConfigSHA256']:
        old = p.decode(p.unb64(plan['snapshot']['hosts']['storage01']['roles']['api']['config']))['encryption']['keyFile']
        expected.pop(old); stage = p.decode(r.read(BASE / 'stage.json', 0))
        expected[p.KEY_FILE] = {'sha256': stage['keySHA256'], 'bytes': 32, 'uid': 21904, 'mode': 0o600}
        r.need(r.sha(r.read(old, 21904)) == before[old]['sha256'], 'retired_key_changed')
    r.need(materials(p.decode(raw), role) == expected, 'private_material_drift')


def authority(plan, host):
    if host == 'pg01': p.database_continuity(plan['snapshot']['hosts'][host]['database'], database()); return
    baseline = plan['snapshot']['hosts'][host]
    for role, value in baseline['roles'].items():
        _, root, uid, _, unit, _, _ = r.SPECS[role]
        raw = r.read(root + '/config.json', uid)
        allowed = (plan['beforeConfigSHA256'], plan['afterConfigSHA256']) if role == 'api' else (r.sha(p.unb64(value['config'])),)
        r.need(r.sha(raw) in allowed and r.read('/etc/systemd/system/' + unit + '.service', 0, 0o644) == p.unb64(value['unit']), 'configuration_or_unit_drift')
        current_materials(plan, role, raw)
        if role != 'api': r.need(process(role) == value['process'], 'unrelated_process_changed')
    if host == 'control01': r.need({unit: service(unit) for unit in PRESERVED} == baseline['preserved'], 'source_process_changed')
    else:
        r.need(r.read(p.RECOVERY_BEFORE, 0) == p.unb64(baseline['recovery']['config']) and materials(p.decode(p.unb64(baseline['recovery']['config']))) == baseline['recovery']['materials'], 'original_recovery_changed')
        raw = r.read(p.OPERATOR, 0)
        r.need({'sha256': r.sha(raw), 'materials': materials(p.decode(raw))} == baseline['operator'], 'operator_changed')
        r.need(capabilities(p.decode(p.unb64(baseline['roles']['worker']['config']))['controls']) == baseline['capabilities'], 'source_capability_changed')


def receipt(name, value):
    path = BASE / (name + '.json'); raw = r.encoded(value)
    if path.exists(): r.need(r.read(path, 0) == raw, 'receipt_changed')
    else: r.put(path, raw)


@contextmanager
def locked(payload):
    if not BASE.exists():
        r.need(payload['phase'] == 'stage' and not payload.get('observeOnly'), 'rotation_not_staged'); r.create_directory(BASE)
    r.private_directory(BASE)
    path = BASE / '.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.fchmod(fd, 0o600)
    except FileExistsError: fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        r.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'guest_lock_identity')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt('intent', {'planSHA256': payload['planSHA256'], 'implementationSHA256': payload['plan']['implementationSHA256']})
        yield
    finally: os.close(fd)


def staged(plan):
    result = p.decode(r.read(BASE / 'stage.json', 0))
    r.need(result['planSHA256'] == r.sha(r.encoded(plan)) and p.HEX.fullmatch(result['keySHA256']) and result['keyId'] == p.KEY_ID, 'stage_binding')
    old = p.decode(p.unb64(plan['snapshot']['hosts']['storage01']['roles']['api']['config']))['encryption']['keyFile']
    key = r.read(p.KEY_FILE, 21904)
    r.need(len(key) == 32 and r.sha(key) == result['keySHA256'] and key == r.read(BASE / 'key', 0) and key != r.read(old, 21904), 'new_key_identity')
    r.need(r.read(p.DRAFT, 21904) == p.unb64(plan['afterConfig']) and r.read(p.RECOVERY_AFTER, 0) == p.unb64(plan['afterRecovery']), 'staged_config_changed')
    return result


def check_config(plan, path):
    binary = plan['snapshot']['hosts']['storage01']['roles']['api']['process']['binary']
    r.run(['runuser', '-u', r.SPECS['api'][3], '--', binary, '--mode', 'check-config', '--check-mode', 'api', '--config', path], 'new_key_configuration', timeout=15)


def stage(payload):
    plan = payload['plan']
    if (BASE / 'stage.json').exists(): return staged(plan)
    r.need(not payload.get('observeOnly') and not (BASE / 'stage.pending.json').exists(), 'stage_uncertain')
    r.need(process('api') == plan['snapshot']['hosts']['storage01']['roles']['api']['process'], 'prestage_api_changed')
    for name in (p.KEY_FILE, p.DRAFT, p.RECOVERY_AFTER): r.need(not os.path.lexists(name), 'new_path_exists')
    receipt('stage.pending', {'planSHA256': payload['planSHA256']})
    key = os.urandom(32)
    old = p.decode(p.unb64(plan['snapshot']['hosts']['storage01']['roles']['api']['config']))['encryption']['keyFile']
    r.need(len(r.read(old, 21904)) == 32 and key != r.read(old, 21904), 'old_or_new_key_invalid')
    r.put(BASE / 'key', key); r.put(Path(p.KEY_FILE), key, 21904)
    r.put(Path(p.DRAFT), p.unb64(plan['afterConfig']), 21904)
    r.put(Path(p.RECOVERY_AFTER), p.unb64(plan['afterRecovery']))
    check_config(plan, p.DRAFT)
    result = {'planSHA256': payload['planSHA256'], 'keyId': p.KEY_ID, 'keySHA256': r.sha(key), 'stagedAt': int(time.time())}
    receipt('stage', result); return staged(plan)


def apply(payload):
    plan = payload['plan']; staged(plan)
    path = Path(p.API_ROOT) / 'config.json'; before = p.unb64(plan['snapshot']['hosts']['storage01']['roles']['api']['config']); after = p.unb64(plan['afterConfig'])
    proof = {'planSHA256': payload['planSHA256'], 'afterConfigSHA256': r.sha(after)}
    if (BASE / 'apply.json').exists(): r.need(r.read(path, 21904) == after, 'applied_config_changed'); return p.decode(r.read(BASE / 'apply.json', 0))
    if (BASE / 'apply.pending.json').exists():
        r.need(payload.get('observeOnly') and r.read(path, 21904) == after and r.read(BASE / 'api-before.json', 0) == before, 'apply_uncertain')
    else:
        r.need(not payload.get('observeOnly') and r.read(path, 21904) == before and process('api') == plan['snapshot']['hosts']['storage01']['roles']['api']['process'], 'preapply_drift')
        check_config(plan, p.DRAFT); receipt('apply.pending', proof)
        r.atomic_config(path, before, after, 21904, BASE / 'api-before.json', payload['planSHA256'])
    receipt('apply', proof); return proof


def ready_observations(deadline):
    prefix = ['runuser', '-u', r.SPECS['api'][3], '--', 'curl', '--silent', '--fail', '--max-time', '2',
              '--unix-socket', '/run/jobman-dashboard-api-lab/observe.sock']
    for endpoint, state in [('livez', 'alive'), ('readyz', 'ready')]:
        value = p.decode(r.run(prefix + ['http://localhost/' + endpoint], 'readiness_api', timeout=remaining(deadline, 3)))
        r.need(value.get('state') == state and value.get('role') == 'api', 'readiness_api')
    metrics = r.run(prefix + ['http://localhost/metrics'], 'metrics_api', timeout=remaining(deadline, 3)).decode()
    r.need(re.findall(r'^jobman_dashboard_configuration_revision ([0-9]+)$', metrics, re.MULTILINE) == [str(p.REVISION)], 'metrics_revision_api')
    remaining(deadline, 3)


def ready(plan):
    baseline = plan['snapshot']['hosts']['storage01']['roles']['api']['process']; deadline = time.monotonic() + 30
    while True:
        try:
            current = process('api', deadline); immutable = {k: v for k, v in baseline.items() if k not in ('pid', 'startedMonotonic')}
            r.need({k: v for k, v in current.items() if k not in ('pid', 'startedMonotonic')} == immutable and current['pid'] != baseline['pid'] and int(current['startedMonotonic']) > int(baseline['startedMonotonic']), 'new_api_generation')
            ready_observations(deadline); remaining(deadline, 1); return current
        except (ValueError, OSError):
            time.sleep(remaining(deadline, 0.2))


def restart(payload):
    plan = payload['plan']; staged(plan); r.read(BASE / 'apply.json', 0)
    r.need(r.read(p.API_ROOT + '/config.json', 21904) == p.unb64(plan['afterConfig']), 'restart_config')
    if (BASE / 'restart.json').exists():
        result = p.decode(r.read(BASE / 'restart.json', 0)); r.need(ready(plan) == result['process'], 'completed_process_changed'); return result
    baseline = plan['snapshot']['hosts']['storage01']['roles']['api']['process']
    if (BASE / 'restart.pending.json').exists(): r.need(p.decode(r.read(BASE / 'restart.pending.json', 0)) == baseline, 'restart_intent_changed')
    else:
        r.need(not payload.get('observeOnly') and process('api') == baseline, 'restart_before_changed')
        receipt('restart.pending', baseline)
        r.run(['systemctl', 'restart', r.SPECS['api'][4]], 'api_restart', timeout=100)
    result = {'planSHA256': payload['planSHA256'], 'process': ready(plan)}
    receipt('restart', result); return result


def execute(payload):
    host, phase = payload['host'], payload['phase']
    r.need(os.geteuid() == 0 and host in p.HOSTS and socket.gethostname().split('.')[0] == host, 'guest_host_boundary')
    r.need(phase in ('snapshot', 'check', 'preflight', 'stage', 'apply', 'restart', 'verify'), 'guest_phase_boundary')
    if phase == 'snapshot': return snapshot(host)
    plan = payload['plan']; p.validate(plan); r.need(payload['planSHA256'] == r.sha(r.encoded(plan)), 'plan_digest'); authority(plan, host)
    if phase == 'check': return {'planSHA256': payload['planSHA256'], 'host': host, 'authorityUnchanged': True}
    if phase == 'preflight':
        if host == 'storage01':
            r.need(not os.path.lexists(BASE) and not os.path.lexists(p.KEY_FILE) and not os.path.lexists(p.DRAFT), 'rotation_preexisting')
            r.need(process('api') == plan['snapshot']['hosts'][host]['roles']['api']['process'], 'api_baseline_changed')
        return {'planSHA256': payload['planSHA256'], 'host': host, 'preflightAt': int(time.time())}
    if phase == 'verify' and host != 'storage01': return {'planSHA256': payload['planSHA256'], 'host': host, 'preserved': True}
    r.need(host == 'storage01' and payload.get('apply') is True, 'api_host_apply_only')
    with locked(payload):
        if phase == 'stage': return stage(payload)
        if phase == 'apply': return apply(payload)
        if phase == 'restart': return restart(payload)
        result = p.decode(r.read(BASE / 'restart.json', 0)); staged(plan)
        r.need(ready(plan) == result['process'], 'verified_process_changed'); check_config(plan, p.API_ROOT + '/config.json')
        return {'planSHA256': payload['planSHA256'], 'host': host, 'preserved': True, 'process': result['process'], 'authenticationKeyId': p.KEY_ID}


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

