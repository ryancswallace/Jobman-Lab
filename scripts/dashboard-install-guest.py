#!/usr/bin/env python3
"""Fixed fresh-install guest phases. Never invokes a primary or restore mutation."""
import base64
import contextlib
import copy
import fcntl
import grp
import importlib.util
import os
from pathlib import Path
import pwd
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
for name, filename in [('p', 'dashboard-install-plan.py'), ('f', 'dashboard-dependency-fault-guest.py'),
                       ('u', 'dashboard-control-upgrade-guest.py')]:
    if name not in globals():
        spec = importlib.util.spec_from_file_location(name, HERE/filename)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); globals()[name] = module
BASE = Path(p.OPERATIONS)
ROOTS = {role: Path(value) for role, value in p.ROOTS.items()}
RESTORE = [Path('/etc/jobman-dashboard-restore-'+role+'-lab') for role in ('api', 'worker', 'operator')]
RESTORE += [Path('/var/lib/jobman-dashboard-restore-reports-lab')]
SECRET_NAMES = {'auth', 'policy', 'cursor', 'web', 'ddl', 'api', 'worker', 'operator'}


def directory(path, uid=0, gid=0, mode=0o700, create=False):
    path = Path(path)
    p.need(path.is_absolute() and path.parent.resolve() == path.parent, 'directory_parent')
    if create:
        previous = os.umask(0o077)
        try: path.mkdir(mode=mode)
        finally: os.umask(previous)
        fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fchown(fd, uid, gid); os.fchmod(fd, mode); os.fsync(fd)
        finally: os.close(fd)
        f.sync(path.parent)
    info = path.lstat()
    p.need(path.resolve() == path and stat.S_ISDIR(info.st_mode) and
           (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode), 'directory_identity')


def put(path, raw, uid=0, gid=0, mode=0o600):
    path = Path(path)
    p.need(path.parent.resolve() == path.parent, 'write_parent')
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchown(output.fileno(), uid, gid); os.fchmod(output.fileno(), mode)
        output.write(raw); output.flush(); os.fsync(output.fileno())
    f.sync(path.parent)


def marker(root, name, value):
    path = root/(name+'.json'); raw = p.encoded(value)
    if path.exists(): p.need(f.read(path, maximum=8<<20) == raw, 'receipt_drift')
    else: put(path, raw)


@contextlib.contextmanager
def locked():
    if not BASE.exists(): directory(BASE, create=True)
    directory(BASE)
    path = BASE/'.lock'
    try: fd = os.open(path, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK, 0o600); os.fchmod(fd, 0o600)
    except FileExistsError: fd = os.open(path, os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        row = os.fstat(fd)
        p.need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_uid == row.st_gid == 0 and
               stat.S_IMODE(row.st_mode) == 0o600, 'lock_identity')
        fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB); yield
    finally: os.close(fd)


def operation(plan, create=False):
    root = BASE/plan['operationId']
    if create and not root.exists():
        entries = list(BASE.iterdir()); p.need(len(entries) <= 16, 'operation_history_bound')
        for entry in entries:
            if entry.name == '.lock': continue
            directory(entry); p.need((entry/'retired.json').exists(), 'previous_install_not_retired')
        directory(root, create=True); marker(root, 'plan', plan)
    directory(root); p.need(f.read(root/'plan.json', maximum=8<<20) == p.encoded(plan), 'operation_plan_drift')
    return root


def begin(plan, phase):
    root = operation(plan, create=phase in ('stage', 'identity', 'database'))
    p.need(not (root/(phase+'.pending.json')).exists(), 'uncertain_phase_requires_observation')
    marker(root, phase+'.pending', {'operationId': plan['operationId'], 'phase': phase, 'planSHA256': p.sha(p.encoded(plan))})
    return root


def finish(plan, root, phase, extra=None):
    value = dict(extra or {}, operationId=plan['operationId'], phase=phase, completed=True,
                 planSHA256=p.sha(p.encoded(plan)))
    marker(root, phase, value); return value


def sql(query, database='postgres', timeout=20):
    p.need(database in ('postgres', p.DATABASE, 'jobman_dashboard_restore'), 'sql_database')
    return f.run(['podman', 'exec', '-i', '--user', 'postgres', 'jobman-postgres', 'psql', '-X', '-q', '-A', '-t',
                  '-U', 'jobman_control', '-v', 'ON_ERROR_STOP=1', '-d', database], 'install_sql',
                 data=query.encode(), timeout=timeout, maximum=4<<20).decode().strip()


def tree(path, maximum=256<<20):
    """Hash an existing private tree without following links or exposing bytes."""
    root = Path(path); p.need(root.resolve() == root, 'tree_alias')
    result, pending, total = {}, [root], 0
    while pending:
        parent = pending.pop(); row = parent.lstat()
        p.need(stat.S_ISDIR(row.st_mode), 'tree_directory')
        result[str(parent)] = {'uid': row.st_uid, 'gid': row.st_gid, 'mode': stat.S_IMODE(row.st_mode), 'kind': 'directory'}
        for name in sorted(parent.iterdir()):
            row = name.lstat(); p.need(len(result)+len(pending) < 4096, 'tree_count')
            if stat.S_ISDIR(row.st_mode): pending.append(name); continue
            p.need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and 0 <= row.st_size <= 8<<20, 'tree_file')
            total += row.st_size; p.need(total <= maximum, 'tree_bytes')
            fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno()); raw = stream.read((8<<20)+1); after = os.fstat(stream.fileno())
            p.need((row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns,row.st_ctime_ns) ==
                   (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
                   (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and
                   os.path.samestat(after, name.lstat()) and len(raw) == row.st_size,
                   'tree_changed')
            result[str(name)] = {'uid': row.st_uid, 'gid': row.st_gid, 'mode': stat.S_IMODE(row.st_mode),
                                 'bytes': len(raw), 'sha256': p.sha(raw)}
    return p.sha(p.encoded(result))


def restore_storage():
    result = {'trees': {str(path): tree(path) for path in RESTORE}, 'units': {}}
    for role in p.USERS:
        unit = 'jobman-dashboard-restore-'+role+'-lab'
        state = f.properties(unit)
        p.need(state['MainPID'] == '0' and state['ActiveState'] == 'inactive', 'restore_clone_running')
        result['units'][unit] = {'state': state, 'sha256': p.sha(f.read(state['FragmentPath'], 0, 0o644, 32768))}
    return result


def restore_database():
    query = """BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms';
SELECT json_build_object('oid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'ledger',(SELECT json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name) FROM dashboard_schema_migrations),
 'reports',(SELECT count(*) FROM dashboard_report_tasks),
 'rules',(SELECT count(*) FROM dashboard_notification_rules),
 'events',(SELECT count(*) FROM dashboard_source_events),
 'hold',(SELECT row_to_json(x) FROM dashboard_notification_delivery_control x WHERE singleton)); COMMIT;"""
    return p.decode(sql(query, 'jobman_dashboard_restore'))


def free_storage():
    for name, uid in [*p.USERS.values(), p.READER]:
        for lookup, key in ((pwd.getpwnam, name), (pwd.getpwuid, uid), (grp.getgrnam, name), (grp.getgrgid, uid)):
            try: lookup(key)
            except KeyError: continue
            raise p.b.Failure('install_identity_exists')
    paths = [*ROOTS.values(), Path(p.REPORTS), Path(p.RELEASES).parent]
    paths += [Path('/run')/unit for unit in p.UNITS.values()]
    paths += [Path('/etc/systemd/system')/(unit+'.service') for unit in p.UNITS.values()]
    p.need(all(not os.path.lexists(path) for path in paths), 'install_path_exists')
    with socket.socket() as probe: probe.bind(('10.77.0.10', p.PORT))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


class Identity:
    def __init__(self):
        self.token = None
        context = ssl.create_default_context(cafile=p.CA)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPSHandler(context=context), NoRedirect())
        # Existing synthetic administrator credentials are used only in memory.
        values = dict(line.split('=',1) for line in f.read('/etc/jobman-lab/keycloak.env', 0, maximum=65536).decode().splitlines() if '=' in line)
        data = urllib.parse.urlencode({'grant_type': 'password', 'client_id': 'admin-cli',
                                      'username': values['KC_BOOTSTRAP_ADMIN_USERNAME'],
                                      'password': values['KC_BOOTSTRAP_ADMIN_PASSWORD']}).encode()
        self.token = self.request('POST', '/realms/master/protocol/openid-connect/token', data, form=True)['access_token']

    def request(self, method, path, body=None, form=False):
        p.need(path.startswith(('/admin/realms/jobman-lab/', '/realms/master/protocol/openid-connect/token')) and
               method in ('GET', 'POST', 'PUT'), 'identity_operation')
        headers = {'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json'}
        if self.token: headers['Authorization'] = 'Bearer '+self.token
        data = body if isinstance(body, bytes) else p.encoded(body) if body is not None else None
        try:
            with self.opener.open(urllib.request.Request('https://oidc.lab.test:8443'+path, data=data,
                                                        headers=headers, method=method), timeout=f.remaining(10)) as response:
                raw = response.read((2<<20)+1)
                p.need(len(raw) <= 2<<20 and response.status in (200, 201, 204), 'identity_response')
                return p.decode(raw) if raw else None
        except (urllib.error.URLError, ValueError, KeyError): raise p.b.Failure('identity_unavailable') from None

    def get(self, suffix): return self.request('GET', '/admin/realms/jobman-lab/'+suffix)


def identity_proof(admin, absent=False):
    clients = admin.get('clients'); users = admin.get('users?first=0&max=1001')
    p.need(isinstance(clients, list) and len(clients) <= 256 and isinstance(users, list) and len(users) <= 1000, 'identity_inventory_bound')
    ours = [c for c in clients if c.get('clientId') == p.CLIENT]
    p.need(len(ours) <= 1 and (not absent or not ours), 'install_client_exists')
    preserved = [c for c in clients if c.get('clientId') != p.CLIENT]
    return {'clientsSHA256': p.sha(p.encoded(sorted(preserved, key=lambda c: c['id']))),
            'usersSHA256': p.sha(p.encoded(sorted(users, key=lambda c: c['id']))),
            'profileSHA256': p.sha(p.encoded(admin.get('users/profile'))), 'absent': not ours}, ours


def hba_bytes():
    return f.run(['podman', 'exec', 'jobman-postgres', 'cat', '/var/lib/postgresql/data/pg_hba.conf'], 'hba_read', maximum=1<<20)


def hba_prefix():
    roles = ','.join(p.ROLES.values())
    return (f'# Disposable Jobman Dashboard install {p.SCOPE}\nhostssl {p.DATABASE} {roles} 10.77.0.10/32 scram-sha-256\n'
            f'host all {roles} 0.0.0.0/0 reject\nhost all {roles} ::/0 reject\n').encode()


def retained_attempt(value,host,require_abort=True):
    p.validate_previous(value,with_states=require_abort)
    old=prior_guest; plan=value['plan']; proof=value['abortedReceipt']; old.p.validate(plan)
    root=old.operation(plan)
    if old.p.SCOPE=='v1':
        p.need(not (root/'upgrade.pending.json').exists() and not (root/'rollback.pending.json').exists(),
               'previous_transition_admitted')
    else:
        p.need(old.p.SCOPE=='v2' and p.SCOPE=='v3','previous_attempt_scope')
        old.retained_attempt(plan['snapshot'][host]['previousAttempt'],host)
        p.need(not any((root/n).exists() for n in ('upgrade.json','rollback.pending.json','rollback.json','retired.json')),
               'previous_transition_completed')
        # Upgrade mutation is admitted only on storage01; no new receipt is made.
        if host=='storage01':
            raw=f.read(root/'upgrade.pending.json')
            row=p.decode(raw)
            p.need(p.sha(raw)==proof['upgradeIntentSHA256'] and row=={'operationId':plan['operationId'],
                   'phase':'upgrade','planSHA256':proof['planSHA256']},'previous_upgrade_intent')
    result={'operationId':plan['operationId'],'operationTreeSHA256':old.tree(root)}
    if host=='storage01':
        raw=f.read(root/'stop.json')
        p.need(p.sha(raw)==proof['stopSHA256'],'previous_stop_receipt')
        stopped_value=p.decode(raw)
        p.need(stopped_value.get('stopped') is True and stopped_value.get('completed') is True and
               stopped_value.get('operationId')==plan['operationId'],'previous_not_stopped')
        old.stopped();old.own_configuration(plan,'upgrade' if old.p.SCOPE=='v2' else 'baseline')
        result['trees']={str(path):old.tree(path) for path in [*old.ROOTS.values(),Path(old.p.REPORTS)]}
        result['units']={unit:f.properties(unit) for unit in old.p.UNITS.values()}
        for candidate in ('baseline','upgrade'):old.verify_release(plan,candidate)
        result['releases']={k:v['files'] for k,v in plan['candidates'].items()}
    elif host=='control01':
        raw=f.read(root/'retire-identity.json');row=p.decode(raw)
        p.need(p.sha(raw)==proof['retireSHA256'] and row.get('enabled') is False and row.get('completed') is True and
               row.get('operationId')==plan['operationId'],'previous_retirement_receipt')
        admin=old.Identity();client_id=row['clientId']
        secret=admin.get('clients/'+client_id+'/client-secret')['value']
        p.need(isinstance(secret,str) and p.sha(secret.encode())==plan['generatedSHA256']['web'],'previous_secret_changed')
        p.need(old.check_client(admin,secret,True)==client_id,'previous_client_changed')
        result['clientSHA256']=p.sha(p.encoded(admin.get('clients/'+client_id)))
        result['clientId']=client_id;result['enabled']=False
    else:
        p.need(host=='pg01','previous_host')
        result['data']=old.data_state(plan)
        if old.p.SCOPE=='v1':
            p.need(result['data']['reports']==result['data']['rules']==0,'previous_failure_stage_changed')
        else:
            p.need({k:result['data'][k] for k in proof['baselineRetained']}==proof['baselineRetained'],
                   'previous_baseline_changed')
        names=p.decode(old.sql("SELECT coalesce(json_agg(c.relname ORDER BY c.relname),'[]') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p');",old.p.DATABASE))
        p.need(1<=len(names)<=128 and all(p.re.fullmatch('dashboard_[a-z_]{1,80}',n) for n in names),'previous_table_names')
        selects=["SELECT '"+n+"' AS name,count(*) AS count,coalesce(sum(octet_length(to_jsonb(t)::text)),0) AS bytes,encode(sha256(convert_to(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),''),'UTF8')),'hex') AS digest FROM public."+n+' t' for n in names]
        query="BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms'; SELECT json_agg(row_to_json(x) ORDER BY name) FROM ("+' UNION ALL '.join(selects)+") x; COMMIT;"
        rows=p.decode(old.sql(query,old.p.DATABASE))
        p.need(all(x['count']<=1000 and x['bytes']<=1<<20 for x in rows) and sum(x['bytes'] for x in rows)<=8<<20,'previous_data_bound')
        result['tablesSHA256']=p.sha(p.encoded(rows))
        roles=','.join("'"+x+"'" for x in old.p.ROLES.values())
        result['rolesSHA256']=p.sha(old.sql("SELECT json_agg(row_to_json(r) ORDER BY rolname) FROM (SELECT oid,rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolconnlimit,rolvaliduntil,rolbypassrls,rolconfig FROM pg_roles WHERE rolname IN ("+roles+")) r").encode())
    if require_abort:p.need(result==proof['states'][host],'previous_attempt_drift')
    return result


def snapshot(host, revision, previous=None):
    if host == 'storage01':
        free_storage(); configs, materials = {}, {}
        for role, (root, uid) in p.PRIMARY.items():
            value = p.decode(f.read(root+'/config.json', uid, maximum=256<<10)); configs[role] = value
            for name in p.references(value):
                if name == value['databaseURLFile']: continue
                p.need(name.startswith(root+'/') or name == p.CA, 'role_material_boundary')
                owner, mode = (0, 0o644) if name == p.CA else (uid, 0o600)
                raw = f.read(name, owner, mode)
                materials[name] = {'uid': owner, 'mode': mode, 'bytes': len(raw), 'sha256': p.sha(raw)}
        memory = int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024
        space = os.statvfs('/var/lib')
        return {'unused': True, 'configs': configs, 'materials': materials, 'preserved': f.host_snapshot(host, revision),
                'restore': restore_storage(), 'memoryBytes': memory, 'freeBytes': space.f_bavail*space.f_frsize}
    if host == 'control01':
        identity, _ = identity_proof(Identity(), absent=True)
        return {'preserved': f.host_snapshot(host, revision), 'sourceInventory': u.source_inventory(), 'identity': identity}
    names = ','.join("'"+name+"'" for name in p.ROLES.values())
    p.need(sql("SELECT count(*) FROM pg_database WHERE datname='"+p.DATABASE+"'") == '0' and
           sql('SELECT count(*) FROM pg_roles WHERE rolname IN ('+names+')') == '0', 'new_database_or_role_exists')
    p.need(sql("SELECT current_setting('ssl')='on' AND NOT EXISTS(SELECT FROM pg_hba_file_rules WHERE error IS NOT NULL)") == 't', 'database_tls_or_hba')
    slots = int(sql("SELECT current_setting('max_connections')::int-count(*)-current_setting('superuser_reserved_connections')::int FROM pg_stat_activity"))
    space = os.statvfs('/var/lib/containers')
    return {'unused': True, 'preserved': u.databases(), 'restore': restore_database(), 'hbaSHA256': p.sha(hba_bytes()),
            'connections': slots, 'freeBytes': space.f_bavail*space.f_frsize}


def preserved(plan, host):
    before = plan['snapshot'][host]
    if p.SCOPE!='v1': retained_attempt(before['previousAttempt'],host)
    if host in ('control01', 'storage01'):
        p.need(f.host_snapshot(host, before['preserved']['revision']) == before['preserved'], 'existing_runtime_changed')
        if host == 'storage01': p.need(restore_storage() == before['restore'], 'restore_storage_changed')
        else:
            p.need(u.source_inventory() == before['sourceInventory'], 'existing_source_files_changed')
            value, _ = identity_proof(Identity()); old = dict(before['identity']); old['absent'] = value['absent']
            p.need(value == old, 'existing_identity_changed')
    else:
        value = u.databases(); p.b.database_preserved(before['preserved']['dashboard'], value['dashboard'])
        # No normal source workloads are submitted by this exercise.
        p.need(value['sources'] == before['preserved']['sources'], 'existing_source_data_changed')
        p.need(restore_database() == before['restore'], 'restore_database_changed')
        raw = hba_bytes()
        p.need(p.sha(raw) == before['hbaSHA256'] or raw.startswith(hba_prefix()) and
               p.sha(raw[len(hba_prefix()):]) == before['hbaSHA256'], 'unrelated_hba_changed')
    return {'preserved': True, 'host': host}


def verify_secrets(plan, values):
    p.need(set(values) == SECRET_NAMES, 'secret_names')
    decoded = {}
    for name, value in values.items():
        raw = base64.b64decode(value, validate=True)
        p.need(len(raw) == (32 if name in ('auth', 'policy', 'cursor') else 64) and
               (name in ('auth', 'policy', 'cursor') or p.s.HEX.fullmatch(raw.decode())) and
               p.sha(raw) == plan['generatedSHA256'][name], 'secret_pin')
        decoded[name] = raw
    p.need(len({p.sha(v) for v in decoded.values()}) == len(decoded), 'secret_reuse')
    return decoded


def candidate_files(plan, selected, values):
    candidate = plan['candidates'][selected]
    p.need(set(values) == set(candidate['files']), 'candidate_files')
    result = {}
    for name, row in candidate['files'].items():
        raw = base64.b64decode(values[name], validate=True)
        p.need(len(raw) == row['bytes'] and p.sha(raw) == row['sha256'], 'candidate_file_digest')
        result[name] = raw
    p.need(p.decode(result['build.json'])['revision'] == candidate['revision'], 'candidate_build_metadata')
    for role in p.USERS:
        expected = p.unit(role, candidate, result['deploy/systemd/jobman-dashboard-'+role+'.service'])
        p.need(base64.b64decode(plan['units'][selected][role], validate=True) == expected, 'unit_not_packaged_transform')
    return result


def verify_release(plan, selected):
    candidate = plan['candidates'][selected]; root = Path(p.release(candidate))
    directory(root, mode=0o755)
    paths = set()
    for parent, directories, files in os.walk(root, followlinks=False):
        directory(parent, mode=0o755)
        p.need(len(paths)+len(files)+len(directories) <= 2048, 'release_file_count')
        for child in directories: directory(Path(parent)/child, mode=0o755)
        for child in files:
            path = Path(parent)/child; name = str(path.relative_to(root)); paths.add(name)
            p.need(name in candidate['files'], 'unexpected_release_file')
            row = candidate['files'][name]
            if row['bytes'] == 0:
                fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                try:
                    st = os.fstat(fd)
                    p.need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == st.st_gid == 0 and
                           stat.S_IMODE(st.st_mode) == (0o755 if name.startswith('bin/') else 0o644) and st.st_size == 0,
                           'empty_release_file_identity')
                    raw = os.read(fd, 1)
                finally: os.close(fd)
            else: raw = f.read(path, 0, 0o755 if name.startswith('bin/') else 0o644, maximum=96<<20)
            p.need(len(raw) == row['bytes'] and p.sha(raw) == row['sha256'], 'release_drift')
    p.need(paths == set(candidate['files']), 'release_incomplete')
    return str(root/'bin/jobman-dashboard')


def stage(plan, payload):
    root = begin(plan, 'stage')
    p.need(set(payload['packages']) == {'baseline', 'upgrade'}, 'package_pair')
    packages = {key: candidate_files(plan, key, value) for key, value in payload['packages'].items()}
    directory(Path(p.RELEASES).parent, mode=0o755, create=True); directory(p.RELEASES, mode=0o755, create=True)
    for selected, files in packages.items():
        target = Path(p.release(plan['candidates'][selected])); directory(target, mode=0o755, create=True)
        for name, raw in sorted(files.items()):
            path = target/name
            pending = []
            parent = path.parent
            while parent != target and not parent.exists(): pending.append(parent); parent = parent.parent
            for parent in reversed(pending): directory(parent, mode=0o755, create=True)
            put(path, raw, mode=0o755 if name.startswith('bin/') else 0o644)
        verify_release(plan, selected)
    return finish(plan, root, 'stage', {'revisions': {k:v['revision'] for k,v in plan['candidates'].items()}})


def check_client(admin, secret, retired=False):
    values = admin.get('clients?'+urllib.parse.urlencode({'clientId': p.CLIENT}))
    p.need(isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict) and
           isinstance(values[0].get('id'), str) and p.b.UUID.fullmatch(values[0]['id']), 'client_identity_count')
    client_id = values[0]['id']; value = admin.get('clients/'+client_id); expected = p.client_spec(secret)
    p.need(isinstance(value, dict) and value.get('id') == client_id, 'client_identity_changed')
    if retired: expected['enabled'] = False
    for key, wanted in expected.items():
        if key == 'secret': continue
        if key == 'protocolMappers':
            rows = value.get(key)
            p.need(isinstance(rows, list) and len(rows) == len(wanted) and
                   all(isinstance(m, dict) and isinstance(m.get('name'), str) for m in rows), 'client_mappers_changed')
            current = {m['name']: {k:v for k,v in m.items() if k != 'id'} for m in rows}
            # JSON encoding distinguishes false from 0; count equality also
            # rejects duplicate names instead of silently keeping the last row.
            p.need(len(current) == len(rows) and p.encoded(current) == p.encoded({m['name']:m for m in wanted}),
                   'client_mappers_changed')
        elif key == 'attributes':
            actual = value.get(key)
            p.need(isinstance(actual, dict) and all(type(actual.get(k)) is type(v) and actual.get(k) == v
                                                   for k,v in wanted.items()), 'client_attributes_changed')
        else: p.need(type(value.get(key)) is type(wanted) and value.get(key) == wanted, 'client_policy_changed')
    p.need(admin.get('clients/'+client_id+'/client-secret').get('value') == secret, 'client_secret_changed')
    return client_id


def identity(plan, payload, retire=False):
    phase = 'retire-identity' if retire else 'identity'; root = begin(plan, phase)
    secret = verify_secrets(plan, payload['secrets'])['web'].decode(); admin = Identity()
    if retire:
        client_id = check_client(admin, secret)
        receipt = p.decode(f.read(root/'identity.json'))
        p.need(receipt['clientId'] == client_id, 'retire_client_identity')
        spec = p.client_spec(secret); spec['enabled'] = False
        admin.request('PUT', '/admin/realms/jobman-lab/clients/'+client_id, spec)
    else:
        proof, values = identity_proof(admin, absent=True)
        p.need(proof == plan['snapshot']['control01']['identity'] and not values, 'identity_baseline_changed')
        admin.request('POST', '/admin/realms/jobman-lab/clients', p.client_spec(secret))
    client_id = check_client(admin, secret, retired=retire)
    return finish(plan, root, phase, {'clientId': client_id, 'enabled': not retire})


def role_sql(secrets):
    lines = ["SET statement_timeout='20000ms'; SET lock_timeout='500ms';"]
    for role, name in p.ROLES.items():
        secret = secrets[role].decode(); p.need(p.s.HEX.fullmatch(secret), 'role_secret')
        limit = 16 if role in ('api', 'worker') else 2
        lines.append(f"CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {limit} PASSWORD '{secret}';")
    lines += [f'CREATE DATABASE {p.DATABASE} OWNER {p.ROLES["ddl"]};', f'REVOKE ALL ON DATABASE {p.DATABASE} FROM PUBLIC;',
              f'GRANT CONNECT ON DATABASE {p.DATABASE} TO '+','.join(p.ROLES[role] for role in ('api','worker','operator'))+';',
              f'\\connect {p.DATABASE}', 'REVOKE ALL ON SCHEMA public FROM PUBLIC;',
              f'ALTER SCHEMA public OWNER TO {p.ROLES["ddl"]};']
    return '\n'.join(lines)+'\n'


def empty_database():
    query = """BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms';
SELECT json_build_object(
 'relations',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'),
 'extraSchemas',(SELECT count(*) FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('public','information_schema')),
 'routines',(SELECT count(*) FROM pg_proc r JOIN pg_namespace n ON n.oid=r.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'),
 'types',(SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'),
 'extensions',(SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql'),
 'ledgerAbsent',to_regclass('public.dashboard_schema_migrations') IS NULL,
 'publicOwner',(SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public'));
COMMIT;"""
    value = p.decode(sql(query, p.DATABASE))
    p.need(value == {'relations':0,'extraSchemas':0,'routines':0,'types':0,'extensions':0,'ledgerAbsent':True,'publicOwner':p.ROLES['ddl']},
           'fresh_database_not_empty')
    return {'empty':True,'database':p.DATABASE}


def database(plan, payload):
    root = begin(plan, 'database'); secrets = verify_secrets(plan, payload['secrets'])
    names = ','.join("'"+name+"'" for name in p.ROLES.values())
    p.need(sql("SELECT count(*) FROM pg_database WHERE datname='"+p.DATABASE+"'") == '0' and
           sql('SELECT count(*) FROM pg_roles WHERE rolname IN ('+names+')') == '0', 'install_database_exists')
    before = hba_bytes(); p.need(p.sha(before) == plan['snapshot']['pg01']['hbaSHA256'], 'hba_drift')
    put(root/'hba.before', before); put(root/'hba.after', hba_prefix()+before)
    sql(role_sql(secrets), timeout=35)
    empty_database()
    # The fixed container path is exclusive. The ordinary database service is
    # only reloaded; no PostgreSQL or other service restart is performed.
    target = '/var/lib/postgresql/data/pg_hba.install-'+plan['operationId']
    command = 'set -eu; set -C; umask 077; cat > "$1"; chown postgres:postgres "$1"; chmod 0600 "$1"; sync -f "$1"; mv -T "$1" /var/lib/postgresql/data/pg_hba.conf; sync -f /var/lib/postgresql/data'
    p.need(hba_bytes() == before, 'hba_pre_swap_changed')
    f.run(['podman','exec','-i','--user','root','jobman-postgres','sh','-c',command,'install-hba',target],
          'hba_install', data=hba_prefix()+before, timeout=15)
    p.need(sql('SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL') == '0' and
           sql('SELECT pg_reload_conf()') == 't', 'hba_reload_failed')
    oid = sql("SELECT oid::text FROM pg_database WHERE datname='"+p.DATABASE+"'")
    p.need(oid.isdigit() and int(oid)>0 and hba_bytes() == hba_prefix()+before, 'database_postcheck')
    return finish(plan, root, 'database', {'databaseOID': oid, 'hbaSHA256': p.sha(hba_prefix()+before)})


def dsn(role, secret):
    p.need(role in p.ROLES and p.s.HEX.fullmatch(secret.decode()), 'dsn_role')
    query = urllib.parse.urlencode({'sslmode': 'verify-full', 'sslrootcert': p.CA, 'connect_timeout': '5'})
    return ('postgres://'+p.ROLES[role]+':'+secret.decode()+'@10.77.0.20:5432/'+p.DATABASE+'?'+query+'\n').encode()


def own_identities():
    p.need(grp.getgrnam(p.READER[0]).gr_gid == p.READER[1], 'reader_group')
    for name, uid in p.USERS.values():
        row = pwd.getpwnam(name)
        p.need(row.pw_uid == row.pw_gid == uid and row.pw_dir == '/nonexistent' and row.pw_shell == '/usr/sbin/nologin' and
               grp.getgrnam(name).gr_gid == uid and set(os.getgrouplist(name, uid)) == {uid, p.READER[1]}, 'install_user_drift')


def install(plan, payload):
    root = begin(plan, 'install'); secrets = verify_secrets(plan, payload['secrets'])
    p.need(p.decode(f.read(root/'stage.json'))['completed'] is True, 'stage_required')
    for selected in plan['candidates']: verify_release(plan, selected)
    for name, gid in [*p.USERS.values(), p.READER]:
        f.run(['groupadd','--gid',str(gid),name], 'create_install_group')
    for role, (name, uid) in p.USERS.items():
        f.run(['useradd','--uid',str(uid),'--gid',str(uid),'--groups',p.READER[0], '--no-create-home',
               '--home-dir','/nonexistent','--shell','/usr/sbin/nologin',name], 'create_install_user')
        directory(ROOTS[role], uid, uid, create=True); directory(ROOTS[role]/'material', uid, uid, create=True)
        directory(Path('/run')/p.UNITS[role], uid, uid, create=True)
    directory(ROOTS['operator'], create=True)
    directory(p.REPORTS, p.USERS['worker'][1], p.READER[1], 0o750, create=True)
    own_identities()
    for item in plan['copies']:
        raw = f.read(item['source'], item['uid'], item['mode'])
        p.need(len(raw) == item['bytes'] and p.sha(raw) == item['sha256'], 'material_copy_drift')
        uid = p.USERS[item['role']][1]; put(item['destination'], raw, uid, uid)
    for role, (_, uid) in p.USERS.items():
        for filename, secret in [('database-url', dsn(role,secrets[role])), ('report-policy.key',secrets['policy']), ('log-cursor.key',secrets['cursor'])]:
            put(ROOTS[role]/filename, secret, uid, uid)
        if role == 'api':
            put(ROOTS[role]/'auth.key', secrets['auth'], uid, uid); put(ROOTS[role]/'web-secret', secrets['web'], uid, uid)
        put(ROOTS[role]/'config.json', p.encoded(plan['configs'][role]), uid, uid)
        put('/etc/systemd/system/'+p.UNITS[role]+'.service', base64.b64decode(plan['units']['baseline'][role]), mode=0o644)
    for role in ('ddl','operator'): put(ROOTS['operator']/(role+'-url' if role == 'ddl' else 'database-url'), dsn(role,secrets[role]))
    put(ROOTS['operator']/'config.json', p.encoded(plan['configs']['operator']))
    f.run(['systemctl','daemon-reload'], 'install_daemon_reload', timeout=10)
    # Actual file permission probe. An unexpected success leaves only this
    # disposable root's probe file and fails without silently repairing modes.
    probe = "import os,sys\ntry: os.open(sys.argv[1]+'/.api-write-probe',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\nexcept PermissionError: sys.exit(0)\nsys.exit(2)"
    f.run(['runuser','-u',p.USERS['api'][0],'--','python3','-c',probe,p.REPORTS], 'api_report_write_denied')
    return finish(plan, root, 'install', {'unitsStarted': False, 'configSHA256': {k:p.sha(p.encoded(v)) for k,v in plan['configs'].items()}})


def migrate(plan):
    root = begin(plan, 'migrate'); binary = own_configuration(plan, 'baseline')
    # Migrator is the only product command with the new DDL file. No retained
    # application database is copied or given this credential.
    f.run([binary,'--mode','migrate','--config',str(ROOTS['api']/'config.json'),
           '--migration-database-url-file',str(ROOTS['operator']/'ddl-url')], 'fresh_migration', timeout=60, maximum=65536)
    return finish(plan, root, 'migrate', {'expectedLedgerSHA256': p.sha(p.encoded(plan['candidates']['baseline']['ledger']))})


def install_ledger():
    query = "BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms'; SELECT json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name) FROM dashboard_schema_migrations; COMMIT;"
    return p.ledger(p.decode(sql(query, p.DATABASE)))


def grants(plan, payload):
    root = begin(plan, 'grants'); p.need(install_ledger() == plan['candidates']['baseline']['ledger'], 'installed_schema_differs')
    values = payload['grants']; p.need(set(values) == {'api','worker','operator'}, 'grant_roles')
    for role, value in values.items():
        raw = base64.b64decode(value, validate=True)
        p.need(len(raw) <= 256<<10 and p.sha(raw) == plan['grantSHA256'][role], 'grant_sql_changed')
        sql(raw.decode(), p.DATABASE, timeout=35)
    role_names=','.join("'"+p.ROLES[role]+"'" for role in ('api','worker','operator'))
    rows = p.decode(sql("SELECT json_agg(json_build_object('name',rolname,'safe',NOT(rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit))) FROM pg_roles WHERE rolname IN ("+role_names+")"))
    p.need(len(rows) == 3 and all(v['safe'] for v in rows), 'runtime_role_privileges')
    return finish(plan, root, 'grants', {'ledgerSHA256': p.sha(p.encoded(install_ledger())), 'runtimeRoles': sorted(v['name'] for v in rows)})


def config_for(plan, selected, role):
    value = copy.deepcopy(plan['configs'][role])
    if role == 'api': value['webRoot'] = p.release(plan['candidates'][selected])+'/web'
    return p.encoded(value)


def own_configuration(plan, selected):
    own_identities(); binary = verify_release(plan, selected)
    directory(ROOTS['operator'])
    p.need(f.read(ROOTS['operator']/'config.json') == p.encoded(plan['configs']['operator']), 'operator_config_drift')
    for role, name in [('ddl', 'ddl-url'), ('operator', 'database-url')]:
        raw = f.read(ROOTS['operator']/name); parsed = urllib.parse.urlparse(raw.decode().strip())
        p.need(parsed.password is not None and p.sha(parsed.password.encode()) == plan['generatedSHA256'][role] and
               raw == dsn(role, parsed.password.encode()), 'operator_dsn_drift')
    for role, (_, uid) in p.USERS.items():
        directory(ROOTS[role], uid, uid)
        for name, key in [('report-policy.key', 'policy'), ('log-cursor.key', 'cursor')]+([('auth.key', 'auth'), ('web-secret', 'web')] if role == 'api' else []):
            p.need(p.sha(f.read(ROOTS[role]/name, uid)) == plan['generatedSHA256'][key], 'purpose_key_drift')
        raw_dsn = f.read(ROOTS[role]/'database-url', uid)
        parsed = urllib.parse.urlparse(raw_dsn.decode().strip())
        p.need(parsed.password is not None and p.sha(parsed.password.encode()) == plan['generatedSHA256'][role] and
               raw_dsn == dsn(role, parsed.password.encode()), 'runtime_dsn_drift')
        p.need(f.read(ROOTS[role]/'config.json', uid) == config_for(plan, selected, role), 'install_config_drift')
        unit = f.read('/etc/systemd/system/'+p.UNITS[role]+'.service', 0, 0o644, 32768)
        p.need(unit == base64.b64decode(plan['units'][selected][role]), 'install_unit_drift')
        for item in plan['copies']:
            if item['role'] == role:
                p.need(p.sha(f.read(item['destination'], uid)) == item['sha256'], 'copied_material_drift')
    return binary


def replace(path, before, after, root, name, uid=0, mode=0o600):
    p.need(f.read(path, uid, mode) == before, 'replacement_compare_failed')
    put(root/(name+'.before'), before); target = Path(str(path)+'.install-'+root.name+'-'+name)
    put(target, after, uid, uid, mode)
    p.need(f.read(path, uid, mode) == before, 'replacement_pre_swap_changed')
    os.replace(target, path); f.sync(Path(path).parent)


def stopped():
    for unit in p.UNITS.values():
        value = f.properties(unit)
        p.need(value['MainPID'] == '0' and value['ActiveState'] == 'inactive', 'install_not_stopped')


def process(plan, selected, role):
    value = f.process(p.UNITS[role]); candidate = plan['candidates'][selected]
    binary = p.release(candidate)+'/bin/jobman-dashboard'; config = str(ROOTS[role]/'config.json')
    args = '\0'.join([binary,'--mode',role,'--config',config])+'\0'
    p.need(value['uid'] == p.USERS[role][1] and value['binary'] == binary and
           value['binarySHA256'] == candidate['files']['bin/jobman-dashboard']['sha256'] and
           value['argumentsSHA256'] == p.sha(args.encode()) and
           value['unitSHA256'] == p.sha(base64.b64decode(plan['units'][selected][role])), 'install_process_identity')
    return value


def ready(plan, selected, seconds=25):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        try:
            values = {role:process(plan, selected, role) for role in p.USERS}
            f.run(['curl','--silent','--fail','--max-time','2','--cacert',p.CA,p.ORIGIN+'/healthz'],
                  'install_health', timeout=min(3,max(.001,deadline-time.monotonic())), maximum=1024)
            p.need(time.monotonic() < deadline, 'install_readiness_deadline')
            return values
        except (OSError, ValueError):
            p.need(time.monotonic() < deadline, 'install_not_ready'); time.sleep(min(.2,max(0,deadline-time.monotonic())))
    raise p.b.Failure('install_not_ready')


def runtime_directory(path, uid, gid):
    # A normal systemd stop removes RuntimeDirectory by default. Manual
    # check-config still verifies that the private socket parent resolves.
    # Create only an absent exact own path; never repair a preexisting path.
    try: Path(path).lstat()
    except FileNotFoundError: directory(path, uid, gid, create=True)
    else: directory(path, uid, gid)


def runtime_directories():
    for role, (_, uid) in p.USERS.items():
        runtime_directory(Path('/run')/p.UNITS[role], uid, uid)


def activate(plan, phase):
    p.need(phase in ('baseline','upgrade','rollback'), 'activation_phase')
    selected = 'upgrade' if phase == 'upgrade' else 'baseline'
    previous = 'baseline' if phase in ('baseline','upgrade') else 'upgrade'
    root = begin(plan, phase)
    own_configuration(plan, previous)
    if phase != 'baseline':
        # One ordinary stop for the disposable pair; never stops a primary or
        # restore unit. No forced cgroup kill or automatic fallback is present.
        for role in p.USERS: process(plan, previous, role)
        f.run(['systemctl','stop',*p.UNITS.values()], 'install_stop_before_transition', timeout=100)
    stopped()
    if selected != previous:
        for role, (_, uid) in p.USERS.items():
            old = base64.b64decode(plan['units'][previous][role]); new = base64.b64decode(plan['units'][selected][role])
            replace('/etc/systemd/system/'+p.UNITS[role]+'.service',old,new,root,phase+'-'+role+'-unit',mode=0o644)
        replace(ROOTS['api']/'config.json',config_for(plan,previous,'api'),config_for(plan,selected,'api'),root,
                phase+'-api-config',uid=p.USERS['api'][1])
        f.run(['systemctl','daemon-reload'], 'transition_daemon_reload', timeout=10)
    binary = own_configuration(plan, selected)
    runtime_directories()
    # Both packaged binaries must independently accept the exact real ledger.
    status = p.decode(f.run([binary,'status','--operator-config',str(ROOTS['operator']/'config.json')],
                           'install_schema_check',timeout=15,maximum=65536))
    p.need(isinstance(status,dict), 'install_status_shape')
    for role,(user,_) in p.USERS.items():
        f.run(['runuser','-u',user,'--',binary,'--mode','check-config','--check-mode',role,'--config',str(ROOTS[role]/'config.json')],
              'install_'+role+'_local_validation',timeout=10,maximum=8192)
    # Start API before worker so it persists fresh source identities first.
    f.run(['systemctl','start',p.UNITS['api']], 'install_start_api',timeout=15)
    f.run(['systemctl','start',p.UNITS['worker']], 'install_start_worker',timeout=15)
    values = ready(plan,selected)
    return finish(plan,root,phase,{'selected':selected,'processes':values,'objectsSHA256':tree(p.REPORTS)})


def data_state(plan):
    p.need(install_ledger() == plan['candidates']['baseline']['ledger'], 'fresh_ledger_drift')
    query = """BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms';
SELECT json_build_object('databaseOID',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'accounts',(SELECT count(*) FROM dashboard_accounts),'reports',(SELECT count(*) FROM dashboard_report_tasks),
 'rules',(SELECT count(*) FROM dashboard_notification_rules),'inbox',(SELECT count(*) FROM dashboard_notification_inbox),
 'devices',(SELECT count(*) FROM dashboard_notification_device_bindings),
 'events',(SELECT count(*) FROM dashboard_source_events),
 'feeds',(SELECT json_agg(json_build_object('deploymentId',f.deployment_id,'instance',i.control_instance_id,
   'epoch',i.recovery_epoch,'status',f.status,'position',f.last_position::text,'namespaceIds',f.namespace_ids) ORDER BY f.deployment_id)
   FROM dashboard_event_feeds f JOIN dashboard_source_identities i USING(deployment_id)),
 'retainedSHA256',encode(sha256(convert_to(json_build_object(
   'preferences',(SELECT coalesce(json_agg(row_to_json(x) ORDER BY account_id),'[]') FROM dashboard_preferences x),
   'rules',(SELECT coalesce(json_agg(row_to_json(x) ORDER BY id),'[]') FROM dashboard_notification_rules x),
   'reports',(SELECT coalesce(json_agg(row_to_json(x) ORDER BY id),'[]') FROM dashboard_report_tasks x)
 )::text,'UTF8')),'hex')); COMMIT;"""
    value = p.decode(sql(query,p.DATABASE))
    p.need(0 <= value['accounts'] <= 2 and 0 <= value['reports'] <= 4 and 0 <= value['rules'] <= 1 and
           value['inbox'] == value['devices'] == value['events'] == 0, 'install_acceptance_bounds')
    feeds = value['feeds'] or []
    p.need(len(feeds) == len(plan['configs']['api']['controls']), 'fresh_feed_count')
    for item in feeds:
        expected = next(c for c in plan['configs']['api']['controls'] if c['id'] == item['deploymentId'])
        p.need(item['status'] == 'active' and item['instance'] == expected['expectedInstanceId'] and
               item['epoch'] == '1' and set(item['namespaceIds']) == set(expected['namespaceIds']), 'fresh_feed_identity')
    return value


def stop(plan):
    root = begin(plan,'stop')
    # This path remains available after a failed transition, but only with exact
    # reviewed own-unit bytes and UID identity. It never retries an activation.
    for role in p.USERS:
        raw = f.read('/etc/systemd/system/'+p.UNITS[role]+'.service',0,0o644,32768)
        p.need(raw in [base64.b64decode(plan['units'][s][role]) for s in plan['units']], 'stop_unit_boundary')
        state = f.properties(p.UNITS[role])
        if state['MainPID'] != '0': p.need(Path('/proc',state['MainPID']).stat().st_uid == p.USERS[role][1], 'stop_owner_boundary')
    f.run(['systemctl','stop',*p.UNITS.values()], 'install_close_stop',timeout=100)
    f.run(['systemctl','disable',*p.UNITS.values()], 'install_close_disable',timeout=10)
    stopped()
    return finish(plan,root,'stop',{'stopped':True,'retained':True})


def observe(plan, phase, payload):
    root = operation(plan); p.need((root/(phase+'.pending.json')).exists(), 'phase_not_admitted')
    # Only a durable completed receipt is adopted. A partial SQL, file, client,
    # stop or start effect needs a separately reviewed forward recovery packet.
    value = p.decode(f.read(root/(phase+'.json')))
    p.need(value.get('completed') is True and value.get('phase') == phase and
           value.get('planSHA256') == p.sha(p.encoded(plan)), 'completion_receipt')
    if phase == 'stage':
        for selected in plan['candidates']: verify_release(plan,selected)
    elif phase in ('baseline','upgrade','rollback'):
        own_configuration(plan,value['selected']); ready(plan,value['selected'],5)
    elif phase in ('identity','retire-identity'):
        secret = verify_secrets(plan,payload['secrets'])['web'].decode()
        p.need(check_client(Identity(),secret,phase=='retire-identity') == value['clientId'], 'identity_receipt_drift')
    elif phase == 'database':
        p.need(sql("SELECT oid::text FROM pg_database WHERE datname='"+p.DATABASE+"'") == value['databaseOID'], 'database_receipt_drift')
    elif phase == 'install': own_configuration(plan,'baseline')
    elif phase == 'grants': p.need(p.sha(p.encoded(install_ledger())) == value['ledgerSHA256'], 'grants_receipt_drift')
    elif phase == 'stop': stopped()
    return value


def execute(payload):
    p.need(os.geteuid() == 0 and sys.platform == 'linux', 'linux_root_required')
    host = socket.gethostname().split('.')[0]; phase = payload['phase']
    p.need(host == payload['host'] and host in ('storage01','control01','pg01'), 'fixed_guest_host')
    with f.bounded(240 if phase in ('baseline','upgrade','rollback') else 150):
        if phase == 'prior-state':
            p.need(p.SCOPE in ('v1','v3'),'prior_state_scope');return retained_attempt(payload['previousAttempt'],host,False)
        if phase == 'snapshot':
            previous=payload.get('previousAttempt')
            if p.SCOPE!='v1': retained_attempt(previous,host)
            else: p.need(previous is None,'unexpected_previous_attempt')
            result=snapshot(host,payload['revision'])
            if previous: result['previousAttempt']=previous
            return result
        plan = payload['plan']; p.validate(plan)
        if phase == 'preserved': return preserved(plan,host)
        if phase == 'data': p.need(host == 'pg01','data_host'); return data_state(plan)
        if phase == 'empty-schema':
            p.need(host == 'pg01', 'empty_schema_host'); return empty_database()
        if phase == 'ledger':
            p.need(host == 'pg01', 'ledger_host'); value = install_ledger()
            p.need(value == plan['candidates']['baseline']['ledger'], 'fresh_ledger_drift')
            return {'ledgerSHA256': p.sha(p.encoded(value))}
        actual = payload.get('observedPhase') if phase == 'observe' else phase
        p.need(actual in p.PHASE_HOST and host == p.PHASE_HOST[actual], 'phase_host')
        preserved(plan,host)
        with locked():
            if phase == 'observe': return observe(plan,actual,payload)
            p.need(payload.get('apply') is True,'explicit_apply_required')
            if phase == 'stage': result = stage(plan,payload)
            elif phase in ('identity','retire-identity'): result = identity(plan,payload,phase=='retire-identity')
            elif phase == 'database': result = database(plan,payload)
            elif phase == 'install': result = install(plan,payload)
            elif phase == 'migrate': result = migrate(plan)
            elif phase == 'grants': result = grants(plan,payload)
            elif phase in ('baseline','upgrade','rollback'): result = activate(plan,phase)
            elif phase == 'stop': result = stop(plan)
            else: raise p.b.Failure('phase_denied')
        preserved(plan,host)
        return result
