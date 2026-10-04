#!/usr/bin/env python3
"""Fixed secondary-source guest phases; no Dashboard configuration mutations."""
import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import time

DB = 'jobman_dashboard_control_secondary'
ROOT = Path('/etc/jobman-dashboard-secondary')
CONTROL = ROOT / 'control'
DIRECTORY = ROOT / 'directory'
SPOOL = Path('/var/lib/jobman-dashboard-secondary/seed-logs')
BIN = Path('/usr/local/libexec/jobman-dashboard-secondary')
RECEIPTS = Path('/var/lib/jobman-dashboard-secondary-operator')
SOURCE_UNIT = 'jobman-dashboard-lab-control-secondary.service'
LDAP_UNIT = 'jobman-dashboard-lab-directory-secondary.service'
PRIMARY = Path('/etc/jobman-dashboard-lab/control-fixture')
PRIMARY_INSTANCE = 'e633cf92-258d-48ff-965a-fda88d68ef3a'
SOURCE_REVISION = 'd332a2b569333ae8aed9c2fc9ebc648d8eb5ba4e'
SOURCE_HASH = '38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e'
MIGRATION = '000021_monitoring_events.sql'
DEPLOYMENT = '72000000-0000-4000-8000-000000000002'
CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'
HEX = re.compile(r'[0-9a-f]{64}')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
LOG = b'SYNTHETIC Dashboard Lab log: metadata and byte delivery acceptance only.\n'


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'Duplicate JSON member')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def read(path, maximum=1 << 20, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= maximum, 'Expected bounded regular file')
        if private:
            need(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'Operator file is not private')
        raw = stream.read(maximum + 1)
        need(len(raw) == info.st_size, 'File changed while read')
        return raw


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def directory(path, mode=0o700):
    path.mkdir(mode=mode)
    need(path.resolve() == path, 'Directory alias refused')
    os.chmod(path, mode)
    sync(path.parent)


def private_directory(path):
    info = path.lstat()
    need(path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700, 'Expected private operator directory')


def put(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync(path.parent)


def run(args, raw=None, timeout=25):
    result = subprocess.run(args, input=raw, capture_output=True, timeout=timeout)
    need(result.returncode == 0 and len(result.stdout) <= 2 << 20,
         'Scoped command failed; retain receipts for inspection')
    return result.stdout


def sql(query, database='postgres'):
    need(database in ('postgres', 'jobman_dashboard_control', DB), 'Database outside source scope')
    return run(['podman', 'exec', '-i', 'jobman-postgres', 'psql', '-X', '-At', '-v',
                'ON_ERROR_STOP=1', '-U', 'jobman_control', '-d', database], query.encode()).decode().strip()


def hba_block():
    return (f'# BEGIN Dashboard secondary source\nlocal all {DB} reject\n'
            f'hostnossl all {DB} 0.0.0.0/0 reject\nhostnossl all {DB} ::0/0 reject\n'
            f'hostssl {DB} {DB} 10.77.0.0/24 scram-sha-256\n'
            f'hostssl {DB} {DB} 127.0.0.1/32 scram-sha-256\n'
            f'host all {DB} 0.0.0.0/0 reject\nhost all {DB} ::0/0 reject\n'
            '# END Dashboard secondary source\n').encode()


def database_sql(password):
    need(HEX.fullmatch(password), 'Synthetic password shape differs')
    return (f"CREATE ROLE {DB} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16 PASSWORD '{password}';\n"
            f'CREATE DATABASE {DB} OWNER {DB};\nREVOKE ALL ON DATABASE {DB} FROM PUBLIC;\n'
            f'\\connect {DB}\nREVOKE CREATE ON SCHEMA public FROM PUBLIC;\nALTER SCHEMA public OWNER TO {DB};\n')


def unit(directory_service=False):
    user = 'jobman-dashboard-directory2' if directory_service else 'jobman-dashboard-source2'
    command = (f'{BIN}/jobman-control-lab-helper directory --profile secondary-v1 --root {DIRECTORY}'
               if directory_service else f'{BIN}/jobman-control')
    environment = '' if directory_service else f'EnvironmentFile={CONTROL}/control.env\n'
    return (f'[Unit]\nDescription=Synthetic secondary Dashboard {"LDAP" if directory_service else "Control"}\n'
            'After=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\n'
            f'User={user}\nGroup={user}\n{environment}ExecStart={command}\n'
            'Restart=on-failure\nRestartSec=3\nUMask=0077\nNoNewPrivileges=true\n'
            'PrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n'
            'CapabilityBoundingSet=\nRestrictSUIDSGID=true\n\n[Install]\nWantedBy=multi-user.target\n').encode()


def verify_plan(payload):
    plan = payload['plan']
    need(HEX.fullmatch(payload['planSHA256']) and sha(encoded(plan)) == payload['planSHA256'], 'Plan digest differs')
    source, secondary = plan['sourceBuild'], plan['secondary']
    need(plan['synthetic'] is True and plan['formatVersion'] == 1 and plan['applySupported'] is False and
         source['revision'] == SOURCE_REVISION and source['sha256'] == SOURCE_HASH and source['migration'] == MIGRATION and
         plan['primary']['instanceId'] == PRIMARY_INSTANCE and secondary['deploymentId'] == DEPLOYMENT and
         secondary['database'] == DB and secondary['databaseRole'] == DB and secondary['schema'] == 'public' and
         secondary['endpoint'] == 'https://10.77.0.21:28443' and secondary['controlRoot'] == str(CONTROL) and
         secondary['directoryRoot'] == str(DIRECTORY) and secondary['spoolRoot'] == str(SPOOL) and
         secondary['controlUser'] == {'name': 'jobman-dashboard-source2', 'uid': 21907, 'gid': 21907} and
         secondary['directoryUser'] == {'name': 'jobman-dashboard-directory2', 'uid': 21908, 'gid': 21908},
         'Fixed secondary-source plan differs')
    build = payload['helperBuild']
    need(re.fullmatch('[0-9a-f]{40}', build['revision']) and HEX.fullmatch(build['sha256']) and
         build['platform'] == 'linux/arm64' and build['toolchain'] == 'go1.26.6', 'Helper build identity differs')
    need(set(payload['implementationSHA256']) == {'apply-dashboard-second-source.py', 'dashboard-second-source-guest.py', 'dashboard-second-source-plan.py', 'continue-dashboard-second-source.py'} and
         all(HEX.fullmatch(v) for v in payload['implementationSHA256'].values()), 'Apply implementation identity differs')
    keys = ['planSHA256', 'helperBuild', 'implementationSHA256']
    if 'continuation' in payload:
        prior = payload['continuation']
        need(prior.get('priorExecutionId') == 'd87f4b43ba6cb4d503f09e3cf4738795f52550c04623bfeeb8c4bce2f5f93331' and
             prior.get('priorPlanSHA256') == 'ae19480a6f6e79bc2fa144b1a383af0087df353ea86ad001a7ffcedde1f2cc2d', 'Unrecognized prior failure')
        keys.append('continuation')
    return sha(encoded({key: payload[key] for key in keys}))


def source_snapshot():
    source = decode(read(Path('/usr/local/libexec/jobman-dashboard-lab/source-current.json')))
    need(source['revision'] == SOURCE_REVISION, 'Primary source revision changed')
    need(sha(read(Path('/usr/local/libexec/jobman-dashboard-lab/jobman-control'), 64 << 20)) == SOURCE_HASH,
         'Primary source executable changed')
    info = decode(read(PRIMARY / 'fixture-info.json'))
    need(info['instanceId'] == PRIMARY_INSTANCE and info['synthetic'] is True, 'Primary fixture changed')
    need(not list(PRIMARY.glob('.directory-acceptance-*.json')) and
         not list(PRIMARY.glob('*.pending')) and not (PRIMARY / '.diagnostic-prepare.json').exists(),
         'Primary fixture recovery requires inspection')
    processes = {}
    for name in ('jobman-control', 'jobman-dashboard-lab-control', 'jobman-dashboard-lab-directory', 'jobman-keycloak'):
        run(['systemctl', 'is-active', '--quiet', name])
        processes[name] = run(['systemctl', 'show', name, '--property=ExecMainStartTimestampMonotonic', '--value']).decode().strip()
    files = {name: sha(read(PRIMARY / name)) for name in ('control.env', 'delegation.json', 'directory.json', 'fixture-info.json')}
    return {'processes': processes, 'files': files}


def database_snapshot():
    need(sql("SELECT current_setting('ssl')='on' AND NOT EXISTS(SELECT FROM pg_hba_file_rules WHERE error IS NOT NULL)") == 't', 'PostgreSQL TLS/HBA is not ready')
    need(sql('SELECT id::text FROM control_instance', 'jobman_dashboard_control') == PRIMARY_INSTANCE and
         sql('SELECT max(version) FROM schema_migrations', 'jobman_dashboard_control') == MIGRATION,
         'Primary source database differs')
    return {'primaryInstance': PRIMARY_INSTANCE, 'primaryMigration': MIGRATION,
            'hbaSHA256': sha(run(['podman', 'exec', 'jobman-postgres', 'cat', '/var/lib/postgresql/data/pg_hba.conf']))}


def unused_control():
    for uid, name in ((21907, 'jobman-dashboard-source2'), (21908, 'jobman-dashboard-directory2')):
        need(re.fullmatch(r'[a-z][a-z0-9-]{0,31}', name), 'Identity name exceeds Linux bounds')
        for lookup, value in ((pwd.getpwuid, uid), (pwd.getpwnam, name), (grp.getgrgid, uid), (grp.getgrnam, name)):
            try:
                lookup(value)
            except KeyError:
                continue
            raise ValueError('Reserved secondary identity is already used')
    for path in (ROOT, SPOOL.parent, BIN, Path('/data/jobman/alice/dashboard-secondary')):
        # Root is squashed on NFS, so inspect its planned subtree as Alice below.
        if str(path).startswith('/data/'):
            run(['runuser', '-u', 'alice', '--', 'test', '!', '-e', str(path)])
        else:
            need(not path.exists() and not path.is_symlink(), 'Secondary path already exists')
    listeners = run(['ss', '-H', '-lnt']).decode()
    need(not re.search(r':(?:28443|28636)\s', listeners), 'Secondary listener already used')
    for name in (SOURCE_UNIT, LDAP_UNIT):
        need(not (Path('/etc/systemd/system') / name).exists(), 'Secondary unit already exists')


def begin(payload, name):
    if not RECEIPTS.exists():
        directory(RECEIPTS)
    private_directory(RECEIPTS)
    root = RECEIPTS / payload['executionId']
    if not root.exists():
        directory(root)
    private_directory(root)
    completed, pending = root / (name + '.json'), root / (name + '.pending.json')
    if completed.exists():
        need(not pending.exists(), 'Completed phase retains a pending operation')
        return root, decode(read(completed, private=True))
    need(not pending.exists(), 'Incomplete phase requires operator inspection; no automatic retry')
    put(pending, encoded({'executionId': payload['executionId'], 'phase': name, 'startedAt': int(time.time())}))
    return root, None


def finish(root, name, result):
    put(root / (name + '.json'), encoded(result))
    (root / (name + '.pending.json')).unlink()
    sync(root)
    return result


def require_primary(payload, host):
    actual = source_snapshot() if host == 'control01' else database_snapshot()
    expected = payload['preflight'][host]['snapshot']
    if host == 'pg01':
        actual.pop('hbaSHA256')
        expected = {k: v for k, v in expected.items() if k != 'hbaSHA256'}
    need(actual == expected, 'Original source or services changed since preflight')


def database_phase(payload):
    require_primary(payload, 'pg01')
    root, completed = begin(payload, 'database')
    hba_path = '/var/lib/postgresql/data/pg_hba.conf'
    current = run(['podman', 'exec', 'jobman-postgres', 'cat', hba_path])
    if completed:
        need(sha(current) == completed['hbaSHA256'] and
             sql(f"SELECT r.rolname FROM pg_database d JOIN pg_roles r ON d.datdba=r.oid WHERE d.datname='{DB}'") == DB,
             'Completed database phase changed')
        return completed
    need(sha(current) == payload['preflight']['pg01']['snapshot']['hbaSHA256'], 'HBA changed since preflight')
    need(sql(f"SELECT (SELECT count(*) FROM pg_roles WHERE rolname='{DB}')+(SELECT count(*) FROM pg_database WHERE datname='{DB}')") == '0', 'Secondary database/role already exists')
    put(root / 'pg_hba.before', current)
    put(root / 'pg_hba.after', hba_block() + current)
    sql(database_sql(payload['password']))
    run(['podman', 'cp', str(root / 'pg_hba.after'), 'jobman-postgres:' + hba_path])
    run(['podman', 'exec', '--user', 'root', 'jobman-postgres', 'chown', 'postgres:postgres', hba_path])
    need(sql('SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL') == '0', 'New HBA does not parse')
    need(sql('SELECT pg_reload_conf()') == 't', 'HBA reload failed')
    return finish(root, 'database', {'database': DB, 'hbaSHA256': sha(hba_block() + current), 'originalsPreserved': True})


def public_fixture(value, plan):
    secondary = plan['secondary']
    need(value.get('synthetic') is True and value.get('profile') == 'secondary-v1' and
         value.get('endpoint') == secondary['endpoint'] and value.get('issuer') == secondary['issuer'] and
         value.get('delegationAudience') == secondary['delegationAudience'] and
         UUID.fullmatch(value.get('instanceId', '')) and value['instanceId'] != PRIMARY_INSTANCE,
         'Secondary public fixture identity differs')
    scopes = value.get('namespaces', [])
    need(len(scopes) == 2 and {n['name'] for n in scopes} == {'dashboard-research', 'dashboard-operations'} and
         len({n['id'] for n in scopes}) == 2 and all(UUID.fullmatch(n['id']) and UUID.fullmatch(n['targetGenerationId']) for n in scopes),
         'Secondary namespace identity differs')
    identities = value.get('identities', [])
    need(len(identities) == 2 and len({i['principalId'] for i in identities}) == 2, 'Secondary principal set differs')
    for identity, user in zip(identities, secondary['users']):
        need(UUID.fullmatch(identity['principalId']) and identity['directoryId'] == user['directoryId'] and
             identity['subject'] == user['subject'] and identity['issuer'] == secondary['issuer'], 'Secondary signed alias differs')
    return value


def private_tree(path, uid):
    count = 0
    for current, dirs, files in os.walk(path, followlinks=False):
        for item in [Path(current)] + [Path(current) / name for name in files]:
            info = item.lstat()
            need(not stat.S_ISLNK(info.st_mode) and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'Unexpected fixture node')
            need(stat.S_IMODE(info.st_mode) == (0o700 if item.is_dir() else 0o600), 'Private fixture mode differs')
            os.chown(item, uid, uid)
            count += 1
            need(count <= 64, 'Private fixture tree exceeds bound')
        need(all(not (Path(current) / name).is_symlink() for name in dirs), 'Fixture directory symlink')


def log_objects(info):
    objects = []
    for current, dirs, files in os.walk(SPOOL, followlinks=False):
        need(all(not (Path(current) / name).is_symlink() for name in dirs), 'Synthetic spool symlink')
        for name in files:
            path = Path(current) / name
            key = path.relative_to(SPOOL).as_posix()
            match = re.fullmatch(r'namespaces/(dashboard-research|dashboard-operations)/jobs/([0-9a-f-]{36})/executions/([0-9a-f-]{36})/logs/(stdout|stderr)/(00000001|00000002)\.chunk', key)
            need(match and UUID.fullmatch(match[2]) and UUID.fullmatch(match[3]), 'Unexpected synthetic log key')
            scope = next(n for n in info['namespaces'] if n['name'] == match[1])
            need(match[2] in scope['jobIds'][:3], 'Log outside seeded execution jobs')
            raw = read(path, 4096)
            need(raw in (b'', LOG), 'Unexpected synthetic log bytes')
            objects.append({'key': key, 'length': len(raw), 'sha256': sha(raw), 'data': base64.b64encode(raw).decode()})
            need(len(objects) <= 12, 'Synthetic object bound exceeded')
    need(len(objects) == 12 and sum(bool(v['length']) for v in objects) == 2, 'Incomplete synthetic spool')
    return sorted(objects, key=lambda value: value['key'])


def publish_logs(objects):
    program = r'''import base64,hashlib,json,os,stat,sys
from pathlib import Path
assert os.geteuid()==21001
root=Path('/data/jobman/alice/dashboard-secondary');assert not root.exists() and not root.is_symlink()
root.mkdir(mode=0o750)
for item in json.load(sys.stdin):
 parts=Path(item['key']).parts;assert not Path(item['key']).is_absolute() and '..' not in parts
 current=root
 for part in parts[:-1]:
  current=current/part
  if not current.exists():current.mkdir(mode=0o750)
  assert not current.is_symlink() and current.is_dir()
 raw=base64.b64decode(item['data'],validate=True);assert len(raw)==item['length'] and hashlib.sha256(raw).hexdigest()==item['sha256']
 fd=os.open(current/parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
'''
    run(['runuser', '-u', 'alice', '--', 'python3', '-c', program], encoded(objects))
    verify_logs(objects)


def verify_logs(objects):
    need(len(objects) == 12 and all(re.fullmatch(r'namespaces/(dashboard-research|dashboard-operations)/jobs/[0-9a-f-]{36}/executions/[0-9a-f-]{36}/logs/(stdout|stderr)/(00000001|00000002)\.chunk', item['key']) and
         type(item['length']) is int and 0 <= item['length'] <= 4096 and HEX.fullmatch(item['sha256']) for item in objects), 'Log verification bounds differ')
    program = r'''import hashlib,json,os,stat,sys
from pathlib import Path
root=Path('/data/jobman/alice/dashboard-secondary')
def exact(item):
 fd=os.open('/',os.O_PATH|os.O_DIRECTORY)
 try:
  parts=(root/item['key']).parts[1:]
  for part in parts[:-1]:
   child=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
  file=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
  with os.fdopen(file,'rb') as stream:
   info=os.fstat(stream.fileno());assert stat.S_ISREG(info.st_mode) and info.st_uid==21001 and info.st_size==item['length']
   return stream.read(4097)
 finally:os.close(fd)
for item in json.load(sys.stdin):
 try:raw=exact(item)
 except PermissionError:
  assert os.geteuid()==21002;continue
 assert os.geteuid()==21901 and len(raw)==item['length'] and hashlib.sha256(raw).hexdigest()==item['sha256']
'''
    for user in ('jobman-dashboard-log', 'bob'):
        run(['runuser', '-u', user, '--', 'python3', '-c', program], encoded(objects))


def prepare_phase(payload):
    need(HEX.fullmatch(payload['password']), 'Synthetic credential shape differs')
    binaries = {}
    for name, expected in (('jobman-control', SOURCE_HASH), ('jobman-control-lab-helper', payload['helperBuild']['sha256'])):
        raw = base64.b64decode(payload['binaries'][name], validate=True)
        need(len(raw) <= 64 << 20 and raw[:6] == b'\x7fELF\x02\x01' and raw[18:20] == b'\xb7\x00' and sha(raw) == expected, 'Staged executable differs')
        binaries[name] = raw
    require_primary(payload, 'control01')
    root, completed = begin(payload, 'prepare')
    if completed:
        verify_prepared(completed)
        return completed
    unused_control()
    for uid, name in ((21907, 'jobman-dashboard-source2'), (21908, 'jobman-dashboard-directory2')):
        run(['groupadd', '--gid', str(uid), name])
        run(['useradd', '--system', '--uid', str(uid), '--gid', str(uid), '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', name])
    for path in (ROOT, CONTROL, DIRECTORY, SPOOL.parent, SPOOL, BIN):
        directory(path, 0o755 if path == BIN else 0o700)
    need(HEX.fullmatch(payload['password']), 'Synthetic credential shape differs')
    put(ROOT / 'control-database-url', f'postgres://{DB}:{payload["password"]}@10.77.0.20:5432/{DB}?sslmode=verify-full&sslrootcert={CA}\n'.encode())
    input_value = {k: payload['plan']['secondary'][k] for k in ('issuer', 'audience', 'users')}
    input_value['host'] = '10.77.0.21'
    put(ROOT / 'fixture-input.json', encoded(input_value))
    for name, raw in binaries.items():
        put(BIN / name, raw, 0o755)
    run([str(BIN / 'jobman-control-lab-helper'), 'prepare', '--profile', 'secondary-v1', '--root', str(CONTROL),
         '--directory-root', str(DIRECTORY), '--config', str(ROOT / 'fixture-input.json'),
         '--database-url-file', str(ROOT / 'control-database-url'), '--log-root', str(SPOOL)], timeout=125)
    info = public_fixture(decode(read(CONTROL / 'fixture-info.json')), payload['plan'])
    need(sha(read(CONTROL / 'fixture-ca.crt')) != sha(read(PRIMARY / 'fixture-ca.crt')), 'Secondary trust reused the primary CA')
    primary = decode(read(PRIMARY / 'fixture-info.json'))
    need(not {n['id'] for n in info['namespaces']} & {n['id'] for n in primary['namespaces']} and
         not {p['principalId'] for p in info['identities']} & {p['principalId'] for p in primary['identities']}, 'Generated source identities collide')
    objects = log_objects(info)
    publish_logs(objects)
    private_tree(CONTROL, 21907)
    private_tree(DIRECTORY, 21908)
    run(['setfacl', '-n', '-m', 'u:21907:--x,u:21908:--x,g::---,m::--x,o::---', str(ROOT)])
    for name, raw in ((SOURCE_UNIT, unit()), (LDAP_UNIT, unit(True))):
        put(Path('/etc/systemd/system') / name, raw, 0o644)
    for user, allowed, denied in (
            ('jobman-dashboard-source2', CONTROL / 'control.env', DIRECTORY / 'directory-server.key'),
            ('jobman-dashboard-directory2', DIRECTORY / 'directory-server.key', CONTROL / 'control.env')):
        run(['runuser', '-u', user, '--', 'test', '-r', str(allowed)])
        run(['runuser', '-u', user, '--', 'test', '!', '-r', str(denied)])
        run(['runuser', '-u', user, '--', 'test', '!', '-r', str(ROOT / 'control-database-url')])
    paths = list(CONTROL.iterdir()) + list(DIRECTORY.iterdir()) + [BIN / 'jobman-control', BIN / 'jobman-control-lab-helper',
             ROOT / 'control-database-url', ROOT / 'fixture-input.json',
             Path('/etc/systemd/system') / SOURCE_UNIT, Path('/etc/systemd/system') / LDAP_UNIT]
    files = {}
    for path in paths:
        info_stat = path.lstat()
        files[str(path)] = {'sha256': sha(read(path, 64 << 20)), 'uid': info_stat.st_uid, 'gid': info_stat.st_gid,
                            'mode': stat.S_IMODE(info_stat.st_mode)}
    result = {'fixture': info, 'files': files, 'objects': [{k: v for k, v in o.items() if k != 'data'} for o in objects],
              'sourceBuild': payload['plan']['sourceBuild'], 'helperBuild': payload['helperBuild'], 'servicesStarted': False}
    require_primary(payload, 'control01')
    return finish(root, 'prepare', result)


def verify_prepared(value):
    need(20 <= len(value['files']) <= 64 and len(value['objects']) == 12, 'Prepared receipt bounds differ')
    for name, recorded in value['files'].items():
        path = Path(name)
        allowed = path in (BIN / 'jobman-control', BIN / 'jobman-control-lab-helper', ROOT / 'control-database-url',
                           ROOT / 'fixture-input.json', Path('/etc/systemd/system') / SOURCE_UNIT,
                           Path('/etc/systemd/system') / LDAP_UNIT) or path.parent in (CONTROL, DIRECTORY)
        need(allowed and path.parent.resolve() == path.parent and sha(read(path, 64 << 20)) == recorded['sha256'],
             'Prepared source file changed')
        info = path.lstat()
        need((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
             (recorded['uid'], recorded['gid'], recorded['mode']), 'Prepared source ownership changed')
    verify_logs(value['objects'])


def verify_running(payload, prepared):
    for name, uid, executable in ((SOURCE_UNIT, 21907, BIN / 'jobman-control'), (LDAP_UNIT, 21908, BIN / 'jobman-control-lab-helper')):
        pid = run(['systemctl', 'show', name, '--property=MainPID', '--value']).decode().strip()
        need(pid.isdigit() and int(pid) > 0 and Path('/proc', pid).stat().st_uid == uid and
             os.readlink('/proc/' + pid + '/exe') == str(executable), 'Secondary process identity differs')
    for name in (SOURCE_UNIT, LDAP_UNIT):
        run(['systemctl', 'is-active', '--quiet', name])
    ready = False
    for _ in range(10):
        result = subprocess.run(['runuser', '-u', 'jobman-dashboard-source2', '--', 'curl', '--silent', '--fail', '--max-time', '3',
                                 '--cacert', str(CONTROL / 'fixture-ca.crt'), 'https://127.0.0.1:28443/v1/capabilities'], capture_output=True, timeout=5)
        if result.returncode == 0 and len(result.stdout) < 65536:
            value = decode(result.stdout).get('capabilities', {})
            if value.get('instanceId') == prepared['fixture']['instanceId'] and value.get('recoveryEpoch') == '1':
                ready = True
                break
        time.sleep(1)
    need(ready, 'Secondary source TLS/instance readiness failed')
    require_primary(payload, 'control01')


def start_phase(payload):
    require_primary(payload, 'control01')
    prepared = decode(read(RECEIPTS / payload['executionId'] / 'prepare.json', private=True))
    verify_prepared(prepared)
    root, completed = begin(payload, 'start')
    if not completed:
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', LDAP_UNIT, SOURCE_UNIT])
    verify_running(payload, prepared)
    if completed:
        return completed
    return finish(root, 'start', {'instanceId': prepared['fixture']['instanceId'], 'sourceBuild': prepared['sourceBuild'],
                                  'helperBuild': prepared['helperBuild'], 'originalsPreserved': True, 'dashboardRegistered': False})


def verify_phase(payload):
    root = RECEIPTS / payload['executionId']
    private_directory(root)
    need(not (root / 'start.pending.json').exists(), 'Start needs private operator inspection')
    completed = decode(read(root / 'start.json', private=True))
    prepared = decode(read(root / 'prepare.json', private=True))
    verify_prepared(prepared)
    verify_running(payload, prepared)
    return completed



def fresh_database_query():
    # A fresh PG17 template has public plus only system schemas and plpgsql.
    # Relations alone miss function/type-only drift under the new DB owner.
    return """SELECT
      (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') +
      (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public') +
      (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public') +
      (SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('public','pg_catalog','information_schema')
       AND nspname !~ '^pg_(toast|temp)(_[0-9]+|_temp_[0-9]+)?$') +
      (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql')"""


def continuation_preflight(payload, host):
    prior = payload['continuation']
    root = RECEIPTS / prior['priorExecutionId']
    private_directory(root)
    snapshot = source_snapshot() if host == 'control01' else database_snapshot()
    expected = prior['priorPreflight'][host]['snapshot']
    if host == 'pg01':
        need(not (root / 'database.pending.json').exists(), 'Prior database is incomplete')
        completed = decode(read(root / 'database.json', private=True))
        need(completed == prior['priorDatabase'] and snapshot['hbaSHA256'] == completed['hbaSHA256'], 'Prior database/HBA receipt changed')
        need({k: v for k, v in snapshot.items() if k != 'hbaSHA256'} ==
             {k: v for k, v in expected.items() if k != 'hbaSHA256'}, 'Primary database changed')
        need(sql(f"SELECT r.rolname FROM pg_database d JOIN pg_roles r ON d.datdba=r.oid WHERE d.datname='{DB}'") == DB,
             'Secondary database owner changed')
        need(sql(fresh_database_query(), DB) == '0',
             'Secondary schema is no longer fresh')
    else:
        need(snapshot == expected, 'Original source/process snapshot changed')
        need(not any((root / name).exists() for name in ('prepare.json', 'start.json', 'start.pending.json')), 'Prior preparation progressed')
        pending = decode(read(root / 'prepare.pending.json', private=True))
        need(set(pending) == {'executionId', 'phase', 'startedAt'} and pending['executionId'] == prior['priorExecutionId'] and
             pending['phase'] == 'prepare' and type(pending['startedAt']) is int, 'Prior pending record differs')
        unused_control()
        for name in ('jobman-dashboard-source-secondary', 'jobman-dashboard-directory-secondary'):
            for lookup in (pwd.getpwnam, grp.getgrnam):
                try: lookup(name)
                except KeyError: continue
                raise ValueError('Unexpected partial legacy identity exists')
    return {'epoch': int(time.time()), 'snapshot': snapshot, 'mutatedGuests': False,
            'priorExecutionId': prior['priorExecutionId']}

def dispatch(payload):
    expected_id = verify_plan(payload)
    need(payload['executionId'] == expected_id and os.geteuid() == 0 and sys.platform == 'linux' and
         socket.gethostname().split('.')[0] == payload['host'], 'Guest identity or execution boundary differs')
    phase, host = payload['phase'], payload['host']
    need(host in ('pg01', 'control01') and phase in ('preflight', 'database', 'prepare', 'start', 'verify', 'continuation_preflight'), 'Unlisted guest phase')
    need('continuation' not in payload or phase not in ('preflight', 'database'), 'Continuation cannot recreate completed database')
    if phase == 'continuation_preflight':
        return continuation_preflight(payload, host)
    if phase == 'preflight':
        if host == 'control01':
            snapshot = source_snapshot()
            unused_control()
        else:
            snapshot = database_snapshot()
            need(sql(f"SELECT (SELECT count(*) FROM pg_roles WHERE rolname='{DB}')+(SELECT count(*) FROM pg_database WHERE datname='{DB}')") == '0', 'Secondary role/database already exists')
        return {'epoch': int(time.time()), 'snapshot': snapshot, 'mutatedGuests': False}
    if phase == 'verify' and host == 'control01':
        return verify_phase(payload)
    need(payload.get('apply') is True and set(payload['preflight']) == {'pg01', 'control01'}, 'Apply and exact preflight required')
    need(0 <= int(time.time()) - min(v['epoch'] for v in payload['preflight'].values()) <= 3600, 'Preflight exceeds one hour')
    if phase == 'database' and host == 'pg01':
        return database_phase(payload)
    if phase == 'prepare' and host == 'control01':
        return prepare_phase(payload)
    if phase == 'start' and host == 'control01':
        return start_phase(payload)
    raise ValueError('Wrong guest for phase')


if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read((192 << 20) + 1)
        need(len(raw) <= 192 << 20, 'Guest payload exceeds limit')
        print(encoded(dispatch(decode(raw))).decode(), end='')
    except Exception:
        print('Secondary-source phase failed; preserve private receipts and inspect the scoped state. No automatic reset or rollback.', file=sys.stderr)
        sys.exit(1)
