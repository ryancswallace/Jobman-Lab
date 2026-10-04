#!/usr/bin/env python3
"""Explicit receipt-bound multi-source phases; defaults to read-only preflight."""
import argparse
import base64
from datetime import datetime
from contextlib import contextmanager
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

plan = load('dashboard-multisource-plan')
r = load('dashboard-multisource-runtime')
FILES = ('apply-dashboard-multisource.py', 'dashboard-multisource-guest.py', 'dashboard-multisource-runtime.py', 'dashboard-multisource-plan.py', 'continue-dashboard-multisource.py')
PHASES = ('preflight', 'materials', 'install', 'apply', 'restart', 'verify')
ROLES = ('broker', 'api', 'worker')
PRIOR_IMPLEMENTATION = 'c993dcc1b92bf404def903f211862b406c41b3cdbbc4680ee2bcedea1fe82f35'
PRIOR_EXECUTION = '1bb641283d575e6df8003c6a5034e67254baae0957309def1d9393702140305b'


def private_directory(path):
    info = path.lstat()
    r.need(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private_host_directory')


def read(path, maximum=2 << 20):
    r.need(path.is_absolute() and path.parent.resolve() == path.parent, 'host_path_alias')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        a = os.fstat(stream.fileno())
        r.need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == os.getuid() and stat.S_IMODE(a.st_mode) == 0o600 and 0 < a.st_size <= maximum, 'private_host_file')
        raw = stream.read(maximum + 1); b = os.fstat(stream.fileno()); c = path.lstat()
        r.need(len(raw) == a.st_size and (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns) and (c.st_dev, c.st_ino) == (a.st_dev, a.st_ino), 'host_file_changed')
        return raw


def source_bytes(name):
    path = HERE / name
    r.need(name in FILES and path.resolve() == path, 'implementation_path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        a = os.fstat(stream.fileno())
        r.need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == os.getuid() and stat.S_IMODE(a.st_mode) & 0o022 == 0 and 0 < a.st_size <= 1 << 20, 'implementation_identity')
        raw = stream.read((1 << 20) + 1); b = os.fstat(stream.fileno()); c = path.lstat()
        r.need(len(raw) == a.st_size and (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns) and (c.st_dev, c.st_ino) == (a.st_dev, a.st_ino), 'implementation_changed')
        return raw


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    r.sync(path.parent)


def receipt(path, value):
    raw = r.encoded(value)
    if path.exists(): r.need(read(path) == raw, 'retained_host_receipt_changed')
    else: write(path, raw)


@contextmanager
def locked(staging):
    path = staging / '.apply.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.fchmod(fd, 0o600)
    except FileExistsError: fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        r.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, 'host_lock_identity')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); yield
    finally: os.close(fd)


def prepared(args):
    private_directory(args.staging)
    r.need(args.lab_root.is_absolute() and args.lab_root.resolve() == args.lab_root, 'lab_root_alias')
    raw = read(args.staging / 'review.json'); review = plan.decode(raw)
    r.need(re.fullmatch('[0-9a-f]{64}', args.expected_review_sha256) and r.sha(raw) == args.expected_review_sha256, 'review_digest')
    implementation = {name: r.sha(source_bytes(name)) for name in FILES}
    r.need(re.fullmatch('[0-9a-f]{64}', args.expected_implementation_sha256) and r.sha(r.encoded(implementation)) == args.expected_implementation_sha256, 'implementation_digest')
    prepared_raw = read(args.secondary_prepare_receipt)
    r.need(re.fullmatch('[0-9a-f]{64}', args.expected_prepare_sha256) and r.sha(prepared_raw) == args.expected_prepare_sha256, 'secondary_receipt_digest')
    source = plan.decode(prepared_raw); fixture = source['fixture']
    file = source['files'][plan.SOURCE_ROOT + '/fixture-info.json']
    r.need(file['sha256'] == review['fixtureSHA256'] and file['uid'] == file['gid'] == 21907 and file['mode'] == 0o600, 'secondary_fixture_receipt')
    fixture_raw = read(args.secondary_fixture)
    r.need(r.sha(fixture_raw) == review['fixtureSHA256'] and plan.decode(fixture_raw) == fixture, 'secondary_fixture_bytes')
    before = {role: read(args.staging / (role + '.before.json')) for role in (*ROLES, 'operator')}
    expected = plan.patch({role: plan.decode(raw) for role, raw in before.items()}, fixture)
    after = {role: read(args.staging / (role + '.after.json')) for role in before}
    r.need(review['synthetic'] is True and review['applies'] is False and len(review['files']) == 4 and {item['role'] for item in review['files']} == set(before), 'review_scope')
    for item in review['files']:
        role = item['role']
        r.need(item['beforeSHA256'] == r.sha(before[role]) and item['afterSHA256'] == r.sha(after[role]) and after[role] == r.encoded(expected[role]) and item['path'] == plan.ROOTS[role] + '/config.json', 'review_config_delta')
    previous = getattr(args, 'continue_from_implementation', None)
    r.need(previous is None or previous == PRIOR_IMPLEMENTATION, 'continuation_predecessor')
    execution = r.sha(r.encoded({'reviewSHA256': args.expected_review_sha256, 'implementationSHA256': previous or args.expected_implementation_sha256, 'secondaryPrepareSHA256': args.expected_prepare_sha256}))
    r.need(previous is None or execution == PRIOR_EXECUTION, 'continuation_execution')
    return {'review': review, 'reviewSHA256': args.expected_review_sha256, 'implementationSHA256': args.expected_implementation_sha256, 'executionId': execution,
            'previousImplementationSHA256': previous, 'preparedSource': source, 'fixture': fixture, 'fixtureBytes': base64.b64encode(fixture_raw).decode(),
            'before': {role: base64.b64encode(raw).decode() for role, raw in before.items()}, 'after': {role: base64.b64encode(raw).decode() for role, raw in after.items()}}, implementation


def ssh_args(lab, host):
    r.need(host in ('pg01', 'control01', 'storage01'), 'ssh_host_boundary')
    inventory = plan.decode(read(lab / '.lab/dashboard/ssh-connections.json', 65536)); c = inventory[host]
    ip = ipaddress.ip_address(c['ansible_host'])
    r.need(c['ansible_user'] == 'vagrant' and type(c['ansible_port']) is int and 1 <= c['ansible_port'] <= 65535 and Path(c['ansible_ssh_private_key_file']).is_absolute() and (str(ip) in ('127.0.0.1', '10.77.0.10', '10.77.0.20', '10.77.0.21') or ip in ipaddress.ip_network('10.211.55.0/24')), 'pinned_ssh_inventory')
    return ['ssh', '-i', c['ansible_ssh_private_key_file'], '-p', str(c['ansible_port']), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(lab / '.lab/dashboard/known_hosts'), '-o', 'HostKeyAlgorithms=ssh-ed25519', c['ansible_user'] + '@' + str(ip)]


def remote(lab, p):
    # Code comes from the reviewed archive, never from a guest path or arbitrary input.
    sources = {name: source_bytes(name).decode() for name in ('dashboard-multisource-plan.py', 'dashboard-multisource-runtime.py', 'dashboard-multisource-guest.py')}
    script = '''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((4<<20)+1)
 if len(raw)>4<<20:raise ValueError()
 payload=json.loads(raw); sources=payload.pop('_sources'); hashes=payload.pop('_hashes')
 if set(sources)!={'dashboard-multisource-plan.py','dashboard-multisource-runtime.py','dashboard-multisource-guest.py'}:raise ValueError()
 for name,source in sources.items():
  if hashlib.sha256(source.encode()).hexdigest()!=hashes[name]:raise ValueError()
 modules={}
 for name in ('runtime','plan'):
  filename='dashboard-multisource-'+name+'.py';module=types.ModuleType(name);exec(compile(sources[filename],filename,'exec'),module.__dict__);modules[name]=module
 namespace={'__name__':'reviewed_guest',**modules};exec(compile(sources['dashboard-multisource-guest.py'],'dashboard-multisource-guest.py','exec'),namespace)
 result=namespace['execute'](payload);print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','guest_phase_failed')
 print(json.dumps({'ok':False,'code':code},sort_keys=True));sys.exit(0)
'''
    body = dict(p, _sources=sources, _hashes={name: r.sha(value.encode()) for name, value in sources.items()})
    output = r.run(ssh_args(lab, p['host']) + [shlex.join(['sudo', 'python3', '-c', script])], 'ssh_' + p['host'] + '_' + p['phase'], input_data=r.encoded(body), timeout=150, maximum=2 << 20)
    result = plan.decode(output)
    if result.get('ok') is not True:
        code = result.get('code', 'guest_phase_failed'); r.need(isinstance(code, str) and r.CODE.fullmatch(code), 'guest_invalid_failure_code'); raise r.Failure(p['phase'] + '_' + code if len(p['phase'] + '_' + code) <= 64 else code)
    return result['result']


def db_validate(value, *, before=None, namespace_sets=None, now=None):
    r.need(value['hold']['held'] is False and value['hold']['generation'] == 3 and value['unfinishedRecoveries'] == value['openGaps'] == 0, 'delivery_hold_or_recovery_changed')
    second = value['secondary']
    r.need(second == {'database': 'jobman_dashboard_control_secondary', 'instanceId': plan.SECONDARY_INSTANCE, 'epoch': '1', 'migration': '000021_monitoring_events.sql', 'freshNamespaceProofs': 2}, 'secondary_database_identity_or_proof')
    expected = {plan.PRIMARY} if before is None else {plan.PRIMARY, plan.SECONDARY}
    r.need({v['deploymentId'] for v in value['identities']} == expected and len(value['identities']) == len(expected), 'source_registry_members')
    r.need({v['deploymentId'] for v in value['feeds']} == expected and len(value['feeds']) == len(expected), 'feed_registry_members')
    for row in value['identities']:
        r.need(row['instanceId'] == (plan.PRIMARY_INSTANCE if row['deploymentId'] == plan.PRIMARY else plan.SECONDARY_INSTANCE) and row['epoch'] == '1' and row['revision'] == (6 if before is None else 7), 'source_registry_fence')
    for row in value['feeds']:
        r.need(row['status'] == 'active' and row['lastError'] == '' and row['generation'] > 0 and row['lastPosition'] >= 0 and row['lastSuccessAt'] is not None, 'feed_not_active')
        if namespace_sets is not None:
            r.need(sorted(row['namespaces']) == sorted(namespace_sets[row['deploymentId']]), 'feed_namespace_fence')
        if now is not None:
            at = datetime.fromisoformat(row['lastSuccessAt'].replace('Z', '+00:00'))
            r.need(at.tzinfo is not None and -10 <= now - at.timestamp() <= 120, 'feed_observation_stale')
    if before is not None:
        r.need(value['hold'] == before['hold'] and value['bindingCount'] == before['bindingCount'] and value['bindingSHA256'] == before['bindingSHA256'], 'durable_bindings_or_hold_changed')
        original = before['feeds'][0]; current = next(v for v in value['feeds'] if v['deploymentId'] == plan.PRIMARY)
        r.need(current['namespaces'] == original['namespaces'] and current['generation'] >= original['generation'] and current['lastPosition'] >= original['lastPosition'], 'primary_feed_not_preserved')


def continuation_identity(p):
    r.need(p.get('previousImplementationSHA256') == PRIOR_IMPLEMENTATION and p['executionId'] == PRIOR_EXECUTION, 'continuation_scope')
    api = plan.decode(base64.b64decode(p['after']['api'])); worker = plan.decode(base64.b64decode(p['after']['worker']))
    api['controls'] = worker['controls']; api.pop('observability', None)
    api['databaseURLFile'] = '/etc/jobman-dashboard-lab/database-url'; before = r.encoded(api)
    api['databaseURLFile'] = '/etc/jobman-dashboard-app-lab/database-url'; after = r.encoded(api)
    return {'executionId': p['executionId'], 'reviewSHA256': p['reviewSHA256'], 'oldImplementationSHA256': PRIOR_IMPLEMENTATION, 'newImplementationSHA256': p['implementationSHA256'], 'oldRecoverySHA256': r.sha(before), 'newRecoverySHA256': r.sha(after)}


def phase_payload(p, host, phase, apply, **fields):
    payload = dict(p, host=host, phase=phase, apply=apply, **fields)
    if 'materials' in payload:
        if 'role' in fields: payload['materials'] = {fields['role']: payload['materials'][fields['role']]}
        else: payload.pop('materials')
    return payload


def execute(args):
    r.need(args.phase in PHASES and (args.phase in ('preflight', 'verify') or args.apply), 'explicit_apply_required')
    private_directory(args.staging)
    with locked(args.staging):
        p, hashes = prepared(args)
        r.need(not p.get('previousImplementationSHA256') or args.phase in ('install', 'apply', 'restart', 'verify'), 'continuation_install_only')
        receipts = args.staging / ('apply-' + p['executionId'])
        namespaces = {entry['id']: entry['namespaceIds'] for entry in plan.decode(base64.b64decode(p['after']['worker']))['controls']}
        if not receipts.exists(): receipts.mkdir(mode=0o700); receipts.chmod(0o700); r.sync(receipts.parent)
        private_directory(receipts)
        if p.get('previousImplementationSHA256'):
            previous = plan.decode(read(receipts / 'implementation.json'))
            r.need(r.sha(r.encoded(previous)) == PRIOR_IMPLEMENTATION, 'continuation_original_implementation')
            continued = plan.decode(read(receipts / 'continuation.complete.json'))
            r.need(continued['identity'] == continuation_identity(p) and set(continued['hosts']) == {'control01', 'storage01'}, 'continuation_completion_required')
            receipt(receipts / 'implementation-current.json', hashes)
        else: receipt(receipts / 'implementation.json', hashes)
        def call(host, phase, **fields):
            return remote(args.lab_root, phase_payload(p, host, phase, args.apply, **fields))
        if args.phase == 'preflight':
            r.need(not (receipts / 'preflight.json').exists(), 'preflight_already_recorded')
            snapshots = {host: call(host, 'preflight') for host in ('control01', 'storage01')}
            r.need(all(abs(int(time.time()) - value['epoch']) <= 10 for value in snapshots.values()), 'guest_clock_skew')
            snapshots['database'] = call('pg01', 'database'); db_validate(snapshots['database'], namespace_sets=namespaces, now=time.time())
            receipt(receipts / 'preflight.json', snapshots)
            return {'phase': 'preflight', 'readOnly': True, 'executionId': p['executionId'], 'receipts': str(receipts)}
        baseline = plan.decode(read(receipts / 'preflight.json')); p['baseline'] = baseline
        if args.phase in ('materials', 'install', 'apply'):
            checked_at = continued['completedAt'] if p.get('previousImplementationSHA256') else min(baseline[host]['epoch'] for host in ('control01', 'storage01'))
            r.need(type(checked_at) is int and 0 <= int(time.time()) - checked_at <= 1800, 'preflight_expired')
        if args.phase == 'materials':
            for host in ('control01', 'storage01'):
                current = call(host, 'preflight')
                r.need({k:v for k,v in current.items() if k != 'epoch'} == {k:v for k,v in baseline[host].items() if k != 'epoch'}, 'preflight_runtime_drift')
            current_db = call('pg01', 'database'); db_validate(current_db, namespace_sets=namespaces, now=time.time())
            r.need(current_db['bindingSHA256'] == baseline['database']['bindingSHA256'] and current_db['hold'] == baseline['database']['hold'], 'preflight_durable_state_drift')
            materials = call('control01', 'materials'); receipt(receipts / 'private-materials.json', materials)
            return {'phase': 'materials', 'complete': True, 'executionId': p['executionId']}
        p['materials'] = plan.decode(read(receipts / 'private-materials.json'))
        p['materialHashes'] = {role: {name: r.sha(base64.b64decode(raw, validate=True)) for name, raw in files.items()} for role, files in p['materials'].items()}
        if args.phase == 'install':
            for role in ROLES: receipt(receipts / ('install-' + role + '.json'), call(r.SPECS[role][0], 'install', role=role))
        elif args.phase == 'apply':
            for role in ROLES: read(receipts / ('install-' + role + '.json')); call(r.SPECS[role][0], 'swap_state', role=role)
            for role in ROLES: receipt(receipts / ('apply-' + role + '.json'), call(r.SPECS[role][0], 'apply', role=role))
        elif args.phase == 'restart':
            for role in ROLES:
                read(receipts / ('apply-' + role + '.json'))
                r.need(call(r.SPECS[role][0], 'swap_state', role=role)['state'] == 'applied', 'restart_all_swaps_required')
            # Broker then API initializes both registries before worker starts using source2.
            # Existing worker is allowed to finish primary-only work until its restart.
            for role in ROLES: receipt(receipts / ('restart-' + role + '.json'), call(r.SPECS[role][0], 'restart', role=role))
        else:
            for role in ROLES:
                read(receipts / ('restart-' + role + '.json'))
                receipt(receipts / ('verify-' + role + '.json'), call(r.SPECS[role][0], 'verify', role=role))
            deadline = time.monotonic() + 65
            while True:
                db = call('pg01', 'database')
                try: db_validate(db, before=baseline['database'], namespace_sets=namespaces, now=time.time()); break
                except r.Failure:
                    r.need(time.monotonic() < deadline, 'database_not_converged'); time.sleep(1)
            receipt(receipts / 'verified-database.json', db)
        return {'phase': args.phase, 'complete': True, 'configurationRevision': 7, 'sourceRestarted': False, 'holdChanged': False, 'executionId': p['executionId']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-root', type=Path, required=True)
    parser.add_argument('--staging', type=Path, required=True)
    parser.add_argument('--secondary-prepare-receipt', type=Path, required=True)
    parser.add_argument('--secondary-fixture', type=Path, required=True)
    parser.add_argument('--expected-prepare-sha256', required=True)
    parser.add_argument('--expected-review-sha256', required=True)
    parser.add_argument('--expected-implementation-sha256', required=True)
    parser.add_argument('--phase', choices=PHASES, default='preflight')
    parser.add_argument('--continue-from-implementation', choices=(PRIOR_IMPLEMENTATION,))
    parser.add_argument('--apply', action='store_true')
    print(r.encoded(execute(parser.parse_args())).decode(), end='')


if __name__ == '__main__':
    try: main()
    except r.Failure as error: raise SystemExit('Multi-source phase stopped: ' + error.code + '. Preserve receipts; no automatic rollback.') from None
    except Exception: raise SystemExit('Multi-source phase stopped: host_phase_failed. Preserve receipts; no automatic rollback.') from None
