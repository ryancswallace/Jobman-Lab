#!/usr/bin/env python3
"""Offline prepare and explicit, fixed-Lab API authentication-key phases."""
import argparse
from contextlib import contextmanager
import fcntl
import importlib.util
import ipaddress
import os
from pathlib import Path
import shlex
import signal
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rotation_plan', HERE / 'dashboard-auth-rotation-plan.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
r = p.r


def read(path, maximum=4 << 20, private=True):
    path = Path(path)
    r.need(path.is_absolute() and path.parent.resolve() == path.parent, 'host_path_alias')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        a = os.fstat(stream.fileno())
        r.need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == os.getuid() and
               (stat.S_IMODE(a.st_mode) == 0o600 if private else stat.S_IMODE(a.st_mode) & 0o022 == 0) and 0 < a.st_size <= maximum, 'host_file_identity')
        raw = stream.read(maximum + 1); b, c = os.fstat(stream.fileno()), path.lstat()
        r.need(len(raw) == a.st_size and (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
               (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns) and (a.st_dev, a.st_ino) == (c.st_dev, c.st_ino), 'host_file_changed'); return raw


def directory(path):
    info = path.lstat()
    r.need(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private_host_directory')


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    r.sync(path.parent)


def save(path, value):
    raw = r.encoded(value)
    if path.exists(): r.need(read(path) == raw, 'receipt_changed')
    else: write(path, raw)


@contextmanager
def locked(lab):
    parent = lab / '.lab/dashboard'; directory(parent)
    path = parent / '.authentication-rotation.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.fchmod(fd, 0o600)
    except FileExistsError: fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.fstat(fd)
        r.need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o600, 'host_lock_identity')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); yield
    finally: os.close(fd)


def implementation(): return {name: r.sha(read(HERE / name, 1 << 20, False)) for name in p.FILES}


def ssh_args(lab, host):
    r.need(host in p.HOSTS, 'fixed_host_required')
    value = p.decode(read(lab / '.lab/dashboard/ssh-connections.json', 65536))[host]
    ip = ipaddress.ip_address(value['ansible_host'])
    allowed = {'storage01': '10.77.0.10', 'pg01': '10.77.0.20', 'control01': '10.77.0.21'}
    r.need(value['ansible_user'] == 'vagrant' and type(value['ansible_port']) is int and 1 <= value['ansible_port'] <= 65535 and Path(value['ansible_ssh_private_key_file']).is_absolute() and
           (str(ip) in ('127.0.0.1', allowed[host]) or ip in ipaddress.ip_network('10.211.55.0/24')), 'ssh_inventory_boundary')
    return ['ssh', '-i', value['ansible_ssh_private_key_file'], '-p', str(value['ansible_port']), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(lab / '.lab/dashboard/known_hosts'),
            '-o', 'HostKeyAlgorithms=ssh-ed25519', value['ansible_user'] + '@' + str(ip)]


BOOTSTRAP = '''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((8<<20)+1)
 if len(raw)>8<<20:raise ValueError()
 payload=json.loads(raw);sources=payload.pop('_sources');hashes=payload.pop('_hashes')
 names={'dashboard-multisource-runtime.py','dashboard-auth-rotation-plan.py','dashboard-auth-rotation-guest.py'}
 if set(sources)!=names or set(hashes)!=names:raise ValueError()
 for name,source in sources.items():
  if hashlib.sha256(source.encode()).hexdigest()!=hashes[name]:raise ValueError()
 runtime=types.ModuleType('reviewed_runtime');exec(compile(sources['dashboard-multisource-runtime.py'],'reviewed_runtime','exec'),runtime.__dict__)
 source=sources['dashboard-auth-rotation-plan.py'];start=source.index('HERE = Path(__file__).resolve().parent');end=source.index('need, sha, encoded =',start)
 source=source[:start]+'r = reviewed_runtime\\n'+source[end:]
 plan=types.ModuleType('reviewed_plan');plan.reviewed_runtime=runtime;exec(compile(source,'reviewed_plan','exec'),plan.__dict__)
 namespace={'__name__':'reviewed_guest','p':plan};exec(compile(sources['dashboard-auth-rotation-guest.py'],'reviewed_guest','exec'),namespace)
 result=namespace['execute'](payload);print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','rotation_guest_failed');print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''


def remote(lab, payload, hashes):
    r.need(payload.get('phase') in ('snapshot', 'check', 'preflight', 'stage', 'apply', 'restart', 'verify'), 'phase_boundary')
    names = ('dashboard-multisource-runtime.py', 'dashboard-auth-rotation-plan.py', 'dashboard-auth-rotation-guest.py')
    sources = {name: read(HERE / name, 1 << 20, False).decode() for name in names}
    r.need(all(r.sha(source.encode()) == hashes[name] for name, source in sources.items()), 'implementation_changed')
    body = r.encoded(dict(payload, _sources=sources, _hashes={name: hashes[name] for name in names})); r.need(len(body) <= 8 << 20, 'transport_bound')
    output = r.run(ssh_args(lab, payload['host']) + [shlex.join(['sudo', 'python3', '-c', BOOTSTRAP])], 'rotation_' + payload['phase'], input_data=body, timeout=160, maximum=4 << 20)
    value = p.decode(output)
    r.need(value.get('ok') is True, value.get('code', 'rotation_failed') if r.CODE.fullmatch(str(value.get('code', ''))) else 'rotation_failed')
    return value['result']


def prepare(args):
    snapshot = p.decode(read(args.snapshot)); hashes = implementation(); plan = p.make(snapshot, args.revision, hashes); p.validate(plan)
    r.need(not os.path.lexists(args.staging), 'staging_exists')
    args.staging.mkdir(mode=0o700); args.staging.chmod(0o700); directory(args.staging); r.sync(args.staging.parent)
    write(args.staging / 'plan.json', r.encoded(plan))
    result = {'planSHA256': r.sha(r.encoded(plan)), 'implementationSHA256': r.sha(r.encoded(hashes)), 'revision': plan['revision'],
              'beforeConfigSHA256': plan['beforeConfigSHA256'], 'afterConfigSHA256': plan['afterConfigSHA256'], 'newKeyId': p.KEY_ID, 'applied': False}
    save(args.staging / 'review.json', result); return result


def load_plan(args):
    directory(args.staging); raw = read(args.staging / 'plan.json'); plan = p.decode(raw); p.validate(plan); hashes = implementation()
    r.need(p.HEX.fullmatch(args.expected_plan_sha256 or '') and p.HEX.fullmatch(args.expected_implementation_sha256 or '') and r.sha(raw) == args.expected_plan_sha256 and
           r.sha(r.encoded(hashes)) == args.expected_implementation_sha256 and hashes == plan['implementationSHA256'], 'reviewed_plan_required')
    return plan, hashes


def phase(args):
    plan, hashes = load_plan(args)
    payload = {'phase': args.phase, 'plan': plan, 'planSHA256': args.expected_plan_sha256, 'apply': args.apply, 'observeOnly': args.observe_only}
    if args.phase == 'preflight':
        r.need(not args.apply and 0 <= time.time() - plan['snapshot']['capturedAt'] <= 3600, 'preflight_snapshot_expired')
        results = {host: remote(args.lab_root, dict(payload, host=host), hashes) for host in p.HOSTS}
        save(args.staging / 'preflight.json', results); return {'planSHA256': args.expected_plan_sha256, 'preflight': True}
    r.need(args.apply, 'explicit_apply_required')
    preflight = p.decode(read(args.staging / 'preflight.json'))
    r.need(set(preflight) == set(p.HOSTS) and all(v['planSHA256'] == args.expected_plan_sha256 for v in preflight.values()), 'preflight_binding')
    if not args.observe_only: r.need(all(0 <= time.time() - v['preflightAt'] <= 3600 for v in preflight.values()), 'preflight_expired')
    previous = {'stage': [], 'apply': ['stage'], 'restart': ['stage', 'apply'], 'verify': ['stage', 'apply', 'restart']}[args.phase]
    for name in previous: r.need(p.decode(read(args.staging / (name + '.json')))['planSHA256'] == args.expected_plan_sha256, 'previous_phase_binding')
    # Current DB hold/source binding and untouched roles are read again before
    # every effect. Successful ingestion may advance generation and position.
    for host in p.HOSTS: remote(args.lab_root, dict(payload, phase='check', host=host), hashes)
    if args.phase == 'verify':
        result = {'planSHA256': args.expected_plan_sha256, 'hosts': {host: remote(args.lab_root, dict(payload, host=host), hashes) for host in p.HOSTS}}
        remote(args.lab_root, dict(payload, phase='check', host='pg01'), hashes)
        save(args.staging / 'verify.json', result); return {'planSHA256': args.expected_plan_sha256, 'verified': True}
    pending, done = args.staging / (args.phase + '.pending.json'), args.staging / (args.phase + '.json')
    if done.exists(): payload['observeOnly'] = True
    elif pending.exists(): r.need(args.observe_only, 'uncertain_phase_requires_observation')
    else: r.need(not args.observe_only, 'no_phase_to_observe')
    save(args.lab_root / '.lab/dashboard/.authentication-rotation.operation.json', {'planSHA256': args.expected_plan_sha256, 'implementationSHA256': args.expected_implementation_sha256})
    if not pending.exists() and not done.exists(): save(pending, {'planSHA256': args.expected_plan_sha256, 'phase': args.phase})
    result = remote(args.lab_root, dict(payload, host='storage01'), hashes)
    save(done, result); return {'planSHA256': args.expected_plan_sha256, 'phase': args.phase, 'completed': True}


def interrupted(_signum, _frame):
    raise r.Failure('rotation_interrupted')


def main():
    signal.signal(signal.SIGINT, interrupted); signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('snapshot', 'prepare', 'preflight', 'stage', 'apply', 'restart', 'verify'))
    parser.add_argument('--lab-root', type=Path); parser.add_argument('--snapshot', type=Path); parser.add_argument('--staging', type=Path)
    parser.add_argument('--revision'); parser.add_argument('--expected-plan-sha256'); parser.add_argument('--expected-implementation-sha256')
    parser.add_argument('--apply', action='store_true'); parser.add_argument('--observe-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.phase == 'prepare':
            r.need(args.snapshot is not None and args.staging is not None and not args.apply and not args.observe_only, 'prepare_inputs'); result = prepare(args)
        else:
            r.need(args.lab_root is not None and args.lab_root.is_absolute() and args.lab_root.resolve() == args.lab_root, 'explicit_lab_root')
            with locked(args.lab_root):
                if args.phase == 'snapshot':
                    r.need(args.snapshot is not None and not args.apply and not args.observe_only and not os.path.lexists(args.snapshot), 'snapshot_inputs')
                    hashes = implementation(); captured = int(time.time())
                    snapshot = {'format': 1, 'capturedAt': captured, 'hosts': {host: remote(args.lab_root, {'phase': 'snapshot', 'host': host}, hashes) for host in p.HOSTS}}
                    write(args.snapshot, r.encoded(snapshot)); result = {'snapshotSHA256': r.sha(r.encoded(snapshot)), 'readOnly': True}
                else: r.need(args.staging is not None, 'staging_required'); result = phase(args)
        print(r.encoded(result).decode(), end='')
    except Exception as error:
        code = getattr(error, 'code', 'authentication_rotation_failed')
        print('Authentication rotation stopped: ' + (code if r.CODE.fullmatch(str(code)) else 'authentication_rotation_failed') + '; preserved state requires inspection.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__': raise SystemExit(main())
