#!/usr/bin/env python3
"""Offline prepare plus explicit, independently reviewed fixed-host upgrade phases."""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('candidate_plan', HERE / 'dashboard-candidate-plan.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
r = p.r


def read(path, maximum=4 << 20, private=True):
    path = Path(path)
    r.need(path.is_absolute() and path.parent.resolve() == path.parent, 'host_path_alias')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        a = os.fstat(stream.fileno())
        r.need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == os.getuid() and
               (stat.S_IMODE(a.st_mode) == 0o600 if private else stat.S_IMODE(a.st_mode) & 0o022 == 0) and
               0 < a.st_size <= maximum, 'host_input_identity')
        raw = stream.read(maximum + 1); b, c = os.fstat(stream.fileno()), path.lstat()
        r.need(len(raw) == a.st_size and (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
               (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns) and (a.st_dev, a.st_ino) == (c.st_dev, c.st_ino), 'host_input_changed')
        return raw


def private_directory(path):
    info = path.lstat()
    r.need(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode) and
           info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'host_directory_identity')


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    r.sync(path.parent)


def save(path, value):
    raw = r.encoded(value)
    if path.exists(): r.need(read(path) == raw, 'retained_host_receipt_changed')
    else: write(path, raw)


@contextmanager
def locked(lab):
    # One lock shared by every candidate plan/phase, not just one staging dir.
    parent = lab / '.lab/dashboard'; private_directory(parent)
    path = parent / '.candidate-upgrade.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.fchmod(fd, 0o600)
    except FileExistsError: fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        r.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, 'host_lock_identity')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); yield
    finally: os.close(fd)


def implementation():
    return {name: r.sha(read(HERE / name, 1 << 20, False)) for name in p.FILES}


def ssh_args(lab, host):
    r.need(host in p.HOSTS, 'ssh_host_boundary')
    c = p.decode(read(lab / '.lab/dashboard/ssh-connections.json', 65536))[host]
    ip = ipaddress.ip_address(c['ansible_host'])
    allowed = {'storage01': '10.77.0.10', 'pg01': '10.77.0.20', 'control01': '10.77.0.21'}
    r.need(c['ansible_user'] == 'vagrant' and type(c['ansible_port']) is int and 1 <= c['ansible_port'] <= 65535 and
           Path(c['ansible_ssh_private_key_file']).is_absolute() and
           (str(ip) in ('127.0.0.1', allowed[host]) or ip in ipaddress.ip_network('10.211.55.0/24')), 'ssh_inventory_boundary')
    return ['ssh', '-i', c['ansible_ssh_private_key_file'], '-p', str(c['ansible_port']), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(lab / '.lab/dashboard/known_hosts'),
            '-o', 'HostKeyAlgorithms=ssh-ed25519', c['ansible_user'] + '@' + str(ip)]


BOOTSTRAP = '''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((40<<20)+1)
 if len(raw)>40<<20:raise ValueError()
 payload=json.loads(raw); sources=payload.pop('_sources'); hashes=payload.pop('_hashes')
 expected={'dashboard-multisource-runtime.py','dashboard-split-plan.py','dashboard-candidate-plan.py','dashboard-candidate-guest.py'}
 if set(sources)!=expected or set(hashes)!=expected:raise ValueError()
 for name,source in sources.items():
  if hashlib.sha256(source.encode()).hexdigest()!=hashes[name]:raise ValueError()
 modules={}
 for filename in ('dashboard-multisource-runtime.py','dashboard-split-plan.py'):
  module=types.ModuleType(filename);exec(compile(sources[filename],filename,'exec'),module.__dict__);modules[filename]=module
 # Resolve imports entirely from the reviewed stdin bytes; no guest module path.
 source=sources['dashboard-candidate-plan.py']
 source=source.replace("HERE = Path(__file__).resolve().parent", "HERE = Path('/reviewed')")
 source=source.replace("split = load('dashboard-split-plan')", "split = modules['dashboard-split-plan.py']")
 source=source.replace("r = load('dashboard-multisource-runtime')", "r = modules['dashboard-multisource-runtime.py']")
 plan=types.ModuleType('candidate_plan');plan.modules=modules;exec(compile(source,'dashboard-candidate-plan.py','exec'),plan.__dict__)
 namespace={'__name__':'reviewed_guest','p':plan};exec(compile(sources['dashboard-candidate-guest.py'],'dashboard-candidate-guest.py','exec'),namespace)
 result=namespace['execute'](payload);print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','guest_phase_failed')
 print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''


def remote(lab, payload, hashes):
    names = ('dashboard-multisource-runtime.py', 'dashboard-split-plan.py', 'dashboard-candidate-plan.py', 'dashboard-candidate-guest.py')
    sources = {name: read(HERE / name, 1 << 20, False).decode() for name in names}
    r.need(all(r.sha(value.encode()) == hashes[name] for name, value in sources.items()), 'remote_implementation_drift')
    body = dict(payload, _sources=sources, _hashes={name: hashes[name] for name in names})
    encoded = r.encoded(body); r.need(len(encoded) <= 40 << 20, 'remote_input_bound')
    raw = r.run(ssh_args(lab, payload['host']) + [shlex.join(['sudo', 'python3', '-c', BOOTSTRAP])],
                'candidate_remote_' + payload['phase'], input_data=encoded, timeout=180, maximum=4 << 20)
    answer = p.decode(raw)
    r.need(answer.get('ok') is True, answer.get('code', 'candidate_remote_failed') if r.CODE.fullmatch(str(answer.get('code', ''))) else 'candidate_remote_failed')
    return answer['result']


def schema_manifest(dashboard):
    r.need(dashboard.is_absolute() and dashboard.resolve() == dashboard, 'dashboard_source_path')
    values = []
    for commit in (p.OLD, p.NEW):
        names = r.run(['git', '-C', str(dashboard), 'ls-tree', '-r', '--name-only', commit, 'internal/store/migrations'],
                      'schema_source_inventory', timeout=5, maximum=16384).decode().splitlines()
        r.need(len(names) == 18 and all(re.fullmatch(r'internal/store/migrations/[0-9]{6}_[a-z_]+\.sql', name) for name in names), 'schema_source_paths')
        rows = []
        for name in names:
            raw = r.run(['git', '-C', str(dashboard), 'show', commit + ':' + name], 'schema_source_bytes', timeout=5, maximum=1 << 20)
            # Go's embed.FS/fs.Glob ledger key retains the migrations/ prefix.
            rows.append({'name': Path(name).relative_to('internal/store').as_posix(), 'sha256': r.sha(raw)})
        values.append(rows)
    r.need(values[0] == values[1], 'candidate_requires_migration')
    return values[0]


def prepare(args):
    snapshot = p.decode(read(args.snapshot)); hashes = implementation()
    metadata, files = p.split.candidate_files(args.candidate, p.ARCHIVE)
    plan = p.make(snapshot, metadata, files, schema_manifest(args.dashboard_root), hashes)
    p.validate(plan)
    r.need(not args.staging.exists() and not args.staging.is_symlink(), 'staging_already_exists')
    args.staging.mkdir(mode=0o700); args.staging.chmod(0o700); private_directory(args.staging); r.sync(args.staging.parent)
    write(args.staging / 'plan.json', r.encoded(plan))
    write(args.staging / 'candidate.tar.gz', read(args.candidate, 32 << 20, False))
    save(args.staging / 'review.json', {'planSHA256': r.sha(r.encoded(plan)), 'implementationSHA256': r.sha(r.encoded(hashes)),
                                      'candidateRevision': p.NEW, 'archiveSHA256': p.ARCHIVE,
                                      'changes': {role: {k: v for k, v in change.items() if not k.startswith('after') or k.endswith('SHA256')}
                                                  for role, change in plan['changes'].items()},
                                      'configurationRevision': p.REVISION, 'applied': False})
    return {'planSHA256': r.sha(r.encoded(plan)), 'implementationSHA256': r.sha(r.encoded(hashes)), 'prepared': True}


def load_plan(args):
    private_directory(args.staging)
    raw = read(args.staging / 'plan.json'); plan = p.decode(raw); p.validate(plan)
    hashes = implementation()
    r.need(p.HEX.fullmatch(args.expected_plan_sha256 or '') and r.sha(raw) == args.expected_plan_sha256 and
           r.sha(r.encoded(hashes)) == args.expected_implementation_sha256 and hashes == plan['implementationSHA256'], 'reviewed_plan_or_implementation')
    return plan, hashes


def payload_for(args, plan):
    host = r.SPECS[args.role][0] if args.phase == 'restart' else args.host
    r.need(host in p.HOSTS, 'phase_host_required')
    return {'phase': args.phase, 'host': host, 'role': args.role, 'plan': plan, 'planSHA256': args.expected_plan_sha256,
            'apply': args.apply, 'observeOnly': args.observe_only}


def required_receipts(staging, phase, host, role, plan_sha):
    before = []
    if phase in ('stage', 'apply', 'restart', 'verify'): before += ['preflight-' + h for h in p.HOSTS]
    if phase in ('apply', 'restart', 'verify'): before += ['stage-control01', 'stage-storage01']
    if phase in ('restart', 'verify'): before += ['apply-control01', 'apply-storage01']
    if phase == 'restart': before += ['restart-' + r for r in p.ROLES[:p.ROLES.index(role)]]
    if phase == 'verify': before += ['restart-' + r for r in p.ROLES]
    for name in before:
        path = staging / (name + '.json')
        r.need(path.exists(), 'previous_phase_incomplete')
        value = p.decode(read(path))
        r.need(value.get('planSHA256') == plan_sha, 'previous_phase_plan_changed')
        if name.startswith('restart-'): r.need(value.get('role') == name[len('restart-'):], 'previous_restart_role')


def phase(args):
    plan, hashes = load_plan(args); payload = payload_for(args, plan); host = payload['host']
    if args.phase == 'preflight':
        r.need(0 <= time.time() - plan['snapshot']['capturedAt'] <= 3600, 'snapshot_expired')
        result = remote(args.lab_root, payload, hashes)
        target = args.staging / ('preflight-' + host + '.json')
        if target.exists():
            previous = p.decode(read(target))
            r.need(previous['planSHA256'] == result['planSHA256'] and previous['host'] == host, 'preflight_receipt_drift')
            return previous
        save(target, result); return result
    r.need(args.apply is True, 'explicit_mutation_approval')
    required_receipts(args.staging, args.phase, host, args.role, args.expected_plan_sha256)
    # Full operation begins within one hour of all host preflights. A later
    # --observe-only can prove existing effects but cannot initiate new effects.
    if not args.observe_only:
        times = [p.decode(read(args.staging / ('preflight-' + h + '.json')))['preflightAt'] for h in p.HOSTS]
        r.need(all(0 <= time.time() - t <= 3600 for t in times), 'preflight_expired')
    if host == 'pg01': r.need(args.phase == 'verify', 'database_mutation_forbidden')
    name = args.phase + '-' + (args.role if args.phase == 'restart' else host)
    pending, completed = args.staging / (name + '.pending.json'), args.staging / (name + '.json')
    if completed.exists(): payload['observeOnly'] = True
    elif pending.exists(): r.need(args.observe_only, 'uncertain_phase_requires_observation')
    else: r.need(not args.observe_only, 'no_pending_phase_to_observe')
    if args.phase == 'stage' and not payload['observeOnly']:
        archive = read(args.staging / 'candidate.tar.gz', 32 << 20)
        r.need(r.sha(archive) == p.ARCHIVE, 'retained_archive_digest')
        payload['archive'] = base64.b64encode(archive).decode()
    # Complete read-only checks before marking any mutation uncertain.
    remote(args.lab_root, dict(payload, phase='database-check', host='pg01', archive=''), hashes)
    global_path = args.lab_root / '.lab/dashboard/.candidate-upgrade.operation.json'
    save(global_path, {'planSHA256': args.expected_plan_sha256, 'implementationSHA256': args.expected_implementation_sha256})
    if not pending.exists() and not completed.exists():
        save(pending, {'planSHA256': args.expected_plan_sha256, 'phase': args.phase, 'host': host, 'role': args.role})
    result = remote(args.lab_root, payload, hashes)
    save(completed, result); return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('snapshot', 'prepare', 'preflight', 'stage', 'apply', 'restart', 'verify'))
    parser.add_argument('--lab-root', type=Path)
    parser.add_argument('--staging', type=Path)
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--dashboard-root', type=Path)
    parser.add_argument('--host', choices=p.HOSTS)
    parser.add_argument('--role', choices=p.ROLES)
    parser.add_argument('--expected-plan-sha256')
    parser.add_argument('--expected-implementation-sha256')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--observe-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.phase == 'prepare':
            r.need(all((args.snapshot, args.candidate, args.staging, args.dashboard_root)) and not args.apply, 'prepare_inputs')
            result = prepare(args)
        else:
            r.need(args.lab_root is not None and args.lab_root.is_absolute() and args.lab_root.resolve() == args.lab_root, 'explicit_lab_root')
            if args.phase == 'snapshot':
                r.need(args.snapshot is not None and not args.apply and not args.snapshot.exists(), 'snapshot_output')
                hashes = implementation(); started = int(time.time())
                hosts = {host: remote(args.lab_root, {'host': host, 'phase': 'snapshot'}, hashes) for host in p.HOSTS}
                result = {'format': 1, 'capturedAt': started, 'hosts': hosts}
                write(args.snapshot, r.encoded(result)); result = {'snapshotSHA256': r.sha(r.encoded(result)), 'readOnly': True}
            else:
                r.need(args.staging is not None and (args.phase != 'restart' or args.role is not None), 'phase_inputs')
                with locked(args.lab_root): result = phase(args)
        print(r.encoded(result).decode(), end='')
    except Exception as error:
        code = getattr(error, 'code', 'candidate_phase_failed')
        print(r.encoded({'ok': False, 'code': code}).decode(), end=''); return 1
    return 0


if __name__ == '__main__': sys.exit(main())
