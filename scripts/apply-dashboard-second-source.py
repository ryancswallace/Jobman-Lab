#!/usr/bin/env python3
"""Explicit receipt-gated second Control provisioning; default is read-only preflight.

No Dashboard or broker registry edit is part of this driver. Mutating phases
require --apply and exact staged plan/helper identities. Never resets partial work.
"""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
LAB = HERE.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


plan = load('second_source_plan', HERE / 'dashboard-second-source-plan.py')
IMPLEMENTATIONS = ('apply-dashboard-second-source.py', 'dashboard-second-source-guest.py', 'dashboard-second-source-plan.py', 'continue-dashboard-second-source.py')
PHASES = ('preflight', 'database', 'prepare', 'start', 'verify')


def private_read(path, maximum=1 << 20):
    info = path.lstat()
    plan.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                 'Expected current-user private file')
    return plan.read(path, maximum)


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def save(path, value):
    raw = plan.encoded(value)
    if path.exists():
        plan.require(private_read(path, 4 << 20) == raw, 'Existing phase receipt differs')
    else:
        write_new(path, raw)


def verify_stage(args, continuation=None):
    root = args.staging
    info = root.lstat()
    plan.require(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(info.st_mode) and
                 info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Private staged plan directory required')
    raw = private_read(root / 'plan.json')
    plan.require(re.fullmatch('[0-9a-f]{64}', args.expected_plan_sha256) and hashlib.sha256(raw).hexdigest() == args.expected_plan_sha256,
                 'Exact staged plan digest differs')
    value = plan.json_value(raw)
    lab = getattr(args, 'lab_root', LAB)
    plan.require(lab.is_absolute() and lab.resolve() == lab and lab.is_dir(), 'Real absolute Lab root required')
    primary = plan.json_value(plan.read(lab / '.lab/dashboard/fixture-info.json', 1 << 20))
    oidc = plan.json_value(plan.read(lab / '.lab/dashboard/oidc-public.json', 16384))
    source = plan.validate_build(args.control_build)
    plan.require(value == plan.make_plan(primary, oidc, source), 'Staged plan differs from current signed identities and fixed source')
    metadata = plan.json_value(plan.read(args.helper_build / 'build.json', 8192))
    plan.require(re.fullmatch('[0-9a-f]{40}', args.helper_revision) and metadata.get('revision') == args.helper_revision and
                 metadata.get('platform') == 'linux/arm64' and metadata.get('toolchain') == 'go1.26.6', 'Reviewed helper build identity differs')
    binary = plan.read(args.helper_build / 'jobman-control-lab-helper', 64 << 20)
    digest = hashlib.sha256(binary).hexdigest()
    plan.require(binary[:6] == b'\x7fELF\x02\x01' and binary[18:20] == b'\xb7\x00' and
                 metadata.get('sha256', {}).get('jobman-control-lab-helper') == digest, 'Exact helper binary digest differs')
    helper = {'revision': args.helper_revision, 'sha256': digest, 'platform': 'linux/arm64', 'toolchain': 'go1.26.6'}
    implementations = {name: hashlib.sha256(plan.read(HERE / name, 1 << 20)).hexdigest() for name in IMPLEMENTATIONS}
    identity = {'planSHA256': args.expected_plan_sha256, 'helperBuild': helper, 'implementationSHA256': implementations}
    if continuation is None and (root / 'continuation.json').exists():
        continuation = plan.json_value(private_read(root / 'continuation.json'))
    if continuation is not None:
        plan.require(continuation.get('priorExecutionId') == 'd87f4b43ba6cb4d503f09e3cf4738795f52550c04623bfeeb8c4bce2f5f93331' and
                     continuation.get('priorPlanSHA256') == 'ae19480a6f6e79bc2fa144b1a383af0087df353ea86ad001a7ffcedde1f2cc2d', 'Unrecognized continuation')
        identity['continuation'] = continuation
    execution = hashlib.sha256(plan.encoded(identity)).hexdigest()
    return dict(identity, plan=value, executionId=execution), binary


def connections(lab):
    value = plan.json_value(private_read(lab / '.lab/dashboard/ssh-connections.json', 65536))
    for host in ('control01', 'pg01'):
        item = value[host]
        address = ipaddress.ip_address(item['ansible_host'])
        plan.require(item['ansible_user'] == 'vagrant' and Path(item['ansible_ssh_private_key_file']).is_absolute() and
                     type(item['ansible_port']) is int and 1 <= item['ansible_port'] <= 65535 and
                     (str(address) in ('127.0.0.1', '10.77.0.20', '10.77.0.21') or address in ipaddress.ip_network('10.211.55.0/24')),
                     'Unexpected pinned Lab guest endpoint')
    return value


def ssh_arguments(host, lab):
    plan.require(host in ('pg01', 'control01'), 'Unlisted guest')
    connection = connections(lab)[host]
    return ['ssh', '-i', connection['ansible_ssh_private_key_file'], '-p', str(connection['ansible_port']),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(lab / '.lab/dashboard/known_hosts'),
            '-o', 'HostKeyAlgorithms=ssh-ed25519', connection['ansible_user'] + '@' + connection['ansible_host']]


def remote(host, payload, lab):
    script = plan.read(HERE / 'dashboard-second-source-guest.py', 1 << 20).decode()
    command = ssh_arguments(host, lab) + [shlex.join(['sudo', 'python3', '-c', script])]
    result = subprocess.run(command, input=plan.encoded(dict(payload, host=host)), capture_output=True, timeout=180)
    plan.require(result.returncode == 0 and len(result.stdout) <= 2 << 20,
                 'Secondary guest phase failed; preserve private receipts for inspection')
    return plan.json_value(result.stdout)


def probe_database(query, secret, database, ssl, lab):
    role = 'jobman_dashboard_control_secondary'
    plan.require(database in (role, 'jobman_control', 'jobman_dashboard_control', 'jobman_dashboard', 'postgres') and
                 ssl in ('verify-full', 'disable') and re.fullmatch('[0-9a-f]{64}', secret), 'Database probe scope differs')
    environment = ['env', 'PGSSLMODE=' + ssl, 'PGSSLROOTCERT=/var/lib/postgresql/data/dashboard-tls/ca.crt', 'PGCONNECT_TIMEOUT=8']
    command = 'IFS= read -r PGPASSWORD; export PGPASSWORD; ' + shlex.join(environment +
               ['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-U', role, '-d', database, '-h', '127.0.0.1'])
    remote_command = shlex.join(['sudo', 'podman', 'exec', '-i', 'jobman-postgres', 'sh', '-c', command])
    return subprocess.run(ssh_arguments('pg01', lab) + [remote_command], input=(secret + '\n' + query + '\n').encode(),
                          capture_output=True, timeout=25)


def password(lab, create=False):
    path = lab / '.lab/credentials/dashboard-secondary.env'
    parent = path.parent
    info = parent.lstat()
    plan.require(parent.resolve() == parent and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o700, 'Private Lab credential directory required')
    if create and not path.exists():
        write_new(path, ('JOBMAN_LAB_DASHBOARD_SECONDARY_CONTROL_PASSWORD=' + secrets.token_hex(32) + '\n').encode())
    raw = private_read(path, 256).decode()
    match = re.fullmatch('JOBMAN_LAB_DASHBOARD_SECONDARY_CONTROL_PASSWORD=([0-9a-f]{64})\n', raw)
    plan.require(match, 'Secondary synthetic credential format differs')
    return match[1]


def verify_database(secret, lab, fixture=None):
    database = 'jobman_dashboard_control_secondary'
    query = "SELECT current_database(); SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid(); SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls FROM pg_roles WHERE rolname=current_user;"
    result = probe_database(query, secret, database, 'verify-full', lab)
    plan.require(result.returncode == 0 and result.stdout.decode().strip() == database + '\nt\nt', 'Secondary TLS/role verification failed')
    for other in ('jobman_control', 'jobman_dashboard_control', 'jobman_dashboard', 'postgres'):
        plan.require(probe_database('SELECT 1;', secret, other, 'verify-full', lab).returncode != 0, 'Secondary identity reached another database')
    plan.require(probe_database('SELECT 1;', secret, database, 'disable', lab).returncode != 0,
                 'Secondary identity accepted plaintext')
    if fixture is not None:
        instance = fixture['instanceId']
        plan.require(plan.UUID.fullmatch(instance), 'Secondary instance is invalid')
        query = "SELECT id::text FROM control_instance; SELECT max(version) FROM schema_migrations; SELECT restore_epoch FROM service_recovery_state; SELECT count(*) FROM namespace_directory_state WHERE last_verified_at > statement_timestamp()-interval '120 seconds';"
        result = probe_database(query, secret, database, 'verify-full', lab)
        plan.require(result.returncode == 0 and result.stdout.decode().strip() == instance + '\n' + plan.MIGRATION + '\n1\n2',
                     'Secondary source identity/schema/current directory proof differs')
    return {'tlsVerified': True, 'roleIsolated': True, 'directoryProofVerified': fixture is not None}


def execute_locked(args):
    plan.require(args.phase in PHASES and (args.phase in ('preflight', 'verify') or args.apply),
                 'Mutating phase requires explicit --apply')
    payload, helper_binary = verify_stage(args)
    lab = getattr(args, 'lab_root', LAB)
    receipts = args.staging / ('apply-' + payload['executionId'])
    if not receipts.exists():
        receipts.mkdir(mode=0o700)
        receipts.chmod(0o700)
    info = receipts.lstat()
    plan.require(receipts.resolve() == receipts and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o700, 'Private receipt boundary differs')
    plan.require('continuation' not in payload or args.phase not in ('preflight', 'database'), 'Continuation already carries verified database/preflight; proceed to prepare')
    if args.phase == 'preflight':
        snapshots = {host: remote(host, dict(payload, phase='preflight'), lab) for host in ('pg01', 'control01')}
        plan.require(all(abs(value['epoch'] - int(time.time())) <= 10 for value in snapshots.values()), 'Lab clocks differ')
        save(receipts / 'preflight.json', snapshots)
        return {'preflight': True, 'mutatedGuests': False}
    preflight = plan.json_value(private_read(receipts / 'preflight.json'))
    payload.update(preflight=preflight, phase=args.phase, apply=args.apply)
    secret = password(lab, create=args.phase == 'database')
    if args.phase == 'database':
        output = remote('pg01', dict(payload, password=secret), lab)
        verify_database(secret, lab)
    elif args.phase == 'prepare':
        plan.json_value(private_read(receipts / 'database.json'))
        verify_database(secret, lab)
        binaries = {'jobman-control': base64.b64encode(plan.read(args.control_build / 'jobman-control', 64 << 20)).decode(),
                    'jobman-control-lab-helper': base64.b64encode(helper_binary).decode()}
        output = remote('control01', dict(payload, password=secret, binaries=binaries), lab)
    elif args.phase == 'start':
        plan.json_value(private_read(receipts / 'prepare.json', 2 << 20))
        output = remote('control01', payload, lab)
    else:
        prior = plan.json_value(private_read(receipts / 'prepare.json', 2 << 20))
        plan.json_value(private_read(receipts / 'start.json'))
        # Dedicated read-only verification cannot create a receipt or restart
        # any service, even if a start receipt is absent or inconsistent.
        remote('control01', dict(payload, phase='verify'), lab)
        output = verify_database(secret, lab, prior['fixture'])
        output['dashboardRegistered'] = False
    save(receipts / (args.phase + '.json'), output)
    return dict(output) if args.phase == 'verify' else {'phase': args.phase, 'complete': True, 'dashboardRegistered': False}


@contextmanager
def receipt_lock(root):
    path = root / '.secondary-apply.lock'
    created = False
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        created = True
    except FileExistsError:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        plan.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), 'Private receipt lock required')
        if created:
            os.fchmod(fd, 0o600)
        else:
            plan.require(stat.S_IMODE(info.st_mode) == 0o600, 'Existing receipt lock mode differs')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('Another phase is using this staged plan') from error
        yield
    finally:
        os.close(fd)


def execute(args):
    plan.require(args.phase in PHASES and (args.phase in ('preflight', 'verify') or args.apply),
                 'Mutating phase requires explicit --apply')
    root = args.staging
    info = root.lstat()
    plan.require(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(info.st_mode) and
                 info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Private staged plan directory required')
    with receipt_lock(root):
        return execute_locked(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-root', type=Path, default=LAB)
    parser.add_argument('--staging', required=True, type=Path)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--control-build', required=True, type=Path)
    parser.add_argument('--helper-build', required=True, type=Path)
    parser.add_argument('--helper-revision', required=True)
    parser.add_argument('--phase', choices=PHASES, default='preflight')
    parser.add_argument('--apply', action='store_true')
    print(json.dumps(execute(parser.parse_args()), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Secondary-source phase failed; preserve private receipts and inspect the scoped state. No reset or automatic rollback attempted.', file=sys.stderr)
        sys.exit(1)
