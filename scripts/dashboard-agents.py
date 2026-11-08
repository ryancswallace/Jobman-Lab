#!/usr/bin/env python3
"""Recover the synthetic Dashboard agents with fresh authorized enrollment tokens.

This uses the Lab's existing synthetic Alice sign-in, never an expired client
certificate as authority. Pending recovery tokens stay in private ignored state
so uncertain operations can be retried without losing their identity.
"""
import argparse
import datetime
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shlex
import ssl
import stat
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('dashboard_cli', Path(__file__).with_name('dashboard-cli.py'))
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
HOSTS = {'host': 'control01', 'slurm': 'submit01'}
FIELDS = {'agentId', 'targetGenerationId', 'sessionId', 'certificateExpiresAt',
          'sessionExpiresAt', 'active', 'certificateExpired', 'sessionExpired'}


def valid_status(value):
    cli.require(isinstance(value, dict) and set(value) == FIELDS, 'Invalid agent status response')
    for key in ('agentId', 'targetGenerationId', 'sessionId'):
        cli.require(str(uuid.UUID(value[key])) == value[key], 'Invalid agent status identity')
    for key in ('active', 'certificateExpired', 'sessionExpired'):
        cli.require(type(value[key]) is bool, 'Invalid agent readiness flag')
    for key in ('certificateExpiresAt', 'sessionExpiresAt'):
        cli.require(isinstance(value[key], str) and value[key].endswith('Z'), 'Invalid expiry timestamp')
        datetime.datetime.fromisoformat(value[key].split('.')[0].rstrip('Z') + '+00:00')
    return value


def remote(root, kind, action, **values):
    cli.require(kind in HOSTS and action in ('inspect', 'ensure', 'recover'), 'Invalid agent operation')
    source = Path(__file__).with_name('dashboard-agent-guest.py').read_text()
    environment = dict(os.environ, JOBMAN_LAB_GROUP='full', VAGRANT_DEFAULT_PROVIDER='parallels',
                       OBJC_DISABLE_INITIALIZE_FORK_SAFETY='YES')
    request = dict(values, kind=kind, action=action)
    try:
        result = subprocess.run(['vagrant', 'ssh', HOSTS[kind], '-c',
                                 shlex.join(['sudo', 'python3', '-c', source])],
                                cwd=root, env=environment, input=json.dumps(request).encode(),
                                capture_output=True, timeout=240)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Agent operation outcome unknown; retain pending state and retry the same command') from None
    cli.require(result.returncode == 0,
                'Agent operation failed on ' + HOSTS[kind] + '; pending state retained. Check service, installed recovery support, and Control availability')
    cli.require(len(result.stdout) <= 16384, 'Agent response too large')
    return valid_status(json.loads(result.stdout))


def issue_token(root, kind, status):
    access = cli.login(root)
    subject = cli.jwt_claims(access)['sub']
    client = cli.opener(ssl.create_default_context(
        cafile=str(root / '.lab/dashboard/runtime/control/fixture-ca.crt')))
    body = {'apiVersion': 'jobman.control/v1alpha1', 'kind': 'AgentEnrollmentToken',
            'spec': {'principal': {'issuer': cli.ISSUER, 'subject': subject}, 'expectedUser': 'alice'}}
    operation = str(uuid.uuid4())
    request = urllib.request.Request(
        cli.CONTROL + '/v1/namespaces/' + cli.NAMESPACE + '/targets/dashboard-execution-' + kind + '/enrollment-tokens',
        data=json.dumps(body).encode(), method='POST', headers={
            'Authorization': 'Bearer ' + access, 'Content-Type': 'application/json',
            'Idempotency-Key': 'dashboard-agent-recovery-' + operation})
    with client.open(request, timeout=20) as response:
        cli.require(response.status in (200, 201), 'Enrollment authorization failed')
        raw = response.read(65537)
        cli.require(len(raw) <= 65536, 'Enrollment response too large')
    document = json.loads(raw)
    cli.require(document.get('kind') == 'AgentEnrollmentToken' and
                document['spec']['targetGenerationId'] == status['targetGenerationId'],
                'Target generation changed; operator reconciliation is required')
    token = document['spec']['token']
    cli.require(isinstance(token, str) and 0 < len(token) <= 8192 and
                not any(c.isspace() for c in token), 'Invalid enrollment token response')
    return {'operationId': operation, 'agentId': status['agentId'],
            'targetGenerationId': status['targetGenerationId'], 'token': token}


def validate_pending(value, status):
    cli.require(isinstance(value, dict) and set(value) ==
                {'operationId', 'agentId', 'targetGenerationId', 'token'}, 'Invalid pending recovery')
    cli.require(str(uuid.UUID(value['operationId'])) == value['operationId'], 'Invalid recovery operation')
    cli.require(value['agentId'] == status['agentId'] and
                value['targetGenerationId'] == status['targetGenerationId'],
                'Pending recovery identity changed; retain state for operator inspection')
    cli.require(isinstance(value['token'], str) and 0 < len(value['token']) <= 8192 and
                not any(c.isspace() for c in value['token']), 'Invalid pending token')
    return value


def ready(status):
    return status['active'] and not status['certificateExpired'] and not status['sessionExpired']


def wait_ready(root, kind, status):
    if not ready(status) and not status['certificateExpired']:
        for _ in range(10):
            time.sleep(1)
            status = remote(root, kind, 'inspect')
            if ready(status):
                break
    return status


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def manage(root, action, kinds, if_configured=False):
    cli.require(root.is_absolute() and root.is_dir(), 'Expected absolute Lab root')
    root = root.resolve()
    marker = root / '.lab/dashboard/cli/config.yaml'
    if if_configured and not marker.exists():
        print('Dashboard CLI agents are not configured; skipping recovery.')
        return
    cli.require(marker.is_file(), 'Configure Dashboard CLI testing first')
    for parent in (root / '.lab', root / '.lab/dashboard'):
        info = parent.lstat()
        cli.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                    info.st_mode & 0o022 == 0, 'Invalid Lab state directory')
    directory = root / '.lab/dashboard/agent-recovery'
    cli.private_directory(directory)
    sync_directory(directory.parent)
    fd = os.open(directory / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        cli.validate_file(os.fstat(lock.fileno()), directory / 'operation.lock', private=True)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for kind in kinds:
            pending_path = directory / (kind + '.pending.json')
            # Finish an uncertain recovery before starting a service that may
            # still have a pending credential replacement on disk.
            probe = 'inspect' if action == 'check' or pending_path.exists() else 'ensure'
            status = remote(root, kind, probe)
            if action == 'ensure' and (status['certificateExpired'] or pending_path.exists()):
                if pending_path.exists():
                    pending = validate_pending(json.loads(cli.read_file(pending_path, private=True)), status)
                else:
                    pending = issue_token(root, kind, status)
                    cli.write_private(pending_path, (json.dumps(pending) + '\n').encode())
                    sync_directory(directory)
                status = remote(root, kind, 'recover', **pending)
                status = wait_ready(root, kind, status)
                cli.require(ready(status), 'Recovery did not establish a ready agent; pending state retained')
                cli.write_private(directory / (kind + '.completed.json'),
                                  (json.dumps({'operationId': pending['operationId'], **status}) + '\n').encode())
                sync_directory(directory)
                pending_path.unlink()
                sync_directory(directory)
            if action == 'ensure' and not ready(status) and not status['certificateExpired']:
                # The running agent recovers an expired inert session over its
                # still-valid mTLS identity. No new enrollment is needed.
                status = wait_ready(root, kind, status)
            cli.require(ready(status), kind + ' agent is not ready; check upgraded agent/Control and retained recovery state')
            print(kind + ' agent service active; local session and certificate are unexpired.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['ensure', 'check'])
    parser.add_argument('--lab-root', type=Path, default=ROOT)
    parser.add_argument('--kind', choices=list(HOSTS), action='append')
    parser.add_argument('--if-configured', action='store_true')
    args = parser.parse_args()
    try:
        manage(args.lab_root, args.action, args.kind or list(HOSTS), args.if_configured)
    except RuntimeError as exc:
        print('Dashboard agents: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Dashboard agent check/recovery failed; private pending state retained. Check Lab services and authentication.', file=sys.stderr)
        sys.exit(1)
