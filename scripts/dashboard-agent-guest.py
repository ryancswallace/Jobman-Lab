#!/usr/bin/env python3
"""Bounded, root-only recovery of the two synthetic Dashboard execution agents."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid

HOSTS = {'host': 'control01.lab.test', 'slurm': 'submit01.lab.test'}
SERVER = 'https://10.77.0.21:18443'
BASE = Path('/var/lib/jobman-dashboard-execution')
JOURNAL_READER = r'''
import hashlib,json,sqlite3,sys
database=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True,timeout=5)
digest=hashlib.sha256()
try:
    cursor=database.execute('SELECT execution_id,delivery_id,assignment_digest FROM executions ORDER BY execution_id LIMIT 100001')
    for count,row in enumerate(cursor,1):
        if count>100000 or not all(isinstance(v,str) and len(v)<=256 for v in row):
            raise RuntimeError('Journal exceeds bounded inspection')
        digest.update((json.dumps(row)+'\n').encode())
finally:
    database.close()
print(digest.hexdigest())
'''


def require(value, message):
    if not value:
        raise RuntimeError(message)


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=kwargs.pop('timeout', 10), **kwargs)


def read_private(path, uid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and
                info.st_mode & 0o077 == 0 and info.st_size <= 65536,
                'Invalid private recovery state')
        raw = stream.read(65537)
        require(len(raw) <= 65536, 'Recovery state too large')
        return json.loads(raw)


def write_receipt(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write((json.dumps(value) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    try:
        temporary.chmod(0o600)
        temporary.replace(path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def expiry(value):
    return datetime.datetime.fromisoformat(value.split('.')[0].rstrip('Z') + '+00:00')


def inspect(kind):
    state = BASE / ('alice-' + kind)
    info = state.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 21001 and
            stat.S_IMODE(info.st_mode) == 0o700, 'Invalid agent state directory')
    metadata = read_private(state / 'credentials.json', 21001)['metadata']
    require(metadata['serverUrl'] == SERVER, 'Unexpected Control server')
    for key in ('agentId', 'targetGenerationId', 'sessionId'):
        require(str(uuid.UUID(metadata[key])) == metadata[key], 'Invalid agent identity')
    now = datetime.datetime.now(datetime.timezone.utc)
    active = run(['systemctl', 'is-active', '--quiet', unit(kind)]).returncode
    require(active in (0, 3), 'Cannot inspect agent service')
    return {key: metadata[key] for key in ('agentId', 'targetGenerationId', 'sessionId',
            'certificateExpiresAt', 'sessionExpiresAt')} | {
                'active': active == 0,
                'certificateExpired': expiry(metadata['certificateExpiresAt']) <= now,
                'sessionExpired': expiry(metadata['sessionExpiresAt']) <= now}


def unit(kind):
    return 'jobman-dashboard-execution-' + kind + '.service'


def journal_identity(state, owner=21001):
    # Existing child runners may publish progress while the service is stopped.
    # Verify the journal inode and immutable execution identities, not mutable
    # WAL bytes or execution states that can legitimately advance.
    path = state / 'agent.db'
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and
            info.st_mode & 0o077 == 0, 'Invalid agent journal')
    command = [sys.executable, '-c', JOURNAL_READER, str(path)]
    if os.geteuid() != owner:
        require(os.geteuid() == 0 and owner == 21001, 'Unexpected journal owner')
        # Read-only SQLite may create WAL/SHM sidecars. They must belong to the
        # execution user, never root, including when the last service closed DB.
        command = ['runuser', '-u', 'alice', '--', *command]
    result = run(command, timeout=15)
    require(result.returncode == 0 and re.fullmatch(rb'[a-f0-9]{64}\n', result.stdout),
            'Could not inspect execution journal as its owner')
    return (info.st_dev, info.st_ino, result.stdout.decode().strip())


def recover(kind, request):
    before = inspect(kind)
    require(before['agentId'] == request['agentId'] and
            before['targetGenerationId'] == request['targetGenerationId'],
            'Agent identity changed; inspect retained recovery operation')
    operation = request['operationId']
    require(str(uuid.UUID(operation)) == operation, 'Invalid recovery operation')
    receipt = BASE / ('.recovered-' + kind + '.json')
    if receipt.exists():
        previous = read_private(receipt, 0)
        if previous.get('operationId') == operation:
            require(previous.get('agentId') == before['agentId'] and
                    previous.get('targetGenerationId') == before['targetGenerationId'],
                    'Recovery receipt identity differs')
            require(not before['certificateExpired'], 'Completed recovery credentials expired; inspect retained operation')
            require(run(['systemctl', 'start', unit(kind)], timeout=20).returncode == 0,
                    'Recovered agent could not start')
            return inspect(kind)
    require(not (before['active'] and not before['certificateExpired']),
            'Agent already active with valid credentials but no matching receipt; retain pending state and reconcile before stopping work')
    raw = run(['systemctl', 'show', unit(kind), '--property=ExecStart', '--value'])
    require(raw.returncode == 0, 'Cannot inspect agent command')
    paths = set(re.findall(rb'/usr/local/libexec/jobman-dashboard-lab/jobman-agent-execution-[a-f0-9]{64}', raw.stdout))
    require(len(paths) == 1, 'Expected isolated content-addressed agent binary')
    binary = paths.pop().decode()
    require(hashlib.sha256(Path(binary).read_bytes()).hexdigest() == binary[-64:],
            'Agent binary digest differs')
    require(run([binary, 'recover', '--help']).returncode == 0,
            'Install a Jobman agent with credential recovery support first')
    kill_mode = run(['systemctl', 'show', unit(kind), '--property=KillMode', '--value'])
    require(kill_mode.returncode == 0 and kill_mode.stdout.strip() == b'process',
            'Agent unit must use KillMode=process to preserve execution runners during recovery')
    require(run(['systemctl', 'stop', unit(kind)], timeout=30).returncode == 0,
            'Could not stop agent before recovery')
    require(not inspect(kind)['active'], 'Agent still running')
    state = BASE / ('alice-' + kind)
    before_journal = journal_identity(state)
    token = request['token']
    require(isinstance(token, str) and 1 <= len(token) <= 8192 and
            not any(c.isspace() for c in token), 'Invalid enrollment token')
    result = run(['runuser', '-u', 'alice', '--', binary, 'recover',
                  '--state-dir', str(state), '--token-file', '-'],
                 input=(token + '\n').encode(), timeout=75)
    require(result.returncode == 0,
            'Credential recovery failed; agent stopped, journal and pending operation retained')
    after = inspect(kind)
    require(after['agentId'] == before['agentId'] and
            after['targetGenerationId'] == before['targetGenerationId'] and
            not after['certificateExpired'] and not after['sessionExpired'],
            'Recovery identity or credential verification failed')
    require(journal_identity(state) == before_journal, 'Recovery changed execution journal identity')
    write_receipt(receipt, {'operationId': operation, 'agentId': after['agentId'],
                           'targetGenerationId': after['targetGenerationId']})
    require(run(['systemctl', 'start', unit(kind)], timeout=20).returncode == 0,
            'Recovered agent could not start')
    return inspect(kind)


def execute(request):
    kind, action = request.get('kind'), request.get('action')
    require(kind in HOSTS and action in ('inspect', 'ensure', 'recover'), 'Invalid agent operation')
    require(os.geteuid() == 0 and os.uname().nodename == HOSTS[kind], 'Wrong guest or execution user')
    lock = Path('/run/lock') / ('jobman-dashboard-agent-' + kind + '.lock')
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                info.st_nlink == 1 and info.st_mode & 0o077 == 0, 'Invalid operation lock')
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'recover':
            return recover(kind, request)
        current = inspect(kind)
        if action == 'ensure' and not current['certificateExpired']:
            require(run(['systemctl', 'start', unit(kind)], timeout=20).returncode == 0,
                    'Could not start agent')
            current = inspect(kind)
        return current


if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, 'Operation too large')
        print(json.dumps(execute(json.loads(raw))))
    except RuntimeError as exc:
        print('Dashboard agent: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Dashboard agent operation failed; inspect service and retained private recovery state.', file=sys.stderr)
        sys.exit(1)
