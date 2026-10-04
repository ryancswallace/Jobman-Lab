#!/usr/bin/env python3
"""Fixed-scope isolated Slurm agent upgrade. Invoked by the reviewed host driver."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time

UNIT = 'jobman-dashboard-execution-slurm.service'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
ROOT = Path('/var/lib/jobman-dashboard-slurm/upgrades')
BINARY_ROOT = Path('/usr/local/libexec/jobman-dashboard-lab')
OLD_REVISION = '21701b191cd4e4e063d26cad7dae31c35db6bc8c'
NEW_REVISION = '807f1f2f4a89b0b400891c622d2a2cf21606e5d5'
OLD_HASH = 'e955472e6174a03503548137397328a4570e8e257372ac4409ed75a8130dfa72'
NEW_HASH = '9ecc9fe75c404b85eb7b4349b55db736885db5eddd024826a4d0dbf73720a47e'
PLAN_HASH = 'e03a18361b5b368722d545ce7080bc2b0b95c06900a3f2056d769c5183970d2c'
SOURCE_ROLES = {
    'api': ('storage01', '/etc/jobman-dashboard-api-lab/config.json', 21904, 'apiConfigSHA256', 'jobman-dashboard-lab-api'),
    'reports': ('storage01', '/etc/jobman-dashboard-worker-lab/config.json', 21905, 'workerConfigSHA256', 'jobman-dashboard-lab-worker'),
    'broker': ('control01', '/etc/jobman-dashboard-broker-lab/config.json', 21901, 'brokerConfigSHA256', 'jobman-dashboard-lab-broker'),
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def read(path, mode, maximum, uid=0):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == uid and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == mode and 0 < s.st_size <= maximum, 'File identity or bound differs')
        data = f.read(maximum + 1)
        need(len(data) <= maximum, 'File read bound exceeded')
        return data


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def parents(path):
    for item in [path, *path.parents]:
        s = item.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) & 0o022 == 0, 'Unsafe ancestor')


def directory(path, mode):
    parents(path.parent)
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        pass
    else:
        os.chmod(path, mode)
        sync_directory(path.parent)
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == mode, 'Receipt directory differs')


def write_new(path, data, mode):
    parents(path.parent)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        need(read(path, mode, len(data) + 1) == data, 'Existing file differs; preserve it')
        return
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode)
        os.fchown(f.fileno(), 0, 0)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    sync_directory(path.parent)


def run(args, timeout=10, maximum=1048576):
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as child:
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ, True)
        selector.register(child.stderr, selectors.EVENT_READ, False)
        result = bytearray()
        errors = 0
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                need(remaining > 0, 'Command deadline exceeded')
                for key, _ in selector.select(min(remaining, .2)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                    elif key.data:
                        result.extend(data)
                        need(len(result) <= maximum, 'Command output bound exceeded')
                    else:
                        errors += len(data)
                        need(errors <= 65536, 'Command error bound exceeded')
            need(child.wait(timeout=max(.001, deadline - time.monotonic())) == 0, 'Scoped command failed')
            return bytes(result)
        finally:
            selector.close()
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)


def binary(path, digest):
    parents(path.parent)
    need(sha(read(path, 0o755, 64 << 20)) == digest, 'Runner hash differs')


def identity(v, new=False, deadline=None):
    def command(args, maximum=1048576):
        remaining = 3 if deadline is None else min(3, deadline - time.monotonic())
        need(remaining > 0, 'Identity verification deadline exceeded')
        return run(args, timeout=remaining, maximum=maximum)
    expected = v['newRunner'] if new else v['oldRunner']
    digest = v['agentSHA256'] if new else v['oldAgentSHA256']
    unit_digest = v['unitAfterSHA256'] if new else v['unitBeforeSHA256']
    need(sha(read(UNIT_PATH, 0o644, 8192)) == unit_digest, 'Unit bytes differ')
    binary(Path(expected), digest)
    command(['systemctl', 'is-active', '--quiet', UNIT])
    props = dict(line.split('=', 1) for line in command(['systemctl', 'show', UNIT, '--property=MainPID', '--property=ExecMainStartTimestampMonotonic', '--property=DropInPaths']).decode().splitlines())
    need(props.get('DropInPaths') == '', 'Unexpected unit drop-ins')
    pid = props.get('MainPID', '')
    need(pid.isdigit() and int(pid) > 0 and props.get('ExecMainStartTimestampMonotonic', '').isdigit(), 'Process identity unavailable')
    need(Path('/proc', pid).stat().st_uid == 21001 and os.readlink('/proc/' + pid + '/exe') == expected, 'Running binary or UID differs')
    args = Path('/proc', pid, 'cmdline').read_bytes()
    need(len(args) < 8192, 'Process argument bound exceeded')
    unit = read(UNIT_PATH, 0o644, 8192).decode()
    wanted = [line.removeprefix('ExecStart=') for line in unit.splitlines() if line.startswith('ExecStart=')]
    need(len(wanted) == 1 and args.rstrip(b'\0').split(b'\0') == [x.encode() for x in shlex.split(wanted[0])], 'Process arguments differ')
    status = json.loads(command(['runuser', '-u', 'alice', '--', expected, 'status', '--json', '--state-dir', v['preserved']['stateRoot']], maximum=32768))
    need(status['metadata'] == {'agentId': v['preserved']['agentId'], 'targetGenerationId': v['preserved']['targetGenerationId']} and status['status']['serverUrl'] == 'https://10.77.0.21:18443', 'Enrolled identity differs')
    return {'MainPID': pid, 'ExecMainStartTimestampMonotonic': props['ExecMainStartTimestampMonotonic'], 'unitSHA256': unit_digest, 'binarySHA256': digest, 'agentId': status['metadata']['agentId'], 'targetGenerationId': status['metadata']['targetGenerationId']}


def empty_queue():
    need(not run(['/opt/slurm/current/bin/squeue', '--noheader', '--format=%i|%T'], timeout=5).strip(), 'Existing scheduler queue must remain untouched')


def source(v, host):
    need(host in ['storage01', 'control01'], 'Source check host differs')
    result = {'configs': {}, 'processes': {}}
    roles = [row for row in SOURCE_ROLES.values() if row[0] == host]
    for _, path, uid, key, _ in roles:
        raw = read(Path(path), 0o600, 1048576, uid)
        need(sha(raw) == v['dashboard'][key] and json.loads(raw)['configurationRevision'] == 6, 'Dashboard configuration drift')
        result['configs'][key] = sha(raw)
    units = [row[4] for row in roles]
    if host == 'control01':
        units += ['jobman-dashboard-lab-control', 'jobman-dashboard-lab-directory', 'jobman-control', 'jobman-keycloak']
    for unit in units:
        run(['systemctl', 'is-active', '--quiet', unit], timeout=3)
        started = run(['systemctl', 'show', unit, '--property=ExecMainStartTimestampMonotonic', '--value'], timeout=3).decode().strip()
        need(started.isdigit() and int(started) > 0, 'Source process start unavailable')
        result['processes'][unit] = started
    if host == 'control01':
        caps = json.loads(run(['runuser', '-u', 'jobman-dashboard-source', '--', 'curl', '--silent', '--fail', '--max-time', '5', '--cacert', '/etc/jobman-dashboard-lab/control-fixture/fixture-ca.crt', 'https://127.0.0.1:18443/v1/capabilities'], timeout=6, maximum=32768))['capabilities']
        need(caps['instanceId'] == v['preserved']['controlInstanceId'] and caps['recoveryEpoch'] == v['preserved']['recoveryEpoch'], 'Source instance or epoch drift')
        result.update(instanceId=caps['instanceId'], recoveryEpoch=caps['recoveryEpoch'])
    return result


def receipt_root(v):
    directory(ROOT, 0o700)
    root = ROOT / PLAN_HASH
    directory(root, 0o700)
    write_new(root / 'plan.json', encode(v), 0o600)
    return root


def restart(v, root):
    completed, pending = root / 'restart.json', root / 'restart.pending.json'
    if completed.exists():
        value = json.loads(read(completed, 0o600, 32768))
        need(identity(v, True) == value['process'], 'Completed restart process drift')
        return value
    if pending.exists():
        before = json.loads(read(pending, 0o600, 32768))['process']
        after = identity(v, True)
        need(after['MainPID'] != before['MainPID'] and after['ExecMainStartTimestampMonotonic'] != before['ExecMainStartTimestampMonotonic'], 'Uncertain restart has no positive completion proof')
    else:
        # Unit is already swapped; the old running process is checked independently.
        before = json.loads(read(root / 'swap.pending.json', 0o600, 32768))['process']
        pid = run(['systemctl', 'show', UNIT, '--property=MainPID', '--value'], timeout=3).decode().strip()
        start = run(['systemctl', 'show', UNIT, '--property=ExecMainStartTimestampMonotonic', '--value'], timeout=3).decode().strip()
        need(pid == before['MainPID'] and start == before['ExecMainStartTimestampMonotonic'] and os.readlink('/proc/' + pid + '/exe') == v['oldRunner'], 'Old process changed before restart')
        need(sha(read(UNIT_PATH, 0o644, 8192)) == v['unitAfterSHA256'], 'Staged unit changed')
        empty_queue()
        write_new(pending, encode({'process': before}), 0o600)
        run(['systemctl', 'daemon-reload'], timeout=10)
        run(['systemctl', 'restart', UNIT], timeout=45)
        deadline = time.monotonic() + 15
        while True:
            try:
                after = identity(v, True, deadline)
                need(after['MainPID'] != before['MainPID'] and after['ExecMainStartTimestampMonotonic'] != before['ExecMainStartTimestampMonotonic'], 'Restart process did not change')
                break
            except (ValueError, OSError, subprocess.SubprocessError, KeyError):
                need(time.monotonic() < deadline, 'Restart verification deadline exceeded; preserve pending receipt')
                time.sleep(.2)
    value = {'planSHA256': PLAN_HASH, 'process': after}
    write_new(completed, encode(value), 0o600)
    return value


def perform(p):
    v, phase, host = p['plan'], p['phase'], p['host']
    need(os.geteuid() == 0 and sys.platform == 'linux' and os.uname().nodename.split('.')[0] == host, 'Pinned root Linux guest required')
    need(sha(encode(v)) == PLAN_HASH and v['coreRevision'] == NEW_REVISION and v['oldCoreRevision'] == OLD_REVISION and v['agentSHA256'] == NEW_HASH and v['oldAgentSHA256'] == OLD_HASH, 'Exact reviewed plan required')
    need(host in ['control01', 'storage01', 'submit01', 'compute01'], 'Unknown guest')
    if phase == 'source':
        need(host in ['control01', 'storage01'], 'Source host differs')
        return source(v, host)
    need(host in ['submit01', 'compute01'] and phase in ['preflight', 'install', 'swap', 'restart', 'verify'], 'Unsupported phase')
    binary(Path(v['oldRunner']), OLD_HASH)
    if phase == 'preflight':
        result = {'runnerSHA256': OLD_HASH}
        free = os.statvfs(BINARY_ROOT)
        need(free.f_bavail * free.f_frsize > 128 << 20, 'Insufficient bounded installation capacity')
        if host == 'submit01':
            empty_queue()
            result['process'] = identity(v)
        return result
    if phase == 'verify':
        binary(Path(v['newRunner']), NEW_HASH)
        return {'runnerSHA256': NEW_HASH, **({'process': identity(v, True)} if host == 'submit01' else {})}
    root = receipt_root(v)
    if phase == 'install':
        data = base64.b64decode(p['binary'], validate=True)
        need(0 < len(data) < 64 << 20 and sha(data) == NEW_HASH and data[:6] == b'\x7fELF\x02\x01' and data[18:20] == b'\xb7\x00', 'Exact ARM64 binary required')
        write_new(Path(v['newRunner']), data, 0o755)
        binary(Path(v['newRunner']), NEW_HASH)
        result = {'planSHA256': PLAN_HASH, 'host': host, 'runnerSHA256': NEW_HASH}
        write_new(root / 'install.json', encode(result), 0o600)
        return result
    need(host == 'submit01', 'Unit mutation restricted to submit01')
    binary(Path(v['newRunner']), NEW_HASH)
    if phase == 'restart':
        need((root / 'swap.json').exists(), 'Confirmed unit swap required')
        return restart(v, root)
    before, after = p['unitBefore'].encode(), p['unitAfter'].encode()
    need(sha(before) == v['unitBeforeSHA256'] and sha(after) == v['unitAfterSHA256'] and before.count(v['oldRunner'].encode()) == 2 and after == before.replace(v['oldRunner'].encode(), v['newRunner'].encode()), 'Only exact unit binary replacement allowed')
    completed, pending = root / 'swap.json', root / 'swap.pending.json'
    if completed.exists():
        need(read(UNIT_PATH, 0o644, 8192) == after and read(root / 'unit.before', 0o600, 8192) == before, 'Completed swap drift')
        return json.loads(read(completed, 0o600, 32768))
    if pending.exists():
        need(read(UNIT_PATH, 0o644, 8192) == after and read(root / 'unit.before', 0o600, 8192) == before, 'Uncertain swap requires positive completion proof')
    else:
        empty_queue()
        current = identity(v)
        need(current == p['baseline']['process'], 'Agent process drift')
        write_new(root / 'unit.before', before, 0o600)
        staged = UNIT_PATH.parent / ('.' + UNIT + '.' + PLAN_HASH)
        write_new(staged, after, 0o644)
        write_new(pending, encode({'process': current}), 0o600)
        need(identity(v) == current and read(UNIT_PATH, 0o644, 8192) == before, 'Unit/process CAS changed')
        os.replace(staged, UNIT_PATH)
        sync_directory(UNIT_PATH.parent)
    result = {'planSHA256': PLAN_HASH, 'unitSHA256': v['unitAfterSHA256']}
    write_new(completed, encode(result), 0o600)
    return result


def execute(p):
    # No lock-file mutation is permitted until the exact plan and guest match.
    need(os.geteuid() == 0 and sys.platform == 'linux' and sha(encode(p['plan'])) == PLAN_HASH and os.uname().nodename.split('.')[0] == p['host'], 'Exact reviewed guest plan required')
    if p['phase'] not in ['install', 'swap', 'restart']:
        return perform(p)
    need(p['host'] in ['submit01', 'compute01'], 'Pinned executor guest required')
    directory(ROOT.parent, 0o755)
    lock = ROOT.parent / '.upgrade.lock'
    parents(lock.parent)
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(lock, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    else:
        os.fchmod(fd, 0o600)
        os.fchown(fd, 0, 0)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600, 'Unsafe guest lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return perform(p)
    finally:
        os.close(fd)


def main():
    raw = sys.stdin.buffer.read((90 << 20) + 1)
    need(len(raw) <= 90 << 20, 'Input exceeds bound')
    print(json.dumps(execute(json.loads(raw)), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Isolated Slurm upgrade phase failed; preserve receipts and inspect the exact phase before retry.') from None
