#!/usr/bin/env python3
"""Bounded operator primitives for reviewed multi-source phases; no standalone apply."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

SPECS = {
    'api': ('storage01', '/etc/jobman-dashboard-api-lab', 21904, 'jobman-dashboard-api', 'jobman-dashboard-lab-api', 'jobman-dashboard', 'api'),
    'worker': ('storage01', '/etc/jobman-dashboard-worker-lab', 21905, 'jobman-dashboard-worker', 'jobman-dashboard-lab-worker', 'jobman-dashboard', 'worker'),
    'broker': ('control01', '/etc/jobman-dashboard-broker-lab', 21901, 'jobman-dashboard-log', 'jobman-dashboard-lab-broker', 'jobman-log-broker', 'broker')}
CODE = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')

class Failure(ValueError):
    def __init__(self, code):
        assert CODE.fullmatch(code)
        super().__init__(code)
        self.code = code


def need(condition, code):
    if not condition:
        raise Failure(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, uid, mode=0o600, maximum=1 << 20):
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve() == path.parent, 'file_parent_alias')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        first = os.fstat(stream.fileno())
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_uid == uid and first.st_gid == uid and
             stat.S_IMODE(first.st_mode) == mode and 0 < first.st_size <= maximum, 'file_identity')
        raw = stream.read(maximum + 1)
        last, named = os.fstat(stream.fileno()), path.lstat()
        need(len(raw) == first.st_size and (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns, first.st_ctime_ns) ==
             (last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns, last.st_ctime_ns) and
             (first.st_dev, first.st_ino) == (named.st_dev, named.st_ino), 'file_changed')
        return raw


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    need(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700, 'operator_directory_identity')


def create_directory(path):
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    private_directory(path)
    sync(path.parent)


def put(path, raw, uid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), uid, uid)
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def run(args, code, *, timeout=15, input_data=None, maximum=1 << 20):
    need(CODE.fullmatch(code), 'invalid_failure_code')
    with subprocess.Popen(args, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as child:
        streams = selectors.DefaultSelector()
        streams.register(child.stdout, selectors.EVENT_READ, 'out')
        streams.register(child.stderr, selectors.EVENT_READ, 'err')
        if input_data is not None:
            os.set_blocking(child.stdin.fileno(), False)
            streams.register(child.stdin, selectors.EVENT_WRITE, 'in')
        position, errors = 0, 0
        result = bytearray(); deadline = time.monotonic() + timeout
        try:
            while streams.get_map():
                remaining = deadline - time.monotonic()
                need(remaining > 0, code)
                for key, _ in streams.select(min(remaining, 0.2)):
                    if key.data == 'in':
                        if position < len(input_data):
                            position += os.write(key.fileobj.fileno(), input_data[position:position + 16384])
                        if position == len(input_data):
                            streams.unregister(key.fileobj); key.fileobj.close()
                        continue
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        streams.unregister(key.fileobj); continue
                    if key.data == 'out':
                        result.extend(raw); need(len(result) <= maximum, code)
                    else:
                        errors += len(raw); need(errors <= 65536, code)
            need(child.wait(timeout=max(0.01, deadline - time.monotonic())) == 0, code)
            return bytes(result)
        except (OSError, subprocess.SubprocessError) as error:
            raise Failure(code) from error
        finally:
            streams.close()
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL); child.wait()


def process(role):
    _, root, uid, _, unit, binary, mode = SPECS[role]
    run(['systemctl', 'is-active', '--quiet', unit], 'process_not_active')
    pid = run(['systemctl', 'show', unit, '--property=MainPID', '--value'], 'process_pid').decode().strip()
    need(pid.isdigit() and int(pid) > 0 and Path('/proc', pid).stat().st_uid == uid, 'process_owner')
    executable = Path(os.readlink('/proc/' + pid + '/exe'))
    need(re.fullmatch('/opt/jobman-dashboard-lab/releases/[0-9a-f]{40}/bin/' + binary, str(executable)), 'process_binary_path')
    args = Path('/proc', pid, 'cmdline').read_bytes().split(b'\0')
    need(b'--config' in args and args.index(b'--config') + 1 < len(args) and
         args[args.index(b'--config') + 1] == (root + '/config.json').encode(), 'process_config_path')
    if mode != 'broker':
        need(b'--mode' in args and args.index(b'--mode') + 1 < len(args) and args[args.index(b'--mode') + 1] == mode.encode(), 'process_mode')
    return {'binary': str(executable), 'binarySHA256': sha(read(executable, 0, 0o755, 96 << 20)),
            'unitSHA256': sha(read(Path('/etc/systemd/system') / (unit + '.service'), 0, 0o644)), 'uid': uid, 'unit': unit}


def observations(role, revision):
    _, _, _, user, _, _, mode = SPECS[role]
    socket = '/run/jobman-dashboard-' + role + '-lab/observe.sock'
    prefix = ['runuser', '-u', user, '--', 'curl', '--silent', '--fail', '--max-time', '2', '--unix-socket', socket]
    for endpoint, state in [('livez', 'alive'), ('readyz', 'ready')]:
        response = json.loads(run(prefix + ['http://localhost/' + endpoint], 'readiness_' + role, timeout=3))
        need(response.get('state') == state and response.get('role') == mode, 'readiness_' + role)
    metrics = run(prefix + ['http://localhost/metrics'], 'metrics_' + role, timeout=3).decode()
    need(re.findall(r'^jobman_dashboard_configuration_revision ([0-9]+)$', metrics, re.MULTILINE) == [str(revision)], 'metrics_revision_' + role)


def await_ready(role, revision, expected, timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        try:
            need(process(role) == expected, 'restarted_process_identity')
            observations(role, revision)
            return
        except (ValueError, OSError, subprocess.SubprocessError):
            need(time.monotonic() < deadline, 'startup_not_ready_' + role)
            time.sleep(0.25)


def atomic_config(path, before, after, uid, backup, execution):
    need(read(path, uid) == before, 'config_compare_and_swap')
    put(backup, before)
    temporary = path.parent / ('.multisource-' + execution + '.tmp')
    put(temporary, after, uid)
    need(read(path, uid) == before, 'config_changed_before_rename')
    os.replace(temporary, path)
    sync(path.parent)
    need(read(path, uid) == after, 'config_final_bytes')
