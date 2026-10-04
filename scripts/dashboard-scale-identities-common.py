#!/usr/bin/env python3
"""Bounded shared primitives and fixed account specification; no automatic I/O."""
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

ISSUER = 'https://oidc.lab.test:8443/realms/jobman-lab'
INSTANCES = {'primary': 'e633cf92-258d-48ff-965a-fda88d68ef3a', 'secondary': 'a4f0e2ab-7323-4c90-9510-1f073c660f06'}
ATTRIBUTE = 'dashboard_directory_guid'
UUID = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\Z')
CODE = re.compile('[a-z][a-z0-9_]{0,63}\\Z')

class Failure(ValueError):
    def __init__(self, code):
        assert CODE.fullmatch(code)
        super().__init__(code); self.code = code


def need(value, code):
    if not value: raise Failure(code)


def encoded(value): return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate_json_member'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(Failure('invalid_json_number')))


def accounts():
    return [{'username': 'dashboard-scale' + str(i).zfill(2), 'login': 'scale' + str(i).zfill(2),
             'name': 'Synthetic scale ' + str(i).zfill(2), 'directoryId': '74000000-0000-4000-8000-' + str(i).zfill(12),
             'passwordKey': 'JOBMAN_LAB_DASHBOARD_SCALE' + str(i).zfill(2) + '_PASSWORD'} for i in range(1, 26)]


def private_directory(path, uid=None):
    uid = os.getuid() if uid is None else uid
    info = path.lstat()
    need(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700, 'private_directory_identity')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def mkdir(path):
    path.mkdir(mode=0o700); path.chmod(0o700); private_directory(path); sync(path.parent)


def read(path, maximum=1 << 20, mode=0o600, uid=None):
    uid = os.getuid() if uid is None else uid
    need(path.is_absolute() and path.parent.resolve() == path.parent, 'file_parent_alias')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        a = os.fstat(stream.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_uid == uid and stat.S_IMODE(a.st_mode) == mode and 0 < a.st_size <= maximum, 'file_identity')
        raw = stream.read(maximum + 1); b = os.fstat(stream.fileno()); named = path.lstat()
        need(len(raw) == a.st_size and (a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns) and (named.st_dev, named.st_ino) == (a.st_dev, a.st_ino), 'file_changed')
        return raw


def put(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def retain(path, raw):
    if path.exists(): need(read(path) == raw, 'retained_file_changed')
    else: put(path, raw)


def credential_map(raw):
    need(len(raw) <= 65536 and b'\x00' not in raw, 'credential_file_bounds')
    result = {}
    for line in raw.decode().splitlines():
        if not line or line.startswith('#'): continue
        name, separator, value = line.partition('=')
        need(separator and re.fullmatch('[A-Z][A-Z0-9_]*', name) and name not in result and value, 'credential_file_shape')
        result[name] = value
    return result


def append_credentials(before, passwords):
    existing = credential_map(before); wanted = accounts()
    need(set(passwords) == {a['passwordKey'] for a in wanted}, 'password_keys')
    need(not any(key in existing for key in passwords), 'scale_credential_conflict')
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in passwords.values()) and len(set(passwords.values())) == 25, 'password_bounds_or_reuse')
    return before + (b'' if before.endswith(b'\n') else b'\n') + ''.join(a['passwordKey'] + '=' + passwords[a['passwordKey']] + '\n' for a in wanted).encode()


def run(args, payload, timeout=240):
    # Bound both output pipes while consuming them; discard error contents.
    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as child:
        selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ, 'out'); selector.register(child.stderr, selectors.EVENT_READ, 'err')
        os.set_blocking(child.stdin.fileno(), False); selector.register(child.stdin, selectors.EVENT_WRITE, 'in')
        output = bytearray(); position = errors = 0; deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic(); need(remaining > 0, 'bounded_command_timeout')
                for key, _ in selector.select(min(remaining, 0.2)):
                    if key.data == 'in':
                        if position < len(payload): position += os.write(key.fileobj.fileno(), payload[position:position + 16384])
                        if position == len(payload): selector.unregister(key.fileobj); key.fileobj.close()
                        continue
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw: selector.unregister(key.fileobj); continue
                    if key.data == 'out': output.extend(raw); need(len(output) <= 1 << 20, 'bounded_command_output')
                    else: errors += len(raw); need(errors <= 65536, 'bounded_command_errors')
            need(child.wait(timeout=max(0.01, deadline - time.monotonic())) == 0, 'bounded_command_failed')
            return bytes(output)
        except (OSError, subprocess.SubprocessError) as error: raise Failure('bounded_command_failed') from error
        finally:
            selector.close()
            if child.poll() is None: os.killpg(child.pid, signal.SIGKILL); child.wait()
