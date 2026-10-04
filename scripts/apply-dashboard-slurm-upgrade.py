#!/usr/bin/env python3
"""Apply one reviewed isolated-agent upgrade phase with pinned inputs and receipts."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time

PLAN_HASH = 'e03a18361b5b368722d545ce7080bc2b0b95c06900a3f2056d769c5183970d2c'
NAMES = ['apply-dashboard-slurm-upgrade.py', 'dashboard-slurm-upgrade-guest.py']


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= maximum, 'Bounded regular input required')
        data = f.read(maximum + 1)
        need(len(data) <= maximum, 'Input grew beyond bound')
        return data


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def write(path, value):
    raw = encode(value)
    need(len(raw) < 65536, 'Receipt exceeds bound')
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        need(read(path, 65536) == raw, 'Existing host receipt differs')
        return
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(args, data, timeout):
    need(len(data) <= 90 << 20, 'Input exceeds transport bound')
    with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as child:
        selector = selectors.DefaultSelector()
        os.set_blocking(child.stdin.fileno(), False)
        selector.register(child.stdin, selectors.EVENT_WRITE, 'in')
        selector.register(child.stdout, selectors.EVENT_READ, 'out')
        selector.register(child.stderr, selectors.EVENT_READ, 'err')
        out, pos, errors, deadline = bytearray(), 0, 0, time.monotonic() + timeout
        try:
            while selector.get_map():
                left = deadline - time.monotonic()
                need(left > 0, 'SSH deadline exceeded')
                for key, _ in selector.select(min(left, .2)):
                    if key.data == 'in':
                        pos += os.write(child.stdin.fileno(), data[pos:pos+16384])
                        if pos == len(data):
                            selector.unregister(child.stdin)
                            child.stdin.close()
                        continue
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.data == 'out':
                        out.extend(chunk)
                        need(len(out) <= 65536, 'SSH output bound exceeded')
                    else:
                        errors += len(chunk)
                        need(errors <= 65536, 'SSH error bound exceeded')
            need(child.wait(timeout=max(.001, deadline-time.monotonic())) == 0, 'Guest phase failed; retain receipts')
            return json.loads(out)
        finally:
            selector.close()
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)


def prepared(args):
    for path in (args.plan, args.build, args.lab_root):
        need(path.is_absolute(), 'Absolute reviewed paths required')
    raw = read(args.plan, 32768)
    need(sha(raw) == PLAN_HASH and args.expected_plan_sha256 == PLAN_HASH, 'Reviewed plan differs')
    plan = json.loads(raw)
    root = Path(__file__).resolve().parent
    manifest = {name: sha(read(root/name, 65536)) for name in NAMES}
    need(sha(encode(manifest)) == args.expected_implementation_sha256, 'Reviewed implementation differs')
    build_raw = read(args.build/'build.json', 8192)
    need(sha(build_raw) == plan['buildMetadataSHA256'], 'Build provenance differs')
    binary = read(args.build/'jobman-agent', 64 << 20)
    need(sha(binary) == plan['agentSHA256'], 'Build hash differs')
    fixture = read(args.lab_root/'.lab/dashboard/slurm-fixture.json', 32768)
    need(sha(fixture) == plan['fixtureSHA256'], 'Original enrollment receipt changed')
    before = read(args.plan.parent/'unit.before', 8192)
    after = read(args.plan.parent/'unit.after', 8192)
    need(sha(before) == plan['unitBeforeSHA256'] and sha(after) == plan['unitAfterSHA256'] and after == before.replace(plan['oldRunner'].encode(), plan['newRunner'].encode()), 'Unit replacement differs')
    return plan, binary, before.decode(), after.decode(), read(root/NAMES[1], 65536).decode()


def source_states(call):
    return {host: call(host, 'source') for host in ['storage01', 'control01']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['preflight', 'install', 'swap', 'restart', 'verify'])
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--expected-implementation-sha256', required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--lab-root', type=Path, required=True)
    args = parser.parse_args()
    need(args.phase in ['preflight', 'verify'] or args.apply, 'Explicit apply required for mutations')
    plan, binary, before, after, guest = prepared(args)
    state = args.lab_root/'.lab/dashboard-slurm'
    lock = state/'.mapping-apply.lock'
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(lock, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    else:
        os.fchmod(fd, 0o600)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600, 'Unsafe host lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipts = args.plan.parent/'apply-receipts'
        try:
            receipts.mkdir(mode=0o700)
            os.chmod(receipts, 0o700)
        except FileExistsError:
            pass
        s = receipts.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700, 'Unsafe receipt directory')
        def call(host, phase, extra=None):
            directory = args.lab_root/('.lab/dashboard' if host in ['control01', 'storage01'] else '.lab/dashboard-slurm')
            connection = json.loads(read(directory/'ssh-connections.json', 65536))[host]
            command = ['ssh', '-i', connection['ansible_ssh_private_key_file'], '-p', str(connection['ansible_port']), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(directory/'known_hosts'), '-o', 'HostKeyAlgorithms=ssh-ed25519', connection['ansible_user']+'@'+connection['ansible_host'], shlex.join(['sudo', 'python3', '-c', guest])]
            return run(command, encode({'plan': plan, 'phase': phase, 'host': host, **(extra or {})}), 85 if phase == 'restart' else 50)
        current_source = source_states(call)
        if args.phase == 'preflight':
            value = {'planSHA256': PLAN_HASH, 'source': current_source}
            for host in ['compute01', 'submit01']:
                value[host] = call(host, 'preflight')
            write(receipts/'preflight.json', value)
        else:
            baseline = json.loads(read(receipts/'preflight.json', 65536))
            need(baseline['source'] == current_source, 'Source/runtime process drift since preflight')
            if args.phase == 'install':
                value = {host: call(host, 'install', {'binary': base64.b64encode(binary).decode()}) for host in ['compute01', 'submit01']}
            elif args.phase == 'swap':
                installed = json.loads(read(receipts/'install.json', 65536))
                need(set(installed) == {'compute01', 'submit01'} and all(v['runnerSHA256'] == plan['agentSHA256'] for v in installed.values()), 'Both runner receipts required')
                # Independently verify compute copy before changing the submit unit.
                call('compute01', 'verify')
                value = call('submit01', 'swap', {'unitBefore': before, 'unitAfter': after, 'baseline': baseline['submit01']})
            elif args.phase == 'restart':
                read(receipts/'swap.json', 65536)
                call('compute01', 'verify')
                value = call('submit01', 'restart')
            else:
                read(receipts/'restart.json', 65536)
                value = {host: call(host, 'verify') for host in ['compute01', 'submit01']}
            need(source_states(call) == current_source, 'Source/runtime changed during phase')
            write(receipts/(args.phase+'.json'), value)
        print('Verified isolated Slurm upgrade phase: '+args.phase)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Isolated Slurm upgrade failed in the selected phase; preserve all receipts. No automatic rollback or restart retry.') from None
