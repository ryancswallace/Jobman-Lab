#!/usr/bin/env python3
"""Reversible, synthetic-only direct-group changes for coordinated acceptance.

A private receipt retains exact original bytes. Restore refuses concurrent state
changes; it never resets the fixture or modifies directory mappings/Control SQL.
"""
import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
import uuid

FIXTURE_ROOT = Path('/etc/jobman-dashboard-lab/control-fixture')
ALICE = '71000000-0000-4000-8000-000000000001'
BOB = '71000000-0000-4000-8000-000000000002'
VIEWER = '72000000-0000-4000-8000-000000000001'
SUBMITTER = '72000000-0000-4000-8000-000000000002'
SCENARIOS = {
    'alice-viewer-removed': [(VIEWER, ALICE)],
    'alice-research-removed': [(VIEWER, ALICE), (SUBMITTER, ALICE)],
    'bob-research-removed': [(VIEWER, BOB)],
}
MAXIMUM_BYTES = 65536


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid() or info.st_size > MAXIMUM_BYTES:
            raise ValueError('Fixture state/receipt must be a bounded private owned file')
        value = stream.read(MAXIMUM_BYTES + 1)
    if len(value) > MAXIMUM_BYTES:
        raise ValueError('Fixture file exceeded bound')
    return value


def sync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_atomic(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.directory-state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def scenario_state(original, scenario):
    state = json.loads(original)
    if set(state) != {'revision', 'users', 'groups'} or type(state['revision']) is not int or not 1 <= state['revision'] < (1 << 63) - 1:
        raise ValueError('Unexpected fixture state format')
    if sorted(state['users'], key=lambda user: user['directoryId']) != [
            {'directoryId': ALICE, 'enabled': True}, {'directoryId': BOB, 'enabled': True}]:
        raise ValueError('Scenario requires the two enabled synthetic fixture identities')
    groups = {group['id']: group for group in state['groups']}
    expected_ids = {'72000000-0000-4000-8000-%012d' % index for index in range(1, 9)}
    if len(state['groups']) != 8 or set(groups) != expected_ids:
        raise ValueError('Unexpected synthetic group mappings')
    expected = {VIEWER: [ALICE, BOB], SUBMITTER: [ALICE],
                '72000000-0000-4000-8000-000000000008': [ALICE]}
    for group_id, group in groups.items():
        if set(group) != {'id', 'members'} or sorted(group['members']) != expected.get(group_id, []):
            raise ValueError('Fixture memberships differ from the approved baseline')
    for group_id, member in SCENARIOS[scenario]:
        groups[group_id]['members'].remove(member)
    state['revision'] += 1
    return (json.dumps(state, indent=2) + '\n').encode()


def transition(root, action, token, scenario=None):
    root = Path(root)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
        raise ValueError('Fixture root is not the private owned directory')
    if re.fullmatch('[0-9a-f]{32}', token) is None:
        raise ValueError('Invalid recovery receipt identifier')
    lock = os.open(root / '.directory-acceptance.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
            raise ValueError('Fixture transition lock must be private and owned')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return locked_transition(root, action, token, scenario)
    finally:
        os.close(lock)


def locked_transition(root, action, token, scenario):
    state_path = root / 'directory-state.json'
    receipt_path = root / ('.directory-acceptance-' + token + '.json')
    current = read_private(state_path)
    if action == 'begin':
        if scenario not in SCENARIOS or list(root.glob('.directory-acceptance-*.json')):
            raise ValueError('Another scenario is pending restoration, or scenario is unknown')
        changed = scenario_state(current, scenario)
        receipt = {'originalBase64': base64.b64encode(current).decode(), 'changedSHA256': digest(changed), 'scenario': scenario}
        # Persist recovery before publication, even if the process fails mid-step.
        fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write((json.dumps(receipt) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(root)
        if read_private(state_path) != current:
            raise ValueError('Fixture changed concurrently; retained recovery receipt')
        write_atomic(state_path, changed)
        return {'receipt': token, 'scenario': scenario, 'status': 'awaiting-normal-reconciliation'}
    if action != 'restore':
        raise ValueError('Unknown fixture action')
    receipt = json.loads(read_private(receipt_path))
    original = base64.b64decode(receipt['originalBase64'], validate=True)
    if digest(current) not in {receipt['changedSHA256'], digest(original)}:
        raise ValueError('Concurrent fixture change; refusing to overwrite it')
    # Synthetic uSN values only provide within-read consistency. Exact original
    # state restoration is supported by this fixture and changes no AD policy.
    write_atomic(state_path, original)
    receipt_path.unlink()
    sync_directory(root)
    return {'receipt': token, 'status': 'original-restored-awaiting-normal-reconciliation'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest', action='store_true', help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest='action', required=True)
    begin = commands.add_parser('begin')
    begin.add_argument('scenario', choices=sorted(SCENARIOS))
    begin.add_argument('--receipt', help=argparse.SUPPRESS)
    restore = commands.add_parser('restore')
    restore.add_argument('receipt')
    args = parser.parse_args()
    token = args.receipt or uuid.uuid4().hex
    if args.guest:
        if os.geteuid() != 21902:
            raise ValueError('Guest scenarios require the isolated source UID21902')
        print(json.dumps(transition(FIXTURE_ROOT, args.action, token, getattr(args, 'scenario', None))))
        return
    spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check-dashboard-infra.py'))
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    command = ['sudo', '-u', 'jobman-dashboard-source', 'python3', '-', '--guest', args.action]
    command += [args.scenario, '--receipt', token] if args.action == 'begin' else [token]
    result = checks.ssh('control01', shlex.join(command), Path(__file__).read_text())
    if result.returncode:
        print(json.dumps({'receipt': token, 'status': 'transition-failed-inspect-private-receipt'}))
        raise RuntimeError('Synthetic directory transition failed; inspect private receipt')
    print(result.stdout.strip())


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError):
        print('Synthetic directory transition failed; preserve private receipts and inspect the isolated fixture.', file=sys.stderr)
        raise SystemExit(1) from None
