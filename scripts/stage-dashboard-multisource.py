#!/usr/bin/env python3
"""Stage an offline additive multi-source plan from private reviewed snapshots.

No SSH, service command, key generation or configuration write to a guest occurs.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('multisource_plan', HERE / 'dashboard-multisource-plan.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def private_directory(path):
    info = path.lstat()
    plan.require(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode) and
                 info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Real private owned directory required')


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        plan.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and
                     info.st_nlink == 1 and 0 < info.st_size <= 1 << 20, 'Bounded private snapshot required')
        raw = stream.read((1 << 20) + 1)
        after = os.fstat(stream.fileno())
        plan.require(len(raw) == info.st_size and (after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                     (info.st_size, info.st_mtime_ns, info.st_ctime_ns), 'Snapshot changed while read')
        return raw


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def stage(snapshot, destination):
    private_directory(snapshot)
    plan.require(destination.is_absolute() and not destination.exists() and not destination.is_symlink(), 'New absolute destination required')
    private_directory(destination.parent)
    before = {role: read(snapshot / (role + '.json')) for role in ('api', 'worker', 'broker', 'operator')}
    fixture_raw = read(snapshot / 'secondary-fixture.json')
    fixture = plan.decode(fixture_raw)
    original = {role: plan.decode(raw) for role, raw in before.items()}
    after = plan.patch(original, fixture)
    review = {'synthetic': True, 'applies': False, 'liveVerifiedByThisCommand': False,
              'currentRevision': 6, 'nextRevision': 7, 'secondaryInstanceId': plan.SECONDARY_INSTANCE,
              'fixtureSHA256': plan.sha(fixture_raw), 'materialPlan': plan.material_plan(original),
              'files': [{'role': role, 'beforeSHA256': plan.sha(before[role]), 'afterSHA256': plan.sha(plan.encoded(after[role])),
                         'path': plan.ROOTS[role] + '/config.json'} for role in before],
              'requiredBeforeApply': ['Actual revision6 runtime verified after Slurm mapping restart.',
                  'Exact current config hashes/owners/modes and package/process identities rechecked.',
                  'Both current Control instance/epoch/namespace/grant registries and source public material hashes verified.',
                  'Original and new broker client-trust bundle hashes retained with source CA verification.',
                  'Persistent global delivery hold remains false with generation3; all existing bindings, source feeds and rules retained.',
                  'Generate only new source2 broker caller keys/certificates in private receipt-bound staging, without copying a CA key.',
                  'Validate every staged config as its exact service identity with the installed candidate.',
                  'Independent apply-driver review and coordinated configuration window; stop on drift.'],
              'fallback': 'No automatic rollback. Preserve exact originals and any incomplete receipt. Once revision7 has been observed, continue the reviewed remaining swaps or prepare a separately reviewed forward revision8+; never restore revision6 or reset a source ledger.'}
    destination.mkdir(mode=0o700); destination.chmod(0o700)
    for role in before:
        write(destination / (role + '.before.json'), before[role])
        write(destination / (role + '.after.json'), plan.encoded(after[role]))
    write(destination / 'review.json', plan.encoded(review))
    for path in (destination, destination.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    return review


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot-directory', required=True, type=Path)
    parser.add_argument('--output-directory', required=True, type=Path)
    args = parser.parse_args()
    review = stage(args.snapshot_directory, args.output_directory)
    print(plan.encoded({'staged': True, 'applied': False, 'reviewSHA256': plan.sha(plan.encoded(review))}).decode(), end='')


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Multi-source offline staging failed; no guest configuration changed. Preserve partial output.', file=sys.stderr)
        sys.exit(1)
