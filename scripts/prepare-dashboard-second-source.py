#!/usr/bin/env python3
"""Stage public second-source planning evidence only; no guest or DB operations."""
import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('second_source_plan', ROOT / 'scripts/dashboard-second-source-plan.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def stage(destination, payload):
    destination = Path(destination)
    plan.require(destination.is_absolute() and str(destination) == os.path.normpath(destination) and
                 destination.name not in ('', '.', '..'), 'Use a fresh absolute plan directory')
    parent = destination.parent
    info = parent.lstat()
    plan.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                 info.st_uid == os.geteuid() and parent.resolve() == parent,
                 'Plan parent must be a real private directory owned by this user')
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(directory)
        plan.require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), 'Plan parent changed')
        os.mkdir(destination.name, 0o700, dir_fd=directory)
        child = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            fd = os.open('plan.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=child)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(plan.encoded(payload))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(child)
        finally:
            os.close(child)
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control-build', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    metadata = plan.validate_build(args.control_build)
    primary = plan.json_value(plan.read(ROOT / '.lab/dashboard/fixture-info.json', 1 << 20))
    oidc = plan.json_value(plan.read(ROOT / '.lab/dashboard/oidc-public.json', 16384))
    value = plan.make_plan(primary, oidc, metadata)
    stage(args.output_directory, value)
    print('Prepared public secondary-source plan only; helper profile and reviewed provisioning remain required. No services changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Second-source planning failed; inspect public input/build pins and private staging boundary.', file=sys.stderr)
        sys.exit(1)
