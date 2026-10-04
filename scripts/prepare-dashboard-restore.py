#!/usr/bin/env python3
"""Write a new private offline restore plan; never snapshot or change a guest."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

spec = importlib.util.spec_from_file_location('restore_plan', Path(__file__).with_name('dashboard-restore-plan.py'))
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def prepare(archive, archive_sha, api, worker, snapshot, output):
    output = Path(output)
    plan.require(output.is_absolute() and output.resolve() == output, 'Real absolute output path required')
    parent = output.parent.lstat()
    plan.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and
                 stat.S_IMODE(parent.st_mode) == 0o700, 'Private operator-owned parent required')
    plan.require(not output.exists() and not output.is_symlink(), 'New staging required; never overwrite partial preparation')
    metadata, files = plan.shared.candidate_files(archive, archive_sha)
    inputs = {name: plan.private_read(path) for name, path in [('api', api), ('worker', worker), ('snapshot', snapshot)]}
    receipt, generated = plan.make_plan(metadata, archive_sha, inputs)
    plan.directory(output)
    # Completion marker is last; every earlier artifact remains private and an
    # interrupted directory is never implicitly promoted or reused.
    for name in ('inputs', 'configs', 'grants', 'candidate'):
        plan.directory(output / name)
    for name, raw in inputs.items():
        plan.write_new(output / 'inputs' / (name + '.json'), raw)
    for role, config in generated.items():
        plan.write_new(output / 'configs' / (role + '.json'), plan.encoded(config))
    # Keep exact package metadata and grant source, not private source keys.
    for name in ('build.json', 'SHA256SUMS', 'deploy/postgres/grants.py', 'deploy/postgres/grants.json'):
        target = output / 'candidate' / name
        current = output / 'candidate'
        for part in target.parent.relative_to(current).parts:
            current = current / part
            if not current.exists():
                plan.directory(current)
        plan.write_new(target, files[name])
    for role, components in plan.COMPONENTS.items():
        args = ['python3', str(output / 'candidate/deploy/postgres/grants.py'), '--schema', 'public',
                '--role', plan.DATABASE + '_' + role]
        for component in components:
            args.extend(['--component', component])
        result = subprocess.run(args, capture_output=True, timeout=15, check=False,
                                env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'PYTHONNOUSERSITE': '1'})
        plan.require(result.returncode == 0 and 0 < len(result.stdout) <= 1 << 20, 'Reviewed grant rendering failed')
        plan.write_new(output / 'grants' / (role + '.sql'), result.stdout)
    receipt['preparedFiles'] = {}
    for path in sorted(output.rglob('*')):
        if path.is_file():
            raw = plan.private_read(path, 1 << 20)
            receipt['preparedFiles'][path.relative_to(output).as_posix()] = plan.sha(raw)
    receipt['implementationSHA256'] = {name: plan.sha(Path(__file__).with_name(name).read_bytes()) for name in
                                       ('dashboard-restore-plan.py', 'prepare-dashboard-restore.py', 'dashboard-split-plan.py')}
    plan.write_new(output / 'plan.json', plan.encoded(receipt))
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--api-config', required=True, type=Path)
    parser.add_argument('--worker-config', required=True, type=Path)
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--output-directory', required=True, type=Path)
    args = parser.parse_args()
    prepare(args.candidate, args.candidate_sha256, args.api_config, args.worker_config, args.snapshot, args.output_directory)
    print(json.dumps({'prepared': True, 'applied': False, 'planSHA256': plan.sha(plan.private_read(args.output_directory / 'plan.json', 1 << 20))}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Restore preparation failed. Retain private partial evidence; no guest, database, credential or service was changed.') from None
