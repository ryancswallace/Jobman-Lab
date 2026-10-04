#!/usr/bin/env python3
"""Prepare a new private split-runtime plan and artifact tree; never apply it.

Inputs must be current private config snapshots. Live preflight must compare
their SHA256 values again before any migration, identity or service change.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess

spec = importlib.util.spec_from_file_location('split_plan', Path(__file__).with_name('dashboard-split-plan.py'))
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def run(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=30, check=False)
    plan.require(result.returncode == 0 and len(result.stdout) <= 1 << 20, 'Private preparation command failed; inspect retained staging')
    return result.stdout


def key_material(root, role):
    # Four independently revocable pairs: API/worker x Control/broker. CSRs are
    # signed later by the appropriate CA on its existing host. The fixture CA
    # private key never leaves control01. No CSR confers runtime authority.
    for kind in ('control', 'broker'):
        prefix = root / (role + '-' + kind)
        key = Path(str(prefix) + '-client.key')
        csr = Path(str(prefix) + '-client.csr')
        signing = Path(str(prefix) + '-signing-key.pem')
        public = Path(str(prefix) + '-signing-public.pem')
        run(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-subj', '/CN=' + plan.service(role, kind),
             '-addext', 'extendedKeyUsage=clientAuth', '-addext', 'keyUsage=critical,digitalSignature',
             '-addext', 'subjectAltName=URI:urn:jobman:dashboard-lab:' + role + ':' + kind,
             '-keyout', str(key), '-out', str(csr)])
        run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(signing)])
        run(['openssl', 'pkey', '-in', str(signing), '-pubout', '-out', str(public)])
        for path in (key, csr, signing, public):
            path.chmod(0o600)


def prepare(archive, archive_sha, app_path, broker_path, fixture_path, output):
    output = Path(output)
    plan.require(output.is_absolute() and str(output) == os.path.normpath(output), 'Clean absolute staging path required')
    parent = output.parent.lstat()
    plan.require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700 and parent.st_uid == os.getuid(),
                 'Staging parent must be private and operator-owned')
    plan.require(not output.exists() and not output.is_symlink(), 'Staging must be new; partial preparations are never overwritten')
    metadata, files = plan.candidate_files(archive, archive_sha)
    raw_inputs = {key: plan.read(path, 1 << 20, private=True) for key, path in
                  [('app', app_path), ('broker', broker_path), ('fixture', fixture_path)]}
    receipt, generated = plan.make_plan(metadata, archive_sha, raw_inputs)
    output.mkdir(mode=0o700)
    # The plan is written LAST as the preparation completion marker. Partial
    # destinations contain only private material and are retained for inspection.
    for name in ('candidate', 'inputs', 'configs', 'units', 'grants', 'material'):
        (output / name).mkdir(mode=0o700)
    for name, raw in files.items():
        target = output / 'candidate' / name
        parent = output
        for part in target.parent.relative_to(output).parts:
            parent = parent / part
            parent.mkdir(exist_ok=True, mode=0o700)
        plan.write_new(target, raw, 0o700 if name.startswith('bin/') else 0o600)
    for key, raw in raw_inputs.items():
        plan.write_new(output / 'inputs' / (key + '.json'), raw)
    for role, config in generated.items():
        plan.write_new(output / 'configs' / (role + '.json'), plan.encoded(config))
    for role in ('api', 'worker'):
        plan.write_new(output / 'units' / ('jobman-dashboard-lab-' + role + '.service'), plan.unit(role, receipt['releaseRoot']).encode())
        key_material(output / 'material', role)
    plan.write_new(output / 'units/jobman-dashboard-lab-broker.service', plan.broker_unit(receipt['releaseRoot']).encode())
    for role, components in plan.ROLE_COMPONENTS.items():
        args = ['python3', str(output / 'candidate/deploy/postgres/grants.py'), '--schema', 'public', '--role', 'jobman_dashboard_' + role]
        for component in components:
            args.extend(['--component', component])
        plan.write_new(output / 'grants' / (role + '.sql'), run(args))
    # Passwords are independent of the existing owner/combined identities. The
    # apply phase must refuse conflicting role ownership rather than rotate it.
    plan.write_new(output / 'material/database-passwords.json', plan.encoded({role: secrets.token_hex(32) for role in plan.ROLE_COMPONENTS}))
    receipt['preparedFiles'] = {}
    receipt['preparedFileBytes'] = {}
    for path in sorted(output.rglob('*')):
        if path.is_file():
            raw = plan.read(path, 96 << 20)
            receipt['preparedFiles'][path.relative_to(output).as_posix()] = plan.sha(raw)
            receipt['preparedFileBytes'][path.relative_to(output).as_posix()] = len(raw)
    receipt['implementationSHA256'] = {name: plan.sha(plan.read(Path(__file__).with_name(name),1<<20)) for name in
        ('apply-dashboard-split.py','dashboard-split-guest.py','dashboard-split-files.py')}
    plan.write_new(output / 'plan.json', plan.encoded(receipt))
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--app-config', type=Path, required=True)
    parser.add_argument('--broker-config', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    previous = os.umask(0o077)
    try:
        receipt = prepare(args.candidate, args.candidate_sha256, args.app_config, args.broker_config, args.fixture, args.output_directory)
        print(json.dumps({'prepared': True, 'applied': False, 'revision': receipt['revision'],
                          'planSHA256': plan.sha(plan.read(args.output_directory / 'plan.json', 4 << 20))}))
    finally:
        os.umask(previous)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Split preparation failed. Retain the private partial staging tree; no guest, database or service was changed.') from None
