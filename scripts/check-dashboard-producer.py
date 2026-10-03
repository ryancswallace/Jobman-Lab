#!/usr/bin/env python3
"""Run an explicitly supplied Jobman Linux ARM64 ACL test binary in the Lab.

Build in Jobman with: GOOS=linux GOARCH=arm64 go test -c -tags integration
./internal/artifact -o /absolute/path/artifact.test. Only a unique uploaded
binary and a unique Alice-owned synthetic subtree are created/removed.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('dashboard_checks', ROOT / 'scripts/check-dashboard-infra.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def main():
    checks.require(len(sys.argv) == 2, 'Provide the absolute path to a trusted Jobman Linux ARM64 ACL test binary')
    binary = Path(sys.argv[1])
    checks.require(binary.is_absolute() and binary.is_file() and not binary.is_symlink(), 'Binary must be an absolute regular non-symlink file')
    raw = binary.read_bytes()
    checks.require(raw[:6] == b'\x7fELF\x02\x01' and raw[18:20] == b'\xb7\x00', 'Expected a Linux ARM64 ELF binary')
    connection = checks.CONNECTIONS['control01']
    name = 'dashboard-producer-test-' + uuid.uuid4().hex
    remote = '/var/tmp/' + name
    server = '/srv/lab/data/jobman/alice/' + name
    client = '/data/jobman/alice/' + name
    root_created = False
    try:
        args = ['scp', '-i', connection['ansible_ssh_private_key_file'], '-P', str(connection['ansible_port']),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={checks.STATE / "known_hosts"}',
                '-o', 'HostKeyAlgorithms=ssh-ed25519', str(binary),
                f'{connection["ansible_user"]}@{connection["ansible_host"]}:{remote}']
        checks.require(checks.run(args).returncode == 0, 'Test binary upload failed')
        command = 'sudo chown alice:alice ' + shlex.quote(remote) + ' && sudo chmod 0700 ' + shlex.quote(remote)
        checks.require(checks.ssh('control01', command).returncode == 0, 'Test binary ownership failed')
        command = 'sudo -u alice ' + shlex.quote(remote) + " -test.v -test.run 'TestPolicyProducer|TestLogReaderPolicyFileMust|TestPrivateStoreStill'"
        result = checks.ssh('control01', command)
        checks.require(result.returncode == 0 and '--- PASS: TestPolicyProducer' in result.stdout, 'Ordinary-user POSIX producer tests failed or were absent')
        result = checks.ssh('storage01', 'sudo -u alice python3 -',
                            'import os\nos.umask(0o077)\nos.mkdir(' + repr(server) + ',0o750)\n')
        checks.require(result.returncode == 0, 'Disposable NFS root creation failed')
        root_created = True
        command = 'sudo -u alice env JOBMAN_TEST_LOG_READER_ROOT=' + shlex.quote(client) + ' ' + shlex.quote(remote) + " -test.v -test.run '^TestLogReaderProvisionedFilesystem$'"
        result = checks.ssh('control01', command)
        checks.require(result.returncode == 0 and '--- PASS: TestLogReaderProvisionedFilesystem' in result.stdout,
                       'NFS producer test failed or integration-tag test was absent')
        prefix = client + '/namespaces/research/jobs/01990000-0000-7000-8000-000000000001/executions/01990000-0000-7000-8000-000000000002'
        log, private = prefix + '/logs/stdout/00000001.chunk', prefix + '/artifacts/result'
        for user, path, allowed in [('jobman-dashboard-log', log, True), ('jobman-dashboard-log', private, False), ('bob', log, False), ('root', log, False)]:
            result = checks.ssh('control01', 'sudo -u ' + user + ' cat ' + shlex.quote(path) + ' >/dev/null 2>&1')
            checks.require((result.returncode == 0) == allowed, user + ' content read isolation failed')
        checks.require(checks.ssh('control01', 'sudo -u jobman-dashboard-log test -w ' + shlex.quote(log)).returncode != 0, 'Broker can write logs')
        evidence = {'binarySHA256': hashlib.sha256(raw).hexdigest(), 'result': 'passed',
                    'checks': ['ordinary-user POSIX producer', 'NFS4.2 producer', 'broker log read',
                               'private artifact denied', 'Bob denied', 'root-squash read denied', 'broker write denied']}
        (checks.STATE / 'producer-check.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print('PASS: ordinary-user POSIX/NFS producer and actual content isolation; binary SHA256 ' + evidence['binarySHA256'])
    finally:
        if root_created:
            result = checks.ssh('storage01', 'sudo -u alice python3 -', 'import shutil\nshutil.rmtree(' + repr(server) + ')\n')
            checks.require(result.returncode == 0, 'Disposable producer root cleanup failed')
        result = checks.ssh('control01', 'sudo rm -f -- ' + shlex.quote(remote))
        checks.require(result.returncode == 0, 'Disposable producer binary cleanup failed')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Producer check failed; inspect the synthetic fixture privately.', file=sys.stderr)
        sys.exit(1)
