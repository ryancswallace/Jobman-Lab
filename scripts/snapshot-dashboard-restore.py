#!/usr/bin/env python3
"""Read-only fresh Lab snapshots for the offline restore planner; never apply."""
import argparse
import base64
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

plan = load('restore_plan', 'dashboard-restore-plan.py')
ssh = load('restore_ssh', 'apply-dashboard-split.py')


def remote(lab, host, payload):
    plan.require(host in ('pg01', 'storage01'), 'Read-only approved guest required')
    connection = ssh.ssh_connections(lab)[host]
    code = (HERE / 'dashboard-restore-guest.py').read_text()
    args = ['ssh', '-i', connection['ansible_ssh_private_key_file'], '-p', str(connection['ansible_port']),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(lab / '.lab/dashboard/known_hosts'), '-o', 'HostKeyAlgorithms=ssh-ed25519',
            connection['ansible_user'] + '@' + connection['ansible_host'], shlex.join(['sudo', 'python3', '-c', code])]
    result = subprocess.run(args, input=plan.encoded(dict(payload, host=host)), capture_output=True, timeout=90, check=False)
    plan.require(result.returncode == 0 and len(result.stdout) <= 4 << 20, 'Read-only snapshot failed; retain private partial evidence')
    return plan.decode(result.stdout)


def assemble(storage, database, metadata):
    now = time.time()
    plan.require(all(abs(record['epoch'] - now) <= 10 for record in (storage, database)), 'Host/guest clocks or snapshot age differ')
    raw = {role: base64.b64decode(storage['configs'][role], validate=True) for role in ('api', 'worker')}
    plan.require(all(0 < len(value) <= 256 << 10 for value in raw.values()), 'Config snapshot bound exceeded')
    configs = {role: plan.decode(value) for role, value in raw.items()}
    ledger = database['ledger']
    plan.require(len(ledger) == 18 and len({v['name'] for v in ledger}) == 18 and
                 all(plan.shared.HEX.fullmatch(v['sha256']) and v['name'].startswith('migrations/') for v in ledger), 'Complete candidate ledger required')
    capabilities = {value['deploymentId']: value for value in storage['capabilities']}
    plan.require(len(capabilities) == len(storage['capabilities']) == len(database['sources']), 'Capability/source set differs')
    for source in database['sources']:
        value = capabilities.get(source['deploymentId'])
        plan.require(value and value['instanceId'] == source['controlInstanceId'] and value['recoveryEpoch'] == source['recoveryEpoch'], 'Live Control and retained feed pins differ')
        plan.require(abs(plan.timestamp(value['serviceTime']).timestamp() - now) <= 10, 'Source clock differs')
    snapshot = {'formatVersion': 1, 'synthetic': True, 'database': 'jobman_dashboard', 'candidateRevision': metadata['revision'],
                'configurationRevision': configs['api']['configurationRevision'], 'capturedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'apiSHA256': plan.sha(raw['api']), 'workerSHA256': plan.sha(raw['worker']),
                'schema': {'migrationCount': 18, 'ledgerSHA256': plan.sha(plan.encoded(ledger))},
                'hold': database['hold'], 'sources': database['sources'], 'files': storage['files'],
                'processes': storage['processes'], 'capabilities': storage['capabilities'],
                'resources': {'databaseBytes': database['databaseBytes'], 'pgFreeBytes': database['freeBytes'],
                              'storageFreeBytes': storage['freeBytes'], 'memAvailableBytes': storage['memAvailableBytes'],
                              'availableConnectionSlots': database['availableConnectionSlots']},
                'hbaSHA256': database['hbaSHA256']}
    raw['snapshot'] = plan.encoded(snapshot)
    # Reuse the complete offline guard before recording any successful snapshot.
    plan.make_plan(metadata, 'a' * 64, raw)
    return raw


def snapshot(args):
    output = args.output_directory
    plan.require(output.is_absolute() and output.resolve() == output, 'Real absolute snapshot destination required')
    parent = output.parent.lstat()
    plan.require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700,
                 'Private operator-owned snapshot parent required')
    plan.require(not output.exists() and not output.is_symlink(), 'Fresh snapshot directory required')
    metadata, files = plan.shared.candidate_files(args.candidate, args.candidate_sha256)
    request = {'phase': 'snapshot', 'candidate': {'revision': metadata['revision'], 'binarySHA256': plan.sha(files['bin/jobman-dashboard'])}}
    plan.directory(output)
    records = {}
    for host in ('storage01', 'pg01'):
        records[host] = remote(args.lab_root, host, request)
        plan.write_new(output / (host + '.json'), plan.encoded(records[host]))
    assembled = assemble(records['storage01'], records['pg01'], metadata)
    for name, raw in assembled.items():
        plan.write_new(output / (name + '.json'), raw)
    summary = {'snapshotComplete': True, 'guestMutations': False, 'candidateRevision': metadata['revision'],
               'files': {name: plan.sha(raw) for name, raw in assembled.items()},
               'implementationSHA256': {name: plan.sha((HERE / name).read_bytes()) for name in
                                        ('snapshot-dashboard-restore.py', 'dashboard-restore-guest.py', 'dashboard-restore-plan.py')}}
    plan.write_new(output / 'complete.json', plan.encoded(summary))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-root', required=True, type=Path)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--output-directory', required=True, type=Path)
    print(json.dumps(snapshot(parser.parse_args()), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Read-only restore snapshot failed; preserve private partial output. No guest mutation was attempted.') from None
