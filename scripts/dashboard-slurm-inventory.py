#!/usr/bin/env python3
"""Pin exactly the three existing, already-running Slurm VMs; never start them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess

ROOT = Path(__file__).resolve().parent.parent
NODES = ('slurmctl01', 'submit01', 'compute01')


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'Expected regular bounded file')
        data = source.read(maximum + 1)
        require(len(data) <= maximum, 'Input exceeds bound')
        return data


def run(args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=60)
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'Read-only VM inventory command failed')
    return result.stdout


def write_once(path, data):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        require(read(path) == data, 'Retained inventory differs; review before replacing')
    else:
        with os.fdopen(fd, 'wb') as target:
            os.fchmod(target.fileno(), 0o600)
            target.write(data)
            target.flush()
            os.fsync(target.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    raw = read(args.plan)
    require(hashlib.sha256(raw).hexdigest() == args.expected_sha256, 'Reviewed resume plan changed')
    plan = json.loads(raw)
    require(tuple(n['name'] for n in plan['resume']) == NODES and plan['synthetic'] is True, 'Unexpected VM scope')
    state = ROOT / '.lab/dashboard-slurm'
    try:
        state.mkdir(mode=0o700)
        os.chmod(state, 0o700)
    except FileExistsError:
        pass
    info = state.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(), 'Private inventory directory differs')
    hosts, identities, keys = {}, {}, []
    for node in plan['resume']:
        name = node['name']
        identifier = read(ROOT / '.vagrant/machines' / name / 'parallels/id', 128).decode().strip()
        require(identifier == node['vmId'] and re.fullmatch(r'[0-9a-f-]{36}', identifier), 'Vagrant VM identity changed')
        require(re.search(r'\brunning\b', run(['prlctl', 'status', 'jobman-lab-' + name])), 'Required VM is not running')
        endpoint = {}
        for line in run(['vagrant', 'ssh-config', name]).splitlines():
            values = shlex.split(line)
            if len(values) == 2 and values[0] in ('HostName', 'User', 'Port', 'IdentityFile'):
                endpoint[values[0]] = values[1]
        require(set(endpoint) == {'HostName', 'User', 'Port', 'IdentityFile'}, 'Incomplete Vagrant SSH configuration')
        raw_key = run(['prlctl', 'exec', identifier, 'cat', '/etc/ssh/ssh_host_ed25519_key.pub'])
        candidates = [line.split()[:2] for line in raw_key.splitlines() if re.match(r'^ssh-ed25519 [A-Za-z0-9+/=]+(?:\s|$)', line)]
        require(len(candidates) == 1, 'VM-bound host public key unavailable')
        key = ' '.join(candidates[0])
        address = endpoint['HostName'] if endpoint['Port'] == '22' else '[' + endpoint['HostName'] + ']:' + endpoint['Port']
        keys.append(address + ' ' + key + '\n')
        identities[name] = {'vm_id': identifier, 'host_key': key}
        hosts[name] = {'ansible_host': endpoint['HostName'], 'ansible_user': endpoint['User'], 'ansible_port': int(endpoint['Port']), 'ansible_ssh_private_key_file': endpoint['IdentityFile']}
    write_once(state / 'vm-host-keys.json', (json.dumps(identities, sort_keys=True) + '\n').encode())
    write_once(state / 'known_hosts', ''.join(keys).encode())
    write_once(state / 'ssh-connections.json', (json.dumps(hosts, sort_keys=True) + '\n').encode())
    print('Pinned only the three existing Slurm VM identities; no VM or original inventory mutation.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        raise SystemExit('Slurm inventory verification failed; retained state was not reset.') from None
