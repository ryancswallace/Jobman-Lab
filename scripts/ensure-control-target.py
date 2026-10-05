#!/usr/bin/env python3
"""Create missing synthetic targets; reuse only an exactly matching active target."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

ORIGIN = 'https://control01.lab.test:8080'


def validate(expected, actual):
    if actual.get('apiVersion') != expected.get('apiVersion') or actual.get('kind') != 'Target':
        raise RuntimeError('Existing target contract differs')
    meta = actual.get('metadata', {})
    if meta.get('namespace') != 'research' or meta.get('name') != expected['metadata']['name']:
        raise RuntimeError('Existing target identity differs')
    for key in ('id', 'generationId'):
        value = meta.get(key, '')
        if str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
            raise RuntimeError('Existing target identifier invalid')
    if actual.get('status', {}).get('state') != 'active':
        raise RuntimeError('Existing target is not active')
    wanted, found = dict(expected['spec']), dict(actual['spec'])
    for spec in (wanted, found):
        spec.setdefault('controlTransport', 'agent-api')
        spec.setdefault('partitions', [])
    if wanted != found:
        raise RuntimeError('Existing target configuration differs; refusing to replace it')


def ensure(expected, request):
    name = expected.get('metadata', {}).get('name', '')
    if name not in ('onprem-slurm', 'linux-workstation', 'windows-workstation'):
        raise RuntimeError('Unexpected synthetic target name')
    path = '/v1/namespaces/research/targets/' + name
    status, actual = request('GET', path)
    if status == 404:
        status, actual = request('POST', '/v1/namespaces/research/targets')
        if status == 409:  # A concurrent creator may have won; verify, never overwrite.
            status, actual = request('GET', path)
    if status not in (200, 201):
        raise RuntimeError('Target setup failed with HTTP ' + str(status))
    validate(expected, actual)
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('curl_config', type=Path)
    parser.add_argument('request', type=Path)
    parser.add_argument('response', type=Path)
    args = parser.parse_args()
    expected = json.loads(args.request.read_text())
    # Response bodies stay in a private temporary file and are never logged.
    with tempfile.TemporaryDirectory(prefix='jobman-target-') as directory:
        output = Path(directory) / 'response.json'
        def request(method, path):
            command = ['curl', '--config', str(args.curl_config), '--max-time', '15',
                       '--max-filesize', '1048576', '--request', method,
                       '--output', str(output), '--write-out', '%{http_code}']
            if method == 'POST':
                command += ['--header', 'Content-Type: application/json', '--header',
                            'Idempotency-Key: lab-target-' + expected['metadata']['name'] + '-v1',
                            '--data-binary', '@' + str(args.request)]
            result = subprocess.run(command + [ORIGIN + path], capture_output=True, text=True, timeout=20)
            if result.returncode not in (0, 22) or not re.fullmatch(r'\d{3}', result.stdout):
                raise RuntimeError('Target request failed; credentials and response withheld')
            status = int(result.stdout)
            if status not in (200, 201):
                return status, {}
            if output.stat().st_size > 1048576:
                raise RuntimeError('Target response exceeds bound')
            return status, json.loads(output.read_text())
        actual = ensure(expected, request)
    args.response.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.target-', dir=args.response.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(actual, stream)
            stream.write('\n')
        os.replace(temporary, args.response)
    finally:
        Path(temporary).unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        # No raw provider response, command arguments or secrets in diagnostics.
        raise SystemExit('Synthetic target verification failed: ' + type(error).__name__)
