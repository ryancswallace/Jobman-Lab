#!/usr/bin/env python3
"""Run verified Linux releases in new, isolated, disposable Docker resources."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

from evaluation import ROOT, capture, digest, read_manifest, require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = read_manifest(args.manifest)
    require(not args.output.exists() and args.output.is_absolute(), 'Result must be a new absolute file')
    require(not capture(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT).strip(),
            'Commit the evaluation harness before running acceptance')
    require(json.loads((args.inputs / 'selection.json').read_text()) == manifest, 'Verified input selection differs')
    runtime = manifest['runtime']
    for role, image in [('runner', runtime['runnerImage']), ('postgres', runtime['postgresImage'])]:
        repository = 'busybox' if role == 'runner' else 'postgres'
        require(re.fullmatch('docker.io/library/' + repository + '@sha256:[a-f0-9]{64}', image),
                'Runtime image must be the selected immutable official image')
    require(re.fullmatch(r'go1\.[0-9]+\.[0-9]+', runtime['goToolchain']), 'Exact Go toolchain is required')
    suffix = uuid.uuid4().hex[:16]
    network, database, runner = ['jobman-evaluation-' + suffix + '-' + role for role in ('net', 'db', 'run')]
    receipt = {'schemaVersion': 1, 'passed': False, 'selectionSHA256': digest(args.manifest),
               'labRevision': capture(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
               'harnessSHA256': digest(ROOT / 'evaluation/smoke.go'), 'runtime': runtime}
    try:
        with tempfile.TemporaryDirectory(prefix='jobman-release-smoke-') as temporary:
            root = Path(temporary)
            payload = root / 'payload'
            payload.mkdir(mode=0o755)
            (payload / 'bin').mkdir()
            for product in manifest['products'].values():
                for name, item in product['executables'].items():
                    source = args.inputs / 'bin' / name
                    require(source.is_file() and not source.is_symlink() and digest(source) == item['sha256'],
                            'Executable changed after verification')
                    shutil.copyfile(source, payload / 'bin' / name)
                    (payload / 'bin' / name).chmod(0o755)
            dashboard = manifest['products']['dashboard']['executables']['jobman-dashboard']['path']
            web = (args.inputs / 'dashboard/unpacked' / dashboard).parent.parent / 'web'
            require(web.is_dir() and not web.is_symlink(), 'Selected Dashboard web payload is absent')
            shutil.copytree(web, payload / 'web')
            driver = root / 'smoke'
            env = {key: os.environ[key] for key in ('PATH', 'HOME', 'GOCACHE', 'GOMODCACHE') if key in os.environ}
            env.update(GOENV='off', GOWORK='off', GOTOOLCHAIN=runtime['goToolchain'], CGO_ENABLED='0',
                       GOOS='linux', GOARCH=manifest['platform'].split('/')[1])
            capture(['go', 'build', '-trimpath', '-o', str(driver), str(ROOT / 'evaluation/smoke.go')], env=env, timeout=300)
            receipt['driverSHA256'] = digest(driver)
            for image in (runtime['runnerImage'], runtime['postgresImage']):
                capture(['docker', 'pull', '--platform', manifest['platform'], image], timeout=600)
            capture(['docker', 'network', 'create', '--internal', network])
            capture(['docker', 'run', '-d', '--name', database, '--network', network, '--network-alias', 'postgres',
                     '--user', 'postgres:postgres', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                     '--tmpfs', '/var/lib/postgresql/data:rw,uid=70,gid=70,mode=0700', '--tmpfs', '/var/run/postgresql:rw,uid=70,gid=70',
                     '-e', 'POSTGRES_PASSWORD=evaluation-only', '-e', 'POSTGRES_DB=evaluation', runtime['postgresImage']], timeout=60)
            # The fresh database is the only endpoint available on this internal network.
            capture(['docker', 'exec', database, 'sh', '-c',
                     'for n in $(seq 1 60); do pg_isready -h 127.0.0.1 -U postgres -d evaluation >/dev/null && exit 0; sleep 1; done; exit 1'], timeout=70)
            output = capture(['docker', 'run', '--rm', '--name', runner, '--network', network, '--hostname', 'jobman-evaluation',
                              '--platform', manifest['platform'], '--user', '65534:65534', '--read-only', '--cap-drop', 'ALL',
                              '--security-opt', 'no-new-privileges', '--tmpfs', '/work:rw,uid=65534,gid=65534,mode=0700',
                              '--mount', f'type=bind,source={payload},target=/inputs,readonly',
                              '--mount', f'type=bind,source={driver},target=/smoke,readonly',
                              '--entrypoint', '/smoke', runtime['runnerImage']], timeout=270, allowed_codes=(0, 1))
            result = json.loads(output)
            receipt['results'] = result
            require(result.get('passed') is True, 'Synthetic smoke did not pass')
            receipt['passed'] = True
    finally:
        for name in (runner, database):
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        with args.output.open('x') as output:
            json.dump(receipt, output, indent=2)
            output.write('\n')
    print(json.dumps({'passed': True, 'platform': manifest['platform'], 'selectionSHA256': receipt['selectionSHA256']}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        raise SystemExit('Synthetic evaluation stopped; inspect the retained sanitized receipt.') from None
