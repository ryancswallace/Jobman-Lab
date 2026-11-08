#!/usr/bin/env python3
"""Reproduce a reviewed release selection without developer state or credentials."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORIES = {'core': 'ryancswallace/Jobman', 'control': 'ryancswallace/Jobman-Control',
                'diagnose': 'ryancswallace/Jobman-Diagnose', 'dashboard': 'ryancswallace/Jobman-Dashboard'}
EXECUTABLES = {'core': {'jobman', 'jobman-agent'}, 'control': {'jobman-control'},
               'diagnose': {'jobman-diagnose'}, 'dashboard': {'jobman-dashboard', 'jobman-log-broker'}}
SHA = re.compile('[a-f0-9]{40}')
DIGEST = re.compile('[a-f0-9]{64}')
VERSION = re.compile(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?')


def require(value, message):
    if not value:
        raise ValueError(message)


def capture(args, cwd=None, env=None, timeout=120, limit=4 * 1024 * 1024, allowed_codes=(0,)):
    # Temporary pipes/files never become public logs or contain reusable output.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=output,
                                stderr=subprocess.DEVNULL, timeout=timeout)
        require(result.returncode in allowed_codes, 'Command failed: ' + Path(args[0]).name)
        require(output.tell() <= limit, 'Command output exceeds limit')
        output.seek(0)
        return output.read()


def api(path):
    return json.loads(capture(['gh', 'api', path]))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, 'Duplicate manifest field')
        result[name] = value
    return result


def read_manifest(path):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 1024 * 1024,
            'Manifest must be a bounded regular file')
    value = json.loads(path.read_text(), object_pairs_hook=unique)
    require(type(value.get('schemaVersion')) is int and value['schemaVersion'] == 1 and set(value.get('products', {})) == set(REPOSITORIES),
            'Manifest must select all four products')
    require(value.get('platform') in ('linux/amd64', 'linux/arm64'), 'Select an explicit supported Linux platform')
    for name, product in value['products'].items():
        require(product.get('repository') == REPOSITORIES[name] and SHA.fullmatch(product.get('commit', ''))
                and VERSION.fullmatch(product.get('version', '')), 'Invalid immutable product identity')
        for item in ('archive', 'sbom', 'checksums'):
            asset = product[item]
            require(re.fullmatch('[A-Za-z0-9_.-]{1,200}', asset['name'])
                    and DIGEST.fullmatch(asset['sha256']), 'Invalid release asset identity')
        require(set(product.get('executables', {})) == EXECUTABLES[name], 'Executable inventory differs from product boundary')
        for binary, item in product['executables'].items():
            require(binary in ('jobman', 'jobman-agent', 'jobman-control', 'jobman-diagnose',
                               'jobman-dashboard', 'jobman-log-broker'), 'Unexpected executable')
            safe_path(item['path'])
            require(DIGEST.fullmatch(item['sha256']), 'Executable digest is required')
    return value


def safe_path(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '..' not in path.parts
            and path.as_posix() == name and '\\' not in name, 'Unsafe archive path')
    return path


def unpack(data, destination):
    require(not destination.exists(), 'Archive destination must be new')
    destination.mkdir(mode=0o700)
    observed, total = set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for member in archive:
            relative = safe_path(member.name)
            require(member.isdir() or member.isfile(), 'Archive links and special files are forbidden')
            require(member.name not in observed and len(observed) < 20000, 'Duplicate or oversized archive inventory')
            observed.add(member.name)
            total += member.size
            require(0 <= total <= 1024 * 1024 * 1024, 'Archive expands beyond limit')
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as output, archive.extractfile(member) as source:
                shutil.copyfileobj(source, output, 1024 * 1024)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def selected_commit(repository, version):
    reference = api(f'repos/{repository}/git/ref/tags/{version}')['object']
    for _ in range(4):
        if reference['type'] == 'commit':
            return reference['sha']
        require(reference['type'] == 'tag' and SHA.fullmatch(reference['sha']), 'Invalid tag object')
        reference = api(f'repos/{repository}/git/tags/{reference["sha"]}')['object']
    raise ValueError('Tag indirection exceeds limit')


def new_output(path):
    require(path.is_absolute() and not path.exists() and not path.is_symlink(), 'Output must be a new absolute path')
    path.mkdir(mode=0o700)


def fetch(manifest, output):
    new_output(output)
    (output / 'bin').mkdir()
    receipt = {'schemaVersion': 1, 'platform': manifest['platform'], 'products': {},
               'verification': ['manifest SHA-256', 'release checksums', 'exact-source GitHub attestations']}
    for name, product in manifest['products'].items():
        repository, version = product['repository'], product['version']
        require(selected_commit(repository, version) == product['commit'], 'Selected release tag moved')
        release = api(f'repos/{repository}/releases/tags/{version}')
        require(release['draft'] is False and release['prerelease'] is ('-rc.' in version), 'Release channel differs')
        directory = output / name
        directory.mkdir()
        for kind in ('archive', 'sbom', 'checksums'):
            asset = product[kind]
            capture(['gh', 'release', 'download', version, '--repo', repository, '--pattern',
                     asset['name'], '--dir', str(directory)], timeout=600)
            require(digest(directory / asset['name']) == asset['sha256'], 'Downloaded release digest differs')
        checksums = {}
        for line in (directory / product['checksums']['name']).read_text().splitlines():
            match = re.fullmatch(r'([a-f0-9]{64})\s+\*?([A-Za-z0-9_.-]+)', line)
            require(match is not None and match[2] not in checksums, 'Invalid or duplicate checksum record')
            checksums[match[2]] = match[1]
        for kind in ('archive', 'sbom'):
            asset = product[kind]
            require(checksums.get(asset['name']) == asset['sha256'], 'Release checksum differs')
            capture(['gh', 'attestation', 'verify', str(directory / asset['name']), '--repo', repository,
                     '--source-digest', product['commit'], '--signer-workflow', repository + '/.github/workflows/release.yml',
                     '--deny-self-hosted-runners'], timeout=180)
        unpack((directory / product['archive']['name']).read_bytes(), directory / 'unpacked')
        executables = {}
        for binary, selected in product['executables'].items():
            source = directory / 'unpacked' / selected['path']
            require(source.is_file() and not source.is_symlink() and digest(source) == selected['sha256'],
                    'Selected executable differs')
            target = output / 'bin' / binary
            require(not target.exists(), 'Duplicate executable selection')
            shutil.copyfile(source, target)
            target.chmod(0o755)
            executables[binary] = selected['sha256']
        receipt['products'][name] = {'version': version, 'commit': product['commit'], 'executables': executables,
                                     'archiveSHA256': product['archive']['sha256'], 'sbomSHA256': product['sbom']['sha256']}
    (output / 'verification.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (output / 'selection.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'verified': True, 'products': len(receipt['products']), 'platform': manifest['platform']}))


def check_sources(manifest, sources):
    for name, root in sources.items():
        require(not capture(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=root).strip(),
                'Evaluation source checkout is dirty: ' + name)
        require(capture(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip() == manifest['products'][name]['commit'],
                'Evaluation source revision differs: ' + name)


def build(manifest, sources, output):
    check_sources(manifest, sources)
    new_output(output)
    for name, root in sources.items():
        archive = capture(['git', 'archive', manifest['products'][name]['commit']], cwd=root, limit=128 * 1024 * 1024)
        unpack(archive, output / ('source-' + name))
        source = output / ('source-' + name)
        for goos in ('linux', 'windows'):
            target = output / 'bin' / (goos + '-arm64')
            target.mkdir(parents=True, exist_ok=True)
            binaries = {'jobman': '.', 'jobman-agent': './cmd/jobman-agent'} if name == 'core' else {'jobman-control': '.'}
            for binary, package in binaries.items():
                env = {key: os.environ[key] for key in ('PATH', 'HOME', 'GOCACHE', 'GOMODCACHE') if key in os.environ}
                env.update(GOTOOLCHAIN='go' + (source / 'go.version').read_text().strip(), GOENV='off',
                           GOWORK='off', CGO_ENABLED='0', GOOS=goos, GOARCH='arm64')
                capture(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-o',
                         str(target / (binary + ('.exe' if goos == 'windows' else ''))), package], cwd=source, env=env, timeout=600)
    check_sources(manifest, sources)
    receipt = {'schemaVersion': 1, 'sourceMode': 'clean immutable Git archives',
               'sources': {name: manifest['products'][name]['commit'] for name in sources},
               'files': {str(path.relative_to(output)): digest(path) for path in (output / 'bin').rglob('*') if path.is_file()}}
    (output / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('fetch', 'check-sources', 'build'))
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--core', type=Path)
    parser.add_argument('--control', type=Path)
    args = parser.parse_args()
    manifest = read_manifest(args.manifest)
    if args.command == 'fetch':
        require(args.output is not None, 'Output is required')
        fetch(manifest, args.output)
    else:
        require(args.core is not None and args.control is not None, 'Explicit source directories are required')
        sources = {'core': args.core, 'control': args.control}
        if args.command == 'build':
            require(args.output is not None, 'Output is required')
            build(manifest, sources, args.output)
        else:
            check_sources(manifest, sources)
            print('Clean source revisions match the evaluation selection.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Evaluation stopped; no credential or command output is disclosed.') from None
