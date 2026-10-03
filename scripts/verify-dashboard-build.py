#!/usr/bin/env python3
"""Verify exact executable/archive digests and safely stage the static tree."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile

MAXIMUM_TREE_BYTES = 64 << 20
MAXIMUM_FILE_BYTES = 8 << 20
MAXIMUM_MEMBERS = 4096


def read_tree(archive):
    files, directories, names = {}, set(), set()
    total = 0
    with tarfile.open(archive, 'r:gz') as source:
        for index, member in enumerate(source):
            path = PurePosixPath(member.name)
            if index >= MAXIMUM_MEMBERS or path.is_absolute() or '..' in path.parts or '\\' in member.name or '\x00' in member.name or len(member.name) > 4096:
                raise ValueError('Invalid static archive member path/bound')
            if str(path) == '.':
                if not member.isdir():
                    raise ValueError('Static archive root must be a directory')
                continue
            name = str(path)
            if name in names or any(len(part) > 255 for part in path.parts):
                raise ValueError('Duplicate or oversized static archive path')
            names.add(name)
            if member.isdir():
                directories.add(name)
                continue
            if not member.isfile() or member.size < 0 or member.size > MAXIMUM_FILE_BYTES:
                raise ValueError('Static archive requires bounded regular files/directories only')
            total += member.size
            if total > MAXIMUM_TREE_BYTES:
                raise ValueError('Static tree exceeds size bound')
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError('Static archive file is unreadable')
            with stream:
                data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError('Static archive file length differs')
            files[name] = data
    if 'index.html' not in files:
        raise ValueError('Static tree has no index.html')
    for name in names:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.' and str(parent) in files:
                raise ValueError('Static archive file cannot be a parent directory')
    return files, directories


def verify_build(root):
    root = Path(root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ValueError('Exact build directory must be absolute and regular')
    metadata = json.loads((root / 'build.json').read_text())
    if metadata.get('platform') != 'linux/arm64' or re.fullmatch('[0-9a-f]{40}', metadata.get('revision', '')) is None:
        raise ValueError('Invalid exact build identity')
    for name in ['jobman-dashboard', 'jobman-log-broker', 'web.tar.gz']:
        path = root / name
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != metadata['sha256'].get(name):
            raise ValueError('Exact build digest verification failed: ' + name)
    files, directories = read_tree(root / 'web.tar.gz')
    web = root / 'web'
    if web.exists() or web.is_symlink():
        if web.is_symlink() or not web.is_dir():
            raise ValueError('Existing static output is not a regular directory')
        actual = set()
        for path in web.rglob('*'):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError('Existing static output contains a linked/nonregular entry')
            relative = path.relative_to(web).as_posix()
            if path.is_file():
                if relative not in files or path.read_bytes() != files[relative]:
                    raise ValueError('Existing static output differs from the verified archive')
                actual.add(relative)
        if actual != set(files):
            raise ValueError('Existing static output is incomplete')
    else:
        staging = Path(tempfile.mkdtemp(prefix='.web-verified-', dir=root))
        try:
            for name in sorted(directories):
                (staging / name).mkdir(parents=True, exist_ok=True, mode=0o755)
            for name, data in files.items():
                path = staging / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with path.open('xb') as stream:
                    stream.write(data)
                path.chmod(0o644)
            staging.chmod(0o755)
            os.rename(staging, web)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    return metadata['revision']


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Provide one absolute exact build directory')
    try:
        print('Verified executables and exact static archive for Dashboard ' + verify_build(sys.argv[1]))
    except (OSError, ValueError, KeyError, tarfile.TarError):
        raise SystemExit('Dashboard build or static archive validation failed') from None
