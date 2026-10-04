#!/usr/bin/env python3
"""Replace the isolated Lab web root with one verified, bounded static tree."""
import ctypes
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path('/usr/local/share/jobman-dashboard-lab')
MAX_ARCHIVE = 72 << 20
MAX_TREE = 64 << 20
MAX_FILE = 8 << 20
MAX_ENTRIES = 4096


def require(value):
    if not value:
        raise ValueError('Invalid static asset installation')


def directory(path, owner):
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and value.st_uid == owner[0] and
            value.st_gid == owner[1] and stat.S_IMODE(value.st_mode) == 0o755)
    return value


def read(path, maximum, owner, mode):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_uid == owner[0] and before.st_gid == owner[1] and
                stat.S_IMODE(before.st_mode) == mode and before.st_size <= maximum)
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(data) == before.st_size and len(data) <= maximum and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        current = path.lstat()
        require((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino))
        return data


def contents(archive):
    files, directories, names = {}, set(), set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as source:
        for index, member in enumerate(source):
            path = PurePosixPath(member.name)
            require(index < MAX_ENTRIES and not path.is_absolute() and '..' not in path.parts and
                    '\\' not in member.name and '\x00' not in member.name and len(member.name) <= 4096 and
                    all(len(part) <= 255 for part in path.parts))
            if str(path) == '.':
                require(member.isdir())
                continue
            name = str(path)
            require(name not in names)
            names.add(name)
            if member.isdir():
                directories.add(name)
            else:
                require(member.isfile() and 0 <= member.size <= MAX_FILE)
                total += member.size
                require(total <= MAX_TREE)
                stream = source.extractfile(member)
                require(stream is not None)
                with stream:
                    data = stream.read(member.size + 1)
                require(len(data) == member.size)
                files[name] = data
            for parent in path.parents:
                if str(parent) != '.':
                    directories.add(str(parent))
            require(len(directories | set(files)) <= MAX_ENTRIES)
    require('index.html' in files and not directories.intersection(files))
    return files, directories


def inventory(root, owner):
    directory(root, owner)
    files, directories, total = {}, set(), 0
    for parent, children, names in os.walk(root, followlinks=False):
        require(len(files) + len(directories) + len(children) + len(names) <= MAX_ENTRIES)
        for name in children:
            path = Path(parent) / name
            directory(path, owner)
            directories.add(path.relative_to(root).as_posix())
        for name in names:
            path = Path(parent) / name
            data = read(path, MAX_FILE, owner, 0o644)
            total += len(data)
            require(total <= MAX_TREE)
            files[path.relative_to(root).as_posix()] = data
    return files, directories


def exchange_function():
    # No remove/rename fallback: replacement must be one atomic Linux syscall.
    require(sys.platform == 'linux')
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    require(rename is not None)
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int

    def exchange(left, right):
        if rename(-100, os.fsencode(left), -100, os.fsencode(right), 2) != 0:
            number = ctypes.get_errno()
            raise OSError(number, 'Atomic static directory exchange failed')
    return exchange


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install(archive_path, metadata_path, root=ROOT, owner=(0, 0), exchange=None,
            check_only=False, before_publish=None, bootstrap=False):
    require(root.is_absolute() and root.resolve(strict=True) == root)
    directory(root, owner)
    # Resolve platform capability before any lock, staging, or existing-tree change.
    if exchange is None:
        exchange = exchange_function()
    metadata = json.loads(read(metadata_path, 65536, owner, 0o600))
    require(metadata.get('platform') == 'linux/arm64' and
            isinstance(metadata.get('revision'), str) and
            re.fullmatch('[0-9a-f]{40}', metadata['revision']) is not None)
    archive = read(archive_path, MAX_ARCHIVE, owner, 0o600)
    require(hashlib.sha256(archive).hexdigest() == metadata['sha256']['web.tar.gz'])
    expected = contents(archive)
    lock_path = root / '.web-install.lock'
    try:
        lock = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(lock, 0o600)
    except FileExistsError:
        lock = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(lock, 'rb') as stream:
        value = os.fstat(stream.fileno())
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == owner[0] and
                value.st_gid == owner[1] and stat.S_IMODE(value.st_mode) == 0o600)
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = lock_path.lstat()
        require((value.st_dev, value.st_ino) == (current.st_dev, current.st_ino))
        web = root / 'web'
        previous = None
        if os.path.lexists(web):
            previous = directory(web, owner)
            current_contents = inventory(web, owner)
            if current_contents == expected:
                return False
            if bootstrap:
                require(current_contents == ({}, set()))
        if check_only:
            return True
        stage = Path(tempfile.mkdtemp(prefix='.web-staging-', dir=root))
        stage.chmod(0o700)
        identity = stage.stat()
        try:
            files, directories = expected
            # Keep the unpublished root private until every member is complete.
            for name in sorted(directories, key=lambda name: (name.count('/'), name)):
                path = stage / name
                path.mkdir(mode=0o755)
                path.chmod(0o755)
            for name, data in files.items():
                with (stage / name).open('xb') as output:
                    output.write(data)
                    output.flush()
                    os.fchmod(output.fileno(), 0o644)
                    os.fsync(output.fileno())
            stage.chmod(0o755)
            require(inventory(stage, owner) == expected)
            for name in sorted(directories, key=lambda name: (-name.count('/'), name)):
                sync_directory(stage / name)
            sync_directory(stage)
            if before_publish is not None:
                before_publish()
            if previous is None:
                require(not os.path.lexists(web))
                os.rename(stage, web)
            else:
                current = web.lstat()
                require((current.st_dev, current.st_ino) == (previous.st_dev, previous.st_ino))
                exchange(stage, web)
                identity = previous  # The displaced, never-served-again tree is now at stage.
            sync_directory(root)
            return True
        finally:
            if os.path.lexists(stage):
                current = stage.lstat()
                require((current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino) and
                        stat.S_ISDIR(current.st_mode) and shutil.rmtree.avoids_symlink_attacks)
                shutil.rmtree(stage)


def service_stopped(allow_missing=False):
    result = subprocess.run(['systemctl', 'show', 'jobman-dashboard-lab-app.service',
                             '--property=ActiveState,LoadState,MainPID', '--no-pager'],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False)
    require(len(result.stdout) <= 256)
    values = sorted(result.stdout.decode('ascii').splitlines())
    loaded = result.returncode == 0 and values == ['ActiveState=inactive', 'LoadState=loaded', 'MainPID=0']
    missing = allow_missing and result.returncode in (0, 1) and values == [
        'ActiveState=inactive', 'LoadState=not-found', 'MainPID=0']
    require(loaded or missing)


def main():
    require(os.geteuid() == 0 and os.getegid() == 0 and len(sys.argv) in (3, 4))
    require(len(sys.argv) == 3 or sys.argv[3] in ('--check', '--bootstrap'))
    check_only = len(sys.argv) == 4 and sys.argv[3] == '--check'
    bootstrap = len(sys.argv) == 4 and sys.argv[3] == '--bootstrap'
    for path in (ROOT, *ROOT.parents):
        value = path.lstat()
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022)
    if not check_only:
        service_stopped(allow_missing=bootstrap)
    changed = install(Path(sys.argv[1]), Path(sys.argv[2]), check_only=check_only,
                      before_publish=lambda: service_stopped(allow_missing=bootstrap), bootstrap=bootstrap)
    print(('different' if check_only else 'installed') if changed else 'unchanged')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        raise SystemExit('Static asset installation failed') from None
