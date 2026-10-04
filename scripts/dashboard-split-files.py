#!/usr/bin/env python3
"""Receipt-bound report inventory/conversion primitives for stopped Lab services.

This module has no CLI and is not run during preparation. The reviewed apply
driver must establish the persisted hold, stop all Dashboard processes, verify
the database backup, then invoke these functions as root on storage01. No chmod
of a parent, recursive arbitrary tree walk, ACL repair or automatic cleanup.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat

OBJECT = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json\Z')
MAXIMUM_OBJECT = (6 << 20) + (16 << 10)
MAXIMUM_FILES = 10000
MAXIMUM_BYTES = 1 << 30
OLD = '/var/lib/jobman-dashboard-app-lab/reports'
NEW = '/var/lib/jobman-dashboard-reports-lab'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def no_acl(fd, directory=False):
    names = ['system.posix_acl_access'] + (['system.posix_acl_default'] if directory else [])
    for name in names:
        try:
            os.getxattr(fd, name)
        except OSError as error:
            require(error.errno == errno.ENODATA, 'ACL absence not proven')
        else:
            raise ValueError('Unexpected ACL; no automatic ACL conversion')


def digest(fd, size):
    result = hashlib.sha256()
    total = 0
    while True:
        data = os.read(fd, min(65536, size + 1 - total))
        if not data:
            break
        result.update(data)
        total += len(data)
        require(total <= size, 'Object grew during inventory')
    require(total == size, 'Object length changed during inventory')
    return result.hexdigest()


def inventory(root, profiles):
    """Only UUID.json files, one directory, bounded bytes; no content returned."""
    root = Path(root)
    require(root.is_absolute() and str(root) == os.path.normpath(root), 'Clean absolute object root required')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        initial = os.fstat(fd)
        require((initial.st_uid, initial.st_gid, stat.S_IMODE(initial.st_mode)) in [p[:3] for p in profiles], 'Object root ownership differs')
        no_acl(fd, True)
        names = os.listdir(fd)
        require(len(names) <= MAXIMUM_FILES and all(OBJECT.fullmatch(name) for name in names), 'Unknown report entry or count bound')
        entries, total = [], 0
        for name in sorted(names):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(child)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAXIMUM_OBJECT and
                        (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) in [(p[0], p[1], p[3]) for p in profiles],
                        'Object is not private immutable regular file')
                no_acl(child)
                total += info.st_size
                require(total <= MAXIMUM_BYTES, 'Report backup byte bound exceeded')
                checksum = digest(child, info.st_size)
                after = os.fstat(child)
                require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                        (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns), 'Object changed during inventory')
                entries.append({'name': name, 'size': info.st_size, 'sha256': checksum})
            finally:
                os.close(child)
        require(sorted(os.listdir(fd)) == names_sorted(entries), 'Report tree changed during inventory')
        final = os.stat(root, follow_symlinks=False)
        require((final.st_dev, final.st_ino) == (initial.st_dev, initial.st_ino), 'Report root was replaced')
        return {'device': initial.st_dev, 'inode': initial.st_ino, 'entries': entries, 'bytes': total}
    finally:
        os.close(fd)


def names_sorted(entries):
    return [e['name'] for e in entries]


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def backup(root, destination, expected, profile):
    """Copy exact known files to a new private directory before conversion."""
    require(inventory(root, [profile]) == expected, 'Report inventory changed since plan')
    destination = Path(destination)
    require(not destination.exists() and not destination.is_symlink(), 'Backup destination must be new')
    parent = destination.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700 and parent.st_uid == os.getuid(), 'Backup parent is not private')
    destination.mkdir(mode=0o700)
    source = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for entry in expected['entries']:
            child = os.open(entry['name'], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source)
            try:
                info = os.fstat(child)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == entry['size'], 'Backup object changed')
                target = os.open(destination / entry['name'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                checksum, total = hashlib.sha256(), 0
                with os.fdopen(target, 'wb') as out:
                    while True:
                        data = os.read(child, 65536)
                        if not data:
                            break
                        total += len(data)
                        require(total <= entry['size'], 'Backup object grew')
                        checksum.update(data)
                        out.write(data)
                    out.flush();os.fsync(out.fileno())
                require(total == entry['size'] and checksum.hexdigest() == entry['sha256'], 'Backup checksum differs')
            finally:
                os.close(child)
        require(inventory(root, [profile]) == expected, 'Report inventory changed during backup')
        write(destination / 'manifest.json', canonical(expected))
        out = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
        try:os.fsync(out)
        finally:os.close(out)
    finally:
        os.close(source)


def convert(source, destination, receipt, before, after, *, allowed_paths=(OLD, NEW)):
    """Same-device rename with a synced receipt; interrupted exact work resumes.

    Caller must re-prove stopped writers and the persisted hold before every
    invocation. Receipt is a private root-owned file created BEFORE mutations.
    Its exact inventory must be independently backed up and verified first.
    """
    source, destination, receipt = Path(source), Path(destination), Path(receipt)
    require({str(source), str(destination)} == set(allowed_paths) and source != destination, 'Conversion paths outside scoped pair')
    require(not source.is_symlink() and not destination.is_symlink(), 'Conversion root cannot be a link')
    require(source.parent.stat().st_dev == destination.parent.stat().st_dev, 'Cross-filesystem report conversion is not supported')
    private = receipt.parent.lstat()
    require(stat.S_ISDIR(private.st_mode) and stat.S_IMODE(private.st_mode) == 0o700 and private.st_uid == os.getuid(), 'Private receipt parent required')
    st = receipt.lstat()
    require(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.getuid(), 'Private conversion receipt required')
    fd = os.open(receipt, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        actual = os.fstat(stream.fileno())
        require((actual.st_dev,actual.st_ino) == (st.st_dev,st.st_ino) and 0 < actual.st_size <= 4 << 20, 'Receipt was replaced or oversized')
        record = json.loads(stream.read((4 << 20) + 1))
    require(record['source'] == str(source) and record['destination'] == str(destination) and
            record['before'] == list(before) and record['after'] == list(after), 'Receipt belongs to another conversion')
    require(source.exists() != destination.exists(), 'Expected exactly one retained report root')
    current = source if source.exists() else destination
    expected = record['inventory']
    # fchown and fchmod are individually atomic, not an atomic pair. Permit only
    # the finite original/final combinations while resuming this exact receipt.
    profiles = [(owner[0],owner[1],directory[2],file[3]) for owner in (before,after)
                for directory in (before,after) for file in (before,after)]
    require(inventory(current, profiles) == expected, 'Receipt inventory differs')
    if current == source:
        os.rename(source, destination)
        for parent in (source.parent, destination.parent):
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
    root = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for entry in expected['entries']:
            child = os.open(entry['name'], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root)
            try:
                require(digest(child, entry['size']) == entry['sha256'], 'Conversion object checksum differs')
                os.fchown(child, after[0], after[1]);os.fchmod(child, after[3]);os.fsync(child)
            finally:os.close(child)
        os.fchown(root, after[0], after[1]);os.fchmod(root, after[2]);os.fsync(root)
    finally:os.close(root)
    require(inventory(destination, [after]) == expected, 'Post-conversion report inventory differs')
    complete = Path(str(receipt) + '.complete')
    if complete.exists():
        require(complete.read_bytes() == canonical(expected), 'Existing conversion completion differs')
    else:
        write(complete, canonical(expected))
