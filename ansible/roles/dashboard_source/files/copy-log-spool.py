#!/usr/bin/env python3
"""Copy only the prepared synthetic namespace logs as Alice, retaining NFS ACLs."""
import hashlib
import os
from pathlib import Path
import stat

SOURCE = Path('/var/lib/jobman-dashboard-lab/seed-logs')
DESTINATION = Path('/data/jobman/alice')
NAMESPACES = {'dashboard-research', 'dashboard-operations'}


def main():
    if os.getuid() != 21001:
        raise RuntimeError('Synthetic spool copy must run as Alice')
    count = 0
    for current, dirs, files in os.walk(SOURCE, followlinks=False):
        relative = Path(current).relative_to(SOURCE)
        if relative.parts and relative.parts[0] != 'namespaces':
            raise RuntimeError('Unexpected synthetic spool prefix')
        if len(relative.parts) >= 2 and relative.parts[1] not in NAMESPACES:
            raise RuntimeError('Unexpected synthetic namespace')
        for name in dirs + files:
            if (Path(current) / name).is_symlink():
                raise RuntimeError('Synthetic spool contains a symlink')
        target = DESTINATION / relative
        if target.is_symlink():
            raise RuntimeError('NFS target is a symlink')
        target.mkdir(mode=0o750, exist_ok=True)
        for name in files:
            source = Path(current) / name
            if not stat.S_ISREG(source.lstat().st_mode) or source.stat().st_size > 262144:
                raise RuntimeError('Synthetic log must be a bounded regular file')
            data = source.read_bytes()
            output = target / name
            if output.is_symlink():
                raise RuntimeError('NFS output is a symlink')
            try:
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            except FileExistsError:
                if not output.is_file() or output.stat().st_size != len(data) or hashlib.sha256(output.read_bytes()).digest() != hashlib.sha256(data).digest():
                    raise RuntimeError('Existing immutable synthetic output differs; refusing overwrite')
            else:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
            count += 1
    print(f'Synthetic NFS spool ready: {count} immutable objects; bytes not printed.')


if __name__ == '__main__':
    main()
