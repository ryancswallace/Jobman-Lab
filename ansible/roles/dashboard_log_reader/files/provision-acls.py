#!/usr/bin/env python3
"""Narrow the Lab broker grant to canonical published logs and shared prefixes.

Do not follow symlinks or grant access to private artifact payloads. Existing
owner/group/other rights are preserved; unexpected per-user directory grants
are excluded rather than being silently replaced. This is explicit operator
provisioning, never a background ACL repair service.
"""
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path('/srv/lab/data')
READER = '21901'
NAMESPACE = re.compile(r'^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$')
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def valid_uuid(value):
    return UUID.fullmatch(value) is not None and value.replace('-', '') != '0' * 32


def shared_directory(parts):
    if len(parts) > 8:
        return False
    for index, part in enumerate(parts):
        if index in (0, 2, 4, 6) and part != {0: 'namespaces', 2: 'jobs', 4: 'executions', 6: 'logs'}[index]:
            return False
        if index == 1 and NAMESPACE.fullmatch(part) is None:
            return False
        if index in (3, 5) and not valid_uuid(part):
            return False
        if index == 7 and part not in ('stdout', 'stderr'):
            return False
    return True


def shared_file(parts):
    if len(parts) != 9 or not shared_directory(parts[:8]) or not re.fullmatch(r'[0-9]{8,19}\.chunk', parts[8]):
        return False
    digits = parts[8][:-6]
    value = int(digits)
    return 0 < value <= 9223372036854775807 and str(value).zfill(8) == digits


def acl(path):
    result = subprocess.run(['getfacl', '-cpn', '--', str(path)], check=True, capture_output=True, text=True)
    return [line.split('\t', 1)[0].strip() for line in result.stdout.splitlines() if line.strip()]


def set_acl(path, *args):
    subprocess.run(['setfacl', *args, '--', str(path)], check=True, capture_output=True)


def remove_reader(path, entries):
    # -n preserves the existing mask. Automatic recalculation could unmask a
    # preexisting owning-group/named grant while removing only our identity.
    if any(entry.startswith('user:' + READER + ':') for entry in entries):
        set_acl(path, '-n', '-x', 'u:' + READER)
    if any(entry.startswith('default:user:' + READER + ':') for entry in entries):
        set_acl(path, '-n', '-x', 'd:u:' + READER)


def traversal_mask(entries):
    mask = next((entry[6:] for entry in entries if entry.startswith('mask::')), None)
    if mask is None:
        mask = next(entry[7:] for entry in entries if entry.startswith('group::'))
    if mask[2] != 'x':
        for entry in entries:
            fields = entry.split(':')
            group_class = fields[0] == 'group' or (fields[0] == 'user' and fields[1] not in ('', READER))
            if group_class and fields[-1].endswith('x'):
                raise RuntimeError('Parent traversal would unmask an existing group-class execute grant; operator review required')
    return mask[:2] + 'x'


def inventory():
    result = []
    for current, dirs, files in os.walk(ROOT, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
        for path in [Path(current)] + [Path(current) / name for name in files]:
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode) or stat.S_ISREG(mode):
                result.append((path, stat.S_ISDIR(mode), acl(path)))
    return result


def main():
    objects = inventory()
    stores = [ROOT / 'jobman' / name for name in ('alice', 'bob')]
    # Never erase preexisting grants to make an incompatible legacy tree look
    # safe enough for the strict producer policy. Remove our grant there only.
    excluded = []
    for path, directory, entries in objects:
        if directory and any(path.is_relative_to(store) for store in stores):
            permitted = {'user::rwx', 'group::---', 'other::---', 'mask::r-x', 'mask::---',
                         'user:' + READER + ':r-x', 'default:user::rwx', 'default:group::---',
                         'default:other::---', 'default:mask::r-x', 'default:mask::---',
                         'default:user:' + READER + ':r-x'}
            if any(entry not in permitted for entry in entries):
                excluded.append(path)
        store = next((store for store in stores if path.is_relative_to(store)), None)
        if not directory and store is not None and shared_file(path.relative_to(store).parts):
            permitted = {'user::rw-', 'group::---', 'other::---', 'mask::r-x', 'mask::r--',
                         'mask::---', 'user:' + READER + ':r-x', 'user:' + READER + ':r--'}
            if any(entry not in permitted for entry in entries):
                excluded.append(path)
    shared_dirs = shared_logs = private_files = 0
    for path, directory, entries in objects:
        store = next((store for store in stores if path.is_relative_to(store)), None)
        compatible = not any(path == parent or path.is_relative_to(parent) for parent in excluded)
        if store is not None and directory and compatible and shared_directory(path.relative_to(store).parts):
            # Defaults are necessary for the opted-in producer's canonical log
            # prefixes. Never install them on existing private/noncanonical
            # directories: a later 0750 child would unmask the inherited reader.
            set_acl(path, '-m', 'u:' + READER + ':r-x,m::r-x')
            set_acl(path, '-m', 'd:u::rwx,d:u:' + READER + ':r-x,d:g::---,d:m::r-x,d:o::---')
            shared_dirs += 1
        elif store is not None and not directory and compatible and shared_file(path.relative_to(store).parts):
            set_acl(path, '-m', 'u:' + READER + ':r--,m::r--')
            shared_logs += 1
        else:
            remove_reader(path, entries)
            private_files += int(not directory and any(entry.startswith('user:' + READER + ':') for entry in entries))
    # Outside the physical stores only traversal is needed. Preserve all base
    # rights and NFS root_squash; do not create default grants on these parents.
    for path in (ROOT, ROOT / 'jobman'):
        set_acl(path, '-n', '-m', 'u:' + READER + ':--x,m::' + traversal_mask(acl(path)))
    print(f'Published-log ACL policy ready: {shared_dirs} shared directories, {shared_logs} canonical logs; {private_files} nonlog reader grants removed; {len(excluded)} incompatible legacy paths excluded.')


if __name__ == '__main__':
    main()
