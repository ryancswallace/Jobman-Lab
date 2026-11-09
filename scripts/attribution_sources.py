"""Verify Go module source ZIPs against executable build information."""

import base64
from functools import lru_cache
import hashlib
import io
from pathlib import Path
import re
import tarfile
import zipfile

from evaluation import capture, require, safe_path

MAX_SOURCE_BYTES = 512 * 1024 * 1024


def checked_zip(path, prefix=''):
    require(path.is_file() and not path.is_symlink(), 'Source ZIP must be a regular file')
    archive = zipfile.ZipFile(path)
    try:
        records, total = {}, 0
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            safe_path(entry.filename)
            require(entry.filename.startswith(prefix) and entry.filename not in records,
                    'Unexpected or duplicate source path')
            require((entry.external_attr >> 16) & 0o170000 in (0, 0o100000), 'Source links are forbidden')
            total += entry.file_size
            require(len(records) < 50000 and total <= MAX_SOURCE_BYTES, 'Source inventory exceeds bounds')
            records[entry.filename] = entry
        return archive, records
    except Exception:
        archive.close()
        raise


def go_zip_hashes(archive, records):
    """The Go module h1 algorithm, including each module-prefixed filename."""
    result, hashes = hashlib.sha256(), {}
    for name in sorted(records):
        require('\n' not in name, 'Invalid Go module filename')
        with archive.open(records[name]) as stream:
            file_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
        hashes[name] = file_hash
        result.update((file_hash + '  ' + name + '\n').encode())
    return 'h1:' + base64.b64encode(result.digest()).decode(), hashes


def escaped_module(value):
    require(re.fullmatch(r'[A-Za-z0-9._~+/-]+', value) is not None,
            'Invalid Go module identity')
    safe_path(value)
    return ''.join('!' + char.lower() if char.isupper() else char for char in value)


@lru_cache(maxsize=128)
def module_source(cache, name, version, expected_sum):
    path = cache / 'cache/download' / escaped_module(name) / '@v' / (escaped_module(version) + '.zip')
    prefix = name + '@' + version + '/'
    archive, records = checked_zip(path, prefix)
    with archive:
        observed_sum, hashes = go_zip_hashes(archive, records)
        require(observed_sum == expected_sum, f'Go source ZIP differs for {name}@{version}')
        annotations = {}
        for full_name, entry in records.items():
            if not full_name.endswith('.go'):
                continue
            text = archive.read(entry).decode('utf-8', errors='replace')
            identifiers = sorted(set(re.findall(r'SPDX-License-Identifier:[ \t]*([^\r\n]+)', text)))
            if any(re.search(r'\b(?:A?GPL|LGPL|MPL)', item) for item in identifiers) or 'GCC Runtime Library Exception' in text:
                annotations[full_name[len(prefix):]] = {
                    'spdxAnnotations': identifiers,
                    'gccRuntimeLibraryExceptionMentioned': 'GCC Runtime Library Exception' in text,
                }
    return {key[len(prefix):]: value for key, value in hashes.items()}, annotations


def bound_file(directory, name, hashes):
    path = directory / safe_path(name)
    require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(directory.resolve()),
            f'Expected regular source file {name}')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == hashes.get(name), f'Source bytes differ for {name}')
    return data


def verify_export(repository, commit, directory):
    """Bind the build inputs to the selected commit using a read-only Git export."""
    data = capture(['git', '-C', str(repository), 'archive', commit], limit=MAX_SOURCE_BYTES)
    hashes = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for member in archive:
            if member.isdir():
                continue
            if member.issym():
                path = directory / safe_path(member.name)
                require(path.is_symlink() and str(path.readlink()) == member.linkname,
                        f'Source link differs for {member.name}')
                continue
            require(member.isfile(), 'Source export contains unsupported link or special file')
            hashes[member.name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            bound_file(directory, member.name, hashes)
    return hashes
