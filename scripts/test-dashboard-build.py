#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('build_check', Path(__file__).with_name('verify-dashboard-build.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def build(root, entries):
    for name in ['jobman-dashboard', 'jobman-log-broker']:
        (root / name).write_bytes(b'synthetic offline binary')
    with tarfile.open(root / 'web.tar.gz', 'w:gz') as archive:
        for name, mode in entries:
            info = tarfile.TarInfo(name)
            info.type = mode
            data = b'<html>synthetic</html>'
            info.size = len(data) if mode == tarfile.REGTYPE else 0
            info.linkname = '/outside' if mode in [tarfile.SYMTYPE, tarfile.LNKTYPE] else ''
            archive.addfile(info, io.BytesIO(data) if mode == tarfile.REGTYPE else None)
    metadata = {'revision': 'a' * 40, 'platform': 'linux/arm64',
                'sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                           for name in ['jobman-dashboard', 'jobman-log-broker', 'web.tar.gz']}}
    (root / 'build.json').write_text(json.dumps(metadata))


class BuildTests(unittest.TestCase):
    def test_archive_is_verified_staged_and_exact_on_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build(root, [('index.html', tarfile.REGTYPE), ('assets/app.js', tarfile.REGTYPE)])
            self.assertEqual(module.verify_build(root), 'a' * 40)
            self.assertEqual(module.verify_build(root), 'a' * 40)
            (root / 'web/assets/app.js').write_text('changed')
            with self.assertRaises(ValueError):
                module.verify_build(root)

    def test_modified_archive_digest_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build(root, [('index.html', tarfile.REGTYPE)])
            with (root / 'web.tar.gz').open('ab') as stream:
                stream.write(b'changed')
            with self.assertRaises(ValueError):
                module.verify_build(root)
            self.assertFalse((root / 'web').exists())

    def test_paths_links_special_files_and_duplicates_are_rejected(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('assets/link', tarfile.SYMTYPE), ('assets/hardlink', tarfile.LNKTYPE),
                           ('assets/fifo', tarfile.FIFOTYPE), ('index.html', tarfile.REGTYPE),
                           ('index.html/child', tarfile.REGTYPE)]:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                build(root, [('index.html', tarfile.REGTYPE), (name, kind)])
                with self.assertRaises(ValueError):
                    module.verify_build(root)
                self.assertFalse((root / 'web').exists())


if __name__ == '__main__':
    unittest.main()
