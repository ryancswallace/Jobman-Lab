#!/usr/bin/env python3
"""Offline integrity, traversal and reproducible-source evaluation boundaries."""
import copy
import io
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import evaluation

spec = importlib.util.spec_from_file_location('smoke', Path(__file__).with_name('evaluate-smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def manifest():
    value = {'schemaVersion': 1, 'platform': 'linux/arm64', 'products': {}}
    for name, repository in evaluation.REPOSITORIES.items():
        value['products'][name] = {'repository': repository, 'version': 'v1.2.3', 'commit': 'a' * 40,
                                  'executables': {binary: {'path': 'bin/' + binary, 'sha256': 'b' * 64}
                                                  for binary in evaluation.EXECUTABLES[name]}}
        for kind in ('archive', 'sbom', 'checksums'):
            value['products'][name][kind] = {'name': kind + '.txt', 'sha256': 'b' * 64}
    return value


class EvaluationTests(unittest.TestCase):
    def test_cleanup_uses_operation_labels_and_immutable_ids(self):
        with patch.object(smoke, 'capture', side_effect=[b'a' * 64, b'b' * 64, b'', b'']) as command:
            smoke.cleanup('c' * 32)
        calls = [item.args[0] for item in command.call_args_list]
        self.assertIn('label=' + smoke.LABEL + '=' + 'c' * 32, calls[0])
        self.assertIn('label=' + smoke.LABEL + '=' + 'c' * 32, calls[1])
        self.assertEqual(calls[2], ['docker', 'rm', '-f', 'a' * 64])
        self.assertEqual(calls[3], ['docker', 'network', 'rm', 'b' * 64])

    def test_failed_or_unexpected_ownership_inventory_never_deletes_names(self):
        for response in (b'--all', b'not-an-owned-identity', b'a' * 64 + b' ' + b'b' * 64 + b' ' + b'c' * 64):
            with patch.object(smoke, 'capture', side_effect=[response, b'']) as command, self.assertRaises(ValueError):
                smoke.cleanup('c' * 32)
            self.assertEqual(command.call_count, 2)

    def test_manifest_requires_pins_and_rejects_ambient_or_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'selection.json'
            value = manifest()
            path.write_text(json.dumps(value))
            self.assertEqual(evaluation.read_manifest(path), value)
            for product in ('commit', 'version', 'repository'):
                changed = copy.deepcopy(value)
                changed['products']['core'][product] = 'latest'
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError): evaluation.read_manifest(path)
            path.write_text('{"schemaVersion":1,"schemaVersion":1}')
            with self.assertRaises(ValueError): evaluation.read_manifest(path)

    def test_archive_cannot_escape_follow_links_or_replace_an_entry(self):
        for name, kind, repeat in [('../escape', tarfile.REGTYPE, False), ('/escape', tarfile.REGTYPE, False),
                                   ('link', tarfile.SYMTYPE, False), ('regular', tarfile.REGTYPE, True)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode='w') as stream:
                    for _ in range(2 if repeat else 1):
                        item = tarfile.TarInfo(name)
                        item.type = kind
                        item.size = 1 if kind == tarfile.REGTYPE else 0
                        item.linkname = '/outside' if kind == tarfile.SYMTYPE else ''
                        stream.addfile(item, io.BytesIO(b'x'))
                with self.assertRaises(ValueError): evaluation.unpack(data.getvalue(), Path(temporary) / 'new')

    def test_dirty_or_different_source_is_rejected_before_building(self):
        value = manifest()
        for replies in ([b' M file\n'], [b'', b'b' * 40]):
            with patch.object(evaluation, 'capture', side_effect=replies), self.assertRaises(ValueError):
                evaluation.check_sources(value, {'core': Path('/synthetic')})
        with patch.object(evaluation, 'capture', side_effect=[b'', b'a' * 40]):
            evaluation.check_sources(value, {'core': Path('/synthetic')})

    def test_moved_tag_stops_before_any_download(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(evaluation, 'selected_commit', return_value='b' * 40), \
             patch.object(evaluation, 'capture') as command, self.assertRaises(ValueError):
            evaluation.fetch(manifest(), Path(temporary) / 'new')
        command.assert_not_called()

    def test_existing_or_indirect_output_is_never_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in (root, root / 'link'):
                if path.name == 'link': path.symlink_to(root)
                with self.assertRaises(ValueError): evaluation.new_output(path)


if __name__ == '__main__':
    unittest.main()
