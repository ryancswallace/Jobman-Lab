#!/usr/bin/env python3
"""Offline ACL boundary checks; optional real Linux checks use only a temp tree.

Set JOBMAN_TEST_POSIX_ACL=1 to require Linux getfacl/setfacl instead of skipping
when unavailable. No Lab configuration, credentials, SSH, or existing store is
loaded. Root runs additionally prove kernel read decisions as a separate UID.
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    'log_acl_policy', ROOT / 'ansible/roles/dashboard_log_reader/files/provision-acls.py')
ACL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ACL)
PREFIX = ('namespaces', 'dashboard-probe', 'jobs', '01990000-0000-7000-8000-000000000001',
          'executions', '01990000-0000-7000-8000-000000000002', 'logs', 'stdout')
ACCESS = ['user::rwx', 'user:21901:r-x', 'group::---', 'mask::---', 'other::---']
DEFAULT = ['default:user::rwx', 'default:user:21901:r-x', 'default:group::---',
           'default:mask::r-x', 'default:other::---']


class ProvisionBoundaryTests(unittest.TestCase):
    def test_every_existing_noncanonical_directory_loses_access_and_inheritance(self):
        store = ACL.ROOT / 'jobman/alice'
        private = [store / 'private', store / 'private/child', store / 'inputs',
                   store.joinpath(*PREFIX[:6], 'artifacts'),
                   store.joinpath(*PREFIX, 'nested'),
                   store.joinpath(*PREFIX, '00000001.chunk')]
        objects = [(path, True, ACCESS + DEFAULT) for path in private]
        with patch.object(ACL, 'inventory', return_value=objects), \
                patch.object(ACL, 'acl', return_value=['user::rwx', 'group::---', 'other::---']), \
                patch.object(ACL, 'set_acl') as writer, contextlib.redirect_stdout(io.StringIO()):
            ACL.main()
        for path in private:
            self.assertEqual([call.args[1:] for call in writer.call_args_list if call.args[0] == path],
                             [('-n', '-x', 'u:21901'), ('-n', '-x', 'd:u:21901')])

    def test_canonical_prefixes_and_only_regular_log_chunks_keep_grants(self):
        store = ACL.ROOT / 'jobman/alice'
        directories = [store.joinpath(*PREFIX[:n]) for n in range(len(PREFIX) + 1)]
        chunk = store.joinpath(*PREFIX, '00000001.chunk')
        artifact = store.joinpath(*PREFIX[:6], 'artifacts/output.txt')
        objects = [(path, True, ACCESS + DEFAULT) for path in directories]
        objects += [(chunk, False, ['user::rw-', 'group::---', 'other::---']),
                    (artifact, False, ['user::rw-', 'user:21901:r--', 'group::---', 'mask::r--', 'other::---'])]
        with patch.object(ACL, 'inventory', return_value=objects), \
                patch.object(ACL, 'acl', return_value=['user::rwx', 'group::---', 'other::---']), \
                patch.object(ACL, 'set_acl') as writer, contextlib.redirect_stdout(io.StringIO()):
            ACL.main()
        defaults = [call.args[0] for call in writer.call_args_list
                    if call.args[1] == '-m' and call.args[2].startswith('d:')]
        self.assertEqual(defaults, directories)
        self.assertIn((chunk, '-m', 'u:21901:r--,m::r--'), [call.args for call in writer.call_args_list])
        self.assertEqual([call.args[1:] for call in writer.call_args_list if call.args[0] == artifact],
                         [('-n', '-x', 'u:21901')])

    def test_private_unrelated_acl_masks_are_preserved_and_never_replaced(self):
        path = ACL.ROOT / 'jobman/alice/private'
        entries = ACCESS + DEFAULT + ['user:21002:rwx', 'default:user:21002:rwx']
        with patch.object(ACL, 'inventory', return_value=[(path, True, entries)]), \
                patch.object(ACL, 'acl', return_value=['user::rwx', 'group::---', 'other::---']), \
                patch.object(ACL, 'set_acl') as writer, contextlib.redirect_stdout(io.StringIO()):
            ACL.main()
        self.assertEqual([call.args[1:] for call in writer.call_args_list if call.args[0] == path],
                         [('-n', '-x', 'u:21901'), ('-n', '-x', 'd:u:21901')])


class LinuxInheritanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supported = sys.platform == 'linux' and shutil.which('getfacl') and shutil.which('setfacl')
        if not supported:
            if os.environ.get('JOBMAN_TEST_POSIX_ACL') == '1':
                raise RuntimeError('Required disposable Linux ACL test needs Linux getfacl and setfacl')
            raise unittest.SkipTest('Linux getfacl/setfacl unavailable; no live ACL acceptance claimed')

    def test_private_parent_children_deny_reader_and_canonical_chunks_stay_readable(self):
        with tempfile.TemporaryDirectory(prefix='jobman-acl-regression-') as temporary:
            outer = Path(temporary)
            outer.chmod(0o755)
            data = outer / 'data'
            store = data / 'jobman/alice'
            store.mkdir(parents=True, mode=0o700)
            # This exact old ACL is the bug's precondition: the parent access
            # mask is zero, but its default permits later 0750/0640 children.
            ACL.set_acl(store, '--set', 'u::rwx,u:21901:r-x,g::---,m::r-x,o::---')
            ACL.set_acl(store, '-m', 'd:u::rwx,d:u:21901:r-x,d:g::---,d:m::r-x,d:o::---')
            private = store / 'private'
            private.mkdir(mode=0o700)
            before = private / 'before'
            before.mkdir(mode=0o750)
            before_file = before / 'payload'
            fd = os.open(before_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            os.close(fd)
            self.assertIn('user:21901:r-x', ACL.acl(before))
            self.assertIn('mask::r-x', ACL.acl(before))
            self.assertIn('mask::r--', ACL.acl(before_file))
            self.assertTrue(any(entry.startswith('user:21901:') for entry in ACL.acl(before_file)))
            stream = store
            for part in PREFIX:
                stream /= part
                stream.mkdir(mode=0o750)
            artifact = store.joinpath(*PREFIX[:6], 'artifacts')
            artifact.mkdir(mode=0o700)
            old_masks = {path: [entry for entry in ACL.acl(path) if ':mask::' in ':' + entry]
                         for path in [private, before, artifact]}
            with patch.object(ACL, 'ROOT', data), contextlib.redirect_stdout(io.StringIO()):
                ACL.main()
            for path in [private, before, before_file, artifact]:
                self.assertFalse(any(entry.startswith(('user:21901:', 'default:user:21901:'))
                                     for entry in ACL.acl(path)), str(path.relative_to(outer)))
            for path, masks in old_masks.items():
                self.assertEqual([entry for entry in ACL.acl(path) if ':mask::' in ':' + entry], masks)
            for parent in [private, artifact]:
                # Even an owner's later group-mode change must not reactivate
                # a stale reader entry on an already provisioned private path.
                parent.chmod(0o750)
                child = parent / 'after'
                child.mkdir(mode=0o750)
                payload = child / 'payload'
                fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
                os.close(fd)
                for path in [parent, child, payload]:
                    self.assertFalse(any(entry.startswith(('user:21901:', 'default:user:21901:'))
                                         for entry in ACL.acl(path)))
                if os.geteuid() == 0:
                    self.assertEqual(self.reader_status(payload), 1)
            chunk = stream / '00000001.chunk'
            fd = os.open(chunk, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            os.write(fd, b'synthetic canonical chunk\n')
            os.close(fd)
            self.assertIn('default:user:21901:r-x', ACL.acl(stream))
            self.assertIn('mask::r--', ACL.acl(chunk))
            self.assertTrue(any(entry.startswith('user:21901:') for entry in ACL.acl(chunk)))
            if os.geteuid() == 0:
                self.assertEqual(self.reader_status(chunk), 0)

    @staticmethod
    def reader_status(path):
        def demote():
            os.setgroups([])
            os.setgid(21901)
            os.setuid(21901)
        result = subprocess.run([sys.executable, '-c',
                                 'import os,sys;sys.exit(0 if os.access(sys.argv[1],os.R_OK) else 1)', str(path)],
                                preexec_fn=demote, capture_output=True, timeout=5, check=False)
        return result.returncode


if __name__ == '__main__':
    unittest.main()
