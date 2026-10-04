#!/usr/bin/env python3
"""Offline filesystem tests; never contacts a guest or changes a service."""
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'ansible/roles/dashboard_app/files/install-web-assets.py'
spec = importlib.util.spec_from_file_location('web_assets', HELPER)
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


def local_exchange():
    if sys.platform == 'linux':
        return assets.exchange_function()
    if sys.platform != 'darwin':
        raise unittest.SkipTest('Directory exchange test requires Linux or macOS')
    # Tests only: exercise real filesystem exchange on the developer host.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int

    def exchange(left, right):
        if rename(os.fsencode(left), os.fsencode(right), 2) != 0:
            raise OSError(ctypes.get_errno(), 'Test directory exchange failed')
    return exchange


class AssetsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'static'
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        self.archive = self.base / 'web.tar.gz'
        self.metadata = self.base / 'build.json'
        self.owner = (os.getuid(), os.getgid())
        self.exchange = local_exchange()
        self.build([('index.html', b'old index'), ('assets/retired.js', b'old vulnerable asset')])
        self.assertTrue(self.install())

    def build(self, entries):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, content in entries:
                entry = tarfile.TarInfo(name)
                if isinstance(content, bytes):
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
                else:
                    entry.type = content[0]
                    entry.linkname = 'index.html'
                    archive.addfile(entry)
        self.archive.chmod(0o600)
        self.metadata.write_text(json.dumps({'revision': 'a' * 40, 'platform': 'linux/arm64',
            'sha256': {'web.tar.gz': hashlib.sha256(self.archive.read_bytes()).hexdigest()}}))
        self.metadata.chmod(0o600)

    def install(self, exchange=None):
        return assets.install(self.archive, self.metadata, self.root, self.owner,
                              self.exchange if exchange is None else exchange)

    def assert_old(self):
        self.assertEqual((self.root / 'web/index.html').read_bytes(), b'old index')
        self.assertEqual((self.root / 'web/assets/retired.js').read_bytes(), b'old vulnerable asset')
        self.assertEqual(list(self.root.glob('.web-staging-*')), [])

    def test_real_atomic_exchange_removes_obsolete_assets_and_exact_replay_is_unchanged(self):
        original = (self.root / 'web').stat().st_ino
        self.build([('index.html', b'new index'), ('assets/current.js', b'new safe asset'),
                    ('empty', (tarfile.DIRTYPE,))])
        self.assertTrue(self.install())
        self.assertNotEqual((self.root / 'web').stat().st_ino, original)
        self.assertFalse((self.root / 'web/assets/retired.js').exists())
        self.assertEqual((self.root / 'web/assets/current.js').read_bytes(), b'new safe asset')
        self.assertTrue((self.root / 'web/empty').is_dir())
        installed = (self.root / 'web').stat().st_ino
        self.assertFalse(self.install())
        self.assertEqual((self.root / 'web').stat().st_ino, installed)
        self.assertEqual(list(self.root.glob('.web-staging-*')), [])

    def test_failed_exchange_preserves_complete_existing_tree(self):
        self.build([('index.html', b'new index')])
        def unavailable(left, right):
            self.assertEqual((right / 'assets/retired.js').read_bytes(), b'old vulnerable asset')
            self.assertEqual((left / 'index.html').read_bytes(), b'new index')
            raise OSError('Synthetic unsupported atomic exchange')
        with self.assertRaises(OSError):
            self.install(unavailable)
        self.assert_old()

    def test_failed_staging_sync_does_not_publish(self):
        self.build([('index.html', b'new index')])
        with mock.patch.object(assets.os, 'fsync', side_effect=OSError('synthetic fsync failure')):
            with self.assertRaises(OSError):
                self.install()
        self.assert_old()

    def test_changed_archive_is_refused_without_touching_old_assets(self):
        with self.archive.open('ab') as output:
            output.write(b'changed')
        with self.assertRaises(ValueError):
            self.install()
        self.assert_old()

    def test_traversal_links_special_entries_duplicates_and_conflicts_are_refused(self):
        for name, content in [('../outside', b'x'), ('/outside', b'x'), ('a\\b', b'x'),
                              ('link', (tarfile.SYMTYPE,)), ('hardlink', (tarfile.LNKTYPE,)),
                              ('fifo', (tarfile.FIFOTYPE,)), ('index.html', b'duplicate'),
                              ('index.html/child', b'conflict')]:
            with self.subTest(name=name):
                self.build([('index.html', b'new index'), (name, content)])
                with self.assertRaises(ValueError):
                    self.install()
                self.assert_old()

    def test_archive_member_total_and_entry_bounds_are_enforced(self):
        for field, limit in [('MAX_ARCHIVE', 1), ('MAX_FILE', 1), ('MAX_TREE', 1), ('MAX_ENTRIES', 1)]:
            with self.subTest(field=field), mock.patch.object(assets, field, limit):
                with self.assertRaises(ValueError):
                    self.install()
            self.assert_old()
        self.build([('index.html', b'new'), ('a/b/c/d', b'x')])
        with mock.patch.object(assets, 'MAX_ENTRIES', 4), self.assertRaises(ValueError):
            self.install()
        self.assert_old()

    def test_restrictive_umask_still_installs_exact_public_modes(self):
        self.build([('index.html', b'new'), ('assets/deep/app.js', b'script')])
        (self.root / '.web-install.lock').unlink()
        before = os.umask(0o777)
        try:
            self.assertTrue(self.install())
        finally:
            os.umask(before)
        for path in (self.root / 'web').rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o755 if path.is_dir() else 0o644)
        self.assertEqual((self.root / 'web').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.root / '.web-install.lock').stat().st_mode & 0o777, 0o600)

    def test_unexpected_old_links_and_permissions_are_not_repaired(self):
        web = self.root / 'web'
        (web / 'alias').symlink_to(self.metadata)
        with self.assertRaises((ValueError, OSError)):
            self.install()
        (web / 'alias').unlink()
        web.chmod(0o777)
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(web.stat().st_mode & 0o777, 0o777)
        web.chmod(0o755)
        self.assert_old()

    def test_root_and_input_aliases_are_rejected(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            assets.install(self.archive, self.metadata, alias, self.owner, self.exchange)
        self.archive.unlink()
        self.archive.symlink_to(self.metadata)
        with self.assertRaises(OSError):
            self.install()
        self.assert_old()

    def test_unexpected_owner_is_rejected(self):
        with self.assertRaises(ValueError):
            assets.install(self.archive, self.metadata, self.root,
                           (self.owner[0] + 1, self.owner[1]), self.exchange)
        self.assert_old()

    def test_fifo_and_hardlinked_lock_fail_closed(self):
        lock = self.root / '.web-install.lock'
        lock.unlink()
        os.mkfifo(lock, 0o600)
        with self.assertRaises(ValueError):
            self.install()
        lock.unlink()
        lock.write_bytes(b'')
        lock.chmod(0o600)
        os.link(lock, self.base / 'lock-alias')
        with self.assertRaises(ValueError):
            self.install()
        self.assert_old()

    def test_displaced_tree_cleanup_never_follows_a_symlink(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'keep').write_bytes(b'not a web asset')
        self.build([('index.html', b'new')])
        def exchange_and_link(left, right):
            self.exchange(left, right)
            (left / 'link').symlink_to(outside, target_is_directory=True)
        self.assertTrue(self.install(exchange_and_link))
        self.assertEqual((outside / 'keep').read_bytes(), b'not a web asset')
        self.assertEqual(list(self.root.glob('.web-staging-*')), [])

    def test_production_has_no_non_linux_or_missing_syscall_fallback(self):
        with mock.patch.object(assets.sys, 'platform', 'darwin'), self.assertRaises(ValueError):
            assets.install(self.archive, self.metadata, self.root, self.owner)
        with mock.patch.object(assets.sys, 'platform', 'linux'), \
                mock.patch.object(assets.ctypes, 'CDLL', return_value=object()), self.assertRaises(ValueError):
            assets.install(self.archive, self.metadata, self.root, self.owner)
        self.assert_old()

    def test_compare_does_not_mutate_an_open_root_and_publication_requires_stopped_service(self):
        fd = os.open(self.root / 'web', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.build([('index.html', b'new')])
        self.assertTrue(assets.install(self.archive, self.metadata, self.root, self.owner,
                                      self.exchange, check_only=True))
        old = os.open('index.html', os.O_RDONLY, dir_fd=fd)
        with os.fdopen(old, 'rb') as stream:
            self.assertEqual(stream.read(), b'old index')
        active = subprocess.CompletedProcess([], 0, stdout=b'ActiveState=active\nLoadState=loaded\nMainPID=123\n')
        with mock.patch.object(assets.subprocess, 'run', return_value=active), self.assertRaises(ValueError):
            assets.install(self.archive, self.metadata, self.root, self.owner,
                           self.exchange, before_publish=assets.service_stopped)
        self.assert_old()
        stopped = subprocess.CompletedProcess([], 0, stdout=b'MainPID=0\nActiveState=inactive\nLoadState=loaded\n')
        with mock.patch.object(assets.subprocess, 'run', return_value=stopped) as show:
            self.assertTrue(assets.install(self.archive, self.metadata, self.root, self.owner,
                                          self.exchange, before_publish=assets.service_stopped))
            self.assertEqual(show.call_args.kwargs['timeout'], 5)
        reopened = os.open(self.root / 'web', os.O_RDONLY | os.O_DIRECTORY)
        try:
            new = os.open('index.html', os.O_RDONLY, dir_fd=reopened)
            with os.fdopen(new, 'rb') as stream:
                self.assertEqual(stream.read(), b'new')
        finally:
            os.close(reopened)

    def test_stopped_service_check_rejects_transition_unknown_and_nonzero_pid(self):
        for state in [b'ActiveState=deactivating\nMainPID=0\n', b'ActiveState=inactive\nMainPID=1\n',
                      b'ActiveState=failed\nMainPID=0\n', b'', b'x' * 257]:
            with self.subTest(state=state), mock.patch.object(assets.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, stdout=state)), self.assertRaises(ValueError):
                assets.service_stopped()

    def test_first_install_bootstrap_populates_index_without_starting_service(self):
        fresh = self.base / 'fresh'
        fresh.mkdir(mode=0o755)
        fresh.chmod(0o755)
        (fresh / 'web').mkdir(mode=0o755)
        (fresh / 'web').chmod(0o755)
        missing = subprocess.CompletedProcess([], 1, stdout=b'LoadState=not-found\nMainPID=0\nActiveState=inactive\n')
        with mock.patch.object(assets.subprocess, 'run', return_value=missing) as show:
            self.assertTrue(assets.install(self.archive, self.metadata, fresh, self.owner,
                self.exchange, bootstrap=True, before_publish=lambda: assets.service_stopped(allow_missing=True)))
            self.assertEqual((fresh / 'web/index.html').read_bytes(), b'old index')
            self.assertEqual(show.call_args.args[0][0:2], ['systemctl', 'show'])
            self.assertEqual(show.call_count, 1)
            with self.assertRaises(ValueError):
                assets.service_stopped()  # Missing unit is allowed only for bootstrap.
        role = (ROOT / 'ansible/roles/dashboard_app/tasks/main.yml').read_text()
        self.assertLess(role.index('Install the initial tree without starting'), role.index('Validate application configuration'))
        bootstrap = role[role.index('- name: Bootstrap assets only'):role.index('- name: Install private application TLS')]
        self.assertIn('- --bootstrap', bootstrap)
        self.assertNotIn('state: started', bootstrap)
        self.assertNotIn('notify:', bootstrap)

    def test_bootstrap_refuses_to_replace_nonempty_existing_tree(self):
        self.build([('index.html', b'new')])
        with self.assertRaises(ValueError):
            assets.install(self.archive, self.metadata, self.root, self.owner,
                           self.exchange, bootstrap=True)
        self.assert_old()

    def test_role_uploads_archive_and_never_merges_or_removes_the_live_tree(self):
        role = (ROOT / 'ansible/roles/dashboard_app/tasks/main.yml').read_text()
        self.assertIn('loop: [web.tar.gz, build.json]', role)
        self.assertIn("changed_when: dashboard_web_install.stdout == 'installed'", role)
        self.assertIn('/usr/local/libexec/jobman-dashboard-lab/install-web-assets.py', role)
        self.assertNotIn('src: "{{ dashboard_application_build }}/web/"', role)
        self.assertNotIn('dest: /usr/local/share/jobman-dashboard-lab/web/', role)
        self.assertIn('path: "{{ dashboard_web_upload.path }}"\n        state: absent', role)
        self.assertLess(role.index('Validate application configuration'), role.index('state: stopped'))
        self.assertLess(role.index('Apply forward migrations'), role.index('state: stopped'))
        self.assertLess(role.index('Install the isolated Dashboard systemd service'), role.index('state: stopped'))
        self.assertLess(role.index('state: stopped'), role.index('Atomically install the complete static tree'))
        self.assertIn('      always:\n        - name: Reopen the complete static tree even if asset installation failed', role)
        self.assertIn("when: dashboard_web_check.stdout == 'different'", role)
        # The last start is unconditional, so a previous interrupted cutover
        # with an already-exact tree cannot strand the service on an unchanged retry.
        final = role[role.index('- name: Start only the isolated Dashboard application'):]
        self.assertIn('state: started', final)
        self.assertNotIn('when:', final)


if __name__ == '__main__':
    unittest.main()
