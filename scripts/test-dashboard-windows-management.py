#!/usr/bin/env python3
"""Offline checks for the scoped Windows Lab account repair and restart order."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('repair', ROOT / 'scripts/repair-windows-management.py')
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)
IDENTITY = '11111111-2222-4333-8444-555555555555'


class RepairTests(unittest.TestCase):
    def test_requires_the_running_vagrant_owned_windows_vm(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = root / '.vagrant/machines/winws01/parallels/id'
            path.parent.mkdir(parents=True)
            path.write_text(IDENTITY)
            listing = '{' + IDENTITY + '} jobman-lab-winws01 running\n'
            self.assertEqual(repair.windows_vm(root, listing), IDENTITY)
            for unsafe in ('', listing.replace('winws01', 'unrelated'),
                           listing.replace('running', 'stopped'), listing + listing,
                           listing.replace(IDENTITY, 'aaaaaaaa-2222-4333-8444-555555555555')):
                with self.subTest(unsafe=unsafe), self.assertRaises(RuntimeError):
                    repair.windows_vm(root, unsafe)
            path.write_text('not-a-vm; unsafe')
            with self.assertRaises(ValueError):
                repair.windows_vm(root, listing)

    def test_inspection_is_read_only_and_apply_changes_only_expiry(self):
        self.assertNotIn('Set-LocalUser', repair.powershell(False))
        script = repair.powershell(True)
        self.assertIn('Set-LocalUser -Name "vagrant" -PasswordNeverExpires $true', script)
        self.assertNotIn('-Password ', script)
        self.assertNotIn('Enable-LocalUser', script)
        self.assertNotIn('net accounts', script)
        self.assertIn('$before.PasswordLastSet -ne $after.PasswordLastSet', script)

    def test_restart_is_sequential_and_repairs_are_explicit(self):
        make = (ROOT / 'Makefile').read_text()
        block = make[make.index('restart:'):make.index('repair-windows-management:')]
        self.assertLess(block.index(' halt'), block.index(' ensure-running'))
        self.assertNotIn('repair-windows-management', block)
        image = (ROOT / 'packer/scripts/winrm.ps1').read_text()
        self.assertLess(image.index('Set-LocalUser'), image.index('Enable-PSRemoting'))


if __name__ == '__main__':
    unittest.main()
