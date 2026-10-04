#!/usr/bin/env python3
"""Offline source environment tests; never load private Lab connections."""
import ast
from pathlib import Path
import unittest

source = ast.parse(Path(__file__).with_name('upgrade-dashboard-source.py').read_text())
function = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'configure_diagnostic_identity')
namespace = {}
exec(compile(ast.Module(body=[function], type_ignores=[]), '<upgrade environment function>', 'exec'), namespace)
configure = namespace['configure_diagnostic_identity']
DEPLOYMENT = '72000000-0000-4000-8000-000000000001'


class UpgradeTests(unittest.TestCase):
    def test_exact_preservation_and_idempotency(self):
        for original in [b'A="literal \\n value"\nB="quoted \\" value"\n', b'A="without-final-newline"']:
            with self.subTest(original=original):
                updated = configure(original, DEPLOYMENT)
                self.assertTrue(updated.startswith(original))
                self.assertEqual(updated.count(b'JOBMAN_CONTROL_DIAGNOSTIC_DEPLOYMENT_ID='), 1)
                self.assertEqual(configure(updated, DEPLOYMENT), updated)
                self.assertEqual(configure(original, ''), original)

    def test_conflicting_identity_and_invalid_shape_fail(self):
        bad = [b'JOBMAN_CONTROL_DIAGNOSTIC_DEPLOYMENT_ID="different"\n',
               b'A="first"\nA="duplicate"\n', b'A=7\n', b'invalid line', b'x' * 65537]
        for original in bad:
            with self.subTest(original=original[:60]), self.assertRaises(ValueError):
                configure(original, DEPLOYMENT)
        with self.assertRaises(ValueError):
            configure(b'', '79000000-0000-4000-8000-000000000001')


if __name__ == '__main__':
    unittest.main()
