#!/usr/bin/env python3
"""Offline planning and staging tests; never opens Lab credentials or SSH."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

plan = module('second_source_plan', 'dashboard-second-source-plan.py')
stager = module('second_source_stage', 'prepare-dashboard-second-source.py')


def inputs():
    subjects = ['a09dbdf8-aa70-42e7-b58e-fa724f9e3b0d', 'bf296166-4679-441c-b673-71148032d752']
    primary = {'synthetic': True, 'instanceId': plan.PRIMARY_INSTANCE, 'endpoint': 'https://10.77.0.21:18443',
               'issuer': plan.ISSUER, 'identities': [{'directoryId': guid, 'issuer': plan.ISSUER, 'subject': subject}
                                                  for guid, subject in zip(plan.DIRECTORY_IDS, subjects)],
               'namespaces': [{'id': f'40000000-0000-4000-8000-{i:012d}', 'name': name} for i, name in
                              enumerate(['dashboard-research', 'dashboard-operations'], 1)]}
    oidc = {'issuer': plan.ISSUER, 'audience': plan.AUDIENCE, 'webClientId': 'jobman-dashboard-web',
            'nativeClientId': 'jobman-dashboard-native', 'clientIdentityClaim': 'azp', 'directoryGuidClaim': 'directory_guid',
            'users': [{'username': 'dashboard-' + name, 'subject': subject, 'directoryGuid': guid}
                      for name, subject, guid in zip(['alice', 'bob'], subjects, plan.DIRECTORY_IDS)]}
    build = {'revision': plan.SOURCE_REVISION, 'sha256': plan.SOURCE_SHA256, 'platform': 'linux/arm64',
             'toolchain': 'go1.26.6', 'migration': plan.MIGRATION}
    return primary, oidc, build


class SecondaryPlanTests(unittest.TestCase):
    def test_identity_scope_and_asymmetric_groups(self):
        value = plan.make_plan(*inputs())
        self.assertFalse(value['applySupported'])
        second = value['secondary']
        self.assertNotEqual(value['primary']['deploymentId'], second['deploymentId'])
        self.assertEqual(second['instanceId'], 'GENERATE_FRESH_DO_NOT_COPY')
        self.assertEqual(second['database'], 'jobman_dashboard_control_secondary')
        self.assertEqual(len(second['directGroups']), 8)
        self.assertEqual({g['role'] for g in second['directGroups']}, {'viewer', 'submitter', 'operator', 'namespace_admin'})
        operations = [g for g in second['directGroups'] if g['namespaceName'] == 'dashboard-operations']
        self.assertEqual([g['members'] for g in operations], [[], [], [], [plan.DIRECTORY_IDS[1]]])
        self.assertFalse(second['copyPrimaryTrust'])
        self.assertFalse(second['copyPrimaryDatabase'])
        self.assertTrue(all(g['id'].startswith('73000000-') for g in second['directGroups']))
        self.assertNotIn('password', json.dumps(value).lower())

    def test_pins_and_signed_aliases_fail_closed(self):
        for mutate in [lambda p, o, b: p.update(instanceId='10000000-0000-4000-8000-000000000001'),
                       lambda p, o, b: b.update(migration='000020_diagnostic_snapshots.sql'),
                       lambda p, o, b: b.update(sha256='0' * 64),
                       lambda p, o, b: o['users'][0].update(subject=o['users'][1]['subject']),
                       lambda p, o, b: o.update(directoryGuidClaim='email')]:
            values = inputs()
            mutate(*values)
            with self.assertRaises(ValueError):
                plan.make_plan(*values)

    def test_bounded_regular_inputs_and_ambiguous_json(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path).resolve()
            item = root / 'input.json'
            item.write_bytes(b'{"a":1,"a":2}')
            with self.assertRaises(ValueError):
                plan.json_value(plan.read(item, 64))
            with self.assertRaises(ValueError):
                plan.read(item, 4)
            (root / 'alias').symlink_to(item)
            with self.assertRaises(OSError):
                plan.read(root / 'alias', 64)

    def test_stage_is_private_exclusive_and_preserves_existing(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path).resolve()
            root.chmod(0o700)
            target = root / 'secondary'
            value = plan.make_plan(*inputs())
            stager.stage(target, value)
            original = (target / 'plan.json').read_bytes()
            self.assertEqual((target / 'plan.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                stager.stage(target, value)
            self.assertEqual((target / 'plan.json').read_bytes(), original)
            root.chmod(0o755)
            with self.assertRaises(ValueError):
                stager.stage(root / 'not-private', value)

    def test_wrong_build_never_reaches_staging(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path).resolve()
            (root / 'build.json').write_text(json.dumps({'revision': '0' * 40, 'platform': 'linux/arm64', 'toolchain': 'go1.26.6'}))
            with self.assertRaises(ValueError):
                plan.validate_build(root)


if __name__ == '__main__':
    unittest.main()
