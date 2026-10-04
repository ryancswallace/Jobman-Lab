#!/usr/bin/env python3
"""Offline exact-build, additive-map and execution isolation regression tests."""
import ast
import copy
import os
import stat
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('execution_plan', Path(__file__).with_name('dashboard-execution-plan.py'))
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def identifier(number):
    return '78000000-0000-4000-8000-' + f'{number:012d}'


def fixture():
    return {'synthetic': True, 'endpoint': 'https://10.77.0.21:18443', 'instanceId': identifier(1),
            'namespaces': [{'name': plan.NAMESPACE, 'id': identifier(2)}]}


def receipt():
    return {'synthetic': True, 'mode': 'actual-subprocess-execution', 'deploymentId': plan.DEPLOYMENT,
            'controlInstanceId': identifier(1), 'namespaceId': identifier(2), 'namespace': plan.NAMESPACE,
            'targetName': plan.TARGET, 'targetGenerationId': identifier(3), 'storeRoot': plan.STORE_ROOT}


def config():
    return {'configurationRevision': 17, 'preserved': {'unrelated': ['do', 'not', 'change']},
            'controls': [{'id': plan.DEPLOYMENT, 'expectedInstanceId': identifier(1), 'origin': 'https://10.77.0.21:18443', 'namespaceIds': [identifier(2)]}],
            'logBrokers': [{'id': 'control01-nfs', 'deploymentId': plan.DEPLOYMENT, 'origin': 'https://10.77.0.21:19443', 'namespaceIds': [identifier(2)]}],
            'logMappings': [{'deploymentId': 'another', 'targetGenerationId': identifier(4)}],
            'logRoots': [{'deploymentId': 'another', 'targetGenerationId': identifier(4), 'root': '/existing'}]}


class ExecutionPlanTests(unittest.TestCase):
    def test_only_explicit_exact_clean_build_can_produce_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = b'\x7fELF\x02\x01' + b'\x00' * 12 + b'\xb7\x00' + b'public-test-binary'
            (root/'jobman-agent').write_bytes(binary)
            metadata = {'revision': plan.REVISION, 'platform': 'linux/arm64', 'toolchain': 'go1.26.6', 'sha256': {'jobman-agent': hashlib.sha256(binary).hexdigest()}}
            (root/'build.json').write_text(json.dumps(metadata))
            value = plan.make_plan(root, fixture(), 'a' * 40)
            self.assertEqual(value['expectedUID'], 21001)
            self.assertEqual(value['storeRoot'], '/data/jobman/alice/dashboard-execution')
            unit = plan.unit_text(value['agentSHA256'])
            self.assertIn('NoNewPrivileges=true', unit)
            self.assertIn('--max-log-bytes 1048576', unit)
            self.assertNotIn('/var/lib/jobman-agent/', unit)
            self.assertNotIn('jobman-control.service', unit)
            (root/'jobman-agent').write_bytes(binary+b'changed')
            with self.assertRaises(ValueError): plan.validate_build(root)
            (root/'jobman-agent').unlink()
            (root/'jobman-agent').symlink_to(root/'build.json')
            with self.assertRaises(OSError): plan.validate_build(root)

    def test_mapping_preserves_every_unrelated_field_and_is_idempotent(self):
        for role, key in [('api', 'logMappings'), ('reports', 'logMappings'), ('broker', 'logRoots')]:
            original = config()
            patched = plan.mapping_patch(original, receipt(), role, 17)
            self.assertEqual(patched['configurationRevision'], 18)
            self.assertEqual(patched[key][:-1], original[key])
            for name in original:
                if name not in [key, 'configurationRevision']:
                    self.assertEqual(patched[name], original[name])
            self.assertEqual(original, config())
            self.assertEqual(plan.mapping_patch(patched, receipt(), role, 18), patched)
            if role == 'broker': self.assertEqual(patched[key][-1]['root'], plan.STORE_ROOT)

    def test_provision_new_modes_ignore_umask_but_existing_paths_are_not_repaired(self):
        spec = importlib.util.spec_from_file_location('execution_prepare_test', Path(__file__).with_name('prepare-dashboard-execution.py'))
        prepare = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(prepare)
        parsed = ast.parse(prepare.PROVISION)
        helpers = ast.Module(body=[node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name in ['directory', 'file']], type_ignores=[])
        namespace = {'os': os, 'stat': stat}
        exec(compile(helpers, 'provision_helpers', 'exec'), namespace)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous = os.umask(0o077)
            try:
                namespace['directory'](root/'new', 0o755, os.getuid(), os.getgid())
                namespace['file'](root/'new'/'public-ca', b'PUBLIC SYNTHETIC CERTIFICATE', 0o644)
                namespace['file'](root/'new'/'binary', b'PUBLIC SYNTHETIC BINARY', 0o755)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE((root/'new').stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((root/'new'/'public-ca').stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((root/'new'/'binary').stat().st_mode), 0o755)
            (root/'new').chmod(0o700)
            with self.assertRaises(AssertionError): namespace['directory'](root/'new', 0o755, os.getuid(), os.getgid())
            self.assertEqual(stat.S_IMODE((root/'new').stat().st_mode), 0o700)
            existing = root/'existing'; existing.write_bytes(b'PUBLIC'); existing.chmod(0o600)
            with self.assertRaises(AssertionError): namespace['file'](existing, b'PUBLIC', 0o644)
            self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o600)

    def test_stale_revision_wrong_scope_and_conflicting_mapping_rejected(self):
        with self.assertRaises(ValueError): plan.mapping_patch(config(), receipt(), 'api', 16)
        for field, value in [('deploymentId', identifier(9)), ('controlInstanceId', identifier(9)), ('namespaceId', identifier(9)), ('targetGenerationId', '../other'), ('storeRoot', '/data'), ('mode', 'synthetic-observations')]:
            changed = receipt(); changed[field] = value
            with self.assertRaises(ValueError): plan.mapping_patch(config(), changed, 'api', 17)
        changed = config(); changed['logMappings'].append({'deploymentId': plan.DEPLOYMENT, 'targetGenerationId': identifier(3), 'brokerId': 'other'})
        with self.assertRaises(ValueError): plan.mapping_patch(changed, receipt(), 'api', 17)
        changed = config(); changed['controls'][0]['namespaceIds'] = []
        with self.assertRaises(ValueError): plan.mapping_patch(changed, receipt(), 'broker', 17)


if __name__ == '__main__':
    unittest.main()
