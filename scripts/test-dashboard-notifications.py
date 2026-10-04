#!/usr/bin/env python3
"""No-network contract tests for the synthetic cancellation scenario wrapper."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('scenario', Path(__file__).with_name('dashboard-notification-scenario.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.receipt = 'a' * 32
        self.instance = 'e633cf92-258d-48ff-965a-fda88d68ef3a'
        self.namespace = '4156b832-9be8-40ff-a471-cb3061b6001d'
        self.original = {'instanceId': self.instance, 'namespaces': [{'name': 'dashboard-research', 'id': self.namespace}]}
        self.fixture = {'synthetic': True, 'fixtureVersion': 1, 'observationMode': 'normal-cancel-no-execution',
                        'helperCommit': 'b' * 40, 'receipt': self.receipt, 'deploymentId': module.DEPLOYMENT,
                        'controlInstanceId': self.instance, 'recoveryEpoch': '1', 'namespaceId': self.namespace,
                        'namespace': 'dashboard-research', 'jobs': [
                            {'case': 'first', 'jobId': '76000000-0000-4000-8000-000000000001'},
                            {'case': 'stopped', 'jobId': '76000000-0000-4000-8000-000000000002'}]}
        self.complete = {key: self.fixture[key] for key in ['synthetic', 'receipt', 'deploymentId', 'controlInstanceId', 'recoveryEpoch', 'namespaceId']}
        self.complete.update(case='first', jobId=self.fixture['jobs'][0]['jobId'], eventId='77000000-0000-4000-8000-000000000001',
                             outcome='cancelled', jobRevision='2', recordedAt='2026-10-04T12:00:00Z')

    def test_exact_public_receipts(self):
        self.assertEqual(module.validate_fixture(self.fixture, self.original, self.receipt), self.fixture)
        self.assertEqual(module.validate_completion(self.complete, self.fixture, 'first'), self.complete)
        for key, value in [('receipt', 'c' * 32), ('controlInstanceId', self.namespace), ('namespaceId', self.instance),
                           ('deploymentId', self.instance), ('observationMode', 'actual-workload'), ('privateToken', 'must-not-print')]:
            changed = copy.deepcopy(self.fixture)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                module.validate_fixture(changed, self.original, self.receipt)

    def test_original_terminal_identity(self):
        for key, value in [('eventId', "x';DROP"), ('jobId', self.fixture['jobs'][1]['jobId']), ('outcome', 'success'),
                           ('recoveryEpoch', '2'), ('runId', 'not-a-uuid'), ('secret', 'must-not-print')]:
            changed = dict(self.complete, **{key: value})
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                module.validate_completion(changed, self.fixture, 'first')

    def test_receipts_are_immutable_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            module.retained_json(path, self.fixture)
            module.retained_json(path, self.fixture)
            self.assertEqual(module.retained_json(path), self.fixture)
            with self.assertRaises(RuntimeError):
                module.retained_json(path, self.complete)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                module.retained_json(link)
            oversized = Path(directory) / 'oversized'
            oversized.write_bytes(b' ' * 8193)
            with self.assertRaises(RuntimeError):
                module.retained_json(oversized)


if __name__ == '__main__':
    unittest.main()
