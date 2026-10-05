#!/usr/bin/env python3
"""Offline coverage of target reuse after idempotency receipts expire."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('targets', Path(__file__).with_name('ensure-control-target.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class TargetTests(unittest.TestCase):
    def setUp(self):
        self.expected = {'apiVersion': 'jobman.control/v1alpha1', 'kind': 'Target', 'metadata': {'name': 'onprem-slurm'}, 'spec': {'kind': 'slurm', 'partitions': []}}
        self.actual = copy.deepcopy(self.expected)
        self.actual['metadata'].update(namespace='research', id='11111111-1111-4111-8111-111111111111', generationId='22222222-2222-4222-8222-222222222222')
        self.actual['spec']['controlTransport'] = 'agent-api'
        del self.actual['spec']['partitions']
        self.actual['status'] = {'state':'active'}

    def run_requests(self, responses):
        calls = []
        def request(method, path):
            calls.append(method)
            return responses.pop(0)
        value = m.ensure(self.expected, request)
        self.assertEqual(value, self.actual)
        self.assertFalse(responses)
        return calls

    def test_existing_matching_target_needs_only_get(self):
        self.assertEqual(self.run_requests([(200, self.actual)]), ['GET'])

    def test_missing_target_is_created(self):
        self.assertEqual(self.run_requests([(404, {}), (201, self.actual)]), ['GET','POST'])

    def test_create_race_rechecks_existing_target(self):
        self.assertEqual(self.run_requests([(404, {}), (409, {}), (200, self.actual)]), ['GET','POST','GET'])

    def test_drift_is_rejected_without_writes(self):
        self.actual['spec']['kind'] = 'host'
        with self.assertRaisesRegex(RuntimeError, 'configuration differs'):
            m.ensure(self.expected, lambda method, path: self.assertEqual(method, 'GET') or (200, self.actual))

    def test_wrong_namespace_and_inactive_target_are_rejected(self):
        for field, value in [('namespace','other'), ('id','bad'), ('generationId','00000000-0000-0000-0000-000000000000')]:
            actual = copy.deepcopy(self.actual); actual['metadata'][field] = value
            with self.assertRaises((RuntimeError, ValueError)):
                m.validate(self.expected, actual)
        self.actual['status']['state'] = 'disabled'
        with self.assertRaises(RuntimeError): m.validate(self.expected, self.actual)

    def test_auth_or_service_error_never_creates_target(self):
        for status in (401,403,409,500,503):
            with self.assertRaises(RuntimeError):
                m.ensure(self.expected, lambda method, path: self.assertEqual(method,'GET') or (status, {}))

if __name__ == '__main__': unittest.main()
