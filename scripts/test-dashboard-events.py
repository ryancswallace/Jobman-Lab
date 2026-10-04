#!/usr/bin/env python3
"""Offline tests for the narrowly scoped synthetic event service registration."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('event_source', Path(__file__).with_name('configure-dashboard-event-source.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NAMESPACES = ['71000000-0000-4000-8000-000000000001', '71000000-0000-4000-8000-000000000002']


def registry():
    return {'services': [
        {'serviceId': 'dashboard-lab', 'keyId': 'synthetic-lab-v1', 'audience': 'urn:jobman:dashboard-lab:control',
         'publicKey': base64.b64encode(bytes(32)).decode(), 'certificateThumbprints': ['a' * 43],
         'namespaceIds': NAMESPACES, 'enabled': True,
         'operations': ['namespace.read', 'jobs.read', 'groups.read', 'targets.read', 'logs.read', 'artifacts.read', 'evidence.read']},
        {'serviceId': 'dashboard-log-broker-lab', 'operations': ['namespace.read', 'logs.read'], 'otherPreservedField': 'synthetic'}]}


class EventRegistrationTests(unittest.TestCase):
    def test_only_one_operation_changes_and_repeat_is_byte_identical(self):
        original = registry()
        raw = json.dumps(original).encode()
        changed = module.event_registry(raw, list(reversed(NAMESPACES)))
        expected = copy.deepcopy(original)
        expected['services'][0]['operations'].append('events.read')
        self.assertEqual(json.loads(changed), expected)
        self.assertEqual(module.event_registry(changed, NAMESPACES), changed)
        self.assertEqual(original, registry())

    def test_existing_policy_drift_and_revocations_are_not_overwritten(self):
        for field, value in [('keyId', 'different'), ('audience', 'other'), ('enabled', False),
                             ('namespaceIds', NAMESPACES[:1]), ('operations', ['jobs.cancel.own']),
                             ('publicKey', 'invalid'), ('certificateThumbprints', ['a' * 43, 'b' * 43])]:
            with self.subTest(field=field):
                document = registry()
                document['services'][0][field] = value
                with self.assertRaises((ValueError, TypeError)):
                    module.event_registry(json.dumps(document).encode(), NAMESPACES)
        document = registry()
        document['services'][1]['operations'].append('events.read')
        with self.assertRaises(ValueError):
            module.event_registry(json.dumps(document).encode(), NAMESPACES)

    def test_strict_document_and_namespace_bounds(self):
        for data in [b'{"services":[],"services":[]}', b'{}', b' ' * 65537, b'{"services":[null,{}]}']:
            with self.subTest(data_length=len(data)), self.assertRaises(ValueError):
                module.event_registry(data, NAMESPACES)
        for ids in [[], [NAMESPACES[0]] * 2, ['invalid', NAMESPACES[0]]]:
            with self.assertRaises(ValueError):
                module.event_registry(json.dumps(registry()).encode(), ids)


if __name__ == '__main__':
    unittest.main()
