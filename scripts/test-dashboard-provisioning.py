#!/usr/bin/env python3
"""Offline contract tests for scoped Dashboard Lab provisioning."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ACL = load('acl_policy', 'ansible/roles/dashboard_log_reader/files/provision-acls.py')
OIDC = load('oidc_policy', 'ansible/roles/dashboard_identity/files/configure-identity.py')
PREFIX = ('namespaces', 'dashboard-research', 'jobs', '01990000-0000-7000-8000-000000000001',
          'executions', '01990000-0000-7000-8000-000000000002', 'logs', 'stdout')


class ProvisioningTests(unittest.TestCase):
    def test_only_shared_prefixes_are_traversable(self):
        for count in range(9):
            self.assertTrue(ACL.shared_directory(PREFIX[:count]))
        for path in [('inputs',), PREFIX[:6] + ('artifacts',), PREFIX + ('child',),
                     ('namespaces', '..'), PREFIX[:3] + ('0' * 36,)]:
            self.assertFalse(ACL.shared_directory(path))

    def test_removing_reader_preserves_existing_access_and_default_masks(self):
        entries = ['user::rwx', 'user:21901:r-x', 'user:21002:rwx', 'group::rwx',
                   'mask::r-x', 'other::---', 'default:user:21901:r-x',
                   'default:group::rwx', 'default:mask::r--']
        with patch.object(ACL, 'set_acl') as writer:
            ACL.remove_reader(Path('/synthetic'), entries)
        self.assertEqual(writer.call_args_list[0].args, (Path('/synthetic'), '-n', '-x', 'u:21901'))
        self.assertEqual(writer.call_args_list[1].args, (Path('/synthetic'), '-n', '-x', 'd:u:21901'))

    def test_parent_traversal_adds_only_execute_to_existing_mask(self):
        for old, expected in [('---', '--x'), ('r--', 'r-x'), ('rw-', 'rwx'), ('-w-', '-wx'), ('r-x', 'r-x')]:
            self.assertEqual(ACL.traversal_mask(['group::---', 'mask::' + old]), expected)
        self.assertEqual(ACL.traversal_mask(['group::r--']), 'r-x')
        for entry in ['group::rwx', 'group:21002:--x', 'user:21002:r-x']:
            with self.assertRaises(RuntimeError):
                ACL.traversal_mask(['group::---', 'mask::r--', entry])
        self.assertEqual(ACL.traversal_mask(['group::---', 'mask::r--', 'user:21901:r-x']), 'r-x')

    def test_log_sequence_is_canonical_and_bounded(self):
        for value in ['00000001.chunk', '99999999.chunk', '9223372036854775807.chunk']:
            self.assertTrue(ACL.shared_file(PREFIX + (value,)))
        for value in ['1.chunk', '00000000.chunk', '000000001.chunk', '9223372036854775808.chunk',
                      'result', '../00000001.chunk', '00000001.chunk.extra']:
            self.assertFalse(ACL.shared_file(PREFIX + (value,)))
        self.assertFalse(ACL.shared_file(PREFIX[:6] + ('artifacts', 'stdout', '00000001.chunk')))

    def test_clients_require_exact_pkce_flows(self):
        resource, web, native = OIDC.client_specs('private-test-value')
        self.assertTrue(resource['bearerOnly'])
        for client in [web, native]:
            self.assertTrue(client['standardFlowEnabled'])
            for setting in ['directAccessGrantsEnabled', 'implicitFlowEnabled', 'serviceAccountsEnabled', 'fullScopeAllowed']:
                self.assertFalse(client[setting])
            self.assertEqual(client['attributes']['pkce.code.challenge.method'], 'S256')
        self.assertFalse(web['publicClient'])
        self.assertTrue(native['publicClient'])
        self.assertEqual(web['redirectUris'], ['https://dashboard.lab.test:8443/auth/callback'])
        self.assertEqual(native['redirectUris'], ['jobman-dashboard-auth://callback'])

    def test_readback_rejects_policy_or_mapper_drift(self):
        wanted = OIDC.client_specs('private-test-value')[1]
        OIDC.verify_client(copy.deepcopy(wanted), wanted)
        for mutate in [lambda c: c.update(directAccessGrantsEnabled=True),
                       lambda c: c.update(redirectUris=['https://*.lab.test/*']),
                       lambda c: c['attributes'].update({'pkce.code.challenge.method': 'plain'}),
                       lambda c: c['protocolMappers'][1]['config'].update({'user.attribute': 'email'})]:
            current = copy.deepcopy(wanted)
            mutate(current)
            with self.assertRaises(RuntimeError):
                OIDC.verify_client(current, wanted)

    def test_guid_and_audience_are_signed_token_mappers(self):
        mapper = OIDC.directory_mapper()
        self.assertEqual(mapper['config']['claim.name'], 'directory_guid')
        self.assertEqual(mapper['config']['user.attribute'], 'dashboard_directory_guid')
        self.assertEqual(mapper['config']['multivalued'], 'false')
        for mapper in [mapper, OIDC.audience_mapper()]:
            self.assertEqual(mapper['config']['id.token.claim'], 'true')
            self.assertEqual(mapper['config']['access.token.claim'], 'true')


if __name__ == '__main__':
    unittest.main()
