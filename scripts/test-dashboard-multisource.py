#!/usr/bin/env python3
"""Offline multi-source patch isolation tests; no Lab credentials or network."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

plan = load('multisource_test_plan', 'dashboard-multisource-plan.py')
stager = load('multisource_test_stager', 'stage-dashboard-multisource.py')

def inputs():
    source = {'id': plan.PRIMARY, 'origin': 'https://10.77.0.21:18443', 'expectedInstanceId': plan.PRIMARY_INSTANCE,
              'namespaceIds': ['11111111-1111-4111-8111-111111111111'], 'serviceId': 'primary-preserved'}
    remote = {'id': 'primary-broker', 'deploymentId': plan.PRIMARY, 'origin': 'https://10.77.0.21:19443', 'trustRootsFile': '/private/primary-ca.crt'}
    mapping = {'brokerId': remote['id'], 'deploymentId': plan.PRIMARY, 'targetGenerationId': 'primary-and-slurm-preserved', 'storeName': 'lab-nfs', 'storeVersion': '1'}
    values = {role: {'configurationRevision': 6, 'databaseURLFile': plan.ROOTS[role] + '/database-url', 'controls': [copy.deepcopy(source)],
                    'logBrokers': [copy.deepcopy(remote)], 'logMappings': [copy.deepcopy(mapping)], 'opaqueExistingSetting': {'preserve': True}}
              for role in ('api', 'worker')}
    values['api'].update(publicOrigin='https://dashboard.lab.test:8443', listen='10.77.0.10:8443', events={'enabled': True, 'deliveryHold': False})
    values['worker']['deliveryHold'] = False
    values['broker'] = {'configurationRevision': 6, 'listen': '10.77.0.21:19443', 'publicOrigin': 'https://10.77.0.21:19443',
            'stateDirectory': '/var/lib/jobman-dashboard-broker-lab', 'controls': [copy.deepcopy(source)], 'clientTrustRootsFile': '/private/existing-client-ca.crt',
            'services': [{'deploymentId': plan.PRIMARY, 'keyId': 'old-caller'}], 'logRoots': [{k: v for k, v in mapping.items() if k != 'brokerId'}]}
    values['broker']['logRoots'][0]['root'] = '/data/jobman/alice/dashboard-slurm'
    values['operator'] = {'schemaVersion': 1, 'databaseURLFile': plan.ROOTS['operator'] + '/database-url', 'deployments': [{'id': plan.PRIMARY, 'name': 'Primary'}]}
    fixture = {'synthetic': True, 'profile': 'secondary-v1', 'instanceId': plan.SECONDARY_INSTANCE, 'endpoint': 'https://10.77.0.21:28443',
               'delegationAudience': plan.SOURCE_AUDIENCE, 'namespaces': [{'name': name, 'id': f'11111111-1111-4111-8111-{i:012d}',
                  'targetGenerationId': f'22222222-2222-4222-8222-{i:012d}'} for i, name in enumerate(('dashboard-research', 'dashboard-operations'), 1)]}
    return values, fixture

class MultiSourceTests(unittest.TestCase):
    def test_patch_preserves_all_existing_values_and_source_qualified_mappings(self):
        original, fixture = inputs(); saved = copy.deepcopy(original); after = plan.patch(original, fixture)
        self.assertEqual(original, saved)
        for role in ('api', 'worker', 'broker'):
            self.assertEqual(after[role]['configurationRevision'], 7)
            self.assertEqual(after[role]['controls'][:-1], original[role]['controls'])
            self.assertEqual(after[role]['controls'][-1]['id'], plan.SECONDARY)
        for role in ('api', 'worker'):
            for name in ('logBrokers', 'logMappings'):
                self.assertEqual(after[role][name][:len(original[role][name])], original[role][name])
            self.assertEqual(after[role]['opaqueExistingSetting'], original[role]['opaqueExistingSetting'])
            self.assertEqual(after[role]['logBrokers'][-1]['trustRootsFile'], original[role]['logBrokers'][0]['trustRootsFile'])
        self.assertFalse(after['api']['events']['deliveryHold']); self.assertFalse(after['worker']['deliveryHold'])
        self.assertEqual(after['broker']['services'][0], original['broker']['services'][0])
        self.assertEqual(after['broker']['logRoots'][0], original['broker']['logRoots'][0])
        self.assertTrue(all(m['root'] == '/data/jobman/alice/dashboard-secondary' for m in after['broker']['logRoots'][1:]))
        self.assertEqual(after['operator']['deployments'][0], original['operator']['deployments'][0])

    def test_wrong_revision_source_hold_or_existing_secondary_fails_closed(self):
        for modify in [lambda c: c['api'].update(configurationRevision=5), lambda c: c['worker'].update(deliveryHold=True),
                       lambda c: c['broker']['controls'][0].update(expectedInstanceId=plan.SECONDARY_INSTANCE),
                       lambda c: c['api']['controls'].append({'id': plan.SECONDARY}),
                       lambda c: c['broker']['logRoots'][0].update(targetGenerationId='mismatch')]:
            values, fixture = inputs(); modify(values)
            with self.assertRaises(ValueError): plan.patch(values, fixture)
        values, fixture = inputs(); fixture['instanceId'] = plan.PRIMARY_INSTANCE
        with self.assertRaises(ValueError): plan.patch(values, fixture)

    def test_role_source_keys_and_broker_keys_are_distinct_no_ca_private_copy(self):
        values, fixture = inputs(); after = plan.patch(values, fixture)
        keys = {after[role]['controls'][-1]['delegationKeyId'] for role in ('api', 'worker', 'broker')}
        self.assertEqual(len(keys), 3)
        for role in ('api', 'worker'):
            self.assertNotEqual(after[role]['controls'][-1]['delegationKeyFile'], after[role]['logBrokers'][-1]['delegationKeyFile'])
        material = plan.material_plan(values)
        self.assertEqual(len(material['copyOnly']), 12)
        self.assertFalse(any(item['source'].endswith(('.env', 'fixture-ca.key', 'directory-password')) for item in material['copyOnly']))
        self.assertEqual(material['brokerClientTrust']['originalPath'], values['broker']['clientTrustRootsFile'])

    def test_offline_stage_private_exact_hashes_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve(); root.chmod(0o700); source = root / 'snapshot'; source.mkdir(mode=0o700)
            values, fixture = inputs()
            for role, value in dict(values, **{'secondary-fixture': fixture}).items(): stager.write(source / (role + '.json'), plan.encoded(value))
            old = os.umask(0o777)
            try: review = stager.stage(source, root / 'staged')
            finally: os.umask(old)
            self.assertFalse(review['applies']); self.assertFalse(review['liveVerifiedByThisCommand'])
            self.assertEqual((root / 'staged').stat().st_mode & 0o777, 0o700)
            for record in review['files']:
                raw = (root / 'staged' / (record['role'] + '.after.json')).read_bytes()
                self.assertEqual(plan.sha(raw), record['afterSHA256'])
                self.assertEqual((root / 'staged' / (record['role'] + '.after.json')).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError): stager.stage(source, root / 'staged')
            alias = root / 'alias'; alias.symlink_to(source, target_is_directory=True)
            with self.assertRaises(ValueError): stager.stage(alias, root / 'other')

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError): plan.decode(b'{"controls":[],"controls":[]}')

if __name__ == '__main__': unittest.main()
