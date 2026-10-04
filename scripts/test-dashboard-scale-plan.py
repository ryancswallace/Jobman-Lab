#!/usr/bin/env python3
"""Offline additive-scope and source-preservation regression checks."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('scale_plan', Path(__file__).with_name('dashboard-scale-plan.py'))
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def uid(number):
    return '79000000-0000-4000-8000-%012d' % number


def fixture():
    configs = {role: {'configurationRevision': 7, 'controls': [], 'logRoots' if role == 'broker' else 'logMappings':
                     [{'sentinel': 'preserve exact roots, stores, generations, and paths'}],
                     'privateMaterial': '/unchanged/'+role}
               for role in ('api', 'worker', 'broker')}
    configs['api']['events'] = {'enabled': True, 'deliveryHold': False, 'retentionDays': 30}
    configs['worker'].update(deliveryHold=False, components=['ingestion','notifications','reports'])
    configs['operator'] = {'schemaVersion': 1, 'deployments': [{'id': d} for d in plan.INSTANCES],
                           'databaseURLFile': '/operator/private-url'}
    configs['api']['logBrokers'], configs['worker']['logBrokers'], configs['broker']['services'] = [], [], []
    registries, seeds = {}, {}
    for source, (deployment, instance) in enumerate(plan.INSTANCES.items()):
        original = [uid(source*100+1), uid(source*100+2)]
        registries[deployment] = {'services': []}
        for role in ('api','worker','broker'):
            service = '%s-source-%d' % (role,source)
            row = {'id': deployment, 'origin': 'https://10.77.0.21:'+('18443' if source == 0 else '28443'),
                   'expectedInstanceId': instance, 'namespaceIds': original.copy(), 'serviceId': service,
                   'delegationKeyId': service+'-key', 'audience': 'source-'+str(source),
                   'trustRootsFile': '/public-ca', 'clientKeyFile': '/private-key'}
            configs[role]['controls'].append(row)
            registries[deployment]['services'].append({'serviceId': service, 'keyId': service+'-key',
                'audience': row['audience'], 'namespaceIds': original.copy(), 'enabled': True,
                'operations': ['namespaces.read', 'events.read'] if role == 'worker' else ['jobs.read'],
                'publicKey': 'original-public-key', 'certificateThumbprints': ['original-thumbprint']})
            if role == 'broker': continue
            caller = service+'-broker'
            configs[role]['logBrokers'].append({'deploymentId': deployment, 'namespaceIds': original.copy(),
                'serviceId': caller, 'delegationKeyId': caller+'-key', 'audience': 'logs-'+str(source),
                'clientKeyFile': '/original-client'})
            configs['broker']['services'].append({'deploymentId': deployment, 'namespaceIds': original.copy(),
                'serviceId': caller, 'keyId': caller+'-key', 'audience': 'logs-'+str(source),
                'publicKeyFile': '/original-public-key'})
        registries[deployment]['services'].append({'serviceId': 'historical', 'keyId': 'historical',
            'audience': 'historical', 'namespaceIds': original.copy(), 'enabled': False})
        namespaces = []
        for index in range(10 if source == 0 else 5):
            namespaces.append({'id': uid(1000+source*100+index), 'name': 'dashboard-scale-%02d' % (index+1),
                'activeJobId': uid(2000+source*100+index), 'importedJobId': uid(3000+source*100+index),
                'activeJobs': 50, 'importedHistory': 10000})
        identities = [{'directoryId': '74000000-0000-4000-8000-%012d' % (i+1), 'issuer': plan.ISSUER,
                       'subject': uid(4000+i), 'principalId': uid(5000+source*100+i),
                       'displayName': 'Synthetic scale %02d' % (i+1)} for i in range(25)]
        seeds[deployment] = {'version': 1, 'synthetic': True, 'mode': 'imported-history-no-execution',
            'deploymentId': deployment, 'instanceId': instance, 'recoveryEpoch': '1',
            'namespaces': namespaces, 'identities': identities}
    configs['broker']['services'].append({'deploymentId': plan.PRIMARY, 'namespaceIds': [uid(1),uid(2)],
        'serviceId': 'historical-broker', 'keyId': 'historical-key', 'audience': 'historical-audience',
        'publicKeyFile': '/historical-public-key'})
    return configs, registries, seeds


class ScalePlan(unittest.TestCase):
    def test_only_permitted_fields_change_and_inputs_remain_unchanged(self):
        configs, registries, seeds = fixture()
        before = copy.deepcopy((configs,registries,seeds))
        result = plan.patch(configs,registries,seeds)
        self.assertEqual((configs,registries,seeds),before)
        actual, trust = result['configs'], result['registries']
        for role in ('api','worker','broker'):
            self.assertEqual(actual[role]['configurationRevision'],8)
            actual[role]['configurationRevision'] = 7
            for old,new in zip(configs[role]['controls'],actual[role]['controls']):
                extra = [row['id'] for row in seeds[old['id']]['namespaces']]
                self.assertEqual(new['namespaceIds'],sorted(old['namespaceIds']+extra))
                new['namespaceIds'] = old['namespaceIds']
            key = 'services' if role == 'broker' else 'logBrokers'
            for old,new in zip(configs[role][key],actual[role][key]):
                if old['serviceId'] == 'historical-broker':
                    self.assertEqual(old,new)
                    continue
                extra = [row['id'] for row in seeds[old['deploymentId']]['namespaces']]
                self.assertEqual(new['namespaceIds'],sorted(old['namespaceIds']+extra))
                new['namespaceIds'] = old['namespaceIds']
        for deployment in plan.INSTANCES:
            for old,new in zip(registries[deployment]['services'],trust[deployment]['services']):
                if old['serviceId'] == 'historical':
                    self.assertEqual(old,new)
                    continue
                self.assertEqual(new['namespaceIds'],sorted(old['namespaceIds']+[row['id'] for row in seeds[deployment]['namespaces']]))
                new['namespaceIds'] = old['namespaceIds']
        self.assertEqual(actual,configs)
        self.assertEqual(trust,registries)
        self.assertEqual(len(result['feedRecoveryRequired']),2)
        self.assertFalse(result['automaticFeedReset'])
        self.assertTrue(result['directoryReconciliationRequired'])

    def test_source_revision_and_seed_identity_mismatches_are_rejected(self):
        mutations = [lambda c,r,s:c['api'].update(configurationRevision=8),
                     lambda c,r,s:c['worker']['controls'][0].update(expectedInstanceId=uid(99)),
                     lambda c,r,s:s[plan.PRIMARY].update(synthetic=False),
                     lambda c,r,s:s[plan.PRIMARY].update(recoveryEpoch='2'),
                     lambda c,r,s:s[plan.SECONDARY]['identities'][0].update(subject=uid(999)),
                     lambda c,r,s:s[plan.PRIMARY]['namespaces'][0].update(activeJobs=51)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                values=fixture(); mutate(*values)
                with self.assertRaises(ValueError):plan.patch(*values)

    def test_no_duplicate_aliases_namespaces_or_job_samples(self):
        for field in ('subject','principalId'):
            values=fixture(); identities=values[2][plan.PRIMARY]['identities']
            identities[1][field]=identities[0][field]
            with self.assertRaises(ValueError):plan.patch(*values)
        for field in ('id','activeJobId'):
            values=fixture(); rows=values[2][plan.PRIMARY]['namespaces']
            if field == 'id': rows[1]['id']=rows[0]['id']
            else: rows[0]['activeJobId']=rows[0]['importedJobId']
            with self.assertRaises(ValueError):plan.patch(*values)

    def test_missing_disabled_duplicate_and_scope_drift_in_service_registry_fail(self):
        for case in ('missing','disabled','duplicate','drift'):
            values=fixture(); rows=values[1][plan.PRIMARY]['services']
            if case == 'missing': rows.pop(0)
            elif case == 'disabled': rows[0]['enabled']=False
            elif case == 'duplicate': rows.append(copy.deepcopy(rows[0]))
            else: rows[0]['namespaceIds']=[uid(88),uid(89)]
            with self.subTest(case=case),self.assertRaises(ValueError):plan.patch(*values)

    def test_broker_duplicate_callers_and_role_scope_disagreement_fail(self):
        values=fixture(); values[0]['broker']['services'][1]=copy.deepcopy(values[0]['broker']['services'][0])
        with self.assertRaises(ValueError):plan.patch(*values)
        values=fixture(); values[0]['worker']['controls'][0]['namespaceIds']=[uid(88),uid(89)]
        with self.assertRaises(ValueError):plan.patch(*values)

    def test_existing_scale_namespace_blocks_reapplication(self):
        values=fixture(); values[2][plan.PRIMARY]['namespaces'][0]['id']=values[0]['api']['controls'][0]['namespaceIds'][0]
        with self.assertRaises(ValueError):plan.patch(*values)

    def test_secondary_broker_duplicate_or_missing_registration_fails(self):
        values=fixture(); rows=values[0]['broker']['services']
        rows.append(copy.deepcopy(next(row for row in rows if row['deploymentId']==plan.SECONDARY)))
        with self.assertRaises(ValueError):plan.patch(*values)
        values=fixture(); rows=values[0]['broker']['services']
        rows.remove(next(row for row in rows if row['deploymentId']==plan.SECONDARY))
        with self.assertRaises(ValueError):plan.patch(*values)

    def test_runtime_hold_policy_is_preserved_and_mismatch_fails(self):
        for role in ('api','worker'):
            values=fixture()
            target=values[0][role]['events'] if role=='api' else values[0][role]
            target['deliveryHold']=True
            with self.subTest(role=role),self.assertRaises(ValueError):plan.patch(*values)


if __name__ == '__main__': unittest.main()
