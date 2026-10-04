#!/usr/bin/env python3
"""Offline restoration guards; no SSH, real credentials, SQL or service access."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


p = module('restore', 'dashboard-restore-plan.py')
prepare = module('restore_prepare', 'prepare-dashboard-restore.py')
UUID = '11111111-1111-4111-8111-111111111111'
NS = '22222222-2222-4222-8222-222222222222'
META = {'revision': 'a' * 40}


def fixture(two_sources=False):
    def controls(role):
        result = []
        for index, (deployment, origin) in enumerate(p.SOURCES.items()):
            if index and not two_sources:
                break
            result.append({'id': deployment, 'origin': origin, 'expectedInstanceId': UUID,
                           'namespaceIds': [NS], 'serviceId': 'dashboard-' + role + '-lab',
                           'delegationKeyId': role + '-key', 'audience': 'urn:fixture:control',
                           'delegationKeyFile': p.PRIMARY[role] + '/source-' + str(index) + '.key'})
        return result
    mapping = {'deploymentId': next(iter(p.SOURCES)), 'targetGenerationId': UUID,
               'storeName': 'lab-nfs', 'storeVersion': '1', 'brokerId': 'nfs'}
    api = {'configurationRevision': 7, 'publicOrigin': 'https://dashboard.lab.test:8443', 'listen': '10.77.0.10:8443',
           'databaseURLFile': p.PRIMARY['api'] + '/database-url', 'events': {'enabled': True, 'deliveryHold': False},
           'oidc': {'issuer': p.ISSUER, 'webClientSecretFile': p.PRIMARY['api'] + '/web-secret'},
           'encryption': {'keyId': 'original', 'keyFile': p.PRIMARY['api'] + '/auth.key'},
           'serverTLS': {'certificateFile': p.PRIMARY['api'] + '/server.crt', 'keyFile': p.PRIMARY['api'] + '/server.key'},
           'controls': controls('api'), 'logBrokers': [{'id':'nfs','origin':'https://10.77.0.21:19443','deploymentId':next(iter(p.SOURCES)),'namespaceIds':[NS]}], 'logMappings': [mapping],
           'reports': {'objectRoot': '/var/lib/jobman-dashboard-reports-lab', 'objectAccess': {'mode': 'shared_group', 'workerUid': 21905, 'readerGid': 21906},
                       'redactionFile': p.PRIMARY['api'] + '/redaction.json', 'policyKeyFile': p.PRIMARY['api'] + '/policy.key'},
           'logCursorKeyFile': p.PRIMARY['api'] + '/cursor.key', 'notifications': {'deviceTopics': []}}
    worker = {'configurationRevision': 7, 'databaseURLFile': p.PRIMARY['worker'] + '/database-url',
              'components': ['ingestion', 'notifications', 'reports', 'retention'], 'identityIssuer': p.ISSUER,
              'controls': controls('worker'), 'logBrokers': copy.deepcopy(api['logBrokers']), 'logMappings': [mapping], 'deliveryHold': False,
              'reports': {'objectRoot': '/var/lib/jobman-dashboard-reports-lab', 'objectAccess': copy.deepcopy(api['reports']['objectAccess']),
                          'redactionFile': p.PRIMARY['worker'] + '/redaction.json', 'policyKeyFile': p.PRIMARY['worker'] + '/policy.key'},
              'logCursorKeyFile': p.PRIMARY['worker'] + '/cursor.key', 'notifications': {'deviceTopics': []}}
    snapshot = {'formatVersion': 1, 'synthetic': True, 'database': 'jobman_dashboard', 'candidateRevision': META['revision'],
                'configurationRevision': 7, 'capturedAt': '2026-10-04T15:00:00Z',
                'schema': {'migrationCount': 18, 'ledgerSHA256': 'b' * 64}, 'hold': {'generation': '3', 'held': False},
                'sources': [dict(p.binding(c), recoveryEpoch='1', configurationRevision=7, state='active') for c in api['controls']], 'files': []}
    for role, config in [('api', api), ('worker', worker)]:
        for path in p.file_references(config):
            snapshot['files'].append({'path': path, 'sha256': 'c' * 64, 'bytes': 32, 'uid': 21904 if role == 'api' else 21905,
                                      'gid': 21904 if role == 'api' else 21905, 'mode': '0600'})
    return api, worker, snapshot


def inputs(api, worker, snapshot):
    raw = {'api': p.encoded(api), 'worker': p.encoded(worker)}
    snapshot = dict(snapshot, apiSHA256=p.sha(raw['api']), workerSHA256=p.sha(raw['worker']))
    return dict(raw, snapshot=p.encoded(snapshot))


class RestoreTests(unittest.TestCase):
    def test_preserves_actual_sources_mappings_and_identity_without_provider(self):
        a, w, s = fixture(True)
        original = copy.deepcopy((a, w, s))
        receipt, configs = p.make_plan(META, 'd' * 64, inputs(a, w, s))
        self.assertEqual((a, w, s), original)
        self.assertEqual(receipt['configurationRevision'], 7)
        self.assertEqual(len(receipt['sources']), 2)
        self.assertEqual(configs['api']['logMappings'], a['logMappings'])
        self.assertEqual(configs['worker']['components'], ['ingestion', 'notifications', 'reports'])
        self.assertTrue(configs['api']['events']['deliveryHold'])
        self.assertTrue(configs['worker']['deliveryHold'])
        self.assertFalse(receipt['clone']['deliveryAllowed'])
        self.assertFalse(receipt['applySupported'])
        self.assertEqual(configs['recovery']['controls'], configs['worker']['controls'])
        for role in ('api', 'worker'):
            self.assertNotEqual(configs[role]['databaseURLFile'], original[0 if role == 'api' else 1]['databaseURLFile'])
            for before, after in zip(original[0 if role == 'api' else 1]['controls'], configs[role]['controls']):
                for key in ('id', 'origin', 'expectedInstanceId', 'namespaceIds', 'serviceId', 'delegationKeyId', 'audience'):
                    self.assertEqual(before[key], after[key])
            self.assertTrue(all(ref.startswith(p.ROOTS[role] + '/') for ref in p.file_references(configs[role])))
        self.assertNotIn('encryption', configs['worker'])
        self.assertNotIn('oidc', configs['worker'])

    def test_rejects_omitted_or_rebound_or_inactive_sources(self):
        for change in [lambda a,w,s: s['sources'].pop(), lambda a,w,s: s['sources'][0].update(controlInstanceId=NS),
                       lambda a,w,s: s['sources'][0].update(recoveryEpoch='01'), lambda a,w,s: s['sources'][0].update(state='paused'),
                       lambda a,w,s: s['sources'][0].update(namespaceIds=[]), lambda a,w,s: w.update(configurationRevision=8),
                       lambda a,w,s: a['controls'][0].update(origin='https://unapproved.example'),
                       lambda a,w,s: s['hold'].update(held=True), lambda a,w,s: s['schema'].update(migrationCount=17)]:
            a,w,s=fixture(True);change(a,w,s)
            with self.subTest(change=change), self.assertRaises(ValueError):
                p.make_plan(META,'d'*64,inputs(a,w,s))

    def test_rejects_provider_delivery_and_cross_role_private_access(self):
        for change in [lambda a,w,s: w['components'].append('delivery'),
                       lambda a,w,s: a['notifications'].update(apns=[{'privateKeyFile':'/private/key'}]),
                       lambda a,w,s: w['notifications'].update(tokenEncryption={'current':{}}),
                       lambda a,w,s: w['reports'].update(policyKeyFile=p.PRIMARY['api']+'/policy.key'),
                       lambda a,w,s: a['encryption'].update(keyFile=p.PRIMARY['api']+'/../elsewhere'),
                       lambda a,w,s: s['files'][0].update(mode='0644'), lambda a,w,s: s['files'][0].update(uid=0),
                       lambda a,w,s: s['files'].append(dict(s['files'][0])),
                       lambda a,w,s: a['logMappings'][0].update(brokerId='absent'),
                       lambda a,w,s: w['logBrokers'][0].update(namespaceIds=[])]:
            a,w,s=fixture();change(a,w,s)
            with self.subTest(change=change), self.assertRaises(ValueError):
                p.make_plan(META,'d'*64,inputs(a,w,s))

    def test_config_cas_and_untouched_complete_material_inventory(self):
        a,w,s=fixture();raw=inputs(a,w,s)
        changed=p.decode(raw['api']);changed['configurationRevision']=8
        with self.assertRaisesRegex(ValueError,'CAS'):
            p.make_plan(META,'d'*64,dict(raw,api=p.encoded(changed)))
        s['files'].append(dict(s['files'][0],path=p.PRIMARY['api']+'/unused.key'))
        with self.assertRaisesRegex(ValueError,'Extra'):
            p.make_plan(META,'d'*64,inputs(a,w,s))
        with self.assertRaises(ValueError):
            p.decode(b'{"a":1,"a":2}')

    def test_resource_capacity_and_strict_positive_counter_bounds(self):
        self.assertTrue(p.capacity(100<<20,1<<20,1024,3<<30,3<<30))
        for args in [(0,0,0,3<<30,3<<30),(2<<30,0,0,4<<30,4<<30),(100,0,0,0,3<<30),(100,0,0,3<<30,0)]:
            with self.assertRaises(ValueError):p.capacity(*args)
        for invalid in ('0','01','-1','1.0','9223372036854775808',1):self.assertFalse(p.decimal(invalid))
        self.assertTrue(p.decimal('9223372036854775807'))

    def test_private_creation_resists_umask_and_rejects_links_overwrite(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();old=os.umask(0o777)
            try:
                p.directory(root/'private');p.write_new(root/'private/input',b'{}')
            finally:os.umask(old)
            self.assertEqual(stat.S_IMODE((root/'private').stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((root/'private/input').stat().st_mode),0o600)
            self.assertEqual(p.private_read(root/'private/input'),b'{}')
            with self.assertRaises(FileExistsError):p.write_new(root/'private/input',b'changed')
            (root/'link').symlink_to(root/'private/input')
            with self.assertRaises(ValueError):p.private_read(root/'link')
            os.link(root/'private/input',root/'hardlink')
            with self.assertRaises(ValueError):p.private_read(root/'private/input')

    def test_preparation_success_is_private_and_keeps_provider_absent(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();root.chmod(0o700)
            a,w,s=fixture(True);data=inputs(a,w,s)
            for key,raw in data.items():p.write_new(root/(key+'.json'),raw)
            files={k:b'{}' for k in ('build.json','SHA256SUMS','deploy/postgres/grants.py','deploy/postgres/grants.json')}
            output=root/'prepared'
            from types import SimpleNamespace
            with patch.object(prepare.plan.shared,'candidate_files',return_value=(META,files)),patch.object(prepare.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'-- synthetic grant renderer output\n')) as render:
                result=prepare.prepare(root/'archive','d'*64,root/'api.json',root/'worker.json',root/'snapshot.json',output)
            self.assertFalse(result['applySupported'])
            self.assertEqual(render.call_count,3)
            worker_call=render.call_args_list[1].args[0]
            self.assertNotIn('delivery',worker_call)
            self.assertNotIn('retention',worker_call)
            self.assertIn('jobman_dashboard_restore_worker',worker_call)
            for path in output.rglob('*'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700 if path.is_dir() else 0o600)
            receipt=p.decode(p.private_read(output/'plan.json',1<<20))
            self.assertEqual(receipt['inputSHA256'],{k:p.sha(v) for k,v in data.items()})
            self.assertTrue(all(p.sha(p.private_read(output/name,1<<20))==digest for name,digest in receipt['preparedFiles'].items()))

    def test_preparation_failure_never_completes_or_overwrites_partial(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();root.chmod(0o700)
            a,w,s=fixture();data=inputs(a,w,s)
            for key,raw in data.items():p.write_new(root/(key+'.json'),raw)
            files={k:b'{}' for k in ('build.json','SHA256SUMS','deploy/postgres/grants.py','deploy/postgres/grants.json')}
            output=root/'prepared'
            with patch.object(prepare.plan.shared,'candidate_files',return_value=(META,files)),patch.object(prepare.subprocess,'run',side_effect=RuntimeError('render fails')):
                with self.assertRaises(RuntimeError):prepare.prepare(root/'archive','d'*64,root/'api.json',root/'worker.json',root/'snapshot.json',output)
            self.assertFalse((output/'plan.json').exists())
            self.assertTrue((output/'configs/api.json').exists())
            with self.assertRaisesRegex(ValueError,'New staging'):
                prepare.prepare(root/'archive','d'*64,root/'api.json',root/'worker.json',root/'snapshot.json',output)


if __name__ == '__main__':
    unittest.main()
