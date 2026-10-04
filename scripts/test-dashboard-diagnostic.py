#!/usr/bin/env python3
"""Offline supplemental fixture validation and mapping isolation regressions."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load('diagnostic_fixture', 'prepare-dashboard-diagnostic.py')
renderer = load('diagnostic_renderer', 'render-dashboard-runtime.py')


def fixtures():
    def identifier(number):
        return '79000000-0000-4000-8000-' + f'{number:012d}'
    original = {'synthetic': True, 'endpoint': 'https://10.77.0.21:18443', 'instanceId': identifier(1),
                'delegationAudience': 'synthetic-audience', 'namespaces': [
                    {'id': identifier(2), 'name': 'dashboard-research', 'targetGenerationId': identifier(3)},
                    {'id': identifier(4), 'name': 'dashboard-operations', 'targetGenerationId': identifier(5)}]}
    supplement = {'synthetic': True, 'fixtureVersion': 1, 'observationMode': 'synthetic-store-observations-no-execution',
                  'helperCommit': 'a' * 40, 'deploymentId': helper.DEPLOYMENT, 'controlInstanceId': identifier(1),
                  'recoveryEpoch': '1', 'namespaceId': identifier(4), 'namespace': 'dashboard-operations',
                  'targetId': identifier(6), 'targetName': 'synthetic-diagnostics', 'targetGenerationId': identifier(7),
                  'jobId': identifier(8), 'jobRevision': '5', 'runId': identifier(9), 'executionId': identifier(10), 'streams': []}
    for stream, data in [('stdout', b''), ('stderr', b'SYNTHETIC OBSERVATION ONLY: open synthetic-output.txt: permission denied; metadata and byte delivery\n')]:
        key = 'namespaces/dashboard-operations/jobs/' + identifier(8) + '/executions/' + identifier(10) + '/logs/' + stream + '/00000001.chunk'
        supplement['streams'].append({'stream': stream, 'state': 'complete', 'runId': identifier(9),
            'executionId': identifier(10), 'targetGenerationId': identifier(7), 'namespaceId': identifier(4),
            'byteLength': str(len(data)), 'chunks': [{'objectKey': key, 'sequence': '1', 'byteOffset': '0',
                'byteLength': str(len(data)), 'checksum': 'sha256:' + hashlib.sha256(data).hexdigest(),
                'storeName': 'lab-nfs', 'storeVersion': '1', 'complete': True, 'truncated': False}]})
    return original, supplement


class DiagnosticTests(unittest.TestCase):
    def test_only_exact_synthetic_scope_and_two_immutable_objects_are_accepted(self):
        original, supplement = fixtures()
        objects = helper.validate_fixture(supplement, original, 'a' * 40)
        self.assertEqual(len(objects), 2)
        self.assertEqual(objects[0]['length'], 0)
        self.assertGreater(objects[1]['length'], 0)
        for mutate in [lambda s: s.update(controlInstanceId='other'), lambda s: s.update(namespaceId=original['namespaces'][0]['id']),
                       lambda s: s.update(helperCommit='b' * 40), lambda s: s.update(observationMode='actual-execution'),
                       lambda s: s['streams'].reverse(), lambda s: s['streams'][1]['chunks'][0].update(objectKey='../private/key'),
                       lambda s: s['streams'][1]['chunks'][0].update(storeName='other-store'),
                       lambda s: s['streams'][1]['chunks'][0].update(checksum='sha256:' + 'a' * 64),
                       lambda s: s['streams'][1].update(byteLength='9007199254740993'),
                       lambda s: s['streams'][1]['chunks'][0].update(complete=False)]:
            changed = copy.deepcopy(supplement)
            mutate(changed)
            with self.assertRaises(ValueError):
                helper.validate_fixture(changed, original, 'a' * 40)

    def test_renderer_adds_one_exact_mapping_and_refuses_manifest_removal(self):
        original, supplement = fixtures()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / '.lab/dashboard'
            runtime = state / 'runtime'
            runtime.mkdir(parents=True)
            credentials = root / '.lab/credentials'
            credentials.mkdir()
            (credentials / 'dashboard.env').write_text(''.join(name + '=' + 'a' * 64 + '\n' for name in [
                'JOBMAN_LAB_DASHBOARD_PASSWORD', 'JOBMAN_LAB_DASHBOARD_DDL_PASSWORD', 'JOBMAN_LAB_DASHBOARD_WEB_SECRET']))
            (runtime / 'encryption-key').write_bytes(b'k' * 32)
            (state / 'fixture-info.json').write_text(json.dumps(original))
            (state / 'oidc-public.json').write_text(json.dumps({'issuer': 'https://oidc.lab.test:8443/realms/jobman-lab',
                'audience': 'jobman-dashboard-api', 'webClientId': 'jobman-dashboard-web', 'nativeClientId': 'jobman-dashboard-native',
                'directoryGuidClaim': 'directory_guid', 'clientIdentityClaim': 'azp'}))
            with patch.object(renderer, 'ROOT', root), patch.object(renderer, 'STATE', state), patch.object(renderer, 'RUNTIME', runtime):
                renderer.main(['--reports'])
                before = json.loads((runtime / 'dashboard.json').read_text())
                prior_broker = json.loads((runtime / 'broker.json').read_text())
                (state / 'diagnostic-fixture.json').write_text(json.dumps(supplement))
                renderer.main(['--reports'])
                after = json.loads((runtime / 'dashboard.json').read_text())
                broker = json.loads((runtime / 'broker.json').read_text())
                self.assertEqual(after['configurationRevision'], 2)
                self.assertEqual(broker['configurationRevision'], 2)
                self.assertEqual(after['logMappings'][:2], before['logMappings'])
                self.assertEqual(broker['logRoots'][:2], prior_broker['logRoots'])
                self.assertEqual(len(after['logMappings']), 3)
                self.assertEqual(len(broker['logRoots']), 3)
                self.assertEqual(after['logMappings'][2]['targetGenerationId'], supplement['targetGenerationId'])
                self.assertEqual(broker['logRoots'][2]['root'], '/data/jobman/alice')
                for key in before:
                    if key not in ['configurationRevision', 'logMappings']:
                        self.assertEqual(before[key], after[key])
                renderer.main(['--reports'])
                exact = (runtime / 'dashboard.json').read_bytes()
                (state / 'diagnostic-fixture.json').unlink()
                with self.assertRaises(RuntimeError):
                    renderer.main(['--reports'])
                self.assertEqual(exact, (runtime / 'dashboard.json').read_bytes())


if __name__ == '__main__':
    unittest.main()
