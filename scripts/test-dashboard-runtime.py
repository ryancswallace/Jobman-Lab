#!/usr/bin/env python3
"""Offline runtime renderer tests; all identities/credentials are synthetic."""
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime', Path(__file__).with_name('render-dashboard-runtime.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimeTests(unittest.TestCase):
    def test_reporting_is_explicit_private_and_preserves_other_services(self):
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
            (state / 'fixture-info.json').write_text(json.dumps({'synthetic': True, 'endpoint': 'https://10.77.0.21:18443',
                'instanceId': 'synthetic-instance', 'delegationAudience': 'synthetic-audience',
                'namespaces': [{'id': 'research', 'targetGenerationId': 'host-one'}, {'id': 'operations', 'targetGenerationId': 'host-two'}]}))
            (state / 'oidc-public.json').write_text(json.dumps({'issuer': 'https://oidc.lab.test:8443/realms/jobman-lab',
                'audience': 'jobman-dashboard-api', 'webClientId': 'jobman-dashboard-web', 'nativeClientId': 'jobman-dashboard-native',
                'directoryGuidClaim': 'directory_guid', 'clientIdentityClaim': 'azp'}))
            with patch.object(module, 'ROOT', root), patch.object(module, 'STATE', state), patch.object(module, 'RUNTIME', runtime):
                module.main([])
                before = json.loads((runtime / 'dashboard.json').read_text())
                broker = (runtime / 'broker.json').read_bytes()
                self.assertNotIn('reports', before)
                self.assertFalse((runtime / 'redaction.json').exists())
                module.main(['--reports'])
                after = json.loads((runtime / 'dashboard.json').read_text())
                reports = after.pop('reports')
                self.assertEqual(after, before)
                self.assertEqual((runtime / 'broker.json').read_bytes(), broker)
                self.assertEqual(reports, {'objectRoot': '/var/lib/jobman-dashboard-app-lab/reports',
                                          'redactionFile': '/etc/jobman-dashboard-app-lab/redaction.json'})
                policy = runtime / 'redaction.json'
                self.assertEqual(stat.S_IMODE(policy.stat().st_mode), 0o600)
                self.assertLess(policy.stat().st_size, 4096)
                contents = policy.read_bytes()
                values = json.loads(contents)
                self.assertEqual(set(values), {'values', 'patterns'})
                self.assertEqual(len(values['values']), 1)
                self.assertIn(values['values'][0], 'SYNTHETIC Dashboard Lab log: metadata and byte delivery acceptance only.\n')
                self.assertEqual(values['patterns'], [])
                module.main(['--reports'])
                self.assertEqual(policy.read_bytes(), contents)
                module.main([])
                self.assertEqual(policy.read_bytes(), contents)  # Never remove retained private state.


if __name__ == '__main__':
    unittest.main()
