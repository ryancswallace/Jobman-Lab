#!/usr/bin/env python3
"""Offline receipt/publication tests: no Lab data, credentials, guests or network."""
from argparse import Namespace
import copy
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


h = load('dashboard-scale-fixture'); a = h.a; c = h.c
factory = load('test-dashboard-scale-activation')


def save(path, value):
    if not path.parent.exists(): path.parent.mkdir(parents=True, mode=0o700)
    raw = value if isinstance(value, bytes) else c.encoded(value)
    path.write_bytes(raw); path.chmod(0o600); return c.sha(raw)


def fixture(root):
    snapshot, handoffs = factory.fixture()
    identity = root / 'identity'; handoff = root / 'identity-handoff'; activation = root / 'activation'
    users = [{'username': spec['login'], 'keycloakUsername': spec['username'], 'directoryId': spec['directoryId'],
              'subject': '79000000-0000-4000-8000-%012d' % (4000+index), 'name': spec['name']} for index, spec in enumerate(h.i.accounts())]
    preserved = {'originalAccountSentinel': 'unchanged'}
    identity_result = {'version': 1, 'synthetic': True, 'issuer': c.ISSUER, 'preservedSHA256': c.sha(c.encoded(preserved)), 'users': users}
    pre = {'implementationSHA256': 'd'*64, 'baseline': {'preserved': preserved}}
    pre_sha = save(identity / 'preflight.json', pre)
    stage = {'version': 1, 'issuer': c.ISSUER, 'accounts': h.i.accounts(), 'implementationSHA256': 'd'*64, 'preflightSHA256': pre_sha,
             'passwordsSHA256': 'f'*64, 'beforeSHA256': 'b'*64, 'afterSHA256': 'c'*64}
    stage_sha = save(identity / 'stage.json', stage); identity_sha = save(identity / 'identities.json', identity_result)
    save(handoff / 'identities.json', identity_result)
    identity_proof = {'stageSHA256': stage_sha, 'identitiesSHA256': identity_sha}
    save(identity / 'apply.complete.json', identity_proof); save(identity / 'verify.complete.json', identity_proof)
    source_inputs, hashes = {}, {}
    for profile, spec in c.PROFILES.items():
        value = {'instanceId': spec['instance'], 'issuer': c.ISSUER, 'historyAt': '2026-01-01T00:00:00Z',
                 'users': [{key: u[key] for key in ('directoryId', 'subject', 'name')} for u in users]}
        source_inputs[profile] = value; name = profile + '-scale-input.json'; hashes[name] = save(handoff / name, value)
    manifest = {'stageSHA256': stage_sha, 'historyAt': '2026-01-01T00:00:00Z', 'files': hashes}
    identity_handoff_sha = save(handoff / 'handoff.json', manifest)
    verification = {}
    for profile, spec in c.PROFILES.items():
        source = root / profile
        baseline = {'database': spec['database'], 'instance': spec['instance'], 'epoch': '1', 'migrations': 21, 'ledgerSHA256': 'a'*64,
                    'namespaceIds': ['79000000-0000-4000-8000-000000000099'], 'namespaceSHA256': 'b'*64, 'jobs': {'count': 5, 'sha256': 'c'*64}, 'namespaceTotal': 2}
        pre = {'implementationSHA256': a.SOURCE_IMPLEMENTATION_SHA, 'profile': profile, 'input': source_inputs[profile],
               'identityHandoffSHA256': identity_handoff_sha, 'database': baseline}
        execution = save(source / 'preflight.json', pre)
        seed = a.document(handoffs[profile]['seed.json']); seed.update(preparedAt='2026-01-01T01:00:00Z', historyAt='2026-01-01T00:00:00Z')
        factory.mutate_file(handoffs[profile], 'seed.json', lambda v: v.update(seed))
        factory.mutate_file(handoffs[profile], 'receipt.json', lambda v: v.update(inputSHA256=c.sha(c.encoded(source_inputs[profile])), output=str(c.RECEIPTS/execution/'output')))
        driver = a.document(handoffs[profile]['driver-receipt.json']); driver['executionId'] = execution
        handoffs[profile]['driver-receipt.json'] = a.encoded_file(c.encoded(driver))
        for name, encoded in handoffs[profile].items(): save(source / 'handoff' / name, a.raw(encoded))
        save(source / 'seed.complete.json', driver)
        database = dict(baseline, scaleNamespaces=spec['count'], scalePrincipals=25, namespaceTotal=spec['count']+2,
                        scaleCounts=[{'name': name, 'total': 10050, 'active': 50, 'imported': 10000, 'runs': 0, 'executions': 0, 'agents': 0, 'events': 0} for name in c.names(profile)])
        verification[profile] = save(source / 'verify.complete.json', {'receipt': driver, 'database': database})
    materials = {'api': {}, 'worker': {}}
    for role in ('api', 'worker'):
        value = a.document(snapshot['runtime'][role])
        for profile, control in zip(c.PROFILES, value['controls']):
            control['trustRootsFile'] = '/private-path-only/' + profile + '-ca.crt'
            materials[role][control['trustRootsFile']] = {'sha256': c.sha(CERTIFICATES[profile]), 'uid': 21904 if role == 'api' else 21905, 'mode': 0o600}
        snapshot['runtime'][role] = a.encoded_file(c.encoded(value))
    snapshot['runtime']['recovery'] = a.encoded_file(c.encoded(a.recovery(a.document(snapshot['runtime']['api']), a.document(snapshot['runtime']['worker']))))
    snapshot['hosts'] = {'storage01': {'materials': materials}}
    snapshot['seedVerificationSHA256'] = verification
    snapshot['database'] = {'database': 'jobman_dashboard', 'migrations': 18, 'bindingCount': 0, 'bindingSHA256': 'e'*64,
                            'hold': {'held': False, 'generation': 3}, 'identities': [], 'feeds': []}
    for spec, control in zip(c.PROFILES.values(), a.document(snapshot['runtime']['api'])['controls']):
        snapshot['database']['identities'].append({'deploymentId': spec['deployment'], 'instanceId': spec['instance'], 'epoch': '1', 'revision': 7})
        snapshot['database']['feeds'].append({'deploymentId': spec['deployment'], 'instanceId': spec['instance'], 'epoch': '1', 'namespaces': control['namespaceIds'], 'generation': 5, 'lastPosition': 20})
    plan = a.draft(snapshot, handoffs); impl = 'a'*64; execution = a.binding(snapshot, handoffs, plan, impl)
    for name, value in [('snapshot', snapshot), ('handoffs', handoffs), ('plan', plan), ('binding', {'implementationSHA256': impl, 'executionId': execution}),
                        ('hold', {'held': True, 'generation': '4'}), ('resume', {'held': False, 'generation': '5'}),
                        ('verify', {host: {'host': host, 'revision': 8, 'verified': True} for host in ('control01', 'storage01')})]: save(activation/(name+'.json'), value)
    for role in ('api', 'worker', 'broker'): save(activation/('restart-'+role+'.json'), {'role': role, 'ready': True, 'revision': 8})
    for index, (profile, spec) in enumerate(c.PROFILES.items()):
        scope = next(s for s in plan['feedRecoveryRequired'] if s['deploymentId'] == spec['deployment'])
        recovery = {'id': factory.factory.uid(91000+index), 'gapId': factory.factory.uid(92000+index), 'digest': str(index+1)*64,
                    'deploymentId': spec['deployment'], 'configurationRevision': '8', 'mode': 'retained', 'reason': 'event_cursor_scope_changed',
                    'effectiveReason': 'event_cursor_scope_changed', 'removedNamespaceIds': [], 'addedNamespaceIds': sorted(set(scope['newNamespaceIds'])-set(scope['oldNamespaceIds'])),
                    'namespaceIds': scope['newNamespaceIds'], 'revision': '1', 'feedGeneration': '6', 'pages': '0', 'scanned': '0', 'added': '0',
                    'uncertainty': {'dashboardRestored': False, 'suppressAllRecovered': False}, 'status': 'replaying'}
        save(activation/('recovery-plan-'+profile+'.json'), recovery)
        save(activation/('recovery-apply-'+profile+'.json'), dict(recovery, revision='3', status='applied'))
    for profile, cert in CERTIFICATES.items(): save(root/(profile+'.crt'), cert)
    lab = root/'lab'; dashboard = lab/'.lab/dashboard'; dashboard.mkdir(parents=True, mode=0o700)
    return Namespace(phase='prepare', lab_root=lab, staging=root/'fixture-stage', identity_staging=identity, identity_handoff=handoff,
                     primary_handoff=root/'primary/handoff', secondary_handoff=root/'secondary/handoff', activation_staging=activation,
                     activation_plan_sha256=c.sha(c.encoded(plan)), activation_implementation_sha256=impl,
                     primary_ca=root/'primary.crt', secondary_ca=root/'secondary.crt', stage_sha256=None, apply=False)


class ScaleFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.args = fixture(self.root)

    def mutate(self, relative, function):
        path = self.root/relative; value = c.decode(c.read(path)); function(value); save(path, value)

    def test_exact_public_projection_and_historical_receipts(self):
        value = h.assemble(self.args); output = a.document(value['outputs']['scale-fixture.json']['bytesBase64'])
        self.assertEqual(set(output), {'version', 'synthetic', 'mode', 'preparedAt', 'historyAt', 'users', 'sources'})
        self.assertEqual(len(output['users']), 25); self.assertEqual(output['users'][0]['username'], 'scale01')
        self.assertEqual([len(s['namespaces']) for s in output['sources']], [10, 5])
        self.assertEqual(output['historyAt'], '2026-01-01T00:00:00Z')
        self.assertNotIn(b'principalId', c.encoded(output)); self.assertNotIn(b'private-path-only', c.encoded(output))
        # No live authority/process/zero-event query exists; later legitimate
        # directory activation does not invalidate captured seed evidence.
        with patch.object(c, 'run', side_effect=AssertionError('network/command forbidden')): h.assemble(self.args)

    def test_identity_verification_and_subject_drift(self):
        self.mutate('identity/verify.complete.json', lambda v: v.update(stageSHA256='f'*64))
        with self.assertRaisesRegex(ValueError, 'identity_verification_incomplete'): h.assemble(self.args)

    def test_no_unknown_namespace_data_is_projected(self):
        actual = a.validate_handoff
        def extra(*args):
            seed = actual(*args); seed['namespaces'][0]['privateMetadata'] = 'must-not-publish'; return seed
        with patch.object(a, 'validate_handoff', side_effect=extra), self.assertRaisesRegex(ValueError, 'public_namespace_fields'):
            h.assemble(self.args)

    def test_seed_input_and_actual_source_profile_are_bound(self):
        self.mutate('primary/preflight.json', lambda v: v['input']['users'][0].update(subject=factory.factory.uid(99999)))
        with self.assertRaisesRegex(ValueError, 'source_verified_input_binding'): h.assemble(self.args)

    def test_incomplete_or_execution_claiming_seed_is_rejected(self):
        self.mutate('secondary/verify.complete.json', lambda v: v['database']['scaleCounts'][0].update(events=1))
        with self.assertRaisesRegex(ValueError, 'captured_seed_execution_counts'): h.assemble(self.args)

    def test_missing_activation_verification_is_rejected(self):
        (self.args.activation_staging/'verify.json').unlink()
        with self.assertRaises(OSError): h.assemble(self.args)

    def test_resume_and_recovery_completion_are_required(self):
        self.mutate('activation/resume.json', lambda v: v.update(held=True))
        with self.assertRaisesRegex(ValueError, 'activation_resume_incomplete'): h.assemble(self.args)
        self.mutate('activation/resume.json', lambda v: v.update(held=False))
        self.mutate('activation/recovery-apply-primary.json', lambda v: v.update(status='ready'))
        with self.assertRaisesRegex(ValueError, 'activation_recovery_incomplete'): h.assemble(self.args)

    def test_ca_must_match_both_configured_roles_and_contain_only_certificate(self):
        save(self.args.primary_ca, CERTIFICATES['secondary'])
        with self.assertRaisesRegex(ValueError, 'configured_public_ca_drift'): h.assemble(self.args)
        save(self.args.primary_ca, CERTIFICATES['primary']+b'PRIVATE DATA')
        with self.assertRaisesRegex(ValueError, 'single_public_ca_required'): h.assemble(self.args)

    def test_prepare_requires_review_before_publish_and_exact_retry(self):
        proof = h.execute(self.args); self.assertFalse(proof['published'])
        self.args.phase='publish'; self.args.stage_sha256=proof['stageSHA256']
        with self.assertRaisesRegex(ValueError, 'explicit_local_publish_required'): h.execute(self.args)
        self.args.apply=True; result=h.execute(self.args); self.assertTrue(result['published'])
        self.assertEqual(h.execute(self.args), result)
        dashboard=self.args.lab_root/'.lab/dashboard'
        self.assertEqual(stat.S_IMODE((dashboard/'scale-fixture.json').stat().st_mode),0o644)
        self.assertTrue((dashboard/'scale-fixture.complete.json').exists())

    def test_existing_fixture_cannot_be_adopted_or_overwritten(self):
        proof=h.execute(self.args); self.args.phase='publish'; self.args.stage_sha256=proof['stageSHA256']; self.args.apply=True
        existing=self.args.lab_root/'.lab/dashboard/scale-fixture.json'; save(existing,b'preexisting unrelated evidence')
        with self.assertRaisesRegex(ValueError,'existing_fixture_not_adopted'):h.execute(self.args)
        self.assertEqual(existing.read_bytes(),b'preexisting unrelated evidence')

    def test_source_receipt_changed_after_review_stops_before_publish(self):
        proof=h.execute(self.args);self.args.phase='publish';self.args.stage_sha256=proof['stageSHA256'];self.args.apply=True
        self.mutate('secondary/verify.complete.json', lambda v:v['database'].update(epoch='2'))
        with self.assertRaisesRegex(ValueError,'fixture_input_drift'):h.execute(self.args)
        self.assertFalse((self.args.lab_root/'.lab/dashboard/scale-fixture.pending.json').exists())

    def test_stage_digest_and_exclusive_lock_are_required(self):
        proof=h.execute(self.args);self.args.phase='publish';self.args.stage_sha256='f'*64;self.args.apply=True
        with self.assertRaisesRegex(ValueError,'fixture_stage_digest'):h.execute(self.args)
        self.args.stage_sha256=proof['stageSHA256']
        with h.locked(self.args.staging),self.assertRaises(BlockingIOError):h.execute(self.args)
        dashboard=self.args.lab_root/'.lab/dashboard'
        save(dashboard/'scale-fixture.pending.json',{'stageSHA256':'another-operation'})
        with self.assertRaisesRegex(ValueError,'different_fixture_publication_pending'):h.execute(self.args)

    def test_completed_first_ca_retry_and_partial_bytes_fail_closed(self):
        proof=h.execute(self.args);self.args.phase='publish';self.args.stage_sha256=proof['stageSHA256'];self.args.apply=True
        actual=c.put
        def fail(path,raw,mode=0o600):
            if path.name=='control-secondary-ca.crt':raise OSError('injected interruption')
            return actual(path,raw,mode)
        with patch.object(c,'put',side_effect=fail),self.assertRaises(OSError):h.execute(self.args)
        dashboard=self.args.lab_root/'.lab/dashboard'
        self.assertTrue((dashboard/'scale-fixture.pending.json').exists());self.assertFalse((dashboard/'scale-fixture.complete.json').exists())
        self.assertTrue(h.execute(self.args)['published'])
        broken=dashboard/'scale/control-primary-ca.crt';broken.write_bytes(b'partial');broken.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'existing_fixture_bytes_changed'):h.execute(self.args)
        self.assertEqual(broken.read_bytes(),b'partial')

    def test_private_input_bounds_links_and_duplicate_json(self):
        path=self.args.identity_staging/'verify.complete.json';path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'file_identity'):h.assemble(self.args)
        path.chmod(0o600);link=self.root/'alias';link.symlink_to(self.args.identity_staging)
        self.args.identity_staging=link
        with self.assertRaisesRegex(ValueError,'directory_identity'):h.assemble(self.args)
        with self.assertRaises(ValueError):c.decode(b'{"x":1,"x":2}')

    def test_publication_modes_survive_restrictive_umask(self):
        previous=os.umask(0o777)
        try:
            proof=h.execute(self.args);self.args.phase='publish';self.args.stage_sha256=proof['stageSHA256'];self.args.apply=True
            self.assertTrue(h.execute(self.args)['published'])
        finally:os.umask(previous)


# Only generated synthetic PUBLIC certificates; no private keys in this file.
CERTIFICATES = {'primary': b'-----BEGIN CERTIFICATE-----\nMIIDKTCCAhGgAwIBAgIUU39X/7tM/Kn38rb/sWBqhCu9sPYwDQYJKoZIhvcNAQEL\nBQAwJDEiMCAGA1UEAwwZc3ludGhldGljLW9mZmxpbmUtcHJpbWFyeTAeFw0yNjEw\nMDQxMDU1MjJaFw0zNjEwMDExMDU1MjJaMCQxIjAgBgNVBAMMGXN5bnRoZXRpYy1v\nZmZsaW5lLXByaW1hcnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC\naxhI0cBrHKyISY/dLQd1yH+6zWmXKzQCPDnJDDJm/uSYqoh3PdwFgHBvClchlAGd\nOWLuP2xz9PQ9P72gLpPWtVicIKh0Uy/QTmd9GjiDVQlHMg2ACnErgbr5eMkm8I6v\n8pCIaXlBxm9O3qlxJvwuDuvDRx84AFPYqyp2A3HksVYwIOSot/Fzmlp72JqwTDbN\nBqt7AUMEB7nH8I51f6QG/V6iq+5vF3DRQ/8mIVsbMekeptKd/2gjJwVK4YNQbJFq\nC+9XvfFT0yEGWxXQyElnBJ2teUowAJI0RlmIOJ7MbJ7JhUEmZhMYYEE/ySuG8Mg7\n4HP4RH1Di2xc3Us5nFCJAgMBAAGjUzBRMB0GA1UdDgQWBBT8KDTc1mB0AYb1xij0\nCbgYdV+XwzAfBgNVHSMEGDAWgBT8KDTc1mB0AYb1xij0CbgYdV+XwzAPBgNVHRMB\nAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC73tWVOrnKREqKWCVpwdBXQjk2\ncigid5HMwSZkq67zWWH6VYWZIJc2sVW+mZ4FOIFIbWYbawAFEpGA+FJQKN88Xmpp\n2aCVEaQsbF9YRbryAIrTFw/xgglnZzibPugprSI1ijBAFrIo/MaUGzAHuWxBY6mC\nFMt2PArvU2E3QiCYBrgL1JnhNsCVgYYh4TbnpnVEcQXR7/EmF556wV7RussTOkZS\nXl3kAatZsfBusXhPP2ENIYtMcvY50YHX2JVVz8eFLbOhOt8sQaVvG9Y3pYX21VsY\nflJnIthJ0EKaziMKkcB7CSp0TRvM3CRQEwqrdIUpgxjwInRjBJFsa0hkoDPg\n-----END CERTIFICATE-----\n', 'secondary': b'-----BEGIN CERTIFICATE-----\nMIIDLTCCAhWgAwIBAgIUNUJk7rNJl17ZiNd8QcXGE9zURIgwDQYJKoZIhvcNAQEL\nBQAwJjEkMCIGA1UEAwwbc3ludGhldGljLW9mZmxpbmUtc2Vjb25kYXJ5MB4XDTI2\nMTAwNDEwNTUyMloXDTM2MTAwMTEwNTUyMlowJjEkMCIGA1UEAwwbc3ludGhldGlj\nLW9mZmxpbmUtc2Vjb25kYXJ5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAw01d61t6GCNvL2zGXTNHlPnMnzlFgW8B3Sdws2Y9IqrmKyqHCFK5Cl87W58q\na7LweXwYYX/nqWm/RwsgPGJK8uPry2AdMLS2gB2Znh/oWfIhPMfmMuK6pgzJkmRp\nFW0p9QkLiY96Ja6HmXkGckJHB59zTrcZNrHz2WNXqkNDCBiNVgqPeYVlrTzVQN5n\ntLmr0osbvzjuWpc1cqx3K+Wcq2nsL7GbN16RodRzeVn/8Y1OBXDnQRSMALJUKFqa\nVe5bFp5m5eVzB5lNGeaAxXB/q93gtb8yk8rsCirwHn7Um6+S0rmoKTgaantS+iZW\nRnCDVoN5kveo71093XTR73LSEQIDAQABo1MwUTAdBgNVHQ4EFgQU0oPbmAA3uRw+\np7XhXIb0e0+WZBcwHwYDVR0jBBgwFoAU0oPbmAA3uRw+p7XhXIb0e0+WZBcwDwYD\nVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAiml4tfEwid7fznIfp4Kt\nzVBJLpbYdOwhunOelmEDz4ebgsXxdGqQtCcTNMMzIp/yqojzgksfZ4wGc3TkEguy\nrh8FScp4cxvGymbMQJt6Juso1elInltFoXmbGgx7vDQbAIPgoodBM92dDuQ+aj2E\n4Rc+vrhTXewQJA3jQkpBCNEY2JmerrJfGfWlPgiBTIg0n4YHhuhNIoKR1y9o5n+P\na+KGTrKJPZN7HAIrpd+GNRns4RGv5jsaCBRRVtmqGkacV7mCcVDr/Hg6m0kxmVu/\ntapxinWi/KJrixI+nu/OJOU/M9HFkWoRTWnYPx0BeIApW3KFKKZG4WXF2ILUZ17c\nqA==\n-----END CERTIFICATE-----\n'}

if __name__ == '__main__': unittest.main()
