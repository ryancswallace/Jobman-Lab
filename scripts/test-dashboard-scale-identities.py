#!/usr/bin/env python3
"""Entirely offline regression tests: never load Lab credentials or contact guests."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

host = load('dashboard-scale-identities'); guest = load('dashboard-scale-identities-guest'); c = host.c

class FakeModule:
    @staticmethod
    def client_specs(_): return [{'clientId': 'jobman-dashboard-' + value, 'enabled': True} for value in ('api', 'web', 'native')]
    @staticmethod
    def verify_client(actual, spec): c.need(all(actual.get(k) == v for k, v in spec.items()), 'test_client_changed')

class FakeAdmin:
    def __init__(self):
        self.users = [{'id': '71000000-0000-4000-8000-000000000099', 'username': 'existing-alice', 'attributes': {c.ATTRIBUTE: ['71000000-0000-4000-8000-000000000001']}}]
        self.clients = [dict(value, id='client-' + str(i)) for i, value in enumerate(FakeModule.client_specs(''))]
        self.profile = {'attributes': [{'name': c.ATTRIBUTE, 'displayName': 'Dashboard synthetic directory identity', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin']}, 'multivalued': False}]}
        self.realm = {'realm': 'jobman-lab', 'enabled': True}; self.posts = []; self.failure = None
    def get(self, path):
        if path.startswith('users?'): return copy.deepcopy(self.users)
        if path == 'users/profile': return copy.deepcopy(self.profile)
        if path.startswith('clients?'): return copy.deepcopy(self.clients)
        if path.startswith('users/'):
            return copy.deepcopy(next(v for v in self.users if v['id'] == path[6:]))
        raise AssertionError('Unexpected GET')
    def request(self, method, path, body=None):
        if method == 'GET' and path == guest.REALM + '/': return copy.deepcopy(self.realm)
        raise AssertionError('Unexpected realm mutation')
    def create(self, value):
        self.posts.append(copy.deepcopy(value))
        if self.failure == 'before': raise c.Failure('test_post_failed')
        subject = '75000000-0000-4000-8000-' + str(len(self.posts)).zfill(12)
        self.users.append(dict({k: copy.deepcopy(v) for k, v in value.items() if k != 'credentials'}, id=subject))
        if self.failure == 'after': raise c.Failure('test_post_uncertain')
        return subject

class Identities(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.api = FakeAdmin(); self.passwords = {a['passwordKey']: format(i, '064x') for i, a in enumerate(c.accounts(), 1)}
        # Guest root ownership is separately validated in execute; run pure receipt
        # algorithms as the current unprivileged offline test user.
        original = guest.c.read
        self.read_patch = patch.object(guest.c, 'read', side_effect=lambda path, **kw: original(path, **dict(kw, uid=os.getuid())))
        self.read_patch.start(); self.addCleanup(self.read_patch.stop); self.addCleanup(self.temp.cleanup)
        self.baseline = guest.preserved_snapshot(self.api, FakeModule)
    def apply(self): return guest.apply_users(self.api, FakeModule, self.root, self.passwords, self.baseline)
    def test_exact_accounts_and_preserving_append(self):
        self.assertEqual(len(c.accounts()), 25)
        self.assertEqual(c.accounts()[0]['name'], 'Synthetic scale 01')
        self.assertEqual(c.accounts()[-1]['directoryId'], '74000000-0000-4000-8000-000000000025')
        before = b'# original\nORIGINAL_PASSWORD=unaltered'
        after = c.append_credentials(before, self.passwords)
        self.assertTrue(after.startswith(before + b'\n')); self.assertEqual(len(c.credential_map(after)), 26)
        with self.assertRaises(c.Failure): c.append_credentials(after, self.passwords)
        with self.assertRaises(c.Failure): c.credential_map(b'ORIGINAL=x\nORIGINAL=y\n')
        invalid = dict(self.passwords); invalid[next(iter(invalid))] = 'not-a-password'
        with self.assertRaises(c.Failure): c.append_credentials(before, invalid)
    def test_exact_creates_then_safe_completed_resume(self):
        result = self.apply(); self.assertEqual(len(result), 25); self.assertEqual(len(self.api.posts), 25)
        self.assertEqual(self.apply(), result); self.assertEqual(len(self.api.posts), 25)
        self.assertEqual(guest.preserved_snapshot(self.api, FakeModule, {v['keycloakUsername']: v['subject'] for v in result}), self.baseline)
        for value, account in zip(self.api.posts, c.accounts()):
            self.assertEqual(value, guest.user_spec(account, self.passwords[account['passwordKey']]))
        self.assertEqual(len({row['subject'] for row in result}), 25)
    def test_conflicting_existing_username_and_guid_never_adopted(self):
        for conflict in ({'username': 'DASHBOARD-SCALE01', 'attributes': {}}, {'username': 'another', 'attributes': {c.ATTRIBUTE: [c.accounts()[0]['directoryId']]}}):
            with self.subTest(conflict=conflict['username']):
                api = FakeAdmin(); api.users.append(dict(conflict, id='79000000-0000-4000-8000-000000000001'))
                with self.assertRaises(guest.c.Failure): guest.apply_users(api, FakeModule, self.root, self.passwords, self.baseline)
                self.assertEqual(api.posts, [])
    def test_uncertain_post_stops_without_reset_or_adoption(self):
        self.api.failure = 'after'
        with self.assertRaises(c.Failure): self.apply()
        self.api.failure = None
        with self.assertRaises(guest.c.Failure): self.apply()
        self.assertEqual(len(self.api.posts), 1); self.assertTrue((self.root / 'scale01.pending.json').exists())
        self.assertFalse((self.root / 'scale01.complete.json').exists())
    def test_failed_post_before_creation_requires_review(self):
        self.api.failure = 'before'
        with self.assertRaises(c.Failure): self.apply()
        self.api.failure = None
        with self.assertRaises(guest.c.Failure): self.apply()
        self.assertEqual(len(self.api.posts), 1)
    def test_completed_partial_resume_only_creates_missing_accounts(self):
        first = c.accounts()[0]; value = guest.user_spec(first, self.passwords[first['passwordKey']]); subject = self.api.create(value)
        c.put(self.root / 'scale01.complete.json', c.encoded({'username': first['username'], 'subject': subject, 'requestSHA256': c.sha(c.encoded(value))}))
        self.assertEqual(len(self.apply()), 25); self.assertEqual(len(self.api.posts), 25)
    def test_changed_receipt_subject_and_preexisting_state_fail_closed(self):
        self.apply(); self.api.users[0]['username'] = 'changed'
        with self.assertRaises(guest.c.Failure): self.apply()
        self.assertEqual(len(self.api.posts), 25)
    def test_changed_created_account_fails_without_update(self):
        self.apply(); self.api.users[-1]['enabled'] = False
        with self.assertRaises(guest.c.Failure): self.apply()
        self.assertEqual(len(self.api.posts), 25)
    def test_inventory_bounds_and_immutable_claim_policy(self):
        self.api.users *= 101
        with self.assertRaises(guest.c.Failure): guest.preserved_snapshot(self.api, FakeModule)
        self.api = FakeAdmin(); self.api.profile['attributes'][0]['permissions']['edit'] = ['user']
        with self.assertRaises(guest.c.Failure): guest.preserved_snapshot(self.api, FakeModule)
    def test_write_allowlist_excludes_all_update_delete_and_password_endpoints(self):
        self.assertTrue(guest.request_allowed('POST', guest.REALM + '/users'))
        self.assertTrue(guest.request_allowed('POST', '/realms/master/protocol/openid-connect/token'))
        for method, path in [('PUT', guest.REALM + '/users/x'), ('DELETE', guest.REALM + '/users/x'), ('POST', guest.REALM + '/clients'), ('POST', guest.REALM + '/users/x/reset-password'), ('GET', '/admin/realms/other/users')]:
            self.assertFalse(guest.request_allowed(method, path))
    def test_credential_cas_retry_and_drift(self):
        creds = self.root / 'credentials'; c.mkdir(creds); stage = self.root / 'stage'; c.mkdir(stage)
        path = creds / 'dashboard.env'; before = b'EXISTING=preserved\n'; after = c.append_credentials(before, self.passwords); c.put(path, before)
        host.append_cas(path, before, after, stage); host.append_cas(path, before, after, stage)
        self.assertEqual(c.read(path), after); self.assertEqual(c.read(stage / 'credentials.backup.env'), before)
        path.write_bytes(after + b'UNRELATED=change\n')
        with self.assertRaises(c.Failure): host.append_cas(path, before, after, stage)
    def test_credentials_changed_without_receipt_not_adopted(self):
        creds = self.root / 'credentials'; c.mkdir(creds); stage = self.root / 'stage'; c.mkdir(stage)
        path = creds / 'dashboard.env'; before = b'EXISTING=preserved\n'; after = c.append_credentials(before, self.passwords); c.put(path, after)
        with self.assertRaises(FileNotFoundError): host.append_cas(path, before, after, stage)
    def test_modes_restrictive_umask_and_symlink_rejection(self):
        old = os.umask(0o777)
        try:
            child = self.root / 'child'; c.mkdir(child); c.put(child / 'secret', b'private')
        finally: os.umask(old)
        self.assertEqual((child.stat().st_mode & 0o777), 0o700); self.assertEqual(((child / 'secret').stat().st_mode & 0o777), 0o600)
        self.assertEqual(c.read(child / 'secret'), b'private')
        (child / 'alias').symlink_to(child / 'secret')
        with self.assertRaises(OSError): c.read(child / 'alias')
    def test_lock_excludes_concurrent_receipt_operations(self):
        with host.locked(self.root):
            with self.assertRaises(BlockingIOError):
                with host.locked(self.root): pass
    def test_public_handoff_contains_exact_source_inputs_no_secrets(self):
        result = {'version': 1, 'synthetic': True, 'issuer': c.ISSUER, 'users': self.apply(), 'preservedSHA256': c.sha(c.encoded(self.baseline))}
        host.validate_result(result, {'preserved': self.baseline}); now = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
        values = host.handoff(result, '2026-10-04T11:58:00Z', now)
        for source, item in values.items():
            self.assertEqual(set(item), {'instanceId', 'issuer', 'historyAt', 'users'}); self.assertEqual(item['instanceId'], c.INSTANCES[source])
            self.assertTrue(all(set(row) == {'directoryId', 'subject', 'name'} for row in item['users']))
            for password in self.passwords.values(): self.assertNotIn(password.encode(), c.encoded(item))
        for when in ('2026-10-04T12:00:00Z', '2026-09-20T12:00:00Z', '2026-10-04T11:58:00+00:00'):
            with self.assertRaises(c.Failure): host.handoff(result, when, now)
    def host_setup(self):
        lab = self.root / 'lab'; c.mkdir(lab); staging = self.root / 'staging'
        (lab / '.lab/credentials').mkdir(parents=True, mode=0o700)
        c.put(lab / '.lab/credentials/dashboard.env', b'EXISTING=preserved\n')
        helper = lab / host.HELPER; helper.parent.mkdir(parents=True)
        helper.write_text('# reviewed existing helper placeholder\n'); helper.chmod(0o644)
        args = types.SimpleNamespace(lab_root=lab, staging=staging, implementation_sha256=c.sha(c.encoded(host.implementation())), stage_sha256=None, phase='preflight', history_at=None, output_directory=None)
        guest_root = self.root / 'guest'; c.mkdir(guest_root)
        def remote(_lab, payload):
            if payload['phase'] == 'preflight': return {'epoch': int(__import__('time').time()), 'preserved': guest.preserved_snapshot(self.api, FakeModule)}
            if payload['phase'] == 'apply':
                users = guest.apply_users(self.api, FakeModule, guest_root, payload['passwords'], payload['baseline']['preserved'])
            else:
                owned = guest.subject_receipts(guest_root, payload['passwords'])
                self.assertEqual(guest.preserved_snapshot(self.api, FakeModule, owned), payload['baseline']['preserved'])
                users = [{'username': a['login'], 'keycloakUsername': a['username'], 'directoryId': a['directoryId'], 'subject': owned[a['username']], 'name': a['name']} for a in c.accounts()]
            return {'version': 1, 'synthetic': True, 'issuer': c.ISSUER, 'users': users, 'preservedSHA256': c.sha(c.encoded(payload['baseline']['preserved']))}
        return args, remote
    def test_host_phases_full_offline_with_safe_retry(self):
        args, remote = self.host_setup()
        with patch.object(host, 'remote', side_effect=remote):
            self.assertEqual(host.execute(args)['accountsAbsent'], 25)
            self.assertEqual(self.api.posts, [])
            args.phase = 'stage'; args.stage_sha256 = host.execute(args)['stageSHA256']
            self.assertEqual(self.api.posts, [])
            self.assertEqual(c.read(args.lab_root / '.lab/credentials/dashboard.env'), b'EXISTING=preserved\n')
            args.phase = 'apply'; host.execute(args); host.execute(args)
            self.assertEqual(len(self.api.posts), 25)
            args.phase = 'verify'; host.execute(args)
            args.phase = 'handoff'; args.output_directory = self.root / 'handoff'
            args.history_at = (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
            self.assertFalse(host.execute(args)['guestChanges'])
            self.assertEqual(len(c.decode(c.read(args.output_directory / 'primary-scale-input.json'))['users']), 25)
    def test_host_stage_or_policy_drift_before_apply_creates_nothing(self):
        args, remote = self.host_setup()
        with patch.object(host, 'remote', side_effect=remote):
            host.execute(args); args.phase = 'stage'; args.stage_sha256 = host.execute(args)['stageSHA256']
            args.phase = 'apply'; self.api.realm['enabled'] = False
            with self.assertRaises(c.Failure): host.execute(args)
            self.assertEqual(self.api.posts, []); self.assertEqual(c.read(args.lab_root / '.lab/credentials/dashboard.env'), b'EXISTING=preserved\n')
            self.api.realm['enabled'] = True; args.stage_sha256 = '0' * 64
            with self.assertRaises(c.Failure): host.execute(args)
            self.assertEqual(self.api.posts, [])
    def test_host_lost_response_after_completed_accounts_can_resume(self):
        args, remote = self.host_setup()
        with patch.object(host, 'remote', side_effect=remote):
            host.execute(args); args.phase = 'stage'; args.stage_sha256 = host.execute(args)['stageSHA256']
        def lost(lab, payload):
            value = remote(lab, payload)
            if payload['phase'] == 'apply': raise c.Failure('test_lost_transport_response')
            return value
        args.phase = 'apply'
        with patch.object(host, 'remote', side_effect=lost):
            with self.assertRaises(c.Failure): host.execute(args)
        self.assertEqual(len(self.api.posts), 25)
        self.assertFalse((args.staging / 'apply.complete.json').exists())
        with patch.object(host, 'remote', side_effect=remote): host.execute(args)
        self.assertEqual(len(self.api.posts), 25)
    def test_subprocess_output_and_runtime_bounded(self):
        with self.assertRaises(c.Failure): c.run([sys.executable, '-c', 'import time;time.sleep(5)'], b'', timeout=0.05)
        with self.assertRaises(c.Failure): c.run([sys.executable, '-c', 'import sys;sys.stdout.write("x"*(2<<20))'], b'')
        self.assertEqual(c.run([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'], b'bounded'), b'bounded')

if __name__ == '__main__': unittest.main()
