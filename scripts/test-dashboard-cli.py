#!/usr/bin/env python3
"""Offline native PKCE, identity, private-file and CLI boundary checks."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.parse

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('dashboard_cli', ROOT / 'scripts/dashboard-cli.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def token(claims):
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return 'test-header.' + encoded + '.test-signature'


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        for name in ('.lab', '.lab/dashboard', '.lab/credentials'):
            (self.root / name).mkdir(mode=0o700)
        public = {'issuer': cli.ISSUER, 'audience': cli.AUDIENCE, 'nativeClientId': cli.CLIENT,
                  'users': [{'username': 'dashboard-alice', 'directoryGuid': cli.DIRECTORY_ID,
                             'subject': 'synthetic-alice-subject'}]}
        (self.root / '.lab/dashboard/oidc-public.json').write_text(json.dumps(public))
        credentials = self.root / '.lab/credentials/dashboard.env'
        credentials.write_text('JOBMAN_LAB_DASHBOARD_ALICE_PASSWORD=' + 'p' * 64 + '\n')
        credentials.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def flow(self, *, bad_state=False, wrong_subject=False, wrong_nonce=False, control_status=200):
        observations = []
        authorization = {}
        def exchange(client, url, **kwargs):
            observations.append((url, kwargs))
            if url.endswith('/.well-known/openid-configuration'):
                return 200, {}, json.dumps({'issuer': cli.ISSUER,
                    'authorization_endpoint': cli.ISSUER + '/protocol/openid-connect/auth',
                    'token_endpoint': cli.ISSUER + '/protocol/openid-connect/token'}).encode()
            if '/protocol/openid-connect/auth?' in url:
                authorization.update(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query))
                return 200, {}, ('<form id="kc-form-login" action="' + cli.ISSUER +
                                  '/login-actions/authenticate?session=test&amp;execution=1"></form>').encode()
            if '/login-actions/authenticate?' in url:
                self.assertEqual(kwargs['form']['username'], 'dashboard-alice')
                self.assertEqual(kwargs['form']['password'], 'p' * 64)
                state = 'wrong' if bad_state else authorization['state'][0]
                return 302, {'Location': cli.CALLBACK + '?' + urllib.parse.urlencode({
                    'state': state, 'code': 'synthetic-code', 'iss': cli.ISSUER})}, b''
            if url.endswith('/protocol/openid-connect/token'):
                form = kwargs['form']
                self.assertEqual(form['grant_type'], 'authorization_code')
                self.assertEqual(form['redirect_uri'], cli.CALLBACK)
                self.assertEqual(form['client_id'], cli.CLIENT)
                self.assertEqual(authorization['code_challenge_method'], ['S256'])
                challenge = base64.urlsafe_b64encode(hashlib.sha256(form['code_verifier'].encode()).digest()).decode().rstrip('=')
                self.assertEqual(authorization['code_challenge'], [challenge])
                self.assertNotIn('client_secret', form)
                claims = {'iss': cli.ISSUER, 'sub': 'synthetic-alice-subject',
                          'directory_guid': cli.DIRECTORY_ID, 'exp': time.time() + 300}
                access = token(dict(claims, aud=[cli.AUDIENCE], azp=cli.CLIENT))
                identity = token(dict(claims, aud=cli.CLIENT,
                                      nonce='wrong' if wrong_nonce else authorization['nonce'][0]))
                return 200, {}, json.dumps({'access_token': access, 'id_token': identity,
                                           'token_type': 'Bearer', 'refresh_token': 'NEVER-PERSIST'}).encode()
            self.assertEqual(url, cli.CONTROL + '/v1/me?limit=200')
            self.assertIn('token', kwargs)
            principal = {'issuer': cli.ISSUER, 'subject': 'other' if wrong_subject else 'synthetic-alice-subject',
                         'directoryId': cli.DIRECTORY_ID}
            return control_status, {}, json.dumps({'kind': 'CurrentPrincipal', 'principal': principal,
                'namespaces': [{'name': cli.NAMESPACE}]}).encode()
        return exchange, observations

    def test_native_pkce_and_control_validation_without_policy_changes(self):
        exchange, observations = self.flow()
        output = io.StringIO()
        with patch.object(cli, 'identity_context', return_value='identity-context'), \
             patch.object(cli.ssl, 'create_default_context', return_value='control-context') as control_tls, \
             patch.object(cli, 'opener'), patch.object(cli, 'request', side_effect=exchange), \
             contextlib.redirect_stdout(output):
            result = cli.login(self.root)
        self.assertEqual(len(observations), 5)
        self.assertEqual(cli.jwt_claims(result)['sub'], 'synthetic-alice-subject')
        control_tls.assert_called_once_with(cafile=str(self.root / '.lab/dashboard/runtime/control/fixture-ca.crt'))
        self.assertEqual(output.getvalue(), '')
        self.assertFalse((self.root / '.lab/dashboard/cli').exists())

    def test_state_nonce_and_control_identity_fail_closed(self):
        for values in ({'bad_state': True}, {'wrong_nonce': True}, {'wrong_subject': True}, {'control_status': 401}):
            with self.subTest(values=values):
                exchange, observations = self.flow(**values)
                with patch.object(cli, 'identity_context'), patch.object(cli.ssl, 'create_default_context'), \
                     patch.object(cli, 'opener'), patch.object(cli, 'request', side_effect=exchange):
                    with self.assertRaises(RuntimeError):
                        cli.login(self.root)
                if values.get('bad_state'):
                    self.assertEqual(len(observations), 3)

    def test_form_and_callback_cannot_escape_pinned_origins(self):
        for action in ('https://evil.example/realms/jobman-lab/login-actions/authenticate',
                       'https://oidc.lab.test:8443@evil.example/realms/jobman-lab/login-actions/a',
                       cli.ISSUER + '/elsewhere', 'http://oidc.lab.test:8443/realms/jobman-lab/login-actions/a'):
            with self.subTest(action=action), self.assertRaises(RuntimeError):
                cli.form_action(('<form id="kc-form-login" action="' + action + '">').encode())
        for callback in ('https://evil.example/?state=x&code=y',
                         cli.CALLBACK + '?state=x&state=x&code=y',
                         cli.CALLBACK + '?state=x&code=y&code=z',
                         cli.CALLBACK + '?state=x&code=y&iss=https://evil.example'):
            with self.subTest(callback=callback), self.assertRaises(RuntimeError):
                cli.callback_code(callback, 'x')
        self.assertIsNone(cli.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.example'))

    def test_credentials_and_state_refuse_symlinks_and_public_permissions(self):
        path = self.root / '.lab/credentials/dashboard.env'
        path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            cli.read_file(path, private=True)
        path.chmod(0o600)
        link = self.root / 'linked-token'
        link.symlink_to(path)
        with self.assertRaises(RuntimeError):
            cli.write_private(link, b'changed')
        self.assertIn('p' * 64, path.read_text())
        directory = self.root / '.lab/dashboard/cli'
        directory.symlink_to(self.root / '.lab/credentials')
        with patch.object(cli, 'login') as login, self.assertRaises(RuntimeError):
            cli.execute(self.root, ['list'])
        login.assert_not_called()

    def test_atomic_token_refresh_does_not_read_a_superseded_inode(self):
        path = self.root / 'access-token'
        replacement = self.root / 'replacement'
        for file in (path, replacement):
            file.write_bytes(b'old-token\n')
            file.chmod(0o600)
        original_open = os.open

        def replace_after_open(file, *args, **kwargs):
            fd = original_open(file, *args, **kwargs)
            if Path(file) == path:
                # Reproduce the zero-link inode window from atomic renewal.
                replacement.replace(path)
                self.assertEqual(os.fstat(fd).st_nlink, 0)
            return fd

        with patch.object(cli.os, 'open', side_effect=replace_after_open):
            cli.write_private(path, b'new-token\n')
        self.assertEqual(cli.read_file(path, private=True), b'new-token\n')

    def test_replacement_preserves_file_security_boundaries(self):
        path = self.root / 'access-token'
        for case in ('hardlink', 'public', 'oversized', 'directory'):
            with self.subTest(case=case):
                if case == 'directory':
                    path.mkdir()
                else:
                    path.write_bytes(b'x' * (65537 if case == 'oversized' else 8))
                    path.chmod(0o644 if case == 'public' else 0o600)
                alias = self.root / 'alias'
                if case == 'hardlink':
                    os.link(path, alias)
                try:
                    with self.assertRaises(RuntimeError):
                        cli.write_private(path, b'new-token\n')
                    if case != 'directory':
                        self.assertEqual(path.read_bytes(), b'x' * (65537 if case == 'oversized' else 8))
                finally:
                    alias.unlink(missing_ok=True)
                    if case == 'directory':
                        path.rmdir()
                    else:
                        path.unlink()

    def test_repeated_invocations_refresh_existing_token_and_config(self):
        with patch.object(cli.shutil, 'which', return_value='/synthetic/jobman'), \
             patch.object(cli, 'login', side_effect=['first-token', 'second-token']), \
             patch.object(cli.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            self.assertEqual(cli.execute(self.root, ['status', 'synthetic-job']), 0)
            self.assertEqual(cli.execute(self.root, ['status', 'synthetic-job']), 0)
        directory = self.root / '.lab/dashboard/cli'
        self.assertEqual(cli.read_file(directory / 'access-token', private=True), b'second-token\n')
        self.assertEqual(json.loads(cli.read_file(directory / 'config.yaml', private=True))['shared']['current_profile'],
                         cli.PROFILE)

    def test_wrapper_preserves_arguments_private_files_and_exit_code(self):
        arguments = ['run', '--target', 'dashboard-execution-host', '--', '/bin/sh', '-c', 'echo "two words"; exit 7']
        def invoke(command, **kwargs):
            directory = self.root / '.lab/dashboard/cli'
            config = json.loads((directory / 'config.yaml').read_text())
            self.assertEqual(config['trusted_project_roots'], [])
            profile = config['shared']['profiles'][cli.PROFILE]
            self.assertEqual(profile['namespace'], cli.NAMESPACE)
            self.assertEqual(profile['endpoint'], cli.CONTROL)
            self.assertEqual(command, ['/synthetic/jobman', '--config', str(directory / 'config.yaml'),
                '--state-dir', str(directory / 'state'), '--no-extensions', 'shared', '--profile', cli.PROFILE,
                *arguments])
            self.assertNotIn('timeout', kwargs)
            self.assertNotIn('PRIVATE-ACCESS', repr(command))
            for name in ('access-token', 'config.yaml', 'operation.lock'):
                self.assertEqual(stat.S_IMODE((directory / name).stat().st_mode), 0o600)
            self.assertEqual((directory / 'access-token').read_text(), 'PRIVATE-ACCESS\n')
            # Long waits do not retain the wrapper login lock: cancellation and
            # other reads can obtain fresh tokens concurrently with Jobman.
            with (directory / 'operation.lock').open('r+') as stream:
                cli.fcntl.flock(stream, cli.fcntl.LOCK_EX | cli.fcntl.LOCK_NB)
            return subprocess.CompletedProcess(command, 7)
        with patch.object(cli.shutil, 'which', return_value='/synthetic/jobman'), \
             patch.object(cli, 'login', return_value='PRIVATE-ACCESS'), \
             patch.object(cli.subprocess, 'run', side_effect=invoke):
            self.assertEqual(cli.execute(self.root, arguments), 7)

    def test_profile_overrides_and_unmapped_byte_logs_are_rejected_before_login(self):
        for arguments in (['list', '--profile', 'other'], ['list', '--config=/tmp/other'],
                          ['run', '--state-dir', '/tmp/other'], ['logs', 'id'], ['logs', '--json', '--follow', 'id'],
                          ['logs', '--json', '--json=false', 'id'], ['logs', '--json=true', '--json=false', 'id'],
                          ['logs', '--json', '--json', 'id'], ['logs', '--json=false', 'id'],
                          ['logs', '--json=1', 'id'], ['logs', '--json', '--follow=true', 'id']):
            with self.subTest(arguments=arguments), patch.object(cli, 'login') as login, self.assertRaises(RuntimeError):
                cli.execute(self.root, arguments)
            login.assert_not_called()
        cli.validate_command(['run', '--', '/bin/echo', '--config=workload-value'])
        cli.validate_command(['logs', '--json', 'id'])
        cli.validate_command(['logs', '--json=true', 'id'])


if __name__ == '__main__':
    unittest.main()
