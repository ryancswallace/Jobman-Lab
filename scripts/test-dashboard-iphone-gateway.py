#!/usr/bin/env python3
"""Offline iPhone gateway policy/lifecycle and real synthetic TLS generation checks."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

gateway = load('iphone-gateway')
tls = load('ensure-oidc-tls')
CONFIG = {'interface': 'en0', 'mac_address': '192.168.20.2', 'phone_address': '192.168.20.3',
          'upstream_dns': ['192.168.20.1']}


class GatewayTests(unittest.TestCase):
    def test_rejects_broad_or_injected_configuration(self):
        for field, value in [('phone_address', '192.168.20.0/24'), ('phone_address', '0.0.0.0'),
                             ('phone_address', '8.8.8.8'), ('phone_address', '10.77.0.10'),
                             ('mac_address', '::'), ('interface', 'en0\nsetACL({})'),
                             ('upstream_dns', ['192.168.20.2']), ('upstream_dns', [])]:
            with self.subTest(field=field, value=value):
                c = dict(CONFIG, **{field: value})
                with self.assertRaises((ValueError, RuntimeError)):
                    gateway.validate(c)

    def test_phone_only_policy_and_tls_passthrough(self):
        configs = gateway.configurations(CONFIG, Path('/var/run/test'), 'tester')
        self.assertIn("setACL({'192.168.20.3/32', '127.0.0.1/32'})", configs['dnsdist.conf'])
        self.assertIn('listen-address=127.0.0.1', configs['dnsmasq.conf'])
        self.assertIn('no-hosts', configs['dnsmasq.conf'])
        self.assertNotIn('192.168.20.0/24', ''.join(configs.values()))
        proxy = configs['haproxy.cfg']
        self.assertIn('tcp-request connection reject unless phone', proxy)
        self.assertIn('tcp-request content reject if tls_hello !dashboard !identity', proxy)
        self.assertNotIn('default_backend', proxy)
        self.assertNotIn(' crt ', proxy)
        self.assertIn('server identity 10.77.0.21:8443', proxy)

    def test_launchd_drops_privileges(self):
        account = pwd.getpwuid(os.getuid()).pw_name
        paths = {name: '/tools/' + name for name in gateway.SERVICES}
        jobs = gateway.plists(paths, Path('/var/run/test'), account)
        self.assertEqual(jobs['haproxy']['UserName'], account)
        self.assertEqual(jobs['dnsmasq']['UserName'], account)
        self.assertIn('--uid', jobs['dnsdist']['ProgramArguments'])
        self.assertIn(account, jobs['dnsdist']['ProgramArguments'])
        for job in jobs.values():
            self.assertTrue(job['KeepAlive'])
            self.assertNotIn('sh', job['ProgramArguments'])

    def test_address_change_fails_closed(self):
        with patch.object(gateway.sys, 'platform', 'darwin'), patch.object(gateway, 'run') as run:
            run.return_value.stdout = '192.168.20.9\n'
            with self.assertRaisesRegex(RuntimeError, 'address changed'):
                gateway.preflight(CONFIG)

    def test_stop_targets_only_owned_labels(self):
        with patch.object(gateway, 'loaded', return_value=True), patch.object(gateway, 'run') as run:
            run.return_value.returncode = 0
            gateway.stop()
            self.assertEqual(run.call_count, 3)
            for call in run.call_args_list:
                self.assertEqual(call.args[0][:2], ['/bin/launchctl', 'bootout'])
                self.assertTrue(call.args[0][2].startswith('system/' + gateway.LABEL + '.'))

    def test_idempotent_start_verifies_without_restarting(self):
        account = pwd.getpwuid(os.getuid()).pw_name
        paths = {name: '/tools/' + name for name in gateway.SERVICES}
        with tempfile.TemporaryDirectory() as d:
            runtime = Path(d)
            (runtime / 'configuration.json').write_text(json.dumps({'config': CONFIG, 'tools': paths, 'user': account, 'implementation_sha256': hashlib.sha256(Path(gateway.__file__).read_bytes()).hexdigest()}, sort_keys=True))
            # stat's owner check is mocked only; no root access or services are used.
            original_stat = Path.stat
            def stat(p, *args, **kwargs):
                value = original_stat(p, *args, **kwargs)
                if p == runtime:
                    values = list(value); values[4] = 0
                    return os.stat_result(values)
                return value
            with patch.object(gateway, 'RUNTIME', runtime), patch.object(gateway.os, 'geteuid', return_value=0), \
                 patch.object(gateway, 'preflight'), patch.object(gateway, 'tools', return_value=paths), \
                 patch.object(gateway, 'loaded', return_value=True), patch.object(gateway, 'verify') as verify, \
                 patch.object(gateway, 'stop') as stop, patch.object(Path, 'stat', stat):
                gateway.manage_start(CONFIG, account)
                verify.assert_called_once_with(CONFIG)
                stop.assert_not_called()

    def test_bootstrap_failure_cleans_up_and_restrictive_umask_is_supported(self):
        account = pwd.getpwuid(os.getuid()).pw_name
        paths = {name: '/tools/' + name for name in gateway.SERVICES}
        with tempfile.TemporaryDirectory() as d:
            runtime = Path(d) / 'runtime'
            original_stat = Path.stat
            def stat(p, *args, **kwargs):
                value = original_stat(p, *args, **kwargs)
                if p == runtime:
                    values = list(value); values[4] = 0
                    return os.stat_result(values)
                return value
            def command(args, **kwargs):
                failed = 'bootstrap' in args and str(args[-1]).endswith('dnsdist.plist')
                return subprocess.CompletedProcess(args, 1 if failed else 0, '', 'synthetic failure' if failed else '')
            previous = os.umask(0o077)
            try:
                with patch.object(gateway, 'RUNTIME', runtime), patch.object(gateway.os, 'geteuid', return_value=0), \
                     patch.object(gateway, 'preflight'), patch.object(gateway, 'tools', return_value=paths), \
                     patch.object(gateway, 'loaded', return_value=False), patch.object(gateway, 'stop') as stop, \
                     patch.object(gateway.socket, 'socket'), patch.object(gateway, 'run', side_effect=command), \
                     patch.object(Path, 'stat', stat), patch.object(gateway.os, 'chown', wraps=os.chown) as chown:
                    with self.assertRaisesRegex(RuntimeError, 'launchd startup failed'):
                        gateway.manage_start(CONFIG, account)
                    self.assertEqual(stop.call_count, 2)
                    account_info = pwd.getpwnam(account)
                    self.assertEqual(chown.call_count, 2)
                    for name in ('dnsmasq', 'dnsdist'):
                        chown.assert_any_call(runtime / (name + '.log'), account_info.pw_uid, account_info.pw_gid)
                self.assertEqual(runtime.stat().st_mode & 0o777, 0o755)
                self.assertFalse((runtime / 'configuration.json').exists())
                # Actual filesystem ownership/mode, not a mocked chown: the
                # service account must be able to open launchd redirections.
                for name in ('dnsmasq', 'dnsdist'):
                    log = runtime / (name + '.log')
                    self.assertEqual(log.stat().st_uid, pwd.getpwnam(account).pw_uid)
                    self.assertEqual(log.stat().st_gid, pwd.getpwnam(account).pw_gid)
                    self.assertEqual(log.stat().st_mode & 0o777, 0o600)
                    with log.open('a') as stream:
                        stream.write('service diagnostic\n')
            finally:
                os.umask(previous)

    def test_lifecycle_hooks(self):
        make = (ROOT / 'Makefile').read_text()
        startup = make[make.index('ensure-running:'):make.index('inventory:')]
        self.assertIn('ensure-vms', startup)
        self.assertIn('start --if-configured', startup)
        converge = make[make.index('converge:'):make.index('configure-control:')]
        self.assertLess(converge.index('ansible-playbook'), converge.index('iphone-gateway.py'))
        self.assertIn('inventory: ensure-vms', make)
        halt = make[make.index('halt:'):make.index('down:')]
        self.assertLess(halt.index('iphone-gateway.py stop'), halt.index('vagrant halt'))
        for script in ('destroy-lab.sh', 'clean-generated.sh'):
            text = (ROOT / 'scripts' / script).read_text()
            self.assertGreater(text.index('iphone-gateway.py" stop'), text.index('read -r'))



class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        tls.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '730',
                 '-subj', '/CN=Synthetic Test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                 '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                 '-keyout', self.directory / 'lab-ca.key', '-out', self.directory / 'lab-ca.crt'])

    def tearDown(self):
        self.temp.cleanup()

    def test_new_certificate_and_idempotence(self):
        self.assertTrue(tls.ensure(self.directory))
        cert = self.directory / 'control01.lab.test.crt'
        first = cert.read_bytes()
        self.assertIn(b'TLS Web Server Authentication', tls.run(['openssl', 'x509', '-in', cert, '-noout', '-ext', 'extendedKeyUsage']))
        self.assertFalse(tls.ensure(self.directory))
        self.assertEqual(first, cert.read_bytes())
        # One-year lifetime, not the old 825-day leaf.
        dates = tls.run(['openssl', 'x509', '-in', cert, '-noout', '-dates']).decode().splitlines()
        from email.utils import parsedate_to_datetime
        before, after = [parsedate_to_datetime(v.split('=', 1)[1]) for v in dates]
        self.assertEqual((after - before).days, 365)

    def test_legacy_leaf_reissued_without_key_or_ca_rotation(self):
        key = self.directory / 'control01.lab.test.key'
        cert = self.directory / 'control01.lab.test.crt'
        csr = self.directory / 'legacy.csr'
        tls.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=control01.lab.test',
                 '-addext', 'subjectAltName=DNS:control01.lab.test,DNS:oidc.lab.test,IP:10.77.0.21', '-keyout', key, '-out', csr])
        tls.run(['openssl', 'x509', '-req', '-days', '365', '-in', csr, '-CA', self.directory / 'lab-ca.crt',
                 '-CAkey', self.directory / 'lab-ca.key', '-set_serial', '4', '-copy_extensions', 'copyall', '-out', cert])
        previous = cert.read_bytes()
        originals = {p: p.read_bytes() for p in (key, self.directory / 'lab-ca.key', self.directory / 'lab-ca.crt')}
        self.assertTrue(tls.ensure(self.directory))
        self.assertNotEqual(previous, cert.read_bytes())
        self.assertEqual(previous, next(self.directory.glob('*.before-*')).read_bytes())
        for p, data in originals.items():
            self.assertEqual(data, p.read_bytes())

    def test_missing_key_does_not_replace_existing_identity(self):
        (self.directory / 'control01.lab.test.crt').write_text('existing')
        with self.assertRaisesRegex(RuntimeError, 'private key missing'):
            tls.ensure(self.directory)


if __name__ == '__main__':
    unittest.main()
