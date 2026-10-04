#!/usr/bin/env python3
"""Offline failure-boundary checks. No guests, credentials, or scheduler calls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

guest = load('upgrade_guest', 'dashboard-slurm-upgrade-guest.py')
host = load('upgrade_host', 'apply-dashboard-slurm-upgrade.py')


class Upgrade(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.plan = {'oldRunner': '/old/runner', 'newRunner': '/new/runner', 'unitAfterSHA256': hashlib.sha256(b'new-unit').hexdigest()}
        self.before = {'MainPID': '11', 'ExecMainStartTimestampMonotonic': '100'}
        self.after = {'MainPID': '12', 'ExecMainStartTimestampMonotonic': '200'}
        self.writes = []

    def save(self, name, value):
        p = self.root/name
        p.write_bytes(guest.encode(value))
        p.chmod(0o600)

    def test_bounded_read_rejects_symlink_nonregular_and_growth_bound(self):
        path = self.root/'file'; path.write_bytes(b'abc'); path.chmod(0o600)
        self.assertEqual(host.read(path, 3), b'abc')
        with self.assertRaises(ValueError): host.read(path, 2)
        link = self.root/'link'; link.symlink_to(path)
        with self.assertRaises(OSError): host.read(link, 3)
        fifo = self.root/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): host.read(fifo, 3)

    def test_new_file_mode_exact_under_restrictive_umask_existing_never_repaired(self):
        path = self.root/'new'
        old = os.umask(0o777)
        try:
            with patch.object(guest, 'parents'), patch.object(guest.os, 'fchown'):
                guest.write_new(path, b'fixed', 0o644)
        finally: os.umask(old)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        path.chmod(0o600)
        with patch.object(guest, 'parents'), self.assertRaises(ValueError):
            guest.write_new(path, b'fixed', 0o644)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.read_bytes(), b'fixed')

    def test_host_receipt_is_exclusive_and_exact_under_umask(self):
        path = self.root/'receipt.json'; old = os.umask(0o777)
        try: host.write(path, {'fixed': True})
        finally: os.umask(old)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        host.write(path, {'fixed': True})
        with self.assertRaises(ValueError): host.write(path, {'fixed': False})

    def test_uncertain_restart_of_old_process_is_never_reissued(self):
        self.save('restart.pending.json', {'process': self.before})
        with patch.object(guest, 'read', side_effect=lambda p, *_: p.read_bytes()), patch.object(guest, 'identity', side_effect=ValueError('old process')), patch.object(guest, 'run') as run:
            with self.assertRaises(ValueError): guest.restart(self.plan, self.root)
            run.assert_not_called()
        self.assertFalse((self.root/'restart.json').exists())

    def test_lost_restart_receipt_requires_both_changed_pid_and_start(self):
        self.save('restart.pending.json', {'process': self.before})
        for value in [self.before, {'MainPID': '12', 'ExecMainStartTimestampMonotonic': '100'}, {'MainPID': '11', 'ExecMainStartTimestampMonotonic': '200'}]:
            with self.subTest(value=value), patch.object(guest, 'read', side_effect=lambda p, *_: p.read_bytes()), patch.object(guest, 'identity', return_value=value), patch.object(guest, 'run') as run:
                with self.assertRaises(ValueError): guest.restart(self.plan, self.root)
                run.assert_not_called()
        with patch.object(guest, 'read', side_effect=lambda p, *_: p.read_bytes()), patch.object(guest, 'identity', return_value=self.after), patch.object(guest, 'run') as run, patch.object(guest, 'write_new', side_effect=lambda p, data, mode: self.writes.append((p.name, json.loads(data)))):
            result = guest.restart(self.plan, self.root)
            self.assertEqual(result['process'], self.after)
            self.assertEqual(self.writes[0][0], 'restart.json')
            run.assert_not_called()

    def test_completed_restart_never_restarts_and_rejects_drift(self):
        self.save('restart.json', {'process': self.after})
        with patch.object(guest, 'read', side_effect=lambda p, *_: p.read_bytes()), patch.object(guest, 'identity', return_value=self.after), patch.object(guest, 'run') as run:
            self.assertEqual(guest.restart(self.plan, self.root)['process'], self.after)
            run.assert_not_called()
        with patch.object(guest, 'read', side_effect=lambda p, *_: p.read_bytes()), patch.object(guest, 'identity', return_value=self.before):
            with self.assertRaises(ValueError): guest.restart(self.plan, self.root)

    def test_pending_written_before_only_restart_then_whole_identity_retried(self):
        self.save('swap.pending.json', {'process': self.before})
        unit = self.root/'unit'; unit.write_bytes(b'new-unit'); unit.chmod(0o644)
        events = []
        def run(args, **_):
            if '--property=MainPID' in args: return b'11\n'
            if '--property=ExecMainStartTimestampMonotonic' in args: return b'100\n'
            events.append(args[1]); return b''
        def write(path, data, mode): events.append(path.name)
        with patch.object(guest, 'UNIT_PATH', unit), patch.object(guest, 'read', side_effect=lambda p, *_: p.read_bytes()), patch.object(guest.os, 'readlink', return_value='/old/runner'), patch.object(guest, 'empty_queue'), patch.object(guest, 'run', side_effect=run), patch.object(guest, 'write_new', side_effect=write), patch.object(guest.time, 'sleep'), patch.object(guest, 'identity', side_effect=[ValueError('starting'), self.after]) as identity:
            guest.restart(self.plan, self.root)
            self.assertEqual(events, ['restart.pending.json', 'daemon-reload', 'restart', 'restart.json'])
            self.assertEqual(identity.call_count, 2)
            self.assertEqual(identity.call_args.args[:2], (self.plan, True))
            self.assertIsInstance(identity.call_args.args[2], float)

    def test_restart_command_failure_keeps_pending_and_never_completes(self):
        self.save('swap.pending.json', {'process': self.before})
        unit = self.root/'unit'; unit.write_bytes(b'new-unit')
        def run(args, **_):
            if '--property=MainPID' in args: return b'11\n'
            if '--property=ExecMainStartTimestampMonotonic' in args: return b'100\n'
            if args[1] == 'restart': raise ValueError('failed')
            return b''
        with patch.object(guest, 'UNIT_PATH', unit), patch.object(guest, 'read', side_effect=lambda p, *_: p.read_bytes()), patch.object(guest.os, 'readlink', return_value='/old/runner'), patch.object(guest, 'empty_queue'), patch.object(guest, 'run', side_effect=run), patch.object(guest, 'write_new', side_effect=lambda p, data, mode: self.writes.append(p.name)):
            with self.assertRaises(ValueError): guest.restart(self.plan, self.root)
        self.assertEqual(self.writes, ['restart.pending.json'])

    def swap_case(self, pending=False, current_new=False, drift=False):
        from types import SimpleNamespace
        v = dict(self.plan, coreRevision=guest.NEW_REVISION, oldCoreRevision=guest.OLD_REVISION, agentSHA256=guest.NEW_HASH, oldAgentSHA256=guest.OLD_HASH)
        before = b'ExecStart=/old/runner run --slurm-runner /old/runner\n'
        after = before.replace(b'/old/runner', b'/new/runner')
        v['unitBeforeSHA256'], v['unitAfterSHA256'] = guest.sha(before), guest.sha(after)
        unit = self.root/'unit'; unit.write_bytes(after if current_new else before)
        if pending:
            self.save('swap.pending.json', {'process': self.before})
            (self.root/'unit.before').write_bytes(before)
        payload = {'plan': v, 'phase': 'swap', 'host': 'submit01', 'unitBefore': before.decode(), 'unitAfter': after.decode(), 'baseline': {'process': self.before}}
        def writer(path, raw, mode):
            if path.exists(): self.assertEqual(path.read_bytes(), raw)
            else: path.write_bytes(raw)
        changes = [self.before, self.after] if drift else [self.before, self.before]
        from contextlib import ExitStack
        with ExitStack() as stack:
            for target, name, kwargs in [
                (guest, 'UNIT_PATH', {'new': unit}),
                (guest, 'PLAN_HASH', {'new': guest.sha(guest.encode(v))}),
                (guest.os, 'geteuid', {'return_value': 0}),
                (guest.sys, 'platform', {'new': 'linux'}),
                (guest.os, 'uname', {'return_value': SimpleNamespace(nodename='submit01')}),
                (guest, 'binary', {}),
                (guest, 'receipt_root', {'return_value': self.root}),
                (guest, 'read', {'side_effect': lambda p, *_: p.read_bytes()}),
                (guest, 'write_new', {'side_effect': writer}),
                (guest, 'identity', {'side_effect': changes}),
                (guest, 'empty_queue', {}),
                (guest, 'sync_directory', {})]:
                stack.enter_context(patch.object(target, name, **kwargs))
            if drift or (pending and not current_new):
                with self.assertRaises(ValueError): guest.perform(payload)
                self.assertEqual(unit.read_bytes(), before)
                self.assertFalse((self.root/'swap.json').exists())
            else:
                guest.perform(payload)
                self.assertEqual(unit.read_bytes(), after)
                self.assertEqual((self.root/'unit.before').read_bytes(), before)
                self.assertTrue((self.root/'swap.json').exists())

    def test_unit_swap_cas_preserves_backup(self):
        self.swap_case()

    def test_unit_process_drift_rejects_swap(self):
        self.swap_case(drift=True)

    def test_uncertain_swap_requires_installed_exact_new_bytes(self):
        self.swap_case(pending=True)

    def test_lost_swap_response_can_complete_from_exact_new_bytes(self):
        self.swap_case(pending=True, current_new=True)

    def test_source_runtime_roles_match_actual_split_hosts_and_units(self):
        expected = {
            'api': ('storage01', '/etc/jobman-dashboard-api-lab/config.json', 21904, 'apiConfigSHA256', 'jobman-dashboard-lab-api'),
            'reports': ('storage01', '/etc/jobman-dashboard-worker-lab/config.json', 21905, 'workerConfigSHA256', 'jobman-dashboard-lab-worker'),
            'broker': ('control01', '/etc/jobman-dashboard-broker-lab/config.json', 21901, 'brokerConfigSHA256', 'jobman-dashboard-lab-broker'),
        }
        self.assertEqual(guest.SOURCE_ROLES, expected)
        raw = b'{"configurationRevision":6}'
        value = {'dashboard': {row[3]: guest.sha(raw) for row in expected.values()}, 'preserved': {'controlInstanceId': 'instance', 'recoveryEpoch': '1'}}
        for machine in ['storage01', 'control01']:
            paths, units = [], []
            def reader(path, mode, maximum, uid):
                paths.append((str(path), uid))
                self.assertEqual(mode, 0o600)
                return raw
            def runner(args, **unused):
                if args[0] == 'runuser':
                    self.assertEqual(machine, 'control01')
                    return b'{"capabilities":{"instanceId":"instance","recoveryEpoch":"1"}}'
                if args[1] == 'is-active':
                    units.append(args[-1]); return b''
                return b'123\n'
            with self.subTest(machine=machine), patch.object(guest, 'read', side_effect=reader), patch.object(guest, 'run', side_effect=runner):
                result = guest.source(value, machine)
                rows = [row for row in expected.values() if row[0] == machine]
                self.assertEqual(paths, [(row[1], row[2]) for row in rows])
                self.assertEqual(set(result['configs']), {row[3] for row in rows})
                wanted = [row[4] for row in rows]
                if machine == 'control01': wanted += ['jobman-dashboard-lab-control', 'jobman-dashboard-lab-directory', 'jobman-control', 'jobman-keycloak']
                self.assertEqual(units, wanted)
                self.assertEqual(set(result['processes']), set(wanted))

    def test_host_checks_both_split_hosts_before_and_after_mutations(self):
        calls = []
        def call(machine, phase):
            calls.append((machine, phase)); return {'verified': machine}
        self.assertEqual(host.source_states(call), {'storage01': {'verified': 'storage01'}, 'control01': {'verified': 'control01'}})
        self.assertEqual(calls, [('storage01', 'source'), ('control01', 'source')])

    def test_unsafe_plan_rejected_before_creating_guest_lock(self):
        with patch.object(guest.os, 'geteuid', return_value=0), patch.object(guest.sys, 'platform', 'linux'), patch.object(guest, 'directory') as directory:
            with self.assertRaises(ValueError): guest.execute({'plan': {}, 'phase': 'install', 'host': 'submit01'})
            directory.assert_not_called()

    def test_bounded_commands_kill_excess_output_without_revealing_stderr(self):
        with self.assertRaisesRegex(ValueError, 'output bound'):
            guest.run([sys.executable, '-c', 'print("x"*100000)'], maximum=1024)
        with self.assertRaisesRegex(ValueError, 'Scoped command failed'):
            guest.run([sys.executable, '-c', 'import sys; print("private",file=sys.stderr);sys.exit(1)'])

    def test_host_transport_deadline_and_bound(self):
        with self.assertRaisesRegex(ValueError, 'deadline'):
            host.run([sys.executable, '-c', 'import time;time.sleep(10)'], b'{}', .03)
        with self.assertRaisesRegex(ValueError, 'output bound'):
            host.run([sys.executable, '-c', 'import sys;sys.stdin.read();print("x"*100000)'], b'{}', 2)


if __name__ == '__main__': unittest.main()
