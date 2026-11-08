#!/usr/bin/env python3
"""Offline recovery orchestration, identity and uncertain-outcome regressions."""
import importlib.util
import json
import os
import sqlite3
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('agents', Path(__file__).with_name('dashboard-agents.py'))
agents = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agents)
guest_spec = importlib.util.spec_from_file_location('guest', Path(__file__).with_name('dashboard-agent-guest.py'))
guest = importlib.util.module_from_spec(guest_spec)
guest_spec.loader.exec_module(guest)

AGENT = '8538455c-3758-4885-9bb5-4dec0d88e504'
GENERATION = '3ae8ed72-6d05-4af6-9fce-2f1c54df4b02'
OPERATION = '05000000-0000-4000-8000-000000000001'


def status(expired=False, session_expired=False):
    return {'agentId': AGENT, 'targetGenerationId': GENERATION,
            'sessionId': '06000000-0000-4000-8000-000000000001',
            'certificateExpiresAt': '2026-11-09T12:00:00.123456789Z',
            'sessionExpiresAt': '2026-11-09T11:00:00.123456789Z',
            'active': True, 'certificateExpired': expired, 'sessionExpired': session_expired}


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for name in ('.lab', '.lab/dashboard', '.lab/dashboard/cli'):
            (self.root / name).mkdir(mode=0o700)
        (self.root / '.lab/dashboard/cli/config.yaml').write_text('{}')
        self.pending = {'operationId': OPERATION, 'agentId': AGENT,
                        'targetGenerationId': GENERATION, 'token': 'synthetic-private-token'}

    def test_healthy_agent_requires_no_enrollment(self):
        with patch.object(agents, 'remote', return_value=status()), patch.object(agents, 'issue_token') as issue:
            agents.manage(self.root, 'ensure', ['host'])
        issue.assert_not_called()

    def test_pending_token_is_private_before_guest_mutation(self):
        def remote(root, kind, action, **values):
            if action == 'ensure':
                return status(expired=True)
            self.assertEqual(action, 'recover')
            self.assertEqual(values, self.pending)
            path = root / '.lab/dashboard/agent-recovery/host.pending.json'
            self.assertEqual(json.loads(path.read_text()), self.pending)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            return status()
        with patch.object(agents, 'remote', side_effect=remote), \
             patch.object(agents, 'issue_token', return_value=self.pending):
            agents.manage(self.root, 'ensure', ['host'])
        directory = self.root / '.lab/dashboard/agent-recovery'
        self.assertFalse((directory / 'host.pending.json').exists())
        self.assertNotIn('token', json.loads((directory / 'host.completed.json').read_text()))

    def test_uncertain_operation_reuses_exact_token_and_identity(self):
        with patch.object(agents, 'remote', side_effect=[status(expired=True), RuntimeError('uncertain')]), \
             patch.object(agents, 'issue_token', return_value=self.pending), self.assertRaises(RuntimeError):
            agents.manage(self.root, 'ensure', ['host'])
        with patch.object(agents, 'remote', side_effect=[status(), status()]) as remote, \
             patch.object(agents, 'issue_token') as issue:
            agents.manage(self.root, 'ensure', ['host'])
        issue.assert_not_called()
        self.assertEqual(remote.call_args.kwargs, self.pending)
        # A committed credential update with a missing SSH response must not
        # start a service before the retained recovery operation is completed.
        self.assertEqual(remote.call_args_list[0].args[2], 'inspect')

    def test_changed_agent_refuses_pending_recovery(self):
        directory = self.root / '.lab/dashboard/agent-recovery'
        directory.mkdir(mode=0o700)
        path = directory / 'host.pending.json'
        agents.cli.write_private(path, json.dumps(self.pending).encode())
        changed = dict(status(), agentId='8538455c-3758-4885-9bb5-4dec0d88e505')
        with patch.object(agents, 'remote', return_value=changed) as remote, self.assertRaises(RuntimeError):
            agents.manage(self.root, 'ensure', ['host'])
        self.assertEqual(remote.call_count, 1)
        self.assertTrue(path.exists())

    def test_session_only_expiry_waits_for_authenticated_agent_renewal(self):
        with patch.object(agents, 'remote', side_effect=[status(session_expired=True), status()]) as remote, \
             patch.object(agents, 'issue_token') as issue, patch.object(agents.time, 'sleep'):
            agents.manage(self.root, 'ensure', ['host'])
        issue.assert_not_called()
        self.assertEqual(remote.call_args.args[2], 'inspect')

    def test_check_cannot_recover_and_missing_configuration_skips(self):
        with patch.object(agents, 'remote', return_value=status(expired=True)), \
             patch.object(agents, 'issue_token') as issue, self.assertRaises(RuntimeError):
            agents.manage(self.root, 'check', ['host'])
        issue.assert_not_called()
        (self.root / '.lab/dashboard/cli/config.yaml').unlink()
        with patch.object(agents, 'remote') as remote:
            agents.manage(self.root, 'ensure', ['host'], if_configured=True)
        remote.assert_not_called()

    def test_private_pending_symlink_is_not_followed(self):
        directory = self.root / '.lab/dashboard/agent-recovery'
        directory.mkdir(mode=0o700)
        other = self.root / 'other.json'
        other.write_text(json.dumps(self.pending))
        other.chmod(0o600)
        (directory / 'host.pending.json').symlink_to(other)
        with patch.object(agents, 'remote', return_value=status(expired=True)), self.assertRaises(OSError):
            agents.manage(self.root, 'ensure', ['host'])
        self.assertEqual(json.loads(other.read_text()), self.pending)

    def test_remote_response_rejects_unexpected_fields_and_invalid_types(self):
        for value in (dict(status(), token='secret'), dict(status(), active='true'),
                      dict(status(), agentId='invalid'), dict(status(), certificateExpiresAt='tomorrow')):
            with self.subTest(value=value), self.assertRaises((RuntimeError, ValueError)):
                agents.valid_status(value)

    def test_guest_completed_receipt_does_not_stop_or_repeat_recovery(self):
        (self.root / '.recovered-host.json').write_text('{}')
        receipt = {key: self.pending[key] for key in ('operationId', 'agentId', 'targetGenerationId')}
        with patch.object(guest, 'BASE', self.root), patch.object(guest, 'inspect', return_value=status()), \
             patch.object(guest, 'read_private', return_value=receipt), patch.object(guest, 'run') as run:
            run.return_value.returncode = 0
            self.assertEqual(guest.recover('host', self.pending), status())
        run.assert_called_once_with(['systemctl', 'start', 'jobman-dashboard-execution-host.service'], timeout=20)

    def test_guest_refuses_receipt_identity_change_or_ambiguous_restart(self):
        receipt_path = self.root / '.recovered-host.json'
        receipt_path.write_text('{}')
        for changes in ({'agentId': OPERATION}, {'targetGenerationId': OPERATION}):
            receipt = {**self.pending, **changes}
            with patch.object(guest, 'BASE', self.root), patch.object(guest, 'inspect', return_value=status()), \
                 patch.object(guest, 'read_private', return_value=receipt), patch.object(guest, 'run') as run, \
                 self.assertRaises(RuntimeError):
                guest.recover('host', self.pending)
            run.assert_not_called()
        receipt_path.unlink()
        with patch.object(guest, 'BASE', self.root), patch.object(guest, 'inspect', return_value=status()), \
             patch.object(guest, 'run') as run, self.assertRaises(RuntimeError):
            guest.recover('host', self.pending)
        run.assert_not_called()

    def test_journal_preserves_identity_while_existing_runner_advances(self):
        path = self.root / 'agent.db'
        database = sqlite3.connect(path)
        self.addCleanup(database.close)
        database.execute('CREATE TABLE executions (execution_id TEXT, delivery_id TEXT, assignment_digest TEXT, state TEXT)')
        database.execute("INSERT INTO executions VALUES ('execution','delivery','digest','running')")
        database.commit()
        path.chmod(0o600)
        original = guest.journal_identity(self.root, os.getuid())
        database.execute("UPDATE executions SET state='terminal'")
        database.commit()
        self.assertEqual(guest.journal_identity(self.root, os.getuid()), original)
        database.execute("UPDATE executions SET delivery_id='different'")
        database.commit()
        self.assertNotEqual(guest.journal_identity(self.root, os.getuid()), original)


if __name__ == '__main__':
    unittest.main()
