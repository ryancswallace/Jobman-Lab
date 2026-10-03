#!/usr/bin/env python3
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('scenario', Path(__file__).with_name('dashboard-directory-scenario.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def baseline(root):
    state = {'revision': 1, 'users': [{'directoryId': module.ALICE, 'enabled': True}, {'directoryId': module.BOB, 'enabled': True}],
             'groups': [{'id': '72000000-0000-4000-8000-%012d' % index, 'members': []} for index in range(1, 9)]}
    state['groups'][0]['members'] = [module.ALICE, module.BOB]
    state['groups'][1]['members'] = [module.ALICE]
    state['groups'][7]['members'] = [module.ALICE]
    raw = (json.dumps(state, indent=2) + '\n').encode()
    path = root / 'directory-state.json'
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


class ScenarioTests(unittest.TestCase):
    def test_narrow_group_edits_restore_exact_bytes_and_private_mode(self):
        for scenario in module.SCENARIOS:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                original = baseline(root)
                token = '1' * 32
                module.transition(root, 'begin', token, scenario)
                changed = json.loads((root / 'directory-state.json').read_bytes())
                self.assertEqual(changed['revision'], 2)
                self.assertEqual(changed['users'], json.loads(original)['users'])
                for group_id, member in module.SCENARIOS[scenario]:
                    group = next(group for group in changed['groups'] if group['id'] == group_id)
                    self.assertNotIn(member, group['members'])
                self.assertEqual(changed['groups'][7]['members'], [module.ALICE])
                self.assertEqual((root / 'directory-state.json').stat().st_mode & 0o777, 0o600)
                module.transition(root, 'restore', token)
                self.assertEqual((root / 'directory-state.json').read_bytes(), original)
                self.assertEqual(list(root.glob('.directory-acceptance-*.json')), [])

    def test_pending_receipt_and_concurrent_changes_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline(root)
            token = '2' * 32
            module.transition(root, 'begin', token, 'bob-research-removed')
            with self.assertRaises(ValueError):
                module.transition(root, 'begin', '3' * 32, 'alice-viewer-removed')
            state = root / 'directory-state.json'
            changed = json.loads(state.read_bytes())
            changed['revision'] = 999
            state.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                module.transition(root, 'restore', token)
            self.assertEqual(json.loads(state.read_bytes())['revision'], 999)
            self.assertTrue((root / ('.directory-acceptance-' + token + '.json')).exists())

    def test_active_transition_lock_prevents_second_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = baseline(root)
            lock = root / '.directory-acceptance.lock'
            lock.touch(mode=0o600)
            with lock.open('r+') as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    module.transition(root, 'begin', '5' * 32, 'alice-viewer-removed')
            self.assertEqual((root / 'directory-state.json').read_bytes(), original)
            self.assertEqual(list(root.glob('.directory-acceptance-*.json')), [])

    def test_unexpected_accounts_and_symlink_state_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = json.loads(baseline(root))
            original['users'][0]['enabled'] = False
            with self.assertRaises(ValueError):
                module.scenario_state(json.dumps(original), 'alice-viewer-removed')
            os.rename(root / 'directory-state.json', root / 'other.json')
            (root / 'directory-state.json').symlink_to(root / 'other.json')
            with self.assertRaises(OSError):
                module.transition(root, 'begin', '4' * 32, 'alice-viewer-removed')


if __name__ == '__main__':
    unittest.main()
