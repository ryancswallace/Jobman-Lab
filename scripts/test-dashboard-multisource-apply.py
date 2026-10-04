#!/usr/bin/env python3
"""Offline bounded multi-source runtime helpers; no Lab/network invocation."""
import importlib.util
import base64
import copy
import json
import os
import tempfile
from contextlib import ExitStack
from types import SimpleNamespace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('multi_runtime', Path(__file__).with_name('dashboard-multisource-runtime.py'))
runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)

class RuntimeTests(unittest.TestCase):
    def test_startup_wait_covers_delayed_process_identity_and_readiness(self):
        expected = {'binary': 'fixed'}
        with patch.object(runtime, 'process', side_effect=[ValueError('old process'), expected, expected]) as process, patch.object(runtime, 'observations', side_effect=[ValueError('not ready'), None]) as ready, patch.object(runtime.time, 'sleep'):
            runtime.await_ready('api', 7, expected)
            self.assertEqual(process.call_count, 3)
            self.assertEqual(ready.call_count, 2)
            self.assertEqual(ready.call_args.args, ('api', 7))

    def test_startup_deadline_fails_with_fixed_safe_phase_code(self):
        with patch.object(runtime, 'process', side_effect=ValueError('sensitive raw dependency failure')), patch.object(runtime.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaisesRegex(runtime.Failure, '^startup_not_ready_worker$'):
                runtime.await_ready('worker', 7, {})

    def test_subprocess_output_error_and_timeout_are_bounded_sanitized(self):
        self.assertEqual(runtime.run([sys.executable, '-c', 'print("public")'], 'test_command'), b'public\n')
        for source in ['import sys;sys.stderr.write("private");sys.exit(1)', 'print("x"*10000)', 'import time;time.sleep(2)']:
            with self.assertRaisesRegex(runtime.Failure, '^test_command$'):
                runtime.run([sys.executable, '-c', source], 'test_command', timeout=0.1, maximum=100)

    def test_empty_stdin_closes_and_child_finishes(self):
        self.assertEqual(runtime.run([sys.executable, '-c', 'import sys;print(len(sys.stdin.buffer.read()))'], 'test_input', input_data=b''), b'0\n')



def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

host = load('multisource_host', 'apply-dashboard-multisource.py')
guest = load('multisource_guest', 'dashboard-multisource-guest.py')
fixtures = load('multisource_fixtures', 'test-dashboard-multisource.py')


def material_values():
    return {role: {name: base64.b64encode(('synthetic-' + name).encode()).decode() for name in guest.destination_names(role)} for role in ('api', 'worker', 'broker')}


def database_value():
    return {'hold': {'held': False, 'generation': 3, 'restoreRecordedThrough': None},
            'unfinishedRecoveries': 0, 'openGaps': 0, 'bindingCount': 2, 'bindingSHA256': 'a' * 64,
            'secondary': {'database': 'jobman_dashboard_control_secondary', 'instanceId': host.plan.SECONDARY_INSTANCE,
                          'epoch': '1', 'migration': '000021_monitoring_events.sql', 'freshNamespaceProofs': 2},
            'identities': [{'deploymentId': host.plan.PRIMARY, 'instanceId': host.plan.PRIMARY_INSTANCE, 'epoch': '1', 'revision': 6}],
            'feeds': [{'deploymentId': host.plan.PRIMARY, 'namespaces': ['primary-namespace'], 'status': 'active', 'generation': 4, 'lastPosition': 100, 'lastError': '', 'lastSuccessAt': '2026-10-04T00:00:00Z'}]}


class BoundaryTests(unittest.TestCase):
    def test_fixed_public_ledger_and_ca_require_root_0644(self):
        ledger = {'revision': guest.SOURCE_REVISION}
        with patch.object(guest.r, 'read', return_value=runtime.encoded(ledger)) as read:
            self.assertEqual(guest.public_source_ledger(), ledger)
            read.assert_called_once_with(Path('/usr/local/libexec/jobman-dashboard-lab/source-current.json'), 0, 0o644)
        before = {'broker': runtime.encoded({'clientTrustRootsFile': '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'})}
        with patch.object(guest.r, 'read', return_value=b'exact-public-ca\n') as read:
            self.assertEqual(guest.original_trust(before), b'exact-public-ca\n')
            read.assert_called_once_with(Path('/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'), 0, 0o644)
        for path in ('/etc/jobman-dashboard-broker-lab/private-ca.crt', '/etc/pki/ca-trust/source/anchors/other.crt'):
            with patch.object(guest.r, 'read') as read, self.assertRaisesRegex(guest.r.Failure, 'original_trust_path'):
                guest.original_trust({'broker': runtime.encoded({'clientTrustRootsFile': path})})
            read.assert_not_called()
        with patch.object(guest.r, 'read', side_effect=runtime.Failure('file_identity')):
            # Metadata validation failures stay fatal; no alternative mode retry.
            with self.assertRaises(ValueError): guest.public_source_ledger()
            with self.assertRaises(ValueError): guest.original_trust(before)

    def test_control_dispatch_checks_exact_public_ca_before_material_mutation(self):
        raw = b'exact-public-ca\n'
        before = {'broker': runtime.encoded({'clientTrustRootsFile': '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'})}
        payload = {'phase': 'materials', 'host': 'control01', 'apply': True, 'executionId': 'a'*64, 'reviewSHA256': 'b'*64, 'implementationSHA256': 'c'*64,
                   'baseline': {'control01': {'sources': {'unchanged': True}, 'originalTrustSHA256': runtime.sha(raw)}}}
        for content, accepted in ((raw, True), (b'changed-ca', False)):
            with patch.object(guest, 'input_value', return_value=(before, {})), patch.object(guest, 'directory'), patch.object(guest, 'retained'), patch.object(guest, 'lock', side_effect=lambda *a, **k: os.open(os.devnull, os.O_RDONLY)), patch.object(guest, 'source_snapshot', return_value={'unchanged': True}), patch.object(guest.r, 'read', return_value=content) as read, patch.object(guest, 'make_materials', return_value={'complete': True}) as mutation:
                if accepted: self.assertEqual(guest.execute(payload), {'complete': True})
                else:
                    with self.assertRaisesRegex(guest.r.Failure, 'original_trust_changed'): guest.execute(payload)
                read.assert_called_once_with(Path('/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'), 0, 0o644)
                self.assertEqual(mutation.call_count, 1 if accepted else 0)

    def test_database_snapshot_uses_existing_admin_and_fixed_read_only_databases(self):
        first = {'database': 'jobman_dashboard', 'bindingCount': 2, 'bindingSHA256': 'a'*64}
        second = {'database': 'jobman_dashboard_control_secondary'}
        with patch.object(guest.r, 'run', side_effect=[runtime.encoded(first), runtime.encoded(second)]) as run:
            self.assertEqual(guest.database_snapshot(), dict(first, secondary=second))
        self.assertEqual(run.call_count, 2)
        for call, database in zip(run.call_args_list, ('jobman_dashboard', 'jobman_dashboard_control_secondary')):
            self.assertEqual(call.args[0], ['podman', 'exec', '-i', '--user', 'postgres', 'jobman-postgres', 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'jobman_control', '-d', database])
            sql = call.kwargs['input_data'].decode()
            self.assertIn('READ ONLY;', sql); self.assertIn("SET statement_timeout='5s'", sql)
            self.assertEqual(call.kwargs['timeout'], 8)
            self.assertNotRegex(sql, r'(?i)\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP)\b')

    def test_only_intended_role_receives_private_materials_and_database_receives_none(self):
        original = {'materials': material_values()}
        for role in ('api', 'worker', 'broker'):
            output = host.phase_payload(original, runtime.SPECS[role][0], 'install', True, role=role)
            self.assertEqual(set(output['materials']), {role})
        self.assertNotIn('materials', host.phase_payload(original, 'pg01', 'database', False))
        self.assertEqual(set(original['materials']), {'api', 'worker', 'broker'})

    def test_no_ca_private_keys_or_other_material_names_can_be_installed(self):
        for extra in ('fixture-ca.key', '../control.env', 'database-url'):
            value = material_values(); value['api'][extra] = base64.b64encode(b'private').decode()
            with self.assertRaisesRegex(guest.r.Failure, 'material_allowlist'):
                guest.validate_materials(value)
        value = material_values(); value['broker']['secondary-api-client.crt'] = value['api']['secondary-broker-client.crt']; value['broker']['secondary-worker-client.crt'] = value['worker']['secondary-broker-client.crt']
        guest.validate_materials(value)
        guest.validate_materials({'api': value['api']}, ['api'])
        with self.assertRaisesRegex(guest.r.Failure, 'material_roles'):
            guest.validate_materials(value, ['api'])

    def test_manifest_binds_every_installed_byte(self):
        value = material_values(); hashes = {role: {name: runtime.sha(base64.b64decode(raw)) for name, raw in files.items()} for role, files in value.items()}
        p = {'executionId': 'a'*64, 'reviewSHA256': 'b'*64, 'materialHashes': hashes, 'materials': {'api': value['api']}}
        self.assertEqual(guest.identity(p)['materialHashes'], hashes)
        p['materials']['api']['secondary-control-client.key'] = base64.b64encode(b'changed').decode()
        with self.assertRaisesRegex(guest.r.Failure, 'material_manifest_changed'): guest.identity(p)

    def test_recovery_config_uses_worker_authority_and_privileged_dsn_only(self):
        before, fixture = fixtures.inputs(); after = fixtures.plan.patch(before, fixture)
        after['api']['observability'] = {'socketPath': '/runtime/socket'}
        raw = {key: runtime.encoded(value) for key, value in after.items()}
        recovery = json.loads(guest.recovery_config(raw))
        self.assertEqual(recovery['controls'], after['worker']['controls'])
        self.assertEqual(recovery['databaseURLFile'], '/etc/jobman-dashboard-app-lab/database-url')
        self.assertNotIn('observability', recovery)
        self.assertEqual(after['api']['databaseURLFile'], fixtures.plan.ROOTS['api'] + '/database-url')

    def test_database_before_and_after_require_continuous_primary_feed(self):
        before = database_value(); host.db_validate(before)
        after = copy.deepcopy(before)
        after['identities'][0]['revision'] = 7
        after['identities'].append({'deploymentId': host.plan.SECONDARY, 'instanceId': host.plan.SECONDARY_INSTANCE, 'epoch': '1', 'revision': 7})
        after['feeds'][0]['lastPosition'] = 103
        after['feeds'].append(dict(after['feeds'][0], deploymentId=host.plan.SECONDARY, namespaces=['secondary'], generation=2, lastPosition=0))
        host.db_validate(after, before=before)
        advancing = copy.deepcopy(after)
        advancing['feeds'][0].update(generation=8, lastPosition=104)
        host.db_validate(advancing, before=before)
        edits = [lambda x: x['hold'].update(held=True), lambda x: x['hold'].update(generation=4),
                 lambda x: x.update(bindingSHA256='b'*64), lambda x: x.update(openGaps=1),
                 lambda x: x['feeds'][0].update(generation=3), lambda x: x['feeds'][0].update(lastPosition=99),
                 lambda x: x['feeds'][0].update(namespaces=['changed']), lambda x: x['feeds'][1].update(status='paused'),
                 lambda x: x['identities'][1].update(instanceId=host.plan.PRIMARY_INSTANCE),
                 lambda x: x['secondary'].update(freshNamespaceProofs=1)]
        for edit in edits:
            with self.subTest(edit=edit):
                broken = copy.deepcopy(after); edit(broken)
                with self.assertRaises(host.r.Failure): host.db_validate(broken, before=before)

    def test_private_receipts_survive_restrictive_umask_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            old = os.umask(0o777)
            try:
                with host.locked(root): host.receipt(root / 'receipt.json', {'phase': 'public'})
            finally: os.umask(old)
            self.assertEqual((root / 'receipt.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / '.apply.lock').stat().st_mode & 0o777, 0o600)
            host.receipt(root / 'receipt.json', {'phase': 'public'})
            with self.assertRaises(host.r.Failure): host.receipt(root / 'receipt.json', {'phase': 'changed'})
            with host.locked(root):
                with self.assertRaises(BlockingIOError):
                    with host.locked(root): pass

    def test_host_inputs_reject_aliases_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700); host.write(root / 'private', b'content')
            os.link(root / 'private', root / 'hard')
            with self.assertRaises(host.r.Failure): host.read(root / 'private')
            alias = root / 'alias'; alias.symlink_to(root / 'private')
            with self.assertRaises(OSError): host.read(alias)

    def test_guest_rejects_nonadditive_configuration_even_with_recomputed_hash(self):
        values, fixture = fixtures.inputs(); after = fixtures.plan.patch(values, fixture)
        before = {key: runtime.encoded(value) for key, value in values.items()}; raw_after = {key: runtime.encoded(value) for key, value in after.items()}
        fixture_raw = runtime.encoded(fixture)
        def payload():
            review = {'synthetic': True, 'applies': False, 'fixtureSHA256': runtime.sha(fixture_raw), 'files': [{'role': key, 'path': fixtures.plan.ROOTS[key]+'/config.json', 'beforeSHA256': runtime.sha(before[key]), 'afterSHA256': runtime.sha(raw_after[key])} for key in before]}
            return {'host': 'storage01', 'phase': 'preflight', 'executionId': 'a'*64, 'review': review, 'reviewSHA256': runtime.sha(runtime.encoded(review)), 'before': {key:base64.b64encode(value).decode() for key,value in before.items()}, 'after': {key:base64.b64encode(value).decode() for key,value in raw_after.items()}, 'fixture': fixture, 'fixtureBytes': base64.b64encode(fixture_raw).decode()}
        with patch.object(guest.os, 'geteuid', return_value=0), patch.object(guest.sys, 'platform', 'linux'), patch.object(guest.os, 'uname', return_value=SimpleNamespace(nodename='storage01')):
            guest.input_value(payload())
            after['api']['controls'][0]['namespaceIds'].append('unexpected')
            raw_after['api'] = runtime.encoded(after['api'])
            with self.assertRaisesRegex(guest.r.Failure, 'additive_config_mismatch'): guest.input_value(payload())


class ContinuationTests(unittest.TestCase):
    def scenario(self, root):
        config_roots = {role: str(root / role) for role in ('api', 'worker', 'broker', 'operator')}
        for path in config_roots.values(): Path(path).mkdir(mode=0o700)
        operator = root / 'receipts'; operator.mkdir(mode=0o700); state = operator / guest.PRIOR_EXECUTION; state.mkdir(mode=0o700)
        before = {role: runtime.encoded({'original': role}) for role in config_roots}
        after = {role: runtime.encoded({'new': role, 'controls': []}) for role in config_roots}
        materials = material_values(); hashes = {role: {name: runtime.sha(base64.b64decode(raw)) for name, raw in files.items()} for role, files in materials.items()}
        expected = {role: {'binary': '/fixed/' + role} for role in ('api', 'worker')}
        starts = {role: {'pid': role + '-pid'} for role in expected}
        p = {'phase': 'continuation_check', 'host': 'storage01', 'executionId': guest.PRIOR_EXECUTION, 'reviewSHA256': 'b'*64, 'previousImplementationSHA256': guest.PRIOR_IMPLEMENTATION, 'implementationSHA256': 'f'*64, 'materialHashes': hashes,
             'baseline': {'storage01': {'roles': expected}}, 'continuationProcesses': {'storage01': starts}}
        value, old, new, old_binding, _ = guest.continuation_values(p, after)
        host.write(state / 'binding.json', old_binding)
        marker = guest.identity(dict(p, materials={}))
        for role in expected:
            path = Path(config_roots[role]); host.write(path / 'config.json', before[role]); host.write(path / ('.multisource-' + guest.PRIOR_EXECUTION + '.json'), after[role])
            host.write(state / (role + '-install.json'), runtime.encoded(marker))
            for name, raw in materials[role].items(): host.write(path / name, base64.b64decode(raw))
        host.write(Path(config_roots['operator']) / 'config.json', before['operator'])
        draft = Path(config_roots['operator']) / 'multisource-recovery.json'; host.write(draft, old)
        stack = ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch.object(guest, 'ROOT', operator)); stack.enter_context(patch.dict(guest.plan.ROOTS, config_roots))
        stack.enter_context(patch.object(guest, 'lock', side_effect=lambda *a, **kw: os.open(os.devnull, os.O_RDONLY)))
        stack.enter_context(patch.object(guest.r, 'private_directory'))
        stack.enter_context(patch.object(guest.r, 'read', side_effect=lambda path, *a, **kw: host.read(Path(path), kw.get('maximum', 2 << 20))))
        stack.enter_context(patch.object(guest.r, 'put', side_effect=lambda path, raw, *a, **kw: host.write(Path(path), raw)))
        stack.enter_context(patch.object(guest.r, 'process', side_effect=lambda role: expected[role]))
        stack.enter_context(patch.object(guest.r, 'observations'))
        stack.enter_context(patch.object(guest, 'service_start', side_effect=lambda unit, *a: starts['api' if unit.endswith('-api') else 'worker']))
        command = stack.enter_context(patch.object(guest.r, 'run', return_value=b''))
        return p, before, after, state, draft, old, new, value, command

    def test_exact_inactive_draft_continuation_and_replay_preserve_runtime_and_materials(self):
        with tempfile.TemporaryDirectory() as directory:
            p, before, after, state, draft, old, new, value, command = self.scenario(Path(directory).resolve())
            original = {str(path): path.read_bytes() for path in draft.parent.parent.rglob('*') if path.is_file()}
            result = guest.continue_install(p, before, after)
            self.assertFalse(result['complete']); self.assertEqual(draft.read_bytes(), old); command.assert_not_called()
            p.update(phase='continuation_apply', apply=True)
            original_cas = guest.continuation_cas
            with patch.object(guest, 'continuation_cas', wraps=original_cas) as cas:
                self.assertTrue(guest.continue_install(p, before, after)['complete'])
                for call in cas.call_args_list: self.assertEqual(call.args[0].parent, call.args[4].parent)
            self.assertTrue(guest.continue_install(p, before, after)['complete'])
            self.assertEqual(draft.read_bytes(), new); self.assertEqual((state / 'recovery-before-continuation.json').read_bytes(), old)
            self.assertEqual(json.loads((state / 'continuation.complete.json').read_bytes()), value)
            for path, raw in original.items():
                if path in (str(draft), str(state / 'binding.json')): continue
                self.assertEqual(Path(path).read_bytes(), raw)
            self.assertEqual(command.call_args.args[0][1:5], ['--mode', 'check-config', '--check-mode', 'api'])
            self.assertTrue(all('systemctl' not in call.args[0] for call in command.call_args_list))

    def test_pending_continuation_can_finish_after_draft_cas_without_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            p, before, after, state, draft, old, new, value, command = self.scenario(Path(directory).resolve())
            p.update(phase='continuation_apply', apply=True); command.side_effect = [guest.r.Failure('validation_interrupted'), b'']
            with self.assertRaises(guest.r.Failure): guest.continue_install(p, before, after)
            self.assertEqual(draft.read_bytes(), new); self.assertTrue((state / 'continuation.pending.json').exists()); self.assertFalse((state / 'continuation.complete.json').exists())
            self.assertTrue(guest.continue_install(p, before, after)['complete'])
            self.assertEqual((state / 'recovery-before-continuation.json').read_bytes(), old)

    def test_changed_draft_binding_install_or_started_swap_refuses_before_write(self):
        for kind in ('draft', 'binding', 'install', 'swap', 'process', 'active'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                p, before, after, state, draft, old, new, value, command = self.scenario(Path(directory).resolve())
                p.update(phase='continuation_apply', apply=True)
                if kind == 'draft': draft.write_bytes(b'changed-private-draft')
                elif kind == 'binding': (state / 'binding.json').write_bytes(b'changed')
                elif kind == 'install': (state / 'api-install.json').write_bytes(b'{}')
                elif kind == 'swap': host.write(state / 'api-apply.pending.json', b'{}')
                elif kind == 'active': (draft.parent.parent / 'api/config.json').write_bytes(b'changed-active')
                else: p['continuationProcesses']['storage01']['api'] = {'pid': 'restarted'}
                if kind == 'process':
                    # Keep the actual observed start independent of the desired map.
                    with patch.object(guest, 'service_start', side_effect=lambda unit, *a: {'pid': 'api-pid' if unit.endswith('-api') else 'worker-pid'}):
                        with self.assertRaises(ValueError): guest.continue_install(p, before, after)
                else:
                    with self.assertRaises(ValueError): guest.continue_install(p, before, after)
                command.assert_not_called(); self.assertFalse((state / 'continuation.pending.json').exists())
                # Close this iteration's scoped monkeypatches before the next fixture.
                self.doCleanups()

    def test_continuation_identity_only_accepts_fixed_predecessor_and_changes_one_draft_field(self):
        values, fixture = fixtures.inputs(); after = fixtures.plan.patch(values, fixture)
        p = {'previousImplementationSHA256': host.PRIOR_IMPLEMENTATION, 'executionId': host.PRIOR_EXECUTION, 'reviewSHA256': 'b'*64, 'implementationSHA256': 'f'*64, 'after': {role: base64.b64encode(runtime.encoded(value)).decode() for role, value in after.items()}}
        identity = host.continuation_identity(p)
        value, old, new, _, _ = guest.continuation_values(p, {role:runtime.encoded(value) for role,value in after.items()})
        self.assertEqual(identity, value)
        old_json, new_json = json.loads(old), json.loads(new)
        self.assertEqual(old_json.pop('databaseURLFile'), '/etc/jobman-dashboard-lab/database-url')
        self.assertEqual(new_json.pop('databaseURLFile'), '/etc/jobman-dashboard-app-lab/database-url')
        self.assertEqual(old_json, new_json)
        p['previousImplementationSHA256'] = '0'*64
        with self.assertRaises(ValueError): host.continuation_identity(p)
        with self.assertRaises(ValueError): guest.continuation_values(p, {})


class ReceiptStateTests(unittest.TestCase):
    def test_interrupted_install_fails_without_writing_again(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); role_root = root / 'api'; role_root.mkdir(); receipts = root / 'receipts'; receipts.mkdir()
            before = {'api': b'before'}; after = {'api': b'after'}
            (role_root / 'config.json').write_bytes(before['api']); (receipts / 'api-install.pending.json').write_bytes(b'{}')
            materials = material_values(); hashes = {role: {name: runtime.sha(base64.b64decode(raw)) for name,raw in files.items()} for role,files in materials.items()}
            p = {'phase': 'install', 'host': 'storage01', 'executionId': 'a'*64, 'reviewSHA256': 'b'*64, 'materials': {'api': materials['api']}, 'materialHashes': hashes, 'baseline': {'storage01': {'roles': {'api': {'binary': 'unused'}}}}}
            with patch.dict(guest.plan.ROOTS, {'api': str(role_root)}), patch.object(guest.r, 'process', return_value={'binary': 'unused'}), patch.object(guest.r, 'read', side_effect=lambda path,*args,**kw: path.read_bytes()), patch.object(guest.r, 'put') as write:
                with self.assertRaisesRegex(guest.r.Failure, 'uncertain_material_installation'): guest.role_phase(p, 'api', receipts, before, after)
                write.assert_not_called()

    def test_completed_material_install_rechecks_all_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); role_root = root / 'api'; role_root.mkdir(); receipts = root / 'receipts'; receipts.mkdir()
            before = {'api': b'before'}; after = {'api': b'after'}
            (role_root / 'config.json').write_bytes(before['api'])
            materials = material_values(); hashes = {role: {name: runtime.sha(base64.b64decode(raw)) for name,raw in files.items()} for role,files in materials.items()}
            p = {'phase': 'install', 'host': 'storage01', 'executionId': 'a'*64, 'reviewSHA256': 'b'*64, 'materials': {'api': materials['api']}, 'materialHashes': hashes, 'baseline': {'storage01': {'roles': {'api': {'binary': 'unused'}}}}}
            for name,raw in materials['api'].items(): (role_root/name).write_bytes(base64.b64decode(raw))
            (role_root / ('.multisource-'+p['executionId']+'.json')).write_bytes(after['api'])
            (receipts/'api-install.json').write_bytes(runtime.encoded(guest.identity(p)))
            with patch.dict(guest.plan.ROOTS, {'api': str(role_root)}), patch.object(guest.r, 'process', return_value={'binary': 'unused'}), patch.object(guest.r, 'read', side_effect=lambda path,*args,**kw: path.read_bytes()), patch.object(guest.r, 'put') as write:
                self.assertTrue(guest.role_phase(p, 'api', receipts, before, after)['complete']); write.assert_not_called()
                (role_root/'secondary-control-client.key').write_bytes(b'drift')
                with self.assertRaisesRegex(guest.r.Failure, 'installed_material_changed'): guest.role_phase(p, 'api', receipts, before, after)


    def test_cas_lost_response_finishes_only_receipt_bound_new_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); role_root = root / 'api'; role_root.mkdir(); receipts = root / 'receipts'; receipts.mkdir()
            before = {'api': b'before'}; after = {'api': b'after'}; config = role_root / 'config.json'; config.write_bytes(before['api'])
            materials = material_values(); hashes = {role: {name: runtime.sha(base64.b64decode(raw)) for name,raw in files.items()} for role,files in materials.items()}
            p = {'phase': 'apply', 'host': 'storage01', 'executionId': 'a'*64, 'reviewSHA256': 'b'*64, 'materials': {'api': materials['api']}, 'materialHashes': hashes, 'baseline': {'storage01': {'roles': {'api': {'binary': 'unused'}}}}}
            for name,raw in materials['api'].items(): (role_root/name).write_bytes(base64.b64decode(raw))
            (role_root / ('.multisource-'+p['executionId']+'.json')).write_bytes(after['api'])
            (receipts/'api-install.json').write_bytes(runtime.encoded(guest.identity(p)))
            def lost(path, previous, desired, uid, backup, execution):
                backup.write_bytes(previous); path.write_bytes(desired); raise OSError('lost response after rename')
            def put(path, raw, uid=0):
                with path.open('xb') as stream: stream.write(raw)
            with patch.dict(guest.plan.ROOTS, {'api': str(role_root)}), patch.object(guest.r, 'process', return_value={'binary': 'unused'}), patch.object(guest.r, 'read', side_effect=lambda path,*args,**kw: path.read_bytes()), patch.object(guest.r, 'put', side_effect=put), patch.object(guest.r, 'atomic_config', side_effect=lost) as swap:
                with self.assertRaises(OSError): guest.role_phase(p, 'api', receipts, before, after)
                self.assertEqual(config.read_bytes(), b'after')
                self.assertTrue(guest.role_phase(p, 'api', receipts, before, after)['complete'])
                self.assertEqual(swap.call_count, 1)
                self.assertTrue((receipts/'api-apply.json').exists())
                (receipts/'api-apply.json').unlink(); (receipts/'api-apply.pending.json').write_bytes(b'{}')
                with self.assertRaisesRegex(guest.r.Failure, 'uncertain_swap_identity'): guest.role_phase(p, 'api', receipts, before, after)

    def test_lost_restart_response_checks_new_ready_process_without_second_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); role_root = root / 'api'; role_root.mkdir(); receipts = root / 'receipts'; receipts.mkdir()
            binary = root / 'binary'; binary.write_bytes(b'binary'); before = {'api': b'before'}; after = {'api': b'after'}
            (role_root/'config.json').write_bytes(b'after')
            expected = {'binary': str(binary), 'binarySHA256': runtime.sha(b'binary'), 'unit': 'fixed-unit', 'unitSHA256': runtime.sha(b'unit')}
            materials = material_values(); hashes = {role: {name: runtime.sha(base64.b64decode(raw)) for name,raw in files.items()} for role,files in materials.items()}
            p = {'phase': 'restart', 'host': 'storage01', 'executionId': 'a'*64, 'reviewSHA256': 'b'*64, 'materials': {'api': materials['api']}, 'materialHashes': hashes, 'baseline': {'storage01': {'roles': {'api': expected}}}}
            for name,raw in materials['api'].items(): (role_root/name).write_bytes(base64.b64decode(raw))
            value = guest.identity(p)
            for name in ('api-install.json', 'api-apply.json'): (receipts/name).write_bytes(runtime.encoded(value))
            (receipts/'api-restart.pending.json').write_bytes(runtime.encoded({'identity': value, 'before': {'MainPID': '1'}}))
            def read(path,*args,**kw): return b'unit' if str(path).startswith('/etc/systemd/system/') else path.read_bytes()
            with patch.dict(guest.plan.ROOTS, {'api': str(role_root)}), patch.object(guest.r, 'read', side_effect=read), patch.object(guest.r, 'put', side_effect=lambda path,raw: path.write_bytes(raw)), patch.object(guest.r, 'run') as run, patch.object(guest, 'service_start', return_value={'MainPID': '2'}), patch.object(guest.r, 'await_ready') as ready, patch.object(guest, 'check_config'):
                self.assertTrue(guest.role_phase(p, 'api', receipts, before, after)['complete'])
                run.assert_not_called(); self.assertGreaterEqual(ready.call_count, 1)
                (receipts/'api-restart.json').unlink()
                with patch.object(guest, 'service_start', return_value={'MainPID': '1'}):
                    with self.assertRaisesRegex(guest.r.Failure, 'uncertain_restart_no_new_process'): guest.role_phase(p, 'api', receipts, before, after)
                run.assert_not_called()


if __name__ == '__main__': unittest.main()
