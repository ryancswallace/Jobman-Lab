#!/usr/bin/env python3
"""Offline second-source apply tests: mocked guest boundaries, no Lab credentials."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


inputs = module('secondary_apply_test_inputs', 'test-dashboard-second-source.py')
driver = module('secondary_apply_driver', 'apply-dashboard-second-source.py')
guest = module('secondary_apply_guest', 'dashboard-second-source-guest.py')
continuation = module('secondary_continuation', 'continue-dashboard-second-source.py')


def payload():
    plan = inputs.plan.make_plan(*inputs.inputs())
    value = {'plan': plan, 'planSHA256': guest.sha(guest.encoded(plan)),
             'helperBuild': {'revision': 'a' * 40, 'sha256': 'b' * 64, 'platform': 'linux/arm64', 'toolchain': 'go1.26.6'},
             'implementationSHA256': {name: 'c' * 64 for name in driver.IMPLEMENTATIONS}}
    value['executionId'] = guest.verify_plan(value)
    return value


class SecondaryApplyTests(unittest.TestCase):

    def test_fixed_user_names_fit_linux_limit_and_reject_old_names(self):
        value = payload()
        for kind in ('controlUser', 'directoryUser'):
            self.assertRegex(value['plan']['secondary'][kind]['name'], r'^[a-z][a-z0-9-]{0,31}$')
        value['plan']['secondary']['controlUser']['name'] = 'jobman-dashboard-source-secondary'
        value['planSHA256'] = guest.sha(guest.encoded(value['plan']))
        with self.assertRaisesRegex(ValueError, 'Fixed secondary'):
            guest.verify_plan(value)

    def test_continuation_identity_binds_prior_and_forbids_database_recreation(self):
        value = payload()
        old_id = value['executionId']
        value['continuation'] = {'priorExecutionId': continuation.PRIOR_EXECUTION,
                                 'priorPlanSHA256': continuation.PRIOR_PLAN_SHA256}
        value['executionId'] = guest.verify_plan(value)
        self.assertNotEqual(old_id, value['executionId'])
        value.update(phase='database', host='pg01', apply=True)
        with patch.object(guest.os, 'geteuid', return_value=0), patch.object(guest.sys, 'platform', 'linux'), patch.object(guest.socket, 'gethostname', return_value='pg01'), patch.object(guest, 'database_phase') as mutation:
            with self.assertRaisesRegex(ValueError, 'cannot recreate'):
                guest.dispatch(value)
            mutation.assert_not_called()
        value['continuation']['priorExecutionId'] = '1' * 64
        with self.assertRaisesRegex(ValueError, 'Unrecognized'):
            guest.verify_plan(value)

    def test_continuation_guest_requires_exact_pending_zero_effects_and_preserves_it(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name).resolve()
            root = base / continuation.PRIOR_EXECUTION
            root.mkdir()
            pending = {'executionId': continuation.PRIOR_EXECUTION, 'phase': 'prepare', 'startedAt': 123}
            (root / 'prepare.pending.json').write_bytes(guest.encoded(pending))
            original = (root / 'prepare.pending.json').read_bytes()
            value = {'continuation': {'priorExecutionId': continuation.PRIOR_EXECUTION,
                     'priorPreflight': {'control01': {'snapshot': {'original': 'unchanged'}}}}}
            with patch.object(guest, 'RECEIPTS', base), patch.object(guest, 'private_directory'), patch.object(guest, 'source_snapshot', return_value={'original': 'unchanged'}), patch.object(guest, 'unused_control') as unused, patch.object(guest, 'read', side_effect=lambda path, *a, **k: path.read_bytes()), patch.object(guest.pwd, 'getpwnam', side_effect=KeyError), patch.object(guest.grp, 'getgrnam', side_effect=KeyError), patch.object(guest, 'begin') as begin, patch.object(guest, 'run') as run:
                self.assertFalse(guest.continuation_preflight(value, 'control01')['mutatedGuests'])
                unused.assert_called_once()
                begin.assert_not_called(); run.assert_not_called()
                self.assertEqual((root / 'prepare.pending.json').read_bytes(), original)
                with patch.object(guest, 'unused_control', side_effect=ValueError('partial effect')):
                    with self.assertRaisesRegex(ValueError, 'partial effect'):
                        guest.continuation_preflight(value, 'control01')
                (root / 'prepare.json').write_bytes(b'{}')
                with self.assertRaisesRegex(ValueError, 'progressed'):
                    guest.continuation_preflight(value, 'control01')

    def test_continuation_database_requires_matching_hba_and_empty_schema(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name).resolve(); root = base / continuation.PRIOR_EXECUTION; root.mkdir()
            database = {'database': guest.DB, 'hbaSHA256': 'a' * 64, 'originalsPreserved': True}
            (root / 'database.json').write_bytes(guest.encoded(database))
            snapshot = {'primaryInstance': guest.PRIMARY_INSTANCE, 'primaryMigration': guest.MIGRATION, 'hbaSHA256': 'a' * 64}
            value = {'continuation': {'priorExecutionId': continuation.PRIOR_EXECUTION, 'priorDatabase': database,
                     'priorPreflight': {'pg01': {'snapshot': dict(snapshot, hbaSHA256='b' * 64)}}}}
            with patch.object(guest, 'RECEIPTS', base), patch.object(guest, 'private_directory'), patch.object(guest, 'database_snapshot', return_value=snapshot), patch.object(guest, 'read', side_effect=lambda path, *a, **k: path.read_bytes()), patch.object(guest, 'sql', side_effect=[guest.DB, '0']) as sql, patch.object(guest, 'begin') as begin:
                self.assertFalse(guest.continuation_preflight(value, 'pg01')['mutatedGuests'])
                self.assertTrue(all(call.args[0].startswith('SELECT') for call in sql.call_args_list))
                begin.assert_not_called()
                # A function-only change has no pg_class row. Require its
                # namespace catalog to be queried before reporting this drift.
                def function_only(query, database='postgres'):
                    if database == guest.DB:
                        self.assertIn('FROM pg_proc', query)
                        self.assertIn('FROM pg_type', query)
                        self.assertIn('FROM pg_namespace WHERE', query)
                        self.assertIn('FROM pg_extension', query)
                        return '1'
                    return guest.DB
                with patch.object(guest, 'sql', side_effect=function_only):
                    with self.assertRaisesRegex(ValueError, 'no longer fresh'):
                        guest.continuation_preflight(value, 'pg01')
                with patch.object(guest, 'database_snapshot', return_value=dict(snapshot, hbaSHA256='c' * 64)):
                    with self.assertRaisesRegex(ValueError, 'receipt changed'):
                        guest.continuation_preflight(value, 'pg01')

    def test_continuation_host_carries_completed_database_but_never_mutates_guest(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve(); old = root / 'old'; new = root / 'new'
            old.mkdir(mode=0o700); new.mkdir(mode=0o700)
            record = {'priorExecutionId': continuation.PRIOR_EXECUTION, 'priorDatabase': {'database': guest.DB}}
            args = argparse.Namespace(prior_staging=old, staging=new, lab_root=root)
            value = {'executionId': 'f' * 64}
            with patch.object(continuation, 'prior_record', return_value=record), patch.object(continuation.driver, 'verify_stage', return_value=(value, b'')), patch.object(continuation.driver, 'password', return_value='e' * 64) as password, patch.object(continuation.driver, 'verify_database') as verify, patch.object(continuation.driver, 'remote', return_value={'epoch': int(driver.time.time()), 'snapshot': {}, 'mutatedGuests': False}) as remote:
                result = continuation.prepare(args)
                self.assertFalse(result['guestMutations'])
                self.assertEqual([call.args[1]['phase'] for call in remote.call_args_list], ['continuation_preflight'] * 2)
                password.assert_called_once_with(root)
                verify.assert_called_once_with('e' * 64, root)
                self.assertEqual(json.loads((new / 'continuation.json').read_text()), record)
                self.assertEqual(json.loads((new / ('apply-' + 'f' * 64) / 'database.json').read_text()), record['priorDatabase'])
                with self.assertRaisesRegex(ValueError, 'already recorded'):
                    continuation.prepare(args)
                self.assertEqual(remote.call_count, 2)

    def test_private_records_and_exclusive_lock_with_restrictive_umask(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            root.chmod(0o700)
            prior = os.umask(0o777)
            try:
                driver.write_new(root / 'receipt.json', b'{}')
                self.assertEqual((root / 'receipt.json').stat().st_mode & 0o777, 0o600)
                with driver.receipt_lock(root):
                    self.assertEqual((root / '.secondary-apply.lock').stat().st_mode & 0o777, 0o600)
                    with self.assertRaisesRegex(ValueError, 'Another phase'):
                        with driver.receipt_lock(root):
                            self.fail('Concurrent phase lock succeeded')
                with driver.receipt_lock(root):
                    pass
            finally:
                os.umask(prior)

    def test_database_transport_uses_fixed_role_verified_tls_and_private_stdin(self):
        secret = 'e' * 64
        with patch.object(driver, 'ssh_arguments', return_value=['ssh', 'pinned-pg01']), patch.object(driver.subprocess, 'run') as run:
            driver.probe_database('SELECT 1;', secret, guest.DB, 'verify-full', Path('/synthetic-lab'))
            arguments = run.call_args.args[0]
            self.assertNotIn(secret, repr(arguments))
            self.assertIn('PGSSLMODE=verify-full', arguments[-1])
            self.assertIn('PGSSLROOTCERT=/var/lib/postgresql/data/dashboard-tls/ca.crt', arguments[-1])
            self.assertIn('-U ' + guest.DB, arguments[-1])
            self.assertEqual(run.call_args.kwargs['input'], (secret + '\nSELECT 1;\n').encode())
            with self.assertRaises(ValueError):
                driver.probe_database('SELECT 1;', secret, 'unlisted-database', 'verify-full', Path('/synthetic-lab'))
            self.assertEqual(run.call_count, 1)

    def test_archived_driver_reads_explicit_lab_root_and_binds_all_dependencies(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            archive, lab, staging, helper = (root / x for x in ('archive', 'lab', 'stage', 'helper'))
            for path in (archive, lab, staging, helper):
                path.mkdir(mode=0o700)
            for filename in driver.IMPLEMENTATIONS:
                (archive / filename).write_bytes((HERE / filename).read_bytes())
            spec = importlib.util.spec_from_file_location('secondary_archived', archive / 'apply-dashboard-second-source.py')
            archived = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(archived)
            primary, oidc, build = inputs.inputs()
            state = lab / '.lab/dashboard'
            state.mkdir(parents=True)
            (state / 'fixture-info.json').write_bytes(guest.encoded(primary))
            (state / 'oidc-public.json').write_bytes(guest.encoded(oidc))
            planned = inputs.plan.make_plan(primary, oidc, build)
            raw = guest.encoded(planned)
            driver.write_new(staging / 'plan.json', raw)
            binary = b'\x7fELF\x02\x01' + b'\x00' * 12 + b'\xb7\x00' + b'\x00' * 8
            (helper / 'jobman-control-lab-helper').write_bytes(binary)
            (helper / 'build.json').write_bytes(guest.encoded({'revision': 'a' * 40, 'platform': 'linux/arm64',
                'toolchain': 'go1.26.6', 'sha256': {'jobman-control-lab-helper': guest.sha(binary)}}))
            args = argparse.Namespace(lab_root=lab, staging=staging, expected_plan_sha256=guest.sha(raw),
                                      control_build=root / 'source', helper_build=helper, helper_revision='a' * 40)
            with patch.object(archived.plan, 'validate_build', return_value=build):
                value, returned = archived.verify_stage(args)
            self.assertEqual(returned, binary)
            self.assertEqual(set(value['implementationSHA256']), set(driver.IMPLEMENTATIONS))
            self.assertEqual(value['implementationSHA256']['dashboard-second-source-plan.py'],
                             guest.sha((archive / 'dashboard-second-source-plan.py').read_bytes()))
            self.assertFalse((root / '.lab').exists())

    def test_fixed_guest_boundary_rejects_source_or_role_repurpose(self):
        for key, replacement in [('database', 'jobman_control'), ('controlRoot', '/etc/jobman-dashboard-lab/control-fixture'),
                                 ('endpoint', 'https://10.77.0.21:18443')]:
            value = payload()
            value['plan']['secondary'][key] = replacement
            value['planSHA256'] = guest.sha(guest.encoded(value['plan']))
            with self.assertRaisesRegex(ValueError, 'Fixed secondary'):
                guest.verify_plan(value)
        value = payload()
        value['helperBuild']['platform'] = 'linux/amd64'
        with self.assertRaises(ValueError):
            guest.verify_plan(value)
        value = payload()
        value['implementationSHA256']['other-driver.py'] = 'c' * 64
        with self.assertRaises(ValueError):
            guest.verify_plan(value)
        with self.assertRaises(ValueError):
            guest.decode(b'{"phase":"verify","phase":"start"}')

    def test_database_sql_and_hba_are_additive_and_one_role_only(self):
        sql = guest.database_sql('a' * 64)
        self.assertEqual(sql.count('CREATE ROLE '), 1)
        self.assertEqual(sql.count('CREATE DATABASE '), 1)
        self.assertNotIn('DROP ', sql)
        self.assertNotIn('ALTER ROLE ', sql)
        self.assertIn('NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', sql)
        self.assertIn('REVOKE ALL ON DATABASE ' + guest.DB + ' FROM PUBLIC', sql)
        for value in ("' OR 1=1", '', 'A' * 64):
            with self.assertRaises(ValueError):
                guest.database_sql(value)
        hba = guest.hba_block().decode()
        self.assertNotIn('trust', hba)
        self.assertIn('hostnossl all ' + guest.DB, hba)
        self.assertIn('hostssl ' + guest.DB + ' ' + guest.DB + ' 10.77.0.0/24 scram-sha-256', hba)
        self.assertIn('local all ' + guest.DB + ' reject', hba)
        original = b'# old Control rules\nhost all jobman_control 10.77.0.0/24 scram-sha-256\n'
        self.assertTrue((guest.hba_block() + original).endswith(original))

    def test_units_have_separate_users_and_only_new_source_paths(self):
        source, ldap = guest.unit().decode(), guest.unit(True).decode()
        self.assertIn('User=jobman-dashboard-source2', source)
        self.assertIn('User=jobman-dashboard-directory2', ldap)
        self.assertIn('--profile secondary-v1 --root /etc/jobman-dashboard-secondary/directory', ldap)
        self.assertNotIn('EnvironmentFile=', ldap)
        for value in (source, ldap):
            self.assertIn('ProtectSystem=strict', value)
            self.assertIn('NoNewPrivileges=true', value)
            self.assertNotIn('/etc/jobman-dashboard-lab/control-fixture', value)
            self.assertNotIn('ReadWritePaths=', value)

    def test_pending_receipt_never_automatically_retries(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name).resolve() / 'operator'
            value = payload()
            with patch.object(guest, 'RECEIPTS', base), patch.object(guest, 'private_directory'):
                root, completed = guest.begin(value, 'prepare')
                self.assertIsNone(completed)
                before = (root / 'prepare.pending.json').read_bytes()
                with self.assertRaisesRegex(ValueError, 'Incomplete phase'):
                    guest.begin(value, 'prepare')
                self.assertEqual((root / 'prepare.pending.json').read_bytes(), before)
                result = {'fixture': 'synthetic'}
                guest.finish(root, 'prepare', result)
                with patch.object(guest, 'read', side_effect=lambda path, *args, **kwargs: path.read_bytes()):
                    self.assertEqual(guest.begin(value, 'prepare')[1], result)
                self.assertEqual((root / 'prepare.json').stat().st_mode & 0o777, 0o600)
                self.assertFalse((root / 'prepare.pending.json').exists())
                with self.assertRaises(FileExistsError):
                    guest.put(root / 'prepare.json', b'overwrite')

    def test_mutation_requires_flag_before_files_credentials_or_network(self):
        for phase in ('database', 'prepare', 'start'):
            args = argparse.Namespace(phase=phase, apply=False)
            with patch.object(driver, 'verify_stage') as staged, patch.object(driver, 'password') as credential, patch.object(driver, 'remote') as remote:
                with self.assertRaisesRegex(ValueError, 'explicit --apply'):
                    driver.execute(args)
                staged.assert_not_called()
                credential.assert_not_called()
                remote.assert_not_called()

    def test_bad_executable_fails_before_any_guest_mutation(self):
        value = payload()
        value['password'] = 'f' * 64
        value['binaries'] = {'jobman-control': 'bm90IGEgYmluYXJ5'}
        with patch.object(guest, 'run') as command, patch.object(guest, 'begin') as receipt:
            with self.assertRaisesRegex(ValueError, 'Staged executable'):
                guest.prepare_phase(value)
            command.assert_not_called()
            receipt.assert_not_called()

    def test_verify_never_substitutes_a_start_or_sets_apply(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            root.chmod(0o700)
            value = payload()
            receipts = root / ('apply-' + value['executionId'])
            receipts.mkdir(mode=0o700)
            for filename, document in [('preflight.json', {'pg01': {'epoch': 1}, 'control01': {'epoch': 1}}),
                                       ('prepare.json', {'fixture': {'instanceId': 'synthetic'}}), ('start.json', {'complete': True})]:
                driver.write_new(receipts / filename, guest.encoded(document))
            args = argparse.Namespace(staging=root, phase='verify', apply=False)
            with patch.object(driver, 'verify_stage', return_value=(value, b'')), patch.object(driver, 'password', return_value='a' * 64), patch.object(driver, 'verify_database', return_value={'tlsVerified': True}), patch.object(driver, 'remote', return_value={}) as remote:
                result = driver.execute(args)
                self.assertFalse(result['dashboardRegistered'])
                self.assertEqual(remote.call_count, 1)
                self.assertEqual(remote.call_args.args[0], 'control01')
                sent = remote.call_args.args[1]
                self.assertEqual(sent['phase'], 'verify')
                self.assertFalse(sent['apply'])
                self.assertNotIn('password', sent)

    def test_guest_verify_is_read_only_even_when_receipt_missing(self):
        value = dict(payload(), phase='verify', host='control01', apply=False)
        with patch.object(guest.os, 'geteuid', return_value=0), patch.object(guest.sys, 'platform', 'linux'), patch.object(guest.socket, 'gethostname', return_value='control01'), patch.object(guest, 'verify_phase', side_effect=FileNotFoundError), patch.object(guest, 'begin') as begin, patch.object(guest, 'run') as command:
            with self.assertRaises(FileNotFoundError):
                guest.dispatch(value)
            begin.assert_not_called()
            command.assert_not_called()

    def test_public_fixture_cannot_reuse_primary_instance_or_alias(self):
        value = payload()['plan']
        fixture = {'synthetic': True, 'profile': 'secondary-v1', 'instanceId': '60000000-0000-4000-8000-000000000001',
                   'endpoint': value['secondary']['endpoint'], 'issuer': value['secondary']['issuer'],
                   'delegationAudience': value['secondary']['delegationAudience'],
                   'namespaces': [{'id': f'40000000-0000-4000-8000-{i:012d}', 'name': ns,
                                   'targetGenerationId': f'50000000-0000-4000-8000-{i:012d}'}
                                  for i, ns in enumerate(('dashboard-research', 'dashboard-operations'), 1)],
                   'identities': [dict(user, principalId=f'61000000-0000-4000-8000-{i:012d}', issuer=value['secondary']['issuer'])
                                  for i, user in enumerate(value['secondary']['users'], 1)]}
        guest.public_fixture(fixture, value)
        bad = copy.deepcopy(fixture)
        bad['instanceId'] = guest.PRIMARY_INSTANCE
        with self.assertRaises(ValueError):
            guest.public_fixture(bad, value)
        bad = copy.deepcopy(fixture)
        bad['identities'][0]['subject'] = bad['identities'][1]['subject']
        with self.assertRaises(ValueError):
            guest.public_fixture(bad, value)


if __name__ == '__main__':
    unittest.main()
