#!/usr/bin/env python3
"""Offline candidate-upgrade checks; no Lab credentials, guests, or providers."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

p = load('dashboard-candidate-plan'); g = load('dashboard-candidate-guest'); h = load('upgrade-dashboard-candidate')


def b64(raw): return base64.b64encode(raw).decode()


# Captured independently using Go embed.FS + fs.Glob("migrations/*.sql")
# over exact Dashboard42d153b committed files (same construction as postgres.go).
COMMITTED_LEDGER = [{'name': 'migrations/000001_foundation.sql',
  'sha256': 'f2e3626fa5e41266ce18837cbd03d0ff03e115687f96283d13a45d9df6a8c0cf'},
 {'name': 'migrations/000002_cursor_quotas.sql',
  'sha256': '44e1be4b9b1315f95be786326aaca3670313ac929d48a81b78cd64f240bcaf92'},
 {'name': 'migrations/000003_authentication.sql',
  'sha256': '4613b1c269ebe5fdfb968cd76a41888688c9efcb1bd233cac4b77fc265a68de2'},
 {'name': 'migrations/000004_authentication_indexes.sql',
  'sha256': 'a6b0f659afba142b79efa0b911c8ee0fc0ba74078b86f0b70fd27094347fd752'},
 {'name': 'migrations/000005_report_queue.sql',
  'sha256': '9b69f89ec1d777bd06b5c51e01577c146c641141b77c608e4d51974dc0800f0f'},
 {'name': 'migrations/000006_event_ingestion.sql',
  'sha256': '936ee057fb7f72e0cf8be4de9e146a302d971714f40dc6b082541b672ae661e0'},
 {'name': 'migrations/000007_notification_rules.sql',
  'sha256': 'e3dd24535e1cf2442846f540011e88a5c9f9696c32ef6446b01597bfa53ea33d'},
 {'name': 'migrations/000008_event_recovery.sql',
  'sha256': '6d2af41f21d2b8f02b036e84263d916655ce4e01213cf1167f6dfb86eb822d71'},
 {'name': 'migrations/000009_notification_scope_revocations.sql',
  'sha256': 'cda4d43726a207496aed98eefae74a18f5c5249d419385a466dd317bda6d6339'},
 {'name': 'migrations/000010_notification_devices.sql',
  'sha256': 'c103b016074b231a7f55ef99fa9b1ae83b1f1ca793ff7461564b967bcb8c50a8'},
 {'name': 'migrations/000011_notification_delivery_hold.sql',
  'sha256': 'ad666ac1588a15df850054ecde95b91fd4319a123caacf9e262d52658f924563'},
 {'name': 'migrations/000012_notification_evaluation.sql',
  'sha256': '601a63494e803943bb94a53c14630f295d66312cb33025dd4896ca70a818929f'},
 {'name': 'migrations/000013_notification_device_revocations.sql',
  'sha256': 'f7c360024cd85c221cbba7ea69b54d886e3a3d1b5c11ca6a085be101aae3bbb7'},
 {'name': 'migrations/000014_notification_delivery.sql',
  'sha256': '3a0defb7bb50423d00dbf562e84defd43afea85f0967edb38d0967f10e76a221'},
 {'name': 'migrations/000015_notification_inbox.sql',
  'sha256': 'da22b7ec8e5ed285fedade948e0c72acbd7454a17fb2227bbfefb6a342865b75'},
 {'name': 'migrations/000016_notification_activation_work.sql',
  'sha256': 'eb4dff200b1dfc0bb41b7948cf26803406df4638003d24d754c6411e50b873e7'},
 {'name': 'migrations/000017_notification_retention.sql',
  'sha256': '964892bea39f4444f2ad0e7e0fda6dae2d1baba578c301331ac3ca42f656e689'},
 {'name': 'migrations/000018_runtime_lock_privileges.sql',
  'sha256': '797106a3d693f2db868714038977786097fbfd73f8525f259d751840b994b594'}]

def fixture():
    ns = ['73000000-0000-4000-8000-000000000001']
    sources = [{'id': dep, 'expectedInstanceId': instance, 'origin': 'https://10.77.0.21:' + port, 'namespaceIds': ns}
               for (dep, instance), port in zip(p.SOURCE_IDS.items(), ('18443', '28443'))]
    ledger = copy.deepcopy(COMMITTED_LEDGER)
    db = {'ledger': ledger, 'sources': [{'deploymentId': c['id'], 'controlInstanceId': c['expectedInstanceId'],
          'recoveryEpoch': '1', 'namespaceIds': ns, 'configurationRevision': 7, 'state': 'active', 'generation': '3', 'lastPosition': '42',
          'openGaps': 0, 'unfinishedRecoveries': 0} for c in sources],
          'hold': {'held': False, 'generation': '3', 'suppressRecordedThrough': None},
          'rolesSHA256': 'e' * 64, 'databaseOID': '4242'}
    hosts = {'pg01': {'database': db}, 'storage01': {'roles': {}, 'operator': {}}, 'control01': {'roles': {}}}
    for role in p.ROLES:
        config = {'configurationRevision': 7, 'controls': sources, 'kept': {'arbitrary': ['value']}}
        if role == 'api': config['webRoot'] = p.OLD_ROOT + '/web'
        unit = '[Unit]\nDescription=Synthetic\n[Service]\n' + ''.join(k + '=' + v + '\n' for k, v in p.unit_lines(role, p.OLD_ROOT).items())
        hosts[p.r.SPECS[role][0]]['roles'][role] = {'config': b64(p.encoded(config)), 'unit': b64(unit.encode()),
            'materials': {}, 'process': {'pid': '11', 'startedMonotonic': '100', 'bootId': '11111111-1111-4111-8111-111111111111',
                                         'uid': p.r.SPECS[role][2], 'binary': p.OLD_ROOT + '/bin/' + p.r.SPECS[role][5], 'binarySHA256': 'a' * 64},
            'capabilities': [{'deploymentId': c['id'], 'instanceId': c['expectedInstanceId'], 'recoveryEpoch': '1'} for c in sources] if role == 'worker' else []}
    snapshot = {'format': 1, 'capturedAt': int(time.time()), 'hosts': hosts}
    files = {name: b'x' for name in ('bin/jobman-dashboard', 'bin/jobman-log-broker', 'build.json', 'SHA256SUMS', 'web/index.html')}
    metadata = {'revision': p.NEW, 'version': p.VERSION}
    plan = p.make(snapshot, metadata, files, ledger, {name: 'a' * 64 for name in p.FILES})
    return plan


class Candidate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.plan = fixture()

    def save(self, name, value):
        path = self.root / name; path.write_bytes(p.encoded(value)); path.chmod(0o600); return path

    def test_all_template_sites_are_transformed_and_no_other_bytes(self):
        for role, count in [('api', 3), ('worker', 3), ('broker', 2)]:
            baseline = self.plan['snapshot']['hosts'][p.r.SPECS[role][0]]['roles'][role]
            before = p.unb64(baseline['unit']); after = p.transform_unit(role, before)
            self.assertEqual(after.count(p.NEW_ROOT.encode()), count)
            self.assertEqual(after.replace(p.NEW_ROOT.encode(), p.OLD_ROOT.encode()), before)
            self.assertNotIn(p.OLD_ROOT.encode(), after)

    def test_unit_extra_site_duplicate_precheck_or_wrong_mode_rejected(self):
        before = p.unb64(self.plan['snapshot']['hosts']['storage01']['roles']['api']['unit'])
        for raw in (before + b'# ' + p.OLD_ROOT.encode() + b'\n', before + b'ExecStartPre=/other\n',
                    before.replace(b'--check-mode api', b'--check-mode worker'), before.replace(b'WorkingDirectory=', b'#WorkingDirectory=')):
            with self.subTest(raw=raw), self.assertRaises(ValueError): p.transform_unit('api', raw)

    def test_only_api_webroot_changes_worker_and_broker_exact_bytes(self):
        for role in p.ROLES:
            before = p.unb64(self.plan['snapshot']['hosts'][p.r.SPECS[role][0]]['roles'][role]['config'])
            after = p.transform_config(role, before)
            if role == 'api':
                value = p.decode(after); self.assertEqual(value.pop('webRoot'), p.NEW_ROOT + '/web')
                original = p.decode(before); original.pop('webRoot'); self.assertEqual(value, original)
            else: self.assertEqual(after, before)

    def test_source_revision_epoch_scope_and_hold_are_pinned(self):
        p.validate(self.plan)
        for field, value in [('state', 'paused'), ('recoveryEpoch', '0'), ('configurationRevision', 8), ('openGaps', 1), ('unfinishedRecoveries', 1)]:
            candidate = copy.deepcopy(self.plan); candidate['database']['sources'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): p.validate(candidate)
        for path in ('config', 'unit'):
            candidate = copy.deepcopy(self.plan)
            candidate['snapshot']['hosts']['storage01']['roles']['api'][path] = b64(b'changed')
            with self.assertRaises(ValueError): p.validate(candidate)

    def test_member_escape_modes_and_oversize_rejected(self):
        for name, item in [('../escape', {'bytes': 1, 'sha256': 'a' * 64, 'mode': 0o644}),
                           ('web/large', {'bytes': (96 << 20) + 1, 'sha256': 'a' * 64, 'mode': 0o644}),
                           ('web/writeable', {'bytes': 1, 'sha256': 'a' * 64, 'mode': 0o666})]:
            candidate = copy.deepcopy(self.plan); candidate['candidateFiles'][name] = item
            with self.subTest(name=name), self.assertRaises(ValueError): p.validate(candidate)

    def test_new_files_force_modes_and_never_repair_existing(self):
        path = self.root / 'fresh'; previous = os.umask(0o777)
        try:
            with patch.object(g.os, 'fchown'): g.put(path, b'new', mode=0o644)
        finally: os.umask(previous)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        path.chmod(0o600)
        with patch.object(g.os, 'fchown'), self.assertRaises(FileExistsError): g.put(path, b'new', mode=0o644)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        receipt = self.root / 'receipt'; previous = os.umask(0o777)
        try: h.write(receipt, b'proof')
        finally: os.umask(previous)
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)

    def test_bounded_host_read_symlink_fifo_private_permissions(self):
        path = self.root / 'file'; path.write_bytes(b'ab'); path.chmod(0o600)
        self.assertEqual(h.read(path, 2), b'ab')
        with self.assertRaises(ValueError): h.read(path, 1)
        link = self.root / 'link'; link.symlink_to(path)
        with self.assertRaises(OSError): h.read(link)
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): h.read(fifo)
        path.chmod(0o644)
        with self.assertRaises(ValueError): h.read(path)

    def test_existing_partial_stage_never_reinvokes_extraction(self):
        self.save('stage.pending.json', {'planSHA256': 'a' * 64})
        with self.assertRaises(ValueError), patch.object(g.p.split, 'candidate_files') as extract:
            g.stage({'plan': self.plan, 'host': 'storage01'}, self.root)
        extract.assert_not_called()

    def test_cas_recovery_proves_after_and_never_rewrites_before_or_partial(self):
        path = self.root / 'config'; path.write_bytes(b'after')
        proof = {'beforeSHA256': p.sha(b'before'), 'afterSHA256': p.sha(b'after'), 'path': str(path)}
        self.save('change.pending.json', proof)
        read = lambda path, *_: Path(path).read_bytes()
        with patch.object(g.r, 'read', side_effect=read), patch.object(g, 'receipt') as receipt, patch.object(g, 'put') as put:
            g.change_file(self.root, 'change', path, b'before', b'after', 0, 0o600)
            put.assert_not_called(); self.assertEqual(receipt.call_args.args[1], 'change')
            path.write_bytes(b'before')
            with self.assertRaises(ValueError): g.change_file(self.root, 'change', path, b'before', b'after', 0, 0o600)
            put.assert_not_called()

    def test_restart_uncertainty_is_observed_without_restarting(self):
        baseline = self.plan['snapshot']['hosts']['control01']['roles']['broker']['process']
        self.save('broker-restart.pending.json', baseline)
        changed = dict(baseline, pid='12', startedMonotonic='200', binary=p.NEW_ROOT + '/bin/jobman-log-broker')
        payload = {'plan': self.plan, 'host': 'control01', 'role': 'broker', 'planSHA256': 'b' * 64, 'observeOnly': True}
        originals = self.plan['changes']['broker']
        def read(path, *_):
            path = Path(path)
            if path == self.root / 'broker-restart.pending.json': return path.read_bytes()
            return b'config' if path.name == 'config.json' else b'unit'
        originals['afterConfigSHA256'] = p.sha(b'config'); originals['afterUnitSHA256'] = p.sha(b'unit')
        with patch.object(g, 'authority'), patch.object(g, 'immutable_candidate'), patch.object(g, 'reload_units'), patch.object(g.r, 'read', side_effect=read), patch.object(g, 'receipt') as receipt, patch.object(g.r, 'run') as run:
            with patch.object(g, 'ready', return_value=changed):
                self.assertEqual(g.restart(payload, self.root)['process'], changed)
            run.assert_not_called(); self.assertEqual(receipt.call_args.args[1], 'broker-restart')
            for current in [baseline, dict(changed, pid=baseline['pid']), dict(changed, startedMonotonic=baseline['startedMonotonic'])]:
                with patch.object(g, 'ready', return_value=current), self.assertRaises(ValueError): g.restart(payload, self.root)
            run.assert_not_called()

    def test_missing_pending_cannot_start_restart_in_observe_mode(self):
        plan = copy.deepcopy(self.plan); plan['changes']['broker']['afterConfigSHA256'] = p.sha(b'x'); plan['changes']['broker']['afterUnitSHA256'] = p.sha(b'x')
        payload = {'plan': plan, 'host': 'control01', 'role': 'broker', 'observeOnly': True}
        with patch.object(g, 'authority'), patch.object(g, 'immutable_candidate'), patch.object(g, 'reload_units'), patch.object(g.r, 'read', return_value=b'x'), patch.object(g.r, 'run') as run, self.assertRaises(ValueError):
            g.restart(payload, self.root)
        run.assert_not_called()

    def test_lost_daemon_reload_reply_never_reissues_reload(self):
        self.save('reload.pending.json', {'host': 'storage01', 'newRevision': p.NEW})
        with patch.object(g, 'loaded_units') as loaded, patch.object(g, 'receipt') as receipt, patch.object(g.r, 'run') as run:
            g.reload_units(self.plan, 'storage01', self.root, True)
            run.assert_not_called(); loaded.assert_called_once(); self.assertEqual(receipt.call_args.args[1], 'reload')

    def test_readiness_deadline_covers_configuration_and_metrics(self):
        clock = [0.0]; supplied = []
        def process(*args): clock[0] += 0.8; return {'ok': True}
        def config(role, release, deadline): supplied.append(g.remaining(deadline, 10)); clock[0] += 0.3; raise ValueError()
        with patch.object(g.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(g, 'process', side_effect=process), patch.object(g, 'check_config', side_effect=config), self.assertRaisesRegex(ValueError, 'startup_configuration'):
            g.ready('api', self.plan, 1)
        self.assertAlmostEqual(supplied[0], 0.2)

    def test_database_query_is_fixed_readonly_and_omits_mutations_credentials(self):
        sql = g.DATABASE_SQL.upper()
        self.assertIn('REPEATABLE READ READ ONLY', sql)
        for token in ('INSERT ', 'UPDATE ', 'DELETE ', 'ALTER ', 'CREATE ', 'PG_RELOAD_CONF', 'ROLPASSWORD'):
            self.assertNotIn(token, sql)
        value = copy.deepcopy(self.plan['database']); value.pop('rolesSHA256'); value['roleProof'] = {'roles': [{}, {}, {}, {}]}
        with patch.object(g.r, 'run', return_value=p.encoded(value)) as run:
            result = g.database()
        self.assertEqual(result['sources'], self.plan['database']['sources'])
        self.assertEqual(run.call_args.args[0][-2:], ['-d', 'jobman_dashboard'])
        self.assertLessEqual(run.call_args.kwargs['timeout'], 15)

    def test_actual_new_binary_schema_check_is_status_not_config_or_migrate(self):
        with patch.object(g, 'operator_proofs'), patch.object(g.r, 'run', return_value=b'{}') as run:
            g.schema_check(self.plan)
        args = run.call_args.args[0]
        self.assertEqual(args, [p.NEW_ROOT + '/bin/jobman-dashboard', 'status', '--operator-config', p.OPERATOR])

    def test_real_host_role_matrix_and_unit_names(self):
        self.assertEqual(p.r.SPECS['api'][:3], ('storage01', '/etc/jobman-dashboard-api-lab', 21904))
        self.assertEqual(p.r.SPECS['worker'][4], 'jobman-dashboard-lab-worker')
        self.assertEqual(p.r.SPECS['broker'][:3], ('control01', '/etc/jobman-dashboard-broker-lab', 21901))
        self.assertEqual(p.r.SPECS['broker'][4], 'jobman-dashboard-lab-broker')

    def test_ssh_uses_explicit_lab_pin_and_forbids_wrong_fixed_host(self):
        entry = {'storage01': {'ansible_host': '10.77.0.10', 'ansible_user': 'vagrant', 'ansible_port': 22, 'ansible_ssh_private_key_file': '/fixture/key'}}
        with patch.object(h, 'read', return_value=p.encoded(entry)):
            args = h.ssh_args(Path('/fixture/lab'), 'storage01')
        self.assertIn('StrictHostKeyChecking=yes', args); self.assertIn('UserKnownHostsFile=/fixture/lab/.lab/dashboard/known_hosts', args)
        entry['storage01']['ansible_host'] = '10.77.0.21'
        with patch.object(h, 'read', return_value=p.encoded(entry)), self.assertRaises(ValueError): h.ssh_args(Path('/fixture/lab'), 'storage01')

    def test_host_global_lock_blocks_concurrent_other_plan(self):
        parent = self.root / '.lab/dashboard'; parent.mkdir(parents=True); parent.chmod(0o700)
        with h.locked(self.root):
            with self.assertRaises(BlockingIOError):
                with h.locked(self.root): self.fail('second operator acquired lock')

    def test_phase_order_requires_all_hosts_staged_and_broker_first(self):
        with self.assertRaises(ValueError): h.required_receipts(self.root, 'stage', 'control01', None, 'pinned')
        for host in p.HOSTS: self.save('preflight-' + host + '.json', {'planSHA256': 'pinned'})
        h.required_receipts(self.root, 'stage', 'control01', None, 'pinned')
        with self.assertRaises(ValueError): h.required_receipts(self.root, 'restart', 'storage01', 'api', 'pinned')
        for name in ['stage-control01', 'stage-storage01', 'apply-control01', 'apply-storage01']: self.save(name + '.json', {'planSHA256': 'pinned'})
        h.required_receipts(self.root, 'restart', 'control01', 'broker', 'pinned')
        with self.assertRaises(ValueError): h.required_receipts(self.root, 'restart', 'storage01', 'api', 'pinned')
        self.save('restart-broker.json', {'planSHA256': 'pinned', 'role': 'broker'}); h.required_receipts(self.root, 'restart', 'storage01', 'api', 'pinned')

    def test_reviewed_bootstrap_loads_without_guest_files_or_actions(self):
        names = ('dashboard-multisource-runtime.py', 'dashboard-split-plan.py', 'dashboard-candidate-plan.py', 'dashboard-candidate-guest.py')
        sources = {name: (HERE / name).read_text() for name in names}
        raw = p.encoded({'host': 'not-a-lab-host', 'phase': 'snapshot', '_sources': sources, '_hashes': {n: p.sha(v.encode()) for n, v in sources.items()}})
        result = subprocess.run([sys.executable, '-c', h.BOOTSTRAP], input=raw, capture_output=True, timeout=5, check=True)
        self.assertEqual(json.loads(result.stdout), {'ok': False, 'code': 'guest_host_identity'})
        self.assertEqual(result.stderr, b'')

    def test_materials_include_database_and_private_keys_as_digests_only(self):
        config = {'databaseURLFile': '/role/database', 'nested': {'keyFile': '/role/key'}, 'secretsNotInline': True}
        with patch.object(g.r, 'read', return_value=b'synthetic-secret'):
            value = g.file_proofs(config, '/role', 21904)
        self.assertEqual(set(value), {'/role/database', '/role/key'})
        self.assertNotIn('synthetic-secret', json.dumps(value))
        with self.assertRaises(ValueError): g.file_proofs({'keyFile': '/another/secret'}, '/role', 21904)


    def test_phase_receipts_from_another_plan_never_authorize_next_step(self):
        for host in p.HOSTS: self.save('preflight-' + host + '.json', {'planSHA256': 'other'})
        with self.assertRaisesRegex(ValueError, 'previous_phase_plan_changed'):
            h.required_receipts(self.root, 'stage', 'control01', None, 'pinned')

    def test_schema_changed_between_commits_blocks_prepare(self):
        calls = []
        def run(args, *_args, **_kwargs):
            calls.append(args)
            if args[3] == 'ls-tree':
                return ('\n'.join('internal/store/' + row['name'] for row in self.plan['database']['ledger']) + '\n').encode()
            return b'old' if args[4].startswith(p.OLD) else b'new'
        with patch.object(h.r, 'run', side_effect=run), self.assertRaisesRegex(ValueError, 'candidate_requires_migration'):
            h.schema_manifest(self.root)
        self.assertEqual(len(calls), 38)

    def test_public_archive_validator_rejects_wrong_digest_before_extracting(self):
        path = self.root / 'candidate.tar.gz'; path.write_bytes(b'not-a-tar')
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            p.split.candidate_files(path, p.ARCHIVE)

    def test_database_failure_creates_no_mutation_pending_or_operation(self):
        from argparse import Namespace
        plan = copy.deepcopy(self.plan); digest = p.sha(p.encoded(plan))
        for host in p.HOSTS: self.save('preflight-' + host + '.json', {'planSHA256': digest, 'preflightAt': int(time.time())})
        for host in ('control01', 'storage01'): self.save('stage-' + host + '.json', {'planSHA256': digest})
        args = Namespace(staging=self.root, phase='apply', host='control01', role=None, expected_plan_sha256=digest,
                         expected_implementation_sha256='i', lab_root=self.root, apply=True, observe_only=False)
        with patch.object(h, 'load_plan', return_value=(plan, {})), patch.object(h, 'remote', side_effect=ValueError('db unavailable')):
            with self.assertRaises(ValueError): h.phase(args)
        self.assertFalse((self.root / 'apply-control01.pending.json').exists())
        self.assertFalse((self.root / '.lab/dashboard/.candidate-upgrade.operation.json').exists())

    def test_uncertain_host_phase_does_not_resend_a_mutation(self):
        from argparse import Namespace
        plan = copy.deepcopy(self.plan); digest = p.sha(p.encoded(plan))
        for host in p.HOSTS: self.save('preflight-' + host + '.json', {'planSHA256': digest, 'preflightAt': int(time.time())})
        for host in ('control01', 'storage01'): self.save('stage-' + host + '.json', {'planSHA256': digest})
        self.save('apply-control01.pending.json', {'planSHA256': digest})
        args = Namespace(staging=self.root, phase='apply', host='control01', role=None, expected_plan_sha256=digest,
                         expected_implementation_sha256='i', lab_root=self.root, apply=True, observe_only=False)
        with patch.object(h, 'load_plan', return_value=(plan, {})), patch.object(h, 'remote') as remote:
            with self.assertRaisesRegex(ValueError, 'uncertain_phase_requires_observation'): h.phase(args)
        remote.assert_not_called()

    def test_candidate_extra_empty_directory_is_rejected(self):
        release = self.root / 'release'; release.mkdir(); (release / 'injected').mkdir()
        with patch.object(g.p, 'NEW_ROOT', str(release)), patch.object(g, 'directory'), self.assertRaisesRegex(ValueError, 'unexpected_candidate_directory'):
            g.immutable_candidate(self.plan)



    def test_normal_feed_advance_is_allowed_but_authority_change_is_not(self):
        baseline = self.plan['database']; advanced = copy.deepcopy(baseline)
        for item in advanced['sources']: item.update(generation='900', lastPosition='600')
        g.database_continuity(baseline, advanced)
        for name, value in [('generation', '2'), ('lastPosition', '41'), ('lastPosition', '-1'), ('generation', '03'),
                            ('recoveryEpoch', '2'), ('namespaceIds', []), ('state', 'paused'), ('openGaps', 1)]:
            candidate = copy.deepcopy(advanced); candidate['sources'][0][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError): g.database_continuity(baseline, candidate)
        for key in ('held', 'generation', 'suppressRecordedThrough'):
            candidate = copy.deepcopy(advanced); candidate['hold'][key] = True if key == 'held' else 'changed'
            with self.subTest(key=key), self.assertRaises(ValueError): g.database_continuity(baseline, candidate)



    def test_recovery_legacy_database_reference_is_exact_owned_and_digest_only(self):
        legacy = '/etc/jobman-dashboard-app-lab/database-url'
        operator = {'databaseURLFile': '/etc/jobman-dashboard-operator-lab/database-url'}
        recovery = {'databaseURLFile': legacy, 'webRoot': p.OLD_ROOT + '/web'}
        calls = []
        def read(name, uid, mode=0o600, *_):
            calls.append((str(name), uid, mode))
            if str(name) == p.OPERATOR: return p.encoded(operator)
            if str(name) == p.RECOVERY: return p.encoded(recovery)
            return b'synthetic-private-dsn'
        with patch.object(g.r, 'read', side_effect=read):
            proof = g.operator_proofs()
        self.assertIn((legacy, 21903, 0o600), calls)
        self.assertNotIn('synthetic-private-dsn', json.dumps(proof))
        recovery['databaseURLFile'] = legacy + '.neighbor'
        with patch.object(g.r, 'read', side_effect=read), self.assertRaisesRegex(ValueError, 'operator_reference_boundary'):
            g.operator_proofs()
        recovery['databaseURLFile'] = legacy; recovery['keyFile'] = legacy
        with patch.object(g.r, 'read', side_effect=read), self.assertRaisesRegex(ValueError, 'legacy_database_reference_reused'):
            g.operator_proofs()
        recovery.pop('keyFile'); operator['databaseURLFile'] = legacy
        with patch.object(g.r, 'read', side_effect=read), self.assertRaisesRegex(ValueError, 'operator_reference_boundary'):
            g.operator_proofs()



    def test_actual_committed_embed_ledger_preserves_directory_prefix(self):
        value = copy.deepcopy(self.plan['database'])
        self.assertEqual(value['ledger'], COMMITTED_LEDGER)
        p.stable_database(value)
        value['ledger'] = [dict(row, name=Path(row['name']).name) for row in value['ledger']]
        with self.assertRaisesRegex(ValueError, 'schema_version'): p.stable_database(value)
        def git(args, *_args, **_kwargs):
            if args[3] == 'ls-tree':
                return ('\n'.join('internal/store/' + row['name'] for row in COMMITTED_LEDGER) + '\n').encode()
            return b'fixture SQL for checksum behavior'
        with patch.object(h.r, 'run', side_effect=git): rows = h.schema_manifest(self.root)
        self.assertEqual([row['name'] for row in rows], [row['name'] for row in COMMITTED_LEDGER])

    def test_postgres_json_scalars_match_declared_column_types(self):
        # json_build_object emits bigint/count as JSON numbers unless explicitly
        # ::text. recovery_epoch is already SQL text; UUID[] becomes strings.
        baseline = copy.deepcopy(self.plan['database']); p.stable_database(baseline)
        for field, wrong in [('configurationRevision', '7'), ('configurationRevision', 7.0),
                             ('openGaps', False), ('openGaps', '0'), ('unfinishedRecoveries', False),
                             ('generation', 3), ('lastPosition', 42), ('recoveryEpoch', 1),
                             ('generation', '9223372036854775808'), ('lastPosition', '-1')]:
            value = copy.deepcopy(baseline); value['sources'][0][field] = wrong
            with self.subTest(field=field, wrong=wrong), self.assertRaises(ValueError): p.stable_database(value)
        for field, wrong in [('held', 'false'), ('held', 0), ('generation', 3), ('generation', '03'), ('suppressRecordedThrough', 1)]:
            value = copy.deepcopy(baseline); value['hold'][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError): p.stable_database(value)



    def test_stage_runs_actual_bounded_transport_for_database_check(self):
        from argparse import Namespace
        plan = copy.deepcopy(self.plan); digest = p.sha(p.encoded(plan))
        for host in p.HOSTS:
            self.save('preflight-' + host + '.json', {'planSHA256': digest, 'preflightAt': int(time.time())})
        archive = b'synthetic archive for host transport regression'
        (self.root / 'candidate.tar.gz').write_bytes(archive); (self.root / 'candidate.tar.gz').chmod(0o600)
        parent = self.root / '.lab/dashboard'; parent.mkdir(parents=True); parent.chmod(0o700)
        trace = self.root / 'transport-phases.jsonl'
        # Real bounded r.run, selector input/output and failure-code validation.
        # Only the ssh executable is replaced by a local Python fixture; remote()
        # still serializes and hashes the actual reviewed modules.
        fixture = "import json,sys;from pathlib import Path;v=json.load(sys.stdin);" + \
                  "p=Path(sys.argv[1]);f=p.open('a');f.write(json.dumps({'phase':v['phase'],'host':v['host']})+'\\n');f.close();" + \
                  "print(json.dumps({'ok':True,'result':{'planSHA256':v['planSHA256'],'phase':v['phase']}}))"
        args = Namespace(staging=self.root, phase='stage', host='control01', role=None, expected_plan_sha256=digest,
                         expected_implementation_sha256='i', lab_root=self.root, apply=True, observe_only=False)
        hashes = h.implementation()
        with patch.object(h, 'load_plan', return_value=(plan, hashes)), patch.object(h.p, 'ARCHIVE', p.sha(archive)), \
             patch.object(h, 'ssh_args', return_value=[sys.executable, '-c', fixture, str(trace)]):
            result = h.phase(args)
        self.assertEqual(result['phase'], 'stage')
        phases = [json.loads(line) for line in trace.read_text().splitlines()]
        self.assertEqual(phases, [{'phase':'database-check','host':'pg01'}, {'phase':'stage','host':'control01'}])
        self.assertTrue((self.root / 'stage-control01.pending.json').exists())
        self.assertTrue((self.root / 'stage-control01.json').exists())

    def test_unknown_internal_phase_is_rejected_before_transport(self):
        for phase in ('database/check', 'database_check', 'stage;echo', '', None, 'migrate'):
            with self.subTest(phase=phase), patch.object(h, 'ssh_args') as ssh, self.assertRaisesRegex(ValueError, 'remote_phase_boundary'):
                h.remote(self.root, {'phase': phase, 'host': 'pg01'}, {})
            ssh.assert_not_called()


if __name__ == '__main__': unittest.main()
