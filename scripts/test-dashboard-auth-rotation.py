#!/usr/bin/env python3
"""Offline auth-rotation guards; no Lab credentials, network or guest calls."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
p = load('dashboard-auth-rotation-plan'); g = load('dashboard-auth-rotation-guest'); h = load('rotate-dashboard-auth')


def b64(raw): return base64.b64encode(raw).decode()


def fixture():
    sources = [{'id': dep, 'expectedInstanceId': instance, 'origin': 'https://10.77.0.21:' + port,
                'namespaceIds': ['73000000-0000-4000-8000-%012d' % n for n in range(1, count + 1)]}
               for (dep, instance), port, count in zip(p.SOURCES.items(), ('18443', '28443'), (12, 7))]
    db = {'ledger': [{'name': 'migrations/%06d_test.sql' % n, 'sha256': 'a' * 64} for n in range(1, 19)], 'databaseOID': '42', 'rolesSHA256': 'b' * 64,
          'hold': {'held': False, 'generation': '5', 'suppressRecordedThrough': '2026-10-04 00:00:00+00'},
          'sources': [{'deploymentId': s['id'], 'controlInstanceId': s['expectedInstanceId'], 'recoveryEpoch': '1', 'namespaceIds': s['namespaceIds'], 'configurationRevision': 8,
                       'state': 'active', 'generation': '10', 'lastPosition': '42', 'openGaps': 0, 'unfinishedRecoveries': 0} for s in sources]}
    hosts = {'pg01': {'database': db}, 'control01': {'roles': {}, 'preserved': {}}, 'storage01': {'roles': {}, 'operator': {}, 'capabilities': []}}
    commit = 'a' * 40
    for role in p.ROLES:
        host, root, uid, _, unit, binary, _ = p.r.SPECS[role]
        config = {'configurationRevision': 8, 'controls': copy.deepcopy(sources), 'kept': {'opaque': ['value']}}
        materials = {}
        if role == 'api':
            config.update(publicOrigin='https://dashboard.lab.test:8443', listen='10.77.0.10:8443', oidc={'issuer':'https://oidc.lab.test:8443/realms/jobman-lab'}, encryption={'keyId': 'previous', 'keyFile': root + '/encryption-key'}, databaseURLFile=root + '/database-url',
                          webRoot='/opt/jobman-dashboard-lab/releases/' + commit + '/web', observability={'socket': '/socket'},
                          logCursorKeyFile=root + '/log-cursor-key', reports={'policyKeyFile': root + '/policy-key'},
                          notifications={'tokenEncryption': {'current': {'keyId': 'token-current', 'keyFile': root + '/token-key'}, 'previous': []}})
            materials[root + '/encryption-key'] = {'sha256': 'c' * 64, 'bytes': 32, 'uid': uid, 'mode': 0o600}
        raw = p.encoded(config); unitraw = b'[Service]\nUnit=unchanged\n'
        hosts[host]['roles'][role] = {'config': b64(raw), 'unit': b64(unitraw), 'materials': materials,
            'process': {'uid': uid, 'unit': unit, 'binary': '/opt/jobman-dashboard-lab/releases/' + commit + '/bin/' + binary,
                        'binarySHA256': 'd' * 64, 'unitSHA256': p.sha(unitraw), 'pid': '100', 'startedMonotonic': '1000', 'bootId': '10000000-0000-4000-8000-000000000001'}}
    recovery = p.decode(p.unb64(hosts['storage01']['roles']['api']['config'])); recovery['controls'] = sources
    recovery['databaseURLFile'] = p.PRIVILEGED_DSN; recovery.pop('observability')
    hosts['storage01']['recovery'] = {'config': b64(p.encoded(recovery)), 'materials': {}}
    return p.make({'format': 1, 'capturedAt': int(time.time()), 'hosts': hosts}, commit, {name: 'f' * 64 for name in p.FILES})


class Rotation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700); self.plan = fixture()

    def test_only_auth_encryption_changes_and_new_recovery_preserves_old(self):
        p.validate(self.plan)
        for old, new in [(p.unb64(self.plan['snapshot']['hosts']['storage01']['roles']['api']['config']), p.unb64(self.plan['afterConfig'])),
                         (p.unb64(self.plan['snapshot']['hosts']['storage01']['recovery']['config']), p.unb64(self.plan['afterRecovery']))]:
            before, after = p.decode(old), p.decode(new)
            self.assertEqual(after.pop('encryption'), {'keyId': p.KEY_ID, 'keyFile': p.KEY_FILE})
            before.pop('encryption'); self.assertEqual(before, after)
        self.assertNotEqual(p.RECOVERY_AFTER, p.RECOVERY_BEFORE)
        self.assertNotIn(p.KEY_FILE, str(self.plan['snapshot']['hosts']['storage01']['roles']['worker']))

    def test_dedicated_purpose_keys_and_distinct_auth_required(self):
        raw = p.unb64(self.plan['snapshot']['hosts']['storage01']['roles']['api']['config'])
        for change in ('logCursorKeyFile', 'reports', 'notifications'):
            value = p.decode(raw); value.pop(change)
            with self.subTest(change=change), self.assertRaises(ValueError): p.transform(p.encoded(value))
        value = p.decode(raw); value['logCursorKeyFile'] = value['encryption']['keyFile']
        with self.assertRaises(ValueError): p.transform(p.encoded(value))
        value = p.decode(raw); value['encryption']['keyId'] = p.KEY_ID
        with self.assertRaises(ValueError): p.transform(p.encoded(value))

    def test_old_key_length_is_exact_and_config_revision_does_not_advance(self):
        snapshot = copy.deepcopy(self.plan['snapshot']); key = p.API_ROOT + '/encryption-key'
        for size in (0, 31, 33, 64):
            snapshot['hosts']['storage01']['roles']['api']['materials'][key]['bytes'] = size
            with self.subTest(size=size), self.assertRaises(ValueError): p.make(snapshot, self.plan['revision'], self.plan['implementationSHA256'])
        self.assertEqual(p.decode(p.unb64(self.plan['afterConfig']))['configurationRevision'], 8)

    def test_recovery_cannot_change_database_source_or_other_authority(self):
        for field, value in [('databaseURLFile', p.API_ROOT + '/database-url'), ('configurationRevision', 7), ('encryption', {'keyId': 'other', 'keyFile': '/other'})]:
            snapshot = copy.deepcopy(self.plan['snapshot']); original = p.decode(p.unb64(snapshot['hosts']['storage01']['recovery']['config'])); original[field] = value
            snapshot['hosts']['storage01']['recovery']['config'] = b64(p.encoded(original))
            with self.subTest(field=field), self.assertRaises(ValueError): p.make(snapshot, self.plan['revision'], self.plan['implementationSHA256'])

    def test_reviewed_candidate_exact_but_no_old_revision_assumption(self):
        snapshot = copy.deepcopy(self.plan['snapshot']); commit = 'b' * 40
        for host in snapshot['hosts'].values():
            for role, value in host.get('roles', {}).items(): value['process']['binary'] = value['process']['binary'].replace('a' * 40, commit)
        p.make(snapshot, commit, self.plan['implementationSHA256'])
        with self.assertRaises(ValueError): p.make(snapshot, 'c' * 40, self.plan['implementationSHA256'])

    def test_feed_advances_but_scope_epoch_hold_and_schema_do_not(self):
        before = self.plan['snapshot']['hosts']['pg01']['database']; after = copy.deepcopy(before)
        after['sources'][0]['generation'] = '100'; after['sources'][0]['lastPosition'] = '999'; p.database_continuity(before, after)
        for field, value in [('generation', '9'), ('lastPosition', '41'), ('recoveryEpoch', '2'), ('configurationRevision', 7), ('openGaps', 1), ('state', 'paused')]:
            after = copy.deepcopy(before); after['sources'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): p.database_continuity(before, after)
        for held in (True, 0, 1):
            after = copy.deepcopy(before); after['hold']['held'] = held
            with self.subTest(held=held), self.assertRaises(ValueError): p.stable_database(after)
        after = copy.deepcopy(before); after['hold']['generation'] = '6'
        with self.assertRaises(ValueError): p.database_continuity(before, after)

    def test_fresh_scopes_and_embedded_migration_keys_required(self):
        for mutation in ('scope', 'ledger', 'scalar'):
            value = copy.deepcopy(self.plan['snapshot']['hosts']['pg01']['database'])
            if mutation == 'scope': value['sources'][0]['namespaceIds'].pop()
            if mutation == 'ledger': value['ledger'][0]['name'] = '000001_test.sql'
            if mutation == 'scalar': value['sources'][0]['generation'] = 10
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): p.stable_database(value)

    def test_plan_tampering_and_duplicate_keys_rejected(self):
        for field in ('afterConfigSHA256', 'beforeRecoverySHA256', 'keyFile', 'revision'):
            value = copy.deepcopy(self.plan); value[field] = 'changed'
            with self.subTest(field=field), self.assertRaises(ValueError): p.validate(value)
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError): p.decode(raw)

    def test_host_private_write_under_restrictive_umask_and_no_overwrite(self):
        old = os.umask(0o777)
        try: h.write(self.root / 'receipt', b'private')
        finally: os.umask(old)
        self.assertEqual((self.root / 'receipt').stat().st_mode & 0o777, 0o600)
        self.assertEqual(h.read(self.root / 'receipt'), b'private')
        with self.assertRaises(FileExistsError): h.write(self.root / 'receipt', b'changed')

    def test_host_file_alias_and_public_secret_rejected(self):
        h.write(self.root / 'input', b'private'); (self.root / 'link').symlink_to(self.root / 'input')
        with self.assertRaises(OSError): h.read(self.root / 'link')
        (self.root / 'input').chmod(0o644)
        with self.assertRaises(ValueError): h.read(self.root / 'input')

    def test_host_lock_is_exclusive(self):
        (self.root / '.lab').mkdir(); (self.root / '.lab/dashboard').mkdir(mode=0o700)
        with h.locked(self.root):
            with self.assertRaises(BlockingIOError):
                with h.locked(self.root): pass

    def test_uncertain_stage_never_generates_another_key(self):
        (self.root / 'stage.pending.json').write_text('{}')
        with patch.object(g, 'BASE', self.root), patch.object(g.os, 'urandom') as random:
            with self.assertRaises(ValueError): g.stage({'plan': self.plan, 'observeOnly': False})
            random.assert_not_called()

    def test_uncertain_restart_observes_without_repeating_service_change(self):
        baseline = self.plan['snapshot']['hosts']['storage01']['roles']['api']['process']
        (self.root / 'restart.pending.json').write_text('{}')
        after = dict(baseline, pid='200', startedMonotonic='2000')
        def read(path, *_):
            if str(path).endswith('config.json'): return p.unb64(self.plan['afterConfig'])
            if str(path).endswith('restart.pending.json'): return p.encoded(baseline)
            return b'{}'
        with patch.object(g, 'BASE', self.root), patch.object(g, 'staged'), patch.object(g.r, 'read', side_effect=read), patch.object(g, 'ready', return_value=after), patch.object(g, 'receipt') as receipt, patch.object(g.r, 'run') as run:
            result = g.restart({'plan': self.plan, 'planSHA256': 'a' * 64, 'observeOnly': True})
            self.assertEqual(result['process'], after); run.assert_not_called(); receipt.assert_called_once()

    def test_ready_rejects_late_success_and_bounds_each_probe(self):
        baseline = self.plan['snapshot']['hosts']['storage01']['roles']['api']['process']
        after = dict(baseline, pid='200', startedMonotonic='2000')
        clock = [100.0]
        def late(_deadline): clock[0] = 130.1
        with patch.object(g.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(g, 'process', return_value=after), patch.object(g, 'ready_observations', side_effect=late), patch.object(g.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'rotated_api_not_ready'): g.ready(self.plan)
            sleep.assert_not_called()
        clock[0] = 100.0; timeouts = []
        def run(args, _code, **kwargs):
            timeouts.append(kwargs['timeout']); clock[0] += 0.75
            if args[-1].endswith('/livez'): return p.encoded({'state': 'alive', 'role': 'api'})
            if args[-1].endswith('/readyz'): return p.encoded({'state': 'ready', 'role': 'api'})
            return b'jobman_dashboard_configuration_revision 8\n'
        with patch.object(g.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(g.r, 'run', side_effect=run):
            g.ready_observations(102.5)
        self.assertEqual(timeouts, [2.5, 1.75, 1.0])

    def test_ready_starting_then_ready_preserves_single_deadline(self):
        baseline = self.plan['snapshot']['hosts']['storage01']['roles']['api']['process']
        after = dict(baseline, pid='200', startedMonotonic='2000'); clock = [10.0]
        def sleep(delay): clock[0] += delay
        with patch.object(g.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(g.time, 'sleep', side_effect=sleep), patch.object(g, 'process', side_effect=[ValueError('starting'), after]) as process, patch.object(g, 'ready_observations') as observe:
            self.assertEqual(g.ready(self.plan), after)
        self.assertEqual([call.args for call in process.call_args_list], [('api', 40.0), ('api', 40.0)])
        observe.assert_called_once_with(40.0)

    def test_stage_and_apply_only_on_storage_and_explicit_apply(self):
        payload = {'host': 'control01', 'phase': 'apply', 'plan': self.plan, 'planSHA256': p.sha(p.encoded(self.plan)), 'apply': True}
        with patch.object(g.os, 'geteuid', return_value=0), patch.object(g.socket, 'gethostname', return_value='control01'), patch.object(g, 'authority'), patch.object(g, 'locked') as lock:
            with self.assertRaises(ValueError): g.execute(payload)
            lock.assert_not_called()

    def test_phase_guard_invokes_all_readonly_hosts_before_effect(self):
        staging = self.root / 'stage'; staging.mkdir(mode=0o700)
        digest = p.sha(p.encoded(self.plan)); proof = {'planSHA256': digest, 'preflightAt': int(time.time())}
        h.save(staging / 'preflight.json', {host: dict(proof, host=host) for host in p.HOSTS})
        args = SimpleNamespace(staging=staging, lab_root=self.root, phase='stage', apply=True, observe_only=False, expected_plan_sha256=digest, expected_implementation_sha256='e' * 64)
        calls = []
        def remote(lab, payload, hashes):
            calls.append((payload['host'], payload['phase']))
            if payload['host'] == 'control01': raise ValueError('drift')
            return proof
        with patch.object(h, 'load_plan', return_value=(self.plan, {})), patch.object(h, 'remote', side_effect=remote):
            with self.assertRaises(ValueError): h.phase(args)
        self.assertEqual(calls, [('pg01', 'check'), ('control01', 'check')]); self.assertFalse((staging / 'stage.pending.json').exists())

    def test_remote_serialization_uses_actual_bounded_runner_no_network(self):
        local = self.root / 'local.py'
        local.write_text('import json,sys\nx=json.load(sys.stdin)\nassert set(x["_sources"])==set(x["_hashes"])\nprint(json.dumps({"ok":True,"result":{"phase":x["phase"]}}))\n')
        hashes = h.implementation()
        with patch.object(h, 'ssh_args', return_value=[sys.executable, str(local)]):
            value = h.remote(self.root, {'host': 'pg01', 'phase': 'check'}, hashes)
        self.assertEqual(value, {'phase': 'check'})
        with self.assertRaises(ValueError): h.remote(self.root, {'host': 'pg01', 'phase': 'arbitrary-operation'}, hashes)

    def test_guest_bootstrap_has_exact_three_file_allowlist(self):
        compile(h.BOOTSTRAP, '<bootstrap>', 'exec')
        sources = {name: h.read(HERE / name, 1 << 20, False).decode() for name in ('dashboard-multisource-runtime.py', 'dashboard-auth-rotation-plan.py', 'dashboard-auth-rotation-guest.py')}
        # Execute only a mocked entrypoint after real source loading. This proves
        # imports resolve from the reviewed stdin bytes, not guest disk paths.
        sources['dashboard-auth-rotation-guest.py'] += '\ndef execute(payload): return {"loaded": payload["phase"]}\n'
        body = dict(phase='offline', _sources=sources, _hashes={name: p.sha(raw.encode()) for name, raw in sources.items()})
        result = subprocess.run([sys.executable, '-c', h.BOOTSTRAP], input=p.encoded(body), capture_output=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), {'ok': True, 'result': {'loaded': 'offline'}})
        body['_sources']['unexpected.py'] = ''
        result = subprocess.run([sys.executable, '-c', h.BOOTSTRAP], input=p.encoded(body), capture_output=True, check=True, timeout=5)
        self.assertFalse(json.loads(result.stdout)['ok'])

    def test_database_transport_readonly_fixed_scope(self):
        self.assertIn('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY', g.DATABASE_SQL)
        self.assertIn("statement_timeout='5000ms'", g.DATABASE_SQL)
        self.assertNotIn('UPDATE ', g.DATABASE_SQL); self.assertNotIn('DELETE ', g.DATABASE_SQL)
        with patch.object(g.r, 'run', return_value=b'{}') as run:
            with self.assertRaises(KeyError): g.database()
        self.assertEqual(run.call_args.args[0], ['podman', 'exec', '-i', '--user', 'postgres', 'jobman-postgres', 'psql', '-X', '-q', '-A', '-t', '-U', 'jobman_control', '-v', 'ON_ERROR_STOP=1', '-d', 'jobman_dashboard'])


if __name__ == '__main__': unittest.main()
