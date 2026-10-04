#!/usr/bin/env python3
"""Offline failure and boundary tests; never connect to a guest or database."""
import base64
from contextlib import nullcontext
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE/filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

guest = load('restore_test_guest', 'dashboard-restore-guest.py')
host = load('restore_test_host', 'apply-dashboard-restore.py')
snapshot = load('restore_test_snapshot', 'snapshot-dashboard-restore.py')


class RestoreApplyTests(unittest.TestCase):
    def test_dump_success_and_exact_hash_with_restrictive_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'dump.partial'
            previous = os.umask(0o077)
            try:
                result = guest.stream_dump([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"hello"*20000)'],path,200000,3)
            finally:
                os.umask(previous)
            self.assertEqual(result,{'bytes':100000,'sha256':guest.digest(b'hello'*20000)})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertEqual(guest.hash_file(path,200000,owner=(os.getuid(),os.getgid())),result)

    def test_dump_failure_never_promotes_or_reuses_partial(self):
        for program, maximum, seconds in [('import sys;sys.stdout.write("TOC valid");sys.exit(9)',100,2),
                                           ('import sys;sys.stdout.write("x"*10000)',100,2),
                                           ('import time;time.sleep(3)',100,0.1)]:
            with self.subTest(program=program), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'dump.partial'
                started=time.monotonic()
                with self.assertRaises(ValueError):guest.stream_dump([sys.executable,'-c',program],path,maximum,seconds)
                self.assertLess(time.monotonic()-started,2.5)
                self.assertTrue(path.exists())
                self.assertFalse(path.with_suffix('').exists())
                with self.assertRaises(FileExistsError):guest.stream_dump([sys.executable,'-c','print("ok")'],path,maximum,2)

    def test_private_file_exactness_and_no_links(self):
        with tempfile.TemporaryDirectory() as parent:
            root=Path(parent).resolve()/'private'
            old=os.umask(0o077)
            try:
                guest.directory(root,os.getuid(),os.getgid(),0o750)
                guest.put(root/'item',b'bytes',os.getuid(),os.getgid(),0o640)
            finally:os.umask(old)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode),0o750)
            self.assertEqual(guest.read(root/'item',owner=(os.getuid(),os.getgid()),mode=0o640)[0],b'bytes')
            with self.assertRaises(ValueError):guest.read(root/'item',mode=0o600)
            os.symlink(root/'item',root/'link')
            with self.assertRaises((ValueError,OSError)):guest.read(root/'link')
            os.link(root/'item',root/'hard')
            with self.assertRaises(ValueError):guest.read(root/'item')

    def test_independent_checkpoint_restore_rejects_cursor_or_identity_drift(self):
        values = [{'deploymentId': '72000000-0000-4000-8000-00000000000'+str(n),
                   'controlInstanceId': instance, 'recoveryEpoch':'1', 'configurationRevision':'7',
                   'namespaceIds':['namespace'], 'status':'active', 'checkpointSHA256':'a'*64,
                   'cursorSHA256':'b'*64, 'positionSHA256':'c'*64} for n,instance in
                  ((1,'e633cf92-258d-48ff-965a-fda88d68ef3a'),(2,'a4f0e2ab-7323-4c90-9510-1f073c660f06'))]
        with patch.object(guest,'sql',return_value=guest.encoded(values)) as query:
            self.assertEqual(guest.retained_source_checkpoints('jobman_dashboard'),values)
            for token in ('LIMIT 3','sha256(f.checkpoint)','sha256(convert_to(f.cursor'):
                self.assertIn(token,query.call_args.args[0])
        payload={'coherentBackup':{'receipts':{'database':{'retainedIdentities':{},'sourceCheckpoints':values}}},
                 'plan':{'primary':{'schema':{'ledgerSHA256':guest.digest(guest.encoded([]))}}}}
        for key in ('cursorSHA256','checkpointSHA256','positionSHA256','controlInstanceId','namespaceIds'):
            changed=[dict(v) for v in values];changed[1][key]='different'
            with patch.object(guest,'sql',return_value='[]'),patch.object(guest,'retained_identities',return_value={}),\
                 patch.object(guest,'retained_source_checkpoints',return_value=changed):
                with self.assertRaisesRegex(ValueError,'independent source checkpoints differ'):
                    guest.verify_restored_database(payload)
        with patch.object(guest,'sql',return_value=guest.encoded(values[:1])):
            with self.assertRaisesRegex(ValueError,'Two independent'):guest.retained_source_checkpoints('jobman_dashboard')

    def test_completed_restore_only_accepts_exact_later_hold_without_cursor_drift(self):
        cutoff='2026-10-04T12:34:56+00:00'
        saved=[{'deploymentId':str(n),'status':'active','cursorSHA256':'a'*64} for n in (1,2)]
        paused=[dict(v,status='paused') for v in saved]
        payload={'externalCutoff':cutoff,'coherentBackup':{'receipts':{'database':{'retainedIdentities':{},'sourceCheckpoints':saved}}},
                 'plan':{'primary':{'schema':{'ledgerSHA256':guest.digest(guest.encoded([]))}}}}
        def verify(values,hold):
            with patch.object(guest,'sql',side_effect=['[]',guest.encoded(hold)]),\
                 patch.object(guest,'retained_identities',return_value={}),\
                 patch.object(guest,'retained_source_checkpoints',return_value=values) as reader:
                result=guest.verify_restored_database(payload,completed=True)
                reader.assert_called_once_with(guest.DATABASE,allow_paused=True)
                return result
        self.assertEqual(verify(paused,{'held':True,'cutoff':cutoff}),[])
        for hold in ({'held':False,'cutoff':cutoff},{'held':True,'cutoff':None},{'held':True,'cutoff':'2026-10-04T12:34:57+00:00'}):
            with self.assertRaisesRegex(ValueError,'unrelated hold'):verify(paused,hold)
        with self.assertRaisesRegex(ValueError,'partially paused'):verify([paused[0],saved[1]],{'held':True,'cutoff':cutoff})
        drift=[dict(v) for v in paused];drift[1]['cursorSHA256']='b'*64
        with self.assertRaisesRegex(ValueError,'checkpoints differ'):verify(drift,{'held':True,'cutoff':cutoff})

    def test_fresh_clone_checks_more_than_tables(self):
        query=guest.fresh_database_query()
        for catalog in ('pg_class','pg_proc','pg_type','pg_namespace','pg_extension'):
            self.assertIn(catalog,query)
        self.assertIn("extname<>'plpgsql'",query)
        self.assertIn("nspname NOT IN('public','pg_catalog','information_schema')",query)

    def test_fixed_database_roles_hba_and_connection_bound(self):
        passwords={role:'a'*64 for role in ('ddl','api','worker','operator')}
        sql=guest.clone_role_sql(passwords)
        self.assertIn('CREATE DATABASE jobman_dashboard_restore OWNER jobman_dashboard_restore_ddl',sql)
        self.assertNotIn('DROP ',sql)
        self.assertEqual(sql.count('CONNECTION LIMIT 16'),2)
        self.assertEqual(sql.count('CONNECTION LIMIT 2'),2)
        self.assertEqual(sql.count('NOBYPASSRLS'),4)
        hba=guest.clone_hba().decode()
        self.assertIn('10.77.0.10/32 scram-sha-256',hba)
        self.assertIn('0.0.0.0/0 reject',hba)
        self.assertIn('::/0 reject',hba)
        with self.assertRaises(ValueError):guest.clone_role_sql(dict(passwords,ddl="';DROP DATABASE jobman_dashboard;--"))
        dsn=guest.clone_dsn('worker','b'*64).decode()
        self.assertIn('/jobman_dashboard_restore?',dsn)
        self.assertIn('sslmode=verify-full',dsn)
        with self.assertRaises(ValueError):guest.clone_dsn('postgres','a'*64)

    def test_clone_units_resource_cap_and_no_delivery(self):
        binary='/opt/jobman-dashboard-lab/releases/'+'a'*40+'/bin/jobman-dashboard'
        for role in ('api','worker'):
            unit=guest.clone_unit(role,binary).decode()
            self.assertIn('TasksMax=256',unit)
            self.assertIn('Environment=GOMAXPROCS=2',unit)
            self.assertIn('MemoryMax='+('512' if role=='api' else '768')+'M',unit)
            self.assertIn('--mode '+role,unit)
            self.assertIn('jobman-dash-restore-readers',unit)
            self.assertNotIn('jobman-dashboard-lab-api.service',unit)
            self.assertNotIn('apns',unit)
        self.assertIn('ReadOnlyPaths=/var/lib/jobman-dashboard-restore-reports-lab',guest.clone_unit('api',binary).decode())

    def _receipt_mocks(self, root, values):
        def read(path,*args,**kwargs):return guest.encoded(values[Path(path).name]),None
        def put(path,raw,*args,**kwargs):
            path=Path(path)
            self.assertNotIn(path.name,values)
            values[path.name]=guest.decode(raw)
            path.touch()
        return patch.object(guest,'read',side_effect=read),patch.object(guest,'put',side_effect=put)

    def test_watchdog_restart_fixed_units_idempotent_and_never_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            values={'armed.json':{'bootId':'boot','armedMonotonic':10,'restartAtMonotonic':160}}
            payload={'operationId':'a'*64}
            reader,writer=self._receipt_mocks(root,values)
            with reader,writer,patch.object(guest,'execution_root',return_value=root),patch.object(guest,'restart_lock',return_value=nullcontext()),\
                 patch.object(guest,'boot_id',return_value='boot'),patch.object(guest,'primary_pins',return_value={'api':{'active':True},'worker':{'active':True}}),\
                 patch.object(guest.time,'monotonic',return_value=160),patch.object(guest,'run',return_value=b'') as runner:
                result=guest.restart_primary(payload,fired=True)
                self.assertTrue(result['watchdogFired'])
                self.assertEqual(runner.call_args.args[0],['systemctl','start',guest.UNIT['api'],guest.UNIT['worker']])
                self.assertEqual(guest.restart_primary(payload,fired=True),result)
                self.assertEqual(runner.call_count,1)
            self.assertIn('fired.json',values)
            self.assertIn('disarmed.json',values)

    def test_watchdog_refuses_changed_primary_without_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            reader,writer=self._receipt_mocks(root,{'armed.json':{'bootId':'boot','armedMonotonic':10,'restartAtMonotonic':160}})
            with reader,writer,patch.object(guest,'execution_root',return_value=root),patch.object(guest,'restart_lock',return_value=nullcontext()),\
                 patch.object(guest,'boot_id',return_value='boot'),patch.object(guest,'primary_pins',side_effect=ValueError('unit drift')),patch.object(guest,'run') as runner:
                with self.assertRaisesRegex(ValueError,'unit drift'):guest.restart_primary({'operationId':'a'*64},fired=True)
                runner.assert_not_called()

    def test_backup_coherence_rejects_fired_expired_or_running(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            armed={'bootId':'boot','restartAtMonotonic':150}
            reader,_=self._receipt_mocks(root,{'armed.json':armed})
            with reader,patch.object(guest,'boot_id',return_value='boot'),patch.object(guest.time,'monotonic',return_value=20),\
                 patch.object(guest,'primary_pins',return_value={'api':{'active':False},'worker':{'active':True}}):
                with self.assertRaises(ValueError):guest.backup_window(root,True,{})
                self.assertEqual(guest.backup_window(root),armed)
                (root/'fired.json').touch()
                with self.assertRaises(ValueError):guest.backup_window(root)
                (root/'fired.json').unlink()
                with patch.object(guest.time,'monotonic',return_value=151):
                    with self.assertRaises(ValueError):guest.backup_window(root)

    def test_pending_phase_never_blindly_reapplied_completed_reply_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            payload={'operationId':'a'*64,'planSHA256':'b'*64}
            receipt=dict(payload,complete=True)
            (root/'test.pending.json').touch()
            with patch.object(guest,'execution_root',return_value=root):
                with self.assertRaises(ValueError):guest.begin_phase(payload,'test')
                (root/'test.json').touch()
                with patch.object(guest,'read',return_value=(guest.encoded(receipt),None)):
                    self.assertEqual(guest.begin_phase(payload,'test'),(root,receipt))

    def test_host_always_restarts_after_dump_or_reply_failure(self):
        for failure in ('stop-primary','database-backup','objects-backup','complete-backup'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                calls=[]
                def call(args,out,payload,where,phase,*unused):
                    calls.append(phase)
                    if phase==failure:raise ValueError('response lost')
                    return {'stopped':True,'operationId':'a'*64,'files':2}
                restart={'primaryRestarted':True,'watchdogFired':False,'elapsedSinceArmSeconds':20}
                with patch.object(host,'call',side_effect=call),patch.object(host,'remote',return_value=restart) as remote,patch.object(host,'local_record'):
                    with self.assertRaises(ValueError):host.coordinated_backup(types.SimpleNamespace(lab_root=Path(directory)),Path(directory),{'operationId':'a'*64})
                    self.assertEqual(remote.call_args.args[3],'restart-primary')
                    self.assertEqual(calls[:2],['arm-backup','stop-primary'])

    def test_host_rejects_snapshot_when_watchdog_won_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            def call(args,out,payload,where,phase,*unused):return {'stopped':True,'operationId':'a'*64,'files':2}
            with patch.object(host,'call',side_effect=call),patch.object(host,'remote',return_value={'watchdogFired':True,'elapsedSinceArmSeconds':150}),patch.object(host,'local_record') as record:
                with self.assertRaises(ValueError):host.coordinated_backup(types.SimpleNamespace(lab_root=Path(directory)),Path(directory),{'operationId':'a'*64})
                self.assertFalse(any(value.args[0].name=='coherent-backup.json' for value in record.call_args_list))

    def test_dispatch_cannot_run_database_mutation_on_storage_or_unknown_host(self):
        with patch.object(guest.os,'geteuid',return_value=0),patch.object(guest.sys,'platform','linux'),patch.object(guest.socket,'gethostname',return_value='storage01'),patch.object(guest,'restore_database') as restore:
            with self.assertRaises(ValueError):guest.dispatch({'host':'storage01','phase':'restore-database'})
            with self.assertRaises(ValueError):guest.dispatch({'host':'pg01','phase':'restore-database'})
            restore.assert_not_called()

    def test_arm_does_not_reuse_a_single_use_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'fired.json').touch()
            pins={'api':{'active':True},'worker':{'active':True}}
            payload={'primaryPins':{'processes':pins}}
            with patch.object(guest,'execution_root',return_value=root),patch.object(guest,'primary_pins',return_value=pins),patch.object(guest,'run') as runner:
                with self.assertRaises(ValueError):guest.arm_backup(payload)
                runner.assert_not_called()

    def test_unacknowledged_arm_never_stops_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            calls=[]
            def call(args,out,payload,where,phase,*unused):
                calls.append(phase)
                raise ValueError('arm response lost')
            with patch.object(host,'call',side_effect=call),patch.object(host,'remote',return_value={'primaryRestarted':True}) as fallback,patch.object(host,'local_record'):
                with self.assertRaises(ValueError):host.coordinated_backup(types.SimpleNamespace(lab_root=Path(directory)),Path(directory),{'operationId':'a'*64})
                self.assertEqual(calls,['arm-backup'])
                self.assertEqual(fallback.call_args.args[3],'restart-primary')

    def test_start_requires_exact_durable_hold_before_any_service_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            payload={}
            with patch.object(guest,'begin_phase',return_value=(root,None)),patch.object(guest,'clone_stopped'),patch.object(guest,'candidate',return_value='/fixed/binary'),\
                 patch.object(guest,'read',return_value=(guest.encoded({'hold':{'held':True,'generation':'4'}}),None)),\
                 patch.object(guest,'run',return_value=guest.encoded({'held':False,'generation':'4'})) as runner:
                with self.assertRaises(ValueError):guest.start_clone(payload)
                self.assertEqual(runner.call_count,1)
                self.assertIn('hold-status',runner.call_args.args[0])

    def test_restored_identity_difference_blocks_acceptance(self):
        payload={'coherentBackup':{'receipts':{'database':{'retainedIdentities':{'inbox':'original'}}}},
                 'plan':{'primary':{'schema':{'ledgerSHA256':guest.digest(guest.encoded([]))}}}}
        with patch.object(guest,'sql',return_value='[]'),patch.object(guest,'retained_identities',return_value={'inbox':'changed'}):
            with self.assertRaisesRegex(ValueError,'stable identities differ'):guest.verify_restored_database(payload)

    def test_stop_loses_to_watchdog_without_late_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            armed={'bootId':'boot','restartAtMonotonic':150}
            reader,writer=self._receipt_mocks(root,{'armed.json':armed})
            def watchdog_wins(*unused,**kwargs):
                (root/'disarmed.json').touch()
                return {'api':{'active':True},'worker':{'active':True}}
            with reader,writer,patch.object(guest,'execution_root',return_value=root),patch.object(guest,'boot_id',return_value='boot'),\
                 patch.object(guest,'restart_lock',return_value=nullcontext()) as locked,patch.object(guest,'primary_pins',side_effect=watchdog_wins),\
                 patch.object(guest.time,'monotonic',return_value=20),patch.object(guest,'run') as runner:
                with self.assertRaises(ValueError):guest.stop_primary({'operationId':'a'*64})
                locked.assert_called_once()
                runner.assert_not_called()

    def test_stop_reserves_restart_budget_and_rechecks_after_receipt_io(self):
        for clock in (30,20):
            with self.subTest(clock=clock),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                armed={'bootId':'boot','restartAtMonotonic':150}
                current=[clock]
                reader,_=self._receipt_mocks(root,{'armed.json':armed})
                def slow_receipt(*unused,**kwargs):current[0]=149
                with reader,patch.object(guest,'put',side_effect=slow_receipt),patch.object(guest,'execution_root',return_value=root),\
                     patch.object(guest,'boot_id',return_value='boot'),patch.object(guest,'restart_lock',return_value=nullcontext()),\
                     patch.object(guest,'primary_pins',return_value={}),patch.object(guest.time,'monotonic',side_effect=lambda:current[0]),patch.object(guest,'run') as runner:
                    with self.assertRaises(ValueError):guest.stop_primary({'operationId':'a'*64})
                    runner.assert_not_called()

    def test_critical_commands_and_lock_acquisition_have_whole_deadlines(self):
        with patch.object(guest.time,'monotonic',return_value=10):
            with guest.phase_deadline(12),patch.object(guest.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=b'ok')) as run:
                guest.run(['fixed'],timeout=30)
                self.assertEqual(run.call_args.kwargs['timeout'],2)
                with patch.object(guest.time,'monotonic',return_value=13):
                    with self.assertRaises(ValueError):guest.run(['must-not-start'])
                self.assertEqual(run.call_count,1)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                with guest.restart_lock(Path(directory),deadline=time.monotonic()-1):self.fail('expired lock entered')

    def test_clone_ready_retries_only_transient_observations(self):
        with patch.object(guest,'verify_clone',side_effect=[guest.ReadinessPending('starting'),{'held':True}]) as verify,patch.object(guest.time,'sleep'):
            self.assertEqual(guest.await_clone_ready({},1),{'held':True})
            self.assertEqual(verify.call_count,2)
        with patch.object(guest,'verify_clone',side_effect=ValueError('config changed')) as verify:
            with self.assertRaisesRegex(ValueError,'config changed'):guest.await_clone_ready({},1)
            self.assertEqual(verify.call_count,1)
        clock=[0.0]
        def sleep(seconds):clock[0]+=seconds
        with patch.object(guest.time,'monotonic',side_effect=lambda:clock[0]),patch.object(guest.time,'sleep',side_effect=sleep),\
             patch.object(guest,'verify_clone',side_effect=guest.ReadinessPending('unavailable')):
            with self.assertRaisesRegex(ValueError,'readiness deadline'):guest.await_clone_ready({},0.5)
            self.assertEqual(clock[0],0.5)

    def test_snapshot_mismatched_clock_and_pins_rejected_before_write(self):
        with patch.object(snapshot.time,'time',return_value=100):
            with self.assertRaises(ValueError):snapshot.assemble({'epoch':80},{'epoch':100},{})
        self.assertNotIn('resume',Path(HERE/'apply-dashboard-restore.py').read_text().split("choices=[",1)[1].split(']',1)[0])


if __name__=='__main__':unittest.main()
