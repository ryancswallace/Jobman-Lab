#!/usr/bin/env python3
"""Offline watchdog proof guards. Never invokes SSH/systemd/SQL."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def load(name,file,extra=None):
    module=types.ModuleType(name);module.__file__=str(HERE/file)
    if extra:module.__dict__.update(extra)
    exec(compile((HERE/file).read_text(),str(HERE/file),'exec'),module.__dict__);return module
p=load('watchdog_plan','dashboard-watchdog-plan.py')
f=load('fault_plan','dashboard-dependency-fault-plan.py')
g=load('fault_guest','dashboard-dependency-fault-guest.py',{'p':f})
r=load('original_restore','dashboard-restore-guest.py')
SOURCES={name:(HERE/name).read_text() for name in p.FILES[:2]+p.DEPS[:3]}
w=load('watchdog_guest','dashboard-watchdog-guest.py',{'p':p,'f':f,'g':g,'r':r,'SOURCES':SOURCES})
h=load('watchdog_host','dashboard-watchdog.py')

def fixture():
    processes={};pins={'configs':{},'processes':{}}
    for i,role in enumerate(('api','worker')):
        state={'unitSHA256':'a'*64,'active':True,'pid':str(100+i),'startedMonotonic':'100'}
        pins['configs'][role]='b'*64;pins['processes'][role]=state
        processes['jobman-dashboard-lab-'+role]={'pid':state['pid'],'start':'100','unitSHA256':'a'*64,
            'binarySHA256':'c'*64,'uid':21904+i,'binary':'/opt/jobman-dashboard-lab/releases/'+'d'*40+'/bin/jobman-dashboard','bootId':'boot','argumentsSHA256':'e'*64}
    return p.validate({'format':1,'synthetic':True,'scenario':p.SCENARIO,'operationId':'1'*64,'createdAt':1,
        'candidate':{'revision':'d'*40,'binarySHA256':'c'*64},'implementationSHA256':{n:p.sha((HERE/n).read_bytes()) for n in p.FILES+p.DEPS},
        'snapshot':{'storage01':{'host':'storage01','observedAt':1,'primaryPins':pins,'preserved':{'processes':processes},'objects':{'count':0}},
            'control01':{'host':'control01','observedAt':1,'preserved':{}},'pg01':{'host':'pg01','observedAt':1,'quiet':True,'database':{},'retained':{},'postgresProcess':'1 x','bootId':'boot'}}})

def restart(plan):
    states=copy.deepcopy(plan['snapshot']['storage01']['primaryPins']['processes'])
    for role,v in states.items():v['pid']=str(int(v['pid'])+100);v['startedMonotonic']='200'
    return {'primaryRestarted':True,'watchdogFired':True,'states':states,'operationId':plan['operationId'],'elapsedSinceArmSeconds':151.5}

class WatchdogTests(unittest.TestCase):
    def test_plan_has_no_clone_restore_or_arbitrary_units(self):
        plan=fixture();self.assertNotIn('clone',plan)
        for alter in (lambda v:v.update(scenario='isolated-dashboard-postgresql-restore'),lambda v:v.update(clone={}),
                      lambda v:v['snapshot']['storage01']['primaryPins']['processes'].update(other={}),
                      lambda v:v['candidate'].update(binarySHA256='f'*64),lambda v:v['snapshot']['pg01'].update(quiet=False)):
            bad=copy.deepcopy(plan);alter(bad)
            with self.assertRaises(ValueError):p.validate(bad)

    def test_restart_requires_real_fired_and_exact_new_processes(self):
        plan=fixture();good=restart(plan);self.assertEqual(p.restarted(plan,good),good)
        for alter in (lambda v:v.update(watchdogFired=False),lambda v:v.update(primaryRestarted=False),lambda v:v.update(operationId='2'*64),
                lambda v:v.update(elapsedSinceArmSeconds=149.9),lambda v:v.update(elapsedSinceArmSeconds=180.1),
                lambda v:v['states']['api'].update(pid='100'),lambda v:v['states']['worker'].update(startedMonotonic='100'),
                lambda v:v['states']['api'].update(unitSHA256='f'*64)):
            bad=copy.deepcopy(good);alter(bad)
            with self.assertRaises(ValueError):p.restarted(plan,bad)

    def test_preservation_allows_only_two_pids_and_start_times(self):
        plan=fixture();before=plan['snapshot']['storage01']['preserved'];after=copy.deepcopy(before);states=restart(plan)['states']
        for role,v in states.items():after['processes']['jobman-dashboard-lab-'+role].update(pid=v['pid'],start=v['startedMonotonic'])
        p.preserved_host(before,after,states)
        for key in ('uid','unitSHA256','binarySHA256','argumentsSHA256','bootId'):
            bad=copy.deepcopy(after);bad['processes']['jobman-dashboard-lab-api'][key]='changed'
            with self.assertRaises(ValueError):p.preserved_host(before,bad,states)

    def test_adapter_exact_payload_and_staged_plan(self):
        plan=fixture();value=w.payload(plan)
        with patch.object(w,'private_dir'),patch.object(r,'read',side_effect=[(p.encoded(plan),None),(p.encoded(w.intent(plan)),None)]):
            self.assertEqual(w.adapter(value),Path(p.BASE)/plan['operationId'])
        for change in (lambda v:v.update(objectHelperSHA256='a'*64),lambda v:v.update(passwords={}),lambda v:v.update(apply=False),lambda v:v.update(primaryPins={})):
            bad=copy.deepcopy(value);change(bad)
            with self.assertRaises(ValueError):w.adapter(bad)

    def test_timer_loader_uses_exact_original_module_and_is_bounded(self):
        data=p.loader(SOURCES);self.assertLess(len(data),1<<20);compile(data,'timer','exec')
        self.assertIn('r.restart_primary(value,fired=True)',SOURCES['dashboard-watchdog-guest.py'])
        self.assertEqual(SOURCES['dashboard-watchdog-guest.py'].count('r.restart_primary('),1)
        self.assertNotIn('r.complete_backup(',SOURCES['dashboard-watchdog-guest.py'])
        self.assertNotIn('r.restore_database(',SOURCES['dashboard-watchdog-guest.py'])
        for name in ('arm_backup','stop_primary','restart_lock','backup_window','restart_primary'):
            self.assertEqual(getattr(r,name).__module__,'original_restore')

    def test_actual_remote_bootstrap_rejects_host_before_effects(self):
        body=p.encoded({'sources':SOURCES,'hashes':{n:p.sha(v.encode()) for n,v in SOURCES.items()},
                        'request':{'phase':'snapshot','host':'not-a-host','candidate':fixture()['candidate']}})
        result=subprocess.run([sys.executable,'-c',h.BOOTSTRAP],input=body,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,1);value=json.loads(result.stdout)
        self.assertIn(value['code'],('linux_root_required','fixed_host_required'))
        self.assertEqual(result.stderr,b'')

    def test_tampered_embedded_module_fails_before_exec(self):
        hashes={n:p.sha(v.encode()) for n,v in SOURCES.items()};hashes['dashboard-restore-guest.py']='f'*64
        result=subprocess.run([sys.executable,'-c',h.BOOTSTRAP],input=p.encoded({'sources':SOURCES,'hashes':hashes,'request':{}}),capture_output=True,timeout=5)
        self.assertEqual(result.returncode,1);self.assertEqual(json.loads(result.stdout)['code'],'bootstrap_failed')

    def test_begin_arms_before_stop_and_never_restarts_on_failure(self):
        plan=fixture();order=[]
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            with patch.object(w,'no_other_timers'),patch.object(w,'operation_lock',return_value=__import__('contextlib').nullcontext()),patch.object(w,'adapter',return_value=Path(tmp)),\
                 patch.object(w.time,'time',return_value=2),patch.object(w,'compare'),patch.object(w,'snapshot'),\
                 patch.object(r,'put',side_effect=lambda *_:order.append('intent')),patch.object(r,'arm_backup',side_effect=lambda *_:order.append('arm')),\
                 patch.object(r,'stop_primary',side_effect=ValueError('lost_stop')) as stop,patch.object(r,'restart_primary') as restart_call:
                with self.assertRaises(ValueError):w.begin(plan)
                self.assertEqual(order,['intent','arm']);stop.assert_called_once();restart_call.assert_not_called()

    def test_begin_pending_blocks_all_effects(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);(root/'begin.pending.json').write_text('{}')
            with patch.object(w,'no_other_timers'),patch.object(w,'operation_lock',return_value=__import__('contextlib').nullcontext()),patch.object(w,'adapter',return_value=root),\
                 patch.object(w.time,'time',return_value=2),patch.object(r,'arm_backup') as arm,self.assertRaises(ValueError):w.begin(fixture())
            arm.assert_not_called()

    def test_stop_after_watchdog_disarm_is_refused_by_original(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);(root/'disarmed.json').write_text('{}')
            with patch.object(r,'execution_root',return_value=root),patch.object(r,'read',return_value=(p.encoded({'bootId':'x','restartAtMonotonic':150}),None)),\
                 patch.object(r,'boot_id',return_value='x'),patch.object(r.time,'monotonic',return_value=149),patch.object(r,'run') as run,self.assertRaises(ValueError):r.stop_primary({})
            run.assert_not_called()

    def test_timer_requires_unit_context_and_never_manual_restart(self):
        plan=fixture();value=w.payload(plan);value.pop('guestCode');value['phase']='watchdog';root=Path(p.BASE)/plan['operationId']
        with patch.object(w,'guard'),patch.object(w,'adapter',return_value=root),patch.object(r,'read',side_effect=[(p.encoded(value),None),(w.code(),None)]),\
             patch.object(w.sys,'argv',[str(root/'guest.py'),'--watchdog',str(root/'watchdog.json')]),patch.object(Path,'read_text',return_value='0::/user.slice\n'),\
             patch.dict(os.environ,{'INVOCATION_ID':'id'}),patch.object(r,'restart_primary') as restart_call,self.assertRaises(ValueError):w.timer_main(str(root/'watchdog.json'))
        restart_call.assert_not_called()

    def test_exact_timer_context_calls_only_fired_restart(self):
        plan=fixture();value=w.payload(plan);value.pop('guestCode');value['phase']='watchdog';root=Path(p.BASE)/plan['operationId']
        previous=r.execution_root
        try:
            with patch.object(w,'guard'),patch.object(w,'adapter',return_value=root),patch.object(r,'read',side_effect=[(p.encoded(value),None),(w.code(),None)]),\
                 patch.object(w.sys,'argv',[str(root/'guest.py'),'--watchdog',str(root/'watchdog.json')]),\
                 patch.object(Path,'read_text',return_value='0::/system.slice/'+r.watchdog_name(value)+'.service\n'),\
                 patch.dict(os.environ,{'INVOCATION_ID':'id'}),patch.object(r,'restart_primary',return_value=restart(plan)) as call:
                w.timer_main(str(root/'watchdog.json'));call.assert_called_once_with(value,fired=True)
        finally:r.execution_root=previous

    def test_status_never_claims_success_without_stopped_and_fired(self):
        plan=fixture()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);(root/'disarmed.json').write_text('{}')
            with patch.object(w,'adapter',return_value=root),patch.object(r,'read',return_value=(p.encoded(restart(plan)),None)),self.assertRaises(ValueError):w.status(plan)

    def test_status_only_reads_and_preserves_unknown_pending(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            with patch.object(w,'adapter',return_value=Path(tmp)),patch.object(r,'restart_primary') as restart_call,patch.object(r,'put') as put:
                value=w.status(fixture());self.assertFalse(value['restarted']);put.assert_not_called();restart_call.assert_not_called()

    def test_quiet_database_is_read_only_and_excludes_current_work(self):
        with patch.object(r,'sql',return_value='t') as sql:self.assertTrue(w.quiet_database())
        query=sql.call_args.args[0];self.assertIn('BEGIN READ ONLY',query)
        for table in ('dashboard_report_tasks','dashboard_notification_evaluations','dashboard_notification_fanout','dashboard_notification_deliveries','dashboard_notification_rules'):self.assertIn(table,query)
        with patch.object(r,'sql',return_value='f'),self.assertRaises(ValueError):w.quiet_database()

    def test_host_pending_written_before_remote_no_uncertain_retry(self):
        plan=fixture()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);h.h.save(root/'stage.json',{'staged':True,'operationId':plan['operationId']})
            args=types.SimpleNamespace(phase='begin',staging=root,lab_root=Path('/unused'),apply=True,expected_plan_sha256='a'*64)
            def remote(*_):self.assertTrue((root/'begin.pending.json').exists());raise ValueError('lost')
            with patch.object(h,'read_plan',return_value=(plan,{})),patch.object(h,'no_other_operations'),patch.object(h.time,'time',return_value=2),\
                 patch.object(h,'verify_external'),patch.object(h,'remote',side_effect=remote) as called:
                for _ in range(2):
                    with self.assertRaises(ValueError):h.phase(args)
                called.assert_called_once()

    def test_no_remote_restart_restore_hold_or_cancel_routes(self):
        for name in ('restart','recover','restore','resume','cancel'):
            with self.assertRaises(ValueError):h.remote(Path('/unused'),{'phase':name}, {})

    def test_source_and_pg_verification_both_required(self):
        args=types.SimpleNamespace(lab_root=Path('/unused'));hosts=[]
        def remote(_,request,__):hosts.append(request['host']);return {'host':request['host'],'preserved':True}
        with patch.object(h,'remote',side_effect=remote):h.verify_external(args,fixture(),{})
        self.assertEqual(hosts,['control01','pg01'])


    def test_original_watchdog_failed_completion_retains_fired_and_no_acceptance(self):
        plan=fixture();value=w.payload(plan);value.pop('guestCode');value['phase']='watchdog'
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);armed={'operationId':plan['operationId'],'bootId':'boot','armedMonotonic':0,'restartAtMonotonic':150}
            (root/'armed.json').write_bytes(p.encoded(armed));(root/'stopped.json').write_bytes(p.encoded({'operationId':plan['operationId']}))
            original_read=r.read
            def read(path,*_,**__):return (Path(path).read_bytes(),None)
            def put(path,raw,*_,**__):Path(path).write_bytes(raw)
            with patch.object(r,'execution_root',return_value=root),patch.object(r,'read',side_effect=read),patch.object(r,'put',side_effect=put),\
                 patch.object(r,'boot_id',return_value='boot'),patch.object(r.time,'monotonic',return_value=151),\
                 patch.object(r,'restart_lock',return_value=__import__('contextlib').nullcontext()),\
                 patch.object(r,'primary_pins',side_effect=[{},ValueError('transitional_identity')]),patch.object(r,'run') as run:
                with self.assertRaises(ValueError):r.restart_primary(value,fired=True)
                self.assertEqual(run.call_args.args[0],['systemctl','start',r.UNIT['api'],r.UNIT['worker']]);run.assert_called_once()
            self.assertTrue((root/'fired.json').exists());self.assertFalse((root/'disarmed.json').exists())
            with patch.object(w,'adapter',return_value=root),patch.object(r,'read',side_effect=read),patch.object(r,'boot_id',return_value='boot'),\
                 patch.object(r,'restart_primary') as restart_call:
                result=w.status(plan);self.assertTrue(result['fired']);self.assertFalse(result['restarted']);restart_call.assert_not_called()

    def test_host_lost_begin_response_has_no_restart_or_retry(self):
        # The exact host route test above proves the receipt precedes transport.
        # Its only next legal path is status, which cannot invoke begin/restart.
        plan=fixture();args=types.SimpleNamespace(phase='status',staging=Path('/unused'),lab_root=Path('/unused'),apply=False)
        with patch.object(h,'read_plan',return_value=(plan,{})),patch.object(h,'remote',return_value={'armed':True,'restarted':False}) as remote:
            value=h.phase(args);self.assertFalse(value['restarted']);self.assertEqual(remote.call_args.args[1]['phase'],'status')

    def test_pg_snapshot_preserves_exact_go_or_iso_process_time(self):
        valid=['11996 2026-08-31 21:00:39.957135268 +0200 CEST',
               '11996 2026-08-31T19:00:39.957135268Z','11996 2026-08-31T21:00:39+02:00']
        with patch.object(w,'guard'),patch.object(g,'database',return_value={}),\
             patch.object(r,'retained_identities',return_value={}),patch.object(w,'quiet_database',return_value=True),\
             patch.object(r,'boot_id',return_value='boot'):
            for raw in valid:
                with patch.object(g,'run',return_value=(raw+'\n').encode()) as run:
                    result=w.snapshot('pg01',fixture()['candidate'])
                    self.assertEqual(result['postgresProcess'],raw)
                    self.assertEqual(run.call_args.args[0],['podman','inspect','--format','{{.State.Pid}} {{.State.StartedAt}}','jobman-postgres'])
            for raw in ['0 2026-08-31T19:00:39Z','01 2026-08-31T19:00:39Z',
                        '11996 2026-02-30T19:00:39Z','11996 2026-08-31 25:00:39.1 +0200 CEST',
                        '11996 2026-08-31 21:00:39.1234567890 +0200 CEST',
                        '11996 2026-08-31 21:00:39.1 +2500 CEST',
                        '11996 2026-08-31 21:00:39.1 +0260 CEST','11996 2026-08-31T21:00:39+02:60',
                        '11996 2026-08-31 21:00:39.1 +0200 CEST extra',
                        '11996 2026-08-31T19:00:39','2147483648 2026-08-31T19:00:39Z']:
                with patch.object(g,'run',return_value=raw.encode()),patch.object(g,'database') as database:
                    with self.assertRaisesRegex(ValueError,'postgres_process'):w.snapshot('pg01',fixture()['candidate'])
                    database.assert_not_called()

    def test_watchdog_uses_relocated_registry_and_refuses_active_or_drifted_records(self):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as name,\
             tempfile.TemporaryDirectory(dir=Path('/tmp').resolve(),prefix='jobman-dashboard-fault-records-') as rec:
            lab=Path(name);home=lab/'.lab/dashboard';home.mkdir(parents=True,mode=0o700);home.chmod(0o700)
            args=types.SimpleNamespace(lab_root=lab,records_root=Path(rec),apply=True)
            h.h.prepare_records(args)
            # The deliberately incomplete legacy guard still blocks frozen old
            # code, but a valid current binding selects the private registry.
            h.no_other_operations(lab)
            legacy=home/'dependency-fault-operations'/h.h.RECORDS_GUARD
            self.assertFalse((legacy/'complete.json').exists())
            operation=Path(rec)/'71000000-0000-4000-8000-000000000001';h.h.directory(operation,True)
            with self.assertRaisesRegex(ValueError,'another_fault_pending'):h.no_other_operations(lab)
            h.h.save(operation/'complete.json',{'closed':True});h.no_other_operations(lab)
            (home/h.h.RECORDS_BINDING).unlink()
            with self.assertRaisesRegex(ValueError,'records_setup_incomplete'):h.no_other_operations(lab)

    def test_snapshot_age_cannot_be_reset_by_new_prepare(self):
        plan=fixture();plan['createdAt']=902
        with self.assertRaises(ValueError):p.validate(plan)

    def retired_fixture(self, root):
        plan=fixture();plan['operationId']=root.name
        original={'plan.json':p.encoded(plan),'intent.json':p.encoded(w.intent(plan)),
                  'staged.json':p.encoded({'staged':True,'operationId':root.name})}
        tombstone={'operationId':root.name,'planSHA256':p.sha(original['plan.json']),
                   'outcome':'aborted_before_arm','accepted':False,
                   'failureEvidenceSHA256':'a'*64,'retirementProofSHA256':'b'*64}
        original['begin.pending.json']=p.encoded(tombstone)
        receipt={'format':1,'operationId':root.name,'outcome':'aborted_before_arm','accepted':False,
                 'originalSHA256':{n:p.sha(original[n]) for n in ('plan.json','intent.json','staged.json')},
                 'beginTombstoneSHA256':p.sha(original['begin.pending.json']),
                 'failureEvidenceSHA256':'a'*64,'retirementProofSHA256':'b'*64}
        original['aborted.json']=p.encoded(receipt)
        for name,raw in original.items():(root/name).write_bytes(raw)
        return original,receipt

    def test_staged_retirement_is_explicit_not_acceptance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/('2'*64);root.mkdir();raw,receipt=self.retired_fixture(root)
            with patch.object(w,'private_dir'),patch.object(r,'read',side_effect=lambda path,*a,**kw:(path.read_bytes(),None)):
                self.assertEqual(w.prior_operation_closed(root),receipt)
                self.assertFalse((root/'accepted.json').exists())
                for missing in ('aborted.json','begin.pending.json'):
                    (root/missing).unlink()
                    with self.assertRaises(ValueError):w.prior_operation_closed(root)
                    (root/missing).write_bytes(raw[missing])
                # A plain pending start, or a partial retirement, is never closure.
                (root/'begin.pending.json').write_bytes(p.encoded({'operationId':root.name,'planSHA256':receipt['originalSHA256']['plan.json']}))
                with self.assertRaises(ValueError):w.prior_operation_closed(root)

    def test_retirement_denies_any_timer_or_unknown_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/('2'*64);root.mkdir();self.retired_fixture(root)
            with patch.object(w,'private_dir'),patch.object(r,'read',side_effect=lambda path,*a,**kw:(path.read_bytes(),None)):
                for name in ('armed.json','stopped.json','fired.json','disarmed.json','watchdog.json','guest.py','accepted.json','unknown'):
                    (root/name).write_bytes(b'{}')
                    with self.assertRaisesRegex(ValueError,'retirement_artifacts'):w.aborted_operation(root)
                    (root/name).unlink()

    def test_retirement_requires_exact_canonical_proofs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/('2'*64);root.mkdir();raw,_=self.retired_fixture(root)
            changes={'aborted.json':({'accepted':True},{'accepted':0},{'format':True},{'originalSHA256':{}},{'beginTombstoneSHA256':'f'*64},{'unknown':True}),
                     'begin.pending.json':({'accepted':True},{'operationId':'3'*64},{'outcome':'accepted'},{'retirementProofSHA256':'x'}),
                     'staged.json':({'staged':False},{'staged':1}),
                     'intent.json':({'timerCodeSHA256':'x'},{'originalRestoreSHA256':'f'*64}),
                     'plan.json':({'operationId':'3'*64},)}
            with patch.object(w,'private_dir'),patch.object(r,'read',side_effect=lambda path,*a,**kw:(path.read_bytes(),None)):
                for name,variants in changes.items():
                    for change in variants:
                        value=p.decode(raw[name]);value.update(change);(root/name).write_bytes(p.encoded(value))
                        with self.assertRaises(ValueError):w.aborted_operation(root)
                        (root/name).write_bytes(raw[name])
                (root/'aborted.json').write_bytes(raw['aborted.json']+b' ')
                with self.assertRaisesRegex(ValueError,'retirement_original_changed'):w.aborted_operation(root)

    def test_retirement_tombstone_blocks_original_begin_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/('2'*64);root.mkdir();self.retired_fixture(root)
            with patch.object(w,'operation_lock',return_value=__import__('contextlib').nullcontext()),                 patch.object(w,'no_other_timers'),patch.object(w,'adapter',return_value=root),                 patch.object(w.time,'time',return_value=2),patch.object(r,'arm_backup') as arm,                 patch.object(r,'stop_primary') as stop:
                with self.assertRaisesRegex(ValueError,'uncertain_begin_no_retry'):w.begin(fixture())
                arm.assert_not_called();stop.assert_not_called()

    def test_stage_accepts_verified_retirement_but_not_partial_tombstone(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);old=base/('2'*64);old.mkdir();raw,_=self.retired_fixture(old)
            def read(path,*args,**kwargs):return path.read_bytes(),None
            def put(path,data):
                with path.open('xb') as stream:stream.write(data)
            with patch.object(p,'BASE',str(base)),patch.object(w,'private_dir'),                 patch.object(w,'operation_lock',return_value=__import__('contextlib').nullcontext()),                 patch.object(w,'no_other_timers'),patch.object(w.time,'time',return_value=2),                 patch.object(w,'compare'),patch.object(w,'snapshot'),patch.object(r,'read',side_effect=read),                 patch.object(r,'directory',side_effect=lambda path:Path(path).mkdir()),patch.object(r,'put',side_effect=put):
                (old/'aborted.json').unlink()
                with self.assertRaises(ValueError):w.stage(fixture())
                self.assertFalse((base/fixture()['operationId']).exists())
                (old/'aborted.json').write_bytes(raw['aborted.json'])
                result=w.stage(fixture());self.assertTrue(result['staged'])
                self.assertEqual(set(x.name for x in (base/fixture()['operationId']).iterdir()),{'plan.json','intent.json','staged.json'})
                self.assertEqual({n:(old/n).read_bytes() for n in raw},raw)

    def test_other_active_fault_or_restore_timer_prevents_stage(self):
        with patch.object(g,'run',return_value=b'jobman-dashboard-fault-old.timer loaded active waiting\n'),self.assertRaises(ValueError):w.no_other_timers()
        with patch.object(g,'run',return_value=b''):w.no_other_timers()

if __name__=='__main__':unittest.main()
