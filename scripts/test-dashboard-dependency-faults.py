#!/usr/bin/env python3
"""Offline regressions only: no Lab connection, systemd, or nftables mutation."""
import base64
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

p=load('dashboard-dependency-fault-plan'); g=load('dashboard-dependency-fault-guest'); h=load('dashboard-dependency-faults')
REV='a'*40; BOOT='78000000-0000-4000-8000-000000000001'; OP='78000000-0000-4000-8000-000000000002'; SHA='c'*64
UNIT='jobman-dashboard-lab-broker'
CONTROL='jobman-dashboard-lab-control'


def proc(uid=21901,pid='100',start='1000'):
    return {'pid':pid,'start':start,'bootId':BOOT,'uid':uid,'binary':'/opt/jobman-dashboard-lab/releases/'+REV+'/bin/jobman-log-broker',
            'binarySHA256':SHA,'unitSHA256':SHA,'argumentsSHA256':SHA}


def baseline(scenario='broker'):
    db={'schemaSHA256':SHA,'rolesSHA256':SHA,'databaseOID':'20000','hold':{'held':False,'generation':'3','suppressRecordedThrough':None},'sources':[]}
    for dep,instance in p.SOURCE_IDS.items():
        db['sources'].append({'deploymentId':dep,'controlInstanceId':instance,'recoveryEpoch':'1','configurationRevision':8,
        'namespaceIds':['78000000-0000-4000-8000-000000000010'],'status':'active','generation':'100','lastPosition':'1000','openGaps':0,'unfinishedRecoveries':0})
    control={'host':'control01','revision':REV,'bootId':BOOT,'configurationRevisions':[8], 'preservedSHA256':SHA,'files':{},'capabilities':[],
      'processes':{UNIT:proc(),'jobman-dashboard-lab-directory':proc(21902),CONTROL:proc(21902)},'firewallSHA256':None}
    storage=dict(copy.deepcopy(control),host='storage01',processes={'jobman-dashboard-lab-api':proc(21904),'jobman-dashboard-lab-worker':proc(21905)},firewallSHA256=SHA)
    snapshot={'control01':control,'storage01':storage,'pg01':{'database':db}}
    return p.make(snapshot,scenario,OP,REV,{n:SHA for n in p.IMPLEMENTATION},int(time.time()))


def table(plan,fault,packets=0):
    rows=copy.deepcopy(p.firewall_elements(plan['operationId'],fault))
    for index,item in enumerate(rows): next(iter(item.values()))['handle']=index+1
    rows[-1]['rule']['expr'][-2]['counter']={'packets':packets,'bytes':packets*80}
    return {'nftables':[{'metainfo':{'version':'synthetic'}}]+rows}


class PlanTests(unittest.TestCase):
    def test_reconstruct_and_monotonic_progress(self):
        plan=baseline(); p.validate(plan)
        before=plan['snapshot']['pg01']['database']; after=copy.deepcopy(before)
        after['sources'][0]['generation']='101'; after['sources'][1]['lastPosition']='1002'; p.database_preserved(before,after)
        for field,value in [('generation','99'),('lastPosition','999'),('recoveryEpoch','2'),('configurationRevision',9),('namespaceIds',[])]:
            changed=copy.deepcopy(before); changed['sources'][0][field]=value
            with self.assertRaises(ValueError): p.database_preserved(before,changed)
    def test_hold_identity_and_incomplete_recovery_rejected(self):
        for path,value in [('held',True),('generation','4')]:
            before=baseline()['snapshot']['pg01']['database']; after=copy.deepcopy(before); after['hold'][path]=value
            with self.assertRaises(ValueError): p.database_preserved(before,after)
        for field,value in [('openGaps',1),('unfinishedRecoveries',1),('status','paused'),('controlInstanceId',OP)]:
            plan=baseline(); plan['snapshot']['pg01']['database']['sources'][0][field]=value
            with self.assertRaises(ValueError): p.validate(plan)
    def test_json_duplicate_nonfinite_rejected(self):
        for raw in ('{"x":1,"x":2}','{"x":NaN}'):
            with self.assertRaises(ValueError): p.decode(raw)
    def test_atomic_firewall_is_exactly_two_uids_one_destination(self):
        plan=baseline('database')
        for fault in plan['faults']:
            batch=p.decode(p.firewall_batch(OP,fault))
            self.assertEqual([list(v) for v in batch['nftables']],[['create'],['create'],['add']])
            self.assertEqual(batch['nftables'][2]['add']['rule']['expr'][-2],{'counter':{'packets':0,'bytes':0}})
            self.assertEqual(g.normalize_nft([next(iter(v.values())) for v in batch['nftables']]),p.firewall_elements(OP,fault))
            g.validate_table(table(plan,fault,5),plan,fault)
            for path in ('uid','destination','port','rule','chain'):
                bad=table(plan,fault)
                rule=bad['nftables'][-1]['rule']
                if path=='uid':rule['expr'][0]['match']['right']['set'].append(0)
                elif path=='destination':rule['expr'][1]['match']['right']='0.0.0.0/0'
                elif path=='port':rule['expr'][2]['match']['right']=22
                elif path=='rule':bad['nftables'].append(copy.deepcopy(bad['nftables'][-1]))
                else:bad['nftables'][2]['chain']['policy']='drop'
                with self.assertRaises(ValueError):g.validate_table(bad,plan,fault)
    def test_shared_nft_counters_only_may_change(self):
        a={'nftables':[{'rule':{'expr':[{'counter':{'packets':0,'bytes':0}},{'drop':None}],'handle':1}}]}
        b=copy.deepcopy(a);b['nftables'][0]['rule']['expr'][0]['counter']['packets']=999
        self.assertEqual(g.normalize_nft(a),g.normalize_nft(b))
        b['nftables'][0]['rule']['expr'][-1]={'accept':None}
        self.assertNotEqual(g.normalize_nft(a),g.normalize_nft(b))
    def test_existing_firewall_metadata_is_preserved_with_or_without_fault_table(self):
        existing={'nftables':[{'metainfo':{'version':'synthetic'}},
          {'table':{'family':'inet','name':'existing','handle':1,'comment':'preserved'}},
          {'chain':{'family':'inet','table':'existing','name':'output','type':'filter','hook':'output','prio':0,'policy':'accept','handle':2}}]}
        def digest(value,operation=None):
            with patch.object(g,'run',return_value=p.encoded(value)):
                return g.firewall_preserved(operation)
        baseline=digest(existing)
        self.assertEqual(baseline,digest(existing,OP))
        active=copy.deepcopy(existing)
        active['nftables']+=copy.deepcopy(p.firewall_elements(OP,'database_reject'))
        self.assertEqual(baseline,digest(active,OP))
        self.assertNotEqual(baseline,digest(active))
        for field,value in [('name','different'),('comment','changed'),('family','ip')]:
            changed=copy.deepcopy(existing);changed['nftables'][1]['table'][field]=value
            self.assertNotEqual(baseline,digest(changed,OP))
        same_name_other_family=copy.deepcopy(existing)
        same_name_other_family['nftables'].append({'table':{'family':'ip','name':p.table_name(OP)}})
        self.assertNotEqual(baseline,digest(same_name_other_family,OP))
    def test_watchdog_policy_honors_existing_stop_timeout(self):
        self.assertEqual(p.FAULTS['broker_stop']['watchdogSeconds'],120)
        self.assertGreaterEqual(p.FAULTS['broker_stop']['applyReserveSeconds'],100)
        self.assertEqual(p.FAULTS['broker_pause']['watchdogSeconds'],45)


class PrimitiveTests(unittest.TestCase):
    def test_new_private_file_ignores_restrictive_umask(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw).resolve()/'private'; before=os.umask(0o777)
            try:g.put(path,b'only synthetic fixture')
            finally:os.umask(before)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            with self.assertRaises(FileExistsError):g.put(path,b'overwrite')
            self.assertEqual(path.read_bytes(),b'only synthetic fixture')
    def test_host_refuses_symlink_fifo_and_existing_mode_drift(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve(); item=root/'regular';item.write_bytes(b'test');item.chmod(0o640)
            with self.assertRaises(ValueError):h.read(item)
            item.chmod(0o600);self.assertEqual(h.read(item),b'test')
            link=root/'link';link.symlink_to(item)
            with self.assertRaises(OSError):h.read(link)
            fifo=root/'fifo';os.mkfifo(fifo,0o600)
            start=time.monotonic()
            with self.assertRaises(ValueError):h.read(fifo)
            self.assertLess(time.monotonic()-start,1)
    def test_bounded_child_deadline_and_output(self):
        start=time.monotonic()
        with self.assertRaises(ValueError):g.run([sys.executable,'-c','import time;time.sleep(3)'],'synthetic_deadline',timeout=.05)
        self.assertLess(time.monotonic()-start,1)
        with self.assertRaises(ValueError):g.run([sys.executable,'-c','print("a"*100000)'],'synthetic_output',maximum=128)
    def test_shared_remaining_deadline(self):
        with g.bounded(.01):
            time.sleep(.02)
            with self.assertRaises(ValueError):g.run([sys.executable,'-c','print(1)'],'synthetic')
    def test_remote_phase_allowlist_and_real_runner(self):
        # Real bounded subprocess / stdin JSON path, without any SSH executable.
        with tempfile.TemporaryDirectory() as raw:
            driver=Path(raw).resolve()/'child.py';driver.write_text('import json,sys\nx=json.load(sys.stdin)\nassert x["phase"]=="database-check"\nprint(json.dumps({"ok":True,"result":{"preserved":True}}))\n')
            with patch.object(h,'ssh_args',return_value=[sys.executable,str(driver)]):
                result=h.remote(Path(raw).resolve(),{'phase':'database-check','host':'pg01'},h.implementation())
            self.assertEqual(result,{'preserved':True})
        with self.assertRaises(ValueError):h.remote(Path('/unused'),{'phase':'arbitrary','host':'pg01'},h.implementation())


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.base=Path(self.temp.name).resolve(); self.plan=baseline('database')
        self.root=self.base/OP/'database_reject'; self.root.mkdir(parents=True)
        self.commands=[];self.current=table(self.plan,'database_reject',4)
        self.stack=contextlib.ExitStack()
        for name,value in [('BASE',self.base),('locked',lambda **_:contextlib.nullcontext()),('verify_staged',lambda *_:None),('directory',lambda *_a,**_k:None),('target_pins',lambda *_:None),('read',lambda path,*_a,**_k:Path(path).read_bytes())]:
            self.stack.enter_context(patch.object(g,name,value))
        self.stack.enter_context(patch.object(g,'nft_table',lambda _:copy.deepcopy(self.current)))
        self.stack.enter_context(patch.object(g,'run',self.command))
        g.receipt(self.root,'intent',{'planSHA256':p.sha(p.encoded(self.plan)),'fault':'database_reject','createdAt':0})
        g.receipt(self.root,'firewall-intent',{'batchSHA256':p.sha(p.firewall_batch(OP,'database_reject')),'expected':p.firewall_elements(OP,'database_reject')})
    def tearDown(self):self.stack.close();self.temp.cleanup()
    def command(self,args,code,**_):
        self.commands.append(args)
        if args[:4]==['/usr/sbin/nft','delete','table','inet']:self.current=None
        return b''
    def test_lost_apply_receipt_still_restores_exact_predeclared_table(self):
        self.assertFalse((self.root/'firewall-applied.json').exists())
        result=g.recover(self.plan,'database_reject',watchdog=True)
        self.assertTrue(result['restored']);self.assertIsNone(self.current)
        self.assertEqual(len(self.commands),1);self.assertEqual(self.commands[0][-1],p.table_name(OP))
        self.assertTrue((self.root/'watchdog-complete.json').exists())
    def test_recovery_receipt_retry_preserves_initial_counter_evidence(self):
        g.receipt(self.root,'firewall-removal-proof',{'counter':{'packets':1,'bytes':80},'expectedSHA256':p.sha(p.encoded(p.firewall_elements(OP,'database_reject')))})
        g.recover(self.plan,'database_reject',watchdog=True)
        proof=p.decode((self.root/'firewall-removal-proof.json').read_bytes());self.assertEqual(proof['counter']['packets'],1)
    def test_firewall_drift_never_deletes_table(self):
        self.current['nftables'][-1]['rule']['expr'][0]['match']['right']['set']=[0]
        with self.assertRaises(ValueError):g.recover(self.plan,'database_reject',watchdog=True)
        self.assertEqual(self.commands,[]);self.assertFalse((self.root/'restored.json').exists())
    def test_restore_replay_is_observation_without_repeated_mutation(self):
        first=g.recover(self.plan,'database_reject',watchdog=True);second=g.recover(self.plan,'database_reject',watchdog=True)
        self.assertEqual(first,second);self.assertEqual(len(self.commands),1)
    def test_watchdog_wins_prevents_late_begin(self):
        g.recover(self.plan,'database_reject',watchdog=True)
        with self.assertRaises(ValueError):g.require_window(self.root,time.monotonic()+60,20)
        other=self.base/'absent'
        with self.assertRaises(ValueError):g.require_window(other,time.monotonic()+1,20)
    def test_earlier_recovery_updates_only_permitted_process_identity(self):
        plan=baseline();root=self.base/OP/'broker_stop';root.mkdir()
        new=proc(pid='101',start='1100')
        g.receipt(root,'restored',{'operationId':OP,'fault':'broker_stop','restored':True,'process':new})
        g.receipt(root,'watchdog-complete',{'restored':True})
        self.assertEqual(g.expected_processes(plan,'control01','broker_pause')[UNIT],new)
        value=p.decode((root/'restored.json').read_bytes());value['process']['binarySHA256']='b'*64;(root/'restored.json').write_bytes(p.encoded(value))
        with self.assertRaises(ValueError):g.expected_processes(plan,'control01','broker_pause')
    def test_wrong_process_never_receives_continue(self):
        plan=baseline(); plan['faults']=['broker_pause']; root=self.base/OP/'broker_pause';root.mkdir()
        g.receipt(root,'intent',{'planSHA256':p.sha(p.encoded(plan)),'fault':'broker_pause','createdAt':0})
        with patch.object(g,'expected_processes',return_value={UNIT:proc()}),patch.object(g,'process',return_value=proc(pid='999')),patch.object(g.os,'kill') as kill:
            with self.assertRaises(ValueError):g.recover(plan,'broker_pause',watchdog=True)
            kill.assert_not_called()
    def test_active_wrapper_converges_to_exact_final_identity_without_second_start(self):
        plan=baseline();root=self.base/OP/'broker_stop';root.mkdir()
        g.receipt(root,'intent',{'planSHA256':p.sha(p.encoded(plan)),'fault':'broker_stop','createdAt':0})
        g.receipt(root,'applied',{'fault':'broker_stop','atMonotonic':1})
        final=proc(pid='101',start='1100');wrapper=dict(final,binary='/usr/bin/python3',binarySHA256='d'*64,argumentsSHA256='e'*64)
        with patch.object(g,'expected_processes',return_value={UNIT:proc()}),patch.object(g,'properties',return_value={'ActiveState':'inactive'}),patch.object(g,'process',side_effect=[wrapper,final]) as observed,patch.object(g.time,'sleep'):
            result=g.recover(plan,'broker_stop',watchdog=True)
        self.assertEqual(result['process'],final);self.assertEqual(observed.call_count,2)
        self.assertEqual(self.commands,[['systemctl','start','--no-block',UNIT]])
        self.assertTrue((root/'restored.json').exists());self.assertTrue((root/'watchdog-complete.json').exists())
    def test_exact_identity_observed_after_deadline_cannot_create_success_receipt(self):
        plan=baseline();root=self.base/OP/'broker_stop';root.mkdir()
        g.receipt(root,'intent',{'planSHA256':p.sha(p.encoded(plan)),'fault':'broker_stop','createdAt':0})
        g.receipt(root,'applied',{'fault':'broker_stop','atMonotonic':1});clock=[100.0]
        def slow_process(_):clock[0]+=26;return proc(pid='101',start='1100')
        with patch.object(g,'expected_processes',return_value={UNIT:proc()}),patch.object(g,'properties',return_value={'ActiveState':'inactive'}),patch.object(g,'process',side_effect=slow_process),patch.object(g.time,'monotonic',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(ValueError,'operation_deadline'):g.recover(plan,'broker_stop',watchdog=True)
        self.assertEqual(self.commands,[['systemctl','start','--no-block',UNIT]])
        self.assertFalse((root/'restored.json').exists());self.assertFalse((root/'watchdog-complete.json').exists())
    def test_persistent_active_identity_mismatch_expires_without_restart_retry(self):
        for field,value in [('uid',0),('binary','/wrong'),('binarySHA256','d'*64),('argumentsSHA256','d'*64),('unitSHA256','d'*64),('bootId',OP),('start','1000')]:
            with self.subTest(field=field):
                plan=baseline();root=self.base/OP/'broker_stop'
                if root.exists():
                    for path in root.iterdir():path.unlink()
                else:root.mkdir()
                g.receipt(root,'intent',{'planSHA256':p.sha(p.encoded(plan)),'fault':'broker_stop','createdAt':0})
                g.receipt(root,'applied',{'fault':'broker_stop','atMonotonic':1})
                wrong=proc(pid='101',start='1100');wrong[field]=value;clock=[100.0];self.commands=[]
                def advance(_):clock[0]+=10
                with patch.object(g,'expected_processes',return_value={UNIT:proc()}),patch.object(g,'properties',return_value={'ActiveState':'inactive'}),patch.object(g,'process',return_value=wrong) as observed,patch.object(g.time,'sleep',side_effect=advance),patch.object(g.time,'monotonic',side_effect=lambda:clock[0]):
                    with self.assertRaisesRegex(ValueError,'operation_deadline'):g.recover(plan,'broker_stop',watchdog=True)
                self.assertGreater(observed.call_count,1)
                self.assertEqual(self.commands,[['systemctl','start','--no-block',UNIT]])
                self.assertFalse((root/'restored.json').exists());self.assertFalse((root/'watchdog-complete.json').exists())


class WatchdogTests(unittest.TestCase):
    def test_process_replacement_during_pause_intent_never_receives_signal(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw).resolve();plan=baseline();plan['faults']=['broker_pause'];(base/OP).mkdir()
            def directory(path,create=False):
                if create:path.mkdir()
                else:self.assertTrue(path.is_dir())
            with patch.object(g,'BASE',base),patch.object(g,'locked',return_value=contextlib.nullcontext()),patch.object(g,'directory',side_effect=directory),patch.object(g,'verify_staged'),patch.object(g,'unchanged'),patch.object(g,'arm_watchdog',return_value=time.monotonic()+45),patch.object(g,'target_pins'),patch.object(g,'process',side_effect=[proc(),proc(pid='999')]),patch.object(g.os,'kill') as kill:
                with self.assertRaisesRegex(ValueError,'pause_process_changed'):g.begin(plan,'broker_pause')
                kill.assert_not_called()
    def test_delayed_specific_intent_cannot_begin_late_stop_or_pause(self):
        for fault in ('broker_stop','broker_pause','control_pause'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as raw:
                base=Path(raw).resolve();plan=baseline('control' if fault=='control_pause' else 'broker');plan['faults']=[fault];(base/OP).mkdir()
                root=base/OP/fault;clock=[100.0];original_receipt=g.receipt
                def directory(path,create=False):
                    if create:path.mkdir()
                    else:self.assertTrue(path.is_dir())
                def slow_receipt(path,name,value):
                    original_receipt(path,name,value)
                    if name in ('stop-intent','pause-intent'):clock[0]+=p.FAULTS[fault]['watchdogSeconds']
                with patch.object(g,'BASE',base),patch.object(g,'locked',return_value=contextlib.nullcontext()),patch.object(g,'directory',side_effect=directory),patch.object(g,'verify_staged'),patch.object(g,'unchanged'),patch.object(g,'arm_watchdog',return_value=clock[0]+p.FAULTS[fault]['watchdogSeconds']),patch.object(g,'target_pins'),patch.object(g,'process',return_value=proc(p.FAULTS[fault]['uid'])),patch.object(g,'receipt',side_effect=slow_receipt),patch.object(g.time,'monotonic',side_effect=lambda:clock[0]),patch.object(g,'run') as command,patch.object(g.os,'kill') as kill:
                    with self.assertRaisesRegex(ValueError,'fault_window_expired'):g.begin(plan,fault)
                    command.assert_not_called();kill.assert_not_called()
                self.assertTrue((root/('stop-intent.json' if fault.endswith('_stop') else 'pause-intent.json')).exists())
                self.assertFalse((root/'applied.json').exists())
    def test_restore_between_ack_and_side_effect_prevents_late_stop(self):
        with tempfile.TemporaryDirectory() as raw:
            base=Path(raw).resolve(); plan=baseline(); (base/OP).mkdir(); root=base/OP/'broker_stop'
            def directory(path,create=False):
                if create: path.mkdir()
                else: self.assertTrue(path.is_dir())
            def restore(*_): g.receipt(root,'restored',{'restored':True})
            with patch.object(g,'BASE',base),patch.object(g,'locked',return_value=contextlib.nullcontext()),patch.object(g,'directory',side_effect=directory),patch.object(g,'verify_staged'),patch.object(g,'unchanged'),patch.object(g,'arm_watchdog',return_value=time.monotonic()+120),patch.object(g,'target_pins',side_effect=restore),patch.object(g,'run') as command:
                with self.assertRaisesRegex(ValueError,'fault_window_expired'):g.begin(plan,'broker_stop')
                command.assert_not_called()
                self.assertTrue((root/'intent.json').exists());self.assertFalse((root/'stop-intent.json').exists())
    def test_timer_acknowledgement_must_name_the_exact_service(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();plan=baseline();calls=[]
            def command(args,code,**_):
                calls.append(args)
                if args[0]=='systemd-run':return b''
                return b'ActiveState=active\nTriggers=wrong.service\n'
            with patch.object(g,'run',side_effect=command):
                with self.assertRaisesRegex(ValueError,'watchdog_not_armed'):g.arm_watchdog(plan,'broker_stop',root)
            self.assertIn('--property=Type=oneshot',calls[0]);self.assertIn('--on-active=120s',calls[0])
            self.assertFalse((root/'watchdog-armed.json').exists())
    def test_private_guest_script_is_hash_pinned_before_recovery(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();plan=baseline();(root/'plan.json').write_bytes(p.encoded(plan))
            with patch.object(g,'directory'),patch.object(g,'read',side_effect=lambda path,**_:Path(path).read_bytes()):
                for name in p.IMPLEMENTATION:(root/name).write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'staged_implementation_changed'):g.verify_staged(root,plan)


class HostStateTests(unittest.TestCase):
    def test_uncertain_begin_never_reissues_fault(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();plan=baseline();args=type('Args',(),dict(staging=root,phase='begin',fault='broker_stop',apply=True,lab_root=root,expected_plan_sha256=SHA))()
            h.save(root/'stage.json',{'staged':True,'operationId':OP,'host':'control01'})
            h.save(root/'broker_stop.pending.json',{'retained':True})
            with patch.object(h,'load_plan',return_value=(plan,{})),patch.object(h,'remote') as remote:
                with self.assertRaises(ValueError):h.phase(args)
                remote.assert_not_called()
    def test_begin_checks_database_before_admission_and_saves_intent_before_call(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();plan=baseline();args=type('Args',(),dict(staging=root,phase='begin',fault='broker_stop',apply=True,lab_root=root,expected_plan_sha256=SHA))()
            h.save(root/'stage.json',{'staged':True,'operationId':OP,'host':'control01'});phases=[]
            def remote(_lab,payload,_hashes):
                phases.append(payload['phase'])
                if payload['phase']=='begin':
                    self.assertTrue((root/'broker_stop.pending.json').exists());raise ValueError('uncertain')
                return {'preserved':True}
            with patch.object(h,'load_plan',return_value=(plan,{})),patch.object(h,'remote',side_effect=remote),patch.object(h,'operation_record'):
                with self.assertRaises(ValueError):h.phase(args)
            self.assertEqual(phases,['database-check','begin']);self.assertTrue((root/'broker_stop.pending.json').exists())


class ControlPauseTests(unittest.TestCase):
    def test_only_primary_control_and_fixed_watchdog_are_admitted(self):
        plan=baseline('control');p.validate(plan)
        self.assertEqual(plan['faults'],['control_pause'])
        self.assertEqual(p.FAULTS['control_pause'],{'host':'control01','unit':CONTROL,'uid':21902,'watchdogSeconds':45,'applyReserveSeconds':30})
        for uid in (0,21901,21907):
            wrong=copy.deepcopy(plan);wrong['snapshot']['control01']['processes'][CONTROL]['uid']=uid
            with self.assertRaisesRegex(ValueError,'fault_process_owner'):p.validate(wrong)
        wrong=copy.deepcopy(plan);wrong['faults']=['broker_pause']
        with self.assertRaises(ValueError):p.validate(wrong)

    def environment(self, base, stack):
        def directory(path,create=False):
            if create:path.mkdir()
            else:self.assertTrue(path.is_dir())
        for name,value in [('BASE',base),('locked',lambda **_:contextlib.nullcontext()),('directory',directory),('verify_staged',lambda *_:None),('read',lambda path,*_a,**_k:Path(path).read_bytes())]:
            stack.enter_context(patch.object(g,name,value))
        stack.enter_context(patch.object(g,'target_pins'))
        stack.enter_context(patch.object(g,'wait_state'))

    def test_acknowledged_timer_precedes_stop_and_recovery_uses_no_source_http(self):
        with tempfile.TemporaryDirectory() as raw,contextlib.ExitStack() as stack:
            base=Path(raw).resolve();(base/OP).mkdir();plan=baseline('control');root=base/OP/'control_pause';calls=[]
            self.environment(base,stack)
            stack.enter_context(patch.object(g,'unchanged'))
            stack.enter_context(patch.object(g,'source_capabilities',side_effect=AssertionError('paused source HTTP is forbidden')))
            stack.enter_context(patch.object(g,'host_snapshot',side_effect=AssertionError('recovery must not resnapshot HTTP')))
            def command(args,code,**_):
                calls.append(code)
                if code=='watchdog_ack':return ('ActiveState=active\nTriggers='+g.timer_name(plan,'control_pause')+'.service\n').encode()
                return b''
            stack.enter_context(patch.object(g,'run',side_effect=command))
            stack.enter_context(patch.object(g,'process',return_value=proc(21902)))
            def signal(pid,kind):
                self.assertEqual(pid,100);self.assertTrue((root/'watchdog-armed.json').exists())
                if kind==g.signal.SIGSTOP:
                    self.assertEqual(calls,['watchdog_arm','watchdog_ack']);self.assertTrue((root/'pause-intent.json').exists())
                calls.append(kind)
            stack.enter_context(patch.object(g.os,'kill',side_effect=signal))
            self.assertTrue(g.begin(plan,'control_pause')['applied'])
            result=g.recover(plan,'control_pause',watchdog=True)
            self.assertEqual(result['process'],proc(21902));self.assertTrue(result['restored'])
            self.assertEqual(calls,['watchdog_arm','watchdog_ack',g.signal.SIGSTOP,g.signal.SIGCONT])
            self.assertEqual(g.recover(plan,'control_pause',watchdog=True),result)
            self.assertEqual(calls.count(g.signal.SIGCONT),1)

    def test_real_target_guard_reads_only_primary_identity_and_material(self):
        plan=baseline('control');expected=plan['snapshot']['control01']['processes'][CONTROL];raw=b'exact guarded bytes'
        expected['unitSHA256']=expected['binarySHA256']=p.sha(raw)
        primary='/etc/jobman-dashboard-lab/control-fixture/control.env';secondary='/etc/jobman-dashboard-secondary/control/control.env'
        plan['snapshot']['control01']['files']={primary:p.sha(raw),secondary:p.sha(raw)};reads=[]
        def read(path,uid,mode=0o600,maximum=2<<20):
            reads.append((str(path),uid,mode));return raw
        with patch.object(g.Path,'read_text',return_value=BOOT),patch.object(g,'read',side_effect=read),patch.object(g,'properties'),patch.object(g,'source_capabilities',side_effect=AssertionError('no source HTTP')):
            g.target_pins(plan,'control_pause')
        self.assertEqual(reads,[('/etc/systemd/system/'+CONTROL+'.service',0,0o644),(expected['binary'],0,0o755),(primary,21902,0o600)])
        with patch.object(g.Path,'read_text',return_value=OP),patch.object(g,'read') as read:
            with self.assertRaisesRegex(ValueError,'boot_changed'):g.target_pins(plan,'control_pause')
            read.assert_not_called()

    def test_failed_timer_ack_never_signals(self):
        with tempfile.TemporaryDirectory() as raw,contextlib.ExitStack() as stack:
            base=Path(raw).resolve();(base/OP).mkdir();plan=baseline('control')
            self.environment(base,stack);stack.enter_context(patch.object(g,'unchanged'))
            stack.enter_context(patch.object(g,'run',return_value=b'ActiveState=inactive\nTriggers=wrong.service\n'))
            kill=stack.enter_context(patch.object(g.os,'kill'))
            with self.assertRaisesRegex(ValueError,'watchdog_not_armed'):g.begin(plan,'control_pause')
            kill.assert_not_called();self.assertFalse((base/OP/'control_pause'/'applied.json').exists())

    def test_identity_drift_before_either_signal_is_rejected(self):
        for phase in ('begin','recover'):
            for field,value in [('pid','999'),('start','999'),('bootId',OP),('uid',21907),('binary','/wrong'),('binarySHA256','d'*64),('unitSHA256','d'*64),('argumentsSHA256','d'*64)]:
                with self.subTest(phase=phase,field=field),tempfile.TemporaryDirectory() as raw,contextlib.ExitStack() as stack:
                    base=Path(raw).resolve();(base/OP).mkdir();plan=baseline('control');root=base/OP/'control_pause'
                    self.environment(base,stack);stack.enter_context(patch.object(g,'unchanged'))
                    stack.enter_context(patch.object(g,'arm_watchdog',return_value=time.monotonic()+45))
                    wrong=proc(21902);wrong[field]=value
                    stack.enter_context(patch.object(g,'process',side_effect=[proc(21902),wrong] if phase=='begin' else [wrong]))
                    kill=stack.enter_context(patch.object(g.os,'kill'))
                    if phase=='recover':
                        root.mkdir();g.receipt(root,'intent',{'planSHA256':p.sha(p.encoded(plan)),'fault':'control_pause','createdAt':0})
                    with self.assertRaises(ValueError):getattr(g,phase)(plan,'control_pause')
                    kill.assert_not_called();self.assertFalse((root/'restored.json').exists())

    def test_post_continue_identity_and_status_must_still_be_exact(self):
        with tempfile.TemporaryDirectory() as raw,contextlib.ExitStack() as stack:
            base=Path(raw).resolve();root=base/OP/'control_pause';root.mkdir(parents=True);plan=baseline('control')
            self.environment(base,stack)
            g.receipt(root,'intent',{'planSHA256':p.sha(p.encoded(plan)),'fault':'control_pause','createdAt':0})
            stack.enter_context(patch.object(g,'process',side_effect=[proc(21902),proc(21902,pid='999')]))
            kill=stack.enter_context(patch.object(g.os,'kill'))
            with self.assertRaisesRegex(ValueError,'continued_process_changed'):g.recover(plan,'control_pause')
            kill.assert_called_once_with(100,g.signal.SIGCONT)
            self.assertFalse((root/'restored.json').exists())

    def test_pause_status_is_local_exact_process_proof(self):
        with tempfile.TemporaryDirectory() as raw,contextlib.ExitStack() as stack:
            base=Path(raw).resolve();root=base/OP/'control_pause';root.mkdir(parents=True);plan=baseline('control')
            self.environment(base,stack)
            stack.enter_context(patch.object(g.os,'geteuid',return_value=0));stack.enter_context(patch.object(g.sys,'platform','linux'))
            stack.enter_context(patch.object(g.socket,'gethostname',return_value='control01'))
            stack.enter_context(patch.object(g,'run',return_value=b'ActiveState=inactive\nResult=success\n'))
            stack.enter_context(patch.object(g,'source_capabilities',side_effect=AssertionError('paused source HTTP is forbidden')))
            stack.enter_context(patch.object(g,'host_snapshot',side_effect=AssertionError('no HTTP resnapshot')))
            stack.enter_context(patch.object(g,'process',return_value=proc(21902)))
            payload={'host':'control01','phase':'status','fault':'control_pause','plan':plan}
            self.assertTrue(g.execute(payload)['paused'])
            g.receipt(root,'restored',{'operationId':OP,'fault':'control_pause','restored':True,'process':proc(21902)})
            self.assertFalse(g.execute(payload)['paused'])
            g.wait_state.assert_called_with('100',False)
            bad=p.decode((root/'restored.json').read_bytes());bad['process']['pid']='999'
            (root/'restored.json').write_bytes(p.encoded(bad))
            with self.assertRaisesRegex(ValueError,'control_restore_receipt_changed'):g.execute(payload)


if __name__=='__main__':unittest.main()
