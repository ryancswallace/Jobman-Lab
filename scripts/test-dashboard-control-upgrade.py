#!/usr/bin/env python3
"""Offline source-upgrade regressions; no SSH, service or SQL operations."""
import base64
import contextlib
import copy
import importlib.util
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
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
p=load('dashboard-control-upgrade-plan');g=load('dashboard-control-upgrade-guest');h=load('upgrade-dashboard-controls')
SHA='a'*64;OP='78000000-0000-4000-8000-000000000001';BOOT='78000000-0000-4000-8000-000000000002';REV='b'*40


def source_unit(profile):
    spec=p.PROFILES[profile]
    return ('[Unit]\nDescription=Synthetic\n[Service]\nType=simple\nUser='+spec['user']+'\nGroup='+spec['user']+'\nEnvironmentFile='+spec['root']+'/control.env\nExecStart='+spec['oldBinary']+'\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n').encode()


def fixture(profile='primary'):
    ledger=[{'name':'%06d_fixture.sql'%i,'sha256':SHA} for i in range(1,21)]+[{'name':'000021_monitoring_events.sql','sha256':SHA}]
    sources={}
    dashboard={'databaseOID':'100','schemaSHA256':SHA,'rolesSHA256':SHA,'hold':{'held':False,'generation':'5','suppressRecordedThrough':None},'sources':[]}
    for index,(name,spec) in enumerate(p.PROFILES.items(),1):
        sources[name]={'database':spec['database'],'oid':str(index),'instance':spec['instance'],'epoch':'1','ledger':ledger,
          'namespaces':{'count':spec['scopes'],'sha256':SHA},
          'scale':[{'name':'dashboard-scale-%02d'%i,'imported':10000,'accepted':50,'total':10050} for i in range(1,spec['scaleScopes']+1)],
          'jobs':{'count':spec['scaleScopes']*10050+20,'sha256':SHA},'runs':{'count':10,'sha256':SHA},
          'executions':{'count':10,'sha256':SHA},'terminalEvents':{'count':20,'sha256':SHA},'identitySHA256':SHA,'identityCounts':{key:5 for key in ('principals','accounts','aliases','bindings','grants','sources','delegationKeys')},
          'feed':{'head':'20','retired':'0','retention':'2592000'}}
        dashboard['sources'].append({'deploymentId':list(p.b.SOURCE_IDS)[index-1],'controlInstanceId':spec['instance'],'namespaceIds':[OP],
          'configurationRevision':8,'recoveryEpoch':'1','status':'active','generation':'100','lastPosition':'20','openGaps':0,'unfinishedRecoveries':0})
    selected=p.PROFILES[profile];unit=source_unit(profile)
    processes={spec['unit']:{'binary':spec['oldBinary'],'binarySHA256':p.OLD_SHA,'uid':spec['uid'],'pid':str(100+i),'start':'1000',
      'argumentsSHA256':p.sha((spec['oldBinary']+'\0').encode()),'unitSHA256':p.sha(source_unit(name)),'bootId':BOOT} for i,(name,spec) in enumerate(p.PROFILES.items())}
    files={'/etc/systemd/system/'+spec['unit']+'.service':p.sha(source_unit(name)) for name,spec in p.PROFILES.items()}
    control={'host':'control01','revision':REV,'files':files,'processes':processes,'configurationRevisions':[8],
      'capabilities':[{'instanceId':v['instance'],'recoveryEpoch':'1'} for v in p.PROFILES.values()],'bootId':BOOT,'firewallSHA256':None}
    control['preservedSHA256']=p.sha(p.encoded({k:control[k] for k in ('files','capabilities','configurationRevisions')}))
    storage={'host':'storage01','revision':REV,'processes':{},'files':{},'configurationRevisions':[8,8],'capabilities':[],
      'bootId':BOOT,'firewallSHA256':SHA,'preservedSHA256':SHA}
    snapshot={'control01':{'profile':profile,'baseline':control,'inventory':{'fixture':SHA},'unit':base64.b64encode(unit).decode()},
      'storage01':storage,'pg01':{'dashboard':dashboard,'sources':sources}}
    candidate={'revision':p.NEW,'sha256':p.NEW_SHA,'platform':'linux/arm64','toolchain':'go1.26.6','bytes':100,
      'buildInformationSHA256':SHA,'path':p.BINARY_ROOT+'/'+p.NEW_SHA+'/jobman-control'}
    return p.make(snapshot,profile,candidate,ledger,{name:SHA for name in p.FILES},OP,int(time.time()))


class PlanTests(unittest.TestCase):
    def test_exact_one_execstart_change_for_both_sources(self):
        for profile in p.PROFILES:
            plan=fixture(profile);p.validate(plan)
            before=p.unb64(plan['snapshot']['control01']['unit']);after=p.unb64(plan['afterUnit'])
            self.assertEqual(after,before.replace(p.PROFILES[profile]['oldBinary'].encode(),plan['candidate']['path'].encode(),1))
            for bad in (before.replace(b'ExecStart=',b'ExecStartPre='),before+before,before.replace(b'Type=simple',b'Type=forking'),before.replace(b'\nRestart=',b' --unsafe\nRestart=')):
                with self.assertRaises(ValueError):p.transform_unit(profile,bad,plan['candidate']['path'])
    def test_real_scale_bounds_reject_old_small_fixture_or_changed_schema(self):
        plan=fixture();value=plan['snapshot']['pg01']['sources']['primary'];p.source_database(value,'primary',plan['ledger'])
        self.assertGreater(value['jobs']['count'],100000)
        for key,change in [('epoch','2'),('instance',OP),('ledger',plan['ledger'][:-1]),('namespaces',{'count':11,'sha256':SHA}),('scale',[])]:
            bad=copy.deepcopy(value);bad[key]=change
            with self.assertRaises(ValueError):p.source_database(bad,'primary',plan['ledger'])
    def test_candidate_pins_architecture_metadata_and_full_reviewed_digest(self):
        binary=bytearray(32);binary[:6]=b'\x7fELF\x02\x01';binary[18:20]=(183).to_bytes(2,'little')
        binary.extend(p.NEW.encode()+b'\0dashboard-lab-'+p.NEW[:12].encode());binary=bytes(binary)
        info='fixture: go1.26.6\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=arm64\n\tbuild\tCGO_ENABLED=0\n'
        metadata={'revision':p.NEW,'binarySHA256':p.sha(binary),'os':'linux','architecture':'arm64','twiceIdentical':True,'version':'dashboard-lab-'+p.NEW[:12]}
        with patch.object(p,'NEW_SHA',p.sha(binary)):
            self.assertEqual(p.candidate(metadata,binary,info)['revision'],p.NEW)
            for bad in (binary[:-1],b'not-elf'+binary[7:]):
                with self.assertRaises(ValueError):p.candidate(metadata,bad,info)
            with self.assertRaises(ValueError):p.candidate(metadata,binary,info+'vcs.modified=true')
            with self.assertRaises(ValueError):p.candidate(dict(metadata,revision=p.OLD),binary,info)
    def test_identity_catalog_bounds_are_explicit(self):
        plan=fixture();value=copy.deepcopy(plan['snapshot']['pg01']['sources']['primary'])
        value['identityCounts']['accounts']=1001
        with self.assertRaisesRegex(ValueError,'source_identity_count'):p.source_database(value,'primary',plan['ledger'])
        value['identityCounts']['accounts']=10;value['identityCounts']['grants']=20001
        with self.assertRaisesRegex(ValueError,'source_identity_count'):p.source_database(value,'primary',plan['ledger'])
    def test_new_process_may_change_only_the_exact_selected_process(self):
        plan=fixture();current=copy.deepcopy(plan['snapshot']['control01']['baseline']);spec=p.PROFILES['primary']
        current['files']['/etc/systemd/system/'+spec['unit']+'.service']=plan['afterUnitSHA256']
        process=current['processes'][spec['unit']];process.update(binary=plan['candidate']['path'],binarySHA256=p.NEW_SHA,pid='900',start='1100',unitSHA256=plan['afterUnitSHA256'],argumentsSHA256=p.sha((plan['candidate']['path']+'\0').encode()))
        current['preservedSHA256']=p.sha(p.encoded({k:current[k] for k in ('files','capabilities','configurationRevisions')}))
        p.host_preserved(plan,'control01',current,True,True)
        for field,value in [('uid',0),('binarySHA256',SHA),('argumentsSHA256',SHA),('bootId',OP),('start','1000')]:
            bad=copy.deepcopy(current);bad['processes'][spec['unit']][field]=value
            with self.assertRaises(ValueError):p.host_preserved(plan,'control01',bad,True,True)
        current['processes'][p.PROFILES['secondary']['unit']]['pid']='999'
        with self.assertRaises(ValueError):p.host_preserved(plan,'control01',current,True,True)
    def test_database_allows_monotonic_progress_not_data_or_hold_changes(self):
        plan=fixture();value=copy.deepcopy(plan['snapshot']['pg01'])
        value['dashboard']['sources'][0]['generation']='101';value['sources']['primary']['feed']['head']='21'
        with patch.object(g,'databases',return_value=value):g.check_databases(plan)
        for path in ('data','head','hold'):
            value=copy.deepcopy(plan['snapshot']['pg01'])
            if path=='data':value['sources']['primary']['jobs']['sha256']='b'*64
            elif path=='head':value['sources']['primary']['feed']['head']='19'
            else:value['dashboard']['hold']['held']=True
            with patch.object(g,'databases',return_value=value),self.assertRaises(ValueError):g.check_databases(plan)


class GuestTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.plan=fixture();self.commands=[]
        self.stack=contextlib.ExitStack()
        for name,value in [('locked',lambda:contextlib.nullcontext()),('open_operation',lambda *_a,**_k:self.root),('authority',lambda *_a,**_k:None),('verify_candidate',lambda *_:None),('loaded_command',lambda *_:None)]:self.stack.enter_context(patch.object(g,name,value))
        self.stack.enter_context(patch.object(g.f,'read',side_effect=lambda path,*_a,**_k:Path(path).read_bytes()))
        self.stack.enter_context(patch.object(g.f,'run',side_effect=lambda args,*_a,**_k:self.commands.append(args) or b''))
    def tearDown(self):self.stack.close();self.temp.cleanup()
    def test_uncertain_restart_never_reissues_manager_request(self):
        g.marker(self.root,'applied',{'synthetic':True})
        with patch.object(g,'wait_ready',side_effect=ValueError('uncertain')):
            with self.assertRaises(ValueError):g.restart(self.plan)
        self.assertEqual(self.commands,[['systemctl','restart','--no-block',p.PROFILES['primary']['unit']]])
        with self.assertRaisesRegex(ValueError,'uncertain_restart_requires_observation'):g.restart(self.plan)
        self.assertEqual(len(self.commands),1)
    def test_observation_recovers_only_already_applied_or_restarted_proof(self):
        g.marker(self.root,'apply-intent',{'synthetic':True})
        self.assertTrue(g.observe(self.plan)['applied']);self.assertEqual(self.commands,[])
        g.marker(self.root,'restart-intent',{'synthetic':True})
        with patch.object(g.f,'process',return_value={'synthetic':'verified'}):self.assertTrue(g.observe(self.plan)['restarted'])
        self.assertEqual(self.commands,[])
    def test_lost_stage_reply_observes_only_a_completed_stage(self):
        g.marker(self.root,'stage-intent',{'synthetic':True})
        with self.assertRaisesRegex(ValueError,'stage_not_completed'):g.observe(self.plan)
        expected={'staged':True,'operationId':OP,'candidateSHA256':p.NEW_SHA}
        g.marker(self.root,'staged',expected)
        self.assertEqual(g.observe(self.plan),expected);self.assertEqual(self.commands,[])
    def test_restart_receipt_uses_validated_process_without_later_re_read(self):
        g.marker(self.root,'applied',{'synthetic':True})
        expected={'verified':'same-observation'}
        with patch.object(g,'wait_ready',return_value=expected),patch.object(g.f,'process',side_effect=AssertionError('unverified reread')):
            self.assertEqual(g.restart(self.plan)['process'],expected)
        self.assertEqual(len(self.commands),1)
    def test_pending_stage_does_not_adopt_incomplete_binary(self):
        g.marker(self.root,'stage-intent',{'synthetic':True})
        catalog=self.root/'catalog';catalog.mkdir(mode=0o700)
        with patch.object(g,'BASE',catalog),self.assertRaisesRegex(ValueError,'uncertain_stage_requires_inspection'):
            plan=copy.deepcopy(self.plan);plan['candidate']['sha256']=p.sha(b'fixture');plan['candidate']['bytes']=7;g.stage(plan,b'fixture')
        self.assertEqual(self.commands,[])
    def test_identity_wait_rejects_late_success_under_same_budget(self):
        clock=[100.0]
        def late(*_a,**_k):clock[0]+=121
        with patch.object(g,'authority',side_effect=late),patch.object(g.time,'monotonic',side_effect=lambda:clock[0]),self.assertRaisesRegex(ValueError,'operation_deadline'):g.wait_ready(self.plan)
        self.assertEqual(self.commands,[])
    def test_identity_wait_polls_without_restarting(self):
        with patch.object(g,'authority',side_effect=[ValueError('temporary'),None]) as checks,patch.object(g.time,'sleep'):
            g.wait_ready(self.plan)
        self.assertEqual(checks.call_count,2);self.assertEqual(self.commands,[])


class HostTests(unittest.TestCase):
    def test_new_lock_mode_and_existing_wrong_type_are_not_repaired(self):
        with tempfile.TemporaryDirectory() as raw:
            lab=Path(raw).resolve();parent=lab/'.lab/dashboard';parent.mkdir(parents=True,mode=0o700)
            before=os.umask(0o777)
            try:
                with h.locked(lab):pass
            finally:os.umask(before)
            lock=parent/'.control-binary-upgrade.lock';self.assertEqual(stat.S_IMODE(lock.stat().st_mode),0o600)
            lock.chmod(0o640)
            with self.assertRaises(ValueError):
                with h.locked(lab):pass
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode),0o640)
            lock.unlink();os.mkfifo(lock,0o600)
            with self.assertRaises(ValueError):
                with h.locked(lab):pass
    def test_remote_phase_uses_real_bounded_transport_and_sanitized_errors(self):
        with tempfile.TemporaryDirectory() as raw:
            child=Path(raw).resolve()/'child.py';child.write_text('import json,sys\nx=json.load(sys.stdin)\nassert x["phase"]=="authority"\nprint(json.dumps({"ok":True,"result":{"preserved":True}}))\n')
            with patch.object(h.h,'ssh_args',return_value=[sys.executable,str(child)]):
                self.assertEqual(h.remote(Path(raw),{'phase':'authority','host':'pg01'},h.implementation()),{'preserved':True})
            with self.assertRaises(ValueError):h.remote(Path(raw),{'phase':'migration','host':'pg01'},h.implementation())
    def test_host_pending_barrier_prevents_second_mutation(self):
        with tempfile.TemporaryDirectory() as raw:
            staging=Path(raw).resolve();plan=fixture();args=type('Args',(),dict(staging=staging,lab_root=staging,phase='restart',apply=True,expected_plan_sha256=SHA))()
            h.h.save(staging/'apply.json',{'applied':True,'operationId':OP,'unitSHA256':plan['afterUnitSHA256']});h.h.save(staging/'restart.pending.json',{'pending':True})
            calls=[]
            with patch.object(h,'load_plan',return_value=(plan,{})),patch.object(h,'operation',return_value=staging),patch.object(h,'remote',side_effect=lambda _l,p,_h:calls.append(p['phase']) or {'preserved':True}):
                with self.assertRaisesRegex(ValueError,'uncertain_mutation_requires_observation'):h.phase(args)
            self.assertEqual(calls,['authority','authority'])
    def test_control_migration_names_use_basename_not_dashboard_prefix(self):
        names=['internal/store/postgres/migrations/%06d_fixture.sql'%i for i in range(1,22)]
        calls=[]
        def command(args,*_a,**_k):
            calls.append(args)
            return ('\n'.join(names)+'\n').encode() if 'ls-tree' in args else b'-- immutable SQL\n'
        with tempfile.TemporaryDirectory() as raw,patch.object(h.f,'run',side_effect=command):
            ledger=h.schema_manifest(Path(raw).resolve(),p.OLD)
        self.assertEqual(ledger[0],{'name':'000001_fixture.sql','sha256':p.sha(b'-- immutable SQL\n')})
        self.assertEqual(len(calls),22)
    def test_empty_lock_inventory_remains_bounded_and_read_only(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw).resolve()/'lock';path.touch(mode=0o600)
            # fstat is real: the current local user's uid/gid are the fixture pins.
            info=path.stat()
            with patch.object(g.os,'fstat',wraps=os.fstat) as observed:
                if info.st_uid==info.st_gid:
                    self.assertEqual(g.inventory_file(path,info.st_uid,0o600),p.sha(b''))
                    self.assertGreaterEqual(observed.call_count,2)
                else:
                    with self.assertRaisesRegex(ValueError,'inventory_file_identity'):g.inventory_file(path,info.st_uid,0o600)
            alias=path.parent/'alias';alias.symlink_to(path)
            with self.assertRaises(OSError):g.inventory_file(alias,info.st_uid,0o600)
    def test_loaded_command_requires_reloaded_exact_execstart(self):
        plan=fixture();binary=plan['candidate']['path'];original=g.loaded_command
        for need_reload,command,want in [('no',binary,True),('yes',binary,False),('no',p.PROFILES['primary']['oldBinary'],False),('no',binary+' --unsafe',False)]:
            body=('NeedDaemonReload='+need_reload+'\nExecStart={ path='+command+' ; argv[]='+command+' ; ignore_errors=no ; start_time=[n/a] ; }\n').encode()
            with patch.object(g.f,'run',return_value=body):
                if want:original(plan)
                else:
                    with self.assertRaises(ValueError):original(plan)


if __name__=='__main__':unittest.main()
