#!/usr/bin/env python3
"""Offline mapping boundary, interruption and restart tests. No guest access."""
import base64
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name,filename):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

host=load('mapping_host_test','apply-dashboard-slurm-mappings.py');guest=host.guest


def scenario():
 fixture={'synthetic':True,'mode':'actual-slurm-execution','deploymentId':guest.DEPLOYMENT,'namespace':'dashboard-operations','namespaceId':'80000000-0000-4000-8000-000000000001','controlInstanceId':'80000000-0000-4000-8000-000000000002','recoveryEpoch':'1','targetGenerationId':'80000000-0000-4000-8000-000000000003','targetName':host.plan.TARGET,'storeRoot':host.plan.STORE_ROOT}
 config={'configurationRevision':5,'controls':[{'id':guest.DEPLOYMENT,'origin':'https://10.77.0.21:18443','expectedInstanceId':fixture['controlInstanceId'],'namespaceIds':[fixture['namespaceId']]}],'logBrokers':[{'id':'control01-nfs','deploymentId':guest.DEPLOYMENT,'origin':'https://10.77.0.21:19443','namespaceIds':[fixture['namespaceId']]}],'events':{'deliveryHold':False},'unrelated':{'privateFile':'/private/reference','keep':[1,2,3]}}
 review={'synthetic':True,'applies':False,'currentRevision':5,'nextRevision':6,'sourceInstanceId':fixture['controlInstanceId'],'targetGenerationId':fixture['targetGenerationId'],'fixtureSHA256':guest.sha(guest.encoded(fixture)),'files':[]}
 values={}
 for role in host.ROLES:
  after=host.plan.mapping_patch(config,fixture,role,5);key='logRoots' if role=='broker' else 'logMappings';spec=guest.SPECS[role]
  before=guest.encoded(config);after_raw=guest.encoded(after)
  item={'role':role,'host':spec[0],'path':spec[1],'uid':spec[2],'gid':spec[2],'mode':0o600,'beforeSHA256':guest.sha(before),'afterSHA256':guest.sha(after_raw),'addedMapping':after[key][-1]};review['files'].append(item)
  values[role]={'role':role,'file':item,'fixture':fixture,'before':base64.b64encode(before).decode(),'after':base64.b64encode(after_raw).decode()}
 for p in values.values():p.update(review=review,reviewSHA256=guest.sha(guest.encoded(review)))
 return values


class MappingBoundaryTests(unittest.TestCase):
 def test_guest_rejects_nonadditive_or_source_changes_even_with_new_digest(self):
  original=scenario()['api']
  for mutate in [lambda x:x['unrelated'].update(keep=[]),lambda x:x['events'].update(deliveryHold=True),lambda x:x.update(configurationRevision=5),lambda x:x['controls'][0].update(namespaceIds=[])]:
   p=copy.deepcopy(original);changed=json.loads(base64.b64decode(p['after']));mutate(changed);raw=guest.encoded(changed);p['after']=base64.b64encode(raw).decode();p['file']['afterSHA256']=guest.sha(raw);p['reviewSHA256']=guest.sha(guest.encoded(p['review']))
   with patch.object(guest.os,'geteuid',return_value=0),patch.object(guest.sys,'platform','linux'),patch.object(guest.os,'uname',return_value=SimpleNamespace(nodename='storage01')),self.assertRaises(ValueError):guest.input_value(p)
  with patch.object(guest.os,'geteuid',return_value=0),patch.object(guest.sys,'platform','linux'),patch.object(guest.os,'uname',return_value=SimpleNamespace(nodename='storage01')):
   guest.input_value(original)

 def test_safe_file_creation_umask_and_existing_file_not_repaired(self):
  with tempfile.TemporaryDirectory() as temporary:
   path=Path(temporary)/'new';old=os.umask(0o777)
   try:
    with patch.object(guest.os,'fchown') as owner:guest.put(path,b'private',os.getuid())
   finally:os.umask(old)
   owner.assert_called_once();self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
   path.chmod(0o644)
   with self.assertRaises(ValueError):guest.put(path,b'private',os.getuid())
   self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o644)
   link=Path(temporary)/'link';link.symlink_to(path)
   with self.assertRaises(OSError):guest.read(link,os.getuid())
   hard=Path(temporary)/'hard';os.link(path,hard);path.chmod(0o600)
   with self.assertRaises(ValueError):guest.read(path,os.getuid())

 def test_bounded_transport_drains_stdin_and_rejects_output_timeout(self):
  raw=b'x'*(2<<20)
  self.assertEqual(guest.run([sys.executable,'-c','import sys; print(len(sys.stdin.buffer.read()))'],input_data=raw),str(len(raw)).encode()+b'\n')
  with self.assertRaises(ValueError):guest.run([sys.executable,'-c','import sys; sys.stdout.buffer.write(b"x"*1100000)'])
  with self.assertRaises(ValueError):guest.run([sys.executable,'-c','import sys; sys.stderr.buffer.write(b"x"*70000)'])
  with self.assertRaises(ValueError):guest.run([sys.executable,'-c','import time; time.sleep(5)'],timeout=0.05)

 def test_running_revision_and_source_identity_must_be_exact(self):
  for metrics in [b'jobman_dashboard_configuration_revision 5\n',b'jobman_dashboard_configuration_revision 6\njobman_dashboard_configuration_revision 6\n']:
   with patch.object(guest,'run',side_effect=[b'{"state":"alive","role":"api"}',metrics]),self.assertRaises(ValueError):guest.running_revision('api',guest.SPECS['api'],6)
  with patch.object(guest,'run',side_effect=[b'{"state":"alive","role":"api"}',b'jobman_dashboard_configuration_revision 6\n']):guest.running_revision('api',guest.SPECS['api'],6)
  fixture=scenario()['broker']['fixture']
  def run(args,**kw):
   if 'curl' in args:return json.dumps({'capabilities':{'instanceId':fixture['controlInstanceId'],'recoveryEpoch':'2'}}).encode()
   return b'123\n'
  with patch.object(guest,'run',side_effect=run),self.assertRaises(ValueError):guest.source_state(fixture)

 def test_startup_wait_includes_process_and_configuration_before_revision(self):
  process={'binary':'/fixed'};spec=guest.SPECS['api'];stages=[]
  def observe(*args):
   stages.append('process')
   if stages.count('process')==1:raise ValueError('starting')
   return process
  def config(*args):
   stages.append('config')
   if stages.count('config')==1:raise ValueError('configuration startup')
  def revision(*args):stages.append('revision')
  with patch.object(guest,'process',side_effect=observe),patch.object(guest,'config_check',side_effect=config),patch.object(guest,'running_revision',side_effect=revision),patch.object(guest.time,'sleep'):
   guest.await_restart('api',spec,6,process,Path('/fixed.json'))
  self.assertEqual(stages,['process','process','config','process','config','revision'])

 def test_startup_wait_deadline_reports_only_fixed_safe_stage(self):
  for stage in ['process_identity','config_validation','loaded_revision']:
   clock=[0.0]
   def fail(*args):clock[0]=11;raise ValueError('PRIVATE command error')
   mocks={'process':lambda *a:{'binary':'/fixed'},'config_check':lambda *a:None,'running_revision':lambda *a:None}
   mocks[{'process_identity':'process','config_validation':'config_check','loaded_revision':'running_revision'}[stage]]=fail
   with self.subTest(stage=stage),patch.object(guest.time,'monotonic',side_effect=lambda:clock[0]),patch.object(guest,'process',side_effect=mocks['process']),patch.object(guest,'config_check',side_effect=mocks['config_check']),patch.object(guest,'running_revision',side_effect=mocks['running_revision']),patch.object(guest.time,'sleep') as sleep:
    with self.assertRaises(ValueError) as caught:guest.await_restart('api',guest.SPECS['api'],6,{'binary':'/fixed'},Path('/fixed.json'))
    self.assertIn(stage,str(caught.exception));self.assertNotIn('PRIVATE',str(caught.exception));sleep.assert_not_called()

 def test_startup_commands_share_remaining_deadline(self):
  with patch.object(guest.time,'monotonic',return_value=9.75),patch.object(guest,'run',return_value=b'') as run:
   guest.config_check(guest.SPECS['api'],'/fixed',Path('/fixed.json'),10)
   self.assertEqual(run.call_args.kwargs['timeout'],0.25)
  with patch.object(guest.time,'monotonic',return_value=10),patch.object(guest,'run') as run:
   with self.assertRaises(ValueError):guest.config_check(guest.SPECS['api'],'/fixed',Path('/fixed.json'),10)
   run.assert_not_called()


class GuestPhasesTests(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close);self.p=scenario()['api'];self.p.update(apply=True,phase='stage',baseline={'process':{'binary':'/candidate','unit':'api'}})
  self.path=Path('/configs/config.json');self.before=base64.b64decode(self.p['before']);self.after=base64.b64decode(self.p['after']);self.files={self.path:self.before};self.root=Path('/receipts');self.backup=Path('/configs/before');self.staged=Path('/configs/after');self.start={'MainPID':'1','ExecMainStartTimestampMonotonic':'10'}
  self.stack.enter_context(patch.object(guest,'input_value',return_value=(guest.SPECS['api'],self.path,self.before,self.after)))
  self.stack.enter_context(patch.object(guest,'paths',return_value=(self.backup,self.staged,self.root)))
  self.stack.enter_context(patch.object(guest,'process',side_effect=lambda _:self.p['baseline']['process']))
  self.stack.enter_context(patch.object(guest,'process_start',side_effect=lambda _:dict(self.start)))
  self.stack.enter_context(patch.object(guest,'directory'))
  self.stack.enter_context(patch.object(guest,'sync'))
  self.stack.enter_context(patch.object(guest,'read',side_effect=self.read))
  self.stack.enter_context(patch.object(guest,'put',side_effect=self.put))
  self.stack.enter_context(patch.object(guest.Path,'exists',lambda p:p in self.files))
  self.stack.enter_context(patch.object(guest.os,'replace',side_effect=self.replace))
  self.check=self.stack.enter_context(patch.object(guest,'config_check'))
  self.healthy=self.stack.enter_context(patch.object(guest,'await_restart'))
  self.command=self.stack.enter_context(patch.object(guest,'run',side_effect=self.command_run))
 def read(self,p,*args):
  if p not in self.files:raise FileNotFoundError(str(p))
  return self.files[p]
 def put(self,p,raw,*args):
  if p in self.files and self.files[p]!=raw:raise ValueError('retained differs')
  self.files[p]=raw
 def replace(self,a,b):self.files[b]=self.files.pop(a)
 def command_run(self,*args,**kwargs):self.start={'MainPID':'2','ExecMainStartTimestampMonotonic':'20'};return b''
 def phase(self,phase):self.p['phase']=phase;return guest.execute(self.p)
 def test_validation_failure_keeps_original_and_backup(self):
  self.check.side_effect=ValueError('invalid staged config')
  with self.assertRaises(ValueError):self.phase('stage')
  self.assertEqual(self.files[self.path],self.before);self.assertEqual(self.files[self.backup],self.before);self.assertNotIn(self.root/'stage.json',self.files);self.command.assert_not_called()
 def test_cas_drift_never_replaced_or_repaired(self):
  self.phase('stage');self.files[self.path]=b'drift'
  with self.assertRaises(ValueError):self.phase('apply')
  self.assertEqual(self.files[self.path],b'drift');self.assertNotIn(self.root/'apply.pending.json',self.files);self.command.assert_not_called()
 def test_lost_swap_completion_recovers_exact_new_bytes_without_second_swap(self):
  self.phase('stage');real_put=self.put
  def lost(p,raw,*a):
   if p==self.root/'apply.json':raise OSError('response lost')
   real_put(p,raw,*a)
  with patch.object(guest,'put',side_effect=lost),self.assertRaises(OSError):self.phase('apply')
  self.assertEqual(self.files[self.path],self.after);self.assertEqual(self.phase('swap-state')['state'],'applied')
  with patch.object(guest.os,'replace',side_effect=AssertionError('repeat swap')):self.phase('apply')
  self.assertEqual(self.files[self.backup],self.before);self.command.assert_not_called()
 def test_lost_restart_completion_recovers_only_new_healthy_process(self):
  self.phase('stage');self.phase('apply');self.healthy.side_effect=ValueError('not ready yet')
  with self.assertRaises(ValueError):self.phase('restart')
  self.command.assert_called_once();self.healthy.side_effect=None;self.phase('restart');self.command.assert_called_once()
  self.phase('restart');self.command.assert_called_once()
 def test_pending_restart_with_unchanged_process_is_not_repeated(self):
  self.phase('stage');self.phase('apply');self.command.side_effect=OSError('did not start')
  with self.assertRaises(OSError):self.phase('restart')
  with self.assertRaises(ValueError):self.phase('restart')
  self.command.assert_called_once()


class HostPhasesTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.lab=self.root/'lab';self.stage=self.root/'stage'
  (self.lab/'.lab/dashboard-slurm').mkdir(parents=True,mode=0o700);(self.lab/'.lab/dashboard').mkdir(mode=0o700);self.stage.mkdir(mode=0o700)
  self.values=scenario();p=self.values['api'];host.put(self.lab/'.lab/dashboard/slurm-fixture.json',p['fixture']);host.put(self.stage/'review.json',p['review'])
  for role,v in self.values.items():
   for kind in ('before','after'):
    path=self.stage/(role+'.'+kind+'.json');path.write_bytes(base64.b64decode(v[kind]));path.chmod(0o600)
  self.args=SimpleNamespace(lab_root=self.lab,staging=self.stage,expected_review_sha256=p['reviewSHA256'],expected_implementation_sha256=guest.sha(guest.encoded(host.implementation())),phase='preflight',apply=True)
  self.calls=[];self.fail=None;self.states={role:'original' for role in host.ROLES};self.baseline={role:{'epoch':int(time.time()),'process':{'unit':role},'beforeSHA256':v['file']['beforeSHA256']} for role,v in self.values.items()}
  self.stack=ExitStack();self.addCleanup(self.stack.close);self.stack.enter_context(patch.object(host,'remote',side_effect=self.remote))
 def remote(self,lab,p):
  role,phase=p['role'],p['phase'];self.calls.append((role,phase))
  if self.fail==(role,phase):raise ValueError('drift')
  if phase=='preflight':return self.baseline[role]
  if phase=='swap-state':return {'state':self.states[role]}
  if phase=='apply':self.states[role]='applied'
  return {'role':role,'phase':phase}
 def phase(self,p):self.args.phase=p;return host.execute(self.args)
 def test_all_three_fresh_checks_precede_first_stage(self):
  self.phase('preflight');self.calls=[];self.fail=('reports','preflight')
  with self.assertRaises(ValueError):self.phase('stage')
  self.assertEqual(self.calls,[(r,'preflight') for r in host.ROLES]);self.assertFalse(any(p=='stage' for r,p in self.calls))
 def test_all_three_cas_states_precede_first_swap_and_all_swaps_precede_restart(self):
  self.phase('preflight');self.phase('stage');self.calls=[];self.fail=('reports','swap-state')
  with self.assertRaises(ValueError):self.phase('apply')
  self.assertFalse(any(p=='apply' for r,p in self.calls));self.fail=None;self.phase('apply');self.calls=[];self.states['reports']='original'
  with self.assertRaises(ValueError):self.phase('restart')
  self.assertFalse(any(p=='restart' for r,p in self.calls))
 def test_private_receipts_restrictive_umask_and_global_lock(self):
  old=os.umask(0o777)
  try:self.phase('preflight')
  finally:os.umask(old)
  self.assertEqual(stat.S_IMODE((self.stage/'apply-receipts').stat().st_mode),0o700)
  self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in (self.stage/'apply-receipts').iterdir()))
  with host.lock(self.lab),self.assertRaises(BlockingIOError):
   with host.lock(self.lab):pass
 def test_reviewed_bytes_and_implementation_drift_stop_before_remote(self):
  self.args.expected_implementation_sha256='0'*64
  with self.assertRaises(ValueError):self.phase('preflight')
  self.assertEqual(self.calls,[]);self.args.expected_implementation_sha256=guest.sha(guest.encoded(host.implementation()))
  (self.stage/'api.after.json').write_bytes(b'{}')
  with self.assertRaises(ValueError):self.phase('preflight')
  self.assertEqual(self.calls,[])
 def test_completed_phases_can_be_replayed_without_changed_receipts(self):
  for phase in host.PHASES:self.phase(phase)
  self.phase('verify');self.phase('restart')
  self.assertTrue((self.stage/'apply-receipts/verified-broker.json').exists())


if __name__=='__main__':unittest.main()
