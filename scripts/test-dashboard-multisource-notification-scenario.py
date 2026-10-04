#!/usr/bin/env python3
"""Offline two-source receipt, barrier and fixed guest guards. No guest calls."""
import copy
import contextlib
import io
import importlib.util
import os
import tempfile
import stat
from pathlib import Path
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('scenario',HERE/'dashboard-multisource-notification-scenario.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
c,_=h.common_module()
g=types.ModuleType('guest');g.__dict__.update(vars(h));exec(compile(h.REMOTE,'guest','exec'),g.__dict__)


def fixture(profile='primary'):
 p=c.PROFILES[profile]
 value={'synthetic':True,'fixtureVersion':1,'observationMode':'normal-cancel-no-execution','helperCommit':c.COMMIT,'receipt':'a'*32,'deploymentId':p['deployment'],'controlInstanceId':p['instance'],'recoveryEpoch':'1','namespaceId':h.NAMESPACES[profile],'namespace':'dashboard-research','jobs':[{'case':name,'jobId':'76000000-0000-4000-8000-%012d'%i} for i,name in enumerate(('first','stopped'),1)]}
 if profile=='secondary':value['profile']='secondary-v1'
 return value


def event(profile='primary'):
 f=fixture(profile)
 return dict({k:f[k] for k in ('receipt','deploymentId','controlInstanceId','recoveryEpoch','namespaceId')},synthetic=True,case='first',jobId=f['jobs'][0]['jobId'],eventId='77000000-0000-4000-8000-000000000001',outcome='cancelled',jobRevision='2',recordedAt='2026-10-04T10:00:00Z')


class TwoSourceNotificationTests(unittest.TestCase):
 def test_profiles_and_mutated_source_receipts(self):
  for profile in c.PROFILES:
   good=fixture(profile);self.assertEqual(h.validate_fixture(c,good,profile,'a'*32),good)
   for key,value in (('deploymentId',c.PROFILES['secondary' if profile=='primary' else 'primary']['deployment']),('controlInstanceId','00000000-0000-4000-8000-000000000001'),('namespaceId',h.NAMESPACES['secondary' if profile=='primary' else 'primary']),('recoveryEpoch','2'),('helperCommit','f'*40),('receipt','b'*32),('synthetic',False)):
    bad=copy.deepcopy(good);bad[key]=value
    with self.subTest(profile=profile,key=key),self.assertRaises(c.Failure):h.validate_fixture(c,bad,profile,'a'*32)
   bad=copy.deepcopy(good);bad['jobs'][1]['jobId']=bad['jobs'][0]['jobId']
   with self.assertRaises(c.Failure):h.validate_fixture(c,bad,profile,'a'*32)

 def test_terminal_event_exact_identity_and_no_fake_run(self):
  for profile in c.PROFILES:
   good=event(profile);self.assertEqual(h.validate_event(c,good,fixture(profile),'first'),good)
   for key,value in (('jobId',fixture(profile)['jobs'][1]['jobId']),('eventId','x'),('outcome','success'),('jobRevision','9223372036854775808'),('namespaceId',h.NAMESPACES['secondary' if profile=='primary' else 'primary']),('runId','78000000-0000-4000-8000-000000000001'),('recordedAt','2026-10-04T10:00:00')):
    bad=copy.deepcopy(good);bad[key]=value
    with self.subTest(profile=profile,key=key),self.assertRaises((c.Failure,ValueError)):h.validate_event(c,bad,fixture(profile),'first')

 def test_barrier_reads_exact_composite_identity_and_current_checkpoint(self):
  for profile in c.PROFILES:
   source,dashboard=h.barrier_queries(c,fixture(profile),event(profile))
   for raw in (source,dashboard):
    for forbidden in ('INSERT ','UPDATE ','DELETE ','CREATE ','DROP '):self.assertNotIn(forbidden,raw)
   for key in ('deploymentId','controlInstanceId','namespaceId','jobId','eventId'):self.assertIn(event(profile)[key],dashboard)
   self.assertIn('monitoring_feed',source);self.assertIn('restore_epoch::text FROM service_recovery_state',source)
   self.assertIn("convert_from(s.checkpoint,'UTF8')::jsonb->>'controlInstanceId'",dashboard)
   self.assertIn("n.state='pending'",dashboard);self.assertIn("s.status='active'",dashboard)
   self.assertNotIn('s.recovery_epoch',dashboard);self.assertNotIn('s.control_instance_id',dashboard)

 def test_process_requires_only_exact_upgraded_source_for_both_profiles(self):
  expected='7faac82263dfa281d2fec7c3e8a52a55a121294e39e7e2d1706115751d4a2123'
  prior='38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e'
  self.assertEqual(h.SOURCE_SHA,expected)
  for profile in c.PROFILES:
   executable='/fixed-reviewed/control';start='100 (control) '+' '.join(['S']+['0']*18+['77'])
   with patch.object(c,'run',side_effect=[b'',b'100\n']),patch.object(Path,'stat',return_value=types.SimpleNamespace(st_uid=c.PROFILES[profile]['uid'])),patch.object(g.os,'readlink',return_value=executable),patch.object(c,'read',return_value=b'fixed-upgraded-binary') as read,patch.object(c,'sha',return_value=expected),patch.object(Path,'read_text',return_value=start):
    self.assertEqual(g.process(c,profile),('100','77',executable));read.assert_called_once_with(Path(executable),128<<20,uid=0,mode=0o755)
   for rejected in (prior,'0'*64):
    with self.subTest(profile=profile,hash=rejected),patch.object(c,'run',side_effect=[b'',b'100\n']),patch.object(Path,'stat',return_value=types.SimpleNamespace(st_uid=c.PROFILES[profile]['uid'])),patch.object(g.os,'readlink',return_value=executable),patch.object(c,'read',return_value=b'wrong-binary'),patch.object(c,'sha',return_value=rejected),patch.object(Path,'read_text') as stat_text:
     with self.assertRaisesRegex(c.Failure,'source_binary'):g.process(c,profile)
     stat_text.assert_not_called()

 def test_guest_host_and_root_guard_precede_mutation(self):
  payload={'profile':'primary','action':'prepare','receipt':'a'*32,'case':None}
  with patch.object(g.os,'geteuid',return_value=1),patch.object(g,'process') as process:
   with self.assertRaisesRegex(h.ScenarioFailure,'scenario_guest_preflight_common_failure'):g.guest(c,payload)
   process.assert_not_called()
  with patch.object(g.os,'geteuid',return_value=0),patch.object(g.sys,'platform','linux'),patch.object(g.os,'uname') as host,patch.object(g,'process') as process:
   host.return_value.nodename='storage01'
   with self.assertRaisesRegex(h.ScenarioFailure,'scenario_guest_preflight_common_failure'):g.guest(c,payload)
   process.assert_not_called()

 def test_barrier_boolean_is_not_a_timer_or_cross_database_write(self):
  for published,settled in ((False,False),(False,True),(True,False),(True,True)):
   payload={'profile':'secondary','action':'settled','receipt':'a'*32,'case':'first','fixture':fixture('secondary'),'event':event('secondary')}
   results=[c.encoded({'published':published,'instance':c.PROFILES['secondary']['instance'],'epoch':'1'}),c.encoded({'settled':settled})]
   with patch.object(g.os,'geteuid',return_value=0),patch.object(g.sys,'platform','linux'),patch.object(g.os,'uname') as host,patch.object(c,'run',side_effect=results) as run:
    host.return_value.nodename='pg01';result=g.guest(c,payload)
    self.assertEqual(result['settled'],published and settled)
    self.assertEqual(result['deploymentId'],c.PROFILES['secondary']['deployment'])
    self.assertIn(c.PROFILES['secondary']['database'],run.call_args_list[0].args[0])
    self.assertIn('jobman_dashboard',run.call_args_list[1].args[0])
    for call in run.call_args_list:
     self.assertIn(b'REPEATABLE READ READ ONLY',call.args[1]);self.assertIn(b"statement_timeout='5s'",call.args[1]);self.assertTrue(call.args[1].endswith(b'ROLLBACK;'))

 def test_new_lock_exact_mode_under_restrictive_umask_existing_drift_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'lock';original=os.fstat
   def fstat(fd):
    value=original(fd);return types.SimpleNamespace(st_mode=value.st_mode,st_nlink=value.st_nlink,st_uid=0)
   with patch.object(g.os,'fstat',side_effect=fstat):
    old=os.umask(0o777)
    try:fd=g.operation_lock(c,path)
    finally:os.umask(old)
    os.close(fd);self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
    path.chmod(0o640)
    with self.assertRaisesRegex(c.Failure,'operation_lock'):g.operation_lock(c,path)
    self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o640)
    path.unlink();os.mkfifo(path);original_open=os.open
    def no_block(path,flags,*args):
     self.assertTrue(flags & os.O_NONBLOCK,'wrong-type lock opens must not block before validation')
     return original_open(path,flags,*args)
    with patch.object(g.os,'open',side_effect=no_block),self.assertRaises(OSError):g.operation_lock(c,path)

 def test_both_fixture_roots_reject_pending_scenarios_but_keep_scale_evidence(self):
  with tempfile.TemporaryDirectory() as directory:
   base=Path(directory).resolve();source=base/'source';ldap=base/'directory'
   source.mkdir(mode=0o700);ldap.mkdir(mode=0o700)
   profile=dict(c.PROFILES['secondary'],root=str(source),directory=str(ldap),uid=os.getuid(),directoryUID=os.getuid())
   with patch.dict(c.PROFILES,{'secondary':profile}):
    for root in (source,ldap):
     c.put(root/'.scale-seed.pending.json',b'preserved-seed');c.put(root/'.scale-seed.completed.json',b'preserved-seed')
    g.directory_preflight(c,'secondary')
    for root in (source,ldap):
     for name in ('.directory-acceptance-abc.json','.diagnostic-prepare.json','.secondary-prepare.json'):
      marker=root/name;c.put(marker,b'uncertain')
      with self.subTest(root=root.name,marker=name),self.assertRaisesRegex(c.Failure,'unfinished_directory_or_fixture_operation'):g.directory_preflight(c,'secondary')
      self.assertEqual(c.read(marker),b'uncertain');marker.unlink()
    self.assertEqual(c.read(source/'.scale-seed.pending.json'),b'preserved-seed')
    self.assertEqual(c.read(ldap/'.scale-seed.completed.json'),b'preserved-seed')
    (source/'.scale-seed.completed.json').unlink()
    with self.assertRaisesRegex(c.Failure,'unfinished_scale_preparation'):g.directory_preflight(c,'secondary')
    self.assertEqual(c.read(source/'.scale-seed.pending.json'),b'preserved-seed')
    c.put(source/'.scale-seed.completed.json',b'different-receipt')
    with self.assertRaisesRegex(c.Failure,'unfinished_scale_preparation'):g.directory_preflight(c,'secondary')
    (source/'.scale-seed.completed.json').unlink();c.put(source/'.scale-seed.completed.json',b'preserved-seed')
    ldap.chmod(0o750)
    with self.assertRaisesRegex(c.Failure,'fixture_directory_identity'):g.directory_preflight(c,'secondary')

 def test_normal_helper_private_transport_cleanup_and_pending_fence(self):
  with tempfile.TemporaryDirectory() as directory:
   base=Path(directory).resolve();root=base/'source';root.mkdir(mode=0o700)
   public=base/'public';public.mkdir(mode=0o755);version=public/'version';version.mkdir(mode=0o755)
   binary=version/'helper';c.put(binary,b'fixed-helper',0o755)
   profile=dict(c.PROFILES['primary'],root=str(root),directory=str(root),uid=os.getuid(),directoryUID=os.getuid())
   dsn='postgres://synthetic:never-print@10.77.0.20:5432/jobman_dashboard_control?sslmode=verify-full'
   env={'JOBMAN_CONTROL_DATABASE_URL':dsn,'JOBMAN_CONTROL_DIAGNOSTIC_DEPLOYMENT_ID':profile['deployment'],'JOBMAN_CONTROL_DIRECTORY_MODE':'enforce','JOBMAN_CONTROL_MIGRATE_ON_START':'false'}
   c.put(root/'control.env',b''.join(k.encode()+b'='+c.encoded(v) for k,v in env.items()))
   c.put(root/'fixture-info.json',c.encoded({'synthetic':True,'instanceId':profile['instance'],'namespaces':[{'id':h.NAMESPACES['primary'],'name':'dashboard-research'}]}))
   original_read,original_stat=c.read,os.fstat
   def read(path,*args,**kw):
    if Path(path)==binary:kw['uid']=os.getuid()
    return original_read(path,*args,**kw)
   def fstat(fd):
    value=original_stat(fd);lock=root/'.notification-operation.lock'
    if lock.exists() and (value.st_dev,value.st_ino)==(lock.stat().st_dev,lock.stat().st_ino):return types.SimpleNamespace(st_mode=value.st_mode,st_nlink=value.st_nlink,st_uid=0)
    return value
   def helper(args,**kwargs):
    self.assertEqual(args[0],str(binary));self.assertNotIn(dsn,args)
    temporary=Path(args[args.index('--database-url-file')+1]);self.assertEqual(c.read(temporary),dsn.encode()+b'\n')
    self.assertEqual(kwargs['timeout'],35);self.assertEqual(kwargs['maximum'],8192)
    return c.encoded(fixture())
   payload={'profile':'primary','action':'prepare','receipt':'a'*32,'case':None}
   with patch.dict(c.PROFILES,{'primary':profile}),patch.object(c,'BINARY',binary),patch.object(c,'BINARY_SHA',c.sha(b'fixed-helper')),patch.object(c,'read',side_effect=read),patch.object(g.os,'fstat',side_effect=fstat),patch.object(g.os,'geteuid',return_value=0),patch.object(g.sys,'platform','linux'),patch.object(g.os,'uname') as host,patch.object(g,'process',return_value=('1','2','fixed')),patch.object(c,'run',side_effect=helper) as run:
    host.return_value.nodename='control01'
    self.assertEqual(g.guest(c,payload),fixture());self.assertFalse((root/'.multisource-notification-database-url').exists());run.assert_called_once()
    run.reset_mock();c.put(root/'.multisource-notification-database-url',b'unknown-prior-operation')
    with self.assertRaisesRegex(h.ScenarioFailure,'scenario_guest_preflight_common_failure'):g.guest(c,payload)
    run.assert_not_called();self.assertEqual(c.read(root/'.multisource-notification-database-url'),b'unknown-prior-operation')
    (root/'.multisource-notification-database-url').unlink();run.side_effect=c.Failure('helper_failed')
    with self.assertRaisesRegex(h.ScenarioFailure,'scenario_helper_run_common_failure'):g.guest(c,payload)
    self.assertFalse((root/'.multisource-notification-database-url').exists())
    run.side_effect=helper
    with patch.object(g,'process',side_effect=[('1','2','fixed'),('9','10','changed')]):
     with self.assertRaisesRegex(h.ScenarioFailure,'scenario_guest_postflight_common_failure'):g.guest(c,payload)
    self.assertFalse((root/'.multisource-notification-database-url').exists())

 def test_failed_frames_only_expose_fixed_stage_codes(self):
  secret='private-dsn-and-token-must-never-appear'
  for stage in h.STAGES:
   try:
    with h.at_stage(stage):raise ValueError(secret)
   except h.ScenarioFailure as error:
    frame=h.failure_frame(error)
    self.assertEqual(frame,{'scenarioFailure':{'stage':stage,'code':'python_value_error'}})
    self.assertNotIn(secret,str(frame));self.assertNotIn(secret,str(error))
    with self.assertRaises(h.ScenarioFailure) as parsed:h.checked_result(c,c.encoded(frame))
    self.assertEqual(parsed.exception.stage,stage)
  for bad in ({'scenarioFailure':{'stage':secret,'code':'failed'}},{'scenarioFailure':{'stage':'helper_run','code':secret}},{'scenarioFailure':{'stage':'helper_run','code':'failed','extra':secret}}):
   with self.assertRaisesRegex(h.ScenarioFailure,'scenario_host_decode_invalid_result') as failure:h.checked_result(c,c.encoded(bad))
   self.assertNotIn(secret,str(failure.exception))
  self.assertEqual(h.failure_frame(ValueError(secret)),{'scenarioFailure':{'stage':'host_input','code':'python_value_error'}})

 def test_finite_reasons_never_serialize_private_exception_material(self):
  canary='private-password-and-file-path'
  for reason in h.COMMON_REASONS:
   with self.subTest(reason=reason):
    with self.assertRaises(h.ScenarioFailure) as caught:
     with h.at_stage('host_receipt'):raise c.Failure(reason)
    self.assertEqual(h.failure_frame(caught.exception),{'scenarioFailure':{'stage':'host_receipt','code':'common_'+reason}})
  self.assertEqual(h.failure_code(c.Failure('private_unrecognized_reason')),'common_failure')
  class Untrusted(ValueError):code='file_identity'
  self.assertEqual(h.failure_code(Untrusted(canary)),'failed')
  for number,code in list(h.OS_REASONS.items())+[(99999,'os_error')]:
   with self.subTest(errno=number):
    error=OSError(number,canary,'/'+canary)
    frame=h.failure_frame(error)
    self.assertEqual(frame,{'scenarioFailure':{'stage':'host_input','code':code}})
    self.assertNotIn(canary,str(frame));self.assertIn(code,h.CODES)
  for value in h.CODES:
   with self.assertRaises(h.ScenarioFailure) as caught:h.checked_result(c,c.encoded({'scenarioFailure':{'stage':'host_input','code':value}}))
   self.assertEqual(caught.exception.code,value)

 def test_builtin_exception_codes_are_exact_and_never_expose_values(self):
  for kind,reason in h.PYTHON_REASONS.items():
   error=kind('private-key-or-credential')
   self.assertEqual(h.failure_code(error),reason)
   self.assertNotIn('private',str(h.failure_frame(error)))
   class Custom(kind):pass
   self.assertEqual(h.failure_code(Custom('private')),'failed')

 def test_actual_shared_global_bootstrap_pending_then_settled_and_diagnostics(self):
  common_raw=(HERE/'dashboard-scale-source-common.py').read_bytes();program=h.guest_program(common_raw,(HERE/'dashboard-multisource-notification-scenario.py').read_bytes())
  seam='COMMON_FAILURE_TYPE=c.Failure\ntry:'
  self.assertEqual(program.count(seam),1)
  program=program.replace(seam,'COMMON_FAILURE_TYPE=c.Failure\nc.run=TEST_READONLY_RUN\ntry:')
  def invoke(profile,published,settled,failure=None):
   payload={'profile':profile,'action':'settled','receipt':'a'*32,'case':'first','fixture':fixture(profile),'event':event(profile)}
   values=[{'published':published,'instance':c.PROFILES[profile]['instance'],'epoch':'1'},{'settled':settled}]
   if failure=='input':payload['event']['recordedAt']='private-invalid-time'
   if failure=='result':values[0].pop('instance')
   calls=[]
   def readonly(args,raw,**kwargs):
    index=len(calls);calls.append(args)
    self.assertEqual(args[-1],[c.PROFILES[profile]['database'],'jobman_dashboard'][index])
    self.assertTrue(raw.startswith(b'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'));self.assertTrue(raw.endswith(b'ROLLBACK;'))
    self.assertEqual(kwargs,{'timeout':9,'maximum':8192})
    if failure==['source','dashboard'][index]:raise KeyError('private-query-or-key')
    return c.encoded(values[index])
   output=io.StringIO()
   with patch.object(os,'geteuid',return_value=0),patch.object(h.sys,'platform','linux'),patch.object(os,'uname',return_value=types.SimpleNamespace(nodename='pg01')),patch.object(h.sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(c.encoded(payload)))),contextlib.redirect_stdout(output):
    exec(compile(program,'actual-wrapper-bootstrap','exec'),{'__name__':'__main__','TEST_READONLY_RUN':readonly})
   self.assertNotIn('private-',output.getvalue())
   return c.decode(output.getvalue()),calls
  for profile in c.PROFILES:
   for published,settled in ((False,False),(False,True),(True,False),(True,True)):
    result,calls=invoke(profile,published,settled);self.assertEqual(result['settled'],published and settled);self.assertEqual(len(calls),2)
    self.assertEqual(result['eventId'],event(profile)['eventId'])
   for failure,reason,count in [('input','python_value_error',0),('source','python_key_error',1),('dashboard','python_key_error',2),('result','python_key_error',2)]:
    result,calls=invoke(profile,False,False,failure)
    self.assertEqual(result,{'scenarioFailure':{'stage':'guest_barrier_'+failure,'code':reason}});self.assertEqual(len(calls),count)

 def test_fast_new_receipt_reads_and_metadata_mismatch_are_distinct(self):
  with tempfile.TemporaryDirectory() as name:
   directory=Path(name).resolve()
   for i in range(20):
    path=directory/('receipt-%d.json'%i);raw=c.encoded(event());c.retain(path,raw)
    self.assertEqual(c.read(path),raw);c.retain(path,raw)
    path.chmod(0o640)
    with self.assertRaisesRegex(h.ScenarioFailure,'common_file_identity'):
     with h.at_stage('host_receipt'):c.retain(path,raw)
    path.chmod(0o600)
    with self.assertRaisesRegex(h.ScenarioFailure,'common_immutable_receipt_changed'):
     with h.at_stage('host_receipt'):c.retain(path,c.encoded(dict(event(),jobRevision='3')))
    self.assertEqual(c.read(path),raw)
   actual=Path.lstat
   def changed(path):
    result=actual(path)
    return types.SimpleNamespace(st_dev=result.st_dev,st_ino=result.st_ino+1)
   with patch.object(Path,'lstat',changed):
    with self.assertRaisesRegex(h.ScenarioFailure,'common_file_changed'):
     with h.at_stage('host_receipt'):c.read(path)

 def test_explicit_private_receipt_root_preserves_strict_guards_and_new_only(self):
  self.assertEqual(h.HOST_RECEIPT_PARENT,Path('/private/tmp'))
  with tempfile.TemporaryDirectory() as name:
   base=Path(name).resolve();root=base/'jobman-dashboard-notification-receipts-test';root.mkdir(mode=0o700)
   state=base/'unused-lab-state'
   with patch.object(h,'HOST_RECEIPT_PARENT',base):
    for profile in c.PROFILES:
     directory=h.host_receipt_directory(c,state,profile,'a'*32,'prepare',str(root))
     value=fixture(profile);payload={'profile':profile,'action':'prepare','receipt':'a'*32,'case':None};path=directory/('a'*32+'.json')
     h.retain_result(c,value,payload,path,directory)
     self.assertEqual(c.read(path),c.encoded(value))
     with self.assertRaisesRegex(c.Failure,'new_receipt_required'):h.host_receipt_directory(c,state,profile,'a'*32,'prepare',str(root))
     self.assertEqual(h.host_receipt_directory(c,state,profile,'a'*32,'complete',str(root)),directory)
     payload.update(action='complete',case='first',fixture=value)
     h.retain_result(c,event(profile),payload,path,directory);h.retain_result(c,event(profile),payload,path,directory)
     link=directory/'synthetic-extra-link';os.link(path,link)
     with self.assertRaisesRegex(c.Failure,'file_identity'):c.read(path)
     link.unlink();self.assertEqual(c.read(path),c.encoded(value))
     for old in h.RETAINED_RECEIPTS:
      for action in ('prepare','complete','settled'):
       with self.subTest(receipt=old,action=action),self.assertRaisesRegex(c.Failure,'retained_scenario_excluded'):h.host_receipt_directory(c,state,profile,old,action,str(root))
    self.assertFalse(state.exists())
    for candidate in ('relative',str(base),str(root)+'/../'+root.name,str(base/'wrong-name'),str(base/'jobman-dashboard-notification-receipts-absent')):
     with self.subTest(path=candidate),self.assertRaises((c.Failure,FileNotFoundError)):h.host_receipt_directory(c,state,'primary','b'*32,'prepare',candidate)
    alias=base/'jobman-dashboard-notification-receipts-alias';alias.symlink_to(root,target_is_directory=True)
    with self.assertRaisesRegex(c.Failure,'directory_identity'):h.host_receipt_directory(c,state,'primary','b'*32,'prepare',str(alias))
    root.chmod(0o750)
    with self.assertRaisesRegex(c.Failure,'directory_identity'):h.host_receipt_directory(c,state,'primary','b'*32,'prepare',str(root))
    root.chmod(0o700)
    actual=Path.lstat
    def wrong_owner(path):
     result=actual(path)
     return types.SimpleNamespace(st_mode=result.st_mode,st_uid=os.getuid()+1)
    with patch.object(Path,'lstat',wrong_owner),self.assertRaisesRegex(c.Failure,'directory_identity'):h.host_receipt_directory(c,state,'primary','b'*32,'prepare',str(root))

 def test_explicit_root_flag_never_enters_guest_payload_or_inventory_paths(self):
  with tempfile.TemporaryDirectory() as name:
   base=Path(name).resolve();root=base/'jobman-dashboard-notification-receipts-flow';root.mkdir(mode=0o700)
   lab_state=HERE.parent/'.lab/dashboard';read=c.read
   connection={'ansible_ssh_private_key_file':'/synthetic/key','ansible_port':22,'ansible_user':'vagrant','ansible_host':'127.0.0.1'}
   def input_read(path,*args,**kwargs):
    if path==lab_state/'ssh-connections.json':return c.encoded({'control01':connection,'pg01':connection})
    return read(path,*args,**kwargs)
   def transport(args,payload,**kwargs):
    value=c.decode(payload);self.assertNotIn('hostReceiptRoot',value);self.assertNotIn(str(root),args)
    self.assertIn('UserKnownHostsFile='+str(lab_state/'known_hosts'),args)
    return c.encoded(fixture() if value['action']=='prepare' else event())
   with patch.object(h,'HOST_RECEIPT_PARENT',base),patch.object(c,'read',side_effect=input_read),patch.object(h,'common_module',return_value=(c,b'fixed-common')),patch.object(c,'run',side_effect=transport) as run,patch.object(h.sys,'stdout',types.SimpleNamespace(buffer=__import__('io').BytesIO())):
    for action in ('prepare','complete','complete'):
     args=['scenario','primary',action,'a'*32]+([] if action=='prepare' else ['first'])+['--host-receipt-root',str(root)]
     with patch.object(h.sys,'argv',args):h.main()
    self.assertEqual(run.call_count,3)
    self.assertEqual(c.read(root/'primary'/('a'*32+'-first.json')),c.encoded(event()))

 def test_host_receipt_failure_preserves_existing_bytes_and_success_shape(self):
  with tempfile.TemporaryDirectory() as name:
   directory=Path(name).resolve();path=directory/'fixture.json';payload={'profile':'primary','action':'complete','receipt':'a'*32,'case':'first','fixture':fixture()};result=event()
   h.retain_result(c,result,payload,path,directory)
   destination=directory/('a'*32+'-first.json');before=c.read(destination)
   self.assertEqual(before,c.encoded(result));h.retain_result(c,result,payload,path,directory)
   self.assertEqual(c.read(destination),before)
   changed=dict(result,eventId='77000000-0000-4000-8000-000000000002')
   with self.assertRaisesRegex(h.ScenarioFailure,'scenario_host_receipt_common_immutable_receipt_changed'):h.retain_result(c,changed,payload,path,directory)
   self.assertEqual(c.read(destination),before)
   with self.assertRaisesRegex(h.ScenarioFailure,'scenario_host_validate_common_failure'):h.retain_result(c,dict(result,jobId='secret'),payload,path,directory)
   self.assertEqual(c.read(destination),before)


if __name__=='__main__':unittest.main()
