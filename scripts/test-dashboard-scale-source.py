#!/usr/bin/env python3
"""Offline scale-source safety tests. No SSH, database or fixture mutation."""
import base64
import copy
from datetime import datetime,timedelta,timezone
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name):
 spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

c=load('dashboard-scale-source-common');h=load('dashboard-scale-source')
g=types.ModuleType('guest');g.common=c;exec(compile((HERE/'dashboard-scale-source-guest.py').read_text(),'guest','exec'),g.__dict__)

def scale_input(profile='primary'):
 return {'instanceId':c.PROFILES[profile]['instance'],'issuer':c.ISSUER,'historyAt':(datetime.now(timezone.utc)-timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
  'users':[{'directoryId':'74000000-0000-4000-8000-%012d'%i,'subject':'75000000-0000-4000-8000-%012d'%i,'name':'Synthetic scale %02d'%i} for i in range(1,26)]}

def database(profile='primary'):
 return {'database':c.PROFILES[profile]['database'],'instance':c.PROFILES[profile]['instance'],'epoch':'1','migrations':21,'ledgerSHA256':'a'*64,
  'namespaceIds':['76000000-0000-4000-8000-000000000001'],'namespaceSHA256':'b'*64,'jobs':{'count':3,'sha256':'c'*64},
  'namespaceTotal':1,'scaleNamespaces':0,'scalePrincipals':0,'connectionHeadroom':8,'databaseBytes':1024}

def root_lock_fstat(root):
 original=os.fstat
 def observed(fd):
  info=original(fd);lock=root/'.lock'
  if lock.exists() and (info.st_dev,info.st_ino)==(lock.stat().st_dev,lock.stat().st_ino):return types.SimpleNamespace(st_mode=info.st_mode,st_uid=0,st_nlink=1)
  return info
 return observed

def drafts(profile='primary'):
 before={'url':'ldaps://example.test','passwordFile':'/private/bind-secret','mapping':{'sourceId':'old-source','revision':7,'identities':[{'directoryId':'old-user','aliases':['old-alias']}],'namespaces':['old-ns'],'approvedTransitions':None,'bindings':[{'groupId':'old-group','namespaceId':'old-ns','role':'admin'}]}}
 state={'revision':9,'users':[{'directoryId':'old-user','enabled':False}],'groups':[{'id':'old-group','members':['old-user']}]}
 seed={'identities':[dict(directoryId=u['directoryId'],subject=u['subject'],displayName=u['name'],issuer=c.ISSUER,principalId='79000000-0000-4000-8000-%012d'%i) for i,u in enumerate(scale_input(profile)['users'],1)],
  'namespaces':[{'id':'77000000-0000-4000-8000-%012d'%i,'name':name} for i,name in enumerate(c.names(profile),1)]}
 after=copy.deepcopy(before);after['mapping']['revision']+=1;after['mapping']['approvedTransitions']=[];after['mapping']['identities']+=copy.deepcopy(seed['identities'])
 new=copy.deepcopy(state);new['revision']+=1;members=[u['directoryId'] for u in seed['identities']];new['users'] +=[{'directoryId':u,'enabled':True} for u in members]
 for i,row in enumerate(seed['namespaces']):
  group='78000000-0000-4000-8000-%012d'%((101 if profile=='primary' else 201)+i)
  after['mapping']['namespaces'].append(row['id']);after['mapping']['approvedTransitions'].append(row['id']);after['mapping']['bindings'].append({'groupId':group,'namespaceId':row['id'],'role':'viewer'});new['groups'].append({'id':group,'members':members[:]})
 return before,state,after,new,seed

class ScaleSourceTests(unittest.TestCase):
 def test_input_real_subjects_fixed_profiles_and_time(self):
  for profile in c.PROFILES:self.assertEqual(c.validate_input(scale_input(profile),profile)['instanceId'],c.PROFILES[profile]['instance'])
  for change in ('duplicate','nil','wrong_instance','wrong_guid','time','unknown'):
   value=scale_input()
   if change=='duplicate':value['users'][1]['subject']=value['users'][0]['subject']
   if change=='nil':value['users'][0]['subject']='00000000-0000-0000-0000-000000000000'
   if change=='wrong_instance':value['instanceId']=c.PROFILES['secondary']['instance']
   if change=='wrong_guid':value['users'][0]['directoryId']='75000000-0000-4000-8000-000000000001'
   if change=='time':value['historyAt']=value['historyAt'].replace('Z','+00:00')
   if change=='unknown':value['extra']=True
   with self.subTest(change=change),self.assertRaises(c.Failure):c.validate_input(value,'primary')

 def test_environment_decodes_quoted_values_without_evaluation(self):
  raw=b'JOBMAN_CONTROL_DATABASE_URL="postgres://user:p%40ss@10.77.0.20:5432/test?sslmode=verify-full"\nJOBMAN_CONTROL_LABEL="$(never-execute)"\n'
  self.assertEqual(g.environment(raw)['JOBMAN_CONTROL_LABEL'],'$(never-execute)')
  for raw in (b'JOBMAN_CONTROL_X=unquoted',b'OTHER="bad"',b'JOBMAN_CONTROL_X="one"\nJOBMAN_CONTROL_X="two"',b'JOBMAN_CONTROL_X="\\n"'):
   with self.assertRaises(ValueError):g.environment(raw)

 def test_private_files_and_public_stage_modes_under_restrictive_umask(self):
  with tempfile.TemporaryDirectory() as value:
   root=Path(value).resolve();old=os.umask(0o077)
   try:
    c.directory(root/'public',0o755,True);c.put(root/'public/helper',b'fixed',0o755);c.put(root/'receipt',b'private')
   finally:os.umask(old)
   self.assertEqual(stat.S_IMODE((root/'public').stat().st_mode),0o755)
   self.assertEqual(stat.S_IMODE((root/'public/helper').stat().st_mode),0o755)
   self.assertEqual(c.read(root/'receipt'),b'private');c.retain(root/'receipt',b'private')
   with self.assertRaises(c.Failure):c.retain(root/'receipt',b'changed')
   os.link(root/'receipt',root/'hard')
   with self.assertRaises(c.Failure):c.read(root/'receipt')
   (root/'link').symlink_to(root/'public/helper')
   with self.assertRaises(OSError):c.read(root/'link',mode=0o755)

 def test_duplicate_json_and_command_output_deadline_bounds(self):
  with self.assertRaises(c.Failure):c.decode(b'{"key":1,"key":2}')
  with self.assertRaises(c.Failure):c.decode(b'{"key":NaN}')
  self.assertEqual(c.run([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],b'safe',timeout=2),b'safe')
  with self.assertRaisesRegex(c.Failure,'command_output_bound'):c.run([sys.executable,'-c','print("x"*1000)'],maximum=50,timeout=2)
  with self.assertRaisesRegex(c.Failure,'command_deadline'):c.run([sys.executable,'-c','import time;time.sleep(5)'],timeout=.05)

 def test_drafts_preserve_old_authority_and_only_add_viewers(self):
  for profile in c.PROFILES:
   before,state,after,new,seed=drafts(profile);original=copy.deepcopy((before,state))
   g.validate_drafts(profile,before,state,after,new,seed);self.assertEqual((before,state),original)
   for change in ('old_alias','old_disabled','new_admin','removed_namespace','bind_secret','revision'):
    changed=copy.deepcopy(after);members=copy.deepcopy(new)
    if change=='old_alias':changed['mapping']['identities'][0]['aliases']=[]
    if change=='old_disabled':members['users'][0]['enabled']=True
    if change=='new_admin':changed['mapping']['bindings'][-1]['role']='admin'
    if change=='removed_namespace':changed['mapping']['namespaces'].remove('old-ns')
    if change=='bind_secret':changed['passwordFile']='/different'
    if change=='revision':members['revision']-=1
    with self.subTest(profile=profile,change=change),self.assertRaisesRegex(c.Failure,'directory_draft_not_exactly_additive'):g.validate_drafts(profile,before,state,changed,members,seed)

 def test_database_preflight_rejects_collision_capacity_and_wrong_source(self):
  for key,value in (('database','jobman_control'),('instance',c.PROFILES['secondary']['instance']),('epoch','2'),('migrations',20),('scaleNamespaces',1),('scalePrincipals',1),('connectionHeadroom',7),('databaseBytes',(1<<30)+1),('namespaceTotal',2)):
   row=database();row[key]=value
   with self.subTest(key=key),patch.object(g,'sql',return_value=row),self.assertRaises(c.Failure):g.database_snapshot('primary',scale_input())
  with patch.object(g,'sql',return_value=database()) as query:self.assertEqual(g.database_snapshot('primary',scale_input()),database())
  self.assertNotIn('UPDATE ',query.call_args.args[1]);self.assertNotIn('INSERT ',query.call_args.args[1])

 def test_database_verification_requires_every_exact_namespace_and_no_execution(self):
  for profile in c.PROFILES:
   baseline=database(profile);row=copy.deepcopy(baseline);row.update(scaleNamespaces=c.PROFILES[profile]['count'],scalePrincipals=25,namespaceTotal=1+c.PROFILES[profile]['count'])
   counts=[{'name':name,'total':10050,'active':50,'imported':10000,'runs':0,'executions':0,'agents':0,'events':0} for name in c.names(profile)]
   with patch.object(g,'sql',side_effect=[row,counts]):self.assertEqual(len(g.database_snapshot(profile,scale_input(profile),baseline)['scaleCounts']),c.PROFILES[profile]['count'])
   for key in ('runs','executions','agents','events','active','imported'):
    changed=copy.deepcopy(counts);changed[0][key]+=1
    with self.subTest(profile=profile,key=key),patch.object(g,'sql',side_effect=[row,changed]),self.assertRaisesRegex(c.Failure,'scale_no_execution_counts'):g.database_snapshot(profile,scale_input(profile),baseline)
   row['jobs']['sha256']='d'*64
   with patch.object(g,'sql',return_value=row),self.assertRaisesRegex(c.Failure,'old_source_metadata_changed'):g.database_snapshot(profile,scale_input(profile),baseline)

 def test_readonly_sql_transaction_and_fixed_database(self):
  with patch.object(c,'run',return_value=b'{}') as run:g.sql('secondary','SELECT 1;')
  args=run.call_args.args;self.assertIn(c.PROFILES['secondary']['database'],args[0]);self.assertIn(b'REPEATABLE READ READ ONLY',args[1]);self.assertIn(b"statement_timeout='8s'",args[1]);self.assertTrue(args[1].endswith(b'ROLLBACK;'))

 def test_phase_host_and_apply_boundaries_precede_mutations(self):
  with patch.object(g.os,'geteuid',return_value=0),patch.object(g.os,'uname') as host,patch.object(g,'stage_binary') as stage:
   host.return_value.nodename='control01'
   with self.assertRaisesRegex(c.Failure,'apply_required'):g.execute({'phase':'stage'})
   stage.assert_not_called()
   host.return_value.nodename='pg01'
   with self.assertRaisesRegex(c.Failure,'fixed_guest_required'):g.execute({'phase':'stage','apply':True})
   stage.assert_not_called()

 def test_pending_seed_cannot_execute_again_even_after_lost_reply(self):
  with tempfile.TemporaryDirectory() as value:
   receipts=Path(value).resolve();execution='a'*64;root=receipts/execution;c.directory(root,create=True)
   payload={'profile':'primary','input':scale_input(),'executionId':execution,'baseline':{'files':{},'processes':{}},'implementationSHA256':'b'*64}
   intent={'profile':'primary','executionId':execution,'baselineSHA256':c.sha(c.encoded(payload['baseline'])),'inputSHA256':c.sha(c.encoded(payload['input'])),'implementationSHA256':'b'*64}
   c.put(root/'intent.json',c.encoded(intent));c.put(root/'pending.json',c.encoded(intent));helper=receipts/'helper';c.put(helper,b'helper',0o755)
   original_read=c.read
   def read(path,*args,**kwargs):
    if Path(path)==helper:kwargs['uid']=os.getuid()
    return original_read(path,*args,**kwargs)
   with patch.object(c,'RECEIPTS',receipts),patch.object(c,'BINARY',helper),patch.object(c,'BINARY_SHA',c.sha(b'helper')),patch.object(c,'read',side_effect=read),patch.object(g.os,'fstat',side_effect=root_lock_fstat(root)),patch.object(c,'run') as run:
    with self.assertRaisesRegex(c.Failure,'seed_pending_requires_inspection'):g.source_seed(payload)
    run.assert_not_called();self.assertTrue((root/'pending.json').exists())

 def test_completed_helper_reply_can_be_recovered_without_running_helper(self):
  with tempfile.TemporaryDirectory() as value:
   receipts=Path(value).resolve();root=receipts/('a'*64);c.directory(root,create=True);payload={'profile':'primary','input':scale_input(),'executionId':'a'*64,'baseline':{},'implementationSHA256':'b'*64}
   intent={'profile':'primary','executionId':'a'*64,'baselineSHA256':c.sha(c.encoded({})),'inputSHA256':c.sha(c.encoded(payload['input'])),'implementationSHA256':'b'*64}
   c.put(root/'intent.json',c.encoded(intent));c.put(root/'pending.json',c.encoded(intent));helper=receipts/'helper';c.put(helper,b'helper',0o755)
   original_read=c.read
   def read(path,*args,**kwargs):
    if Path(path)==helper:kwargs['uid']=os.getuid()
    return original_read(path,*args,**kwargs)
   # Validate the receipt recovery seam independently from helper completion
   # proof parsing, which has separate changed-baseline/receipt tests below.
   output={name:b'{}\n' for name in ('seed.json','directory.after.json','directory-state.after.json','receipt.json')}
   with patch.object(c,'RECEIPTS',receipts),patch.object(c,'BINARY',helper),patch.object(c,'BINARY_SHA',c.sha(b'helper')),patch.object(c,'read',side_effect=read),patch.object(g.os,'fstat',side_effect=root_lock_fstat(root)),patch.object(g,'seed_outputs',return_value=output),patch.object(c,'run') as run:
    result=g.source_seed(payload,verify=True);run.assert_not_called();self.assertEqual(set(result['files']),set(output))
   self.assertTrue((root/'pending.json').exists());self.assertTrue((root/'completed.json').exists())

 def test_source_files_allow_completed_diagnostic_but_reject_pending(self):
  with tempfile.TemporaryDirectory() as value:
   root=Path(value).resolve();profile=dict(c.PROFILES['primary'],root=str(root),directory=str(root),uid=os.getuid(),directoryUID=os.getuid())
   env={'JOBMAN_CONTROL_DATABASE_URL':'postgres://fixture:synthetic@10.77.0.20:5432/jobman_dashboard_control?sslmode=verify-full','JOBMAN_CONTROL_DIAGNOSTIC_DEPLOYMENT_ID':profile['deployment'],'JOBMAN_CONTROL_DIRECTORY_MODE':'enforce','JOBMAN_CONTROL_MIGRATE_ON_START':'false','JOBMAN_CONTROL_DIRECTORY_CONFIG_FILE':str(root/'directory.json')}
   c.put(root/'control.env',''.join(k+'='+__import__('json').dumps(v)+'\n' for k,v in env.items()).encode())
   for name,data in [('fixture-info.json',{'synthetic':True,'instanceId':profile['instance']}),('directory.json',{}),('directory-state.json',{}),('delegation.json',{}),('diagnostic-fixture.json',{'completed':True})]:c.put(root/name,c.encoded(data))
   with patch.dict(c.PROFILES,{'primary':profile}):
    self.assertEqual(len(g.source_files('primary')[0]),5)
    c.put(root/'.diagnostic-prepare.json',b'{}')
    with self.assertRaisesRegex(c.Failure,'unfinished_source_operation'):g.source_files('primary')

 def test_output_requires_exact_helper_completion_and_preserved_source(self):
  with tempfile.TemporaryDirectory() as value:
   base=Path(value).resolve();source=base/'source';root=base/'operation';c.directory(source,create=True);c.directory(root,create=True);c.directory(root/'output',create=True)
   profile=dict(c.PROFILES['primary'],root=str(source),directory=str(source));value=scale_input();before,state,after,next_state,seed=drafts()
   for i,row in enumerate(seed['namespaces'],1):row.update(activeJobs=50,importedHistory=10000,activeJobId='71000000-0000-4000-8000-%012d'%i,importedJobId='72000000-0000-4000-8000-%012d'%i)
   for identity in seed['identities']:identity['aliases']=None
   # Regenerate the expected draft's appended identities after adding the
   # explicit Go nil-alias representation; baseline aliases remain untouched.
   after['mapping']['identities']=before['mapping']['identities']+copy.deepcopy(seed['identities'])
   seed.update(version=1,synthetic=True,mode='imported-history-no-execution',deploymentId=profile['deployment'],instanceId=profile['instance'],recoveryEpoch='1',historyAt=value['historyAt'])
   raw={str(source/'directory.json'):c.encoded(before),str(source/'directory-state.json'):c.encoded(state)};files={name:c.sha(data) for name,data in raw.items()};baseline={'files':files,'processes':{'source':'stable'}}
   receipt={'version':1,'synthetic':True,'helperCommit':c.COMMIT,'instanceId':profile['instance'],'deploymentId':profile['deployment'],'inputSHA256':c.sha(c.encoded(value)),'directorySHA256':files[str(source/'directory.json')],'directoryStateSHA256':files[str(source/'directory-state.json')],'output':str(root/'output')}
   for name,data in [('seed.json',seed),('directory.after.json',after),('directory-state.after.json',next_state),('receipt.json',receipt)]:c.put(root/'output'/name,c.encoded(data))
   for name in ('.scale-seed.pending.json','.scale-seed.completed.json'):c.put(source/name,c.encoded(receipt))
   with patch.dict(c.PROFILES,{'primary':profile}),patch.object(g,'source_files',return_value=(files,raw,'private')),patch.object(g,'processes',return_value=baseline['processes']):
    self.assertEqual(len(g.seed_outputs('primary',value,root,baseline)),4)
    changed=copy.deepcopy(receipt);changed['helperCommit']='0'*40;(source/'.scale-seed.completed.json').write_bytes(c.encoded(changed))
    with self.assertRaisesRegex(c.Failure,'helper_completion_receipt'):g.seed_outputs('primary',value,root,baseline)
   with patch.dict(c.PROFILES,{'primary':profile}),patch.object(g,'source_files',return_value=(files,raw,'private')),patch.object(g,'processes',return_value={'source':'restarted'}),self.assertRaisesRegex(c.Failure,'source_baseline_changed'):g.seed_outputs('primary',value,root,baseline)

 def test_handoff_rejects_actual_subject_substitution_or_file_drift(self):
  with tempfile.TemporaryDirectory() as value:
   root=Path(value).resolve();values={profile:scale_input(profile) for profile in c.PROFILES};record={'version':1,'synthetic':True,'issuer':c.ISSUER,'users':values['primary']['users']}
   handoff={'stageSHA256':'a'*64,'historyAt':values['primary']['historyAt'],'files':{profile+'-scale-input.json':c.sha(c.encoded(row)) for profile,row in values.items()}}
   for name,data in [('identities.json',record),('handoff.json',handoff),*[(profile+'-scale-input.json',row) for profile,row in values.items()]]:c.put(root/name,c.encoded(data))
   self.assertEqual(h.identities(root,'secondary')[0],values['secondary'])
   record['users'][0]['subject']='76000000-0000-4000-8000-000000000099';(root/'identities.json').write_bytes(c.encoded(record))
   with self.assertRaisesRegex(h.c.Failure,'actual_subject_handoff'):h.identities(root,'primary')

 def test_seed_output_transfer_is_private_and_hash_bound(self):
  with tempfile.TemporaryDirectory() as value:
   root=Path(value).resolve();files={name:b'{}\n' for name in ('seed.json','directory.after.json','directory-state.after.json','receipt.json')};result={'receipt':{'outputSHA256':{k:c.sha(v) for k,v in files.items()}},'files':{k:base64.b64encode(v).decode() for k,v in files.items()}}
   h.output(root,result);self.assertEqual(c.read(root/'handoff/seed.json'),b'{}\n')
   result['files']['seed.json']=base64.b64encode(b'{"different":true}\n').decode()
   with self.assertRaisesRegex(h.c.Failure,'seed_handoff_hash'):h.output(root,result)

if __name__=='__main__':unittest.main()
