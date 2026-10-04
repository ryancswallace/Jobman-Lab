#!/usr/bin/env python3
"""Offline only: no Lab credential reads, SSH, PostgreSQL or guest operations."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name):
 spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
host=load('dashboard-scale-activation');a=host.a;c=a.c;factory=load('test-dashboard-scale-plan');runtime=load('dashboard-multisource-runtime')
guest=types.ModuleType('guest');guest.__dict__.update(activation=a,runtime=runtime);exec(compile((HERE/'dashboard-scale-activation-guest.py').read_text(),'guest','exec'),guest.__dict__)


def fixture():
 configs,registries,seeds=factory.fixture();runtime_values={name:a.encoded_file(c.encoded(value)) for name,value in configs.items()};runtime_values['recovery']=a.encoded_file(c.encoded(a.recovery(configs['api'],configs['worker'])))
 sources={};handoffs={}
 for profile,p in a.PROFILES.items():
  seed=seeds[p['deployment']]
  for row in seed['identities']:row['aliases']=None
  oldids=configs['api']['controls'][0 if profile=='primary' else 1]['namespaceIds']
  originals=[{'directoryId':factory.uid(6000+i),'principalId':factory.uid(7000+i),'issuer':c.ISSUER,'subject':factory.uid(8000+i),'displayName':'Original '+str(i),'aliases':None} for i in range(2)]
  before={'url':'ldaps://127.0.0.1:18636','passwordFile':'/unchanged/private','mapping':{'sourceId':p['sourceId'],'revision':4,'identities':originals,'namespaces':oldids,'approvedTransitions':[],'bindings':[]}}
  state={'revision':3,'users':[{'directoryId':row['directoryId'],'enabled':True} for row in originals],'groups':[{'id':factory.uid(9000+i),'members':[originals[0]['directoryId']]} for i in range(8)]}
  after=copy.deepcopy(before);next_state=copy.deepcopy(state);after['mapping']['revision']=5;next_state['revision']=4
  after['mapping']['identities']+=seed['identities'];next_state['users']+=[{'directoryId':row['directoryId'],'enabled':True} for row in seed['identities']]
  for i,row in enumerate(seed['namespaces']):
   group='78000000-0000-4000-8000-%012d'%((101 if profile=='primary' else 201)+i)
   after['mapping']['namespaces'].append(row['id']);after['mapping']['approvedTransitions'].append(row['id']);after['mapping']['bindings'].append({'groupId':group,'namespaceId':row['id'],'role':'viewer'});next_state['groups'].append({'id':group,'members':[row['directoryId'] for row in seed['identities']]})
  source={name:a.encoded_file(c.encoded(value)) for name,value in [('directory',before),('state',state),('registry',registries[p['deployment']])]};sources[profile]=source
  execution=('a' if profile=='primary' else 'b')*64
  receipt={'version':1,'synthetic':True,'helperCommit':c.COMMIT,'instanceId':p['instance'],'deploymentId':p['deployment'],'inputSHA256':'c'*64,'directorySHA256':c.sha(a.raw(source['directory'])),'directoryStateSHA256':c.sha(a.raw(source['state'])),'output':str(c.RECEIPTS/execution/'output')}
  handoffs[profile]={name:a.encoded_file(c.encoded(value)) for name,value in [('seed.json',seed),('directory.after.json',after),('directory-state.after.json',next_state),('receipt.json',receipt)]}
  driver={'profile':profile,'executionId':execution,'helperCommit':c.COMMIT,'helperSHA256':c.BINARY_SHA,'outputSHA256':{name:c.sha(a.raw(value)) for name,value in handoffs[profile].items()},'sourceStatePreserved':True}
  handoffs[profile]['driver-receipt.json']=a.encoded_file(c.encoded(driver))
 snapshot={'version':1,'runtime':runtime_values,'sources':sources}
 return snapshot,handoffs


def mutate_file(handoff,name,fn):
 value=a.document(handoff[name]);fn(value);handoff[name]=a.encoded_file(c.encoded(value))
 if name!='driver-receipt.json':
  driver=a.document(handoff['driver-receipt.json']);driver['outputSHA256'][name]=c.sha(a.raw(handoff[name]));handoff['driver-receipt.json']=a.encoded_file(c.encoded(driver))


class ScaleActivation(unittest.TestCase):
 def test_coverage_nanoseconds_validate_on_python39_without_changing_digest(self):
  from datetime import datetime
  class Python39:
   @staticmethod
   def fromisoformat(value):
    fraction=__import__('re').search(r'\.(\d+)',value)
    if fraction and len(fraction.group(1)) not in (3,6):raise ValueError('Python3.9 fraction')
    return datetime.fromisoformat(value)
  for digits in range(10):
   stamp='2026-10-04T11:10:54'+('.'+'175884721'[:digits] if digits else '')+'Z'
   with self.subTest(digits=digits),patch.dict('sys.modules',{'datetime':types.SimpleNamespace(datetime=Python39)}):a.validate_coverage_timestamp(stamp)
  for stamp in ('2026-10-04T11:10:54.17588472Z','2026-10-04T13:10:54.175884721+02:00'):
   original={'completedAt':stamp,'nested':{'asOf':stamp}};before=c.encoded(original)
   with patch.dict('sys.modules',{'datetime':types.SimpleNamespace(datetime=Python39)}):
    a.validate_coverage_timestamp(original['completedAt']);a.validate_coverage_timestamp(original['nested']['asOf'])
   self.assertEqual(c.encoded(original),before);self.assertEqual(c.sha(c.encoded(original)),c.sha(before))
  for stamp in ('2026-10-04T11:10:54.1234567890Z','2026-10-04 11:10:54Z','2026-10-04T11:10:54','2026-02-30T11:10:54Z','2026-10-04T25:10:54Z','2026-10-04T11:10:54+24:00','2026-10-04T11:10:54+02:99','2026-10-04T11:10:54.Z'):
   with self.subTest(stamp=stamp),self.assertRaisesRegex(ValueError,'coverage_timestamp'):a.validate_coverage_timestamp(stamp)

 def test_source_registry_transition_requires_real_per_source_checkpoint(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve()
   for phase in ('restart-api','restart-broker','restart-worker','recovery-plan'):
    self.assertEqual(host.registry_revision_window(root,phase),(7,8))
   for phase in ('recovery-step','recovery-reconcile','recovery-apply','resume','verify'):
    self.assertEqual(host.registry_revision_window(root,phase),8)
   for phase in ('runtime-storage','directory-primary','trust-secondary'):
    self.assertEqual(host.registry_revision_window(root,phase),7)
   c.put(root/'restart-api.json',c.encoded({'role':'api','ready':True,'revision':8}))
   for phase in ('runtime-storage','directory-primary','trust-secondary'):
    self.assertEqual(host.registry_revision_window(root,phase),8)
   for phase in ('restart-api','restart-broker','restart-worker','recovery-plan'):
    self.assertEqual(host.registry_revision_window(root,phase),(7,8))
  snapshot,handoffs=fixture();plan=a.draft(snapshot,handoffs)
  value={'identities':[{'deploymentId':p['deployment'],'revision':7} for p in a.PROFILES.values()]}
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();host.planned_registry_fence(root,value,plan)
   with self.assertRaises(ValueError):host.planned_registry_fence(root,value,plan,'primary')
   value['identities'][0]['revision']=8;host.planned_registry_fence(root,value,plan,'primary')
   with self.assertRaises(ValueError):host.planned_registry_fence(root,value,plan,'secondary')
   # An acknowledged source cannot regress to 7 while its sibling plans.
   c.put(root/'recovery-plan-primary.json',c.encoded({'already':'validated'}))
   with patch.object(a,'validate_recovery') as validate:
    host.planned_registry_fence(root,value,plan);validate.assert_called_once()
    value['identities'][0]['revision']=7
    with self.assertRaises(ValueError):host.planned_registry_fence(root,value,plan)

 def test_additive_plan_preserves_recovery_authority_and_original_bytes(self):
  snapshot,handoffs=fixture();original=copy.deepcopy((snapshot,handoffs));plan=a.draft(snapshot,handoffs)
  self.assertEqual((snapshot,handoffs),original);self.assertFalse(plan['automaticFeedReset'])
  self.assertEqual(plan['runtime']['operator'],snapshot['runtime']['operator'])
  recovery=a.document(plan['runtime']['recovery']);self.assertEqual(recovery['databaseURLFile'],a.PRIVILEGED_DSN);self.assertEqual(recovery['controls'],a.document(plan['runtime']['worker'])['controls'])
  self.assertEqual(recovery['configurationRevision'],8);self.assertFalse(recovery['events']['deliveryHold']);self.assertNotIn('observability',recovery)
  for profile,p in a.PROFILES.items():
   mapping=a.document(plan['sources'][profile]['directory'])['mapping'];self.assertEqual(len(mapping['identities']),27);self.assertEqual(len(mapping['namespaces']),p['count']+2)
   self.assertTrue(all(row['role']=='viewer' for row in mapping['bindings']))

 def test_seed_wrong_instance_profile_hash_or_helper_cannot_authorize_draft(self):
  for name,fn in [('receipt.json',lambda v:v.update(instanceId=factory.uid(99))),('driver-receipt.json',lambda v:v.update(profile='secondary')),('driver-receipt.json',lambda v:v.update(helperSHA256='f'*64)),('driver-receipt.json',lambda v:v['outputSHA256'].update(**{'seed.json':'f'*64}))]:
   snapshot,handoffs=fixture();mutate_file(handoffs['primary'],name,fn)
   with self.subTest(name=name),self.assertRaises(ValueError):a.draft(snapshot,handoffs)

 def test_retained_directory_entries_and_exact_viewer_groups_are_mandatory(self):
  edits=[('directory.after.json',lambda v:v['mapping']['bindings'][0].update(role='namespace_admin')),
   ('directory.after.json',lambda v:v.update(passwordFile='/different-secret')),
   ('directory.after.json',lambda v:v['mapping']['identities'][0].update(subject=factory.uid(123))),
   ('directory-state.after.json',lambda v:v['groups'][0]['members'].clear()),
   ('directory-state.after.json',lambda v:v['groups'][-1]['members'].pop()),
   ('seed.json',lambda v:v['identities'][0].update(aliases=[{'issuer':c.ISSUER,'subject':'extra'}]))]
  for name,fn in edits:
   snapshot,handoffs=fixture();mutate_file(handoffs['primary'],name,fn)
   with self.subTest(name=name),self.assertRaises(ValueError):a.draft(snapshot,handoffs)

 def test_old_directory_cas_and_existing_operator_worker_identity_are_bound(self):
  for target in ('directory','recovery'):
   snapshot,handoffs=fixture()
   if target=='directory':snapshot['sources']['secondary']['directory']=a.encoded_file(c.encoded({'changed':True}))
   else:
    value=a.document(snapshot['runtime']['recovery']);value['controls']=a.document(snapshot['runtime']['api'])['controls'];snapshot['runtime']['recovery']=a.encoded_file(c.encoded(value))
   with self.subTest(target=target),self.assertRaises(ValueError):a.draft(snapshot,handoffs)

 def test_plan_and_implementation_digest_prevent_repurposing(self):
  snapshot,handoffs=fixture();plan=a.draft(snapshot,handoffs);self.assertNotEqual(a.binding(snapshot,handoffs,plan,'1'*64),a.binding(snapshot,handoffs,plan,'2'*64))
  plan['automaticFeedReset']=True
  with self.assertRaises(ValueError):a.binding(snapshot,handoffs,plan,'1'*64)

 def test_recovery_requires_exact_additions_retained_mode_and_no_removal(self):
  snapshot,handoffs=fixture();plan=a.draft(snapshot,handoffs);scope=plan['feedRecoveryRequired'][0]
  value={'id':factory.uid(80),'gapId':factory.uid(81),'digest':'d'*64,'deploymentId':scope['deploymentId'],'configurationRevision':'8','mode':'retained','reason':'event_cursor_scope_changed','effectiveReason':'event_cursor_scope_changed','removedNamespaceIds':[],'addedNamespaceIds':sorted(set(scope['newNamespaceIds'])-set(scope['oldNamespaceIds'])),'namespaceIds':scope['newNamespaceIds'],'revision':'1','feedGeneration':'2','pages':'0','scanned':'0','added':'0','uncertainty':{'dashboardRestored':False,'suppressAllRecovered':False},'status':'ready'}
  self.assertEqual(a.validate_recovery(value,'primary',plan),value)
  for fn in [lambda v:v.update(mode='continue'),lambda v:v.update(configurationRevision='7'),lambda v:v['removedNamespaceIds'].append(factory.uid(88)),lambda v:v['addedNamespaceIds'].pop(),lambda v:v['uncertainty'].update(dashboardRestored=True),lambda v:v.update(status='quarantined')]:
   bad=copy.deepcopy(value);fn(bad)
   with self.assertRaises(ValueError):a.validate_recovery(bad,'primary',plan)

 def test_monotonic_feed_generation_not_equality_and_hold_floor_stays(self):
  snapshot,handoffs=fixture();plan=a.draft(snapshot,handoffs)
  value={'database':'jobman_dashboard','migrations':18,'bindingCount':0,'bindingSHA256':'b'*64,'hold':{'held':False,'generation':3,'restoreRecordedThrough':None},'identities':[],'feeds':[]}
  for item in plan['feedRecoveryRequired']:
   value['identities'].append({'deploymentId':item['deploymentId'],'instanceId':item['instanceId'],'epoch':'1','revision':7});value['feeds'].append({'deploymentId':item['deploymentId'],'namespaces':item['oldNamespaceIds'],'generation':10,'lastPosition':20,'status':'active','instanceId':item['instanceId'],'epoch':'1'})
  snapshot['database']=copy.deepcopy(value);value['feeds'][0]['generation']=30;value['feeds'][0]['lastPosition']=40;a.validate_database(value,snapshot,plan,False)
  value['feeds'][0]['generation']=9
  with self.assertRaises(ValueError):a.validate_database(value,snapshot,plan,False)
  value['feeds'][0]['generation']=30;value['hold']['restoreRecordedThrough']='2026-10-04T00:00:00Z'
  with self.assertRaises(ValueError):a.validate_database(value,snapshot,plan,False)

 def test_replay_and_apply_require_both_source_plans(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve()
   for name in ('hold','stop-worker','restart-api','restart-broker','restart-worker','recovery-plan-primary'):
    c.put(root/(name+'.json'),c.encoded({}))
   for phase in ('recovery-step','recovery-reconcile','recovery-apply'):
    with self.assertRaises(ValueError):host.required(root,phase,'primary')
   c.put(root/'recovery-plan-secondary.json',c.encoded({}))
   for phase in ('recovery-step','recovery-reconcile','recovery-apply'):
    for profile in a.PROFILES:host.required(root,phase,profile)

 def test_phase_order_keeps_directory_before_trust_and_explicit_resume(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve()
   for phase,profile in [('trust-primary',None),('runtime-storage',None),('recovery-apply','primary'),('resume',None)]:
    with self.assertRaises(ValueError):host.required(root,phase,profile)
   for name in ('hold','stop-worker','directory-primary','directory-secondary'):(root/(name+'.json')).write_text('{}')
   host.required(root,'trust-primary',None)
   with self.assertRaises(ValueError):host.required(root,'resume',None)

 def test_descriptor_modes_and_exclusive_cas_recovery_without_overwrite(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();path=root/'config';path.write_bytes(b'before');path.chmod(0o600);bound={'executionId':'a'*64,'phase':'test','planSHA256':'b'*64}
   read=lambda path,uid,*args,**kwargs:c.read(path,uid=os.getuid())
   put=lambda path,data,uid=0:c.put(path,data)
   old=os.umask(0o777)
   try:
    with patch.object(runtime,'read',read),patch.object(runtime,'put',put):
     guest.swap(root,'sample',path,a.encoded_file(b'before'),a.encoded_file(b'after'),os.getuid(),bound)
     guest.swap(root,'sample',path,a.encoded_file(b'before'),a.encoded_file(b'after'),os.getuid(),bound)
     self.assertEqual(path.read_bytes(),b'after');self.assertEqual(path.stat().st_mode&0o777,0o600)
     path.write_bytes(b'foreign')
     with self.assertRaises(ValueError):guest.swap(root,'sample',path,a.encoded_file(b'before'),a.encoded_file(b'after'),os.getuid(),bound)
   finally:os.umask(old)

 def test_changed_completion_binding_or_missing_pending_is_rejected(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();bound={'a':1}
   with patch.object(runtime,'read',lambda path,uid:c.read(path,uid=os.getuid())),patch.object(runtime,'put',lambda path,raw:c.put(path,raw)):
    self.assertIsNone(guest.begin(root,'phase',bound));guest.retain(root/'phase.json',bound)
    self.assertEqual(guest.begin(root,'phase',bound),bound)
    with self.assertRaises(ValueError):guest.begin(root,'phase',{'a':2})
    (root/'phase.pending.json').unlink()
    with self.assertRaises(ValueError):guest.begin(root,'phase',bound)

 def test_sql_transport_is_fixed_read_only_and_bounded(self):
  calls=[]
  def run(args,code,**kwargs):calls.append((args,kwargs));return b'{}'
  with patch.object(runtime,'run',run):
   guest.database()
   with self.assertRaises(ValueError):guest.query('jobman_control','SELECT 1;')
  self.assertEqual(len(calls),1);args,kwargs=calls[0];self.assertEqual(args[-1],'jobman_dashboard');self.assertIn('jobman_control',args)
  sql=kwargs['input_data'].decode();self.assertTrue(sql.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'));self.assertTrue(sql.endswith('ROLLBACK;'));self.assertIn("statement_timeout='5s'",sql);self.assertLessEqual(kwargs['timeout'],8)

 def test_hold_timestamp_equivalence_does_not_bypass_generation_or_cutoff(self):
  first={'generation':'4','held':True,'restoreRecordedThrough':'2026-10-04T00:00:00Z'}
  self.assertTrue(guest.same_hold(first,dict(first,generation=4,restoreRecordedThrough='2026-10-04T00:00:00+00:00')))
  self.assertFalse(guest.same_hold(first,dict(first,generation='5')));self.assertFalse(guest.same_hold(first,dict(first,restoreRecordedThrough=None)))


 def test_legacy_recovery_static_root_is_the_only_allowed_rc2_difference(self):
  snapshot,handoffs=fixture();api=a.document(snapshot['runtime']['api']);api['webRoot']='/opt/jobman-dashboard-lab/releases/'+'4'*40+'/web';snapshot['runtime']['api']=a.encoded_file(c.encoded(api))
  recovery=a.document(snapshot['runtime']['recovery']);recovery['webRoot']=a.LEGACY_WEB_ROOT;snapshot['runtime']['recovery']=a.encoded_file(c.encoded(recovery));a.draft(snapshot,handoffs)
  recovery['webRoot']='/arbitrary/retired/path';snapshot['runtime']['recovery']=a.encoded_file(c.encoded(recovery))
  with self.assertRaises(ValueError):a.draft(snapshot,handoffs)

 def test_restart_chain_only_adopts_an_unfinished_exact_bound_intent(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();payload={'executionId':'a'*64,'plan':{'safe':True}};bound=guest.phase_binding(payload,'directory-primary')
   original={'uid':21902,'exe':'/exact','binarySHA256':'b'*64,'unitSHA256':'c'*64,'pid':'1'};updated=dict(original,pid='2');foreign=dict(original,pid='3');label='directory-primary-restart';labels=[(label,'directory-primary')]
   with patch.object(runtime,'read',lambda path,uid:c.read(path,uid=os.getuid())):
    guest.restart_chain(root,labels,original,original,payload)
    with self.assertRaises(ValueError):guest.restart_chain(root,labels,updated,original,payload)
    c.put(root/(label+'.pending.json'),c.encoded(bound));c.put(root/(label+'.started.json'),c.encoded({'binding':bound,'process':original}))
    guest.restart_chain(root,labels,updated,original,payload)
    c.put(root/(label+'.json'),c.encoded({'binding':bound,'process':updated}));guest.restart_chain(root,labels,updated,original,payload)
    with self.assertRaises(ValueError):guest.restart_chain(root,labels,foreign,original,payload)
    (root/(label+'.pending.json')).write_bytes(c.encoded(dict(bound,executionId='d'*64)))
    with self.assertRaises(ValueError):guest.restart_chain(root,labels,updated,original,payload)

 def test_fresh_authority_rejects_stale_alias_or_nonviewer_grants(self):
  snapshot,handoffs=fixture();plan=a.draft(snapshot,handoffs);profile='primary';p=a.PROFILES[profile];mapping=a.document(plan['sources'][profile]['directory'])['mapping']
  original=[[factory.uid(400),factory.uid(401),['viewer']]];snapshot['oldAuthority']={profile:{'originalGrantSHA256':c.sha(c.encoded(original))}}
  payload={'snapshot':snapshot,'plan':plan,'handoffs':handoffs};value={'database':p['database'],'instance':p['instance'],'epoch':'1','migrations':21,'mapping':mapping,'sourceFresh':True,'accountsFresh':27,'namespacesFresh':12,'viewerPairs':250,'unexpectedNewGrants':0,'originalGrants':original,'aliases':[{key:row[key] for key in ('directoryId','principalId','issuer','subject')} for row in mapping['identities']]}
  with patch.object(guest,'query',return_value=value):self.assertEqual(guest.authority(profile,payload)['viewerPairs'],250)
  for fn in [lambda v:v.update(sourceFresh=False),lambda v:v.update(accountsFresh=26),lambda v:v.update(namespacesFresh=11),lambda v:v.update(unexpectedNewGrants=1),lambda v:v.update(viewerPairs=249),lambda v:v['aliases'][0].update(subject=factory.uid(999)),lambda v:v['originalGrants'][0][2].append('namespace_admin')]:
   bad=copy.deepcopy(value);fn(bad)
   with patch.object(guest,'query',return_value=bad),self.assertRaises(ValueError):guest.authority(profile,payload)

 def test_seed_guest_completion_binds_outputs_and_reviewed_driver(self):
  snapshot,handoffs=fixture();payload={'handoffs':handoffs};files={}
  for profile,p in a.PROFILES.items():
   handoff=handoffs[profile];driver=a.document(handoff['driver-receipt.json']);receipt=a.document(handoff['receipt.json']);root=c.RECEIPTS/driver['executionId'];intent={'profile':profile,'executionId':driver['executionId'],'implementationSHA256':a.SOURCE_IMPLEMENTATION_SHA,'inputSHA256':receipt['inputSHA256']}
   files[root/'completed.json']=c.encoded(driver);files[root/'intent.json']=files[root/'pending.json']=c.encoded(intent)
   for name in ('.scale-seed.pending.json','.scale-seed.completed.json'):files[Path(p['root'])/name]=c.encoded(receipt)
   for name in driver['outputSHA256']:files[root/'output'/name]=a.raw(handoff[name])
  with patch.object(runtime,'read',lambda path,uid:files[path]):guest.seed_evidence(payload)
  files[next(path for path in files if path.name=='seed.json')]=b'changed'
  with patch.object(runtime,'read',lambda path,uid:files[path]),self.assertRaises(ValueError):guest.seed_evidence(payload)

 def test_coverage_requires_exact_ready_revision_scope_and_truthful_unavailability(self):
  snapshot,handoffs=fixture();plan=a.draft(snapshot,handoffs);scope=plan['feedRecoveryRequired'][0]
  state={'id':factory.uid(80),'gapId':factory.uid(81),'digest':'d'*64,'deploymentId':scope['deploymentId'],'configurationRevision':'8','mode':'retained','reason':'event_cursor_scope_changed','effectiveReason':'event_cursor_scope_changed','removedNamespaceIds':[],'addedNamespaceIds':sorted(set(scope['newNamespaceIds'])-set(scope['oldNamespaceIds'])),'namespaceIds':scope['newNamespaceIds'],'revision':'4','feedGeneration':'2','pages':'1','scanned':'5','added':'0','uncertainty':{'dashboardRestored':False,'suppressAllRecovered':False},'status':'ready'}
  receipt={'planDigest':state['digest'],'acknowledgedGap':True,'completedAt':'2026-10-04T00:00:00Z','namespaces':[{'namespaceId':key,'status':'unavailable','jobsRead':'0'} for key in state['namespaceIds']]};value={'recovery':state,'reconciliation':receipt}
  a.validate_coverage(value,'primary',plan,state)
  for fn in [lambda v:v['reconciliation']['namespaces'].pop(),lambda v:v['reconciliation']['namespaces'][0].update(jobsRead='1'),lambda v:v['reconciliation'].update(acknowledgedGap=False),lambda v:v['recovery'].update(revision='3')]:
   bad=copy.deepcopy(value);fn(bad)
   with self.assertRaises(ValueError):a.validate_coverage(bad,'primary',plan,state)
  # CLI reconcile returns the receipt itself, not a nested recovery object.
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();c.put(root/'recovery-primary-plan.json',c.encoded(state));payload={'phase':'recovery-reconcile','profile':'primary','plan':plan};calls=[]
   def cli(payload,command,*args):calls.append(command);return state if command=='status' else receipt
   with patch.object(guest,'cli',cli),patch.object(runtime,'read',lambda path,uid:c.read(path,uid=os.getuid())),patch.object(runtime,'put',lambda path,raw:c.put(path,raw)):
    self.assertEqual(guest.recover(payload,root,{}),value)
   self.assertEqual(calls,['status','reconcile'])

 def test_verified_handoff_requires_matching_preflight_implementation(self):
  snapshot,handoffs=fixture();handoff=handoffs['primary'];profile='primary';p=a.PROFILES[profile]
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();out=root/'handoff';out.mkdir(mode=0o700);preflight={'implementationSHA256':a.SOURCE_IMPLEMENTATION_SHA,'profile':profile};c.put(root/'preflight.json',c.encoded(preflight));driver=a.document(handoff['driver-receipt.json']);driver['executionId']=c.sha(c.encoded(preflight))
   for name,value in handoff.items():c.put(out/name,c.encoded(driver) if name=='driver-receipt.json' else a.raw(value))
   c.put(root/'verify.complete.json',c.encoded({'receipt':driver,'database':{'database':p['database'],'instance':p['instance'],'epoch':'1','migrations':21}}));host.read_handoff(out,profile)
   preflight['implementationSHA256']='0'*64;(root/'preflight.json').write_bytes(c.encoded(preflight))
   with self.assertRaises(ValueError):host.read_handoff(out,profile)

 def test_final_verification_rejects_later_hold_generation_or_cutoff(self):
  resumed={'generation':'5','held':False,'restoreRecordedThrough':'2026-10-04T00:00:00Z'}
  a.resumed_hold({'generation':5,'held':False,'restoreRecordedThrough':'2026-10-04T00:00:00+00:00'},resumed)
  for actual in [dict(resumed,generation=6,held=True),dict(resumed,generation=7),dict(resumed,restoreRecordedThrough=None),dict(resumed,held=True)]:
   with self.subTest(actual=actual),self.assertRaisesRegex(ValueError,'completed_resume_changed'):a.resumed_hold(actual,resumed)

 def test_recovery_pages_cap_remaining_budget_and_accept_ready_at_limit(self):
  snapshot,handoffs=fixture();plan=a.draft(snapshot,handoffs);scope=plan['feedRecoveryRequired'][0]
  original={'id':factory.uid(80),'gapId':factory.uid(81),'digest':'d'*64,'deploymentId':scope['deploymentId'],'configurationRevision':'8','mode':'retained','reason':'event_cursor_scope_changed','effectiveReason':'event_cursor_scope_changed','removedNamespaceIds':[],'addedNamespaceIds':sorted(set(scope['newNamespaceIds'])-set(scope['oldNamespaceIds'])),'namespaceIds':scope['newNamespaceIds'],'revision':'4','feedGeneration':'2','pages':'499','scanned':'5','added':'0','uncertainty':{'dashboardRestored':False,'suppressAllRecovered':False},'status':'replaying'}
  payload={'phase':'recovery-step','profile':'primary','plan':plan}
  for pages,status,result_pages,want_step,fails in [(499,'replaying',500,True,False),(500,'ready',500,False,False),(500,'replaying',500,False,True),(499,'replaying',501,True,True)]:
   with self.subTest(pages=pages,status=status,result_pages=result_pages),tempfile.TemporaryDirectory() as directory:
    root=Path(directory).resolve();c.put(root/'recovery-primary-plan.json',c.encoded(original));current=dict(original,pages=str(pages),status=status);result=dict(current,pages=str(result_pages),status='ready',revision='5');calls=[]
    def cli(payload,command,*args):calls.append((command,args));return current if command=='status' else result
    with patch.object(guest,'cli',cli),patch.object(runtime,'read',lambda path,uid:c.read(path,uid=os.getuid())),patch.object(runtime,'put',lambda path,raw:c.put(path,raw)):
     if fails:
      with self.assertRaises(ValueError):guest.recover(payload,root,{})
     else:self.assertEqual(guest.recover(payload,root,{})['pages'],'500')
    self.assertEqual(len(calls),2 if want_step else 1)
    if want_step:self.assertEqual(calls[1][1][-2:],('--pages','1'))


if __name__=='__main__':unittest.main()
