#!/usr/bin/env python3
"""Offline graph planning, scope, quota and retained-publication regressions."""
import argparse
import base64
import copy
import contextlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('graph_host',HERE/'prepare-dashboard-graph-ceiling.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
p,c=h.p,h.c

def fixture():
 meta={'revision':'a'*40,'os':'linux','architecture':'arm64','twiceIdentical':True}
 binary=b'\x7fELF\x02\x01'+b'\0'*12+(183).to_bytes(2,'little')+b'a'*40
 meta['binarySHA256']=c.sha(binary);helper=p.candidate(meta,binary)
 policy={'namespace':p.NAMESPACE,'maxActiveJobs':20,'maxQueuedJobs':10000,'maxCollectionItems':10000,'maxGraphNodes':10000,'idempotencyRetention':86400000000000,'publishedOutboxRetention':86400000000000,'revision':2,'createdAt':'2026-10-04T00:00:00Z','updatedAt':'2026-10-04T00:00:00Z'}
 pre={'version':1,'synthetic':True,'helperCommit':helper['revision'],'instanceId':p.INSTANCE,'recoveryEpoch':'1','namespaceId':'76000000-0000-4000-8000-000000000001','policy':policy,'nonterminal':9,'proposedMaxQueued':20000,'sourceFiles':{name:'b'*64 for name in p.SOURCE_FILES}}
 process={'pid':'123','uid':21902,'exe':p.SOURCE_BINARY,'start':'456','binarySHA256':p.SOURCE_SHA,'unitSHA256':'c'*64}
 source={'epoch':1791072000,'preflight':pre,'processes':{name:copy.deepcopy(process) for name in p.UNITS},'files':pre['sourceFiles']}
 db={'database':p.DATABASE,'instance':p.INSTANCE,'epoch':'1','migrations':21,'ledgerSHA256':'d'*64,'namespaceId':pre['namespaceId'],'graphCount':0,'targetCount':0}
 db.update({name:{'count':10,'sha256':'e'*64} for name in ('jobs','targets','runs','executions','agents','enrollments')})
 plan=p.make(source,db,helper,{name:'f'*64 for name in p.FILES},'76000000-0000-4000-8000-000000000002',source['epoch'])
 return plan,binary

def manifest(plan):
 return {'version':1,'synthetic':True,'mode':'admitted-no-execution','deploymentId':p.DEPLOYMENT,'instanceId':p.INSTANCE,'recoveryEpoch':'1','namespaceId':plan['source']['preflight']['namespaceId'],'namespace':p.NAMESPACE,'targetId':'76000000-0000-4000-8000-000000000003','targetGenerationId':'76000000-0000-4000-8000-000000000004','graphId':'76000000-0000-4000-8000-000000000005','revision':'1','totalNodes':'10000','totalEdges':'100000','requestDigest':'sha256:'+'a'*64,'nodes':[{'index':i,'id':'77000000-0000-4000-8000-%012d'%(i+1)} for i in range(10000)]}

class Plans(unittest.TestCase):
 def test_exact_plan_reconstructs(self):
  plan,_=fixture();p.validate(plan)
  self.assertEqual(plan['source']['preflight']['proposedMaxQueued']-plan['source']['preflight']['policy']['maxQueuedJobs'],10000)
 def test_wrong_source_or_schema_never_adopted(self):
  for mutate in (lambda v:v['source']['preflight'].update(instanceId='76000000-0000-4000-8000-000000000009'),lambda v:v['database'].update(migrations=22),lambda v:v['database'].update(graphCount=1),lambda v:v['source']['processes']['jobman-dashboard-lab-control'].update(uid=0),lambda v:v['helper'].update(path='/bin/sh')):
   plan,_=fixture();mutate(plan)
   with self.assertRaises((ValueError,TypeError)):p.validate(plan)
 def test_binary_and_revision_are_both_pinned(self):
  plan,binary=fixture();metadata={k:v for k,v in plan['helper'].items() if k!='path'}
  for changed in (binary+b'changed',binary[:18]+(62).to_bytes(2,'little')+binary[20:]):
   with self.assertRaises(ValueError):p.candidate(metadata,changed)
  metadata['revision']='b'*40
  with self.assertRaises(ValueError):p.candidate(metadata,binary)
 def test_queue_count_and_graph_bound_are_not_widened(self):
  for change in ({'nonterminal':-1},{'nonterminal':10001},{'proposedMaxQueued':30000}):
   plan,_=fixture();plan['source']['preflight'].update(change)
   with self.assertRaises(ValueError):p.validate(plan)
  plan,_=fixture();plan['source']['preflight']['policy']['maxGraphNodes']=9999
  with self.assertRaises(ValueError):p.validate(plan)
 def test_quota_receipt_only_allows_exact_increase(self):
  plan,_=fixture();before=plan['source']['preflight'];after=copy.deepcopy(before['policy']);after.update(maxQueuedJobs=20000,revision=3,updatedAt='2026-10-04T00:01:00Z');receipt={'before':before,'after':after}
  p.quota_receipt(receipt,plan)
  for key,value in [('maxActiveJobs',21),('revision',4),('maxQueuedJobs',20001),('updatedAt','2026-10-03T23:59:59Z')]:
   changed=copy.deepcopy(receipt);changed['after'][key]=value
   with self.assertRaises(ValueError):p.quota_receipt(changed,plan)
 def test_no_unnecessary_increase(self):
  plan,_=fixture();before=plan['source']['preflight'];before['nonterminal']=0;before['proposedMaxQueued']=10000;p.validate(plan)
  p.quota_receipt({'before':before,'after':copy.deepcopy(before['policy'])},plan)
  changed=copy.deepcopy(before['policy']);changed['maxQueuedJobs']=20000;changed['revision']+=1
  with self.assertRaises(ValueError):p.quota_receipt({'before':before,'after':changed},plan)
 def test_complete_unique_graph_identity_is_required(self):
  plan,_=fixture();value=manifest(plan);p.graph_manifest(value,plan)
  for mutate in (lambda v:v.update(totalEdges='99999'),lambda v:v.update(mode='executed'),lambda v:v['nodes'][9999].update(id=v['nodes'][0]['id']),lambda v:v['nodes'][1].update(index=2)):
   invalid=copy.deepcopy(value);mutate(invalid)
   with self.assertRaises(ValueError):p.graph_manifest(invalid,plan)
 def test_existing_source_identity_and_new_counts_preserved(self):
  plan,_=fixture();before=plan['database'];after=copy.deepcopy(before);after.update(graphCount=1,targetCount=1);p.database_preserved(before,after,True)
  for mutate in (lambda v:v['jobs'].update(sha256='1'*64),lambda v:v.update(targetCount=2),lambda v:v['runs'].update(count=11)):
   invalid=copy.deepcopy(after);mutate(invalid)
   with self.assertRaises(ValueError):p.database_preserved(before,invalid,True)
 def test_handoff_cannot_overwrite_or_accept_extra_paths(self):
  plan,_=fixture();value=manifest(plan);raw={'graph.json':c.encoded(value)}
  raw.update({name:b'{"synthetic":true}\n' for name in ('quota.intent.json','quota.complete.json','seed.intent.json','seed.complete.json')})
  result={'manifest':value,'files':{n:base64.b64encode(v).decode() for n,v in raw.items()},'sha256':{n:c.sha(v) for n,v in raw.items()},'sourcePreserved':True}
  with tempfile.TemporaryDirectory() as name:
   root=Path(name).resolve();root.chmod(0o700);h.publish(root,result,plan);h.publish(root,result,plan)
   wrong=copy.deepcopy(result);wrong['files']['seed.complete.json']=base64.b64encode(b'changed').decode()
   with self.assertRaises(ValueError):h.publish(root,wrong,plan)
   wrong=copy.deepcopy(result);wrong['files']['../escape']='eA=='
   with self.assertRaises(ValueError):h.publish(root,wrong,plan)
 def test_missing_apply_cannot_dispatch_stage(self):
  plan,_=fixture()
  with tempfile.TemporaryDirectory() as name:
   root=Path(name).resolve();root.chmod(0o700)
   args=argparse.Namespace(phase='stage',lab_root=root,staging=root,implementation_sha256=c.sha(p.encoded(h.implementation())),helper_build=root,apply=False)
   with patch.object(h,'helper',return_value=(plan['helper'],b'private')),patch.object(h,'remote') as remote:
    with self.assertRaises(ValueError):h.execute(args)
    remote.assert_not_called()
 def guest(self):
  namespace={'p':p,'c':c};exec(compile((HERE/'dashboard-graph-ceiling-guest.py').read_text(),'guest','exec'),namespace)
  namespace['preserved']=lambda _:None
  namespace['locked']=lambda *_args,**_kwargs:contextlib.nullcontext()
  return namespace
 def quota(self,plan):
  before=plan['source']['preflight'];after=copy.deepcopy(before['policy']);after.update(maxQueuedJobs=20000,revision=3,updatedAt='2026-10-04T00:01:00Z')
  return {'before':before,'after':after}
 def test_pending_seed_is_not_retried(self):
  plan,_=fixture();guest=self.guest()
  with tempfile.TemporaryDirectory() as name:
   base=Path(name).resolve();base.chmod(0o700);guest['BASE']=base;root=base/plan['executionId'];c.directory(root,create=True)
   c.put(root/'plan.json',p.encoded(plan));c.put(root/'quota.complete.json',p.encoded(self.quota(plan)));c.put(root/'seed.pending.json',p.encoded({'phase':'seed'}))
   calls=[];guest['helper']=lambda *args:calls.append(args)
   with self.assertRaisesRegex(ValueError,'seed_pending_requires_inspection'):guest['operation']({'phase':'seed','plan':plan})
   self.assertEqual(calls,[]);self.assertFalse((root/'seed.complete.json').exists())
 def test_verify_does_not_create_missing_plan(self):
  plan,_=fixture();guest=self.guest()
  with tempfile.TemporaryDirectory() as name:
   base=Path(name).resolve();base.chmod(0o700);guest['BASE']=base;root=base/plan['executionId'];c.directory(root,create=True)
   with self.assertRaises(FileNotFoundError):guest['operation']({'phase':'verify','plan':plan})
   self.assertEqual(list(root.iterdir()),[])
 def test_completed_quota_reply_recovery_only_reads_current_policy(self):
  plan,_=fixture();guest=self.guest();quota=self.quota(plan)
  with tempfile.TemporaryDirectory() as name:
   base=Path(name).resolve();base.chmod(0o700);guest['BASE']=base;root=base/plan['executionId'];c.directory(root,create=True)
   c.put(root/'plan.json',p.encoded(plan));c.put(root/'quota.complete.json',p.encoded(quota));c.put(root/'quota.pending.json',p.encoded({'phase':'quota','planSHA256':c.sha(p.encoded(plan))}))
   calls=[]
   def helper(command,*args):calls.append(command);return {'policy':quota['after'],'sourceFiles':plan['source']['files']}
   guest['helper']=helper
   self.assertEqual(guest['operation']({'phase':'quota','plan':plan}),quota);self.assertEqual(calls,['preflight'])
 def test_late_success_is_rejected_with_remaining_budget(self):
  guest=self.guest();guest['DEADLINE']=10
  with patch.object(guest['time'],'monotonic',side_effect=[1,11]),patch.object(c,'run',return_value=b'{}') as run:
   with self.assertRaisesRegex(ValueError,'guest_phase_deadline'):guest['run'](['synthetic'],timeout=30)
   self.assertEqual(run.call_args.kwargs['timeout'],9)
 def test_schema_projection_is_fixed_and_contains_no_mutations(self):
  namespace={'p':p,'c':c};exec(compile((HERE/'dashboard-graph-ceiling-guest.py').read_text(),'guest','exec'),namespace)
  captured=[]
  def run(args,payload,**kwargs):captured.append((args,payload));return b'{}'
  with patch.object(c,'run',side_effect=run):namespace['database_snapshot']()
  args,raw=captured[0];sql=raw.decode()
  self.assertIn('READ ONLY',sql);self.assertIn("statement_timeout='15s'",sql)
  self.assertEqual(args[-1],p.DATABASE)
  for forbidden in ('UPDATE ','INSERT ','DELETE ','ALTER ','DROP '):self.assertNotIn(forbidden,sql)
  self.assertIn('LIMIT 200001',sql);self.assertIn('effective_spec_digest',sql)

if __name__=='__main__':unittest.main()
