#!/usr/bin/env python3
"""Offline exact-CAS, source proof and uncertain-start guards. No guest access."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('restore_release_host',HERE/'dashboard-restore-release.py');host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
r=host.guest_module();g=r.g

class ReleaseTests(unittest.TestCase):
 def test_changes_only_three_startup_flags(self):
  for role in r.ROLES:
   value={'configurationRevision':7,'key':'unchanged','events':{'deliveryHold':True,'enabled':True},'deliveryHold':True}
   changed=g.decode(r.transition(g.encoded(value),role));expected=copy.deepcopy(value)
   if role=='worker':expected['deliveryHold']=False
   else:expected['events']['deliveryHold']=False
   self.assertEqual(changed,expected)
   with self.assertRaises(ValueError):r.transition(g.encoded(changed),role)
 def test_floor_and_generation_never_erase_restore_uncertainty(self):
  release={'hold':{'generation':'4','restoreRecordedThrough':'2026-10-04T09:47:45.507119Z'}}
  for state,generation,held in [('held','4',True),('released','5',False),('retired','6',True)]:
   value=dict(release['hold'],generation=generation,held=held);r.validate_hold(value,release,state)
   for key,wrong in [('generation','3'),('held',not held),('restoreRecordedThrough','2026-10-04T09:47:46Z')]:
    with self.assertRaises(ValueError):r.validate_hold(dict(value,**{key:wrong}),release,state)
 def test_floor_compares_instants_and_rejects_naive_time(self):
  self.assertEqual(r.instant('2026-10-04T09:47:45.507119Z'),r.instant('2026-10-04T11:47:45.507119+02:00'))
  with self.assertRaises(ValueError):r.instant('2026-10-04T09:47:45.507119')
 def test_snapshot_accepts_offset_equivalence_and_rejects_changed_instant(self):
  root=Path('/fixed/operator');recovery_path=str(g.clone_root('operator')/'recovery-database-url')
  prepared=g.encoded({'databaseURLFile':recovery_path})
  expected={'generation':'4','held':True,'restoreRecordedThrough':'2026-10-04T09:47:45.507119Z'}
  def read(path,*args,**kwargs):
   if Path(path)==root/'clone-start.json':return b'{}',None
   if Path(path)==root/'clone-hold.json':return g.encoded({'hold':expected}),None
   if str(path)==recovery_path:return b'postgres://jobman_dashboard_restore_ddl:private@10.77.0.20/jobman_dashboard_restore?sslmode=verify-full',None
   return prepared,None
  with patch.object(r,'existing',return_value=root),patch.object(g,'candidate',return_value='/fixed/bin'),patch.object(g,'primary_pins',return_value={}),patch.object(r,'process',return_value={}),patch.object(g,'read',side_effect=read),patch.object(g,'prepared',return_value=prepared):
   equivalent=dict(expected,restoreRecordedThrough='2026-10-04T11:47:45.507119+02:00')
   with patch.object(r,'hold',return_value=equivalent):self.assertEqual(r.snapshot({'operationId':'known'})['hold'],equivalent)
   with patch.object(r,'hold',return_value=dict(equivalent,restoreRecordedThrough='2026-10-04T11:47:46.507119+02:00')):
    with self.assertRaises(ValueError):r.snapshot({'operationId':'known'})
 def source(self):
  sources=[{'deploymentId':str(n),'controlInstanceId':'instance'+str(n),'recoveryEpoch':'1','namespaceIds':['ns'+str(n)]} for n in (1,2)]
  plan={'configurationRevision':7,'sources':sources}
  proof={'database':g.DATABASE,'openGaps':0,'sources':[dict(v,configurationRevision='7',status='active',position='10',checkpointSHA256='a'*64,cursorSHA256='b'*64) for v in sources]}
  return plan,proof
 def test_running_checkpoints_allow_progress_but_not_identity_or_scope_drift(self):
  plan,proof=self.source();before=copy.deepcopy(proof);proof['sources'][0]['position']='12';proof['sources'][0]['cursorSHA256']='c'*64
  r.validate_sources(proof,plan,before)
  for key,value in [('position','9'),('controlInstanceId','wrong'),('namespaceIds',['wrong']),('status','paused'),('configurationRevision','8')]:
   drift=copy.deepcopy(proof);drift['sources'][0][key]=value
   with self.assertRaises(ValueError):r.validate_sources(drift,plan,before)
  with self.assertRaises(ValueError):r.validate_sources(dict(proof,openGaps=1),plan)
  with self.assertRaises(ValueError):r.validate_sources(dict(proof,sources=proof['sources'][:1]),plan)
 def test_sql_proof_is_bounded_readonly(self):
  with patch.object(g,'run',return_value=b'{}') as run:r.database_proof(g.DATABASE)
  call=run.call_args;self.assertIn(b'REPEATABLE READ READ ONLY',call.args[1]);self.assertIn(b'LIMIT 3',call.args[1]);self.assertIn(b'ROLLBACK',call.args[1]);self.assertEqual(call.kwargs['timeout'],5)
 def test_effective_policy_rejects_override_and_wrong_kill_mode(self):
  valid=b'KillMode=control-group\nTimeoutStopUSec=30s\nDropInPaths=\n'
  with patch.object(g,'run',return_value=valid):self.assertEqual(r.policy('api'),'jobman-dashboard-restore-api-lab.service')
  for bad in [valid.replace(b'30s',b'90s'),valid.replace(b'control-group',b'process'),valid+b'DropInPaths=\n',valid.replace(b'DropInPaths=',b'DropInPaths=/override')]:
   with patch.object(g,'run',return_value=bad),self.assertRaises(ValueError):r.policy('api')
 def test_config_cas_keeps_exact_backup_and_reuses_only_matching_after(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);live=root/'config.json';live.write_bytes(b'before');backup=root/'api.before.json'
   def read(path,**kw):
    self.assertEqual(kw,{'owner':(os.getuid(),os.getuid()),'mode':0o600} if Path(path)==live or Path(path).name=='config.release-staged.json' else {'owner':(0,0),'mode':0o600})
    return Path(path).read_bytes(),None
   def put(path,raw,*a):Path(path).write_bytes(raw)
   with patch.object(r,'location',return_value=(live,os.getuid())),patch.object(g,'read',side_effect=read),patch.object(g,'put',side_effect=put):
    r.replace_one(root,'api',b'before',b'after');self.assertEqual(live.read_bytes(),b'after');self.assertEqual(backup.read_bytes(),b'before')
    r.replace_one(root,'api',b'before',b'after')
    live.write_bytes(b'drift')
    with self.assertRaises(ValueError):r.replace_one(root,'api',b'before',b'after')
 def test_readiness_retries_pending_only_and_never_starts_services(self):
  with patch.object(r,'same_primary'),patch.object(r,'configs_match'),patch.object(r,'validate_hold'),patch.object(r,'hold'),patch.object(g,'candidate'),patch.object(r.time,'sleep'),patch.object(r,'ready',side_effect=[g.ReadinessPending('starting'),{'ready':True}]) as ready,patch.object(g,'run') as run:
   self.assertEqual(r.await_ready({}, {}, {}),{'ready':True});self.assertEqual(ready.call_count,2);run.assert_not_called()
  with patch.object(r,'same_primary'),patch.object(r,'configs_match'),patch.object(r,'validate_hold'),patch.object(r,'hold'),patch.object(g,'candidate'),patch.object(r,'ready',side_effect=ValueError('drift')) as ready:
   with self.assertRaisesRegex(ValueError,'drift'):r.await_ready({}, {}, {})
   self.assertEqual(ready.call_count,1)
 def test_lost_start_response_observes_without_start_or_stop(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);sha='a'*64;receipt=g.encoded({'releaseSHA256':sha});(root/'configure.pending.json').write_bytes(receipt);(root/'start.pending.json').write_bytes(receipt)
   with patch.object(g,'candidate'),patch.object(r,'same_primary'),patch.object(r,'validate_hold'),patch.object(r,'hold'),patch.object(g,'read',side_effect=lambda path,**kw:(Path(path).read_bytes(),None)),patch.object(r,'await_ready',return_value={'ready':True}),patch.object(r,'retain') as retained,patch.object(g,'run') as run:
    self.assertEqual(r.configure({'releaseSHA256':sha},{},{},root),{'ready':True});run.assert_not_called();self.assertEqual(retained.call_args.args[0],root/'configured.json')
 def test_dispatch_wrong_host_or_nonroot_fails_before_files(self):
  for uid,platform,hostname in [(1,'linux','storage01'),(0,'darwin','storage01'),(0,'linux','pg01')]:
   with patch.object(r.os,'geteuid',return_value=uid),patch.object(r.sys,'platform',platform),patch.object(r.socket,'gethostname',return_value=hostname),patch.object(r,'existing') as existing:
    with self.assertRaises(ValueError):r.execute({'host':'storage01','action':'snapshot'})
    existing.assert_not_called()
 def test_no_automatic_resume_or_primary_unit_mutation(self):
  source=(HERE/'dashboard-restore-release-guest.py').read_text()
  self.assertNotIn("'events','resume'",source);self.assertNotIn("'events','hold',",source)
  self.assertIn("'systemctl','stop',*[policy(role) for role in g.CLONE]",source)
  self.assertIn("'systemctl','start',*[policy(role) for role in g.CLONE]",source)

if __name__=='__main__':unittest.main()
