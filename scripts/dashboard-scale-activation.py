#!/usr/bin/env python3
"""Explicit reviewed scale scope activation; default phases perform no guest writes."""
import argparse
import fcntl
import importlib.util
import ipaddress
import os
from pathlib import Path
import shlex
import stat
import time

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('activation',HERE/'dashboard-scale-activation-common.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a);c=a.c
FILES=('dashboard-scale-activation.py','dashboard-scale-activation-common.py','dashboard-scale-activation-guest.py','dashboard-scale-plan.py','dashboard-scale-source-common.py','dashboard-multisource-runtime.py')


def implementation():
 result={}
 for name in FILES:
  path=HERE/name;s=path.lstat();c.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and not stat.S_IMODE(s.st_mode)&0o022,'implementation_file');result[name]=c.sha(c.read(path,uid=os.getuid(),mode=stat.S_IMODE(s.st_mode)))
 return result


def remote(lab,host,payload):
 inventory=c.decode(c.read(lab/'.lab/dashboard/ssh-connections.json',65536));connection=inventory[host];ip=ipaddress.ip_address(connection['ansible_host']);expected={'control01':'10.77.0.21','storage01':'10.77.0.10','pg01':'10.77.0.20'}
 c.need(host in expected and connection['ansible_user']=='vagrant' and type(connection['ansible_port']) is int and 1<=connection['ansible_port']<=65535 and Path(connection['ansible_ssh_private_key_file']).is_absolute() and (str(ip) in ('127.0.0.1',expected[host]) or ip in ipaddress.ip_network('10.211.55.0/24')),'pinned_ssh_inventory')
 sources={name:c.read(HERE/name,uid=os.getuid(),mode=stat.S_IMODE((HERE/name).lstat().st_mode)).decode() for name in FILES[1:]}
 script='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((8<<20)+1)
 if len(raw)>8<<20:raise ValueError()
 p=json.loads(raw);sources=p.pop('_sources');hashes=p.pop('_hashes')
 expected={'dashboard-scale-activation-common.py','dashboard-scale-activation-guest.py','dashboard-scale-plan.py','dashboard-scale-source-common.py','dashboard-multisource-runtime.py'}
 if set(sources)!=expected or set(hashes)!=expected:raise ValueError()
 for name,value in sources.items():
  if hashlib.sha256(value.encode()).hexdigest()!=hashes[name]:raise ValueError()
 def module(name,values):
  m=types.ModuleType(name);m.__dict__.update(values);exec(compile(sources[name],name,'exec'),m.__dict__);return m
 source=module('dashboard-scale-source-common.py',{});plan=module('dashboard-scale-plan.py',{});runtime=module('dashboard-multisource-runtime.py',{})
 activation=module('dashboard-scale-activation-common.py',{'source_common':source,'scale_plan':plan})
 guest=module('dashboard-scale-activation-guest.py',{'activation':activation,'runtime':runtime})
 print(json.dumps({'ok':True,'result':guest.execute(p)},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','activation_guest_failed')
 print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''
 body=c.encoded(dict(payload,host=host,_sources=sources,_hashes={name:c.sha(value.encode()) for name,value in sources.items()}));c.need(len(body)<=8<<20,'remote_payload_bound')
 args=['ssh','-i',connection['ansible_ssh_private_key_file'],'-p',str(connection['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(lab/'.lab/dashboard/known_hosts'),'-o','HostKeyAlgorithms=ssh-ed25519','vagrant@'+str(ip),shlex.join(['sudo','python3','-c',script])]
 result=c.decode(c.run(args,body,timeout=180,maximum=4<<20))
 if result.get('ok') is not True:
  code=result.get('code','activation_guest_failed');c.need(isinstance(code,str) and __import__('re').fullmatch('[a-z][a-z0-9_]{0,63}',code),'guest_error_code');raise c.Failure(code)
 return result['result']


def read_handoff(directory,profile):
 c.directory(directory);names=('seed.json','directory.after.json','directory-state.after.json','receipt.json','driver-receipt.json');result={name:a.encoded_file(c.read(directory/name)) for name in names}
 proof=c.read(directory.parent/'verify.complete.json');value=c.decode(proof);preflight=c.read(directory.parent/'preflight.json');source_plan=c.decode(preflight);driver=a.document(result['driver-receipt.json']);p=a.PROFILES[profile]
 c.need(source_plan['implementationSHA256']==a.SOURCE_IMPLEMENTATION_SHA and source_plan['profile']==profile and c.sha(preflight)==driver['executionId'],'source_implementation_handoff')
 c.need(value['receipt']==driver and driver['profile']==profile and value['database']['database']==p['database'] and value['database']['instance']==p['instance'] and value['database']['epoch']=='1' and value['database']['migrations']==21,'source_verified_handoff_required')
 return result,c.sha(proof)


def put_record(root,name,value):c.retain(root/(name+'.json'),c.encoded(value))
def get(root,name):return c.decode(c.read(root/(name+'.json')))


def required(root,phase,profile):
 base=['hold','stop-worker']
 if phase=='hold':base=[]
 elif phase=='stop-worker':base=['hold']
 elif phase.startswith('directory-'):pass
 elif phase.startswith('trust-'):base+=['directory-primary','directory-secondary']
 elif phase.startswith('runtime-'):base+=['trust-primary','trust-secondary']
 elif phase in ('restart-api','restart-broker'):base+=['runtime-storage','runtime-broker']
 else:base+=['restart-api','restart-broker','restart-worker'] if phase!='restart-worker' else ['restart-api','restart-broker']
 if phase in ('recovery-step','recovery-reconcile','recovery-apply'):base+=['recovery-plan-primary','recovery-plan-secondary']
 if phase in ('resume','verify'):base+=['recovery-apply-primary','recovery-apply-secondary']
 if phase=='verify':base+=['resume']
 for name in base:c.need((root/(name+'.json')).exists(),'phase_predecessor_missing')


def current_db(args,snapshot,plan,held=None,revision=7):
 value=remote(args.lab_root,'pg01',{'phase':'database'});a.validate_database(value,snapshot,plan,held,revision)
 return value


def registry_revision_window(root,phase):
 # Local readiness does not fetch a source. Scope-changed ingestion also
 # pauses before network I/O; only a real checkpoint ends this transition.
 if phase in ('restart-api','restart-broker','restart-worker','recovery-plan'):return (7,8)
 # Rechecking a completed earlier phase after API restart must preserve the
 # existing monotonic registry fence rather than demand the old revision.
 return 8 if (root/'restart-api.json').exists() or phase.startswith('recovery-') or phase in ('resume','verify') else 7


def planned_registry_fence(root,value,plan,completed_profile=None):
 rows={row['deploymentId']:row for row in value['identities']}
 for profile,p in a.PROFILES.items():
  path=root/('recovery-plan-'+profile+'.json')
  if path.exists():a.validate_recovery(get(root,'recovery-plan-'+profile),profile,plan)
  if path.exists() or profile==completed_profile:c.need(rows[p['deployment']]['revision']==8,'checkpoint_registry_revision_required')


def authority_proofs(lab,payload):
 deadline=time.monotonic()+50
 while True:
  try:return {name:remote(lab,'pg01',dict(payload,phase='authority',profile=name)) for name in a.PROFILES}
  except c.Failure as error:
   c.need(error.code=='current_viewer_authority_required','authority_check_failed')
   c.need(time.monotonic()<deadline,'directory_reconciliation_not_ready');time.sleep(1)


def execute(args):
 os.umask(0o077);impl=c.sha(c.encoded(implementation()))
 if args.phase=='digest':return {'implementationSHA256':impl,'files':implementation()}
 c.need(args.implementation_sha256==impl and args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'explicit_implementation_and_lab')
 c.need(args.staging is not None and args.staging.is_absolute(),'private_staging_required')
 if not args.staging.exists():c.directory(args.staging.parent);c.directory(args.staging,create=True)
 c.directory(args.staging);fd=os.open(args.staging/'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
 try:
  os.fchmod(fd,0o600);s=os.fstat(fd);c.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid(),'private_host_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if args.phase=='snapshot':
   c.need(not (args.staging/'snapshot.json').exists() and args.primary_handoff is not None and args.secondary_handoff is not None,'fresh_handoff_snapshot_required')
   handoffs={};verified={}
   for name,directory in [('primary',args.primary_handoff),('secondary',args.secondary_handoff)]:handoffs[name],verified[name]=read_handoff(directory,name)
   hosts={name:remote(args.lab_root,name,{'phase':'snapshot'}) for name in ('control01','storage01')}
   c.need(all(abs(time.time()-value['epoch'])<30 for value in hosts.values()),'fresh_guest_clock')
   runtime=dict(hosts['control01']['runtime'],**hosts['storage01']['runtime']);snapshot={'version':1,'epoch':int(time.time()),'hosts':hosts,'runtime':runtime,'sources':hosts['control01']['sources'],'seedVerificationSHA256':verified}
   snapshot['database']=remote(args.lab_root,'pg01',{'phase':'database'});plan=a.draft(snapshot,handoffs);a.validate_database(snapshot['database'],snapshot,plan,False)
   c.need(snapshot['database']['openGaps']==snapshot['database']['unfinishedRecoveries']==0 and all(row['status']=='active' and len(row['namespaces'])==2 for row in snapshot['database']['feeds']),'clean_active_feed_baseline')
   revisions={Path(value['binary']).parent.parent.name for host in hosts.values() for value in host['roles'].values()};c.need(revisions=={args.candidate_revision} and __import__('re').fullmatch('[0-9a-f]{40}',args.candidate_revision or ''),'approved_candidate_revision')
   operation=a.binding(snapshot,handoffs,plan,impl);probe={'snapshot':snapshot,'handoffs':handoffs,'plan':plan,'implementationSHA256':impl,'executionId':operation,'phase':'authority-baseline'}
   snapshot['oldAuthority']={name:remote(args.lab_root,'pg01',dict(probe,profile=name)) for name in a.PROFILES};plan=a.draft(snapshot,handoffs);operation=a.binding(snapshot,handoffs,plan,impl);put_record(args.staging,'snapshot',snapshot);put_record(args.staging,'handoffs',handoffs);put_record(args.staging,'plan',plan);put_record(args.staging,'binding',{'implementationSHA256':impl,'executionId':operation})
   return {'executionId':operation,'planSHA256':c.sha(c.encoded(plan)),'guestChanges':False,'revision':8}
  snapshot=get(args.staging,'snapshot');handoffs=get(args.staging,'handoffs');plan=get(args.staging,'plan');operation=a.binding(snapshot,handoffs,plan,impl)
  c.need(args.plan_sha256==c.sha(c.encoded(plan)) and get(args.staging,'binding')=={'implementationSHA256':impl,'executionId':operation},'reviewed_plan_required')
  phase=args.phase;c.need(phase in a.PHASES,'phase_boundary');c.need(phase=='verify' or args.apply,'explicit_apply_required');required(args.staging,phase,args.profile)
  payload={'phase':phase,'apply':args.apply,'snapshot':snapshot,'handoffs':handoffs,'plan':plan,'implementationSHA256':impl,'executionId':operation}
  if phase!='hold':payload['held']=get(args.staging,'hold')
  if phase=='hold':c.need(0<=time.time()-snapshot['epoch']<=900,'snapshot_expired')
  db=current_db(args,snapshot,plan,None,registry_revision_window(args.staging,phase))
  planned_registry_fence(args.staging,db,plan)
  if phase=='verify':
   payload['resumed']=get(args.staging,'resume');a.resumed_hold(db['hold'],payload['resumed'])
  if phase=='hold':c.need(db['hold']==snapshot['database']['hold'] or (db['hold']['held'] is True and db['hold']['generation']==snapshot['database']['hold']['generation']+1),'hold_baseline_changed')
  elif phase not in ('resume','verify'):c.need(db['hold']['held'] is True and str(db['hold']['generation'])==payload['held']['generation'],'current_exact_hold_required')
  payload['workerStopped']=(args.staging/'stop-worker.json').exists() and not (args.staging/'restart-worker.json').exists() and phase!='restart-worker'
  for name in ('control01','storage01'):remote(args.lab_root,name,dict(payload,phase='guards'))
  if phase.startswith('trust-') or phase.startswith('runtime-') or phase.startswith('restart-') or phase.startswith('recovery-') or phase in ('resume','verify'):
   payload['authority']=authority_proofs(args.lab_root,payload)
  if phase in ('resume','verify'):
   c.need(all(row['status']=='active' and row['namespaces']==next(v['newNamespaceIds'] for v in plan['feedRecoveryRequired'] if v['deploymentId']==row['deploymentId']) for row in db['feeds']) and db['openGaps']==db['unfinishedRecoveries']==0,'both_recovered_feeds_required')
  if phase.startswith('recovery-'):
   c.need(args.profile in a.PROFILES,'explicit_recovery_profile');payload['profile']=args.profile
   if phase=='recovery-apply':
    c.need(args.coverage_sha256 and c.HEX.fullmatch(args.coverage_sha256) and args.acknowledge_gap,'reviewed_apply_required');coverage=get(args.staging,'coverage-'+args.profile+'-'+args.coverage_sha256);c.need(c.sha(c.encoded(coverage))==args.coverage_sha256,'coverage_hash')
    a.validate_coverage(coverage,args.profile,plan);payload.update(coverage=coverage,coverageSHA256=args.coverage_sha256,acknowledgeGap=True,allowIncomplete=args.allow_incomplete)
  host='control01' if phase.startswith(('directory-','trust-')) or phase in ('runtime-broker','restart-broker') else 'storage01'
  if phase=='verify':
   result={name:remote(args.lab_root,name,payload) for name in ('control01','storage01')};final=current_db(args,snapshot,plan,False,8);a.resumed_hold(final['hold'],payload['resumed']);put_record(args.staging,phase,result);return {'verified':True,'revision':8}
  result=remote(args.lab_root,host,payload)
  if phase=='recovery-plan':
   after=current_db(args,snapshot,plan,True,(7,8));planned_registry_fence(args.staging,after,plan,args.profile)
   c.need(str(after['hold']['generation'])==payload['held']['generation'],'current_exact_hold_required')
  name=phase+'-'+args.profile if phase in ('recovery-plan','recovery-apply') else phase
  if phase=='recovery-reconcile':name='coverage-'+args.profile+'-'+c.sha(c.encoded(result))
  if phase=='recovery-step':name='recovery-step-'+args.profile+'-'+result['revision']
  put_record(args.staging,name,result)
  response={'phase':phase,'complete':True,'executionId':operation}
  if phase=='recovery-reconcile':response['coverageSHA256']=c.sha(c.encoded(result))
  if phase in ('recovery-plan','recovery-step','recovery-apply'):response.update(recoveryId=result['id'],digest=result['digest'],revision=result['revision'],status=result['status'])
  if phase in ('hold','resume'):response.update(held=result['held'],generation=result['generation'])
  return response
 finally:os.close(fd)


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--phase',choices=('digest','snapshot',*a.PHASES),required=True);parser.add_argument('--lab-root',type=Path,required=True);parser.add_argument('--staging',type=Path);parser.add_argument('--implementation-sha256');parser.add_argument('--plan-sha256');parser.add_argument('--candidate-revision');parser.add_argument('--primary-handoff',type=Path);parser.add_argument('--secondary-handoff',type=Path);parser.add_argument('--profile',choices=tuple(a.PROFILES));parser.add_argument('--coverage-sha256');parser.add_argument('--acknowledge-gap',action='store_true');parser.add_argument('--allow-incomplete',action='store_true');parser.add_argument('--apply',action='store_true')
 try:print(c.encoded(execute(parser.parse_args())).decode(),end='')
 except Exception as error:
  code=getattr(error,'code','activation_phase_failed');raise SystemExit('Scale activation failed ('+code+'); preserve receipts and the durable hold. No automatic rollback or resume.') from None
if __name__=='__main__':main()
