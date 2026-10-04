#!/usr/bin/env python3
"""Pin, plan and explicitly admit a single inert ceiling graph in isolated Lab."""
import argparse
import base64
import fcntl
import importlib.util
import ipaddress
import os
from pathlib import Path
import shlex
import stat
import time
import uuid

HERE=Path(__file__).resolve().parent

def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
p=module('graph_plan',HERE/'dashboard-graph-ceiling-plan.py')
c=module('graph_common',HERE/'dashboard-scale-source-common.py')

def implementation():
 result={}
 for name in sorted(p.FILES):
  path=HERE/name;s=path.lstat();p.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and not stat.S_IMODE(s.st_mode)&0o022,'implementation_file')
  result[name]=c.sha(c.read(path,1<<20,uid=os.getuid(),mode=stat.S_IMODE(s.st_mode)))
 return result

def remote(lab,host,payload):
 p.need(host in ('control01','pg01'),'fixed_ssh_host')
 conn=c.decode(c.read(lab/'.lab/dashboard/ssh-connections.json',65536))[host];ip=ipaddress.ip_address(conn['ansible_host'])
 p.need(conn['ansible_user']=='vagrant' and type(conn['ansible_port']) is int and 1<=conn['ansible_port']<=65535 and Path(conn['ansible_ssh_private_key_file']).is_absolute() and (str(ip) in ('127.0.0.1',{'control01':'10.77.0.21','pg01':'10.77.0.20'}[host]) or ip in ipaddress.ip_network('10.211.55.0/24')),'pinned_ssh_inventory')
 names=p.FILES-{'prepare-dashboard-graph-ceiling.py'};sources={name:(HERE/name).read_text() for name in names};hashes=implementation()
 p.need(hashes==payload['implementation'],'implementation_changed_before_dispatch')
 if 'plan' in payload:p.need(payload['plan']['implementation']==hashes,'plan_dispatch_implementation')
 script='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((48<<20)+1)
 if len(raw)>48<<20:raise ValueError()
 payload=json.loads(raw);sources=payload.pop('_sources');hashes=payload.pop('_hashes')
 if set(sources)!={'dashboard-graph-ceiling-plan.py','dashboard-graph-ceiling-guest.py','dashboard-scale-source-common.py'}:raise ValueError()
 for name,source in sources.items():
  if hashlib.sha256(source.encode()).hexdigest()!=hashes[name]:raise ValueError()
 p=types.ModuleType('plan');exec(compile(sources['dashboard-graph-ceiling-plan.py'],'plan','exec'),p.__dict__)
 c=types.ModuleType('common');exec(compile(sources['dashboard-scale-source-common.py'],'common','exec'),c.__dict__)
 guest={'__name__':'graph_guest','p':p,'c':c};exec(compile(sources['dashboard-graph-ceiling-guest.py'],'guest','exec'),guest)
 print(json.dumps({'ok':True,'result':guest['execute'](payload)},sort_keys=True))
except Exception as error:print(json.dumps({'ok':False,'code':getattr(error,'code','graph_guest_failed')},sort_keys=True))
'''
 body=p.encoded(dict(payload,_sources=sources,_hashes=hashes));p.need(len(body)<=48<<20,'transport_input_bound')
 command=['ssh','-i',conn['ansible_ssh_private_key_file'],'-p',str(conn['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(lab/'.lab/dashboard/known_hosts'),'-o','HostKeyAlgorithms=ssh-ed25519','vagrant@'+str(ip),shlex.join(['sudo','python3','-c',script])]
 result=c.decode(c.run(command,body,timeout=560 if payload['phase'] in ('seed','verify') else 120,maximum=6<<20))
 p.need(result.get('ok') is True,'graph_remote_'+payload['phase'].replace('-','_')+'_failed');return result['result']

def helper(directory):
 c.directory(directory);meta=c.decode(c.read(directory/'build.json',65536));path=directory/'jobman-control-lab-helper';mode=stat.S_IMODE(path.lstat().st_mode);raw=c.read(path,32<<20,mode=mode)
 return p.candidate(meta,raw),raw

def retained(staging,name,value):c.retain(staging/name,p.encoded(value))

def publish(staging,result,plan):
 p.graph_manifest(result['manifest'],plan)
 names={'quota.intent.json','quota.complete.json','seed.intent.json','seed.complete.json','graph.json'}
 p.need(set(result)=={'manifest','files','sha256','sourcePreserved'} and result['sourcePreserved'] is True and set(result['files'])==set(result['sha256'])==names,'graph_output_shape')
 out=staging/'handoff';c.directory(out,create=True)
 for name in sorted(names):
  raw=base64.b64decode(result['files'][name],validate=True);p.need(0<len(raw)<=2<<20 and c.sha(raw)==result['sha256'][name],'graph_output_hash');c.retain(out/name,raw)
 p.need(c.decode(c.read(out/'graph.json',2<<20))==result['manifest'],'graph_output_manifest')
 retained(out,'driver-receipt.json',{'planSHA256':c.sha(p.encoded(plan)),'helper':plan['helper'],'files':result['sha256'],'sourcePreserved':True})
 return out

def execute(args):
 p.need(args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'real_lab_root');impl=implementation();digest=c.sha(p.encoded(impl))
 if args.phase=='digest':return {'implementationSHA256':digest,'files':impl}
 def dispatch(host,payload):return remote(args.lab_root,host,dict(payload,implementation=impl))
 p.need(args.implementation_sha256==digest,'exact_implementation_required')
 p.need(args.staging is not None and args.staging.is_absolute() and args.staging.resolve()==args.staging,'private_staging_required')
 if not args.staging.exists():c.directory(args.staging.parent);c.directory(args.staging,create=True)
 c.directory(args.staging)
 try:fd=os.open(args.staging/'.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.fchmod(fd,0o600)
 except FileExistsError:fd=os.open(args.staging/'.lock',os.O_RDWR|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd);p.need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'staging_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if args.phase in ('stage','preflight'):
   p.need(args.helper_build is not None,'exact_helper_build_required');spec,binary=helper(args.helper_build)
   if args.phase=='stage':
    p.need(args.apply,'explicit_stage_apply');result=dispatch('control01',{'phase':'stage','apply':True,'helper':spec,'binary':base64.b64encode(binary).decode()});retained(args.staging,'stage.complete.json',result);return result
   p.need(not (args.staging/'plan.json').exists(),'fresh_plan_required')
   p.need(c.decode(c.read(args.staging/'stage.complete.json'))=={'helper':spec,'sourcePreserved':True},'staged_helper_receipt')
   source=dispatch('control01',{'phase':'source-preflight','helper':spec});db=dispatch('pg01',{'phase':'database'})
   plan=p.make(source,db,spec,impl,str(uuid.uuid4()),int(time.time()));retained(args.staging,'plan.json',plan)
   return {'planSHA256':c.sha(p.encoded(plan)),'guestChanges':False,'currentNonterminal':source['preflight']['nonterminal'],'beforeMaxQueued':source['preflight']['policy']['maxQueuedJobs'],'proposedMaxQueued':source['preflight']['proposedMaxQueued']}
  raw=c.read(args.staging/'plan.json',2<<20);plan=c.decode(raw);p.validate(plan)
  p.need(c.sha(raw)==args.plan_sha256 and plan['implementation']==impl,'reviewed_plan_binding')
  phase=args.phase;p.need(phase in ('quota','seed','verify'),'unknown_phase')
  p.need(phase=='verify' or args.apply,'explicit_apply_required')
  if phase=='quota':p.need(not (args.staging/'seed.pending.json').exists(),'quota_after_seed_denied')
  if phase=='seed':p.quota_receipt(c.decode(c.read(args.staging/'quota.complete.json')),plan)
  if phase!='verify':
   if not (args.staging/(phase+'.pending.json')).exists():
    if phase=='quota':p.need(0<=time.time()-plan['createdAt']<=900,'approved_preflight_expired')
    p.database_preserved(plan['database'],dispatch('pg01',{'phase':'database'}),False)
    retained(args.staging,phase+'.pending.json',{'planSHA256':args.plan_sha256,'phase':phase})
   p.need(c.decode(c.read(args.staging/(phase+'.pending.json')))=={'planSHA256':args.plan_sha256,'phase':phase},'host_pending_binding')
  result=dispatch('control01',{'phase':phase,'apply':args.apply,'plan':plan})
  db=dispatch('pg01',{'phase':'database'});p.database_preserved(plan['database'],db,phase!='quota')
  if phase=='quota':p.quota_receipt(result,plan);retained(args.staging,'quota.complete.json',result);return {'quotaVerified':True,'policy':result['after']}
  out=publish(args.staging,result,plan);receipt={'planSHA256':args.plan_sha256,'graphSHA256':result['sha256']['graph.json'],'existingMetadata':db,'sourcePreserved':True}
  retained(args.staging,phase+'.complete.json',receipt)
  return {'verified':True,'graphId':result['manifest']['graphId'],'nodeCount':10000,'edgeCount':100000,'executed':False,'handoff':str(out)}
 finally:os.close(fd)

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--phase',choices=('digest','stage','preflight','quota','seed','verify'),required=True);parser.add_argument('--lab-root',type=Path,required=True);parser.add_argument('--staging',type=Path);parser.add_argument('--helper-build',type=Path);parser.add_argument('--implementation-sha256');parser.add_argument('--plan-sha256');parser.add_argument('--apply',action='store_true')
 try:print(p.encoded(execute(parser.parse_args())).decode(),end='')
 except Exception as error:raise SystemExit('Graph ceiling operation stopped ('+getattr(error,'code','graph_phase_failed')+'); retain all pending/complete receipts. No automatic retry, reset, quota reduction or cancellation is performed.') from None
if __name__=='__main__':main()
