#!/usr/bin/env python3
"""Prepare/apply only clone startup flags and retirement; never resume or replay."""
import argparse
import base64
import importlib.util
import os
from pathlib import Path
import secrets
import shlex
import subprocess

HERE=Path(__file__).resolve().parent

def load(name,file):
 spec=importlib.util.spec_from_file_location(name,HERE/file);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v

a=load('release_original','apply-dashboard-restore.py');p=a.plan
FILES=('dashboard-restore-release.py','dashboard-restore-release-guest.py','apply-dashboard-restore.py','dashboard-restore-guest.py','dashboard-restore-plan.py','apply-dashboard-split.py','prepare-dashboard-split.py','dashboard-split-plan.py')

def implementation():return {name:p.sha((HERE/name).read_bytes()) for name in FILES}

def guest_module():
 import types
 restore=load('release_restore_primitives','dashboard-restore-guest.py');module=types.ModuleType('release_guest');module.restore=restore
 exec(compile((HERE/'dashboard-restore-release-guest.py').read_text(),'release_guest','exec'),module.__dict__);return module

def remote(args,host,payload,action):
 conn=a.ssh.ssh_connections(args.lab_root)[host];sources={name:(HERE/name).read_text() for name in ('dashboard-restore-guest.py','dashboard-restore-release-guest.py')}
 p.require(p.sha(sources['dashboard-restore-guest.py'].encode())==args.guest_sha256,'Original guest implementation changed')
 script='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((4<<20)+1)
 if len(raw)>4<<20:raise ValueError()
 value=json.loads(raw);sources=value.pop('_sources');hashes=value.pop('_hashes')
 if set(sources)!={'dashboard-restore-guest.py','dashboard-restore-release-guest.py'}:raise ValueError()
 for name,source in sources.items():
  if hashlib.sha256(source.encode()).hexdigest()!=hashes[name]:raise ValueError()
 restore=types.ModuleType('reviewed_restore');restore.__name__='reviewed_restore'
 exec(compile(sources['dashboard-restore-guest.py'],'restore','exec'),restore.__dict__)
 module={'__name__':'reviewed_release','restore':restore}
 exec(compile(sources['dashboard-restore-release-guest.py'],'release','exec'),module)
 print(json.dumps({'ok':True,'result':module['execute'](value)},sort_keys=True))
except Exception:
 print(json.dumps({'ok':False,'code':'clone_release_phase_failed'}))
'''
 body=p.encoded(dict(payload,host=host,action=action,_sources=sources,_hashes={k:p.sha(v.encode()) for k,v in sources.items()}));p.require(len(body)<=4<<20,'Supplemental request exceeds bound')
 argv=['ssh','-i',conn['ansible_ssh_private_key_file'],'-p',str(conn['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(args.lab_root/'.lab/dashboard/known_hosts'),'-o','HostKeyAlgorithms=ssh-ed25519',conn['ansible_user']+'@'+conn['ansible_host'],shlex.join(['sudo','python3','-c',script])]
 result=subprocess.run(argv,input=body,capture_output=True,timeout=165 if action in ('configure','retire') else 60)
 p.require(result.returncode==0 and len(result.stdout)<=1<<20,'Supplemental response lost; preserve pending evidence')
 value=p.decode(result.stdout);p.require(value.get('ok') is True,'Supplemental phase failed; preserve pending evidence');return value['result']

def check_proof(proof,payload,release=None,state='held'):
 g=guest_module();p.require(set(proof)=={'jobman_dashboard',g.g.DATABASE},'Exact primary and clone proof required')
 for database,value in proof.items():
  g.validate_sources(value,payload['plan'],release['database'][database] if release else None)
  p.require(value['database']==database,'Proof database differs')
 if release:
  p.require(proof['jobman_dashboard']['hold']==release['database']['jobman_dashboard']['hold'],'Primary hold changed')
  g.validate_hold(proof[g.g.DATABASE]['hold'],release,state)


def execute(args):
 digest=p.sha(p.encoded(implementation()))
 if args.action=='digest':return {'implementationSHA256':digest,'files':implementation()}
 p.require(args.implementation_sha256==digest,'Exact supplemental implementation required')
 args.command='inspect';output,payload=a.operation(args);g=guest_module()
 folder=args.release_directory;p.require(folder.is_absolute() and folder.resolve()==folder,'Real private release directory required')
 if args.action=='prepare':
  p.require(not folder.exists(),'Fresh release preparation required');p.require(folder.parent.stat().st_uid==os.getuid() and folder.parent.stat().st_mode&0o777==0o700,'Private preparation parent required')
  lost_raw=p.private_read(args.scenario_directory/'lost-interval.json',1<<20);lost=p.decode(lost_raw);p.require(lost['operationId']==payload['operationId'],'Lost-interval operation differs')
  p.timestamp(lost['externalCutoff']);proof=remote(args,'pg01',payload,'proof');check_proof(proof,payload)
  snapshot=remote(args,'storage01',payload,'snapshot');p.require(snapshot['operationId']==payload['operationId'] and snapshot['hold']['held'] is True and g.instant(snapshot['hold']['restoreRecordedThrough'])==g.instant(lost['externalCutoff']),'External floor/held clone mismatch')
  g.validate_hold(proof[g.g.DATABASE]['hold'],{'hold':snapshot['hold']},'held')
  files={};after={}
  for role in g.ROLES:
   raw=base64.b64decode(payload['preparedFiles']['configs/'+role+'.json'],validate=True);changed=g.transition(raw,role);files[role]={'before':p.sha(raw),'after':p.sha(changed)};after[role]=changed
  release={'version':1,'operationId':payload['operationId'],'restorePlanSHA256':payload['planSHA256'],'implementationSHA256':digest,'configurationRevision':payload['plan']['configurationRevision'],'snapshot':snapshot,'database':proof,'hold':snapshot['hold'],'lostIntervalSHA256':p.sha(lost_raw),'files':files}
  p.directory(folder)
  for role,raw in after.items():p.write_new(folder/(role+'.after.json'),raw)
  p.write_new(folder/'plan.json',p.encoded(release));return {'prepared':True,'guestMutations':False,'releaseSHA256':p.sha(p.encoded(release)),'operationId':payload['operationId']}
 raw=p.private_read(folder/'plan.json',1<<20);p.require(p.sha(raw)==args.release_sha256,'Exact reviewed release plan required');release=p.decode(raw);p.require(release['implementationSHA256']==digest,'Supplemental implementation changed since preparation')
 after={}
 for role in g.ROLES:
  raw=p.private_read(folder/(role+'.after.json'));p.require(p.sha(raw)==release['files'][role]['after'],'Reviewed staged config changed');after[role]=base64.b64encode(raw).decode()
 p.require(args.action in ('configure','observe','retire') and (args.action=='observe' or args.apply),'Explicit configure/retire approval required')
 state=args.hold_state if args.action=='observe' else 'retired' if args.action=='retire' else 'held'
 active=dict(payload,release=release,releaseSHA256=args.release_sha256,after=after,explicitApply=args.apply,holdState=state)
 with a.lock(output/'.lock'):
  before=remote(args,'pg01',payload,'proof');check_proof(before,payload,release,state)
  result=remote(args,'storage01',active,args.action)
  after_proof=remote(args,'pg01',payload,'proof');check_proof(after_proof,payload,release,state)
  record={'action':args.action,'holdState':state,'releaseSHA256':args.release_sha256,'before':before,'result':result,'after':after_proof}
  name=args.action+'-'+secrets.token_hex(8)+'.json';p.write_new(folder/name,p.encoded(record))
  return {'action':args.action,'holdState':state,'operationId':payload['operationId'],'releaseSHA256':args.release_sha256,'receipt':str(folder/name),'automaticResume':False}

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('digest','prepare','configure','observe','retire'))
 for name in ('lab-root','prepared-directory','operation-directory','candidate','release-directory','scenario-directory'):parser.add_argument('--'+name,type=Path)
 for name in ('plan-sha256','candidate-sha256','guest-sha256','object-helper-sha256','implementation-sha256','release-sha256'):parser.add_argument('--'+name)
 parser.add_argument('--hold-state',choices=('held','released','retired'),default='held');parser.add_argument('--apply',action='store_true');args=parser.parse_args();os.umask(0o077)
 try:print(p.encoded(execute(args)).decode(),end='')
 except Exception:raise SystemExit('Clone release phase failed; retain exact private receipts. No automatic replay, resume, rollback, primary stop or cleanup is performed.') from None
if __name__=='__main__':main()
