#!/usr/bin/env python3
"""Stage exact helper and seed fixed sources only after reviewed preflight."""
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

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('source_common',HERE/'dashboard-scale-source-common.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
FILES=('dashboard-scale-source.py','dashboard-scale-source-common.py','dashboard-scale-source-guest.py')

def implementation():
 result={}
 for name in FILES:
  path=HERE/name;s=path.lstat();c.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and not stat.S_IMODE(s.st_mode)&0o022,'implementation_identity');result[name]=c.sha(c.read(path,uid=os.getuid(),mode=stat.S_IMODE(s.st_mode)))
 return result

def remote(lab,host,payload):
 inventory=c.decode(c.read(lab/'.lab/dashboard/ssh-connections.json',65536));conn=inventory[host];ip=ipaddress.ip_address(conn['ansible_host']);expected={'control01':'10.77.0.21','pg01':'10.77.0.20'}
 c.need(host in expected and conn['ansible_user']=='vagrant' and isinstance(conn['ansible_port'],int) and 1<=conn['ansible_port']<=65535 and Path(conn['ansible_ssh_private_key_file']).is_absolute() and (str(ip) in ('127.0.0.1',expected[host]) or ip in ipaddress.ip_network('10.211.55.0/24')),'pinned_ssh_inventory')
 sources={name:(HERE/name).read_text() for name in FILES[1:]}
 script='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((48<<20)+1)
 if len(raw)>48<<20:raise ValueError()
 p=json.loads(raw);sources=p.pop('_sources');hashes=p.pop('_hashes')
 if set(sources)!={'dashboard-scale-source-common.py','dashboard-scale-source-guest.py'}:raise ValueError()
 for name,source in sources.items():
  if hashlib.sha256(source.encode()).hexdigest()!=hashes[name]:raise ValueError()
 common=types.ModuleType('common');exec(compile(sources['dashboard-scale-source-common.py'],'common','exec'),common.__dict__)
 namespace={'__name__':'scale_source_guest','common':common};exec(compile(sources['dashboard-scale-source-guest.py'],'guest','exec'),namespace)
 print(json.dumps({'ok':True,'result':namespace['execute'](p)},sort_keys=True))
except Exception as error:
 print(json.dumps({'ok':False,'code':getattr(error,'code','source_guest_failed')},sort_keys=True))
'''
 body=c.encoded(dict(payload,_sources=sources,_hashes={k:c.sha(v.encode()) for k,v in sources.items()}));c.need(len(body)<=48<<20,'guest_input_bound')
 args=['ssh','-i',conn['ansible_ssh_private_key_file'],'-p',str(conn['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(lab/'.lab/dashboard/known_hosts'),'-o','HostKeyAlgorithms=ssh-ed25519','vagrant@'+str(ip),shlex.join(['sudo','python3','-c',script])]
 result=c.decode(c.run(args,body,timeout=560 if payload['phase']=='seed' else 90,maximum=4<<20))
 c.need(result.get('ok') is True,'reviewed_guest_phase_failed');return result['result']

def identities(directory,profile):
 c.directory(directory);handoff=c.decode(c.read(directory/'handoff.json'));record=c.decode(c.read(directory/'identities.json'))
 c.need(set(handoff)=={'stageSHA256','historyAt','files'} and c.HEX.fullmatch(handoff['stageSHA256']) and record['synthetic'] is True and record['version']==1 and record['issuer']==c.ISSUER and len(record['users'])==25,'identity_handoff_receipt')
 values={}
 for name in c.PROFILES:
  file=name+'-scale-input.json';raw=c.read(directory/file);c.need(handoff['files'].get(file)==c.sha(raw),'identity_handoff_hash');value=c.validate_input(c.decode(raw),name);c.need(value['historyAt']==handoff['historyAt'],'identity_history_time')
  expected=[{key:user[key] for key in ('directoryId','subject','name')} for user in record['users']];c.need(value['users']==expected,'actual_subject_handoff');values[name]=value
 c.need(values['primary']['users']==values['secondary']['users'],'source_subjects_differ');return values[profile],c.sha(c.encoded(handoff))

def retained(staging,name,value):c.retain(staging/name,c.encoded(value))
def output(staging,result):
 c.need(set(result)=={'receipt','files'} and set(result['files'])=={'seed.json','directory.after.json','directory-state.after.json','receipt.json'},'seed_handoff_shape')
 root=staging/'handoff';c.directory(root,create=True)
 for name,value in result['files'].items():
  raw=base64.b64decode(value,validate=True);c.need(0<len(raw)<=1<<20 and c.sha(raw)==result['receipt']['outputSHA256'][name],'seed_handoff_hash');c.retain(root/name,raw)
 retained(root,'driver-receipt.json',result['receipt']);return result['receipt']

def execute(args):
 c.need(args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'real_lab_root');impl=c.sha(c.encoded(implementation()))
 if args.phase=='digest':return {'implementationSHA256':impl,'files':implementation()}
 c.need(args.implementation_sha256==impl,'exact_implementation_required')
 c.need(args.staging is not None and args.staging.is_absolute() and args.staging.resolve()==args.staging,'private_staging_required')
 if not args.staging.exists():c.directory(args.staging.parent);c.directory(args.staging,create=True)
 c.directory(args.staging);fd=os.open(args.staging/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  os.fchmod(fd,0o600);s=os.fstat(fd);c.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1,'staging_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if args.phase=='stage':
   c.need(args.apply and args.helper is not None,'explicit_stage_apply');s=args.helper.lstat();raw=c.read(args.helper,32<<20,mode=stat.S_IMODE(s.st_mode));c.need(c.sha(raw)==c.BINARY_SHA,'exact_helper_required')
   result=remote(args.lab_root,'control01',{'phase':'stage','apply':True,'binary':base64.b64encode(raw).decode()});retained(args.staging,'binary-stage.json',result);return result
  c.need(args.profile in c.PROFILES and args.identity_handoff is not None,'fixed_source_and_identity_handoff')
  value,handoff=identities(args.identity_handoff,args.profile)
  if args.phase=='preflight':
   c.need(not (args.staging/'preflight.json').exists(),'fresh_preflight_required')
   source=remote(args.lab_root,'control01',{'phase':'source-preflight','profile':args.profile,'input':value});database=remote(args.lab_root,'pg01',{'phase':'database-preflight','profile':args.profile,'input':value})
   c.need(abs(time.time()-source['epoch'])<=30,'fresh_source_preflight')
   record={'version':1,'profile':args.profile,'implementationSHA256':impl,'input':value,'identityHandoffSHA256':handoff,'source':source,'database':database}
   retained(args.staging,'preflight.json',record);return {'preflightSHA256':c.sha(c.encoded(record)),'profile':args.profile,'guestChanges':False}
  raw=c.read(args.staging/'preflight.json');record=c.decode(raw);c.need(c.sha(raw)==args.preflight_sha256 and record['implementationSHA256']==impl and record['profile']==args.profile and record['input']==value and record['identityHandoffSHA256']==handoff,'reviewed_preflight_binding')
  payload={'profile':args.profile,'input':value,'executionId':args.preflight_sha256,'implementationSHA256':impl,'baseline':record['source']}
  if args.phase=='seed':
   c.need(args.apply,'explicit_seed_apply')
   if not (args.staging/'seed.complete.json').exists():
    c.need(0<=time.time()-record['source']['epoch']<=900,'source_preflight_expired')
    current=remote(args.lab_root,'pg01',{'phase':'database-preflight','profile':args.profile,'input':value})
    for key in ('database','instance','epoch','ledgerSHA256','migrations','namespaceIds','namespaceSHA256','jobs'):c.need(current[key]==record['database'][key],'source_database_preflight_drift')
   result=remote(args.lab_root,'control01',dict(payload,phase='seed',apply=True));receipt=output(args.staging,result);retained(args.staging,'seed.complete.json',receipt)
   return {'seeded':True,'profile':args.profile,'namespaceCount':c.PROFILES[args.profile]['count'],'directoryInstalled':False,'runtimeScopesChanged':False}
  c.need(args.phase=='verify','unsupported_phase')
  result=remote(args.lab_root,'control01',dict(payload,phase='verify'));receipt=output(args.staging,result)
  db=remote(args.lab_root,'pg01',{'phase':'database-verify','profile':args.profile,'input':value,'baseline':record['database']});retained(args.staging,'verify.complete.json',{'receipt':receipt,'database':db})
  return {'verified':True,'profile':args.profile,'existingSourceMetadataPreserved':True,'directoryInstalled':False}
 finally:os.close(fd)

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--phase',choices=('digest','stage','preflight','seed','verify'),required=True);parser.add_argument('--lab-root',type=Path,required=True);parser.add_argument('--staging',type=Path);parser.add_argument('--helper',type=Path);parser.add_argument('--profile',choices=tuple(c.PROFILES));parser.add_argument('--identity-handoff',type=Path);parser.add_argument('--implementation-sha256');parser.add_argument('--preflight-sha256');parser.add_argument('--apply',action='store_true');args=parser.parse_args()
 try:print(c.encoded(execute(args)).decode(),end='')
 except Exception as error:
  code=getattr(error,'code','scale_source_phase_failed');raise SystemExit('Scale source phase failed ('+code+'); retain all private/pending evidence. No configuration install, restart or feed recovery is performed.') from None
if __name__=='__main__':main()
