#!/usr/bin/env python3
"""Explicit phased mapping-only deployment for the separate synthetic Slurm agent."""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('slurm_apply_plan',HERE/'dashboard-slurm-plan.py');plan=importlib.util.module_from_spec(spec);spec.loader.exec_module(plan)
spec=importlib.util.spec_from_file_location('slurm_mapping_guest_transport',HERE/'dashboard-slurm-mapping-guest.py');guest=importlib.util.module_from_spec(spec);spec.loader.exec_module(guest)
FILES=('apply-dashboard-slurm-mappings.py','dashboard-slurm-mapping-guest.py','dashboard-slurm-plan.py','dashboard-execution-plan.py')
ROLES=('broker','api','reports')
PHASES=('preflight','stage','apply','restart','verify')
SPECS={'broker':('control01','/etc/jobman-dashboard-broker-lab/config.json',21901),'api':('storage01','/etc/jobman-dashboard-api-lab/config.json',21904),'reports':('storage01','/etc/jobman-dashboard-worker-lab/config.json',21905)}


def private(path,maximum=1048576):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as stream:
  before=os.fstat(stream.fileno());plan.base.require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=maximum,'Private regular input required')
  raw=stream.read(maximum+1);after=os.fstat(stream.fileno());current=path.lstat()
  plan.base.require(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and (current.st_dev,current.st_ino)==(before.st_dev,before.st_ino),'Private input changed during read')
  return raw

def implementation():return {name:hashlib.sha256(plan.base.read(HERE/name,1048576)).hexdigest() for name in FILES}

def put(path,value):
 raw=plan.base.encoded(value)
 try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 except FileExistsError:plan.base.require(private(path)==raw,'Retained phase receipt differs');return
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

@contextmanager
def lock(lab):
 path=lab/'.lab/dashboard-slurm';s=path.lstat();plan.base.require(path.resolve()==path and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'Private Slurm inventory directory required')
 name=path/'.mapping-apply.lock';created=False
 try:fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600);created=True
 except FileExistsError:fd=os.open(name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);plan.base.require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid(),'Private lock inode required')
  if created:os.fchmod(fd,0o600)
  else:plan.base.require(stat.S_IMODE(s.st_mode)==0o600,'Existing lock mode differs')
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
 finally:os.close(fd)


def prepared(args):
 s=args.staging.lstat();plan.base.require(args.staging.is_absolute() and args.staging.resolve()==args.staging and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'Private absolute staging directory required')
 raw=private(args.staging/'review.json');review=json.loads(raw)
 plan.base.require(re.fullmatch('[0-9a-f]{64}',args.expected_review_sha256) and hashlib.sha256(raw).hexdigest()==args.expected_review_sha256,'Exact reviewed mapping digest differs')
 hashes=implementation();plan.base.require(hashlib.sha256(plan.base.encoded(hashes)).hexdigest()==args.expected_implementation_sha256,'Reviewed implementation differs')
 plan.base.require(review['synthetic'] is True and review['applies'] is False and type(review['currentRevision']) is int and review['nextRevision']==review['currentRevision']+1 and len(review['files'])==3 and {x['role'] for x in review['files']}==set(ROLES),'Mapping review scope differs')
 fixture_raw=plan.base.read(args.lab_root/'.lab/dashboard/slurm-fixture.json',32768);plan.base.require(hashlib.sha256(fixture_raw).hexdigest()==review['fixtureSHA256'],'Executor fixture changed');fixture=json.loads(fixture_raw)
 result={}
 for item in review['files']:
  role=item['role'];host,path,uid=SPECS[role]
  plan.base.require((item['host'],item['path'],item['uid'],item['gid'],item['mode'])==(host,path,uid,uid,0o600),'Role owner/path differs')
  before=private(args.staging/(role+'.before.json'));after=private(args.staging/(role+'.after.json'))
  plan.base.require(hashlib.sha256(before).hexdigest()==item['beforeSHA256'] and hashlib.sha256(after).hexdigest()==item['afterSHA256'] and json.loads(after)==plan.mapping_patch(json.loads(before),fixture,role,review['currentRevision']),'Mapping delta differs from the scoped additive proposal')
  result[role]={'role':role,'file':item,'review':review,'reviewSHA256':args.expected_review_sha256,'fixture':fixture,'before':base64.b64encode(before).decode(),'after':base64.b64encode(after).decode()}
 return result,hashes


def remote(lab,payload):
 host=SPECS[payload['role']][0];inventory=json.loads(private(lab/'.lab/dashboard/ssh-connections.json',65536));c=inventory[host];address=ipaddress.ip_address(c['ansible_host'])
 plan.base.require(c['ansible_user']=='vagrant' and Path(c['ansible_ssh_private_key_file']).is_absolute() and type(c['ansible_port']) is int and 1<=c['ansible_port']<=65535 and (str(address) in ('127.0.0.1','10.77.0.10','10.77.0.21') or address in ipaddress.ip_network('10.211.55.0/24')),'Pinned mapping guest differs')
 script=plan.base.read(HERE/'dashboard-slurm-mapping-guest.py',1048576).decode()
 args=['ssh','-i',c['ansible_ssh_private_key_file'],'-p',str(c['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={lab}/.lab/dashboard/known_hosts','-o','HostKeyAlgorithms=ssh-ed25519',f'{c["ansible_user"]}@{c["ansible_host"]}',shlex.join(['sudo','python3','-c',script])]
 output=guest.run(args,input_data=plan.base.encoded(payload),timeout=60)
 plan.base.require(len(output)<=65536,'Mapping phase failed; retain files and receipts without automatic rollback')
 return json.loads(output)


def execute(args):
 plan.base.require(args.phase in PHASES and (args.phase in ('preflight','verify') or args.apply),'Explicit apply flag required for guest mutation')
 plan.base.require(args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'Real absolute Lab root required')
 with lock(args.lab_root):
  values,hashes=prepared(args);receipts=args.staging/'apply-receipts'
  try:receipts.mkdir(mode=0o700);os.chmod(receipts,0o700)
  except FileExistsError:pass
  s=receipts.lstat();plan.base.require(receipts.resolve()==receipts and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'Receipt directory differs')
  put(receipts/'implementation.json',hashes)
  def call(role,phase,baseline=None):return remote(args.lab_root,dict(values[role],phase=phase,apply=args.apply,baseline=baseline))
  if args.phase=='preflight':
   snapshots={role:call(role,'preflight') for role in ROLES};now=int(time.time());plan.base.require(all(abs(x['epoch']-now)<=10 for x in snapshots.values()),'Guest clocks differ')
   put(receipts/'preflight.json',snapshots);return {'preflight':True,'guestsMutated':False}
  baseline=json.loads(private(receipts/'preflight.json'))
  plan.base.require(set(baseline)==set(ROLES),'Preflight roles differ')
  if args.phase in ('stage','apply'):plan.base.require(0<=int(time.time())-min(x['epoch'] for x in baseline.values())<=900,'Preflight expired; preserve staged state for inspection')
  if args.phase=='stage':
   # Every current hash/role is checked before ANY guest staging mutation.
   for role in ROLES:
    current=call(role,'preflight');plan.base.require({k:v for k,v in current.items() if k!='epoch'}=={k:v for k,v in baseline[role].items() if k!='epoch'},'Preflight runtime changed')
   for role in ROLES:put(receipts/('stage-'+role+'.json'),call(role,'stage',baseline[role]))
  elif args.phase=='apply':
   for role in ROLES:private(receipts/('stage-'+role+'.json'))
   # A lost response may leave only exact pending-receipt-bound new bytes.
   # Validate all three old-or-proven-applied states before the first CAS.
   for role in ROLES:call(role,'swap-state',baseline[role])
   for role in ROLES:put(receipts/('apply-'+role+'.json'),call(role,'apply',baseline[role]))
  elif args.phase=='restart':
   for role in ROLES:private(receipts/('apply-'+role+'.json'));plan.base.require(call(role,'swap-state',baseline[role])['state']=='applied','All swaps must finish before any restart')
   for role in ROLES:put(receipts/('restart-'+role+'.json'),call(role,'restart',baseline[role]))
  else:
   for role in ROLES:private(receipts/('restart-'+role+'.json'))
   for role in ROLES:put(receipts/('verified-'+role+'.json'),call(role,'verify',baseline[role]))
  return {'phase':args.phase,'complete':True,'configurationRevision':values['api']['review']['nextRevision'],'sourceRestarted':False,'workloadsSubmitted':False}

if __name__=='__main__':
 try:
  parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--lab-root',type=Path,default=HERE.parent);parser.add_argument('--staging',type=Path,required=True);parser.add_argument('--expected-review-sha256',required=True);parser.add_argument('--expected-implementation-sha256',required=True);parser.add_argument('--phase',choices=PHASES,default='preflight');parser.add_argument('--apply',action='store_true')
  print(json.dumps(execute(parser.parse_args()),sort_keys=True))
 except Exception:raise SystemExit('Slurm mapping phase failed. Preserve private files/receipts; no rollback, notification resume or source restart attempted.') from None
