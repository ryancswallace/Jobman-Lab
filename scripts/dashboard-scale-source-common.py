#!/usr/bin/env python3
"""Fixed scale-source specification and bounded filesystem/command primitives."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from datetime import datetime, timezone, timedelta

COMMIT = '367006818e72315b01860f56f971004e17c24886'
BINARY_SHA = '6f511e91434dac2499d464f0b424607fe0b099b966148c992499e5371a333f65'
BINARY = Path('/usr/local/libexec/jobman-dashboard-scale')/COMMIT/'jobman-control-lab-helper'
RECEIPTS = Path('/var/lib/jobman-dashboard-scale-source')
ISSUER = 'https://oidc.lab.test:8443/realms/jobman-lab'
HEX = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
PROFILES = {
 'primary': {'root':'/etc/jobman-dashboard-lab/control-fixture','directory':'/etc/jobman-dashboard-lab/control-fixture','uid':21902,'directoryUID':21902,
             'database':'jobman_dashboard_control','instance':'e633cf92-258d-48ff-965a-fda88d68ef3a','deployment':'72000000-0000-4000-8000-000000000001','count':10,'cli':'primary'},
 'secondary': {'root':'/etc/jobman-dashboard-secondary/control','directory':'/etc/jobman-dashboard-secondary/directory','uid':21907,'directoryUID':21908,
             'database':'jobman_dashboard_control_secondary','instance':'a4f0e2ab-7323-4c90-9510-1f073c660f06','deployment':'72000000-0000-4000-8000-000000000002','count':5,'cli':'secondary-v1'}
}

class Failure(ValueError):
 def __init__(self,code):
  assert re.fullmatch('[a-z][a-z0-9_]{0,63}',code)
  self.code=code;super().__init__(code)
def need(value,code):
 if not value:raise Failure(code)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def decode(raw):
 def unique(pairs):
  out={}
  for key,value in pairs:need(key not in out,'duplicate_json_field');out[key]=value
  return out
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(Failure('invalid_json_number')))
def read(path,maximum=1<<20,uid=None,mode=0o600):
 path=Path(path);uid=os.getuid() if uid is None else uid
 need(path.is_absolute() and path.parent.resolve()==path.parent,'file_parent_alias')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==uid and stat.S_IMODE(a.st_mode)==mode and 0<a.st_size<=maximum,'file_identity')
  raw=f.read(maximum+1);b=os.fstat(f.fileno());n=path.lstat()
  need(len(raw)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and (a.st_dev,a.st_ino)==(n.st_dev,n.st_ino),'file_changed')
  return raw
def sync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def directory(path,mode=0o700,create=False):
 path=Path(path)
 if create and not path.exists():path.mkdir(mode=mode);path.chmod(mode);sync(path.parent)
 s=path.lstat();need(path.resolve()==path and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==mode,'directory_identity')
def put(path,raw,mode=0o600):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())
 sync(path.parent)
def retain(path,raw):
 if path.exists():need(read(path)==raw,'immutable_receipt_changed')
 else:put(path,raw)
def run(args,payload=b'',timeout=30,maximum=1<<20,env=None):
 child=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=env)
 output=bytearray();errors=0;position=0;deadline=time.monotonic()+timeout
 try:
  with selectors.DefaultSelector() as selected:
   for stream,events,name in ((child.stdin,selectors.EVENT_WRITE,'in'),(child.stdout,selectors.EVENT_READ,'out'),(child.stderr,selectors.EVENT_READ,'err')):
    os.set_blocking(stream.fileno(),False);selected.register(stream,events,name)
   while selected.get_map():
    need(time.monotonic()<deadline,'command_deadline')
    for key,_ in selected.select(min(0.2,max(0,deadline-time.monotonic()))):
     if key.data=='in':
      if position<len(payload):position+=os.write(key.fileobj.fileno(),payload[position:position+16384])
      if position==len(payload):selected.unregister(key.fileobj);key.fileobj.close()
      continue
     raw=os.read(key.fileobj.fileno(),65536)
     if not raw:selected.unregister(key.fileobj);continue
     if key.data=='out':output.extend(raw);need(len(output)<=maximum,'command_output_bound')
     else:errors+=len(raw);need(errors<=65536,'command_error_bound')
   need(child.wait(timeout=max(0.01,deadline-time.monotonic()))==0,'command_failed')
  return bytes(output)
 finally:
  if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
  for stream in (child.stdin,child.stdout,child.stderr):stream.close()
def names(profile):return ['dashboard-scale-%02d'%i for i in range(1,PROFILES[profile]['count']+1)]
def validate_input(value,profile,now=None):
 p=PROFILES[profile];now=now or datetime.now(timezone.utc)
 need(set(value)=={'instanceId','issuer','historyAt','users'} and value['instanceId']==p['instance'] and value['issuer']==ISSUER and len(value['users'])==25,'scale_input_shape')
 need(isinstance(value['historyAt'],str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',value['historyAt']),'history_time_format')
 when=datetime.fromisoformat(value['historyAt'].replace('Z','+00:00'));need(when.tzinfo is not None and now-timedelta(days=7)<=when<now-timedelta(minutes=1),'history_time_bound')
 subjects=set()
 for i,user in enumerate(value['users'],1):
  need(set(user)=={'directoryId','subject','name'} and user['directoryId']=='74000000-0000-4000-8000-%012d'%i and user['name']=='Synthetic scale %02d'%i and UUID.fullmatch(user['subject']) and user['subject']!='00000000-0000-0000-0000-000000000000' and user['subject'] not in subjects,'scale_identity')
  subjects.add(user['subject'])
 return value
