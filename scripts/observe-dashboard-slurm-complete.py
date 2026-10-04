#!/usr/bin/env python3
"""Read only: repaired runner identity and exact complete-array execution facts."""
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
BINARY = '9ecc9fe75c404b85eb7b4349b55db736885db5eddd024826a4d0dbf73720a47e'
UNIT_SHA = 'e496d8cb124e69fd92edf6d2e8d1081d43a98f6601f7b752ad5f2f4e4bd390f7'


def validate(value):
    if value == {'operation': 'preflight'}:
        return value
    if set(value) == {'operation', 'parentId', 'collectionId'} and value['operation'] == 'accounting' and re.fullmatch('[1-9][0-9]{0,17}', value['parentId']) and UUID.fullmatch(value['collectionId']):
        return value
    if set(value) == {'operation', 'executions'} and value['operation'] == 'completions' and isinstance(value['executions'], list) and len(value['executions']) == 5:
        ids = set()
        for index, item in enumerate(value['executions']):
            if set(item) != {'index', 'executionId'} or type(item['index']) is not int or item['index'] != index or not UUID.fullmatch(item['executionId']) or item['executionId'] in ids:
                raise ValueError('Invalid exact execution identity')
            ids.add(item['executionId'])
        return value
    raise ValueError('Invalid fixed-scope read')


REMOTE = r'''
import hashlib,json,os,re,selectors,stat,subprocess,sys,time
p=json.load(sys.stdin)
def run(args):
 child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);out=bytearray();deadline=time.monotonic()+15
 try:
  with selectors.DefaultSelector() as ready:
   ready.register(child.stdout,selectors.EVENT_READ)
   while True:
    remaining=deadline-time.monotonic();assert remaining>0 and ready.select(remaining)
    part=os.read(child.stdout.fileno(),min(65536,65537-len(out)))
    if not part:break
    out.extend(part);assert len(out)<=65536
  assert child.wait(timeout=max(.001,deadline-time.monotonic()))==0
  return bytes(out)
 finally:
  if child.poll() is None:child.kill();child.wait(timeout=3)
  child.stdout.close()
if p=={'operation':'preflight'}:
 assert os.getuid()==0
 digest='9ecc9fe75c404b85eb7b4349b55db736885db5eddd024826a4d0dbf73720a47e';runner='/usr/local/libexec/jobman-dashboard-lab/jobman-agent-execution-'+digest
 from pathlib import Path
 fd=os.open(runner,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o755 and st.st_size<64<<20
  assert hashlib.sha256(f.read((64<<20)+1)).hexdigest()==digest
 unit='jobman-dashboard-execution-slurm.service';fd=os.open('/etc/systemd/system/'+unit,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno());assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o644 and 0<st.st_size<=8192
  raw=f.read(8193);assert len(raw)<=8192
 assert hashlib.sha256(raw).hexdigest()=='e496d8cb124e69fd92edf6d2e8d1081d43a98f6601f7b752ad5f2f4e4bd390f7'
 assert run(['systemctl','is-active',unit]).strip()==b'active'
 pid=run(['systemctl','show',unit,'--property=MainPID','--value']).decode().strip();assert pid.isdecimal() and Path('/proc',pid).stat().st_uid==21001 and os.readlink('/proc/'+pid+'/exe')==runner
 assert not run(['/opt/slurm/current/bin/squeue','--noheader','--format=%i']).strip()
 assert run(['/opt/slurm/current/bin/sinfo','--noheader','--Node','--nodes=compute01','--format=%N|%T']).strip()==b'compute01|idle'
 assert run(['systemctl','is-active','munge']).strip()==b'active'
 print(json.dumps({'queueEmpty':True,'compute01':'idle','agentSHA256':digest,'unitSHA256':'e496d8cb124e69fd92edf6d2e8d1081d43a98f6601f7b752ad5f2f4e4bd390f7'}))
elif p['operation']=='accounting':
 assert os.getuid()==21001 and re.fullmatch('[1-9][0-9]{0,17}',p['parentId'])
 text=run(['/opt/slurm/current/bin/sacct','--allocations','--array','--noheader','--parsable2','--jobs='+p['parentId'],'--format=JobIDRaw%64,JobID%64,State%40,ExitCode,NodeList,JobName%100,Start,End'])
 print(json.dumps({'accountingText':text.decode()}))
else:
 assert os.getuid()==21001 and p['operation']=='completions' and len(p['executions'])==5
 root=os.open('/data/jobman/alice/dashboard-slurm-bundles/executions',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  rows=[]
  for index,item in enumerate(p['executions']):
   identifier=item['executionId'];assert item['index']==index and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',identifier)
   directory=os.open(identifier,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
   try:fd=os.open('completed.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
   finally:os.close(directory)
   with os.fdopen(fd,'rb') as f:
    before=os.fstat(f.fileno());assert stat.S_ISREG(before.st_mode) and before.st_uid==21001 and 0<before.st_size<=32768
    raw=f.read(32769);after=os.fstat(f.fileno());assert len(raw)<=32768 and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
   value=json.loads(raw);assert value['executionId']==identifier and set(value['result'])=={'outcome','exitCode'} and type(value['result']['exitCode']) is int
   expected={'outcome':'failure','exitCode':7} if index==2 else {'outcome':'success','exitCode':0};assert value['result']==expected
   rows.append({'index':index,'executionId':identifier,'observedAt':value['observedAt'],'outcome':value['result']['outcome'],'exitCode':value['result']['exitCode'],'completionSHA256':hashlib.sha256(raw).hexdigest()})
  print(json.dumps({'executions':rows}))
 finally:os.close(root)
'''


def main():
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192: raise ValueError('Input exceeds bound')
    value = validate(json.loads(raw))
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location('complete_observe_checks', root/'scripts/check-dashboard-infra.py')
    checks = importlib.util.module_from_spec(spec); spec.loader.exec_module(checks)
    state = root/'.lab/dashboard-slurm'
    c = json.loads((state/'ssh-connections.json').read_bytes())['submit01']
    remote = ['sudo'] + ([] if value['operation'] == 'preflight' else ['-u', 'alice']) + ['python3', '-c', REMOTE]
    args = ['ssh', '-i', c['ansible_ssh_private_key_file'], '-p', str(c['ansible_port']), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(state/'known_hosts'), '-o', 'HostKeyAlgorithms=ssh-ed25519', c['ansible_user']+'@'+c['ansible_host'], shlex.join(remote)]
    result = checks.run(args, json.dumps(value), timeout=25)
    if result.returncode or len(result.stdout) > 131072: raise ValueError('Scoped read failed')
    reply = json.loads(result.stdout)
    if value['operation'] == 'accounting':
        spec = importlib.util.spec_from_file_location('complete_accounting', root/'scripts/observe-dashboard-slurm.py')
        old = importlib.util.module_from_spec(spec); spec.loader.exec_module(old)
        reply = old.accounting(reply['accountingText'], value)
    print(json.dumps(reply, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Bounded complete-array observation unavailable; no scheduler/workload mutation attempted.') from None
