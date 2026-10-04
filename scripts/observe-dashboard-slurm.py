#!/usr/bin/env python3
"""Read only: fixed Slurm health or exact collection-parent accounting, bounded."""
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

UUID=re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')

def validate(value):
    if value=={'operation':'preflight'}:return value
    if set(value)!={'operation','collectionId','parentId'} or value['operation']!='accounting' or not UUID.fullmatch(value['collectionId']) or not re.fullmatch(r'[1-9][0-9]{0,17}',value['parentId']):raise ValueError('Invalid exact accounting request')
    return value


def accounting(text,value):
    rows=[];seen=set()
    for line in text.splitlines():
        fields=line.split('|')
        if fields[-1]=='':fields.pop()
        if len(fields)!=8 or any(len(f)>256 for f in fields):raise ValueError('Accounting row bound differs')
        raw,job,state,exit_code,node,name,start,end=fields
        if not re.fullmatch(re.escape(value['parentId'])+r'_[0-4]',job) or job in seen or name!='jobman-array-'+value['collectionId'] or not re.fullmatch(r'[0-9]+(?:(?:_[0-4])|(?:\.[a-z]+))?',raw):raise ValueError('Accounting source identity differs')
        seen.add(job);rows.append(dict(jobId=job,state=state,exitCode=exit_code,nodeList=node,jobName=name,start=start,end=end))
    if len(rows)!=5:raise ValueError('Accounting does not contain exactly five literal tasks')
    return dict(parentId=value['parentId'],collectionId=value['collectionId'],rows=rows)


REMOTE=r'''
import json,os,re,selectors,subprocess,sys,time
p=json.load(sys.stdin);assert os.getuid()==21001

def run(args):
 process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);output=bytearray();deadline=time.monotonic()+15
 try:
  with selectors.DefaultSelector() as ready:
   ready.register(process.stdout,selectors.EVENT_READ)
   while True:
    remaining=deadline-time.monotonic();assert remaining>0 and ready.select(remaining),'Observation deadline'
    chunk=os.read(process.stdout.fileno(),min(65536,65537-len(output)))
    if not chunk:break
    output.extend(chunk);assert len(output)<=65536,'Observation bound'
  assert process.wait(timeout=max(.001,deadline-time.monotonic()))==0
  return bytes(output).decode()
 finally:
  if process.poll() is None:process.kill();process.wait(timeout=3)
  process.stdout.close()
if p=={'operation':'preflight'}:
 assert not run(['/opt/slurm/current/bin/squeue','--noheader','--format=%i']).strip(),'Existing queue must remain untouched'
 node=run(['/opt/slurm/current/bin/sinfo','--noheader','--Node','--nodes=compute01','--format=%N|%T']).strip()
 assert node=='compute01|idle','Approved compute node unavailable'
 assert run(['/usr/bin/systemctl','is-active','munge']).strip()=='active'
 print(json.dumps({'queueEmpty':True,'compute01':'idle'}))
else:
 assert set(p)=={'operation','parentId','collectionId'} and p['operation']=='accounting' and re.fullmatch('[1-9][0-9]{0,17}',p['parentId'])
 text=run(['/opt/slurm/current/bin/sacct','--allocations','--array','--noheader','--parsable2','--jobs='+p['parentId'],'--format=JobIDRaw,JobID,State%40,ExitCode,NodeList,JobName%100,Start,End'])
 print(json.dumps({'accountingText':text}))
'''


def main():
    raw=sys.stdin.buffer.read(4097)
    if len(raw)>4096:raise ValueError('Input exceeds bound')
    value=validate(json.loads(raw));root=Path(__file__).resolve().parent.parent;state=root/'.lab/dashboard-slurm'
    spec=importlib.util.spec_from_file_location('slurm_observe_checks',root/'scripts/check-dashboard-infra.py');checks=importlib.util.module_from_spec(spec);spec.loader.exec_module(checks)
    c=json.loads((state/'ssh-connections.json').read_bytes())['submit01']
    args=['ssh','-i',c['ansible_ssh_private_key_file'],'-p',str(c['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={state}/known_hosts','-o','HostKeyAlgorithms=ssh-ed25519',f'{c["ansible_user"]}@{c["ansible_host"]}',shlex.join(['sudo','-u','alice','python3','-c',REMOTE])]
    result=checks.run(args,json.dumps(value),timeout=25)
    if result.returncode or len(result.stdout)>131072:raise ValueError('Scoped observation failed')
    reply=json.loads(result.stdout)
    if value['operation']=='accounting':reply=accounting(reply['accountingText'],value)
    elif reply!={'queueEmpty':True,'compute01':'idle'}:raise ValueError('Unexpected preflight response')
    print(json.dumps(reply,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):raise SystemExit('Bounded Slurm observation unavailable; no scheduler or workload mutation attempted.') from None
