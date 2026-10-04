#!/usr/bin/env python3
"""Prepare offline, then explicitly run one receipt-bound isolated NFS probe."""
import argparse
import base64
import contextlib
import fcntl
import importlib.util
import os
from pathlib import Path
import shlex
import stat
import sys
import time
import uuid

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
p=load('dashboard-nfs-plan'); h=load('dashboard-dependency-faults'); f=h.g
REMOTE=('dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py','dashboard-nfs-plan.py','dashboard-nfs-protocol.py','dashboard-nfs-relay.py','dashboard-nfs-guest.py')


@contextlib.contextmanager
def locked(root):
    h.directory(root); path=root/'.lock'
    try: fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600); os.fchmod(fd,0o600)
    except FileExistsError: fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd); p.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600,'host_lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); yield
    finally: os.close(fd)


def implementation(): return {name:p.sha(h.read(HERE/name,256<<10,False)) for name in p.FILES}


BOOTSTRAP='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((360<<20)+1)
 if len(raw)>360<<20:raise ValueError()
 value=json.loads(raw);sources=value.pop('_sources');hashes=value.pop('_hashes')
 names={'dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py','dashboard-nfs-plan.py','dashboard-nfs-protocol.py','dashboard-nfs-relay.py','dashboard-nfs-guest.py'}
 if set(sources)!=names or set(hashes)!=names:raise ValueError()
 for name,text in sources.items():
  if hashlib.sha256(text.encode()).hexdigest()!=hashes[name]:raise ValueError()
 def module(name,injected=None):
  m=types.ModuleType(name);m.__file__='/reviewed/'+name+'.py';m.__dict__.update(injected or {})
  exec(compile(sources[name+'.py'],'reviewed-'+name,'exec'),m.__dict__);return m
 b=module('dashboard-dependency-fault-plan');f=module('dashboard-dependency-fault-guest',{'p':b})
 p=module('dashboard-nfs-plan',{'b':b});protocol=module('dashboard-nfs-protocol')
 relay=module('dashboard-nfs-relay',{'p':p,'protocol':protocol,'f':f})
 g=module('dashboard-nfs-guest',{'p':p,'f':f,'relay':relay})
 result=g.execute(value);print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','isolated_nfs_failed')
 print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''


def remote(lab,payload,hashes):
    p.need(payload.get('phase') in ('snapshot','preserved','stage','start','arm','probe','state','resume','observe','close') and payload.get('host') in h.HOSTS,'remote_boundary')
    sources={name:h.read(HERE/name,256<<10,False).decode() for name in REMOTE}
    p.need(all(p.sha(v.encode())==hashes[k] for k,v in sources.items()),'implementation_changed')
    body=p.encoded(dict(payload,_sources=sources,_hashes={k:hashes[k] for k in sources}))
    p.need(len(body)<=360<<20,'remote_bound')
    raw=f.run(h.ssh_args(lab,payload['host'])+[shlex.join(['sudo','python3','-c',BOOTSTRAP])],
              'nfs_remote_'+payload['phase'],data=body,timeout=70,maximum=2<<20)
    value=p.decode(raw); code=value.get('code','')
    p.need(value.get('ok') is True,code if isinstance(code,str) and p.b.re.fullmatch('[a-z][a-z0-9_]{0,63}',code) else 'isolated_nfs_failed')
    return value['result']


def prepare(args):
    inputs=p.decode(h.read(args.inputs,32768))
    p.need(set(inputs)=={'candidate','probe','chunks'},'input_shape')
    # Source ancestry is independently recomputed from the existing repository;
    # the exact binary/build receipt and probe overlay remain explicit inputs.
    candidate=inputs['candidate']; p.need(candidate['outputFixAncestor']==p.FIX,'output_fix_required')
    f.run(['git','-C',str(args.dashboard_root),'merge-base','--is-ancestor',p.FIX,candidate['revision']],
          'candidate_predates_output_fix',maximum=1024)
    for path,expected in ((args.broker,candidate['binary']),(args.probe,inputs['probe']['binary'])):
        raw=h.read(path,128<<20,False)
        p.need(len(raw)==expected['bytes'] and p.sha(raw)==expected['sha256'] and raw[:4]==b'\x7fELF','artifact_identity')
    build=h.read(args.build_receipt,65536); p.need(p.sha(build)==candidate['buildReceiptSHA256'],'build_receipt_identity')
    p.need(p.sha(h.read(args.probe_source,65536,False))==inputs['probe']['sourceSHA256'],'probe_source_identity')
    snapshot=p.decode(h.read(args.snapshot,2<<20)); hashes=implementation()
    plan=p.make(snapshot,str(uuid.uuid4()),candidate,inputs['probe'],inputs['chunks'],hashes,int(time.time()))
    p.validate(plan); h.directory(args.staging,True); h.save(args.staging/'plan.json',plan)
    review={'planSHA256':p.sha(p.encoded(plan)),'implementationSHA256':p.sha(p.encoded(hashes)),
            'operationId':plan['operationId'],'candidate':candidate,'probe':plan['probe'],
            'server':p.SERVER,'export':p.EXPORT,'sourcePorts':p.PORTS,'mountOptions':p.MOUNT_OPTIONS,
            'watchdogSeconds':p.TIMEOUT,'existingRuntimeMutations':False,'applied':False}
    h.save(args.staging/'review.json',review); return review


def phase(args):
    hashes=implementation()
    if args.phase=='snapshot':
        p.need(p.b.REVISION.fullmatch(args.runtime_revision or '') and args.output is not None,'snapshot_arguments')
        value={host:remote(args.lab_root,{'phase':'snapshot','host':host,'revision':args.runtime_revision},hashes) for host in h.HOSTS}
        h.save(args.output,value); return {'snapshotSHA256':p.sha(p.encoded(value)),'mutation':False}
    if args.phase=='prepare': return prepare(args)
    with locked(args.staging):
        raw=h.read(args.staging/'plan.json',2<<20); plan=p.decode(raw); p.validate(plan)
        p.need(p.sha(raw)==args.expected_plan_sha256 and p.sha(p.encoded(hashes))==args.expected_implementation_sha256 and hashes==plan['implementationSHA256'],'reviewed_plan_required')
        if args.phase=='preserved':
            return {host:remote(args.lab_root,{'phase':'preserved','host':host,'plan':plan},hashes) for host in h.HOSTS}
        mutation=args.phase in ('stage','start','arm','probe','resume','close')
        p.need(not mutation or args.apply is True,'explicit_apply_required')
        pending=args.staging/(args.phase+'.pending.json'); completed=args.staging/(args.phase+'.json')
        if mutation and args.phase!='resume':
            p.need(not pending.exists() and not completed.exists(),'uncertain_phase_observe_only')
            # All three baselines are rechecked before the first stage. Later
            # explicit steps check them as well, except safety-only recovery.
            if args.phase in ('stage','start','arm','close'):
                for host in h.HOSTS: remote(args.lab_root,{'phase':'preserved','host':host,'plan':plan},hashes)
            h.save(pending,{'operationId':plan['operationId'],'phase':args.phase})
        payload={'host':'control01','phase':args.phase,'plan':plan,'apply':args.apply}
        if args.phase=='stage':
            payload['sources']={name:h.read(HERE/name,256<<10,False).decode() for name in p.FILES}
            for key,path,expected in (('broker',args.broker,plan['candidate']['binary']),('probe',args.probe,plan['probe']['binary'])):
                data=h.read(path,128<<20,False); p.need(p.sha(data)==expected['sha256'] and len(data)==expected['bytes'],'artifact_changed')
                payload[key]=base64.b64encode(data).decode()
        result=remote(args.lab_root,payload,hashes)
        if mutation and args.phase!='resume': h.save(completed,result)
        return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('phase',choices=('snapshot','prepare','preserved','stage','start','arm','probe','state','resume','observe','close'))
    parser.add_argument('--lab-root',required=True,type=Path)
    for name in ('staging','output','snapshot','inputs','broker','probe','probe-source','build-receipt','dashboard-root'): parser.add_argument('--'+name,type=Path)
    for name in ('runtime-revision','expected-plan-sha256','expected-implementation-sha256'): parser.add_argument('--'+name)
    parser.add_argument('--apply',action='store_true'); args=parser.parse_args()
    p.need(args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'canonical_lab_root')
    print(p.encoded(phase(args)).decode(),end='')


if __name__=='__main__':
    try: main()
    except Exception as error:
        print(p.encoded({'ok':False,'code':getattr(error,'code','isolated_nfs_failed')}).decode(),end=''); sys.exit(1)
