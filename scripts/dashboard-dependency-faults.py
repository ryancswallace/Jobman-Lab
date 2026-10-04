#!/usr/bin/env python3
"""Offline preparation and explicit fixed-host dependency-fault phases."""
import argparse
import base64
import contextlib
import fcntl
import importlib.util
import ipaddress
import os
from pathlib import Path
import shlex
import stat
import sys
import time
import uuid

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fault_plan',HERE/'dashboard-dependency-fault-plan.py')
p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
spec=importlib.util.spec_from_file_location('fault_guest',HERE/'dashboard-dependency-fault-guest.py')
g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
HOSTS=('control01','storage01','pg01')
PHASES=('snapshot','prepare','stage','begin','recover','status','verify','close','observe-api')


def read(path,maximum=2<<20,private=True):
    path=Path(path); p.need(path.is_absolute() and path.parent.resolve()==path.parent,'host_path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        a=os.fstat(f.fileno())
        p.need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==os.getuid() and
               (stat.S_IMODE(a.st_mode)==0o600 if private else not stat.S_IMODE(a.st_mode)&0o022) and 0<a.st_size<=maximum,'host_file')
        raw=f.read(maximum+1); b=os.fstat(f.fileno()); c=path.lstat()
        p.need(len(raw)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and (a.st_dev,a.st_ino)==(c.st_dev,c.st_ino),'host_file_changed')
        return raw


def directory(path,create=False):
    if create:
        path.mkdir(mode=0o700); path.chmod(0o700); g.sync(path.parent)
    s=path.lstat(); p.need(path.is_absolute() and path.resolve()==path and stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,'host_directory')


def save(path,value):
    raw=p.encoded(value)
    if path.exists(): p.need(read(path)==raw,'host_receipt_changed')
    else: g.put(path,raw)


@contextlib.contextmanager
def locked(lab):
    root=lab/'.lab/dashboard'; directory(root)
    path=root/'.dependency-faults.lock'
    try: fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600); os.fchmod(fd,0o600)
    except FileExistsError: fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd); p.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600,'host_lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); yield
    finally: os.close(fd)


def implementation():
    return {name:p.sha(read(HERE/name,256<<10,False)) for name in p.IMPLEMENTATION}


def ssh_args(lab,host):
    p.need(host in HOSTS,'ssh_host')
    row=p.decode(read(lab/'.lab/dashboard/ssh-connections.json',65536))[host]
    ip=ipaddress.ip_address(row['ansible_host'])
    fixed={'control01':'10.77.0.21','storage01':'10.77.0.10','pg01':'10.77.0.20'}
    p.need(row['ansible_user']=='vagrant' and type(row['ansible_port']) is int and 1<=row['ansible_port']<=65535 and
           Path(row['ansible_ssh_private_key_file']).is_absolute() and
           (str(ip) in ('127.0.0.1',fixed[host]) or ip in ipaddress.ip_network('10.211.55.0/24')),'ssh_boundary')
    return ['ssh','-i',row['ansible_ssh_private_key_file'],'-p',str(row['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
            '-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(lab/'.lab/dashboard/known_hosts'),
            '-o','HostKeyAlgorithms=ssh-ed25519',row['ansible_user']+'@'+str(ip)]


BOOTSTRAP='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((2<<20)+1)
 if len(raw)>2<<20:raise ValueError()
 value=json.loads(raw);sources=value.pop('_sources');hashes=value.pop('_hashes')
 names={'dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py'}
 if set(sources)!=names or set(hashes)!=names:raise ValueError()
 for name,text in sources.items():
  if hashlib.sha256(text.encode()).hexdigest()!=hashes[name]:raise ValueError()
 plan=types.ModuleType('fault_plan');exec(compile(sources['dashboard-dependency-fault-plan.py'],'reviewed-plan','exec'),plan.__dict__)
 space={'__name__':'reviewed_guest','__file__':'/reviewed/dashboard-dependency-fault-guest.py','p':plan}
 exec(compile(sources['dashboard-dependency-fault-guest.py'],'reviewed-guest','exec'),space)
 answer=space['execute'](value);print(json.dumps({'ok':True,'result':answer},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','guest_failed')
 print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''


def remote(lab,payload,hashes):
    p.need(payload.get('phase') in ('snapshot','stage','begin','recover','status','verify','database-check','observe-api'),'remote_phase')
    sources={name:read(HERE/name,256<<10,False).decode() for name in p.IMPLEMENTATION[:2]}
    p.need(all(p.sha(value.encode())==hashes[name] for name,value in sources.items()),'implementation_changed')
    body=p.encoded(dict(payload,_sources=sources,_hashes={name:hashes[name] for name in sources}))
    p.need(len(body)<=2<<20,'remote_payload_bound')
    timeout=155 if payload['phase']=='begin' else 70
    raw=g.run(ssh_args(lab,payload['host'])+[shlex.join(['sudo','python3','-c',BOOTSTRAP])],
              'fault_remote_'+payload['phase'].replace('-','_'),timeout=timeout,data=body,maximum=2<<20)
    result=p.decode(raw)
    p.need(result.get('ok') is True,result.get('code') if p.re.fullmatch(r'[a-z][a-z0-9_]{0,63}',str(result.get('code',''))) else 'guest_failed')
    return result['result']


def snapshot(args):
    p.need(p.REVISION.fullmatch(args.revision or '') and args.output is not None,'snapshot_arguments')
    hashes=implementation(); value={host:remote(args.lab_root,{'phase':'snapshot','host':host,'revision':args.revision},hashes) for host in HOSTS}
    p.stable_database(value['pg01']['database']); save(args.output,value)
    return {'snapshotSHA256':p.sha(p.encoded(value)),'mutation':False}


def prepare(args):
    value=p.decode(read(args.snapshot)); hashes=implementation()
    plan=p.make(value,args.scenario,str(uuid.uuid4()),args.revision,hashes,int(time.time()))
    p.validate(plan); directory(args.staging,create=True)
    save(args.staging/'plan.json',plan)
    review={'planSHA256':p.sha(p.encoded(plan)),'implementationSHA256':p.sha(p.encoded(hashes)),
            'scenario':plan['scenario'],'operationId':plan['operationId'],'faults':{f:p.FAULTS[f] for f in plan['faults']},'applied':False}
    save(args.staging/'review.json',review); return review


def load_plan(args):
    directory(args.staging); raw=read(args.staging/'plan.json'); plan=p.decode(raw); p.validate(plan)
    hashes=implementation()
    p.need(p.sha(raw)==args.expected_plan_sha256 and p.sha(p.encoded(hashes))==args.expected_implementation_sha256 and hashes==plan['implementationSHA256'],'reviewed_plan_required')
    return plan,hashes


def operation_record(args,plan,begin=False):
    parent=args.lab_root/'.lab/dashboard/dependency-fault-operations'
    if not parent.exists(): directory(parent,create=True)
    directory(parent); entries=list(parent.iterdir()); p.need(len(entries)<=128,'operation_history_bound')
    for entry in entries:
        directory(entry)
        if entry.name!=plan['operationId']: p.need((entry/'complete.json').exists(),'another_operation_pending')
    root=parent/plan['operationId']
    if not root.exists():
        p.need(begin,'operation_not_admitted'); directory(root,create=True)
        save(root/'intent.json',{'planSHA256':args.expected_plan_sha256,'staging':str(args.staging)})
    p.need(p.decode(read(root/'intent.json'))=={'planSHA256':args.expected_plan_sha256,'staging':str(args.staging)},'operation_identity')
    return root


def phase(args):
    plan,hashes=load_plan(args); fault=args.fault
    p.need(args.phase in ('close','observe-api') or fault in plan['faults'],'fault_required')
    host=p.FAULTS[fault]['host'] if fault else None
    payload={'phase':args.phase,'host':host,'plan':plan,'fault':fault,'apply':args.apply}
    if args.phase=='observe-api': return remote(args.lab_root,dict(payload,host='storage01'),hashes)
    if args.phase=='status': return remote(args.lab_root,payload,hashes)
    if args.phase in ('stage','begin','recover'): p.need(args.apply,'explicit_apply_required')
    if args.phase=='stage':
        p.need(0<=time.time()-plan['createdAt']<=3600,'plan_expired')
        remote(args.lab_root,dict(payload,phase='database-check',host='pg01'),hashes)
        payload['sources']={n:base64.b64encode(read(HERE/n,256<<10,False)).decode() for n in p.IMPLEMENTATION}
        # Repeated stage is proof-only for a complete immutable guest directory.
        result=remote(args.lab_root,payload,hashes); save(args.staging/'stage.json',result); return result
    if args.phase=='close':
        for f in plan['faults']:
            value=p.decode(read(args.staging/(f+'.verified.json')))
            p.need(value=={'verified':True,'operationId':plan['operationId'],'fault':f},'fault_not_verified')
        remote(args.lab_root,dict(payload,phase='database-check',host='pg01'),hashes)
        root=operation_record(args,plan); save(root/'complete.json',{'planSHA256':args.expected_plan_sha256})
        return {'closed':True,'operationId':plan['operationId']}
    staged=p.decode(read(args.staging/'stage.json'))
    p.need(staged=={'staged':True,'operationId':plan['operationId'],'host':host},'stage_missing')
    if args.phase=='begin':
        for previous in plan['faults'][:plan['faults'].index(fault)]:
            p.need(p.decode(read(args.staging/(previous+'.verified.json')))=={'verified':True,'operationId':plan['operationId'],'fault':previous},'previous_fault_unverified')
        pending=args.staging/(fault+'.pending.json')
        p.need(not pending.exists(),'uncertain_begin_requires_recovery')
        remote(args.lab_root,dict(payload,phase='database-check',host='pg01'),hashes)
        operation_record(args,plan,begin=True)
        save(pending,{'operationId':plan['operationId'],'fault':fault,'planSHA256':args.expected_plan_sha256})
        result=remote(args.lab_root,payload,hashes); save(args.staging/(fault+'.applied.json'),result); return result
    p.need((args.staging/(fault+'.pending.json')).exists(),'fault_not_admitted')
    result=remote(args.lab_root,payload,hashes)
    if args.phase=='recover': save(args.staging/(fault+'.restored.json'),result)
    elif args.phase=='verify':
        remote(args.lab_root,dict(payload,phase='database-check',host='pg01'),hashes)
        save(args.staging/(fault+'.verified.json'),result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=PHASES); parser.add_argument('--lab-root',type=Path,required=True)
    parser.add_argument('--staging',type=Path); parser.add_argument('--snapshot',type=Path); parser.add_argument('--output',type=Path)
    parser.add_argument('--revision'); parser.add_argument('--scenario',choices=p.SCENARIOS); parser.add_argument('--fault',choices=p.FAULTS)
    parser.add_argument('--expected-plan-sha256'); parser.add_argument('--expected-implementation-sha256'); parser.add_argument('--apply',action='store_true')
    args=parser.parse_args(); p.need(args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'lab_root')
    with locked(args.lab_root):
        result=snapshot(args) if args.phase=='snapshot' else prepare(args) if args.phase=='prepare' else phase(args)
    sys.stdout.buffer.write(p.encoded(result))


if __name__=='__main__':
    try: main()
    except Exception as error:
        code=getattr(error,'code','phase_failed')
        print('Dependency fault phase stopped ('+code+'); preserve receipts; do not repeat an uncertain begin.',file=sys.stderr)
        raise SystemExit(1) from None
