#!/usr/bin/env python3
"""Explicit offline preparation and separately reviewed disposable probe phases."""
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
spec=importlib.util.spec_from_file_location('schema_probe_plan',HERE/'dashboard-schema-probe-plan.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

def read(path,maximum=8<<20,private=True):
    path=Path(path);p.need(path.is_absolute() and path.parent.resolve()==path.parent,'host_path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        a=os.fstat(stream.fileno());p.need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==os.getuid() and
            (stat.S_IMODE(a.st_mode)==0o600 if private else not stat.S_IMODE(a.st_mode)&0o022) and 0<a.st_size<=maximum,'host_file')
        raw=stream.read(maximum+1);z=os.fstat(stream.fileno());last=path.lstat()
    p.need(len(raw)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==
           (z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) and os.path.samestat(z,last),'host_file_changed')
    return raw

def directory(path):
    row=path.lstat();p.need(path.is_absolute() and path.resolve()==path and stat.S_ISDIR(row.st_mode) and
                          row.st_uid==os.getuid() and stat.S_IMODE(row.st_mode)==0o700,'private_host_directory')

def save(path,value):
    raw=p.encoded(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    with os.fdopen(fd,'wb') as out:
        os.fchmod(out.fileno(),0o600);out.write(raw);out.flush();os.fsync(out.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

@contextlib.contextmanager
def locked(path):
    directory(path);lock=path/'.schema-probe.lock'
    try:fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600);os.fchmod(fd,0o600)
    except FileExistsError:fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);p.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600,'host_lock_identity')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)

def installation(args):
    directory(args.install_staging)
    raw=read(args.install_staging/'plan.json');complete=read(args.install_staging/'complete.json')
    p.need(p.sha(raw)==args.expected_install_plan_sha256 and p.sha(complete)==args.expected_install_complete_sha256,'reviewed_install_required')
    value=p.decode(raw);done=p.decode(complete)
    p.need(done=={'operationId':value['operationId'],'complete':True,'retained':True} and
           set(value['implementationSHA256'])==set(p.INSTALL_FILES),'closed_install_required')
    sources={name:read(args.install_driver/name,256<<10,False).decode() for name in p.INSTALL_FILES}
    p.need({k:p.sha(v.encode()) for k,v in sources.items()}==value['implementationSHA256'],'install_archive_changed')
    # Validate every dependency before importing any reviewed implementation.
    spec=importlib.util.spec_from_file_location('reviewed_install_host',args.install_driver/'install-dashboard-fresh.py')
    i=importlib.util.module_from_spec(spec);spec.loader.exec_module(i);i.p.validate(value)
    sources.update({name:read(HERE/name,256<<10,False).decode() for name in p.FILES})
    return i,value,done,sources

BOOTSTRAP='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((12<<20)+1)
 if len(raw)>12<<20:raise ValueError()
 value=json.loads(raw);sources=value.pop('_sources');hashes=value.pop('_hashes')
 if set(sources)!=set(hashes):raise ValueError()
 for name,text in sources.items():
  if hashlib.sha256(text.encode()).hexdigest()!=hashes[name]:raise ValueError()
 def module(name,injected=None):
  m=types.ModuleType(name);m.__file__='/reviewed/'+name+'.py';m.__dict__.update(injected or {})
  exec(compile(sources[name+'.py'],'reviewed-'+name,'exec'),m.__dict__);return m
 b=module('dashboard-dependency-fault-plan');s=module('dashboard-split-plan')
 f=module('dashboard-dependency-fault-guest',{'p':b})
 up=module('dashboard-control-upgrade-plan',{'b':b});u=module('dashboard-control-upgrade-guest',{'p':up,'f':f})
 ip=module('dashboard-install-plan',{'b':b,'s':s});g=module('dashboard-install-guest',{'p':ip,'f':f,'u':u})
 p=module('dashboard-schema-probe-plan')
 if set(sources)!=set(p.FILES+p.INSTALL_FILES):raise ValueError()
 z=module('dashboard-schema-probe-guest',{'p':p,'g':g,'f':f,'u':u,'b':b})
 result=z.execute(value);print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','schema_probe_failed')
 if not isinstance(code,str) or not __import__('re').fullmatch('[a-z][a-z0-9_]{0,63}',code):code='schema_probe_failed'
 print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''

def remote(args,i,sources,payload):
    p.need(payload['host'] in i.h.HOSTS and payload['phase'] in ('snapshot','preserved','state','empty','artifacts','observe',*p.PHASES),'remote_scope')
    hashes={k:p.sha(v.encode()) for k,v in sources.items()}
    if 'plan' in payload:p.need(hashes==payload['plan']['implementationSHA256'],'probe_implementation_changed')
    body=p.encoded(dict(payload,_sources=sources,_hashes=hashes));p.need(len(body)<=12<<20,'payload_bound')
    raw=i.f.run(i.h.ssh_args(args.lab_root,payload['host'])+[shlex.join(['sudo','python3','-c',BOOTSTRAP])],
                'schema_probe_remote',data=body,timeout=135,maximum=2<<20)
    value=p.decode(raw);code=value.get('code','schema_probe_failed')
    p.need(value.get('ok') is True,code if isinstance(code,str) and p.re.fullmatch('[a-z][a-z0-9_]{0,63}',code) else 'schema_probe_failed')
    return value['result']

def current(args,i,sources,plan,phase,host):return remote(args,i,sources,{'plan':plan,'phase':phase,'host':host})

def snapshot(args,i,install,sources):
    value={host:remote(args,i,sources,{'host':host,'phase':'snapshot','install':install}) for host in i.h.HOSTS}
    save(args.staging/'snapshot.json',value);return {'snapshotSHA256':p.sha(p.encoded(value)),'mutations':False}

def prepare(args,i,install,complete,sources):
    p.need(args.selected in ('baseline','upgrade'),'selected_candidate')
    candidate=install['candidates'][args.selected]
    metadata,files=i.p.s.candidate_files(args.candidate_archive,candidate['archiveSHA256'])
    p.need(metadata['revision']==candidate['revision'] and
           {n:{'bytes':len(v),'sha256':p.sha(v)} for n,v in files.items()}==candidate['files'],'candidate_archive_changed')
    generator=args.staging/'grant-generator';i.h.directory(generator,create=True)
    for name in ('grants.py','grants.json'):i.f.put(generator/name,files['deploy/postgres/'+name])
    grants={r:i.f.run([sys.executable,str(generator/'grants.py'),'--schema','public','--role',p.ROLES[r],
            *[v for c in p.COMPONENTS[r] for v in ('--component',c)]],'render_probe_grants',maximum=256<<10) for r in p.COMPONENTS}
    keys={r:os.urandom(32).hex().encode() for r in p.ROLES}
    plan=p.validate({'format':1,'synthetic':True,'operationId':str(uuid.uuid4()),'createdAt':int(time.time()),
         'install':install,'installComplete':complete,'selected':args.selected,'snapshot':p.decode(read(args.staging/'snapshot.json')),
         'configs':p.configs(install,args.selected),'implementationSHA256':{k:p.sha(v.encode()) for k,v in sources.items()},
         'secretSHA256':{r:p.sha(v) for r,v in keys.items()},'grantSHA256':{r:p.sha(v) for r,v in grants.items()}})
    save(args.staging/'plan.json',plan)
    save(args.staging/'secrets.json',{r:base64.b64encode(v).decode() for r,v in keys.items()})
    save(args.staging/'grants.json',{r:base64.b64encode(v).decode() for r,v in grants.items()})
    result={'operationId':plan['operationId'],'planSHA256':p.sha(p.encoded(plan)),
            'implementationSHA256':p.sha(p.encoded(plan['implementationSHA256'])),'database':p.DATABASE,
            'candidate':candidate['revision'],'schema':18,'newMarker':p.FUTURE,'applied':False}
    save(args.staging/'review.json',result);return result

def receipt(args,plan,phase):
    value=p.decode(read(args.staging/(phase+'.json')))
    p.need(value.get('phase')==phase and value.get('completed') is True and value.get('operationId')==plan['operationId'] and
           value.get('planSHA256')==p.sha(p.encoded(plan)),'previous_completion_required');return value

def run_phase(args,i,install,sources):
    raw=read(args.staging/'plan.json');plan=p.validate(p.decode(raw))
    p.need(p.sha(raw)==args.expected_plan_sha256 and plan['install']==install and
           p.sha(p.encoded(plan['implementationSHA256']))==args.expected_implementation_sha256 and
           {k:p.sha(v.encode()) for k,v in sources.items()}==plan['implementationSHA256'],'reviewed_probe_required')
    for host in i.h.HOSTS:current(args,i,sources,plan,'preserved',host)
    if args.phase=='verify':
        receipt(args,plan,'refuse');expected=receipt(args,plan,'future')['state']
        actual=current(args,i,sources,plan,'state','pg01');p.need(actual==expected,'refused_database_changed')
        artifacts=current(args,i,sources,plan,'artifacts','storage01')
        p.need(p.sha(p.encoded(artifacts))==receipt(args,plan,'refuse')['artifactsSHA256'],'refused_artifacts_changed')
        result={'complete':True,'operationId':plan['operationId'],'databaseUnchanged':True,'artifactsUnchanged':True,
                'refusal':receipt(args,plan,'refuse')['processes'],'ledgerSHA256':p.sha(p.encoded(actual['ledger']))}
        save(args.staging/'complete.json',result);return result
    phase=args.observed_phase if args.phase=='observe' else args.phase
    p.need(phase in p.PHASES,'probe_phase');order=list(p.PHASES)
    if args.phase!='observe':
        p.need(args.apply,'explicit_apply_required')
        if phase=='database':p.need(0<=time.time()-plan['createdAt']<=3600,'plan_expired')
        else:receipt(args,plan,order[order.index(phase)-1])
        if phase=='migrate':p.need(current(args,i,sources,plan,'empty','pg01')=={'empty':True},'empty_probe_required')
        if phase in ('positive','future'):p.need(current(args,i,sources,plan,'state','pg01')==receipt(args,plan,'grants')['state'],'positive_database_changed')
        if phase=='refuse':p.need(current(args,i,sources,plan,'state','pg01')==receipt(args,plan,'future')['state'],'future_database_changed')
    pending=args.staging/(phase+'.pending.json')
    if args.phase=='observe':p.need(p.decode(read(pending))=={'phase':phase,'operationId':plan['operationId'],'planSHA256':p.sha(raw)},'phase_not_admitted')
    else:save(pending,{'phase':phase,'operationId':plan['operationId'],'planSHA256':p.sha(raw)})
    payload={'plan':plan,'phase':args.phase,'host':p.PHASES[phase],'apply':args.apply}
    if args.phase=='observe':payload['observedPhase']=phase
    if phase in ('database','material'):payload['secrets']=p.decode(read(args.staging/'secrets.json',8192))
    if phase=='grants':payload['grants']=p.decode(read(args.staging/'grants.json',1<<20))
    result=remote(args,i,sources,payload)
    p.need(result.get('completed') is True and result.get('phase')==phase and result.get('operationId')==plan['operationId'] and
           result.get('planSHA256')==p.sha(raw),'phase_completion_invalid')
    for host in i.h.HOSTS:current(args,i,sources,plan,'preserved',host)
    if args.phase=='observe' and (args.staging/(phase+'.json')).exists():
        p.need(receipt(args,plan,phase)==result,'completion_receipt_drift')
    else:save(args.staging/(phase+'.json'),result)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('snapshot','prepare',*p.PHASES,'observe','verify'))
    for name in ('lab-root','install-driver','install-staging','staging'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('expected-install-plan-sha256','expected-install-complete-sha256'):parser.add_argument('--'+name,required=True)
    for name in ('expected-plan-sha256','expected-implementation-sha256'):parser.add_argument('--'+name)
    parser.add_argument('--selected',choices=('baseline','upgrade'));parser.add_argument('--candidate-archive',type=Path)
    parser.add_argument('--observed-phase',choices=tuple(p.PHASES));parser.add_argument('--apply',action='store_true')
    args=parser.parse_args();os.umask(0o077)
    try:
        p.need(args.staging.parent==Path('/private/tmp') and args.staging.name.startswith('jobman-schema-probe-'),'private_probe_root')
        with locked(args.staging):
            i,install,complete,sources=installation(args)
            if args.phase=='snapshot':result=snapshot(args,i,install,sources)
            elif args.phase=='prepare':result=prepare(args,i,install,complete,sources)
            else:result=run_phase(args,i,install,sources)
        print(p.encoded({'ok':True,'result':result}).decode(),end='')
    except Exception as error:
        code=getattr(error,'code','schema_probe_failed')
        if not isinstance(code,str) or not p.re.fullmatch('[a-z][a-z0-9_]{0,63}',code):code='schema_probe_failed'
        print(p.encoded({'ok':False,'code':code}).decode(),end='');return 1
    return 0

if __name__=='__main__':sys.exit(main())
