#!/usr/bin/env python3
"""Prepare and execute reviewed, one-source-at-a-time Control binary upgrades."""
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
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
p=load('dashboard-control-upgrade-plan');h=load('dashboard-dependency-faults');f=h.g
PHASES=('snapshot','prepare','stage','apply','restart','observe','verify')


@contextlib.contextmanager
def locked(lab):
    parent=lab/'.lab/dashboard';h.directory(parent)
    path=parent/'.control-binary-upgrade.lock'
    try:fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600);os.fchmod(fd,0o600)
    except FileExistsError:fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        value=os.fstat(fd);p.need(stat.S_ISREG(value.st_mode) and value.st_nlink==1 and value.st_uid==os.getuid() and stat.S_IMODE(value.st_mode)==0o600,'host_lock_identity')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)


def implementation():return {name:p.sha(h.read(HERE/name,256<<10,False)) for name in p.FILES}


BOOTSTRAP='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((90<<20)+1)
 if len(raw)>90<<20:raise ValueError()
 value=json.loads(raw);sources=value.pop('_sources');hashes=value.pop('_hashes')
 names={'dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py','dashboard-control-upgrade-plan.py','dashboard-control-upgrade-guest.py'}
 if set(sources)!=names or set(hashes)!=names:raise ValueError()
 for name,text in sources.items():
  if hashlib.sha256(text.encode()).hexdigest()!=hashes[name]:raise ValueError()
 base=types.ModuleType('fault_plan');exec(compile(sources['dashboard-dependency-fault-plan.py'],'reviewed-base','exec'),base.__dict__)
 old=types.ModuleType('fault_guest');old.__file__='/reviewed/dashboard-dependency-fault-guest.py';old.p=base
 exec(compile(sources['dashboard-dependency-fault-guest.py'],'reviewed-primitives','exec'),old.__dict__)
 plan=types.ModuleType('upgrade_plan');plan.__file__='/reviewed/dashboard-control-upgrade-plan.py';plan.b=base
 exec(compile(sources['dashboard-control-upgrade-plan.py'],'reviewed-plan','exec'),plan.__dict__)
 space={'__name__':'reviewed_guest','__file__':'/reviewed/dashboard-control-upgrade-guest.py','p':plan,'f':old}
 exec(compile(sources['dashboard-control-upgrade-guest.py'],'reviewed-guest','exec'),space)
 result=space['execute'](value);print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','source_upgrade_failed')
 print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''


def remote(lab,payload,hashes):
    p.need(payload.get('host') in h.HOSTS and payload.get('phase') in ('snapshot','authority','stage','apply','restart','observe','verify'),'remote_phase_boundary')
    names=('dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py','dashboard-control-upgrade-plan.py','dashboard-control-upgrade-guest.py')
    sources={name:h.read(HERE/name,256<<10,False).decode() for name in names}
    p.need(all(p.sha(raw.encode())==hashes[name] for name,raw in sources.items()),'reviewed_implementation_changed')
    raw=p.encoded(dict(payload,_sources=sources,_hashes={n:hashes[n] for n in names}))
    p.need(len(raw)<=90<<20,'remote_input_bound')
    answer=p.decode(f.run(h.ssh_args(lab,payload['host'])+[shlex.join(['sudo','python3','-c',BOOTSTRAP])],
                        'source_upgrade_'+payload['phase'],data=raw,timeout=175 if payload['phase']=='restart' else 75,maximum=4<<20))
    p.need(answer.get('ok') is True,answer.get('code') if p.re.fullmatch('[a-z][a-z0-9_]{0,63}',str(answer.get('code',''))) else 'source_upgrade_failed')
    return answer['result']


def schema_manifest(repository,revision):
    p.need(repository.is_absolute() and repository.resolve()==repository and revision in (p.OLD,p.NEW,p.RUNS_NEW),'source_repository')
    root='internal/store/postgres/migrations/'
    names=f.run(['git','-C',str(repository),'ls-tree','-r','--name-only',revision,'--',root],'migration_tree',maximum=8192).decode().splitlines()
    p.need(len(names)==21 and all(name.startswith(root) and p.re.fullmatch(r'[0-9]{6}_[a-z_]+\.sql',name[len(root):]) for name in names),'migration_tree_shape')
    values=[]
    for name in sorted(names):
        raw=f.run(['git','-C',str(repository),'show',revision+':'+name],'migration_read',maximum=1<<20)
        # Control's migrate.go uses path.Base(name), unlike Dashboard's ledger.
        values.append({'name':Path(name).name,'sha256':p.sha(raw)})
    return values


def snapshot(args):
    p.need(args.profile in p.PROFILES and p.REVISION.fullmatch(args.dashboard_revision or ''),'snapshot_identity')
    p.transition(args.transition)
    hashes=implementation();value={host:remote(args.lab_root,{'phase':'snapshot','host':host,'profile':args.profile,'dashboardRevision':args.dashboard_revision,**({'transition':args.transition} if args.transition!=p.DEFAULT_TRANSITION else {})},hashes) for host in h.HOSTS}
    h.save(args.output,value);return {'snapshotSHA256':p.sha(p.encoded(value)),'mutations':False}


def prepare(args):
    p.need(args.profile in p.PROFILES and args.build.is_absolute() and args.build.resolve()==args.build and
           args.go.is_absolute() and args.go.is_file(),'prepare_inputs')
    metadata=p.decode(h.read(args.build/'build-receipt.json',65536,False));binary=h.read(args.build/'jobman-control-1',64<<20,False)
    p.need(binary==h.read(args.build/'jobman-control-2',64<<20,False),'double_build_differs')
    information=f.run([str(args.go),'version','-m',str(args.build/'jobman-control-1')],'candidate_build_information',timeout=10,maximum=65536).decode()
    selected=p.transition(args.transition);candidate=p.candidate(metadata,binary,information,args.transition)
    ledger=schema_manifest(args.control_root,selected['old']);p.need(ledger==schema_manifest(args.control_root,selected['new']),'migration_change_forbidden')
    hashes=implementation();plan=p.make(p.decode(h.read(args.snapshot,4<<20)),args.profile,candidate,ledger,hashes,str(uuid.uuid4()),int(time.time()),args.transition)
    p.validate(plan);h.directory(args.staging,create=True)
    h.save(args.staging/'plan.json',plan)
    # Stage uses the reviewed original artifact and verifies it anew; no secret
    # or binary body is embedded into the human-readable review receipt.
    h.save(args.staging/'build-path.json',{'binary':str(args.build/'jobman-control-1')})
    review={'planSHA256':p.sha(p.encoded(plan)),'implementationSHA256':p.sha(p.encoded(hashes)),
            'profile':args.profile,'operationId':plan['operationId'],'candidate':candidate,
            'beforeUnitSHA256':plan['beforeUnitSHA256'],'afterUnitSHA256':plan['afterUnitSHA256'],
            'unitChange':'one ExecStart binary path','schema':'same 21 migrations; no migration command','applied':False}
    h.save(args.staging/'review.json',review);return review


def load_plan(args):
    h.directory(args.staging);raw=h.read(args.staging/'plan.json',4<<20);plan=p.decode(raw);p.validate(plan)
    p.need(plan.get('transition',p.DEFAULT_TRANSITION)==args.transition,'reviewed_transition_required')
    hashes=implementation();p.need(p.sha(raw)==args.expected_plan_sha256 and p.sha(p.encoded(hashes))==args.expected_implementation_sha256 and hashes==plan['implementationSHA256'],'reviewed_plan_required')
    return plan,hashes


def operation(args,plan,admit=False):
    parent=args.lab_root/'.lab/dashboard/control-binary-upgrades'
    if not parent.exists():h.directory(parent,create=True)
    h.directory(parent);entries=list(parent.iterdir());p.need(len(entries)<64,'operation_history_bound')
    for entry in entries:
        h.directory(entry)
        if entry.name!=plan['operationId']:p.need((entry/'verified.json').exists(),'another_source_upgrade_pending')
    root=parent/plan['operationId']
    if not root.exists():p.need(admit,'operation_not_admitted');h.directory(root,create=True)
    h.save(root/'intent.json',{'planSHA256':args.expected_plan_sha256,'staging':str(args.staging),'profile':plan['profile']})
    return root


def phase(args):
    plan,hashes=load_plan(args);payload={'phase':args.phase,'host':'control01','plan':plan,'planSHA256':args.expected_plan_sha256,'apply':args.apply}
    p.need(args.phase in ('stage','apply','restart','observe','verify'),'phase_not_allowed')
    if args.phase in ('stage','apply','restart'):p.need(args.apply,'explicit_apply_required')
    # The immutable SQL authority and unrelated host must pass before a write;
    # feed counters alone may advance monotonically.
    for host in ('pg01','storage01'):remote(args.lab_root,dict(payload,phase='authority',host=host),hashes)
    root=operation(args,plan,admit=args.phase=='stage')
    if args.phase in ('stage','apply','restart'):
        previous={'apply':'stage','restart':'apply'}.get(args.phase)
        if previous:
            expected={'stage':{'staged':True,'operationId':plan['operationId'],'candidateSHA256':plan['candidate']['sha256']},
                      'apply':{'applied':True,'operationId':plan['operationId'],'unitSHA256':plan['afterUnitSHA256']}}[previous]
            p.need(p.decode(h.read(args.staging/(previous+'.json')))==expected,'previous_phase_unconfirmed')
        pending=args.staging/(args.phase+'.pending.json')
        p.need(not pending.exists(),'uncertain_mutation_requires_observation')
        if args.phase=='stage':
            path=Path(p.decode(h.read(args.staging/'build-path.json'))['binary']);binary=h.read(path,64<<20,False)
            p.need(p.sha(binary)==plan['candidate']['sha256'] and len(binary)==plan['candidate']['bytes'],'candidate_input_changed')
            payload['binary']=base64.b64encode(binary).decode()
        h.save(pending,{'planSHA256':args.expected_plan_sha256,'phase':args.phase})
    result=remote(args.lab_root,payload,hashes)
    if args.phase=='observe':
        completed=[name for name,flag in (('stage','staged'),('apply','applied'),('restart','restarted')) if result.get(flag) is True]
        p.need(len(completed)==1 and result.get('operationId')==plan['operationId'],'observed_phase_invalid')
        name=completed[0]
        p.need((args.staging/(name+'.pending.json')).exists(),'observed_phase_not_admitted')
        h.save(args.staging/(name+'.json'),result)
    else:h.save(args.staging/(args.phase+'.json'),result)
    if args.phase=='verify':
        for host in ('pg01','storage01'):remote(args.lab_root,dict(payload,phase='authority',host=host),hashes)
        p.need(result=={'verified':True,'operationId':plan['operationId'],'candidateSHA256':plan['candidate']['sha256']},'verification_receipt')
        h.save(root/'verified.json',result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=PHASES)
    parser.add_argument('--lab-root',type=Path,required=True);parser.add_argument('--profile',choices=p.PROFILES)
    for name in ('staging','snapshot','output','build','control-root','go'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--transition',choices=p.TRANSITIONS,default=p.DEFAULT_TRANSITION)
    parser.add_argument('--dashboard-revision');parser.add_argument('--expected-plan-sha256');parser.add_argument('--expected-implementation-sha256');parser.add_argument('--apply',action='store_true')
    args=parser.parse_args();p.need(args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'lab_root')
    with locked(args.lab_root):result=snapshot(args) if args.phase=='snapshot' else prepare(args) if args.phase=='prepare' else phase(args)
    sys.stdout.buffer.write(p.encoded(result))


if __name__=='__main__':
    try:main()
    except Exception as error:
        code=getattr(error,'code','source_upgrade_failed')
        print('Control upgrade stopped ('+code+'); preserve receipts; do not repeat an uncertain mutation.',file=sys.stderr)
        raise SystemExit(1) from None
