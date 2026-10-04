#!/usr/bin/env python3
"""Prepare, arm once, and observe a genuine timer-owned primary restart."""
import argparse
import importlib.util
import os
from pathlib import Path
import secrets
import shlex
import sys
import time

HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
p=load('watchdog_plan',HERE/'dashboard-watchdog-plan.py')
h=load('reviewed_fault_host',HERE/'dashboard-dependency-faults.py')


def implementation():return {name:p.sha(h.read(HERE/name,256<<10,False)) for name in p.FILES+p.DEPS}
def sources(hashes):
    values={name:h.read(HERE/name,256<<10,False).decode() for name in p.FILES[:2]+p.DEPS[:3]}
    p.need(all(p.sha(text.encode())==hashes[name] for name,text in values.items()),'implementation_changed');return values

BOOTSTRAP="""import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((2<<20)+1)
 if len(raw)>2<<20:raise ValueError()
 envelope=json.loads(raw);sources=envelope['sources'];hashes=envelope['hashes']
 if set(sources)!=set(hashes):raise ValueError()
 for name,text in sources.items():
  if hashlib.sha256(text.encode()).hexdigest()!=hashes[name]:raise ValueError()
 p=types.ModuleType('watchdog_plan')
 exec(compile(sources['dashboard-watchdog-plan.py'],'reviewed-plan','exec'),p.__dict__)
 exec(compile(p.loader(sources),'reviewed-loader','exec'),{'__name__':'reviewed','_REQUEST':envelope['request']})
except Exception:
 print(json.dumps({'ok':False,'code':'bootstrap_failed'}));sys.exit(1)
"""

def remote(lab,value,hashes):
    p.need(value['phase'] in ('snapshot','stage','begin','status','observe','verify','accept'),'phase_denied')
    src=sources(hashes)
    body=p.encoded({'request':value,'sources':src,'hashes':{n:hashes[n] for n in src}})
    p.need(len(body)<=2<<20,'request_bound')
    raw=h.g.run(h.ssh_args(lab,value['host'])+[shlex.join(['sudo','python3','-c',BOOTSTRAP])],
                'watchdog_remote',data=body,timeout=100 if value['phase']=='begin' else 55,maximum=2<<20)
    result=p.decode(raw);p.need(result.get('ok') is True,'guest_failed');return result['result']

def no_other_operations(lab):
    directory=lab/'.lab/dashboard/dependency-fault-operations'
    if directory.exists():
        h.directory(directory);entries=list(directory.iterdir());p.need(len(entries)<=128,'operation_bound')
        for entry in entries:
            h.directory(entry);p.need((entry/'complete.json').exists(),'another_fault_pending')

def read_plan(args):
    h.directory(args.staging);raw=h.read(args.staging/'plan.json');plan=p.validate(p.decode(raw));hashes=implementation()
    p.need(p.sha(raw)==args.expected_plan_sha256 and hashes==plan['implementationSHA256'] and
           p.sha(p.encoded(hashes))==args.expected_implementation_sha256,'reviewed_plan_required')
    return plan,hashes

def verify_external(args,plan,hashes):
    for host in ('control01','pg01'):
        result=remote(args.lab_root,{'phase':'verify','host':host,'plan':plan},hashes)
        p.need(result=={'host':host,'preserved':True},'external_state_changed')

def phase(args):
    if args.phase=='snapshot':
        p.need(p.REV.fullmatch(args.revision or '') and p.HEX.fullmatch(args.binary_sha256 or ''),'candidate_pin')
        candidate={'revision':args.revision,'binarySHA256':args.binary_sha256};hashes=implementation()
        no_other_operations(args.lab_root)
        value={host:remote(args.lab_root,{'phase':'snapshot','host':host,'candidate':candidate},hashes) for host in p.HOSTS}
        h.save(args.output,value);return {'snapshotSHA256':p.sha(p.encoded(value)),'guestMutation':False}
    if args.phase=='prepare':
        snap=p.decode(h.read(args.snapshot));hashes=implementation()
        plan=p.validate({'format':1,'synthetic':True,'scenario':p.SCENARIO,'operationId':secrets.token_hex(32),'createdAt':int(time.time()),
             'candidate':{'revision':args.revision,'binarySHA256':args.binary_sha256},'snapshot':snap,'implementationSHA256':hashes})
        h.p.stable_database(snap['pg01']['database'])
        h.directory(args.staging,create=True);h.save(args.staging/'plan.json',plan)
        result={'operationId':plan['operationId'],'planSHA256':p.sha(p.encoded(plan)),
                'implementationSHA256':p.sha(p.encoded(hashes)),'scenario':p.SCENARIO,'watchdogSeconds':150,
                'hostRestartAllowed':False,'cloneOrRestore':False,'applied':False}
        h.save(args.staging/'review.json',result);return result
    plan,hashes=read_plan(args)
    request={'phase':args.phase,'host':'storage01','plan':plan,'apply':args.apply}
    if args.phase in ('stage','begin'):
        p.need(args.apply,'explicit_apply_required');no_other_operations(args.lab_root)
        p.need(0<=time.time()-min(v['observedAt'] for v in plan['snapshot'].values())<=900,'plan_expired')
        pending=args.staging/(args.phase+'.pending.json');p.need(not pending.exists(),'uncertain_phase_no_retry')
        if args.phase=='begin':
            p.need(p.decode(h.read(args.staging/'stage.json'))=={'staged':True,'operationId':plan['operationId']},'stage_missing')
        verify_external(args,plan,hashes)
        h.save(pending,{'operationId':plan['operationId'],'planSHA256':args.expected_plan_sha256})
        value=remote(args.lab_root,request,hashes);h.save(args.staging/(args.phase+'.json'),value);return value
    p.need(args.phase in ('status','observe','verify','close'),'phase_denied')
    if args.phase=='status':return remote(args.lab_root,request,hashes)
    request['phase']='observe';value=remote(args.lab_root,request,hashes);p.restarted(plan,value['receipt'])
    if args.phase in ('verify','close'):
        verify_external(args,plan,hashes)
        if args.phase=='close':
            p.need(args.apply,'explicit_apply_required')
            # Invoked by the HTTP harness ONLY after same-credential checks.
            value=remote(args.lab_root,dict(request,phase='accept',apply=True),hashes)
        h.save(args.staging/(args.phase+'.json'),value)
    return value

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('snapshot','prepare','stage','begin','status','observe','verify','close'))
    parser.add_argument('--lab-root',type=Path,required=True);parser.add_argument('--staging',type=Path)
    parser.add_argument('--snapshot',type=Path);parser.add_argument('--output',type=Path)
    parser.add_argument('--revision');parser.add_argument('--binary-sha256')
    parser.add_argument('--expected-plan-sha256');parser.add_argument('--expected-implementation-sha256');parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    p.need(args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'lab_root')
    for path in (args.staging,args.snapshot,args.output):
        if path is not None:p.need(path.is_absolute() and str(path).startswith('/private/tmp/') and path.parent.resolve()==path.parent,'private_host_path')
    with h.locked(args.lab_root):value=phase(args)
    sys.stdout.buffer.write(p.encoded(value))

if __name__=='__main__':
    try:main()
    except Exception:
        print('Watchdog acceptance stopped; retain pending timer and receipts; no automatic restart or retry.',file=sys.stderr)
        raise SystemExit(1) from None
