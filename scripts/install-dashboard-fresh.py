#!/usr/bin/env python3
"""Offline prepare, then explicit receipt-bound disposable installation phases."""
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

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
p = load('dashboard-install-plan'); h = load('dashboard-dependency-faults'); f = h.g
PHASES = ('snapshot','prepare',*p.ORDER,'observe','data','verify','close')


@contextlib.contextmanager
def locked(lab):
    parent = lab/'.lab/dashboard'; h.directory(parent)
    path = parent/'.fresh-install.lock'
    try: fd = os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600); os.fchmod(fd,0o600)
    except FileExistsError: fd = os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        p.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
               stat.S_IMODE(info.st_mode) == 0o600,'host_lock_identity')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); yield
    finally: os.close(fd)


def implementation(): return {name:p.sha(h.read(HERE/name,256<<10,False)) for name in p.FILES}


REMOTE_NAMES = ('dashboard-split-plan.py','dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py',
                'dashboard-control-upgrade-plan.py','dashboard-control-upgrade-guest.py','dashboard-install-plan.py','dashboard-install-guest.py')
BOOTSTRAP = '''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((360<<20)+1)
 if len(raw)>360<<20:raise ValueError()
 value=json.loads(raw);sources=value.pop('_sources');hashes=value.pop('_hashes')
 names={'dashboard-split-plan.py','dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py','dashboard-control-upgrade-plan.py','dashboard-control-upgrade-guest.py','dashboard-install-plan.py','dashboard-install-guest.py'}
 if set(sources)!=names or set(hashes)!=names:raise ValueError()
 for name,text in sources.items():
  if hashlib.sha256(text.encode()).hexdigest()!=hashes[name]:raise ValueError()
 def module(name, injected=None):
  m=types.ModuleType(name);m.__file__='/reviewed/'+name+'.py';m.__dict__.update(injected or {})
  exec(compile(sources[name+'.py'],'reviewed-'+name,'exec'),m.__dict__);return m
 b=module('dashboard-dependency-fault-plan');s=module('dashboard-split-plan')
 f=module('dashboard-dependency-fault-guest',{'p':b})
 up=module('dashboard-control-upgrade-plan',{'b':b});u=module('dashboard-control-upgrade-guest',{'p':up,'f':f})
 p=module('dashboard-install-plan',{'b':b,'s':s});g=module('dashboard-install-guest',{'p':p,'f':f,'u':u})
 result=g.execute(value);print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','fresh_install_failed')
 print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''


def remote(lab,payload,hashes):
    allowed = {'snapshot','preserved','data','ledger','empty-schema','observe',*p.ORDER}
    p.need(payload.get('phase') in allowed and payload.get('host') in h.HOSTS,'remote_boundary')
    sources = {name:h.read(HERE/name,256<<10,False).decode() for name in REMOTE_NAMES}
    p.need(all(p.sha(value.encode()) == hashes[name] for name,value in sources.items()),'implementation_changed')
    body = p.encoded(dict(payload,_sources=sources,_hashes={name:hashes[name] for name in sources}))
    p.need(len(body) <= 360<<20,'remote_input_bound')
    timeout = 270 if payload['phase'] in ('baseline','upgrade','rollback') else 170
    raw = f.run(h.ssh_args(lab,payload['host'])+[shlex.join(['sudo','python3','-c',BOOTSTRAP])],
                'install_remote_'+payload['phase'].replace('-','_'),data=body,timeout=timeout,maximum=8<<20)
    value = p.decode(raw)
    code = value.get('code','')
    p.need(value.get('ok') is True,code if isinstance(code,str) and p.re.fullmatch('[a-z][a-z0-9_]{0,63}',code) else 'fresh_install_failed')
    return value['result']


def schema(repository, revision):
    p.need(repository.is_absolute() and repository.resolve() == repository and p.s.REVISION.fullmatch(revision),'source_repository')
    # The fixed confirmed output-bound repair must be in BOTH tested packages.
    f.run(['git','-C',str(repository),'merge-base','--is-ancestor',p.FIX,revision],'candidate_predates_output_fix',maximum=1024)
    prefix = 'internal/store/migrations/'
    names = f.run(['git','-C',str(repository),'ls-tree','-r','--name-only',revision,'--',prefix],'migration_tree',maximum=8192).decode().splitlines()
    p.need(len(names) == 18 and all(name.startswith(prefix) for name in names),'migration_count')
    return p.ledger([{'name':'migrations/'+Path(name).name,
                      'sha256':p.sha(f.run(['git','-C',str(repository),'show',revision+':'+name],'migration_content',maximum=1<<20))}
                     for name in sorted(names)])


def snapshot(args):
    p.need(p.s.REVISION.fullmatch(args.revision or ''),'snapshot_revision')
    hashes = implementation()
    value = {host:remote(args.lab_root,{'phase':'snapshot','host':host,'revision':args.revision},hashes) for host in h.HOSTS}
    h.save(args.output,value); return {'snapshotSHA256':p.sha(p.encoded(value)),'mutations':False}


def prepare(args):
    review = p.decode(h.read(args.reviewed_pair,65536))
    p.need(set(review) == {'baseline','upgrade'} and all(set(v) == {'revision','archiveSHA256','reviewEvidence','ciEvidence'} and
           p.s.REVISION.fullmatch(v['revision']) and p.s.HEX.fullmatch(v['archiveSHA256']) and
           all(isinstance(v[k],str) and 1 <= len(v[k]) <= 2048 for k in ('reviewEvidence','ciEvidence')) for v in review.values()),
           'independent_pair_review_required')
    candidates, packages, units = {}, {}, {}
    for selected,path in [('baseline',args.baseline_archive),('upgrade',args.upgrade_archive)]:
        metadata,files = p.s.candidate_files(path,review[selected]['archiveSHA256'])
        p.need(metadata['revision'] == review[selected]['revision'],'reviewed_candidate_revision')
        candidates[selected] = p.package(metadata,files,review[selected]['archiveSHA256'],schema(args.dashboard_root,metadata['revision']))
        packages[selected] = files
        units[selected] = {role:base64.b64encode(p.unit(role,candidates[selected],files['deploy/systemd/jobman-dashboard-'+role+'.service'])).decode() for role in p.USERS}
    p.pair(candidates)
    p.need(all(packages['baseline'][name] == packages['upgrade'][name] for name in ('deploy/postgres/grants.py','deploy/postgres/grants.json')),
           'grant_change_requires_different_review')
    h.directory(args.staging,create=True)
    generator = args.staging/'grant-generator'; h.directory(generator,create=True)
    for name in ('grants.py','grants.json'): f.put(generator/name,packages['baseline']['deploy/postgres/'+name])
    grants = {role:f.run([sys.executable,str(generator/'grants.py'),'--schema','public','--role',p.ROLES[role],
                          *[part for component in p.COMPONENTS[role] for part in ('--component',component)]],
                         'render_install_grants',maximum=256<<10) for role in ('api','worker','operator')}
    secrets = {name:os.urandom(32) if name in ('auth','policy','cursor') else os.urandom(32).hex().encode()
               for name in ('auth','policy','cursor','web','ddl','api','worker','operator')}
    hashes = implementation()
    plan = p.make(p.decode(h.read(args.snapshot,8<<20)),candidates,units,hashes,str(uuid.uuid4()),int(time.time()),
                  {k:p.sha(v) for k,v in secrets.items()},{k:p.sha(v) for k,v in grants.items()})
    p.validate(plan)
    for name,value in [('plan',plan),('secrets',{k:base64.b64encode(v).decode() for k,v in secrets.items()}),
                       ('grant-sql',{k:base64.b64encode(v).decode() for k,v in grants.items()}),
                       ('package-paths',{'baseline':str(args.baseline_archive),'upgrade':str(args.upgrade_archive)}),('pair-review',review)]:
        h.save(args.staging/(name+'.json'),value)
    result = {'planSHA256':p.sha(p.encoded(plan)),'implementationSHA256':p.sha(p.encoded(hashes)),
              'operationId':plan['operationId'],'database':p.DATABASE,'publicOrigin':p.ORIGIN,'postFixRevision':p.FIX,
              'candidates':{k:{field:v[field] for field in ('revision','version','archiveSHA256')} for k,v in candidates.items()},
              'schema':'fresh0-to18 then identical18 upgrade/rollback','applied':False}
    h.save(args.staging/'review.json',result); return result


def load_plan(args):
    h.directory(args.staging); raw = h.read(args.staging/'plan.json',8<<20); plan = p.decode(raw); p.validate(plan)
    hashes = implementation()
    p.need(p.sha(raw) == args.expected_plan_sha256 and p.sha(p.encoded(hashes)) == args.expected_implementation_sha256 and
           hashes == plan['implementationSHA256'],'reviewed_plan_required')
    return plan,hashes


def receipt(args,plan,name):
    value = p.decode(h.read(args.staging/(name+'.json'),8<<20))
    p.need(value.get('phase') == name and value.get('operationId') == plan['operationId'] and value.get('completed') is True and
           value.get('planSHA256') == args.expected_plan_sha256,'previous_completion_required')
    return value


def authority(args,plan,hashes):
    for host in h.HOSTS: remote(args.lab_root,{'phase':'preserved','host':host,'plan':plan},hashes)


def data(args,plan,hashes): return remote(args.lab_root,{'phase':'data','host':'pg01','plan':plan},hashes)


def phase(args):
    plan,hashes = load_plan(args); phase = args.phase
    authority(args,plan,hashes)
    if phase == 'data': return data(args,plan,hashes)
    if phase == 'verify':
        p.need(args.selected in ('baseline','upgrade','rollback'),'selected_acceptance')
        receipt(args,plan,args.selected)
        state = data(args,plan,hashes)
        if args.selected == 'baseline': h.save(args.staging/'retained-baseline.json',state)
        else:
            old = p.decode(h.read(args.staging/'retained-baseline.json',65536))
            p.need(state == old,'retained_state_changed')
        h.save(args.staging/('verified-'+args.selected+'.json'),{'verified':True,'operationId':plan['operationId'],'dataSHA256':p.sha(p.encoded(state))})
        return {'verified':True,'selected':args.selected,'dataSHA256':p.sha(p.encoded(state))}
    if phase == 'close':
        receipt(args,plan,'stop'); receipt(args,plan,'retire-identity')
        for closed in ('stop','retire-identity'):
            payload = {'phase':'observe','observedPhase':closed,'host':p.PHASE_HOST[closed],'plan':plan}
            if closed == 'retire-identity': payload['secrets'] = p.decode(h.read(args.staging/'secrets.json',16384))
            observed = remote(args.lab_root,payload,hashes)
            p.need(observed == receipt(args,plan,closed), 'closure_observation_differs')
        for selected in ('baseline','upgrade','rollback'):
            v = p.decode(h.read(args.staging/('verified-'+selected+'.json')))
            p.need(v.get('verified') is True and v.get('operationId') == plan['operationId'],'acceptance_incomplete')
        h.save(args.staging/'complete.json',{'operationId':plan['operationId'],'complete':True,'retained':True})
        return {'complete':True,'retained':True}
    actual = args.observed_phase if phase == 'observe' else phase
    p.need(actual in p.ORDER,'phase_allowed')
    if phase != 'observe':
        p.need(args.apply,'explicit_apply_required')
        if actual == 'stage': p.need(0 <= time.time()-plan['createdAt'] <= 3600,'staging_plan_expired')
        elif actual != 'stop': receipt(args,plan,p.ORDER[p.ORDER.index(actual)-1])
        if actual in ('upgrade','rollback'):
            preceding = 'baseline' if actual == 'upgrade' else 'upgrade'
            verified = p.decode(h.read(args.staging/('verified-'+preceding+'.json')))
            p.need(verified.get('verified') is True and verified.get('operationId') == plan['operationId'],'functional_acceptance_required')
    if actual == 'migrate' and phase != 'observe':
        empty = remote(args.lab_root,{'phase':'empty-schema','host':'pg01','plan':plan},hashes)
        p.need(empty == {'empty':True,'database':p.DATABASE}, 'fresh_database_not_empty')
    payload = {'phase':phase,'host':p.PHASE_HOST[actual],'plan':plan,'apply':args.apply}
    if phase == 'observe': payload['observedPhase'] = actual
    if actual in ('identity','retire-identity','database','install'):
        payload['secrets'] = p.decode(h.read(args.staging/'secrets.json',16384))
    if actual == 'grants': payload['grants'] = p.decode(h.read(args.staging/'grant-sql.json',1<<20))
    if actual == 'stage' and phase != 'observe':
        paths = p.decode(h.read(args.staging/'package-paths.json',65536)); payload['packages'] = {}
        for selected,path in paths.items():
            metadata,files = p.s.candidate_files(Path(path),plan['candidates'][selected]['archiveSHA256'])
            p.need(metadata['revision'] == plan['candidates'][selected]['revision'],'staged_candidate_changed')
            payload['packages'][selected] = {k:base64.b64encode(v).decode() for k,v in files.items()}
    pending = args.staging/(actual+'.pending.json')
    if phase != 'observe':
        p.need(not pending.exists(),'uncertain_mutation_requires_observation')
        h.save(pending,{'operationId':plan['operationId'],'phase':actual,'planSHA256':args.expected_plan_sha256})
    else: p.need(pending.exists(),'phase_not_admitted')
    result = remote(args.lab_root,payload,hashes)
    p.need(result.get('phase') == actual and result.get('completed') is True and
           result.get('planSHA256') == args.expected_plan_sha256,'completion_shape')
    if actual == 'migrate':
        observed = remote(args.lab_root,{'phase':'ledger','host':'pg01','plan':plan},hashes)
        p.need(observed['ledgerSHA256'] == result['expectedLedgerSHA256'], 'migration_ledger_differs')
    authority(args,plan,hashes); h.save(args.staging/(actual+'.json'),result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('phase',choices=PHASES)
    parser.add_argument('--lab-root',type=Path,required=True)
    for name in ('staging','snapshot','output','dashboard-root','baseline-archive','upgrade-archive','reviewed-pair'):
        parser.add_argument('--'+name,type=Path)
    parser.add_argument('--revision'); parser.add_argument('--expected-plan-sha256'); parser.add_argument('--expected-implementation-sha256')
    parser.add_argument('--observed-phase',choices=p.ORDER); parser.add_argument('--selected',choices=('baseline','upgrade','rollback'))
    parser.add_argument('--apply',action='store_true'); args = parser.parse_args()
    p.need(args.lab_root.is_absolute() and args.lab_root.resolve() == args.lab_root,'lab_root')
    with locked(args.lab_root): value = snapshot(args) if args.phase == 'snapshot' else prepare(args) if args.phase == 'prepare' else phase(args)
    sys.stdout.buffer.write(p.encoded(value))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        code = getattr(error,'code','fresh_install_failed')
        print('Fresh install stopped ('+code+'); retain all receipts; do not repeat uncertain mutations.',file=sys.stderr)
        raise SystemExit(1) from None
