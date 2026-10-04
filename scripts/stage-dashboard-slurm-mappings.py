#!/usr/bin/env python3
"""Read exact split configs and stage additive Slurm mapping files; never apply."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess


def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

plan=load('slurm_mapping_plan','dashboard-slurm-plan.py')

REMOTE=r'''
import base64,hashlib,json,os,stat,sys
p=json.load(sys.stdin);assert os.getuid()==0
fd=os.open(p['path'],os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as f:
 s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==p['uid'] and s.st_gid==p['uid'] and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=1048576
 raw=f.read(1048577);after=os.fstat(f.fileno());end=os.lstat(p['path'])
 assert len(raw)==s.st_size and (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)==(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns) and (end.st_dev,end.st_ino)==(s.st_dev,s.st_ino)
print(json.dumps({'raw':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest(),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}))
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--expected-revision',type=int,required=True);args=parser.parse_args()
    plan.base.require(args.output.is_absolute() and not args.output.exists() and args.expected_revision==5,'New absolute staging directory and reviewed split revision5 required')
    checks=load('slurm_mapping_checks','check-dashboard-infra.py');receipt=json.loads(plan.base.read(checks.STATE/'slurm-fixture.json',32768));staged=[]
    for role,host,path,uid in [('api','storage01','/etc/jobman-dashboard-api-lab/config.json',21904),('reports','storage01','/etc/jobman-dashboard-worker-lab/config.json',21905),('broker','control01','/etc/jobman-dashboard-broker-lab/config.json',21901)]:
        reply=checks.ssh(host,'sudo python3 -c '+shlex.quote(REMOTE),json.dumps({'path':path,'uid':uid}))
        plan.base.require(reply.returncode==0 and len(reply.stdout)<1500000,'Read-only configuration fetch failed')
        value=json.loads(reply.stdout);raw=base64.b64decode(value['raw'],validate=True)
        plan.base.require(len(raw)<=1048576 and hashlib.sha256(raw).hexdigest()==value['sha256'],'Remote config changed in transit')
        original=json.loads(raw);changed=plan.mapping_patch(original,receipt,role,args.expected_revision)
        plan.base.require(changed['configurationRevision']==6,'New Slurm mapping must be absent from reviewed split snapshot')
        mapping_key='logRoots' if role=='broker' else 'logMappings'
        a=dict(original);b=dict(changed)
        for key in ('configurationRevision',mapping_key):a.pop(key,None);b.pop(key,None)
        plan.base.require(a==b and changed[mapping_key][:-1]==original.get(mapping_key,[]),'Non-additive configuration delta rejected')
        staged.append((role,host,path,value,raw,plan.base.encoded(changed),changed[mapping_key][-1]))
    args.output.mkdir(mode=0o700)
    review={'synthetic':True,'applies':False,'fixtureSHA256':hashlib.sha256(plan.base.read(checks.STATE/'slurm-fixture.json',32768)).hexdigest(),'sourceInstanceId':receipt['controlInstanceId'],'targetGenerationId':receipt['targetGenerationId'],'currentRevision':5,'nextRevision':6,'files':[],
            'coordination':['Wait for root acceptance of the split report restart and event recovery.','Recheck all three exact original hashes, owner/mode and source instance before the first mutation.','Validate staged API, worker and broker configs with each installed candidate/check-mode before swapping.','Apply only when API, worker and broker configuration writers are coordinated; abort on any drift.','Restart only isolated Dashboard API/worker and log broker, preserving the delivery hold and source services.'],
            'fallback':'Never restore configurationRevision5 after revision6 has been observed. On a partial apply, preserve receipts and staged originals; either finish exact remaining swaps under root review, or prepare new SHA-CAS configs at revision7 or later using current values and source credentials. No automatic rollback, source epoch reset, notification resume, or job resubmission.'}
    for role,host,path,value,before,after,mapping in staged:
        plan.base.write_new(args.output/(role+'.before.json'),before);plan.base.write_new(args.output/(role+'.after.json'),after)
        review['files'].append({'role':role,'host':host,'path':path,'uid':value['uid'],'gid':value['gid'],'mode':value['mode'],'beforeSHA256':hashlib.sha256(before).hexdigest(),'afterSHA256':hashlib.sha256(after).hexdigest(),'addedMapping':mapping})
    plan.base.write_new(args.output/'review.json',plan.base.encoded(review))
    print(json.dumps({'staged':True,'applied':False,'output':str(args.output),'reviewSHA256':hashlib.sha256(plan.base.encoded(review)).hexdigest()}))

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):raise SystemExit('Read-only Slurm mapping staging failed; no guest configuration changed.') from None
