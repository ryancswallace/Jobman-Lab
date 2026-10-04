#!/usr/bin/env python3
"""Stage the separate real Slurm executor and additive log mappings; never apply."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

spec=importlib.util.spec_from_file_location('execution_plan',Path(__file__).with_name('dashboard-execution-plan.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
TARGET='dashboard-execution-slurm'
STATE_ROOT='/var/lib/jobman-dashboard-execution/alice-slurm'
STORE_ROOT='/data/jobman/alice/dashboard-slurm-logs'
BUNDLE_ROOT='/data/jobman/alice/dashboard-slurm-bundles'
UNIT='jobman-dashboard-execution-slurm.service'


def unit_text(digest):
    base.require(re.fullmatch('[0-9a-f]{64}',digest),'Invalid binary digest')
    runner='/usr/local/libexec/jobman-dashboard-lab/jobman-agent-execution-'+digest
    return f'''[Unit]
Description=Isolated Dashboard real Slurm acceptance agent (Alice)
Wants=network-online.target remote-fs.target
After=network-online.target remote-fs.target

[Service]
Type=simple
User=alice
Group=alice
Environment=PATH=/usr/local/bin:/usr/bin:/bin:/opt/slurm/current/bin
ExecStart={runner} run --state-dir {STATE_ROOT} --poll-interval 1s --artifact-store lab-nfs --artifact-store-version 1 --artifact-root {STORE_ROOT} --slurm-root {BUNDLE_ROOT} --slurm-runner {runner} --max-log-bytes 1048576 --max-artifact-bytes 1048576
Restart=on-failure
RestartSec=3s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# Root-squashed NFS child traversal is controlled by Alice's private/DAC ACLs.
ReadWritePaths={STATE_ROOT} /data
TimeoutStopSec=35s

[Install]
WantedBy=multi-user.target
'''


def make_plan(build,fixture,source_revision):
    metadata=base.validate_build(build);namespace=base.validate_fixture(fixture)
    base.require(re.fullmatch('[0-9a-f]{40}',source_revision),'Exact source revision required')
    digest=metadata['sha256']['jobman-agent']
    return {'synthetic':True,'version':1,'mode':'actual-slurm-execution','deploymentId':base.DEPLOYMENT,
            'controlInstanceId':fixture['instanceId'],'namespaceId':namespace,'namespace':base.NAMESPACE,
            'sourceRevision':source_revision,'coreRevision':base.REVISION,'agentSHA256':digest,
            'targetName':TARGET,'targetRequest':{'apiVersion':'jobman.control/v1alpha1','kind':'Target','metadata':{'name':TARGET},'spec':{'kind':'slurm','executionBackend':'slurm','runtimes':['native'],'operatingSystems':['linux'],'architectures':['arm64'],'partitions':[{'name':'cpu','isDefault':True}],'logStore':{'name':'lab-nfs','version':1},'artifactStores':[{'name':'lab-nfs','version':1}],'provider':{'kind':'on-prem'}}},
            'targetIdempotencyKey':'dashboard-execution-slurm-v1','enrollmentIdempotencyKey':'dashboard-slurm-alice-v1','expectedUser':'alice','expectedUID':21001,
            'directoryId':'71000000-0000-4000-8000-000000000001','stateRoot':STATE_ROOT,'storeRoot':STORE_ROOT,'bundleRoot':BUNDLE_ROOT,
            'runner':'/usr/local/libexec/jobman-dashboard-lab/jobman-agent-execution-'+digest,'runnerCopies':['submit01','compute01'],'runnerLayout':'identical-root-owned-local','unit':UNIT,'readerUID':21901,
            'maximumJobs':12,'maximumRunSeconds':30,'maximumRuns':1,
            'policy':{'schema_version':1,'store_name':'lab-nfs','store_version':1,'reader_uid':21901}}


def mapping_patch(config,receipt,role,revision):
    base.require(receipt.get('synthetic') is True and receipt.get('mode')=='actual-slurm-execution' and receipt.get('targetName')==TARGET and receipt.get('storeRoot')==STORE_ROOT,'Exact Slurm receipt required')
    base.require(receipt.get('deploymentId')==base.DEPLOYMENT and receipt.get('namespace')==base.NAMESPACE and base.UUID.fullmatch(receipt.get('namespaceId','')) and base.UUID.fullmatch(receipt.get('targetGenerationId','')),'Source-qualified Slurm receipt invalid')
    base.require(type(revision) is int and revision>0 and config.get('configurationRevision')==revision,'Current configuration revision differs')
    controls=[c for c in config.get('controls',[]) if c.get('id')==base.DEPLOYMENT]
    base.require(len(controls)==1 and controls[0].get('expectedInstanceId')==receipt.get('controlInstanceId') and controls[0].get('origin')=='https://10.77.0.21:18443' and receipt['namespaceId'] in controls[0].get('namespaceIds',[]),'Source identity/namespace differs')
    key='logRoots' if role=='broker' else 'logMappings'
    mapping={'deploymentId':base.DEPLOYMENT,'targetGenerationId':receipt['targetGenerationId'],'storeName':'lab-nfs','storeVersion':'1'}
    if role=='broker':mapping['root']=STORE_ROOT
    else:
        brokers=[b for b in config.get('logBrokers',[]) if b.get('id')=='control01-nfs' and b.get('deploymentId')==base.DEPLOYMENT and b.get('origin')=='https://10.77.0.21:19443' and receipt['namespaceId'] in b.get('namespaceIds',[])]
        base.require(len(brokers)==1,'Source-qualified broker differs');mapping['brokerId']='control01-nfs'
    result=json.loads(json.dumps(config));existing=result.get(key,[])
    base.require(isinstance(existing,list) and len(existing)<64,'Mapping bound exceeded')
    matches=[m for m in existing if m.get('deploymentId')==base.DEPLOYMENT and m.get('targetGenerationId')==receipt['targetGenerationId']]
    if matches:base.require(matches==[mapping],'An existing Slurm mapping differs');return result
    result[key]=existing+[mapping];result['configurationRevision']=revision+1
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    p=sub.add_parser('plan');p.add_argument('--build',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--source-revision',required=True);p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('mapping');p.add_argument('--config',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--role',choices=['api','reports','broker'],required=True);p.add_argument('--expected-revision',type=int,required=True);p.add_argument('--expected-sha256',required=True);p.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.operation=='plan':
        plan=make_plan(args.build,json.loads(base.read(args.fixture,65536)),args.source_revision)
        args.output.mkdir(mode=0o700);base.write_new(args.output/'plan.json',base.encoded(plan));base.write_new(args.output/UNIT,unit_text(plan['agentSHA256']).encode())
        print('Staged separate Slurm executor plan; no service, target, or workload created.')
    else:
        raw=base.read(args.config,1048576);base.require(hashlib.sha256(raw).hexdigest()==args.expected_sha256,'Current configuration SHA differs')
        result=mapping_patch(json.loads(raw),json.loads(base.read(args.receipt,32768)),args.role,args.expected_revision)
        base.write_new(args.output,base.encoded(result));print('Staged exact-source Slurm log mapping; no live config changed.')


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError):raise SystemExit('Slurm staging failed; no live state changed.') from None
