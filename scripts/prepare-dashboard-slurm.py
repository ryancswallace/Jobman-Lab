#!/usr/bin/env python3
"""Provision only the reviewed separate Slurm executor; no workloads or config edits."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


plan=load('slurm_plan','dashboard-slurm-plan.py')

RUNNER=r'''
import base64,hashlib,json,os,pwd,stat,subprocess,sys
from pathlib import Path
p=json.load(sys.stdin);value=p['plan'];assert os.getuid()==0 and value['mode']=='actual-slurm-execution'
def directory(path,mode):
 try:path.mkdir(mode=mode);os.chmod(path,mode)
 except FileExistsError:pass
 st=path.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode
def file(path,data,mode):
 try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 except FileExistsError:
  st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode and st.st_size==len(data) and path.read_bytes()==data
 else:
  with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
binary=base64.b64decode(p['binary'],validate=True);assert 0<len(binary)<64<<20 and hashlib.sha256(binary).hexdigest()==value['agentSHA256']
for path in ['/usr','/usr/local','/usr/local/libexec']:
 directory(Path(path),0o755)
root=Path('/usr/local/libexec/jobman-dashboard-lab');directory(root,0o755)
file(root/('jobman-agent-execution-'+value['agentSHA256']),binary,0o755)
assert str(root/('jobman-agent-execution-'+value['agentSHA256']))==value['runner']
print('immutable-local-runner-ready')
'''

USER_STORAGE=r'''
import json,os,stat,subprocess,sys
from pathlib import Path
p=json.load(sys.stdin);assert os.getuid()==21001
parent=Path('/srv/lab/data/jobman/alice');st=parent.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==21001
expected={'user::rwx','user:21901:r-x','group::---','mask::r-x','other::---','default:user::rwx','default:user:21901:r-x','default:group::---','default:mask::r-x','default:other::---'}
def acl(path):
 out=subprocess.check_output(['getfacl','-cpn','--',str(path)],text=True,timeout=5)
 return set(line for line in out.splitlines() if line and not line.startswith('#'))
assert acl(parent)==expected
logs=parent/'dashboard-slurm-logs'
try:logs.mkdir(mode=0o750)
except FileExistsError:pass
st=logs.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==21001 and stat.S_IMODE(st.st_mode)==0o750 and acl(logs)==expected
policy=(json.dumps(p['policy'],sort_keys=True,separators=(',',':'))+'\n').encode();path=logs/'.jobman-log-reader.json'
try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
except FileExistsError:
 st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==21001 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size==len(policy) and path.read_bytes()==policy
else:
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(policy);f.flush();os.fsync(f.fileno())
bundle=parent/'dashboard-slurm-bundles'
try:
 bundle.mkdir(mode=0o700)
 # Remove inherited reader ACL only from this just-created private bundle root.
 # Assignment/auth documents never inherit the public log-reader grant.
 subprocess.run(['setfacl','-b','-k','--',str(bundle)],check=True,timeout=5);os.chmod(bundle,0o700)
except FileExistsError:pass
st=bundle.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==21001 and stat.S_IMODE(st.st_mode)==0o700 and acl(bundle)=={'user::rwx','group::---','other::---'}
print('separate-private-bundles-and-reader-logs-ready')
'''

SUBMIT=r'''
import hashlib,json,os,pwd,stat,subprocess,sys
from pathlib import Path
p=json.load(sys.stdin);value=p['plan'];assert os.getuid()==0 and pwd.getpwnam('alice').pw_uid==21001
def directory(path,mode,uid,gid):
 try:path.mkdir(mode=mode);os.chown(path,uid,gid);os.chmod(path,mode)
 except FileExistsError:pass
 st=path.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==uid and st.st_gid==gid and stat.S_IMODE(st.st_mode)==mode
def file(path,data,mode):
 try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 except FileExistsError:
  st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode and st.st_size==len(data) and path.read_bytes()==data
 else:
  with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
runner=Path(value['runner']);st=runner.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o755 and st.st_size<64<<20 and hashlib.sha256(runner.read_bytes()).hexdigest()==value['agentSHA256']
base=Path('/var/lib/jobman-dashboard-slurm');directory(base,0o755,0,0)
file(base/'plan.json',(json.dumps(value,sort_keys=True,indent=2)+'\n').encode(),0o600)
ca=p['ca'].encode();assert 0<len(ca)<65536 and b'PRIVATE' not in ca;file(base/'control-ca.crt',ca,0o644)
state=Path(value['stateRoot']);directory(state.parent,0o755,0,0);directory(state,0o700,21001,21001)
file(Path('/etc/systemd/system')/value['unit'],p['unit'].encode(),0o644)
subprocess.run(['systemctl','daemon-reload'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
print('separate-slurm-unit-ready-not-started')
'''

ENROLL=r'''
import json,os,re,stat,subprocess,sys
from pathlib import Path
p=json.load(sys.stdin);plan=p['plan'];enroll=p['enrollment'];base=Path('/var/lib/jobman-dashboard-slurm');state=Path(plan['stateRoot'])
assert os.getuid()==0 and json.loads((base/'plan.json').read_bytes())==plan
identifier=re.compile('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
assert set(enroll)=={'targetId','targetGenerationId','recoveryEpoch','token'} and identifier.fullmatch(enroll['targetId']) and identifier.fullmatch(enroll['targetGenerationId']) and re.fullmatch('[1-9][0-9]{0,18}',enroll['recoveryEpoch'])
token=enroll['token'];assert isinstance(token,str) and len(token)<16384 and not any(c.isspace() for c in token)
def status():
 result=subprocess.run(['runuser','-u','alice','--',plan['runner'],'status','--json','--state-dir',str(state)],capture_output=True,timeout=10)
 if result.returncode:return None
 assert len(result.stdout)<32768
 result=json.loads(result.stdout);assert result['kind']=='AgentStatus' and result['metadata']['targetGenerationId']==enroll['targetGenerationId'] and result['status']['serverUrl']=='https://10.77.0.21:18443' and identifier.fullmatch(result['metadata']['agentId'])
 return result
current=status()
if current is None:
 assert token,'Ambiguous retained enrollment requires inspection, never state reset'
 result=subprocess.run(['runuser','-u','alice','--',plan['runner'],'enroll','--slurm','--state-dir',str(state),'--server','https://10.77.0.21:18443','--target-generation',enroll['targetGenerationId'],'--server-ca',str(base/'control-ca.crt')],input=(token+'\n').encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 assert result.returncode==0,'Enrollment failed; preserve retained state';current=status();assert current is not None
receipt={k:plan[k] for k in ['synthetic','mode','deploymentId','controlInstanceId','namespaceId','namespace','sourceRevision','coreRevision','agentSHA256','targetName','stateRoot','storeRoot','bundleRoot','runner','runnerCopies','runnerLayout','unit']}
receipt.update({k:enroll[k] for k in ['targetId','targetGenerationId','recoveryEpoch']});receipt['agentId']=current['metadata']['agentId']
raw=(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode();path=base/'slurm-fixture.json'
try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
except FileExistsError:
 st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size==len(raw) and path.read_bytes()==raw
else:
 with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
subprocess.run(['systemctl','start',plan['unit']],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
subprocess.run(['systemctl','is-active','--quiet',plan['unit']],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
print(raw.decode(),end='')
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['provision','enroll']);parser.add_argument('--apply',action='store_true',required=True)
    parser.add_argument('--plan',type=Path,required=True);parser.add_argument('--expected-plan-sha256',required=True);parser.add_argument('--build',type=Path,required=True);args=parser.parse_args()
    raw=plan.base.read(args.plan,32768);plan.base.require(hashlib.sha256(raw).hexdigest()==args.expected_plan_sha256,'Reviewed Slurm plan changed')
    value=json.loads(raw);checks=load('slurm_checks','check-dashboard-infra.py');fixture=json.loads(plan.base.read(checks.STATE/'fixture-info.json',65536))
    plan.base.require(value==plan.make_plan(args.build,fixture,value['sourceRevision']),'Slurm plan differs from fixed reviewed scope')
    inventory=checks.ROOT/'.lab/dashboard-slurm';hosts=json.loads(plan.base.read(inventory/'ssh-connections.json',65536))
    def ssh(host,script,payload,user=None):
        c=(hosts if host in hosts else checks.CONNECTIONS)[host];known=(inventory if host in hosts else checks.STATE)/'known_hosts'
        remote=['sudo']+(['-u',user] if user else [])+['python3','-c',script]
        command=['ssh','-i',c['ansible_ssh_private_key_file'],'-p',str(c['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={known}','-o','HostKeyAlgorithms=ssh-ed25519',f'{c["ansible_user"]}@{c["ansible_host"]}',shlex.join(remote)]
        result=checks.run(command,json.dumps(payload),timeout=60);plan.base.require(result.returncode==0 and len(result.stdout)<32768,'Slurm preparation failed; retain partial state without resetting');return result.stdout
    # Recheck the live source build for both resumable phases; credentials never
    # leave the Go caller except the single-use enrollment token through stdin.
    verify="import json,sys;from pathlib import Path;p=json.load(sys.stdin);assert json.loads(Path('/usr/local/libexec/jobman-dashboard-lab/source-current.json').read_bytes())['revision']==p['sourceRevision'];assert json.loads(Path('/etc/jobman-dashboard-lab/control-fixture/fixture-info.json').read_bytes())['instanceId']==p['controlInstanceId'];print('source-pin-verified')"
    ssh('control01',verify,value)
    if args.action=='provision':
        for host in ('submit01','compute01'):
            ssh(host,RUNNER,{'plan':value,'binary':base64.b64encode(plan.base.read(args.build/'jobman-agent',64<<20)).decode()})
        ssh('storage01',USER_STORAGE,value,user='alice')
        ca=plan.base.read(checks.STATE/'runtime/control/fixture-ca.crt',65536).decode()
        ssh('submit01',SUBMIT,{'plan':value,'unit':plan.unit_text(value['agentSHA256']),'ca':ca})
        print('New Slurm runner/state/ACL/unit prepared; no enrollment, start or workloads.')
    else:
        raw=sys.stdin.buffer.read(32769);plan.base.require(len(raw)<=32768,'Enrollment exceeds bound')
        verify_runner="import hashlib,json,stat,sys;from pathlib import Path;p=json.load(sys.stdin);x=Path(p['runner']);s=x.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o755 and s.st_size<64<<20 and hashlib.sha256(x.read_bytes()).hexdigest()==p['agentSHA256'];assert all(a.lstat().st_uid==0 and stat.S_IMODE(a.lstat().st_mode)&0o022==0 and stat.S_ISDIR(a.lstat().st_mode) for a in x.parents);print('exact-local-runner-verified')"
        for host in ('submit01','compute01'):ssh(host,verify_runner,value)
        output=ssh('submit01',ENROLL,{'plan':value,'enrollment':json.loads(raw)})
        receipt=json.loads(output);destination=checks.STATE/'slurm-fixture.json'
        plan.base.require(receipt['mode']=='actual-slurm-execution' and receipt['controlInstanceId']==value['controlInstanceId'],'Slurm enrollment receipt differs')
        if destination.exists():plan.base.require(plan.base.read(destination,32768)==output.encode(),'Existing Slurm receipt differs')
        else:plan.base.write_new(destination,output.encode())
        print(output,end='')


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):raise SystemExit('Isolated Slurm preparation failed. Preserve partial receipts; no original state reset attempted.') from None
