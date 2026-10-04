#!/usr/bin/env python3
"""Explicitly provision/enroll only the reviewed isolated subprocess agent.

No ordinary API bearer is needed here. The Go acceptance harness performs normal
Control requests and sends only its one-time enrollment token through stdin.
This script never reads database credentials, changes original agents or submits
workloads. Provisioning and enrollment are separate resumable phases.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plan = load('execution_plan', 'dashboard-execution-plan.py')

STORAGE = r'''
import json,os,pwd,stat,subprocess,sys
from pathlib import Path
data=json.load(sys.stdin)
assert os.getuid()==21001 and pwd.getpwuid(21001).pw_name=='alice'
parent=Path('/srv/lab/data/jobman/alice');root=parent/'dashboard-execution'
expected={'user::rwx','user:21901:r-x','group::---','mask::r-x','other::---','default:user::rwx','default:user:21901:r-x','default:group::---','default:mask::r-x','default:other::---'}
def verify(path):
 st=path.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==21001 and stat.S_IMODE(st.st_mode)==0o750
 acl=subprocess.check_output(['getfacl','-cpn','--',str(path)],text=True,timeout=5)
 assert set(line for line in acl.splitlines() if line and not line.startswith('#'))==expected
verify(parent)
if not root.exists():root.mkdir(mode=0o750)
verify(root)
policy=json.dumps(data['policy'],sort_keys=True,separators=(',',':')).encode()+b'\n'
path=root/'.jobman-log-reader.json'
try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
except FileExistsError:
 st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==21001 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size==len(policy) and path.read_bytes()==policy
else:
 with os.fdopen(fd,'wb') as out:out.write(policy);out.flush();os.fsync(out.fileno())
print('new-execution-store-ready')
'''

PROVISION = r'''
import base64,hashlib,json,os,pwd,stat,subprocess,sys
from pathlib import Path
payload=json.load(sys.stdin);plan=payload['plan'];fixture=Path('/etc/jobman-dashboard-lab/control-fixture');base=Path('/var/lib/jobman-dashboard-execution')
assert os.getuid()==0 and pwd.getpwnam('alice').pw_uid==21001 and pwd.getpwnam('alice').pw_gid==21001
source=json.loads(Path('/usr/local/libexec/jobman-dashboard-lab/source-current.json').read_bytes())
info=json.loads((fixture/'fixture-info.json').read_bytes())
assert source['revision']==plan['sourceRevision'] and info['instanceId']==plan['controlInstanceId']
assert any(n['name']=='dashboard-operations' and n['id']==plan['namespaceId'] for n in info['namespaces'])
def directory(path,mode,uid,gid):
 try:path.mkdir(mode=mode);os.chown(path,uid,gid);os.chmod(path,mode)
 except FileExistsError:pass
 st=path.lstat();assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode)==mode and st.st_uid==uid and st.st_gid==gid
def file(path,data,mode):
 try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 except FileExistsError:
  st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode and st.st_size==len(data) and path.read_bytes()==data
 else:
  with os.fdopen(fd,'wb') as out:os.fchmod(out.fileno(),mode);out.write(data);out.flush();os.fsync(out.fileno())
directory(base,0o755,0,0)
file(base/'plan.json',(json.dumps(plan,sort_keys=True,indent=2)+'\n').encode(),0o600)
directory(base/'alice-host',0o700,21001,21001)
directory(base/'alice-host'/'work',0o700,21001,21001)
binary=base64.b64decode(payload['binary'],validate=True)
assert 0<len(binary)<64<<20 and hashlib.sha256(binary).hexdigest()==plan['agentSHA256']
path=Path('/usr/local/libexec/jobman-dashboard-lab')/('jobman-agent-execution-'+plan['agentSHA256'])
st=path.parent.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)&0o022==0
file(path,binary,0o755)
ca=(fixture/'fixture-ca.crt').read_bytes();assert 0<len(ca)<65536 and b'PRIVATE' not in ca
file(base/'control-ca.crt',ca,0o644)
unit=Path('/etc/systemd/system/jobman-dashboard-execution-host.service')
file(unit,payload['unit'].encode(),0o644)
subprocess.run(['systemctl','daemon-reload'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
print('new-execution-agent-provisioned-not-started')
'''

ENROLL = r'''
import json,os,re,stat,subprocess,sys
from pathlib import Path
payload=json.load(sys.stdin);plan=payload['plan'];enroll=payload['enrollment'];base=Path('/var/lib/jobman-dashboard-execution');state=base/'alice-host'
assert os.getuid()==0 and json.loads((base/'plan.json').read_bytes())==plan
assert json.loads(Path('/usr/local/libexec/jobman-dashboard-lab/source-current.json').read_bytes())['revision']==plan['sourceRevision']
identifier=re.compile('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
assert set(enroll)=={'targetId','targetGenerationId','recoveryEpoch','token'} and identifier.fullmatch(enroll['targetId']) and identifier.fullmatch(enroll['targetGenerationId']) and re.fullmatch('[1-9][0-9]{0,18}',enroll['recoveryEpoch'])
token=enroll['token'];assert isinstance(token,str) and len(token)<16384 and not any(c.isspace() for c in token)
binary='/usr/local/libexec/jobman-dashboard-lab/jobman-agent-execution-'+plan['agentSHA256']
def status():
 result=subprocess.run(['runuser','-u','alice','--',binary,'status','--json','--state-dir',str(state)],capture_output=True,timeout=10)
 if result.returncode: return None
 assert len(result.stdout)<32768
 result=json.loads(result.stdout);assert result['kind']=='AgentStatus' and result['metadata']['targetGenerationId']==enroll['targetGenerationId'] and result['status']['serverUrl']=='https://10.77.0.21:18443'
 assert identifier.fullmatch(result['metadata']['agentId'])
 return result
current=status()
if current is None:
 assert token,'Enrollment receipt is ambiguous; inspect retained agent state, never reset it automatically'
 result=subprocess.run(['runuser','-u','alice','--',binary,'enroll','--state-dir',str(state),'--server','https://10.77.0.21:18443','--target-generation',enroll['targetGenerationId'],'--server-ca',str(base/'control-ca.crt')],input=(token+'\n').encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 assert result.returncode==0,'Enrollment failed; preserve private pending enrollment before retry'
 current=status();assert current is not None
receipt={k:plan[k] for k in ['synthetic','mode','deploymentId','controlInstanceId','namespaceId','namespace','sourceRevision','coreRevision','agentSHA256','targetName','stateRoot','storeRoot','unit']}
receipt.update({k:enroll[k] for k in ['targetId','targetGenerationId','recoveryEpoch']});receipt['agentId']=current['metadata']['agentId']
raw=(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode();path=base/'execution-fixture.json'
try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
except FileExistsError:
 st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size==len(raw) and path.read_bytes()==raw
else:
 with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
subprocess.run(['systemctl','start','jobman-dashboard-execution-host.service'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
subprocess.run(['systemctl','is-active','--quiet','jobman-dashboard-execution-host.service'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
print(raw.decode(),end='')
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['provision', 'enroll'])
    parser.add_argument('--apply', action='store_true', required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--build', type=Path, required=True)
    args = parser.parse_args()
    raw = plan.read(args.plan, 32768)
    plan.require(hashlib.sha256(raw).hexdigest() == args.expected_plan_sha256, 'Reviewed plan digest differs')
    value = json.loads(raw)
    checks = load('execution_checks', 'check-dashboard-infra.py')
    original = json.loads(plan.read(checks.STATE / 'fixture-info.json', 65536))
    plan.require(value == plan.make_plan(args.build, original, value['sourceRevision']), 'Execution plan differs from approved fixed scope')

    def ssh(host, script, payload, timeout=60, user=None):
        c = checks.CONNECTIONS[host]
        prefix = ['sudo'] + (['-u', user] if user else []) + ['python3', '-c', script]
        command = ['ssh', '-i', c['ansible_ssh_private_key_file'], '-p', str(c['ansible_port']), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={checks.STATE / "known_hosts"}', '-o', 'HostKeyAlgorithms=ssh-ed25519', f'{c["ansible_user"]}@{c["ansible_host"]}', shlex.join(prefix)]
        result = checks.run(command, json.dumps(payload), timeout=timeout)
        plan.require(result.returncode == 0 and len(result.stdout) < 32768, 'Isolated execution action failed; preserve pending state and inspect privately')
        return result.stdout

    if args.action == 'provision':
        ssh('storage01', STORAGE, {'policy': value['policy']}, user='alice')
        binary = plan.read(args.build / 'jobman-agent', 64 << 20)
        ssh('control01', PROVISION, {'plan': value, 'binary': base64.b64encode(binary).decode(), 'unit': plan.unit_text(value['agentSHA256'])})
        print('Provisioned only the new isolated executor; agent has not been started.')
    else:
        secret = sys.stdin.buffer.read(32769)
        plan.require(len(secret) <= 32768, 'Enrollment input exceeds bound')
        enrollment = json.loads(secret)
        output = ssh('control01', ENROLL, {'plan': value, 'enrollment': enrollment})
        receipt = json.loads(output)
        # Persist only the public generation/agent binding, never the enrollment token.
        plan.mapping_patch({'configurationRevision': 1, 'controls': [{'id': plan.DEPLOYMENT, 'expectedInstanceId': value['controlInstanceId'], 'origin': 'https://10.77.0.21:18443', 'namespaceIds': [value['namespaceId']]}]}, receipt, 'broker', 1)
        destination = checks.STATE / 'execution-fixture.json'
        if destination.exists():
            plan.require(plan.read(destination, 32768) == output.encode(), 'Existing execution receipt differs')
        else:
            plan.write_new(destination, output.encode())
        print(output, end='')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise SystemExit('Isolated execution action failed. No automatic state reset or original-service change was attempted; inspect retained partial receipts.') from None
