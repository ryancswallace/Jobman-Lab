#!/usr/bin/env python3
"""Prepare only the reviewed supplemental synthetic diagnostic job and log objects."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess

FIXTURE_ROOT = '/etc/jobman-dashboard-lab/control-fixture'
SPOOL = '/var/lib/jobman-dashboard-lab/diagnostic-logs'
NFS_ROOT = '/data/jobman/alice'
DEPLOYMENT = '72000000-0000-4000-8000-000000000001'


def validate_fixture(value, original, commit=None):
    """Validate public identities and the exact two known nonsecret byte objects."""
    import hashlib
    import re
    deployment = '72000000-0000-4000-8000-000000000001'
    expected = b'SYNTHETIC OBSERVATION ONLY: open synthetic-output.txt: permission denied; metadata and byte delivery\n'
    if not (value.get('synthetic') is True and value.get('fixtureVersion') == 1 and
            value.get('observationMode') == 'synthetic-store-observations-no-execution' and
            value.get('deploymentId') == deployment and value.get('controlInstanceId') == original['instanceId'] and
            value.get('namespace') == 'dashboard-operations' and value.get('targetName') == 'synthetic-diagnostics'):
        raise ValueError('Supplemental fixture identity or synthetic provenance differs')
    operations = [item for item in original['namespaces'] if item['name'] == 'dashboard-operations']
    if len(operations) != 1 or value['namespaceId'] != operations[0]['id']:
        raise ValueError('Supplemental fixture is outside the approved operations namespace')
    for name in ['deploymentId', 'controlInstanceId', 'namespaceId', 'targetId', 'targetGenerationId', 'jobId', 'runId', 'executionId']:
        if not re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', value.get(name, '')):
            raise ValueError('Noncanonical fixture identity')
    if not re.fullmatch('[0-9a-f]{40}', value.get('helperCommit', '')) or commit is not None and value['helperCommit'] != commit:
        raise ValueError('Unverified helper revision')
    if not all(re.fullmatch('[1-9][0-9]{0,18}', value.get(name, '')) for name in ['recoveryEpoch', 'jobRevision']):
        raise ValueError('Invalid source epoch or job revision')
    streams = value.get('streams', [])
    if len(streams) != 2:
        raise ValueError('Exactly two complete synthetic streams are required')
    objects = []
    for index, stream in enumerate(['stdout', 'stderr']):
        page = streams[index]
        data = b'' if stream == 'stdout' else expected
        key = ('namespaces/dashboard-operations/jobs/' + value['jobId'] + '/executions/' +
               value['executionId'] + '/logs/' + stream + '/00000001.chunk')
        if not (page.get('stream') == stream and page.get('state') == 'complete' and
                page.get('runId') == value['runId'] and page.get('executionId') == value['executionId'] and
                page.get('targetGenerationId') == value['targetGenerationId'] and page.get('namespaceId') == value['namespaceId'] and
                page.get('byteLength') == str(len(data)) and not page.get('nextAfterSequence') and len(page.get('chunks', [])) == 1):
            raise ValueError('Supplemental stream metadata differs')
        chunk = page['chunks'][0]
        if not (chunk.get('objectKey') == key and chunk.get('sequence') == '1' and
                chunk.get('byteOffset') == '0' and chunk.get('byteLength') == str(len(data)) and
                chunk.get('checksum') == 'sha256:' + hashlib.sha256(data).hexdigest() and
                chunk.get('storeName') == 'lab-nfs' and chunk.get('storeVersion') == '1' and
                chunk.get('complete') is True and chunk.get('truncated') is False):
            raise ValueError('Supplemental immutable chunk metadata differs')
        objects.append({'key': key, 'length': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    return objects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check-dashboard-infra.py'))
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    build = args.build
    metadata = json.loads((build / 'build.json').read_text())
    revision = metadata.get('revision', metadata.get('commit', ''))
    digest = metadata.get('sha256', {}).get('jobman-control-lab-helper', '')
    checks.require(build.is_absolute() and build.is_dir() and not build.is_symlink() and
                   metadata.get('platform') == 'linux/arm64' and metadata.get('toolchain') == 'go1.26.6' and
                   all(re.fullmatch('[0-9a-f]{40}', item) for item in [revision, args.source_revision]) and
                   re.fullmatch('[0-9a-f]{64}', digest), 'Exact helper build manifest is invalid')
    path = build / 'jobman-control-lab-helper'
    checks.require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size < 100 << 20,
                   'Helper binary is not a bounded regular file')
    binary = path.read_bytes()
    checks.require(hashlib.sha256(binary).hexdigest() == digest, 'Exact helper digest differs')
    original = json.loads((checks.STATE / 'fixture-info.json').read_text())
    checks.require(original.get('synthetic') is True and original['endpoint'] == 'https://10.77.0.21:18443', 'Wrong original source fixture')
    password = checks.credential('dashboard.env', 'JOBMAN_LAB_DASHBOARD_CONTROL_PASSWORD')
    result = checks.sql('jobman_dashboard_control', password,
                        'SELECT current_database(); SELECT id::text FROM control_instance; SELECT max(version) FROM schema_migrations; SELECT count(*)<1000 FROM jobs;',
                        database='jobman_dashboard_control')
    checks.require(result.returncode == 0 and result.stdout.strip() == 'jobman_dashboard_control\n' + original['instanceId'] + '\n000021_monitoring_events.sql\nt',
                   'Dedicated source database/instance/migration/size preflight failed')
    remote = '''import base64,hashlib,json,os,pwd,stat,subprocess,sys
from pathlib import Path
payload=json.load(sys.stdin);root=Path('/etc/jobman-dashboard-lab/control-fixture');base=Path('/usr/local/libexec/jobman-dashboard-lab')
assert pwd.getpwnam('jobman-dashboard-source').pw_uid==21902
assert json.loads((base/'source-current.json').read_text())['revision']==payload['sourceRevision']
info=json.loads((root/'fixture-info.json').read_text());assert info['synthetic'] is True and info['instanceId']==payload['instance']
assert not list(root.glob('.directory-acceptance-*.json')) and not (root/'.diagnostic-prepare.json').exists()
binary=base/('jobman-control-diagnostic-helper-'+payload['revision']);data=base64.b64decode(payload['binary'],validate=True)
assert hashlib.sha256(data).hexdigest()==payload['sha256']
if binary.exists():
 assert stat.S_ISREG(binary.lstat().st_mode) and hashlib.sha256(binary.read_bytes()).hexdigest()==payload['sha256']
else:
 fd=os.open(binary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
 with os.fdopen(fd,'wb') as file:file.write(data);file.flush();os.fsync(file.fileno())
parent=Path('/var/lib/jobman-dashboard-lab');st=parent.lstat()
assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o710
acl=subprocess.check_output(['getfacl','-cpn',str(parent)],text=True)
entries=set(line for line in acl.splitlines() if line and not line.startswith('#'))
expected={'user::rwx','user:21001:--x','group::---','mask::--x','other::---'}
assert entries in [expected,expected|{'user:21902:--x'}]
subprocess.run(['setfacl','-n','-m','u:21902:--x',str(parent)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
spool=parent/'diagnostic-logs'
os.umask(0o027)
if not spool.exists():spool.mkdir(mode=0o750);os.chown(spool,21902,21902)
st=spool.lstat();assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode)==0o750 and st.st_uid==21902
dsnSource=Path('/etc/jobman-dashboard-lab/control-database-url');st=dsnSource.lstat()
assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==0 and 0<st.st_size<16384
dsn=root/'.diagnostic-database-url'
fd=os.open(dsn,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
 with os.fdopen(fd,'wb') as file:os.fchown(file.fileno(),21902,21902);file.write(dsnSource.read_bytes());file.flush();os.fsync(file.fileno())
 result=subprocess.run(['runuser','-u','jobman-dashboard-source','--',str(binary),'diagnostic','--root',str(root),'--database-url-file',str(dsn),'--log-root',str(spool),'--deployment-id','72000000-0000-4000-8000-000000000001'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=95)
 assert result.returncode==0,'Reviewed helper failed; inspect private recovery receipt before any retry'
finally:dsn.unlink()
for current,dirs,files in os.walk(spool,followlinks=False):
 for name in [current]+[str(Path(current)/item) for item in files]:
  path=Path(name);st=path.lstat();assert not stat.S_ISLNK(st.st_mode) and st.st_uid==21902
  rights='r-x' if stat.S_ISDIR(st.st_mode) else 'r--'
  assert stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)
  subprocess.run(['setfacl','-n','-m','u:21001:'+rights+',m::'+rights,str(path)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
print((root/'diagnostic-fixture.json').read_text())
'''
    payload = json.dumps({'revision': revision, 'sourceRevision': args.source_revision, 'sha256': digest,
                          'instance': original['instanceId'], 'binary': base64.b64encode(binary).decode()})
    connection = checks.CONNECTIONS['control01']
    command = ['ssh', '-i', connection['ansible_ssh_private_key_file'], '-p', str(connection['ansible_port']),
               '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes',
               '-o', f'UserKnownHostsFile={checks.STATE / "known_hosts"}', '-o', 'HostKeyAlgorithms=ssh-ed25519',
               f'{connection["ansible_user"]}@{connection["ansible_host"]}', 'sudo python3 -c ' + shlex.quote(remote)]
    result = checks.run(command, payload, timeout=110)
    checks.require(result.returncode == 0 and len(result.stdout) < 64 << 10,
                   'Diagnostic helper failed; inspect its private pending receipt before retrying')
    fixture = json.loads(result.stdout)
    objects = validate_fixture(fixture, original, revision)
    copy = '''import hashlib,json,os,stat,sys
from pathlib import Path
assert os.getuid()==21001
objects=json.load(sys.stdin);source=Path('/var/lib/jobman-dashboard-lab/diagnostic-logs');destination=Path('/data/jobman/alice')
for item in objects:
 parts=Path(item['key']).parts
 current=source
 for part in parts:
  current=current/part;assert not current.is_symlink()
 st=current.lstat();assert stat.S_ISREG(st.st_mode) and st.st_size==item['length'] and st.st_size<4096
 data=current.read_bytes();assert hashlib.sha256(data).hexdigest()==item['sha256']
 parent=destination
 for part in parts[:-1]:
  parent=parent/part
  assert not parent.is_symlink()
  parent.mkdir(mode=0o750,exist_ok=True)
 output=parent/parts[-1]
 try:fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
 except FileExistsError:
  st=output.lstat();assert stat.S_ISREG(st.st_mode) and st.st_size==item['length'] and hashlib.sha256(output.read_bytes()).hexdigest()==item['sha256']
 else:
  with os.fdopen(fd,'wb') as file:file.write(data);file.flush();os.fsync(file.fileno())
'''
    result = checks.ssh('control01', 'sudo -u alice python3 -c ' + shlex.quote(copy), json.dumps(objects))
    checks.require(result.returncode == 0, 'Exact synthetic NFS copy failed; no existing object was overwritten')
    verify = '''import hashlib,json,os,sys
from pathlib import Path
assert os.getuid()==21901
for item in json.load(sys.stdin):
 data=(Path('/data/jobman/alice')/item['key']).read_bytes()
 assert len(data)==item['length'] and hashlib.sha256(data).hexdigest()==item['sha256']
'''
    result = checks.ssh('control01', 'sudo -u jobman-dashboard-log python3 -c ' + shlex.quote(verify), json.dumps(objects))
    checks.require(result.returncode == 0, 'Designated broker reader cannot verify exact synthetic NFS chunks')
    denial = '''import json,os,sys
from pathlib import Path
assert os.getuid()==21002
for item in json.load(sys.stdin):
 try:(Path('/data/jobman/alice')/item['key']).read_bytes()
 except PermissionError:pass
 else:raise RuntimeError('Unrelated account unexpectedly read diagnostic log')
'''
    result = checks.ssh('control01', 'sudo -u bob python3 -c ' + shlex.quote(denial), json.dumps(objects))
    checks.require(result.returncode == 0, 'Nonreader isolation check failed')
    destination = checks.STATE / 'diagnostic-fixture.json'
    encoded = (json.dumps(fixture, indent=2) + '\n').encode()
    if destination.exists():
        checks.require(not destination.is_symlink() and destination.read_bytes() == encoded, 'Existing supplemental manifest differs')
    else:
        with destination.open('xb') as file:
            file.write(encoded)
        destination.chmod(0o600)
    print('PASS: supplemental synthetic observation job prepared; two exact NFS objects verified by broker UID, unrelated-user access denied. No original fixture, service or runtime configuration changed.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('Synthetic diagnostic preparation failed; inspect its bounded public manifest and private recovery receipt. No automatic reset or immutable overwrite was attempted.') from None
