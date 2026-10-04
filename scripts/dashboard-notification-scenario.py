#!/usr/bin/env python3
"""Explicit synthetic Control cancellation and read-only notification barrier.

No agent is started, no source job is inserted through SQL, and no Dashboard
state is mutated outside its API. Retained receipts identify only two new jobs.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

DEPLOYMENT = '72000000-0000-4000-8000-000000000001'
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_fixture(value, original, receipt):
    require(isinstance(value, dict) and set(value) == {'synthetic','fixtureVersion','observationMode','helperCommit','receipt','deploymentId','controlInstanceId','recoveryEpoch','namespaceId','namespace','jobs'} and value.get('synthetic') is True
            and value.get('fixtureVersion') == 1 and value.get('observationMode') == 'normal-cancel-no-execution'
            and value.get('receipt') == receipt and value.get('deploymentId') == DEPLOYMENT
            and value.get('controlInstanceId') == original['instanceId']
            and value.get('namespace') == 'dashboard-research'
            and re.fullmatch('[1-9][0-9]{0,18}', value.get('recoveryEpoch', ''))
            and re.fullmatch('[0-9a-f]{40}', value.get('helperCommit', '')), 'Invalid synthetic scenario receipt')
    namespace = next(n['id'] for n in original['namespaces'] if n['name'] == 'dashboard-research')
    require(value.get('namespaceId') == namespace and UUID.fullmatch(namespace), 'Wrong scenario namespace')
    jobs = value.get('jobs')
    require(isinstance(jobs, list) and len(jobs) == 2 and all(isinstance(j, dict) for j in jobs) and [j.get('case') for j in jobs] == ['first', 'stopped']
            and all(set(j) == {'case', 'jobId'} and UUID.fullmatch(j['jobId']) for j in jobs)
            and jobs[0]['jobId'] != jobs[1]['jobId'], 'Invalid bounded scenario jobs')
    return value


def validate_completion(value, fixture, selected):
    job = next(j['jobId'] for j in fixture['jobs'] if j['case'] == selected)
    require(isinstance(value, dict) and set(value).issubset({'synthetic','receipt','case','deploymentId','controlInstanceId','recoveryEpoch','namespaceId','jobId','eventId','outcome','jobRevision','recordedAt','runId','executionId'}) and value.get('synthetic') is True and value.get('case') == selected
            and value.get('jobId') == job and UUID.fullmatch(value.get('eventId', ''))
            and value.get('outcome') == 'cancelled' and re.fullmatch('[1-9][0-9]{0,18}', value.get('jobRevision', ''))
            and isinstance(value.get('recordedAt'), str) and 20 <= len(value['recordedAt']) <= 40,
            'Invalid terminal event receipt')
    for key in ['receipt', 'deploymentId', 'controlInstanceId', 'recoveryEpoch', 'namespaceId']:
        require(value.get(key) == fixture[key], 'Terminal event source changed')
    for key in ['runId', 'executionId']:
        require(key not in value or UUID.fullmatch(value[key]), 'Invalid actual execution identity')
    return value


def retained_json(path, value=None):
    if value is None:
        info = path.lstat()
        require(path.is_file() and not path.is_symlink() and info.st_size <= 8192, 'Missing bounded scenario receipt')
        return json.loads(path.read_bytes())
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if path.exists():
        require(not path.is_symlink() and path.read_bytes() == raw, 'Existing immutable receipt differs')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'complete', 'settled'])
    parser.add_argument('receipt', nargs='?')
    parser.add_argument('case', nargs='?', choices=['first', 'stopped'])
    parser.add_argument('--receipt', dest='new_receipt')
    args = parser.parse_args()
    receipt = args.new_receipt if args.action == 'prepare' else args.receipt
    require(isinstance(receipt, str) and re.fullmatch('[0-9a-f]{32}', receipt)
            and (args.action == 'prepare' and args.receipt is None and args.case is None
                 or args.action != 'prepare' and args.new_receipt is None and args.case is not None), 'Explicit bounded scenario selection required')
    spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check-dashboard-infra.py'))
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    original = retained_json(checks.STATE / 'fixture-info.json')
    require(original.get('synthetic') is True and original['endpoint'] == 'https://10.77.0.21:18443'
            and UUID.fullmatch(original['instanceId']), 'Wrong original synthetic source')
    directory = checks.STATE / 'notifications'
    if not directory.exists():
        directory.mkdir(mode=0o700)
    require(directory.is_dir() and not directory.is_symlink(), 'Invalid local receipt directory')
    fixture_path = directory / (receipt + '.json')
    fixture = None if args.action == 'prepare' else validate_fixture(retained_json(fixture_path), original, receipt)
    if args.action == 'settled':
        completed = validate_completion(retained_json(directory / (receipt + '-' + args.case + '.json')), fixture, args.case)
        event, instance = completed['eventId'], completed['controlInstanceId']
        password = checks.credential('dashboard.env', 'JOBMAN_LAB_DASHBOARD_CONTROL_PASSWORD')
        source = checks.sql('jobman_dashboard_control', password,
                            f"SELECT EXISTS(SELECT 1 FROM monitoring_feed WHERE event_id='{event}'::uuid AND namespace_id='{fixture['namespaceId']}'::uuid);",
                            database='jobman_dashboard_control')
        require(source.returncode == 0 and source.stdout.strip() in ['t', 'f'], 'Source publication status unavailable')
        query = f"""SELECT EXISTS(SELECT 1 FROM dashboard_source_events e
JOIN dashboard_notification_fanout f USING(deployment_id,control_instance_id,event_id)
JOIN dashboard_event_feeds s USING(deployment_id)
WHERE e.deployment_id='{DEPLOYMENT}'::uuid AND e.control_instance_id='{instance}'::uuid AND e.event_id='{event}'::uuid
AND e.processed_at IS NOT NULL AND f.done AND s.status='active'
AND NOT EXISTS(SELECT 1 FROM dashboard_notification_evaluations n WHERE (n.deployment_id,n.control_instance_id,n.event_id)=(e.deployment_id,e.control_instance_id,e.event_id) AND n.state='pending'));"""
        dashboard = checks.sql('jobman_dashboard', checks.credential('dashboard.env', 'JOBMAN_LAB_DASHBOARD_PASSWORD'), query)
        require(dashboard.returncode == 0 and dashboard.stdout.strip() in ['t', 'f'], 'Dashboard processing status unavailable')
        print(json.dumps({'receipt': receipt, 'case': args.case, 'eventId': event,
                          'settled': source.stdout.strip() == 't' and dashboard.stdout.strip() == 't'}))
        return
    build = retained_json(checks.STATE / 'notification-helper.json')
    require(set(build) == {'revision', 'sha256', 'sourceRevision'}
            and all(re.fullmatch('[0-9a-f]{40}', build[k]) for k in ['revision', 'sourceRevision'])
            and re.fullmatch('[0-9a-f]{64}', build['sha256']), 'Reviewed exact helper manifest required')
    remote = '''import fcntl,hashlib,json,os,pwd,stat,subprocess,sys
from pathlib import Path
payload=json.load(sys.stdin);root=Path('/etc/jobman-dashboard-lab/control-fixture');base=Path('/usr/local/libexec/jobman-dashboard-lab')
st=root.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==21902 and stat.S_IMODE(st.st_mode)==0o700
assert pwd.getpwnam('jobman-dashboard-source').pw_uid==21902
assert json.loads((base/'source-current.json').read_text())['revision']==payload['build']['sourceRevision']
assert json.loads((root/'fixture-info.json').read_text())['instanceId']==payload['instance']
binary=base/('jobman-control-notification-helper-'+payload['build']['revision']);st=binary.lstat()
assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o755 and 0<st.st_size<100<<20
assert hashlib.sha256(binary.read_bytes()).hexdigest()==payload['build']['sha256']
lock=os.open(root/'.notification-operation.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
dsnSource=Path('/etc/jobman-dashboard-lab/control-database-url');st=dsnSource.lstat()
assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<16384
dsn=root/'.notification-database-url'
fd=os.open(dsn,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
 with os.fdopen(fd,'wb') as file:os.fchown(file.fileno(),21902,21902);file.write(dsnSource.read_bytes());file.flush();os.fsync(file.fileno())
 command=['runuser','-u','jobman-dashboard-source','--',str(binary),'notifications','--root',str(root),'--database-url-file',str(dsn),'--deployment-id','72000000-0000-4000-8000-000000000001','--receipt',payload['receipt'],'--action',payload['action']]
 if payload['case'] is not None:command.extend(['--case',payload['case']])
 result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
 assert result.returncode==0 and len(result.stdout)<=8192,'Scenario helper failed; preserve private pending receipt'
 json.loads(result.stdout)
 sys.stdout.buffer.write(result.stdout)
finally:dsn.unlink();os.close(lock)
'''
    payload = json.dumps({'build': build, 'receipt': receipt, 'action': args.action, 'case': args.case, 'instance': original['instanceId']})
    c = checks.CONNECTIONS['control01']
    result = checks.run(['ssh', '-i', c['ansible_ssh_private_key_file'], '-p', str(c['ansible_port']), '-o', 'BatchMode=yes',
                         '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes',
                         '-o', f'UserKnownHostsFile={checks.STATE / "known_hosts"}', '-o', 'HostKeyAlgorithms=ssh-ed25519',
                         f'{c["ansible_user"]}@{c["ansible_host"]}', 'sudo python3 -c ' + shlex.quote(remote)], payload, timeout=45)
    require(result.returncode == 0 and len(result.stdout) <= 8192, 'Reviewed source scenario failed; inspect its private receipt')
    value = json.loads(result.stdout)
    if args.action == 'prepare':
        validate_fixture(value, original, receipt)
        require(value['helperCommit'] == build['revision'], 'Helper revision differs')
        destination = fixture_path
    else:
        validate_completion(value, fixture, args.case)
        destination = directory / (receipt + '-' + args.case + '.json')
    retained_json(destination, value)
    print(json.dumps(value, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, TypeError, StopIteration, subprocess.SubprocessError):
        raise SystemExit('Synthetic notification scenario failed; inspect retained scenario receipts. No automatic reset was attempted.') from None
