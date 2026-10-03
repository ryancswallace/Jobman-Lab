#!/usr/bin/env python3
"""Bounded synthetic TLS, role-isolation, and NFS reader ACL checks.

Passwords are loaded from ignored Lab files and sent through SSH stdin only.
No role passwords, credentials or log bytes are emitted. Created SQL/filesystem
probes use unique names and are removed in finally blocks; existing data stays.
"""
import base64
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / '.lab' / 'dashboard'
CONNECTIONS = json.loads((STATE / 'ssh-connections.json').read_text())


def run(args, payload=None, timeout=25):
    return subprocess.run(args, input=payload, text=True, capture_output=True,
                          timeout=timeout, cwd=ROOT, check=False)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def ssh(host, command, payload=None):
    c = CONNECTIONS[host]
    return run(['ssh', '-i', c['ansible_ssh_private_key_file'], '-p', str(c['ansible_port']),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes',
                '-o', f'UserKnownHostsFile={STATE / "known_hosts"}',
                '-o', 'HostKeyAlgorithms=ssh-ed25519',
                f'{c["ansible_user"]}@{c["ansible_host"]}', command], payload)


def credential(filename, name):
    text = (ROOT / '.lab' / 'credentials' / filename).read_text()
    result = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)[name]
    require(bool(re.fullmatch('[0-9a-f]{48,64}', result)), 'Synthetic password has unexpected format')
    return result


def sql(user, password, query, database='jobman_dashboard', ssl='verify-full', host='127.0.0.1'):
    args = ['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-U', user, '-d', database, '-h', host]
    command = 'IFS= read -r PGPASSWORD; export PGPASSWORD; ' + shlex.join([
        'env', f'PGSSLMODE={ssl}', 'PGSSLROOTCERT=/var/lib/postgresql/data/dashboard-tls/ca.crt',
        'PGCONNECT_TIMEOUT=8']) + ' ' + shlex.join(args)
    return ssh('pg01', 'sudo podman exec -i jobman-postgres sh -c ' + shlex.quote(command), password+'\n'+query+'\n')


def database_checks():
    ca = ROOT / '.lab' / 'certs' / 'lab-ca.crt'
    tls = ['openssl', 's_client', '-starttls', 'postgres', '-connect', '10.77.0.20:5432',
           '-CAfile', str(ca), '-verify_return_error']
    require(run(tls + ['-verify_ip', '10.77.0.20'], '', 12).returncode == 0,
            'Host PostgreSQL TLS verification failed')
    require(run(tls + ['-verify_hostname', 'wrong-host.invalid'], '', 12).returncode != 0,
            'Incorrect PostgreSQL hostname was accepted')
    runtime = credential('dashboard.env', 'JOBMAN_LAB_DASHBOARD_PASSWORD')
    ddl = credential('dashboard.env', 'JOBMAN_LAB_DASHBOARD_DDL_PASSWORD')
    control = credential('lab.env', 'JOBMAN_LAB_POSTGRES_PASSWORD')
    fixture = credential('dashboard.env', 'JOBMAN_LAB_DASHBOARD_CONTROL_PASSWORD')
    users = [('jobman_dashboard', runtime), ('jobman_dashboard_ddl', ddl)]
    for user, password in users:
        check = sql(user, password, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid(); SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication FROM pg_roles WHERE rolname=current_user;")
        require(check.returncode == 0 and check.stdout.strip() == 't\nt', f'{user} TLS/privilege check failed')
        require(sql(user, password, 'SELECT 1;', ssl='disable').returncode != 0,
                f'{user} accepted plaintext authentication')
        require(sql(user, password, 'SELECT 1;', database='jobman_control').returncode != 0,
                f'{user} can connect to the Control database')
    require(sql('jobman_control', control, 'SELECT 1;', database='jobman_control',
                ssl='disable', host='10.77.0.20').returncode == 0,
            'Existing Control plaintext test connection no longer works')
    check = sql('jobman_dashboard_control', fixture,
                "SELECT current_database(); SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid(); SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication FROM pg_roles WHERE rolname=current_user;",
                database='jobman_dashboard_control')
    require(check.returncode == 0 and check.stdout.strip() == 'jobman_dashboard_control\nt\nt',
            'Isolated Control fixture database TLS/identity check failed')
    for forbidden in ['jobman_control', 'jobman_dashboard']:
        require(sql('jobman_dashboard_control', fixture, 'SELECT 1;', database=forbidden).returncode != 0,
                'Fixture identity can connect to another database')
    require(sql('jobman_dashboard_control', fixture, 'SELECT 1;', database='jobman_dashboard_control', ssl='disable').returncode != 0,
            'Fixture identity accepted plaintext authentication')
    table = 'dashboard_lab_probe_' + uuid.uuid4().hex
    try:
        setup = sql('jobman_dashboard_ddl', ddl,
                    f'CREATE TABLE public.{table} (value integer); GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO jobman_dashboard;')
        require(setup.returncode == 0, 'DDL role could not create its disposable probe')
        check = sql('jobman_dashboard', runtime, f'INSERT INTO public.{table} VALUES (7); SELECT value FROM public.{table}; DELETE FROM public.{table};')
        require(check.returncode == 0 and '\n7\n' in '\n'+check.stdout,
                'Runtime role could not perform permitted DML')
        require(sql('jobman_dashboard', runtime, f'BEGIN; CREATE TABLE public.{table}_forbidden (id integer); ROLLBACK;').returncode != 0,
                'Runtime role unexpectedly has schema CREATE')
        require(sql('jobman_dashboard', runtime, f'BEGIN; ALTER TABLE public.{table} ADD COLUMN forbidden integer; ROLLBACK;').returncode != 0,
                'Runtime role unexpectedly owns DDL tables')
        require(sql('jobman_dashboard', runtime, 'BEGIN; SET ROLE jobman_dashboard_ddl; ROLLBACK;').returncode != 0,
                'Runtime role can assume the migration identity')
        require(sql('jobman_dashboard_ddl', ddl, 'BEGIN; SET ROLE jobman_control; ROLLBACK;').returncode != 0,
                'DDL role can assume the Control identity')
    finally:
        cleanup = sql('jobman_dashboard_ddl', ddl, f'DROP TABLE IF EXISTS public.{table};')
        require(cleanup.returncode == 0, 'Disposable database probe cleanup failed')
    print('PASS: host TLS/SAN verification, TLS-only SCRAM roles, runtime DML without DDL, database/role isolation, existing Control connection.')


def acl_checks():
    name = '.dashboard-acl-probe-' + uuid.uuid4().hex
    server = '/srv/lab/data/jobman/alice/' + name
    client = '/data/jobman/alice/' + name
    create = f'''import os
p={server!r}
os.umask(0o077)
os.mkdir(p,0o750)
for name,mode in [('readable',0o640),('masked',0o600)]:
 fd=os.open(p+'/'+name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
 os.write(fd,b'synthetic-dashboard-acl-probe\\n');os.close(fd)
for name,mode in [('traversable',0o750),('masked-dir',0o700)]:os.mkdir(p+'/'+name,mode)
'''
    try:
        result = ssh('storage01', 'sudo -u alice python3 -', create)
        require(result.returncode == 0, 'Could not create disposable ACL fixtures')
        mask_probe = f'''import importlib.machinery,importlib.util,os,subprocess
p={server!r}
loader=importlib.machinery.SourceFileLoader('acl_policy','/usr/local/sbin/jobman-dashboard-provision-acls')
spec=importlib.util.spec_from_loader(loader.name,loader);policy=importlib.util.module_from_spec(spec);loader.exec_module(policy)
file=p+'/mask-regression';open(file,'w').close()
os.mkdir(p+'/mask-regression-dir',0o700)
subprocess.run(['setfacl','-m','u:21901:r-x,u:21002:rwx,g::rwx,m::r--',file],check=True)
subprocess.run(['setfacl','-m','d:u:21901:r-x,d:u:21002:rwx,d:g::rwx,d:m::r--',p+'/mask-regression-dir'],check=True)
for target in [file,p+'/mask-regression-dir']:
 before=policy.acl(target);policy.remove_reader(target,before);after=policy.acl(target)
 expected=[entry for entry in before if not entry.startswith(('user:21901:','default:user:21901:'))]
 assert after==expected,'Removing reader changed an unrelated ACL or mask'
'''
        result = ssh('storage01', 'sudo -u alice python3 -', mask_probe)
        require(result.returncode == 0, 'Named-reader removal changed unrelated effective access/default ACL masks')
        result = ssh('control01', 'sudo -u jobman-dashboard-log test -r ' + shlex.quote(client+'/readable'))
        require(result.returncode == 0, 'Reader cannot read inherited0640 log fixture over NFS')
        for user, path, permission in [('jobman-dashboard-log', 'readable', '-w'),
                                      ('bob', 'readable', '-r'),
                                      ('jobman-dashboard-log', 'masked', '-r'),
                                      ('jobman-dashboard-log', 'masked-dir', '-x')]:
            result = ssh('control01', f'sudo -u {user} test {permission} '+shlex.quote(client+'/'+path))
            require(result.returncode == 1, f'Unexpected ACL access: {user} {permission} {path}')
        result = ssh('control01', 'sudo test -r ' + shlex.quote(client+'/readable'))
        require(result.returncode == 1, 'NFS root squash did not deny root read')
        probe = f'''import os,json,base64,stat
p={client!r};out={{}}
for name in ['.','readable','masked','traversable','masked-dir']:
 path=p+'/'+name;s=os.stat(path);x={{}}
 for attr in ['system.nfs4_acl','system.posix_acl_access','system.posix_acl_default']:
  try:x[attr]={{'base64':base64.b64encode(os.getxattr(path,attr)).decode()}}
  except OSError as e:x[attr]={{'errno':e.errno}}
 out[name]={{'mode':oct(stat.S_IMODE(s.st_mode)),'uid':s.st_uid,'gid':s.st_gid,'xattrs':x}}
print(json.dumps(out))
'''
        result = ssh('control01', 'sudo -u alice python3 -', probe)
        require(result.returncode == 0, 'Could not inspect client ACL evidence')
        evidence = {'client':json.loads(result.stdout)}
        result = ssh('storage01', 'sudo getfacl -n -R -p ' + shlex.quote(server))
        require(result.returncode == 0, 'Could not inspect server ACL evidence')
        evidence['server_posix_acl'] = result.stdout
        (STATE/'acl-probe.json').write_text(json.dumps(evidence,indent=2)+'\n')
        os.chmod(STATE/'acl-probe.json',0o600)
        print('PASS: inherited0640/0750 reader access over NFS; no reader write, no Bob read, root_squash retained;0600/0700 correctly remain masked.')
        print('Producer opt-in remains required. Non-secret ACL evidence: .lab/dashboard/acl-probe.json')
    finally:
        # Delete only the unpredictable subtree created by this invocation.
        result = ssh('storage01', 'sudo -u alice python3 -', f'import shutil; shutil.rmtree({server!r},ignore_errors=True)\n')
        require(result.returncode == 0, 'Disposable ACL probe cleanup failed')


if __name__ == '__main__':
    try:
        database_checks()
        acl_checks()
        identity = ssh('control01', 'sudo python3 /usr/local/libexec/jobman-dashboard-lab/configure-identity.py --check')
        require(identity.returncode == 0, 'Dashboard OIDC policy check failed')
        print(identity.stdout.strip())
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f'Dashboard infrastructure check failed: {error}',file=sys.stderr)
        sys.exit(1)
