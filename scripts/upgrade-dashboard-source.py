#!/usr/bin/env python3
"""Explicit forward-only upgrade of the isolated synthetic Control source."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import sys
import time

spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check-dashboard-infra.py'))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
BINARY_ROOT = '/usr/local/libexec/jobman-dashboard-lab'
FIXTURE_ROOT = '/etc/jobman-dashboard-lab/control-fixture'


def require_ok(result, message):
    checks.require(result.returncode == 0, message)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--from-revision', required=True)
    parser.add_argument('--expected-migration', required=True)
    args = parser.parse_args()
    root = args.build
    metadata = json.loads((root / 'build.json').read_text())
    revision = metadata.get('commit', metadata.get('revision', ''))
    digest = metadata.get('sha256')
    if isinstance(digest, dict):
        digest = digest.get('jobman-control')
    checks.require(root.is_absolute() and root.is_dir() and not root.is_symlink() and
                   metadata.get('platform') == 'linux/arm64' and
                   all(re.fullmatch('[0-9a-f]{40}', value) for value in [revision, args.from_revision]) and
                   re.fullmatch('[0-9]{6}_[a-z_]+[.]sql', args.expected_migration) and
                   isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid exact upgrade manifest')
    binary_path = root / 'jobman-control'
    checks.require(binary_path.is_file() and not binary_path.is_symlink() and 0 < binary_path.stat().st_size < 100 << 20,
                   'Upgrade binary must be a bounded regular file')
    binary = binary_path.read_bytes()
    checks.require(hashlib.sha256(binary).hexdigest() == digest, 'Upgrade binary digest differs')
    fixture = json.loads((checks.STATE / 'fixture-info.json').read_text())
    checks.require(fixture.get('synthetic') is True and fixture['endpoint'] == 'https://10.77.0.21:18443', 'Wrong fixture source')
    instance = fixture['instanceId']
    checks.require(re.fullmatch('[0-9a-f-]{36}', instance), 'Invalid fixture instance')
    password = checks.credential('dashboard.env', 'JOBMAN_LAB_DASHBOARD_CONTROL_PASSWORD')
    result = checks.sql('jobman_dashboard_control', password,
                        "SELECT current_database(); SELECT id::text FROM control_instance; SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid(); SELECT count(*)<1000 FROM jobs;",
                        database='jobman_dashboard_control')
    checks.require(result.returncode == 0 and result.stdout.strip() == 'jobman_dashboard_control\n' + instance + '\nt\nt',
                   'Dedicated fixture database/instance/TLS/size preflight failed')
    staged = BINARY_ROOT + '/.control-upgrade-' + revision
    preflight = '''import json,os,stat
from pathlib import Path
from urllib.parse import urlparse,parse_qs
root=Path(ROOT);binary_root=Path(BINARY_ROOT)
assert not list(root.glob('.directory-acceptance-*.json')),'Pending directory recovery receipt'
info=json.loads((root/'fixture-info.json').read_text())
assert info['synthetic'] is True and info['instanceId']==INSTANCE
current=binary_root/'source-current.json'
if not current.exists():current=binary_root/'build.json'
assert json.loads(current.read_text())['revision']==FROM_REVISION,'Current source revision differs'
path=root/'control.env';st=path.lstat()
assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==21902
values=dict((name,json.loads(value)) for name,value in (line.split('=',1) for line in path.read_text().splitlines()))
url=urlparse(values['JOBMAN_CONTROL_DATABASE_URL'])
assert url.scheme in ('postgres','postgresql') and url.username=='jobman_dashboard_control' and url.hostname=='10.77.0.20' and url.port==5432 and url.path=='/jobman_dashboard_control' and parse_qs(url.query).get('sslmode')==['verify-full']
assert values['JOBMAN_CONTROL_DIRECTORY_CONFIG_FILE']==str(root/'directory.json') and values['JOBMAN_CONTROL_DIRECTORY_MODE']=='enforce' and values['JOBMAN_CONTROL_MIGRATE_ON_START']=='false'
'''
    values = {'ROOT': repr(FIXTURE_ROOT), 'BINARY_ROOT': repr(BINARY_ROOT), 'INSTANCE': repr(instance), 'FROM_REVISION': repr(args.from_revision)}
    for key in sorted(values, key=len, reverse=True):
        preflight = preflight.replace(key, values[key])
    require_ok(checks.ssh('control01', 'sudo python3 -', preflight), 'Private source configuration preflight failed')
    print('PASS: exact build, restored synthetic state, dedicated TLS database and pinned source instance preflight')
    upload = '''import base64,hashlib,json,os,sys
payload=json.load(sys.stdin);data=base64.b64decode(payload['binary'],validate=True)
assert hashlib.sha256(data).hexdigest()==payload['sha256']
fd=os.open(payload['path'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
'''
    payload = json.dumps({'path': staged, 'sha256': digest, 'binary': base64.b64encode(binary).decode()})
    require_ok(checks.ssh('control01', 'sudo python3 -c ' + shlex.quote(upload), payload), 'Upgrade staging failed; source unchanged')
    require_ok(checks.ssh('control01', 'sudo systemctl stop jobman-dashboard-lab-control'), 'Could not stop isolated source')
    migration = '''import json,os,subprocess
from pathlib import Path
assert os.geteuid()==21902
root=Path(ROOT)
values=dict((name,json.loads(value)) for name,value in (line.split('=',1) for line in (root/'control.env').read_text().splitlines()))
values.update(LANG='C',PATH='/usr/bin:/bin',JOBMAN_CONTROL_MIGRATE_ON_START='true',JOBMAN_CONTROL_DIRECTORY_MODE='preview')
result=subprocess.run([STAGED],env=values,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
assert result.returncode==0,'Scoped preview migration failed; source remains stopped for inspection'
'''.replace('ROOT', repr(FIXTURE_ROOT)).replace('STAGED', repr(staged))
    require_ok(checks.ssh('control01', 'sudo -u jobman-dashboard-source python3 -', migration),
               'Scoped preview migration failed; inspect isolated source, do not reset or downgrade')
    result = checks.sql('jobman_dashboard_control', password,
                        "SELECT current_database(); SELECT id::text FROM control_instance; SELECT max(version) FROM schema_migrations;",
                        database='jobman_dashboard_control')
    checks.require(result.returncode == 0 and result.stdout.strip() == 'jobman_dashboard_control\n' + instance + '\n' + args.expected_migration,
                   'Post-migration ledger or source identity differs; isolated source remains stopped')
    install = '''import json,os
from pathlib import Path
root=Path(ROOT);binary=root/'jobman-control';backup=root/('jobman-control.before-'+FROM_REVISION)
if not backup.exists():os.link(binary,backup)
os.replace(STAGED,binary)
current=root/'source-current.json';temporary=root/'.source-current.pending'
with temporary.open('x') as stream:json.dump(METADATA,stream);stream.write('\\n');stream.flush();os.fsync(stream.fileno())
os.chmod(temporary,0o644);os.replace(temporary,current)
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(fd)
finally:os.close(fd)
'''.replace('FROM_REVISION', repr(args.from_revision)).replace('ROOT', repr(BINARY_ROOT)).replace('STAGED', repr(staged)).replace('METADATA', repr({'revision': revision, 'sha256': digest, 'migration': args.expected_migration}))
    require_ok(checks.ssh('control01', 'sudo python3 -', install), 'New source installation needs inspection')
    require_ok(checks.ssh('control01', 'sudo systemctl start jobman-dashboard-lab-control'), 'Upgraded isolated source did not start')
    result = require_ok(checks.ssh('control01', 'sudo systemctl is-active jobman-dashboard-lab-control jobman-dashboard-lab-directory jobman-control jobman-keycloak'), 'A required source/issuer unit is not active')
    checks.require(result.stdout.split() == ['active'] * 4, 'A required source/issuer unit is not active')
    ready = False
    for attempt in range(5):
        result = checks.ssh('control01', 'sudo -u jobman-dashboard-source curl --silent --fail --max-time 3 --cacert /etc/jobman-dashboard-lab/control-fixture/fixture-ca.crt https://127.0.0.1:18443/v1/capabilities')
        if result.returncode == 0 and len(result.stdout) < 65536:
            capability = json.loads(result.stdout).get('capabilities', {})
            if capability.get('instanceId') == instance:
                ready = True
                break
        if attempt < 4:
            time.sleep(1)
    checks.require(ready, 'Upgraded source did not pass verified-TLS identity readiness')
    print('PASS: isolated source upgraded to ' + revision + '; migration ' + args.expected_migration + '; source identity preserved')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError):
        raise SystemExit('Isolated source upgrade failed; inspect its staged binary, private configuration and database ledger. No automatic reset or downgrade was attempted.') from None
