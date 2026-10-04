#!/usr/bin/env python3
"""Bounded read-only readiness checks for the isolated synthetic Dashboard stack.

Uses pinned Lab SSH and verified TLS. Does not authenticate an application user,
print secrets, or replace separate end-to-end identity/authorization acceptance.
"""
import argparse
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check-dashboard-infra.py'))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports', action='store_true')
    parser.add_argument('--notifications', action='store_true')
    args = parser.parse_args()
    for host, units in [
        ('control01', [('jobman-dashboard-lab-directory', 'jobman-dashboard-source', '21902'),
                       ('jobman-dashboard-lab-control', 'jobman-dashboard-source', '21902'),
                       ('jobman-dashboard-lab-broker', 'jobman-dashboard-log', '21901')]),
        ('storage01', [('jobman-dashboard-lab-app', 'jobman-dashboard-app', '21903')]),
    ]:
        for unit, user, uid in units:
            result = checks.ssh(host, 'sudo systemctl show ' + unit + ' --property=ActiveState,User,ExecMainStatus --no-pager')
            values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            checks.require(result.returncode == 0 and values.get('ActiveState') == 'active' and
                           values.get('User') == user and values.get('ExecMainStatus') == '0',
                           'Isolated service is not healthy under its assigned identity: ' + unit)
            result = checks.ssh(host, 'id -u ' + user)
            checks.require(result.returncode == 0 and result.stdout.strip() == uid, 'Unexpected service UID')
    for unit in ['jobman-control', 'jobman-keycloak']:
        result = checks.ssh('control01', 'sudo systemctl is-active ' + unit)
        checks.require(result.returncode == 0 and result.stdout.strip() == 'active', 'Original service is not active')
    print('PASS: isolated services active under assigned non-root UIDs; original Control and Keycloak remain active')
    ca = str(checks.ROOT / '.lab/certs/lab-ca.crt')
    curl = ['curl', '--silent', '--show-error', '--max-time', '10', '--cacert', ca,
            '--resolve', 'dashboard.lab.test:8443:10.77.0.10']
    result = checks.run(curl + ['--fail', 'https://dashboard.lab.test:8443/'])
    checks.require(result.returncode == 0 and '<div id="root">' in result.stdout, 'Dashboard verified-TLS static request failed')
    result = checks.run(curl + ['--output', '/dev/null', '--write-out', '%{http_code}',
                                'https://dashboard.lab.test:8443/api/v1/bootstrap'])
    checks.require(result.returncode == 0 and result.stdout == '401', 'Dashboard API accepted unauthenticated access')
    # First prove the broker server certificate, then require client authentication.
    result = checks.run(['openssl', 's_client', '-connect', '10.77.0.21:19443', '-CAfile', ca,
                         '-verify_return_error', '-verify_ip', '10.77.0.21'], '', 12)
    checks.require('Verification: OK' in result.stdout, 'Broker server TLS trust verification failed')
    result = checks.run(['curl', '--silent', '--max-time', '10', '--cacert', ca, 'https://10.77.0.21:19443/'])
    checks.require(result.returncode in [35, 55, 56], 'Broker did not reject missing TLS client identity')
    print('PASS: verified TLS serves the app; unauthenticated API and uncertified broker callers are denied')
    result = checks.ssh('storage01', 'sudo test ! -e /etc/jobman-dashboard-app-lab/migration-database-url')
    checks.require(result.returncode == 0, 'Transient migration credential remains on guest')
    password = checks.credential('dashboard.env', 'JOBMAN_LAB_DASHBOARD_PASSWORD')
    query = "SELECT current_user, current_database(); SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid(); SELECT has_table_privilege(current_user,'dashboard_schema_migrations','SELECT'),has_table_privilege(current_user,'dashboard_schema_migrations','INSERT'),has_table_privilege(current_user,'dashboard_schema_migrations','UPDATE'),has_table_privilege(current_user,'dashboard_schema_migrations','DELETE');"
    result = checks.sql('jobman_dashboard', password, query)
    checks.require(result.returncode == 0 and result.stdout.strip() == 'jobman_dashboard|jobman_dashboard\nt\nt|f|f|f',
                   'Runtime identity, TLS or migration-ledger rights are incorrect')
    print('PASS: runtime database TLS and SELECT-only migration ledger; transient DDL credential absent')
    if args.notifications:
        script = """import json
from pathlib import Path
config=json.loads(Path('/etc/jobman-dashboard-app-lab/config.json').read_text())
assert config['events']=={'enabled':True,'deliveryHold':False}
assert config['notifications']=={'deviceTopics':[{'topic':'org.jobman.dashboard','environment':'sandbox'}],'previousTokenKeys':[],'apns':[]}
"""
        result = checks.ssh('storage01', 'sudo -u jobman-dashboard-app python3 -', script)
        checks.require(result.returncode == 0, 'Synthetic notification mode is absent or includes an unexpected provider')
        query = "SELECT count(*) FROM dashboard_schema_migrations WHERE name IN ('migrations/000007_notification_rules.sql','migrations/000012_notification_evaluation.sql','migrations/000013_notification_device_revocations.sql','migrations/000014_notification_delivery.sql','migrations/000017_notification_retention.sql'); SELECT bool_and(has_table_privilege(current_user,table_name,privilege)) FROM (VALUES ('dashboard_notification_rules'),('dashboard_notification_inbox'),('dashboard_notification_deliveries'),('dashboard_notification_activation_work'),('dashboard_notification_retention_progress')) AS tables(table_name) CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) AS rights(privilege); SELECT count(*)=1 AND bool_and(status='active') FROM dashboard_event_feeds;"
        result = checks.sql('jobman_dashboard', password, query)
        checks.require(result.returncode == 0 and result.stdout.strip() == '5\nt\nt', 'Notification migrations, runtime grants or initial source feed are unavailable')
        print('PASS: durable event/device mode, current runtime table grants and active source feed; no APNs provider is configured')
    if args.reports:
        script = """import json,stat
from pathlib import Path
root=Path('/var/lib/jobman-dashboard-app-lab/reports')
for path in [root.parent,root]:
 st=path.lstat();assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode)==0o700 and st.st_uid==21903
policy=Path('/etc/jobman-dashboard-app-lab/redaction.json');st=policy.lstat()
assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==21903 and st.st_size<4096
value=json.loads(policy.read_text());assert set(value)=={'values','patterns'} and len(value['values'])==1 and value['patterns']==[]
config=json.loads(Path('/etc/jobman-dashboard-app-lab/config.json').read_text())
assert config['reports']=={'objectRoot':str(root),'redactionFile':str(policy)}
"""
        result = checks.ssh('storage01', 'sudo -u jobman-dashboard-app python3 -', script)
        checks.require(result.returncode == 0, 'Report object root, policy mode, owner or configuration is incorrect')
        result = checks.ssh('storage01', 'sudo systemctl show jobman-dashboard-lab-app --property=ReadWritePaths --value')
        checks.require(result.returncode == 0 and result.stdout.strip() == '/var/lib/jobman-dashboard-app-lab/reports',
                       'Report service filesystem write allowance differs')
        query = "SELECT name FROM dashboard_schema_migrations WHERE name='migrations/000005_report_queue.sql'; SELECT bool_and(has_table_privilege(current_user, table_name, privilege)) FROM (VALUES ('dashboard_report_tasks'),('dashboard_report_requesters'),('dashboard_report_idempotency')) AS tables(table_name) CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) AS rights(privilege);"
        result = checks.sql('jobman_dashboard', password, query)
        checks.require(result.returncode == 0 and result.stdout.strip() == 'migrations/000005_report_queue.sql\nt',
                       'Report migration or dedicated runtime table rights are absent')
        print('PASS: private report object root and synthetic policy; narrow service write allowance; report migration and runtime table rights')


if __name__ == '__main__':
    main()
