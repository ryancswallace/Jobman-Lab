#!/usr/bin/env python3
"""Bounded read-only readiness checks for the isolated synthetic Dashboard stack.

Uses pinned Lab SSH and verified TLS. Does not authenticate an application user,
print secrets, or replace separate end-to-end identity/authorization acceptance.
"""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check-dashboard-infra.py'))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def main():
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


if __name__ == '__main__':
    main()
