#!/usr/bin/env python3
"""Generate only the explicitly scoped synthetic runtime configuration."""
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / '.lab' / 'dashboard'
RUNTIME = STATE / 'runtime'
APP = '/etc/jobman-dashboard-app-lab'
BROKER = '/etc/jobman-dashboard-broker-lab'
DEPLOYMENT = '72000000-0000-4000-8000-000000000001'
CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'


def private_file(name, value):
    path = RUNTIME / name
    path.write_bytes(value if isinstance(value, bytes) else value.encode())
    path.chmod(0o600)


def main():
    fixture = json.loads((STATE / 'fixture-info.json').read_text())
    oidc = json.loads((STATE / 'oidc-public.json').read_text())
    if fixture.get('synthetic') is not True or fixture['endpoint'] != 'https://10.77.0.21:18443' or len(fixture['namespaces']) != 2:
        raise RuntimeError('Unexpected fixture source')
    secrets = dict(line.split('=', 1) for line in (ROOT / '.lab/credentials/dashboard.env').read_text().splitlines() if '=' in line)
    for name in ['JOBMAN_LAB_DASHBOARD_PASSWORD', 'JOBMAN_LAB_DASHBOARD_DDL_PASSWORD', 'JOBMAN_LAB_DASHBOARD_WEB_SECRET']:
        if re.fullmatch('[0-9a-f]{64}', secrets[name]) is None:
            raise RuntimeError('Invalid synthetic credential shape')
    namespaces = [entry['id'] for entry in fixture['namespaces']]

    def control(root, role):
        return {'id': DEPLOYMENT, 'name': 'Synthetic Dashboard Lab', 'origin': fixture['endpoint'],
                'expectedInstanceId': fixture['instanceId'], 'namespaceIds': namespaces,
                'trustRootsFile': root + '/control-ca.crt', 'clientCertificateFile': root + '/control-client.crt',
                'clientKeyFile': root + '/control-client.key', 'delegationKeyFile': root + '/control-signing-key.pem',
                'delegationKeyId': 'synthetic-lab-v1' if role == 'dashboard' else 'synthetic-broker-v1',
                'serviceId': 'dashboard-lab' if role == 'dashboard' else 'dashboard-log-broker-lab',
                'audience': fixture['delegationAudience']}

    mappings = [{'deploymentId': DEPLOYMENT, 'targetGenerationId': entry['targetGenerationId'], 'storeName': 'lab-nfs', 'storeVersion': '1'} for entry in fixture['namespaces']]
    app = {'configurationRevision': 1, 'publicOrigin': 'https://dashboard.lab.test:8443', 'listen': '10.77.0.10:8443',
           'webRoot': '/usr/local/share/jobman-dashboard-lab/web',
           'serverTLS': {'certificateFile': APP + '/server.crt', 'keyFile': APP + '/server.key'},
           'databaseURLFile': APP + '/database-url',
           'oidc': {'issuer': oidc['issuer'], 'apiAudience': oidc['audience'], 'webClientId': oidc['webClientId'],
                    'webClientSecretFile': APP + '/web-client-secret', 'nativeClientId': oidc['nativeClientId'],
                    'nativeRedirectURI': 'jobman-dashboard-auth://callback', 'directoryIdClaim': oidc['directoryGuidClaim'],
                    'clientIdClaim': oidc['clientIdentityClaim'], 'trustRootsFile': CA, 'scopes': ['openid', 'profile']},
           'encryption': {'keyId': 'synthetic-lab-v1', 'keyFile': APP + '/encryption-key'},
           'controls': [control(APP, 'dashboard')],
           'logBrokers': [{'id': 'control01-nfs', 'deploymentId': DEPLOYMENT, 'origin': 'https://10.77.0.21:19443',
                           'namespaceIds': namespaces, 'trustRootsFile': CA,
                           'clientCertificateFile': APP + '/broker-client.crt', 'clientKeyFile': APP + '/broker-client.key',
                           'delegationKeyFile': APP + '/broker-signing-key.pem', 'delegationKeyId': 'synthetic-dashboard-broker-v1',
                           'serviceId': 'dashboard-lab-broker-caller', 'audience': 'urn:jobman:dashboard-lab:broker'}],
           'logMappings': [dict(value, brokerId='control01-nfs') for value in mappings]}
    broker = {'configurationRevision': 1, 'publicOrigin': 'https://10.77.0.21:19443', 'listen': '10.77.0.21:19443',
              'serverTLS': {'certificateFile': BROKER + '/server.crt', 'keyFile': BROKER + '/server.key'},
              'clientTrustRootsFile': CA, 'stateDirectory': '/var/lib/jobman-dashboard-broker-lab',
              'controls': [control(BROKER, 'broker')],
              'services': [{'keyId': 'synthetic-dashboard-broker-v1', 'serviceId': 'dashboard-lab-broker-caller',
                            'audience': 'urn:jobman:dashboard-lab:broker', 'deploymentId': DEPLOYMENT,
                            'clientCertificateFile': BROKER + '/dashboard-client.crt',
                            'publicKeyFile': BROKER + '/dashboard-signing-public.pem', 'namespaceIds': namespaces}],
              'logRoots': [dict(value, root='/data/jobman/alice') for value in mappings],
              'readerConcurrency': 4, 'readerTimeoutMilliseconds': 3000}
    for name, value in [('dashboard.json', app), ('broker.json', broker)]:
        private_file(name, json.dumps(value, indent=2) + '\n')
    for role, key, database, output in [('jobman_dashboard', 'JOBMAN_LAB_DASHBOARD_PASSWORD', 'jobman_dashboard', 'database-url'),
                                         ('jobman_dashboard_ddl', 'JOBMAN_LAB_DASHBOARD_DDL_PASSWORD', 'jobman_dashboard', 'migration-database-url')]:
        private_file(output, f'postgres://{role}:{secrets[key]}@10.77.0.20:5432/{database}?sslmode=verify-full&sslrootcert={CA}\n')
    private_file('web-client-secret', secrets['JOBMAN_LAB_DASHBOARD_WEB_SECRET'] + '\n')
    os.chmod(RUNTIME / 'encryption-key', 0o600)


if __name__ == '__main__':
    main()
