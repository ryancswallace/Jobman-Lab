#!/usr/bin/env python3
"""Pure additive secondary-source configuration planner; no credential or I/O work."""
import copy
import hashlib
import json
import re

PRIMARY = '72000000-0000-4000-8000-000000000001'
SECONDARY = '72000000-0000-4000-8000-000000000002'
PRIMARY_INSTANCE = 'e633cf92-258d-48ff-965a-fda88d68ef3a'
SECONDARY_INSTANCE = 'a4f0e2ab-7323-4c90-9510-1f073c660f06'
BROKER_ID = '76000000-0000-4000-8000-000000000002'
ROOTS = {'api': '/etc/jobman-dashboard-api-lab', 'worker': '/etc/jobman-dashboard-worker-lab',
         'broker': '/etc/jobman-dashboard-broker-lab', 'operator': '/etc/jobman-dashboard-operator-lab'}
SOURCE_ROOT = '/etc/jobman-dashboard-secondary/control'
SOURCE_AUDIENCE = 'urn:jobman:dashboard-lab-secondary:control'
BROKER_AUDIENCE = 'urn:jobman:dashboard-lab-secondary:logs'
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')


def require(value, message):
    if not value:
        raise ValueError(message)


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON member')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number')))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_entry(role, namespaces):
    names = {'api': ('dashboard-api-lab-secondary', 'secondary-api-v1'),
             'worker': ('dashboard-worker-lab-secondary', 'secondary-worker-v1'),
             'broker': ('dashboard-log-broker-lab-secondary', 'secondary-broker-v1')}
    service, key = names[role]
    return {'id': SECONDARY, 'name': 'Synthetic secondary Control', 'origin': 'https://10.77.0.21:28443',
            'expectedInstanceId': SECONDARY_INSTANCE, 'namespaceIds': namespaces,
            'trustRootsFile': ROOTS[role] + '/secondary-control-ca.crt',
            'clientCertificateFile': ROOTS[role] + '/secondary-control-client.crt',
            'clientKeyFile': ROOTS[role] + '/secondary-control-client.key',
            'delegationKeyFile': ROOTS[role] + '/secondary-control-signing-key.pem',
            'delegationKeyId': key, 'serviceId': service, 'audience': SOURCE_AUDIENCE}


def patch(configs, fixture, *, expected_revision=6):
    require(set(configs) == {'api', 'worker', 'broker', 'operator'} and expected_revision == 6,
            'Only the reviewed revision6 split snapshot can be extended')
    require(fixture.get('synthetic') is True and fixture.get('profile') == 'secondary-v1' and
            fixture.get('instanceId') == SECONDARY_INSTANCE and fixture.get('endpoint') == 'https://10.77.0.21:28443' and
            fixture.get('delegationAudience') == SOURCE_AUDIENCE, 'Wrong verified secondary source')
    scopes = fixture['namespaces']
    require(len(scopes) == 2 and {s['name'] for s in scopes} == {'dashboard-research', 'dashboard-operations'} and
            all(UUID.fullmatch(s['id']) and UUID.fullmatch(s['targetGenerationId']) for s in scopes), 'Secondary namespace/target identity differs')
    namespaces = sorted(s['id'] for s in scopes)
    require(len(set(namespaces)) == 2 and len({s['targetGenerationId'] for s in scopes}) == 2, 'Duplicate secondary identity')
    api, worker, broker, operator = (configs[role] for role in ('api', 'worker', 'broker', 'operator'))
    require(api.get('publicOrigin') == 'https://dashboard.lab.test:8443' and api.get('listen') == '10.77.0.10:8443' and
            api.get('events', {}).get('enabled') is True and api['events'].get('deliveryHold') is False and
            worker.get('deliveryHold') is False, 'Expected resumed split runtime')
    require(broker.get('listen') == '10.77.0.21:19443' and broker.get('publicOrigin') == 'https://10.77.0.21:19443' and
            broker.get('stateDirectory') == '/var/lib/jobman-dashboard-broker-lab', 'Wrong existing broker')
    require(operator.get('schemaVersion') == 1 and operator.get('databaseURLFile') == ROOTS['operator'] + '/database-url' and
            len(operator.get('deployments', [])) == 1 and operator['deployments'][0]['id'] == PRIMARY, 'Operator source set differs')
    for role in ('api', 'worker', 'broker'):
        config = configs[role]
        require(type(config.get('configurationRevision')) is int and config['configurationRevision'] == expected_revision and
                len(config.get('controls', [])) == 1 and config['controls'][0]['id'] == PRIMARY and
                config['controls'][0]['origin'] == 'https://10.77.0.21:18443' and
                config['controls'][0]['expectedInstanceId'] == PRIMARY_INSTANCE, 'Primary source/revision changed')
    for role in ('api', 'worker'):
        entries = configs[role].get('logBrokers', [])
        require(len(entries) == 1 and entries[0]['deploymentId'] == PRIMARY and entries[0]['origin'] == 'https://10.77.0.21:19443' and
                entries[0]['id'] != BROKER_ID, 'Existing remote broker differs')
        require(configs[role].get('databaseURLFile') == ROOTS[role] + '/database-url', 'Wrong split database boundary')
        require(all(m['deploymentId'] == PRIMARY for m in configs[role]['logMappings']), 'Unexpected existing mapping source')
    require(all(m['deploymentId'] == PRIMARY for m in broker['logRoots']) and
            all(s['deploymentId'] == PRIMARY for s in broker['services']), 'Unexpected broker source/registration')
    old_maps = lambda rows: {(m['deploymentId'], m['targetGenerationId'], m['storeName'], m['storeVersion']) for m in rows}
    require(old_maps(api['logMappings']) == old_maps(worker['logMappings']) == old_maps(broker['logRoots']) and
            len(api['logMappings']) == len(worker['logMappings']) == len(broker['logRoots']), 'Existing mapping sets differ')
    result = copy.deepcopy(configs)
    for role in ('api', 'worker', 'broker'):
        result[role]['configurationRevision'] = expected_revision + 1
        result[role]['controls'].append(source_entry(role, namespaces))
    mappings = [{'deploymentId': SECONDARY, 'targetGenerationId': scope['targetGenerationId'], 'storeName': 'lab-nfs', 'storeVersion': '1'} for scope in sorted(scopes, key=lambda s: s['id'])]
    for role in ('api', 'worker'):
        root = ROOTS[role]
        result[role]['logBrokers'].append({'id': BROKER_ID, 'deploymentId': SECONDARY, 'origin': 'https://10.77.0.21:19443',
            'namespaceIds': namespaces, 'trustRootsFile': configs[role]['logBrokers'][0]['trustRootsFile'],
            'clientCertificateFile': root + '/secondary-broker-client.crt', 'clientKeyFile': root + '/secondary-broker-client.key',
            'delegationKeyFile': root + '/secondary-broker-signing-key.pem', 'delegationKeyId': 'secondary-' + role + '-broker-v1',
            'serviceId': 'dashboard-' + role + '-lab-secondary-broker', 'audience': BROKER_AUDIENCE})
        result[role]['logMappings'].extend(dict(m, brokerId=BROKER_ID) for m in mappings)
        result['broker']['services'].append({'keyId': 'secondary-' + role + '-broker-v1', 'serviceId': 'dashboard-' + role + '-lab-secondary-broker',
            'audience': BROKER_AUDIENCE, 'deploymentId': SECONDARY, 'namespaceIds': namespaces,
            'clientCertificateFile': ROOTS['broker'] + '/secondary-' + role + '-client.crt',
            'publicKeyFile': ROOTS['broker'] + '/secondary-' + role + '-signing-public.pem'})
    result['broker']['logRoots'].extend(dict(m, root='/data/jobman/alice/dashboard-secondary') for m in mappings)
    result['broker']['clientTrustRootsFile'] = ROOTS['broker'] + '/secondary-client-ca-bundle.crt'
    result['operator']['deployments'].append({'id': SECONDARY, 'name': 'Synthetic secondary Control'})
    return result


def material_plan(configs):
    copies = []
    for role, prefix in [('api', 'dashboard'), ('worker', 'worker'), ('broker', 'broker')]:
        for source, target in [('fixture-ca.crt', 'secondary-control-ca.crt'), (prefix + '-client.crt', 'secondary-control-client.crt'),
                               (prefix + '-client.key', 'secondary-control-client.key'), (prefix + '-signing-key.pem', 'secondary-control-signing-key.pem')]:
            copies.append({'source': SOURCE_ROOT + '/' + source, 'destination': ROOTS[role] + '/' + target,
                           'role': role, 'private': not source.endswith('.crt')})
    return {'copyOnly': copies, 'newBrokerCallers': [{'role': role, 'uid': 21904 if role == 'api' else 21905,
             'signing': 'fresh Ed25519', 'tls': 'fresh clientAuth-only certificate signed by secondary fixture CA',
             'serviceId': 'dashboard-' + role + '-lab-secondary-broker', 'keyId': 'secondary-' + role + '-broker-v1'} for role in ('api', 'worker')],
            'brokerClientTrust': {'originalPath': configs['broker']['clientTrustRootsFile'], 'additionalPublicCA': SOURCE_ROOT + '/fixture-ca.crt',
             'destination': ROOTS['broker'] + '/secondary-client-ca-bundle.crt', 'operation': 'preserve original bytes and append only verified secondary public CA'},
            'prohibitedCopies': ['fixture-ca.key', 'control.env', 'control-database-url', 'directory-password', 'directory-server.key']}
