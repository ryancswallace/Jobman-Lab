#!/usr/bin/env python3
"""Pure post-seed synthetic scale scope planner. No I/O or apply entry point."""
import copy
import re

PRIMARY = '72000000-0000-4000-8000-000000000001'
SECONDARY = '72000000-0000-4000-8000-000000000002'
INSTANCES = {PRIMARY: 'e633cf92-258d-48ff-965a-fda88d68ef3a',
             SECONDARY: 'a4f0e2ab-7323-4c90-9510-1f073c660f06'}
ISSUER = 'https://oidc.lab.test:8443/realms/jobman-lab'
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')


def need(value, message):
    if not value:
        raise ValueError(message)


def ids(values, count):
    need(isinstance(values, list) and len(values) == count and
         all(isinstance(value, str) and UUID.fullmatch(value) for value in values) and
         len(set(values)) == count, 'Distinct bounded namespace IDs required')
    return sorted(values)


def seed_scopes(seeds):
    need(set(seeds) == set(INSTANCES), 'Both fixed synthetic sources required')
    scopes, users = {}, None
    for deployment, instance in INSTANCES.items():
        seed = seeds[deployment]
        count = 10 if deployment == PRIMARY else 5
        need(seed.get('version') == 1 and seed.get('synthetic') is True and
             seed.get('mode') == 'imported-history-no-execution' and
             seed.get('deploymentId') == deployment and seed.get('instanceId') == instance and
             seed.get('recoveryEpoch') == '1', 'Verified synthetic scale receipt required')
        rows = seed['namespaces']
        need(len(rows) == count, 'Scale namespace count differs')
        scopes[deployment] = ids([row['id'] for row in rows], count)
        for index, row in enumerate(rows):
            need(row['name'] == 'dashboard-scale-%02d' % (index+1) and
                 row['activeJobs'] == 50 and row['importedHistory'] == 10000 and
                 UUID.fullmatch(row['activeJobId']) and UUID.fullmatch(row['importedJobId']) and
                 row['activeJobId'] != row['importedJobId'], 'Scale metadata envelope differs')
        identities = seed['identities']
        need(len(identities) == 25, 'Exactly25 prepared principals required')
        normalized = []
        for index, identity in enumerate(identities):
            need(identity['directoryId'] == '74000000-0000-4000-8000-%012d' % (index+1) and
                 identity['issuer'] == ISSUER and UUID.fullmatch(identity['subject']) and
                 UUID.fullmatch(identity['principalId']) and
                 identity['displayName'] == 'Synthetic scale %02d' % (index+1), 'Scale identity differs')
            normalized.append((identity['directoryId'], identity['issuer'], identity['subject']))
        need(len({item[2] for item in normalized}) == 25 and
             len({item['principalId'] for item in identities}) == 25, 'Scale identities duplicated')
        need(users is None or users == normalized, 'Source account aliases differ')
        users = normalized
    return scopes


def index_sources(config):
    rows = config.get('controls', [])
    need(len(rows) == 2 and {row['id'] for row in rows} == set(INSTANCES), 'Two-source runtime required')
    return {row['id']: row for row in rows}


def extend(row, old, added):
    need(ids(row['namespaceIds'], len(old)) == old and not set(old).intersection(added),
         'Source namespace baseline changed or scale already installed')
    row['namespaceIds'] = sorted(old + added)


def patch(configs, registries, seeds, *, expected_revision=7):
    """Return additive configuration drafts and explicit recovery prerequisites.

    Inputs must come from one operator-frozen, hash-pinned snapshot. Seed receipts
    are not live membership proof: install their directory drafts and verify
    ordinary LDAPS reconciliation separately. No feed position is generated here.
    """
    need(set(configs) == {'api', 'worker', 'broker', 'operator'} and
         set(registries) == set(INSTANCES) and expected_revision == 7,
         'Reviewed revision7 two-source split snapshot required')
    scopes = seed_scopes(seeds)
    output, trust = copy.deepcopy(configs), copy.deepcopy(registries)
    old_scopes, services = {}, {}
    for role in ('api', 'worker', 'broker'):
        need(type(configs[role].get('configurationRevision')) is int and
             configs[role]['configurationRevision'] == expected_revision, 'Runtime revision differs')
        rows = index_sources(output[role])
        output[role]['configurationRevision'] = expected_revision + 1
        for deployment, row in rows.items():
            port = '18443' if deployment == PRIMARY else '28443'
            need(row['origin'] == 'https://10.77.0.21:'+port and
                 row['expectedInstanceId'] == INSTANCES[deployment], 'Pinned source differs')
            old = ids(row['namespaceIds'], 2)
            need(deployment not in old_scopes or old_scopes[deployment] == old, 'Role scopes disagree')
            old_scopes[deployment] = old
            extend(row, old, scopes[deployment])
            identity = (row['serviceId'], row['delegationKeyId'], row['audience'])
            need(identity not in services.setdefault(deployment, {}), 'Distinct role service identities required')
            services[deployment][identity] = role
    for role in ('api', 'worker'):
        brokers = output[role]['logBrokers']
        need(len(brokers) == 2 and {item['deploymentId'] for item in brokers} == set(INSTANCES),
             'Pinned source broker entries required')
        for row in brokers:
            deployment = row['deploymentId']
            extend(row, old_scopes[deployment], scopes[deployment])
    broker_services = output['broker']['services']
    need(4 <= len(broker_services) <= 64, 'Bounded source-specific broker callers required')
    for deployment in INSTANCES:
        callers = [row for row in broker_services if row['deploymentId'] == deployment]
        expected = [row for role in ('api', 'worker') for row in output[role]['logBrokers']
                    if row['deploymentId'] == deployment]
        expected_identities = {(row['serviceId'], row['delegationKeyId'], row['audience']) for row in expected}
        need(len(expected_identities) == 2, 'Distinct broker caller role identities required')
        found_callers = set()
        for caller in callers:
            identity = (caller['serviceId'], caller['keyId'], caller['audience'])
            if identity not in expected_identities:
                continue  # Historical callers retain their original namespace scope.
            need(identity not in found_callers, 'Duplicate broker caller trust identity')
            found_callers.add(identity)
            extend(caller, old_scopes[deployment], scopes[deployment])
        need(found_callers == expected_identities, 'Broker caller trust identity missing')
        document = trust[deployment]
        need(set(document) == {'services'} and 3 <= len(document['services']) <= 64,
             'Bounded public source registry required')
        found = set()
        for row in document['services']:
            identity = (row['serviceId'], row['keyId'], row['audience'])
            if identity not in services[deployment]:
                continue  # Preserve unrelated historical registrations byte-for-value.
            need(identity not in found and row['enabled'] is True, 'Registered service is duplicate or disabled')
            found.add(identity)
            extend(row, old_scopes[deployment], scopes[deployment])
        need(found == set(services[deployment]), 'Exact registered role services required')
    need(output['api']['events']['enabled'] is True and
         output['api']['events']['deliveryHold'] is False and output['worker']['deliveryHold'] is False,
         'Expected resumed runtime configuration')
    need(configs['operator'].get('schemaVersion') == 1 and
         len(configs['operator'].get('deployments', [])) == 2 and
         {row['id'] for row in configs['operator']['deployments']} == set(INSTANCES),
         'Operator source identities differ')
    recovery = [{'deploymentId': deployment, 'instanceId': INSTANCES[deployment], 'recoveryEpoch': '1',
                 'oldNamespaceIds': old_scopes[deployment],
                 'newNamespaceIds': sorted(old_scopes[deployment]+scopes[deployment]),
                 'serviceId': index_sources(output['worker'])[deployment]['serviceId'],
                 'required': 'reviewed hold, source replay preparation, coverage review, apply, then explicit resume'}
                for deployment in INSTANCES]
    return {'configs': output, 'registries': trust, 'feedRecoveryRequired': recovery,
            'automaticFeedReset': False, 'directoryReconciliationRequired': True}
