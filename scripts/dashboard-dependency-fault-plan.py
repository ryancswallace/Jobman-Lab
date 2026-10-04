#!/usr/bin/env python3
"""Pure bounded plans for separately reviewed Dashboard dependency faults."""
import copy
import hashlib
import json
import re

HEX = re.compile(r'[0-9a-f]{64}\Z')
REVISION = re.compile(r'[0-9a-f]{40}\Z')
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
SOURCE_IDS = {'72000000-0000-4000-8000-000000000001': 'e633cf92-258d-48ff-965a-fda88d68ef3a',
              '72000000-0000-4000-8000-000000000002': 'a4f0e2ab-7323-4c90-9510-1f073c660f06'}
FAULTS = {
    'directory_stop': {'host': 'control01', 'unit': 'jobman-dashboard-lab-directory', 'uid': 21902, 'watchdogSeconds': 180, 'applyReserveSeconds': 145},
    'broker_stop': {'host': 'control01', 'unit': 'jobman-dashboard-lab-broker', 'uid': 21901, 'watchdogSeconds': 120, 'applyReserveSeconds': 100},
    'broker_pause': {'host': 'control01', 'unit': 'jobman-dashboard-lab-broker', 'uid': 21901, 'watchdogSeconds': 45, 'applyReserveSeconds': 30},
    'database_reject': {'host': 'storage01', 'unit': None, 'uid': None, 'watchdogSeconds': 45, 'applyReserveSeconds': 30},
    'database_drop': {'host': 'storage01', 'unit': None, 'uid': None, 'watchdogSeconds': 45, 'applyReserveSeconds': 30},
}
SCENARIOS = {'directory': ['directory_stop'], 'broker': ['broker_stop', 'broker_pause'],
             'database': ['database_reject', 'database_drop']}
IMPLEMENTATION = ['dashboard-dependency-fault-plan.py', 'dashboard-dependency-fault-guest.py',
                  'dashboard-dependency-faults.py']


class Failure(ValueError):
    def __init__(self, code):
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code):
            raise ValueError('invalid_failure_code')
        super().__init__(code)
        self.code = code


def need(condition, code):
    if not condition:
        raise Failure(code)


def decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            need(key not in value,'duplicate_json_field'); value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _: (_ for _ in ()).throw(Failure('invalid_json_number')))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decimal(value):
    return isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,18}', value) and int(value) <= (1 << 63)-1


def stable_database(value):
    need(isinstance(value, dict) and set(value) == {'schemaSHA256', 'rolesSHA256', 'databaseOID', 'sources', 'hold'}, 'database_shape')
    need(HEX.fullmatch(value['schemaSHA256']) and HEX.fullmatch(value['rolesSHA256']) and decimal(value['databaseOID']), 'database_identity')
    need(isinstance(value['sources'], list) and len(value['sources']) == 2 and
         {s['deploymentId']: s['controlInstanceId'] for s in value['sources']} == SOURCE_IDS, 'source_identity')
    for source in value['sources']:
        need(set(source) == {'deploymentId', 'controlInstanceId', 'recoveryEpoch', 'configurationRevision', 'namespaceIds', 'status', 'generation', 'lastPosition', 'openGaps', 'unfinishedRecoveries'}, 'feed_shape')
        need(decimal(source['recoveryEpoch']) and int(source['recoveryEpoch']) > 0 and type(source['configurationRevision']) is int and source['configurationRevision'] > 0 and
             decimal(source['generation']) and int(source['generation']) > 0 and decimal(source['lastPosition']) and source['status'] == 'active' and
             source['openGaps'] == 0 and type(source['openGaps']) is int and source['unfinishedRecoveries'] == 0 and type(source['unfinishedRecoveries']) is int, 'feed_not_healthy')
        need(isinstance(source['namespaceIds'], list) and 1 <= len(source['namespaceIds']) <= 320 and len(set(source['namespaceIds'])) == len(source['namespaceIds']) and all(UUID.fullmatch(n) for n in source['namespaceIds']), 'feed_scope')
    need(set(value['hold']) == {'held', 'generation', 'suppressRecordedThrough'} and value['hold']['held'] is False and decimal(value['hold']['generation']), 'delivery_hold')
    return value


def database_preserved(before, after):
    stable_database(before); stable_database(after)
    normalized = copy.deepcopy(after)
    prior = {s['deploymentId']: s for s in before['sources']}
    for source in normalized['sources']:
        for key in ('generation', 'lastPosition'):
            need(int(source[key]) >= int(prior[source['deploymentId']][key]), 'feed_progress_regressed')
            source[key] = prior[source['deploymentId']][key]
    need(normalized == before, 'database_authority_changed')


def make(snapshot, scenario, operation, revision, implementation, created_at):
    need(scenario in SCENARIOS and UUID.fullmatch(operation) and REVISION.fullmatch(revision), 'scenario_identity')
    need(set(snapshot) == {'control01', 'storage01', 'pg01'}, 'snapshot_hosts')
    need(set(implementation) == set(IMPLEMENTATION) and all(HEX.fullmatch(v) for v in implementation.values()), 'implementation_hashes')
    stable_database(snapshot['pg01']['database'])
    for host in ('control01', 'storage01'):
        value = snapshot[host]
        need(value['host'] == host and UUID.fullmatch(value['bootId']) and value['revision'] == revision and HEX.fullmatch(value['preservedSHA256']), 'host_baseline')
        need(all(v['bootId'] == value['bootId'] and decimal(v['pid']) and int(v['pid']) > 0 and decimal(v['start']) and int(v['start']) > 0 and (v['binarySHA256'] is None if k in ('jobman-control','jobman-keycloak') else bool(HEX.fullmatch(v['binarySHA256']))) and HEX.fullmatch(v['unitSHA256']) for k,v in value['processes'].items()), 'process_baseline')
    for fault in SCENARIOS[scenario]:
        spec = FAULTS[fault]
        if spec['unit']:
            need(snapshot[spec['host']]['processes'][spec['unit']]['uid'] == spec['uid'], 'fault_process_owner')
    need(type(created_at) is int and created_at > 0, 'plan_time')
    return {'format': 1, 'synthetic': True, 'scenario': scenario, 'operationId': operation,
            'createdAt': created_at, 'revision': revision, 'faults': SCENARIOS[scenario],
            'snapshot': snapshot, 'implementationSHA256': implementation}


def validate(plan):
    need(isinstance(plan, dict) and set(plan) == {'format', 'synthetic', 'scenario', 'operationId', 'createdAt', 'revision', 'faults', 'snapshot', 'implementationSHA256'}, 'plan_shape')
    need(type(plan['format']) is int and plan['format']==1 and plan['synthetic'] is True,'plan_flags')
    need(plan == make(plan['snapshot'], plan['scenario'], plan['operationId'], plan['revision'], plan['implementationSHA256'], plan['createdAt']), 'plan_changed')


def table_name(operation):
    need(UUID.fullmatch(operation), 'operation_identity')
    return 'jobman_dashboard_fault_' + operation.replace('-', '')


def firewall_elements(operation, fault):
    need(fault in ('database_reject', 'database_drop'), 'database_fault')
    name = table_name(operation)
    def match(left, right):
        return {'match': {'op': '==', 'left': left, 'right': right}}
    return [
        {'table': {'family': 'inet', 'name': name}},
        {'chain': {'family': 'inet', 'table': name, 'name': 'output',
                   'type': 'filter', 'hook': 'output', 'prio': -300, 'policy': 'accept'}},
        {'rule': {'family': 'inet', 'table': name, 'chain': 'output', 'expr': [
            match({'meta': {'key': 'skuid'}}, {'set': [21904, 21905]}),
            match({'payload': {'protocol': 'ip', 'field': 'daddr'}}, '10.77.0.20'),
            match({'payload': {'protocol': 'tcp', 'field': 'dport'}}, 5432),
            {'counter': {}}, {'reject': {'type': 'tcp reset'}} if fault == 'database_reject' else {'drop': None}]}}]


def firewall_batch(operation, fault):
    # libnftables permits create for tables/chains, but rules require add.
    # Exclusive creation of the enclosing table in this SAME atomic batch
    # prevents appending to any existing table or duplicating a prior rule.
    table, chain, rule = firewall_elements(operation, fault)
    # Input needs an explicit anonymous counter; the read-only semantic form
    # omits changing values so recovery can validate accumulated counters.
    rule['rule']['expr'][-2]['counter'] = {'packets': 0, 'bytes': 0}
    return encoded({'nftables': [{'create': table}, {'create': chain}, {'add': rule}]})
