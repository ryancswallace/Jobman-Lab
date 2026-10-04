#!/usr/bin/env python3
"""Pure plan for the reviewed b8 runtime7 → RC2 binary/static-asset upgrade."""
import base64
import copy
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

split = load('dashboard-split-plan')
r = load('dashboard-multisource-runtime')
need, sha, encoded, decode = r.need, r.sha, r.encoded, split.decode
OLD = 'b8f25afdd90f83b4602f32440a89e74dfa866b6c'
NEW = '42d153b4672aeb5cdb2d7395f052b8c6a095f5e1'
ARCHIVE = '1634cb3c44e9ca1b9321a42783be22fe7254cca8d0c235371de19db593dec85a'
OLD_ROOT = '/opt/jobman-dashboard-lab/releases/' + OLD
NEW_ROOT = '/opt/jobman-dashboard-lab/releases/' + NEW
VERSION = 'v0.1.0-rc.2'
REVISION = 7
ROLES = ('broker', 'api', 'worker')
HOSTS = ('pg01', 'control01', 'storage01')
CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'
OPERATOR = '/etc/jobman-dashboard-operator-lab/config.json'
RECOVERY = '/etc/jobman-dashboard-operator-lab/multisource-recovery.json'
SOURCE_IDS = {'72000000-0000-4000-8000-000000000001': 'e633cf92-258d-48ff-965a-fda88d68ef3a',
              '72000000-0000-4000-8000-000000000002': 'a4f0e2ab-7323-4c90-9510-1f073c660f06'}
FILES = ('dashboard-candidate-plan.py', 'dashboard-candidate-guest.py', 'upgrade-dashboard-candidate.py',
         'dashboard-split-plan.py', 'dashboard-multisource-runtime.py')
HEX = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')


def unb64(value, maximum=1 << 20):
    need(isinstance(value, str) and len(value) <= (maximum + 2) // 3 * 4, 'base64_bound')
    raw = base64.b64decode(value, validate=True)
    need(0 < len(raw) <= maximum, 'decoded_bound')
    return raw


def unit_lines(role, release):
    _, root, _, user, _, binary, mode = r.SPECS[role]
    executable = release + '/bin/' + binary
    common = '--config ' + root + '/config.json'
    result = {'User': user, 'Group': user, 'TimeoutStopSec': '90s'}
    if role == 'broker':
        result.update(ExecStartPre=executable + ' --mode check-config ' + common,
                      ExecStart=executable + ' ' + common)
    else:
        result.update(WorkingDirectory=release,
                      ExecStartPre=executable + ' --mode check-config --check-mode ' + mode + ' ' + common,
                      ExecStart=executable + ' --mode ' + mode + ' ' + common)
    return result


def transform_unit(role, raw):
    text = raw.decode('utf-8')
    need('\r' not in text and text.endswith('\n') and len(raw) <= 16384 and '\\\n' not in text, 'unit_encoding')
    expected = unit_lines(role, OLD_ROOT)
    parsed = {}
    for line in text.splitlines():
        if '=' in line and not line.lstrip().startswith(('#', ';')):
            key, value = line.split('=', 1)
            parsed.setdefault(key, []).append(value)
    need(all(parsed.get(key) == [value] for key, value in expected.items()), 'unit_semantics')
    need(role != 'broker' or 'WorkingDirectory' not in parsed, 'broker_working_directory')
    count = 2 if role == 'broker' else 3
    need(text.count(OLD_ROOT) == count and '/opt/jobman-dashboard-lab/releases/' not in text.replace(OLD_ROOT, ''), 'unit_release_sites')
    after = text.replace(OLD_ROOT, NEW_ROOT).encode()
    need(after.count(NEW_ROOT.encode()) == count and OLD_ROOT.encode() not in after, 'unit_transform')
    return after


def transform_config(role, raw):
    config = decode(raw)
    need(type(config.get('configurationRevision')) is int and config['configurationRevision'] == REVISION, 'runtime_revision')
    need(len(config.get('controls', [])) == 2 and {c['id']: c['expectedInstanceId'] for c in config['controls']} == SOURCE_IDS, 'source_registry')
    for control in config['controls']:
        need(control['origin'] in ('https://10.77.0.21:18443', 'https://10.77.0.21:28443') and
             1 <= len(control['namespaceIds']) <= 320 and len(set(control['namespaceIds'])) == len(control['namespaceIds']) and
             all(UUID.fullmatch(n) for n in control['namespaceIds']), 'source_scope')
    if role != 'api':
        return raw
    need(config.get('webRoot') == OLD_ROOT + '/web', 'static_root')
    result = copy.deepcopy(config); result['webRoot'] = NEW_ROOT + '/web'
    return encoded(result)


def decimal(value, positive=False):
    return isinstance(value, str) and re.fullmatch('[1-9][0-9]{0,18}' if positive else '(0|[1-9][0-9]{0,18})', value) is not None and int(value) <= (1 << 63) - 1


def stable_database(value):
    """Cursor positions/lease/last-success may advance; authority and hold may not."""
    need(isinstance(value, dict) and set(value) == {'ledger', 'sources', 'hold', 'rolesSHA256', 'databaseOID'}, 'database_shape')
    need(len(value['ledger']) == 18 and value['ledger'][-1]['name'] == 'migrations/000018_runtime_lock_privileges.sql', 'schema_version')
    need(all(set(v) == {'name', 'sha256'} and isinstance(v['name'], str) and
             re.fullmatch(r'migrations/[0-9]{6}_[a-z_]+\.sql', v['name']) and HEX.fullmatch(v['sha256']) for v in value['ledger']) and
         len({v['name'] for v in value['ledger']}) == 18 and HEX.fullmatch(value['rolesSHA256']), 'schema_digest')
    need(isinstance(value['databaseOID'], str) and value['databaseOID'].isdigit(), 'database_identity')
    need(len(value['sources']) == 2 and {v['deploymentId']: v['controlInstanceId'] for v in value['sources']} == SOURCE_IDS, 'database_sources')
    for source in value['sources']:
        need(source['state'] == 'active' and type(source['configurationRevision']) is int and source['configurationRevision'] == REVISION and
             decimal(source['recoveryEpoch'], positive=True) and decimal(source['generation'], positive=True) and decimal(source['lastPosition']) and
             type(source['openGaps']) is int and source['openGaps'] == 0 and
             type(source['unfinishedRecoveries']) is int and source['unfinishedRecoveries'] == 0, 'source_recovery_in_progress')
        need(isinstance(source['namespaceIds'], list) and 1 <= len(source['namespaceIds']) <= 320 and
             all(isinstance(n, str) and UUID.fullmatch(n) for n in source['namespaceIds']), 'database_namespace_shape')
    hold = value['hold']
    need(type(hold.get('held')) is bool and decimal(hold.get('generation'), positive=True) and
         (hold.get('suppressRecordedThrough') is None or isinstance(hold['suppressRecordedThrough'], str)), 'hold_shape')
    return value


def make(snapshot, metadata, files, ledger, implementation):
    need(set(snapshot) == {'format', 'capturedAt', 'hosts'} and snapshot['format'] == 1 and type(snapshot['capturedAt']) is int,
         'snapshot_shape')
    need(set(snapshot['hosts']) == set(HOSTS), 'snapshot_hosts')
    need(metadata['revision'] == NEW and metadata['version'] == VERSION, 'candidate_revision')
    need(set(implementation) == set(FILES) and all(HEX.fullmatch(v) for v in implementation.values()), 'implementation_manifest')
    database = stable_database(snapshot['hosts']['pg01']['database'])
    need(database['ledger'] == ledger, 'embedded_schema_baseline')
    changes = {}; all_caps = []
    for role in ROLES:
        host = r.SPECS[role][0]; value = snapshot['hosts'][host]['roles'][role]
        before_config, before_unit = unb64(value['config']), unb64(value['unit'], 16384)
        config = decode(before_config)
        need(value['process']['binary'] == OLD_ROOT + '/bin/' + r.SPECS[role][5] and
             value['process']['uid'] == r.SPECS[role][2] and HEX.fullmatch(value['process']['binarySHA256']), 'baseline_process')
        need(value['process']['pid'].isdigit() and value['process']['startedMonotonic'].isdigit() and UUID.fullmatch(value['process']['bootId']), 'process_generation')
        after_config, after_unit = transform_config(role, before_config), transform_unit(role, before_unit)
        changes[role] = {'beforeConfigSHA256': sha(before_config), 'afterConfigSHA256': sha(after_config),
                         'beforeUnitSHA256': sha(before_unit), 'afterUnitSHA256': sha(after_unit),
                         'afterConfig': base64.b64encode(after_config).decode(), 'afterUnit': base64.b64encode(after_unit).decode()}
        feeds = {s['deploymentId']: s for s in database['sources']}
        for control in config['controls']:
            need(sorted(control['namespaceIds']) == sorted(feeds[control['id']]['namespaceIds']), 'database_scope')
        if role == 'worker': all_caps = value['capabilities']
    need(len(all_caps) == 2 and {c['deploymentId']: c['instanceId'] for c in all_caps} == SOURCE_IDS, 'source_capabilities')
    need(all(next(s for s in database['sources'] if s['deploymentId'] == c['deploymentId'])['recoveryEpoch'] == c['recoveryEpoch'] for c in all_caps), 'source_epoch')
    return {'format': 1, 'scenario': 'dashboard-candidate-upgrade', 'synthetic': True, 'configurationRevision': REVISION,
            'oldRevision': OLD, 'newRevision': NEW, 'archiveSHA256': ARCHIVE, 'candidate': metadata,
            'candidateFiles': {name: {'sha256': sha(raw), 'bytes': len(raw), 'mode': 0o755 if name.startswith('bin/') else 0o644}
                               for name, raw in sorted(files.items())},
            'snapshot': snapshot, 'changes': changes, 'implementationSHA256': implementation,
            'database': database, 'schemaCheck': 'new-binary status uses CheckSchema before read-only status',
            'preserved': ['revision', 'keys', 'roles', 'schema', 'data', 'source-instance', 'source-epoch', 'source-scope', 'feed-generation', 'hold', 'recovery-config'],
            'forbidden': ['migration', 'registry-change', 'feed-reset', 'hold-change', 'source-restart', 'automatic-rollback']}


def validate(plan):
    need(plan.get('format') == 1 and plan.get('scenario') == 'dashboard-candidate-upgrade' and plan.get('synthetic') is True and
         plan.get('oldRevision') == OLD and plan.get('newRevision') == NEW and plan.get('archiveSHA256') == ARCHIVE and
         plan.get('configurationRevision') == REVISION and set(plan.get('changes', {})) == set(ROLES), 'plan_identity')
    need(set(plan['implementationSHA256']) == set(FILES) and all(HEX.fullmatch(v) for v in plan['implementationSHA256'].values()), 'plan_implementation')
    stable_database(plan['database'])
    inventory = plan['candidateFiles']
    need(1 <= len(inventory) <= 4096 and {'bin/jobman-dashboard', 'bin/jobman-log-broker', 'build.json', 'SHA256SUMS', 'web/index.html'} <= set(inventory), 'candidate_inventory_required')
    total = 0
    for name, item in inventory.items():
        path = PurePosixPath(name)
        need(not path.is_absolute() and str(path) == name and '..' not in path.parts and '.' not in path.parts and '\\' not in name and
             len(name) <= 4096 and type(item['bytes']) is int and 0 <= item['bytes'] <= 96 << 20 and HEX.fullmatch(item['sha256']) and
             item['mode'] == (0o755 if name.startswith('bin/') else 0o644), 'candidate_member')
        total += item['bytes']
    need(total <= 384 << 20, 'candidate_expansion_bound')
    for role, change in plan['changes'].items():
        baseline = plan['snapshot']['hosts'][r.SPECS[role][0]]['roles'][role]
        before_config, before_unit = unb64(baseline['config']), unb64(baseline['unit'], 16384)
        need(sha(before_config) == change['beforeConfigSHA256'] and sha(before_unit) == change['beforeUnitSHA256'] and
             unb64(change['afterConfig']) == transform_config(role, before_config) and
             unb64(change['afterUnit'], 16384) == transform_unit(role, before_unit) and
             sha(unb64(change['afterConfig'])) == change['afterConfigSHA256'] and
             sha(unb64(change['afterUnit'], 16384)) == change['afterUnitSHA256'], 'plan_delta')
    need(plan['database'] == plan['snapshot']['hosts']['pg01']['database'], 'plan_database')
