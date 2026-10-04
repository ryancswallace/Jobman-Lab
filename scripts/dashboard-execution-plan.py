#!/usr/bin/env python3
"""Stage an exact, non-applying plan for real synthetic Dashboard workloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

REVISION = '21701b191cd4e4e063d26cad7dae31c35db6bc8c'
DEPLOYMENT = '72000000-0000-4000-8000-000000000001'
TARGET = 'dashboard-execution-host'
NAMESPACE = 'dashboard-operations'
STORE_ROOT = '/data/jobman/alice/dashboard-execution'
STATE_ROOT = '/var/lib/jobman-dashboard-execution/alice-host'
UNIT = 'jobman-dashboard-execution-host.service'
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path, maximum):
    path = Path(path)
    require(path.is_absolute(), 'Path must be absolute')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, 'Expected a bounded regular file')
        value = stream.read(maximum + 1)
        require(len(value) <= maximum, 'File grew beyond bound')
        return value


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def validate_build(build):
    metadata = json.loads(read(build / 'build.json', 8192))
    require(metadata.get('revision') == REVISION and metadata.get('platform') == 'linux/arm64' and
            metadata.get('toolchain') == 'go1.26.6', 'Wrong clean Core build identity')
    agent = read(build / 'jobman-agent', 64 << 20)
    require(agent[:6] == b'\x7fELF\x02\x01' and agent[18:20] == b'\xb7\x00' and
            hashlib.sha256(agent).hexdigest() == metadata.get('sha256', {}).get('jobman-agent'), 'Agent binary identity differs')
    return metadata


def validate_fixture(fixture):
    require(fixture.get('synthetic') is True and fixture.get('endpoint') == 'https://10.77.0.21:18443' and
            UUID.fullmatch(fixture.get('instanceId', '')), 'Wrong isolated Control source')
    namespaces = [n for n in fixture.get('namespaces', []) if n.get('name') == NAMESPACE]
    require(len(namespaces) == 1 and UUID.fullmatch(namespaces[0].get('id', '')), 'Operations namespace is not pinned')
    return namespaces[0]['id']


def unit_text(digest):
    require(re.fullmatch('[0-9a-f]{64}', digest), 'Invalid binary digest')
    binary = '/usr/local/libexec/jobman-dashboard-lab/jobman-agent-execution-' + digest
    return f'''[Unit]
Description=Isolated Dashboard actual subprocess acceptance agent (Alice)
Wants=network-online.target remote-fs.target
After=network-online.target remote-fs.target

[Service]
Type=simple
User=alice
Group=alice
ExecStart={binary} run --state-dir {STATE_ROOT} --poll-interval 1s --artifact-store lab-nfs --artifact-store-version 1 --artifact-root {STORE_ROOT} --max-log-bytes 1048576 --max-artifact-bytes 1048576
Restart=on-failure
RestartSec=3s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# Bind the mount root; root-squashed NFS paths beneath Alice are not root-traversable.
# The ordinary Alice UID and designated-reader ACL still control actual data access.
ReadWritePaths={STATE_ROOT} /data
TimeoutStopSec=35s

[Install]
WantedBy=multi-user.target
'''


def make_plan(build, fixture, source_revision):
    metadata = validate_build(build)
    namespace = validate_fixture(fixture)
    require(re.fullmatch('[0-9a-f]{40}', source_revision), 'Exact current Control revision required')
    target = {'apiVersion': 'jobman.control/v1alpha1', 'kind': 'Target', 'metadata': {'name': TARGET},
              'spec': {'kind': 'host', 'executionBackend': 'subprocess', 'runtimes': ['native'],
                       'operatingSystems': ['linux'], 'architectures': ['arm64'],
                       'logStore': {'name': 'lab-nfs', 'version': 1},
                       'artifactStores': [{'name': 'lab-nfs', 'version': 1}]}}
    plan = {'synthetic': True, 'version': 1, 'mode': 'actual-subprocess-execution', 'deploymentId': DEPLOYMENT,
            'controlInstanceId': fixture['instanceId'], 'namespaceId': namespace, 'namespace': NAMESPACE,
            'sourceRevision': source_revision, 'coreRevision': REVISION, 'agentSHA256': metadata['sha256']['jobman-agent'],
            'targetName': TARGET, 'targetRequest': target, 'targetIdempotencyKey': 'dashboard-execution-host-v1',
            'enrollmentIdempotencyKey': 'dashboard-execution-alice-v1', 'expectedUser': 'alice', 'expectedUID': 21001,
            'directoryId': '71000000-0000-4000-8000-000000000001', 'stateRoot': STATE_ROOT, 'storeRoot': STORE_ROOT,
            'unit': UNIT, 'readerUID': 21901, 'maximumJobs': 12, 'maximumRunSeconds': 30,
            'policy': {'schema_version': 1, 'store_name': 'lab-nfs', 'store_version': 1, 'reader_uid': 21901}}
    return plan


def mapping_patch(config, fixture, role, expected_revision):
    require(type(expected_revision) is int and expected_revision > 0 and config.get('configurationRevision') == expected_revision,
            'Current configuration revision differs')
    require(fixture.get('synthetic') is True and fixture.get('mode') == 'actual-subprocess-execution' and
            fixture.get('deploymentId') == DEPLOYMENT and fixture.get('namespace') == NAMESPACE and
            fixture.get('targetName') == TARGET and fixture.get('storeRoot') == STORE_ROOT and
            UUID.fullmatch(fixture.get('targetGenerationId', '')) and UUID.fullmatch(fixture.get('namespaceId', '')),
            'Exact execution receipt required')
    controls = [c for c in config.get('controls', []) if c.get('id') == DEPLOYMENT]
    require(len(controls) == 1 and controls[0].get('expectedInstanceId') == fixture.get('controlInstanceId') and
            controls[0].get('origin') == 'https://10.77.0.21:18443' and fixture['namespaceId'] in controls[0].get('namespaceIds', []),
            'Configuration source identity or authority differs')
    key = 'logRoots' if role == 'broker' else 'logMappings'
    mapping = {'deploymentId': DEPLOYMENT, 'targetGenerationId': fixture['targetGenerationId'], 'storeName': 'lab-nfs', 'storeVersion': '1'}
    if role == 'broker':
        mapping['root'] = STORE_ROOT
    else:
        brokers = [b for b in config.get('logBrokers', []) if b.get('id') == 'control01-nfs' and b.get('deploymentId') == DEPLOYMENT and
                   b.get('origin') == 'https://10.77.0.21:19443' and fixture['namespaceId'] in b.get('namespaceIds', [])]
        require(len(brokers) == 1, 'Required source-qualified broker differs')
        mapping['brokerId'] = 'control01-nfs'
    result = json.loads(json.dumps(config))
    existing = result.get(key, [])
    require(isinstance(existing, list) and len(existing) < 64, 'Mapping bound exceeded')
    matches = [m for m in existing if m.get('deploymentId') == DEPLOYMENT and m.get('targetGenerationId') == fixture['targetGenerationId']]
    if matches:
        require(matches == [mapping], 'An existing execution mapping differs')
        return result
    result[key] = existing + [mapping]
    result['configurationRevision'] = expected_revision + 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    plan = modes.add_parser('plan')
    plan.add_argument('--build', type=Path, required=True)
    plan.add_argument('--fixture', type=Path, required=True)
    plan.add_argument('--source-revision', required=True)
    plan.add_argument('--output', type=Path, required=True)
    patch = modes.add_parser('mapping')
    patch.add_argument('--config', type=Path, required=True)
    patch.add_argument('--receipt', type=Path, required=True)
    patch.add_argument('--role', choices=['api', 'broker', 'reports'], required=True)
    patch.add_argument('--expected-revision', type=int, required=True)
    patch.add_argument('--expected-sha256', required=True)
    patch.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.mode == 'plan':
        result = make_plan(args.build, json.loads(read(args.fixture, 65536)), args.source_revision)
        args.output.mkdir(mode=0o700)
        write_new(args.output / 'plan.json', encoded(result))
        write_new(args.output / UNIT, unit_text(result['agentSHA256']).encode())
    else:
        original = read(args.config, 1 << 20)
        require(hashlib.sha256(original).hexdigest() == args.expected_sha256, 'Current configuration digest differs')
        result = mapping_patch(json.loads(original), json.loads(read(args.receipt, 32768)), args.role, args.expected_revision)
        write_new(args.output, encoded(result))
    print('Staged exact synthetic execution configuration; no service, source, agent, or workload changed.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('Execution staging failed; existing configuration and services were not changed.') from None
