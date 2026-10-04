#!/usr/bin/env python3
"""Pure, public, non-applying plan for a second isolated Dashboard source."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SOURCE_REVISION = 'd332a2b569333ae8aed9c2fc9ebc648d8eb5ba4e'
SOURCE_SHA256 = '38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e'
MIGRATION = '000021_monitoring_events.sql'
PRIMARY_INSTANCE = 'e633cf92-258d-48ff-965a-fda88d68ef3a'
PRIMARY_DEPLOYMENT = '72000000-0000-4000-8000-000000000001'
SECONDARY_DEPLOYMENT = '72000000-0000-4000-8000-000000000002'
ISSUER = 'https://oidc.lab.test:8443/realms/jobman-lab'
AUDIENCE = 'jobman-dashboard-api'
DIRECTORY_IDS = ['71000000-0000-4000-8000-000000000001', '71000000-0000-4000-8000-000000000002']
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path, maximum):
    path = Path(path)
    require(path.is_absolute(), 'Input path must be absolute')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, 'Expected bounded regular input')
        raw = stream.read(maximum + 1)
        require(len(raw) <= maximum, 'Input grew beyond limit')
        return raw


def json_value(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate JSON member')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def validate_build(build):
    metadata = json_value(read(build / 'build.json', 8192))
    require(metadata.get('revision') == SOURCE_REVISION and metadata.get('platform') == 'linux/arm64' and
            metadata.get('toolchain') == 'go1.26.6', 'Wrong approved source build')
    binary = read(build / 'jobman-control', 64 << 20)
    require(binary[:6] == b'\x7fELF\x02\x01' and binary[18:20] == b'\xb7\x00' and
            hashlib.sha256(binary).hexdigest() == SOURCE_SHA256 and
            metadata.get('sha256', {}).get('jobman-control') == SOURCE_SHA256, 'Exact source binary digest differs')
    return {'revision': SOURCE_REVISION, 'sha256': SOURCE_SHA256, 'platform': 'linux/arm64',
            'toolchain': 'go1.26.6', 'migration': MIGRATION}


def validate_identities(primary, oidc):
    require(primary.get('synthetic') is True and primary.get('instanceId') == PRIMARY_INSTANCE and
            primary.get('endpoint') == 'https://10.77.0.21:18443' and primary.get('issuer') == ISSUER,
            'Primary source is not the approved isolated fixture')
    require(oidc.get('issuer') == ISSUER and oidc.get('audience') == AUDIENCE and
            oidc.get('webClientId') == 'jobman-dashboard-web' and
            oidc.get('nativeClientId') == 'jobman-dashboard-native' and
            oidc.get('clientIdentityClaim') == 'azp' and oidc.get('directoryGuidClaim') == 'directory_guid',
            'Signed identity policy differs')
    users = oidc.get('users', [])
    require(len(users) == 2 and len(primary.get('identities', [])) == 2, 'Expected only the two synthetic identities')
    result = []
    for i, (user, name) in enumerate(zip(users, ['alice', 'bob'])):
        require(user.get('username') == 'dashboard-' + name and user.get('directoryGuid') == DIRECTORY_IDS[i] and
                UUID.fullmatch(user.get('subject', '')), 'Synthetic subject or directory identity differs')
        matching = [identity for identity in primary['identities'] if identity.get('directoryId') == DIRECTORY_IDS[i]]
        require(len(matching) == 1 and matching[0].get('issuer') == ISSUER and
                matching[0].get('subject') == user['subject'], 'Primary alias does not match signed subject')
        result.append({'directoryId': DIRECTORY_IDS[i], 'subject': user['subject'], 'name': 'Synthetic ' + name.title()})
    require(result[0]['subject'] != result[1]['subject'], 'Synthetic subjects must differ')
    namespaces = primary.get('namespaces', [])
    require(len(namespaces) == 2 and {n.get('name') for n in namespaces} ==
            {'dashboard-research', 'dashboard-operations'} and
            all(UUID.fullmatch(n.get('id', '')) for n in namespaces), 'Primary namespace set differs')
    return result


def make_plan(primary, oidc, source_build):
    users = validate_identities(primary, oidc)
    for name in ('jobman-dashboard-source2', 'jobman-dashboard-directory2'):
        require(re.fullmatch(r'[a-z][a-z0-9-]{0,31}', name), 'POSIX fixture identity name exceeds Linux bounds')
    require(source_build == {'revision': SOURCE_REVISION, 'sha256': SOURCE_SHA256, 'platform': 'linux/arm64',
                            'toolchain': 'go1.26.6', 'migration': MIGRATION}, 'Source build pin differs')
    groups = []
    roles = ['viewer', 'submitter', 'operator', 'namespace_admin']
    for index, namespace in enumerate(['dashboard-research', 'dashboard-operations']):
        for role_index, role in enumerate(roles):
            members = []
            if index == 0 and role_index == 0:
                members = DIRECTORY_IDS.copy()
            elif index == 0 and role_index == 1 or index == 1 and role_index == 3:
                members = [DIRECTORY_IDS[1]]
            groups.append({'id': f'73000000-0000-4000-8000-{index * 4 + role_index + 1:012d}',
                           'namespaceName': namespace, 'role': role, 'members': members})
    return {
        'formatVersion': 1, 'synthetic': True, 'mode': 'prepare-only', 'applySupported': False,
        'blockedBy': ['reviewed-secondary-helper-profile', 'separate-database-and-identity-provisioning',
                      'reviewed-source-and-dashboard-registration-apply'],
        'sourceBuild': source_build,
        'primary': {'deploymentId': PRIMARY_DEPLOYMENT, 'instanceId': PRIMARY_INSTANCE,
                    'endpoint': primary['endpoint'], 'preserve': True},
        'secondary': {
            'deploymentId': SECONDARY_DEPLOYMENT, 'displayName': 'Synthetic secondary Control',
            'endpoint': 'https://10.77.0.21:28443', 'instanceId': 'GENERATE_FRESH_DO_NOT_COPY',
            'recoveryEpoch': '1', 'database': 'jobman_dashboard_control_secondary',
            'databaseRole': 'jobman_dashboard_control_secondary', 'schema': 'public',
            'databaseURLFile': '/etc/jobman-dashboard-secondary/control-database-url',
            'controlUser': {'name': 'jobman-dashboard-source2', 'uid': 21907, 'gid': 21907},
            'directoryUser': {'name': 'jobman-dashboard-directory2', 'uid': 21908, 'gid': 21908},
            'controlUnit': 'jobman-dashboard-lab-control-secondary.service',
            'directoryUnit': 'jobman-dashboard-lab-directory-secondary.service',
            'controlRoot': '/etc/jobman-dashboard-secondary/control',
            'directoryRoot': '/etc/jobman-dashboard-secondary/directory',
            'spoolRoot': '/var/lib/jobman-dashboard-secondary/seed-logs',
            'logRoot': '/data/jobman/alice/dashboard-secondary',
            'logicalStore': {'name': 'lab-nfs', 'version': '1'},
            'directoryURL': 'ldaps://127.0.0.1:28636',
            'directorySource': 'synthetic-dashboard-lab-secondary',
            'baseDN': 'DC=dashboard-secondary,DC=lab,DC=test',
            'delegationAudience': 'urn:jobman:dashboard-lab-secondary:control',
            'newServices': [
                {'serviceId': 'dashboard-api-lab-secondary', 'keyId': 'secondary-api-v1',
                 'operations': ['namespace.read', 'jobs.read', 'groups.read', 'targets.read', 'logs.read', 'artifacts.read', 'evidence.read', 'events.read']},
                {'serviceId': 'dashboard-worker-lab-secondary', 'keyId': 'secondary-worker-v1',
                 'operations': ['namespace.read', 'jobs.read', 'logs.read', 'evidence.read', 'events.read']},
                {'serviceId': 'dashboard-log-broker-lab-secondary', 'keyId': 'secondary-broker-v1',
                 'operations': ['namespace.read', 'logs.read']}],
            'issuer': ISSUER, 'audience': AUDIENCE, 'users': users, 'directGroups': groups,
            'nestedGroups': False, 'copyPrimaryTrust': False, 'copyPrimaryDatabase': False,
        },
        'acceptance': [
            'Real PKCE Alice sees primary research/operations plus secondary research only.',
            'Real PKCE Bob sees primary research plus secondary research/operations.',
            'Equal namespace and job display names stay source-qualified; wrong deployment/resource pair is denied.',
            'Aggregated catalogs, counts and stable cursors preserve both sources without duplicate or lost rows.',
            'Secondary outage yields partial primary contributions; both unavailable never report healthy zero totals.',
            'Secondary direct-group removal affects that source only, using existing tokens; restore exact state afterward.',
            'Independent normal terminal events produce one account/event inbox entry with all matching rules; stop/replay stay source-qualified.',
            'Cross-source cursor, event, private-deep-link, report and log substitutions are denied.',
            'Fresh secondary CA/client keys reject a primary-source assertion/certificate without changing primary trust.',
        ],
    }
