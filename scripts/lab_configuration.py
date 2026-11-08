"""One source loader for the explicitly synthetic Lab provisioning adapter."""
import ipaddress
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from jobman_config import ConfigurationError, decode, read_regular

ROOT = Path(__file__).resolve().parents[1]


def reject_templates(value):
    if isinstance(value, dict):
        for child in value.values():
            reject_templates(child)
    elif isinstance(value, list):
        for child in value:
            reject_templates(child)
    elif isinstance(value, str) and any(marker in value for marker in ['{{', '{%', '{#']):
        raise ConfigurationError('Lab configuration does not support Ansible template expressions')


def same_shape(value, baseline):
    if type(value) is not type(baseline):
        raise ConfigurationError('Lab configuration field has the wrong type')
    if isinstance(value, dict):
        if value.keys() != baseline.keys():
            raise ConfigurationError('Lab configuration has unknown or missing fields')
        for key, item in value.items():
            same_shape(item, baseline[key])
    elif isinstance(value, list):
        if len(value) != len(baseline):
            raise ConfigurationError('synthetic fixture identities cannot be added or removed by configuration')
        for item, expected in zip(value, baseline):
            same_shape(item, expected)


def validate_fixture_identity(topology, baseline):
    # These values are recorded acceptance identities, including destructive
    # operation guards. Never reinterpret a changed value as a production target.
    for field in ['name', 'domain', 'namespace', 'provider', 'network', 'users']:
        if topology['lab'][field] != baseline['lab'][field]:
            raise ConfigurationError('recorded Lab fixture identity cannot be overridden; use deployment bundles for other environments')
    if topology['storage'] != baseline['storage']:
        raise ConfigurationError('recorded Lab storage identity cannot be overridden')
    for name, node in topology['nodes'].items():
        for field in ['role', 'group', 'address']:
            if node[field] != baseline['nodes'][name][field]:
                raise ConfigurationError('recorded Lab host identity cannot be overridden')
    for field in ['oidc_audience', 'artifact_store', 'artifact_store_version', 'slurm_partition']:
        if topology['lab']['services'][field] != baseline['lab']['services'][field]:
            raise ConfigurationError('recorded Lab service identity cannot be overridden')


def validate_versions(versions, baseline):
    for section, fields in {'host_tools': ['packer', 'packer_parallels'],
                            'images': ['alma_box_provider', 'alma_box_architecture'],
                            'guest_software': ['mariadb', 'almalinux_release']}.items():
        if any(versions[section][field] != baseline[section][field] for field in fields):
            raise ConfigurationError('selected version requires a different supported Lab platform adapter')
    version_values = [*versions['host_tools'].values(), versions['images']['alma_box_version'],
                      versions['guest_software']['go'], versions['guest_software']['slurm']]
    if any(not re.fullmatch('[0-9]{1,10}(\\.[0-9]{1,10}){1,3}', value) for value in version_values):
        raise ConfigurationError('Lab software versions must be bounded numeric release pins')
    images = versions['images']
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}/[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}', images['alma_box']):
        raise ConfigurationError('Lab box name must be a registry namespace and name')
    for value in [images['alma_box_sha256'], images['windows_iso_sha256'], versions['guest_software']['slurm_sha256']]:
        if not re.fullmatch('[a-f0-9]{64}', value):
            raise ConfigurationError('source artifacts require SHA-256 pins')
    for field in ['postgresql_container', 'keycloak_container']:
        if not re.fullmatch('[a-z0-9][a-z0-9._/:+-]+@sha256:[a-f0-9]{64}', versions['guest_software'][field]):
            raise ConfigurationError('container images require immutable SHA-256 pins')
    source = versions['guest_software']['slurm_url']
    try:
        parsed = urlsplit(source)
        if (len(source) > 4096 or any(character.isspace() or ord(character) < 32 for character in source)
                or parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment or parsed.port == 0):
            raise ValueError('invalid URL')
    except ValueError as error:
        raise ConfigurationError('source URL must be bounded credential-free HTTPS without query or fragment') from error


def load(root=None):
    root = Path(root or os.environ.get('JOBMAN_LAB_CONFIG_ROOT', ROOT / 'config')).resolve(strict=True)
    topology = decode(read_regular(root / 'topology.yml'))
    versions = decode(read_regular(root / 'versions.yml'))
    reject_templates(topology)
    reject_templates(versions)
    baseline = decode(read_regular(ROOT / 'config/topology.yml'))
    same_shape(topology, baseline)
    baseline_versions = decode(read_regular(ROOT / 'config/versions.yml'))
    same_shape(versions, baseline_versions)
    validate_versions(versions, baseline_versions)
    validate_fixture_identity(topology, baseline)
    if set(topology) != {'lab', 'storage', 'nodes'} or set(versions) != {'host_tools', 'images', 'guest_software', 'products'}:
        raise ConfigurationError('Lab topology or version document has unknown or missing sections')
    lab = topology['lab']
    if lab.get('synthetic') is not True or lab.get('provider') != 'parallels':
        raise ConfigurationError('Lab provisioning requires explicit synthetic=true and the supported Parallels adapter')
    if not lab.get('domain', '').endswith('.test') or not re.fullmatch('[a-z][a-z0-9-]{0,47}', lab.get('name', '')):
        raise ConfigurationError('Lab name or synthetic DNS domain is invalid')
    services = lab['services']
    if not re.fullmatch('[a-zA-Z0-9.-]+', services['upstream_ntp']) or len(services['motd']) > 4096 or any(ord(character) < 32 and character not in '\n\t' for character in services['motd']):
        raise ConfigurationError('Lab time source or notice is invalid')
    if not re.fullmatch('INFINITE|[0-9]+(-[0-9]+)?(:[0-9]{1,2}){0,2}', services['slurm_max_time']):
        raise ConfigurationError('invalid synthetic Slurm time limit')
    try:
        network = ipaddress.ip_network(lab['network']['cidr'])
        gateway = ipaddress.ip_address(lab['network']['gateway'])
        addresses = [ipaddress.ip_address(node['address']) for node in topology['nodes'].values()]
        if not network.is_private or gateway not in network or len(addresses) != len(set(addresses)) or any(address not in network or address == gateway for address in addresses):
            raise ValueError('invalid network')
    except (ValueError, KeyError, TypeError) as error:
        raise ConfigurationError('Lab requires a private subnet with distinct host addresses and gateway') from error
    users = lab['users']
    for field in ['name', 'uid', 'gid', 'oidc_subject']:
        if len({user[field] for user in users}) != len(users):
            raise ConfigurationError('Lab user identities must be unique')
    for name, node in topology['nodes'].items():
        if not re.fullmatch('[a-z][a-z0-9-]{0,47}', name) or node['group'] not in {'core', 'full'}:
            raise ConfigurationError('invalid Lab node name or group')
        if type(node['cpus']) is not int or not 1 <= node['cpus'] <= 128 or type(node['memory_mb']) is not int or not 512 <= node['memory_mb'] <= 1048576:
            raise ConfigurationError('Lab node resources are outside supported bounds')
        if 'data_disk_mb' in node and not 1024 <= node['data_disk_mb'] <= 1048576:
            raise ConfigurationError('Lab data disk size must be between 1 GiB and 1 TiB')
    for required in ['storage', 'postgres', 'control', 'slurm_controller', 'submit']:
        if len([node for node in topology['nodes'].values() if node['role'] == required]) != 1:
            raise ConfigurationError('Lab requires exactly one host for each infrastructure role')
    for location in topology['storage'].values():
        for field in ['server_path', 'linux_path']:
            path = location[field]
            if not path.startswith('/') or '..' in Path(path).parts or '\n' in path or not re.fullmatch('/[a-zA-Z0-9_./-]+', path):
                raise ConfigurationError('invalid Lab storage path')
    return {'topology': topology, 'versions': versions}, root


def inventory_variables(document):
    topology, versions = document['topology'], document['versions']
    lab = topology['lab']
    roles = {role: next(name for name, node in topology['nodes'].items() if node['role'] == role)
             for role in ['storage', 'postgres', 'control', 'slurm_controller', 'submit']}
    return {
        'lab_synthetic': True, 'lab_name': lab['name'], 'lab_domain': lab['domain'],
        'lab_namespace': lab['namespace'], 'lab_network_cidr': lab['network']['cidr'],
        'lab_users': lab['users'], 'lab_nodes': topology['nodes'], 'lab_storage': topology['storage'],
        'lab_role_hosts': roles, 'lab_versions': versions,
        'lab_postgres_image': versions['guest_software']['postgresql_container'],
        'lab_keycloak_image': versions['guest_software']['keycloak_container'],
        'lab_slurm_version': versions['guest_software']['slurm'],
        'lab_slurm_sha256': versions['guest_software']['slurm_sha256'],
        'lab_control_endpoint': f'https://{roles["control"]}.{lab["domain"]}:8080',
        'lab_oidc_issuer': f'https://oidc.{lab["domain"]}:8443/realms/{lab["name"]}',
        'lab_oidc_audience': lab['services']['oidc_audience'],
        'lab_artifact_store': lab['services']['artifact_store'],
        'lab_artifact_store_version': lab['services']['artifact_store_version'],
        'lab_upstream_ntp': lab['services']['upstream_ntp'],
        'lab_motd': lab['services']['motd'],
        'lab_slurm_partition': lab['services']['slurm_partition'],
        'lab_slurm_max_time': lab['services']['slurm_max_time'],
    }
