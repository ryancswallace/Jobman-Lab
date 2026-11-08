#!/usr/bin/env python3
"""Opt-in offline integration against explicitly selected component binaries."""
import argparse
import copy
import json
from pathlib import Path
import tempfile

from jobman_config import Bundle, canonical, digest, render


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    documents = {
        'jobman': {'schema_version': 1, 'presentation': {'organization': 'Synthetic North', 'display_name': 'North Jobman'}},
        'jobman-agent': {'schema_version': 1},
        'jobman-diagnose': {'schema_version': 2, 'defaults': {'profile': 'metadata'}, 'profiles': {'metadata': {
            'provider': 'command', 'locality': 'local', 'command': {'executable': '/bin/false'},
            'model': 'synthetic', 'require_json_schema': True, 'timeout': '30s',
            'maximum_input_bytes': 4096, 'maximum_output_bytes': 1024,
            'disclosure': {'metadata': {'maximum_items': 10, 'maximum_bytes': 4096}},
            'source_context': {'mode': 'none'}}}},
    }
    examples = {
        'jobman-control': 'jobman-control/etc/jobman-control/config.example.json',
        'control-directory': 'jobman-control/etc/jobman-control/directory.example.json',
        'control-delegation': 'jobman-control/etc/jobman-control/delegation.example.json',
        'control-resources': 'jobman-control/etc/jobman-control/resources.example.json',
        'dashboard-api': 'jobman-dashboard/deploy/config.example.json',
        'dashboard-worker': 'jobman-dashboard/deploy/worker.example.json',
        'dashboard-operator': 'jobman-dashboard/deploy/operator.example.json',
        'dashboard-broker': 'jobman-dashboard/deploy/log-broker.example.json',
    }
    for kind, relative in examples.items():
        documents[kind] = json.loads((args.source_root / relative).read_text())
    validators = {}
    versions = {}
    for kind in documents:
        binary_name = ('jobman-log-broker' if kind == 'dashboard-broker' else
                       'jobman-dashboard' if kind.startswith('dashboard-') else
                       'jobman-control' if kind.startswith('control-') else kind)
        binary = (args.bin_dir / binary_name).resolve(strict=True)
        validators[kind] = str(binary)
        versions[kind] = {'version': 'offline-working-tree-integration', 'sha256': digest(binary.read_bytes())}
    with tempfile.TemporaryDirectory(prefix='jobman-native-config-') as temporary:
        root = Path(temporary).resolve() / 'source'
        root.mkdir()
        configuration_digests = set()
        for organization in ['north', 'south']:
            components = copy.deepcopy(documents)
            components['jobman']['presentation'] = {'organization': organization.title() + ' Example',
                                                    'display_name': organization.title() + ' Jobman'}
            components['jobman-control']['oidcIssuer'] = f'https://identity.{organization}.example.invalid'
            profile = {'apiVersion': 'jobman.config/v1alpha1', 'kind': 'Deployment',
                       'metadata': {'organization': organization, 'environment': 'test', 'deployment': organization + '-test'},
                       'components': {kind: {'kind': kind, 'config': value} for kind, value in components.items()},
                       'versions': versions}
            (root / 'profile.yaml').write_bytes(canonical(profile))
            bundle = Bundle(root, 'profile.yaml')
            output = root.parent / organization
            render(bundle, output, validators)
            manifest = json.loads((output / 'manifest.json').read_text())
            assert manifest['nativeValidated'] is True
            assert len(manifest['files']) == len(documents) + 1  # Includes provenance.
            for name, expected in manifest['files'].items():
                assert digest((output / name).read_bytes()) == expected
            control = json.loads((output / 'components/jobman-control.json').read_text())
            assert control['oidcIssuer'] == f'https://identity.{organization}.example.invalid'
            configuration_digests.add(manifest['configurationDigest'])
        assert len(configuration_digests) == 2
    print(f'{len(documents)} native configuration kinds validated for two synthetic organizations without secrets or services')


if __name__ == '__main__':
    main()
