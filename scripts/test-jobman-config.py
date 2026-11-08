#!/usr/bin/env python3
"""Offline deployment composition tests; never access Lab state or services."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import jobman_config as config


def deployment(organization='north'):
    return {'apiVersion': config.API_VERSION, 'kind': 'Deployment',
            'metadata': {'organization': organization, 'environment': 'test', 'deployment': organization + '-test'},
            'components': {'client': {'kind': 'jobman', 'config': {'schema_version': 1}}},
            'versions': {'jobman': {'version': 'test', 'sha256': '0' * 64}}}


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'source'
        self.root.mkdir()

    def write(self, name, value):
        data = json.dumps(value).encode() if isinstance(value, dict) else value.encode()
        (self.root / name).write_bytes(data)
        return {'path': name, 'sha256': config.digest(data)}

    def bundle(self, document):
        self.write('deployment.yaml', document)
        return config.Bundle(self.root, 'deployment.yaml')

    def test_layers_origins_empty_reset_and_determinism(self):
        preset = {'apiVersion': config.API_VERSION, 'kind': 'Preset', 'components': {'client': {
            'kind': 'jobman', 'config': {'schema_version': 1, 'concurrency': {'pools': {'batch': 2}},
                                      'presentation': {'display_name': 'Example', 'motd': 'Original'}}}}}
        imported = self.write('preset.yaml', preset)
        document = deployment()
        document['imports'] = [imported]
        document['components']['client']['config'].update({'concurrency': {'pools': {}},
                                                         'presentation': {'motd': 'Updated'}})
        bundle = self.bundle(document)
        effective = bundle.document['components']['client']['config']
        self.assertEqual(effective['concurrency']['pools'], {})
        self.assertEqual(effective['presentation'], {'display_name': 'Example', 'motd': 'Updated'})
        self.assertEqual(bundle.origins['/components/client/config/presentation/display_name'], 'preset.yaml')
        self.assertEqual(bundle.origins['/components/client/config/presentation/motd'], 'deployment.yaml')
        self.assertEqual(bundle.manifest(), self.bundle(document).manifest())

    def test_district_identity_cannot_leak_through_import(self):
        north = deployment('north')
        imported = self.write('north.yaml', north)
        south = deployment('south')
        south['imports'] = [imported]
        with self.assertRaises(config.ConfigurationError):
            self.bundle(south)
        north['kind'] = 'Preset'
        north.pop('metadata')
        north['components']['client']['config']['shared'] = {'current_profile': 'north'}
        south['imports'] = [self.write('north.yaml', north)]
        with self.assertRaises(config.ConfigurationError):
            self.bundle(south)
        self.assertNotEqual(self.bundle(deployment('north')).manifest()['configurationDigest'],
                            self.bundle(deployment('south')).manifest()['configurationDigest'])

    def test_ordered_nested_import_provenance_tracks_only_effective_leaves(self):
        def preset(value, imports=None):
            result = {'apiVersion': config.API_VERSION, 'kind': 'Preset', 'components': {
                'client': {'kind': 'jobman', 'config': {'presentation': value}}}}
            if imports:
                result['imports'] = imports
            return result
        first = self.write('first.yaml', preset({'display_name': 'First', 'motd': 'Remove me'}))
        cleared = self.write('cleared.yaml', preset({}, [first]))
        last = self.write('last.yaml', preset({'display_name': 'Last'}))
        document = deployment()
        document['imports'] = [first, cleared, last]
        bundle = self.bundle(document)
        prefix = '/components/client/config/presentation'
        self.assertEqual(bundle.document['components']['client']['config']['presentation'], {'display_name': 'Last'})
        self.assertEqual({key: value for key, value in bundle.origins.items() if key.startswith(prefix)},
                         {prefix + '/display_name': 'last.yaml'})

    def test_component_retyping_cannot_bypass_preset_identity_guard(self):
        document = deployment()
        document['imports'] = [self.write('preset.yaml', {
            'apiVersion': config.API_VERSION, 'kind': 'Preset', 'components': {
                'client': {'kind': 'jobman', 'config': {'server': 'https://other.example.invalid'}}}})]
        document['components']['client']['kind'] = 'jobman-agent'
        document['versions']['jobman-agent'] = document['versions']['jobman']
        with self.assertRaises(config.ConfigurationError):
            self.bundle(document)
        for kind, field in [('jobman-agent', 'host'), ('jobman-control', 'developmentIssuer'),
                            ('dashboard-worker', 'reports'), ('control-resources', 'expectedInstanceId')]:
            document['imports'] = [self.write('preset.yaml', {
                'apiVersion': config.API_VERSION, 'kind': 'Preset', 'components': {
                    'client': {'kind': kind, 'config': {field: 'other-district'}}}})]
            with self.subTest(kind=kind), self.assertRaises(config.ConfigurationError):
                self.bundle(document)

    def test_explicit_bindings_share_values_without_interpolation(self):
        document = deployment()
        document['bindings'] = {'organization': 'North Example', 'label': '${NO_ENV_EXPANSION}'}
        document['components']['client']['config']['presentation'] = {
            'organization': {'$binding': 'organization'}, 'display_name': {'$binding': 'label'}}
        bundle = self.bundle(document)
        self.assertEqual(bundle.document['components']['client']['config']['presentation'],
                         {'organization': 'North Example', 'display_name': '${NO_ENV_EXPANSION}'})
        self.assertEqual(bundle.binding_origins['/components/client/config/presentation/organization'], '/bindings/organization')
        document['bindings']['organization'] = {'$binding': 'organization'}
        with self.assertRaises(config.ConfigurationError):
            self.bundle(document)

    def test_binding_expansion_is_bounded_before_materializing_output(self):
        document = deployment()
        document['bindings'] = {'value0': 'a'}
        for index in range(1, 12):
            document['bindings'][f'value{index}'] = [{'$binding': f'value{index - 1}'}] * 2
        document['components']['client']['config']['values'] = {'$binding': 'value11'}
        with mock.patch.object(config, 'MAX_NODES', 1000), self.assertRaises(config.ConfigurationError):
            self.bundle(document)
        document['bindings'] = {'large': 'a' * 128}
        document['components']['client']['config']['values'] = [{'$binding': 'large'}] * 20
        with mock.patch.object(config, 'MAX_BUNDLE_BYTES', 2048), self.assertRaises(config.ConfigurationError):
            self.bundle(document)

    def test_strict_yaml_and_schema(self):
        for invalid in ['key: 1\nkey: 2', 'key: &anchor value', 'key: !!str value',
                        'key: null', 'key: .nan', 'key: +.Inf', 'key: .nan\n---\nx: y', 'key: [\n', 'key: 1e9999']:
            with self.subTest(invalid=invalid), self.assertRaises(config.ConfigurationError):
                config.decode(invalid.encode())
        self.assertEqual(config.decode(b'value: off\nnumber: 012\nboolean: false'),
                         {'value': 'off', 'number': '012', 'boolean': False})
        document = deployment()
        document['typo'] = True
        with self.assertRaises(config.ConfigurationError):
            self.bundle(document)

    def test_import_and_asset_digest_path_and_symlink_guards(self):
        document = deployment()
        document['imports'] = [{'path': '../outside.yaml', 'sha256': '0' * 64}]
        with self.assertRaises(config.ConfigurationError):
            self.bundle(document)
        preset = {'apiVersion': config.API_VERSION, 'kind': 'Preset'}
        imported = self.write('preset.yaml', preset)
        imported['sha256'] = '0' * 64
        document['imports'] = [imported]
        with self.assertRaises(config.ConfigurationError):
            self.bundle(document)
        (self.root / 'link.yaml').symlink_to(self.root / 'preset.yaml')
        document['imports'] = [{'path': 'link.yaml', 'sha256': config.digest(json.dumps(preset).encode())}]
        with self.assertRaises(config.ConfigurationError):
            self.bundle(document)
        document.pop('imports')
        self.write('notice.txt', 'Authorized users only.\n')
        document['files'] = [{'source': 'notice.txt', 'destination': 'notices/login.txt',
                              'sha256': config.digest(b'Authorized users only.\n'), 'visibility': 'private'}]
        self.assertIn('notices/login.txt', self.bundle(document).payloads())
        document['files'][0]['destination'] = 'notices/../../escape'
        with self.assertRaises(config.ConfigurationError):
            self.bundle(document)

    def test_secret_canaries_never_echoed(self):
        for field in ['password', 'clientSecret', 'databaseURL', 'agentTokenKey']:
            document = deployment()
            document['components']['client']['config'][field] = 'secret-canary-value'
            self.write('deployment.yaml', document)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = config.main(['validate', '--root', str(self.root), '--profile', 'deployment.yaml'])
            self.assertEqual(status, 1)
            self.assertNotIn('secret-canary-value', stdout.getvalue() + stderr.getvalue())

    def test_render_pins_validator_and_publishes_private_files(self):
        binary = self.base / 'validator'
        binary.write_text('#!/bin/sh\ntest "$1 $2 $3" = "config validate --isolated"\n')
        binary.chmod(0o700)
        document = deployment()
        document['versions']['jobman']['sha256'] = config.digest(binary.read_bytes())
        bundle = self.bundle(document)
        output = self.base / 'release'
        config.render(bundle, output, {'jobman': str(binary)})
        manifest = json.loads((output / 'manifest.json').read_text())
        self.assertTrue(manifest['nativeValidated'])
        self.assertEqual(manifest['files']['origins.json'], config.digest((output / 'origins.json').read_bytes()))
        self.assertEqual((output / 'components/client.yaml').stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(config.ConfigurationError):
            config.render(bundle, output, {'jobman': str(binary)})
        binary.write_text('#!/bin/sh\nexit 0\n')
        with self.assertRaises(config.ConfigurationError):
            config.render(bundle, self.base / 'changed-validator', {'jobman': str(binary)})
        self.assertFalse((self.base / 'changed-validator').exists())

    def test_render_failure_cleans_stage_without_output(self):
        bundle = self.bundle(deployment())
        with self.assertRaises(config.ConfigurationError):
            config.render(bundle, self.base / 'unvalidated', {})
        self.assertFalse((self.base / 'unvalidated').exists())
        self.assertEqual(list(self.base.glob('.jobman-config-*')), [])
        with self.assertRaises(config.ConfigurationError):
            config.render(bundle, self.root / 'output', {})

    def test_production_defaults_fail_closed_and_diff_is_content_free(self):
        document = deployment()
        document['metadata']['environment'] = 'prod'
        document['components'] = {'control': {'kind': 'jobman-control', 'config': {'authMode': 'oidc'}}}
        document['versions']['jobman-control'] = {'version': 'test', 'sha256': '0' * 64}
        with self.assertRaises(config.ConfigurationError):
            self.bundle(document)
        document['components']['control']['config']['migrateOnStart'] = False
        self.bundle(document)
        old = copy.deepcopy(document)
        document['components']['control']['config']['oidcIssuer'] = 'private-value'
        changed = config.changed_paths(old, document)
        self.assertEqual(changed, ['/components/control/config/oidcIssuer'])
        self.assertNotIn('private-value', json.dumps(changed))


if __name__ == '__main__':
    unittest.main()
