#!/usr/bin/env python3
"""Offline checks for the synthetic Lab configuration adapter."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from jobman_config import ConfigurationError
from lab_configuration import ROOT, inventory_variables, load


class LabConfigurationTests(unittest.TestCase):
    def test_upstream_and_external_version_overrides_are_authoritative(self):
        original, _ = load(ROOT / 'config')
        selected = copy.deepcopy(original)
        selected['versions']['guest_software']['slurm'] = '99.0.0'
        selected['versions']['guest_software']['postgresql_container'] = 'example.invalid/postgres@sha256:' + 'a' * 64
        selected['topology']['nodes']['compute01']['cpus'] = 4
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for key in ['topology', 'versions']:
                (root / (key + '.yml')).write_text(json.dumps(selected[key]))
            document, _ = load(root)
        variables = inventory_variables(document)
        self.assertEqual(variables['lab_slurm_version'], '99.0.0')
        self.assertEqual(variables['lab_postgres_image'], selected['versions']['guest_software']['postgresql_container'])
        self.assertEqual(variables['lab_nodes']['compute01']['cpus'], 4)
        self.assertEqual(variables['lab_control_endpoint'], 'https://control01.lab.test:8080')

    def test_production_inputs_and_duplicate_identities_fail(self):
        original, _ = load(ROOT / 'config')
        for mutate in [lambda value: value['lab'].update(synthetic=False),
                       lambda value: value['lab'].update(namespace='production'),
                       lambda value: value['lab'].update(domain='example.internal'),
                       lambda value: value['nodes']['pg01'].update(address='10.77.0.10'),
                       lambda value: value['lab']['users'][1].update(uid=21001)]:
            selected = copy.deepcopy(original)
            mutate(selected['topology'])
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for key in ['topology', 'versions']:
                    (root / (key + '.yml')).write_text(json.dumps(selected[key]))
                with self.assertRaises(ConfigurationError):
                    load(root)

    def test_unsafe_or_unwired_platform_overrides_fail_before_execution(self):
        original, _ = load(ROOT / 'config')
        overrides = [
            ('versions', 'guest_software', 'slurm', '25.05.8 --checkpoint-action=exec=bad'),
            ('versions', 'guest_software', 'slurm_url', '--config=/private/input'),
            ('versions', 'guest_software', 'slurm_url', 'https://user:secret@example.invalid/source'),
            ('versions', 'guest_software', 'slurm_url', 'http://example.invalid/source'),
            ('versions', 'guest_software', 'postgresql_container', '-option@sha256:' + 'a' * 64),
            ('versions', 'images', 'alma_box', '--option'),
            ('versions', 'images', 'alma_box_architecture', 'amd64'),
            ('versions', 'images', 'windows_iso_sha256', 'unverified'),
            ('versions', 'host_tools', 'packer', '1.17.0'),
            ('versions', 'products', 'jobman_repo', '{{ 7 * 7 }}'),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for document, section, field, value in overrides:
                selected = copy.deepcopy(original)
                selected[document][section][field] = value
                for key in ['topology', 'versions']:
                    (root / (key + '.yml')).write_text(json.dumps(selected[key]))
                with self.subTest(field=field, value=value), self.assertRaises(ConfigurationError):
                    load(root)
            selected = copy.deepcopy(original)
            selected['topology']['nodes']['storage01']['data_disk_mb'] = -1
            for key in ['topology', 'versions']:
                (root / (key + '.yml')).write_text(json.dumps(selected[key]))
            with self.assertRaises(ConfigurationError):
                load(root)
            selected = copy.deepcopy(original)
            selected['topology']['lab']['services']['motd'] = '{{ 7 * 7 }}'
            for key in ['topology', 'versions']:
                (root / (key + '.yml')).write_text(json.dumps(selected[key]))
            with self.assertRaises(ConfigurationError):
                load(root)


if __name__ == '__main__':
    unittest.main()
