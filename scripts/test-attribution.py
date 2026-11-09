#!/usr/bin/env python3
"""Exercise attribution integrity without fetching modules or running a release."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

from attribution_sources import bound_file, checked_zip, go_zip_hashes, module_source


spec = importlib.util.spec_from_file_location('attribution', Path(__file__).with_name('dependency-attribution.py'))
attribution = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attribution)


class AttributionTests(unittest.TestCase):
    def test_module_hash_binds_selected_source_and_keeps_exception(self):
        name, version = 'example.org/module', 'v1.2.3'
        source = b'// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note\npackage example\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'cache/download' / name / '@v' / (version + '.zip')
            path.parent.mkdir(parents=True)
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr(name + '@' + version + '/fixture.go', source)
            archive, records = checked_zip(path)
            with archive:
                checksum, _ = go_zip_hashes(archive, records)
            with self.assertRaisesRegex(ValueError, 'source ZIP differs'):
                module_source(root, name, version, 'h1:unverified')
            hashes, annotations = module_source(root, name, version, checksum)
            file = root / 'fixture.go'
            file.write_bytes(source)
            self.assertEqual(bound_file(root, file.name, hashes), source)
            self.assertEqual(annotations[file.name]['spdxAnnotations'], ['GPL-2.0 WITH Linux-syscall-note'])
            file.write_bytes(source + b'// changed\n')
            with self.assertRaisesRegex(ValueError, 'Source bytes differ'):
                bound_file(root, file.name, hashes)

    def test_spdx_reference_must_bind_to_exact_upstream_file(self):
        checksum = 'a' * 64
        record = {'path': 'example.org/module', 'version': 'v1.2.3', 'notices': [],
                  'exceptionFiles': [{'path': 'NOTICE', 'sha256': checksum, 'selectedBuildInput': False}]}
        package = {'name': record['path'], 'versionInfo': record['version'], 'licenseDeclared': 'NOASSERTION',
                   'licenseConcluded': 'LicenseRef-' + checksum}
        reference = {'licenseId': 'LicenseRef-' + checksum, 'extractedText': 'upstream'}
        document = {'packages': [package], 'hasExtractedLicensingInfos': [reference]}
        executables = {'sample': {'modules': [record]}}
        evidence, = attribution.spdx_evidence(document, executables, {})
        self.assertEqual(evidence['original'], package)
        self.assertEqual(evidence['referenceFiles']['sample'][0]['original'], reference)
        record['exceptionFiles'][0]['sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'unmapped SPDX'):
            attribution.spdx_evidence(document, executables, {})

    def test_wheel_selection_rejects_duplicate_platform_distributions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pins = root / 'requirements.txt'
            pins.write_text('my_pkg==1.2.3\n')
            for filename in ('my_pkg-first.whl', 'my_pkg-second.whl'):
                with zipfile.ZipFile(root / filename, 'w') as archive:
                    archive.writestr('my_pkg-1.2.3.dist-info/METADATA', 'Name: My-Pkg\nVersion: 1.2.3\n')
                    archive.writestr('my_pkg-1.2.3.dist-info/licenses/LICENSE', 'notice\n')
            with self.assertRaisesRegex(ValueError, 'unexpected wheel'):
                attribution.python_wheels(root, pins, {})


if __name__ == '__main__':
    unittest.main()
