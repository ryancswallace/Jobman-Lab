"""Strict, offline deployment composition. Native binaries own native validation."""
import argparse
import copy
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

import yaml
from jsonschema import Draft202012Validator

API_VERSION = 'jobman.config/v1alpha1'
TOOL_VERSION = '1.0.0'
MAX_BYTES = 4 * 1024 * 1024
MAX_FILES = 64
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_NODES = 100000
SCHEMA = Path(__file__).resolve().parents[1] / 'config/deployment.schema.json'
YAML_KINDS = {'jobman', 'jobman-agent', 'jobman-diagnose'}
# These fields must be selected in the entry document, never inherited from a preset.
IDENTITY_FIELDS = {
    'jobman': {'shared', 'secrets', 'trusted_project_roots', 'notifiers'},
    'jobman-agent': {'server', 'target_generation', 'token_file', 'server_ca', 'state_dir',
                     'artifact_root', 'artifact_s3_bucket', 'artifact_s3_expected_owner',
                     'artifact_store', 'artifact_store_version', 'artifact_s3_prefix', 'artifact_s3_region',
                     'host', 'agent_binary', 'ssh', 'container_runtime', 'aws_cli', 'slurm_root',
                     'slurm_runner', 'remote_binary', 'remote_state_dir', 'unit_dir'},
    'jobman-control': {'authMode', 'oidcIssuer', 'oidcAudience', 'databaseURLFile', 'agentTokenKeyFile',
                       'bootstrapSubject', 'bootstrapName', 'bootstrapNamespace', 'tlsCertificateFile',
                       'tlsKeyFile', 'agentCACertificateFile', 'agentCAKeyFile', 'directoryConfigFile',
                       'delegationRegistryFile', 'delegationClientCAFile', 'diagnosticDeploymentId',
                       'developmentAuth', 'developmentIssuer', 'developmentSubject', 'developmentName',
                       'developmentNamespace', 'directoryMode', 'listen'},
    'jobman-diagnose': {'profiles'},
    'dashboard-api': {'oidc', 'controls', 'logBrokers', 'logMappings', 'encryption', 'notifications',
                      'databaseURLFile', 'serverTLS', 'publicOrigin', 'logCursorKeyFile', 'reports',
                      'observability', 'configurationRevision'},
    'dashboard-worker': {'identityIssuer', 'controls', 'logBrokers', 'logMappings', 'notifications',
                         'databaseURLFile', 'logCursorKeyFile', 'reports', 'observability', 'configurationRevision'},
    'dashboard-broker': {'controls', 'services', 'logRoots', 'clientTrustRootsFile', 'serverTLS', 'publicOrigin',
                         'stateDirectory', 'observability', 'configurationRevision'},
    'dashboard-operator': {'databaseURLFile', 'deployments'},
    'control-resources': {'resources', 'endpoint', 'expectedInstanceId', 'expectedRecoveryEpoch'},
    'control-directory': {'url', 'baseDn', 'bindDn', 'passwordFile', 'caFile', 'mapping'},
    'control-delegation': {'services'},
}


class ConfigurationError(ValueError):
    """An intentionally content-free configuration error."""


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pointer(parts):
    return '/' + '/'.join(str(part).replace('~', '~0').replace('/', '~1') for part in parts)


def read_regular(path, limit=MAX_BYTES):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ConfigurationError('input must be a bounded regular file')
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ConfigurationError('input exceeds size limit')
        return data
    except OSError as error:
        raise ConfigurationError('cannot read configuration input') from error


def confined(root, parent, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute():
        raise ConfigurationError('bundle references must be relative paths')
    candidate = parent / name
    # Reject symlinks, including intermediate directories, before resolving.
    absolute = Path(os.path.abspath(candidate))
    if not absolute.is_relative_to(root):
        raise ConfigurationError('bundle reference escapes configuration root')
    current = root
    for part in absolute.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise ConfigurationError('bundle references cannot follow symbolic links')
    return absolute


def decode(data):
    """JSON-compatible YAML scalars, unique string keys, no aliases/tags/nulls."""
    try:
        for token in yaml.scan(data):
            if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken)):
                raise ConfigurationError('YAML anchors, aliases and explicit tags are not supported')
        node = yaml.compose(data, Loader=yaml.BaseLoader)

        nodes = 0

        def visit(value, depth=0):
            nonlocal nodes
            nodes += 1
            if nodes > MAX_NODES:
                raise ConfigurationError('configuration node count exceeds limit')
            if depth > 32:
                raise ConfigurationError('configuration nesting exceeds limit')
            if isinstance(value, yaml.MappingNode):
                result = {}
                for key, child in value.value:
                    if not isinstance(key, yaml.ScalarNode) or key.value == '<<' or key.value in result:
                        raise ConfigurationError('mapping keys must be unique strings')
                    result[key.value] = visit(child, depth + 1)
                return result
            if isinstance(value, yaml.SequenceNode):
                return [visit(child, depth + 1) for child in value.value]
            if not isinstance(value, yaml.ScalarNode):
                raise ConfigurationError('configuration document is empty or invalid')
            if value.style is None:
                if value.value in ('null', 'Null', 'NULL', '~', ''):
                    raise ConfigurationError('null is not supported; use explicit empty collections')
                if value.value in ('true', 'false'):
                    return value.value == 'true'
                if value.value.lower() in ('.nan', '.inf', '+.inf', '-.inf'):
                    raise ConfigurationError('nonfinite numbers are not supported')
                if re.fullmatch(r'-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?', value.value):
                    number = json.loads(value.value)
                    if isinstance(number, float) and not math.isfinite(number):
                        raise ConfigurationError('nonfinite numbers are not supported')
                    return number
            return value.value

        return visit(node)
    except (yaml.YAMLError, UnicodeError, RecursionError, ValueError) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError('configuration is not valid restricted YAML') from error


def reject_secret_values(value):
    """Reject known inline secret forms; native validators remain authoritative."""
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub('[^a-z]', '', key.lower())
            if normalized in {'password', 'apikey', 'clientsecret', 'privatekey', 'agenttokenkey', 'databaseurl', 'accesstoken', 'refreshtoken'}:
                raise ConfigurationError('inline secret fields are forbidden; use credential file references')
            reject_secret_values(item)
    elif isinstance(value, list):
        for item in value:
            reject_secret_values(item)
    elif isinstance(value, str):
        if re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----|\b[a-z][a-z0-9+.-]*://[^/\s]+:[^/\s]+@', value):
            raise ConfigurationError('inline secret material is forbidden')


def merge(base, overlay, origins, source, path=()):
    if isinstance(base, dict) and isinstance(overlay, dict) and overlay:
        if len(path) == 2 and path[0] == 'components' and base.get('kind') != overlay.get('kind'):
            raise ConfigurationError('component kind cannot change across configuration layers')
        origins.pop(pointer(path), None)
        result = copy.deepcopy(base)
        for key, value in overlay.items():
            result[key] = merge(result.get(key), value, origins, source, (*path, key))
        return result
    prefix = pointer(path)
    if isinstance(base, (dict, list)) and base:
        for key in list(origins):
            if key == prefix or key.startswith(prefix + '/'):
                del origins[key]
    else:
        origins.pop(prefix, None)
    result = copy.deepcopy(overlay)

    def record(item, parts):
        if isinstance(item, dict) and item:
            for key, child in item.items():
                record(child, (*parts, key))
        elif isinstance(item, list) and item:
            for index, child in enumerate(item):
                record(child, (*parts, index))
        else:
            origins[pointer(parts)] = source
    record(result, path)
    return result


class Bundle:
    def __init__(self, root, entry):
        self.root = Path(root).resolve(strict=True)
        self.sources = {}
        self.origins = {}
        self.assets = {}
        self.input_bytes = 0
        self.load_count = 0
        schema_data = read_regular(SCHEMA)
        self.schema_digest = digest(schema_data)
        schema = json.loads(schema_data)
        Draft202012Validator.check_schema(schema)
        self.validator = Draft202012Validator(schema)
        self.document, self.origins = self._load(confined(self.root, self.root, entry), [])
        if self.document['kind'] != 'Deployment':
            raise ConfigurationError('entry document must be a Deployment')
        self.binding_origins = {}
        self._resolve_bindings()
        self._validate_effective()

    def _load(self, path, stack, expected_digest=None):
        self.load_count += 1
        if path in stack or len(stack) > 16 or self.load_count > MAX_FILES:
            raise ConfigurationError('import cycle or import limit exceeded')
        encoded = read_regular(path)
        encoded_digest = digest(encoded)
        if expected_digest is not None and encoded_digest != expected_digest:
            raise ConfigurationError('import digest mismatch')
        self.input_bytes += len(encoded)
        if self.input_bytes > MAX_BUNDLE_BYTES:
            raise ConfigurationError('combined configuration inputs exceed size limit')
        document = decode(encoded)
        if next(self.validator.iter_errors(document), None) is not None:
            raise ConfigurationError('document does not satisfy deployment schema')
        reject_secret_values(document)
        source = path.relative_to(self.root).as_posix()
        if source in self.sources and self.sources[source] != encoded_digest:
            raise ConfigurationError('configuration input changed during composition')
        self.sources[source] = encoded_digest
        if stack and document['kind'] != 'Preset':
            raise ConfigurationError('imports must select Preset documents, never another deployment')
        if document['kind'] == 'Preset':
            if document.get('bindings'):
                raise ConfigurationError('shared bindings must be selected in the entry document')
            for component in document.get('components', {}).values():
                if IDENTITY_FIELDS[component['kind']] & component['config'].keys():
                    raise ConfigurationError('preset contains deployment-specific trust or identity; select it in the entry document')
                presentation = component['config'].get('presentation', {})
                if component['kind'].startswith('dashboard-') and isinstance(presentation, dict) and 'contentLinkScheme' in presentation:
                    raise ConfigurationError('native application registration must be selected in the entry document')
            if document.get('files'):
                raise ConfigurationError('deployment assets and integration files must be selected in the entry document')
        result = {}
        origins = {}
        for imported in document.get('imports', []):
            dependency = confined(self.root, path.parent, imported['path'])
            inherited, inherited_origins = self._load(dependency, [*stack, path], imported['sha256'])
            result = merge(result, inherited, origins, source)
            origins.update(inherited_origins)
        own = {key: value for key, value in document.items() if key != 'imports'}
        result = merge(result, own, origins, source)
        for item in document.get('files', []):
            target = item['destination']
            if '..' in Path(target).parts or target in self.assets or str(Path(target)) != target:
                raise ConfigurationError('asset destinations must be unique confined paths')
            contents = read_regular(confined(self.root, path.parent, item['source']))
            self.input_bytes += len(contents)
            if self.input_bytes > MAX_BUNDLE_BYTES:
                raise ConfigurationError('combined configuration inputs exceed size limit')
            if digest(contents) != item['sha256']:
                raise ConfigurationError('asset digest mismatch')
            reject_secret_values(contents.decode('utf-8', errors='replace'))
            self.assets[target] = contents
        return result, origins

    def _resolve_bindings(self):
        bindings = self.document.get('bindings', {})
        expanded_bytes = 0
        nodes = 0

        def resolve(item, path=(), stack=()):
            nonlocal expanded_bytes, nodes
            nodes += 1
            if len(stack) > 16 or len(path) > 32 or nodes > MAX_NODES:
                raise ConfigurationError('binding expansion exceeds depth or node limit')
            expanded_bytes += (sum(len(canonical(key)) + 1 for key in item) + 2 if isinstance(item, dict)
                               else len(item) + 2 if isinstance(item, list) else len(canonical(item)) + 1)
            if expanded_bytes > MAX_BUNDLE_BYTES:
                raise ConfigurationError('binding expansion exceeds size limit')
            if isinstance(item, dict):
                if '$binding' in item:
                    name = item['$binding']
                    if len(item) != 1 or not isinstance(name, str) or name not in bindings or name in stack:
                        raise ConfigurationError('binding must select one defined noncyclic entry value')
                    self.binding_origins[pointer(path)] = '/bindings/' + name
                    return resolve(bindings[name], path, (*stack, name))
                return {key: resolve(value, (*path, key), stack) for key, value in item.items()}
            if isinstance(item, list):
                return [resolve(value, (*path, index), stack) for index, value in enumerate(item)]
            return item

        self.document['components'] = resolve(self.document.get('components', {}), ('components',))
        reject_secret_values(self.document['components'])

    def _validate_effective(self):
        if next(self.validator.iter_errors(self.document), None) is not None:
            raise ConfigurationError('effective document does not satisfy deployment schema')
        if len(canonical(self.document)) > MAX_BUNDLE_BYTES:
            raise ConfigurationError('effective configuration exceeds size limit')
        if not self.document.get('components'):
            raise ConfigurationError('deployment requires at least one component')
        for name, component in self.document['components'].items():
            if component['kind'] not in self.document['versions']:
                raise ConfigurationError('each component kind requires a pinned version and executable digest')
            if self.document['metadata']['environment'] == 'prod':
                config = component['config']
                if config.get('authMode') == 'development' or config.get('developmentAuth') is True or config.get('fixture') is True:
                    raise ConfigurationError('production cannot select development or fixture authentication')
                if component['kind'] == 'jobman-control' and config.get('migrateOnStart', True):
                    raise ConfigurationError('production Control requires a separate migration stage')
            if not re.fullmatch('[a-z][a-z0-9._-]{0,63}', name):
                raise ConfigurationError('invalid component identity')

    def payloads(self):
        result = dict(self.assets)
        result['origins.json'] = canonical({'origins': self.origins, 'bindings': self.binding_origins}) + b'\n'
        for name, component in sorted(self.document['components'].items()):
            suffix = 'yaml' if component['kind'] in YAML_KINDS else 'json'
            config = component['config']
            data = yaml.safe_dump(config, sort_keys=True, allow_unicode=True).encode() if suffix == 'yaml' else canonical(config) + b'\n'
            result[f'components/{name}.{suffix}'] = data
        if sum(map(len, result.values())) > MAX_BUNDLE_BYTES:
            raise ConfigurationError('rendered configuration exceeds size limit')
        return result

    def manifest(self, native_validated=False):
        return {
            'apiVersion': API_VERSION, 'rendererVersion': TOOL_VERSION,
            'rendererDigest': digest(read_regular(Path(__file__))),
            'runtimeVersions': {'PyYAML': importlib.metadata.version('PyYAML'),
                                'jsonschema': importlib.metadata.version('jsonschema')},
            'schemaDigest': self.schema_digest, 'metadata': self.document['metadata'],
            'sources': dict(sorted(self.sources.items())), 'versions': self.document['versions'],
            'files': {name: digest(data) for name, data in sorted(self.payloads().items())},
            'configurationDigest': digest(canonical(self.document)),
            'nativeValidated': native_validated,
        }


def validator_command(kind, binary, path):
    if kind == 'jobman':
        return [binary, 'config', 'validate', '--isolated', str(path)]
    if kind in {'jobman-agent', 'jobman-diagnose'}:
        return [binary, 'config', 'validate', str(path)]
    if kind == 'jobman-control':
        return [binary, '--config', str(path), '--check-config']
    if kind == 'dashboard-broker':
        return [binary, '--config', str(path), '--mode', 'validate-config']
    if kind in {'dashboard-api', 'dashboard-worker', 'dashboard-operator'}:
        mode = kind.removeprefix('dashboard-')
        return [binary, '--config', str(path), '--mode', 'validate-config', '--check-mode', mode]
    if kind in {'control-directory', 'control-delegation', 'control-resources'}:
        return [binary, 'config', 'validate', '--kind', kind.removeprefix('control-'), str(path)]
    raise ConfigurationError('component kind lacks a native validator')


def native_validate(bundle, validators, directory):
    for name, component in sorted(bundle.document['components'].items()):
        kind = component['kind']
        binary = validators.get(kind)
        if not binary or not Path(binary).is_absolute():
            raise ConfigurationError('render requires an absolute native validator for every component kind')
        if digest(read_regular(Path(binary), 512 * 1024 * 1024)) != bundle.document['versions'][kind]['sha256']:
            raise ConfigurationError('native validator executable digest mismatch')
        suffix = 'yaml' if kind in YAML_KINDS else 'json'
        # Native validators receive no inherited credentials or configuration overrides.
        environment = {'PATH': os.defpath, 'HOME': str(directory), 'XDG_CONFIG_HOME': str(directory),
                       'XDG_STATE_HOME': str(directory), 'TMPDIR': str(directory)}
        try:
            result = subprocess.run(validator_command(kind, binary, directory / f'components/{name}.{suffix}'),
                                    env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ConfigurationError('native configuration validation could not complete') from error
        if result.returncode:
            raise ConfigurationError('native configuration validation rejected a component; inspect privately with its validator')


def write_payloads(directory, payloads):
    for name, data in sorted(payloads.items()):
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())


def render(bundle, output, validators):
    output = Path(os.path.abspath(output))
    if output.exists() or output.is_symlink() or output.is_relative_to(bundle.root):
        raise ConfigurationError('output must be new and outside the configuration source root')
    parent = output.parent.resolve(strict=True)
    if parent != output.parent or any((path / '.git').exists() for path in [parent, *parent.parents]):
        raise ConfigurationError('output must be outside Git worktrees and symbolic-link paths')
    stage = Path(tempfile.mkdtemp(prefix='.jobman-config-', dir=parent))
    try:
        write_payloads(stage, bundle.payloads())
        native_validate(bundle, validators, stage)
        write_payloads(stage, {'manifest.json': canonical(bundle.manifest(True)) + b'\n'})
        # Exclusively claim the destination. The manifest is published last as
        # the completion marker; consumers must verify it before installation.
        try:
            output.mkdir(mode=0o700)
        except FileExistsError as error:
            raise ConfigurationError('output already exists') from error
        try:
            for child in sorted(stage.iterdir(), key=lambda item: (item.name == 'manifest.json', item.name)):
                os.rename(child, output / child.name)
        except OSError:
            shutil.rmtree(output)
            raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def changed_paths(left, right, path=()):
    if isinstance(left, dict) and isinstance(right, dict):
        result = []
        for key in sorted(left.keys() | right.keys()):
            if key not in left or key not in right:
                result.append(pointer((*path, key)))
            else:
                result.extend(changed_paths(left[key], right[key], (*path, key)))
        return result
    return [] if left == right else [pointer(path)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['validate', 'render', 'explain', 'diff', 'schema'])
    parser.add_argument('--root', type=Path)
    parser.add_argument('--profile')
    parser.add_argument('--against', help='second entry profile under the same root')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--validator', action='append', default=[], metavar='KIND=/ABSOLUTE/BINARY')
    args = parser.parse_args(argv)
    try:
        if args.command == 'schema':
            print(read_regular(SCHEMA).decode())
            return 0
        if args.root is None or args.profile is None:
            raise ConfigurationError('--root and --profile are required')
        bundle = Bundle(args.root, args.profile)
        validators = {}
        for selection in args.validator:
            kind, separator, binary = selection.partition('=')
            if not separator or kind in validators:
                raise ConfigurationError('validator selections must be unique KIND=/ABSOLUTE/BINARY pairs')
            validators[kind] = binary
        if args.command == 'render':
            if args.output is None:
                raise ConfigurationError('render requires --output')
            render(bundle, args.output, validators)
            print(json.dumps({'rendered': True, 'configurationDigest': bundle.manifest()['configurationDigest']}))
        elif args.command == 'explain':
            print(json.dumps({'origins': bundle.origins, 'bindings': bundle.binding_origins}, indent=2, sort_keys=True))
        elif args.command == 'diff':
            if not args.against:
                raise ConfigurationError('diff requires --against')
            other = Bundle(args.root, args.against)
            print(json.dumps({'changedPaths': changed_paths(bundle.document, other.document),
                              'valuesIncluded': False}, indent=2))
        else:
            if validators:
                with tempfile.TemporaryDirectory(prefix='jobman-config-check-') as temporary:
                    directory = Path(temporary)
                    write_payloads(directory, bundle.payloads())
                    native_validate(bundle, validators, directory)
            print(json.dumps({'valid': True, 'nativeValidated': bool(validators),
                              'configurationDigest': bundle.manifest()['configurationDigest']}))
        return 0
    except (ConfigurationError, OSError) as error:
        # Do not include parser, subprocess or filesystem details which may echo data.
        message = str(error) if isinstance(error, ConfigurationError) else 'configuration filesystem operation failed'
        print('jobman-config: ' + message, file=sys.stderr)
        return 1
