#!/usr/bin/env python3
"""Run Jobman shared commands as synthetic Dashboard Alice, using fresh native PKCE.

This is a private Lab helper, not a general OIDC login client. Each invocation
logs in again; it does not save refresh tokens or change identity-provider policy.
Mac log commands require --json: read actual log bytes in Dashboard, since the
Mac does not mount the agents' NFS stores. Long commands retain Jobman's normal
lifetime, but can need a new invocation if their access token expires.
The explicit configuration pins the Lab profile and disables project trust;
Jobman still loads and validates its ordinary system and user configuration.
"""
import argparse
import base64
import fcntl
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ORIGIN = 'https://oidc.lab.test:8443'
ISSUER = ORIGIN + '/realms/jobman-lab'
CONTROL = 'https://10.77.0.21:18443'
NAMESPACE = 'dashboard-operations'
CLIENT = 'jobman-dashboard-native'
AUDIENCE = 'jobman-dashboard-api'
CALLBACK = 'jobman-dashboard-auth://callback'
DIRECTORY_ID = '71000000-0000-4000-8000-000000000001'
PROFILE = 'dashboard-lab'
COMMANDS = {'login', 'run', 'list', 'target', 'status', 'show', 'wait', 'logs',
            'artifacts', 'cancel', 'collection', 'graph', 'operations'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def private_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700, 'Expected an owner-private CLI directory')


def validate_file(info, path, private=False, maximum=65536):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum,
            'Expected a bounded regular Lab file: ' + path.name)
    if private:
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                'Lab credentials must be an owner-private regular file')


def read_file(path, private=False, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        validate_file(os.fstat(stream.fileno()), path, private, maximum)
        data = stream.read(maximum + 1)
        require(len(data) <= maximum, 'Lab file exceeds the size limit')
        return data


def write_private(path, data):
    # Inspect the directory entry without opening the old token. An open inode
    # can have zero links after atomic replacement, even when the new entry is
    # valid. We only replace this entry; we never read or modify its old inode.
    try:
        info = path.lstat()
    except FileNotFoundError:
        pass
    else:
        validate_file(info, path, private=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener(context, cookies=False):
    handlers = [urllib.request.ProxyHandler({}), NoRedirect(),
                urllib.request.HTTPSHandler(context=context)]
    if cookies:
        handlers.append(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    return urllib.request.build_opener(*handlers)


def request(client, url, *, form=None, token=None):
    headers = {'Accept': 'application/json, text/html'}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    try:
        response = client.open(urllib.request.Request(url, data=data, headers=headers), timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read((1 << 20) + 1)
        require(len(body) <= 1 << 20, 'Lab HTTP response exceeds the size limit')
        return response.status, response.headers, body


def json_response(result, message):
    status, _, body = result
    require(status == 200, message)
    value = json.loads(body)
    require(isinstance(value, dict), message)
    return value


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.actions = []

    def handle_starttag(self, tag, attrs):
        if tag != 'form':
            return
        values = dict(attrs)
        if values.get('id') == 'kc-form-login':
            require(len(attrs) == len(values), 'Ambiguous Lab sign-in form')
            self.actions.append(values.get('action', ''))


def form_action(body):
    form = LoginForm()
    form.feed(body.decode('utf-8'))
    require(len(form.actions) == 1, 'Expected the synthetic Keycloak sign-in form')
    action = form.actions[0]
    parsed = urllib.parse.urlsplit(action)
    require(parsed.scheme == 'https' and parsed.netloc == 'oidc.lab.test:8443' and
            parsed.path.startswith('/realms/jobman-lab/login-actions/') and
            not parsed.fragment and not any(c.isspace() for c in action),
            'Lab sign-in action escaped the pinned identity origin')
    return action


def callback_code(location, state):
    parsed = urllib.parse.urlsplit(location)
    require(parsed.scheme == 'jobman-dashboard-auth' and parsed.netloc == 'callback' and
            parsed.path == '' and not parsed.fragment, 'Unexpected Lab sign-in callback')
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    require(query.get('state') == [state] and len(query.get('code', [])) == 1 and
            query['code'][0] and 'error' not in query and
            query.get('iss', [ISSUER]) == [ISSUER], 'Lab authorization state or code was invalid')
    return query['code'][0]


def jwt_claims(token):
    # These claims come from the pinned TLS token endpoint. Control separately
    # authenticates the access token's signature before any token is persisted.
    pieces = token.split('.')
    require(len(pieces) == 3 and len(token) <= 65536, 'Invalid Lab token shape')
    data = base64.urlsafe_b64decode(pieces[1] + '=' * (-len(pieces[1]) % 4))
    value = json.loads(data)
    require(isinstance(value, dict), 'Invalid Lab token claims')
    return value


def identity_context(root):
    spec = importlib.util.spec_from_file_location('iphone_gateway_tls', Path(__file__).with_name('iphone-gateway.py'))
    gateway = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gateway)
    return gateway.tls_context(root / '.lab/certs/lab-ca.crt')


def login(root):
    public = json.loads(read_file(root / '.lab/dashboard/oidc-public.json'))
    require(public.get('issuer') == ISSUER and public.get('audience') == AUDIENCE and
            public.get('nativeClientId') == CLIENT, 'Lab identity configuration differs')
    users = [u for u in public.get('users', []) if u.get('username') == 'dashboard-alice']
    require(len(users) == 1 and users[0].get('directoryGuid') == DIRECTORY_ID and
            users[0].get('subject'), 'Synthetic Alice identity is unavailable')
    subject = users[0]['subject']
    contents = read_file(root / '.lab/credentials/dashboard.env', private=True).decode()
    passwords = [line.partition('=')[2].strip() for line in contents.splitlines()
                 if line.partition('=')[0] == 'JOBMAN_LAB_DASHBOARD_ALICE_PASSWORD']
    require(len(passwords) == 1 and len(passwords[0]) == 64, 'Synthetic Alice credentials are unavailable')
    client = opener(identity_context(root), cookies=True)
    discovery = json_response(request(client, ISSUER + '/.well-known/openid-configuration'),
                              'Lab identity discovery failed')
    authorization = ISSUER + '/protocol/openid-connect/auth'
    exchange = ISSUER + '/protocol/openid-connect/token'
    require(discovery.get('issuer') == ISSUER and discovery.get('authorization_endpoint') == authorization and
            discovery.get('token_endpoint') == exchange, 'Lab identity endpoints differ')
    state, nonce, verifier = [secrets.token_urlsafe(32) for _ in range(3)]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    query = urllib.parse.urlencode({'response_type': 'code', 'client_id': CLIENT, 'redirect_uri': CALLBACK,
                                  'scope': 'openid profile', 'state': state, 'nonce': nonce,
                                  'resource': AUDIENCE, 'code_challenge': challenge, 'code_challenge_method': 'S256'})
    status, _, body = request(client, authorization + '?' + query)
    require(status == 200, 'Lab sign-in form was unavailable')
    action = form_action(body)
    status, headers, _ = request(client, action, form={'username': 'dashboard-alice',
                                                     'password': passwords[0], 'credentialId': ''})
    require(status == 302, 'Synthetic Alice sign-in failed')
    code = callback_code(headers.get('Location', ''), state)
    token = json_response(request(client, exchange, form={'grant_type': 'authorization_code',
                          'client_id': CLIENT, 'redirect_uri': CALLBACK, 'code': code,
                          'code_verifier': verifier, 'resource': AUDIENCE}), 'Lab PKCE exchange failed')
    access = token.get('access_token', '')
    require(isinstance(access, str) and access and not any(c.isspace() for c in access) and
            token.get('token_type', '').lower() == 'bearer', 'No usable Lab access token')
    access_claims = jwt_claims(access)
    identity = jwt_claims(token.get('id_token', ''))
    for claims in (access_claims, identity):
        require(claims.get('iss') == ISSUER and claims.get('sub') == subject and
                claims.get('directory_guid') == DIRECTORY_ID and
                isinstance(claims.get('exp'), (int, float)) and claims['exp'] > time.time() + 10,
                'Lab token identity or expiry differs')
    audience = access_claims.get('aud')
    require(AUDIENCE in ([audience] if isinstance(audience, str) else audience or []) and
            access_claims.get('azp') == CLIENT and identity.get('nonce') == nonce and
            identity.get('aud') in (CLIENT, [CLIENT]), 'Lab token audience or nonce differs')
    control_context = ssl.create_default_context(cafile=str(root / '.lab/dashboard/runtime/control/fixture-ca.crt'))
    current = json_response(request(opener(control_context), CONTROL + '/v1/me?limit=200', token=access),
                            'Control rejected the Lab access token')
    principal = current.get('principal', {})
    require(current.get('kind') == 'CurrentPrincipal' and principal.get('issuer') == ISSUER and
            principal.get('subject') == subject and
            principal.get('directoryId', DIRECTORY_ID) == DIRECTORY_ID and
            any(n.get('name') == NAMESPACE for n in current.get('namespaces', [])),
            'Control did not confirm Alice and the Dashboard namespace')
    return access


def validate_command(arguments):
    require(arguments and arguments[0] in COMMANDS, 'Choose a supported shared command; use --help')
    options = arguments[:arguments.index('--')] if '--' in arguments else arguments
    for value in options:
        require(value.split('=', 1)[0] not in ('--config', '--state-dir', '--profile', '--no-extensions'),
                'The Lab wrapper owns configuration, profile, and state selection')
    if arguments[0] == 'login':
        require(len(arguments) == 1, 'login does not accept further arguments')
    if arguments[0] == 'logs':
        json_flags = [value for value in options if value == '--json' or value.startswith('--json=')]
        require(len(json_flags) == 1 and json_flags[0] in ('--json', '--json=true') and
                not any(value.split('=', 1)[0] in ('--follow', '-f') for value in options),
                'Mac log commands require --json; read live log contents in Dashboard')


def execute(root, arguments):
    validate_command(arguments)
    require(root.is_absolute() and root.is_dir(), '--lab-root must be an existing absolute Lab path')
    root = root.resolve()
    # Do not follow state-directory links into another user or checkout.
    for parent in (root / '.lab', root / '.lab/dashboard'):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o022 == 0,
                'Lab state parents must be owned by this user and not writable by others')
    directory = root / '.lab/dashboard/cli'
    private_directory(directory)
    private_directory(directory / 'state')
    lock = os.open(directory / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, 'r+') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
                info.st_mode & 0o077 == 0, 'Expected a private CLI operation lock')
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Another Lab CLI login is running; retry shortly') from exc
        executable = shutil.which('jobman')
        require(executable, 'Install the Jobman CLI before using this helper')
        access = login(root)
        write_private(directory / 'access-token', (access + '\n').encode())
        # Core's explicit-file sequence replaces the inherited trust-root list
        # before project discovery; its ordinary system/user files still load.
        config = {'trusted_project_roots': [], 'shared': {'current_profile': PROFILE, 'profiles': {PROFILE: {
            'endpoint': CONTROL, 'namespace': NAMESPACE, 'token_file': str(directory / 'access-token'),
            'ca_file': str(root / '.lab/dashboard/runtime/control/fixture-ca.crt')}}}}
        write_private(directory / 'config.yaml', (json.dumps(config, indent=2) + '\n').encode())
        if arguments == ['login']:
            print('Signed in as synthetic dashboard-alice for dashboard-operations; token saved privately.')
            return 0
        command = [executable, '--config', str(directory / 'config.yaml'), '--state-dir', str(directory / 'state'),
                   '--no-extensions', 'shared', '--profile', PROFILE, *arguments]
    # Release the login lock before long waits. Other commands can cancel jobs
    # or refresh the same Alice token while Jobman rereads it for each request.
    return subprocess.run(command, check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-root', required=True, type=Path, help='Absolute existing Jobman Lab checkout')
    parser.add_argument('arguments', nargs=argparse.REMAINDER, help='login, or a Jobman shared command and arguments')
    args = parser.parse_args()
    return execute(args.lab_root, args.arguments)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except RuntimeError as exc:
        print('Dashboard Lab CLI: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        # HTTP errors can contain credential-bearing URLs or response content.
        print('Dashboard Lab CLI: operation failed; check Lab services, TLS trust, and private setup files.', file=sys.stderr)
        sys.exit(1)
