#!/usr/bin/env python3
"""Reconcile only marked Dashboard Lab identities through verified local HTTPS.

The administrative token and all credentials remain in memory/private files.
This fixture proves OIDC mechanics; it is not an AD FS compatibility claim.
"""
import json
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = 'https://oidc.lab.test:8443'
REALM = '/admin/realms/jobman-lab'
DIRECTORY_ATTRIBUTE = 'dashboard_directory_guid'
CLAIM = 'directory_guid'
OWNER = 'jobman-dashboard-lab-v1'
ROOT = Path('/etc/jobman-dashboard-lab')
CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError('Identity endpoint unexpectedly redirected')


class Admin:
    def __init__(self):
        self.token = None
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=CA)), NoRedirect())
        env = dict(line.split('=', 1) for line in Path('/etc/jobman-lab/keycloak.env').read_text().splitlines() if '=' in line)
        body = urllib.parse.urlencode({'grant_type': 'password', 'client_id': 'admin-cli',
                                      'username': env['KC_BOOTSTRAP_ADMIN_USERNAME'],
                                      'password': env['KC_BOOTSTRAP_ADMIN_PASSWORD']}).encode()
        self.token = self.request('POST', '/realms/master/protocol/openid-connect/token', body,
                                  'application/x-www-form-urlencoded')['access_token']

    def request(self, method, path, body=None, content_type='application/json'):
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode()
        headers = {'Content-Type': content_type}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        try:
            with self.opener.open(urllib.request.Request(BASE + path, data=body, method=method,
                                                        headers=headers), timeout=15) as response:
                data = response.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise RuntimeError('Identity response exceeded fixture bound')
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            # Never echo an identity error body (it may contain credentials).
            raise RuntimeError(f'Identity operation failed: {method} {path.split("?")[0]} HTTP {error.code}') from None

    def get(self, path):
        return self.request('GET', REALM + '/' + path)

    def put(self, path, body):
        return self.request('PUT', REALM + '/' + path, body)

    def post(self, path, body):
        return self.request('POST', REALM + '/' + path, body)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def audience_mapper():
    return {'name': 'dashboard-api-audience', 'protocol': 'openid-connect',
            'protocolMapper': 'oidc-audience-mapper', 'consentRequired': False,
            'config': {'included.client.audience': 'jobman-dashboard-api',
                       'id.token.claim': 'true', 'access.token.claim': 'true'}}


def directory_mapper():
    return {'name': 'dashboard-immutable-directory-guid', 'protocol': 'openid-connect',
            'protocolMapper': 'oidc-usermodel-attribute-mapper', 'consentRequired': False,
            'config': {'user.attribute': DIRECTORY_ATTRIBUTE, 'claim.name': CLAIM,
                       'jsonType.label': 'String', 'multivalued': 'false',
                       'id.token.claim': 'true', 'access.token.claim': 'true', 'userinfo.token.claim': 'true'}}


def client_specs(secret):
    base = {'enabled': True, 'protocol': 'openid-connect', 'consentRequired': False,
            'standardFlowEnabled': True, 'implicitFlowEnabled': False,
            'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
            'fullScopeAllowed': False,
            'attributes': {'jobman.lab.owner': OWNER, 'pkce.code.challenge.method': 'S256'},
            'protocolMappers': [audience_mapper(), directory_mapper()]}
    return [
        {'clientId': 'jobman-dashboard-api', 'name': 'Dashboard Lab resource audience',
         'enabled': True, 'protocol': 'openid-connect', 'bearerOnly': True, 'publicClient': False,
         'standardFlowEnabled': False, 'implicitFlowEnabled': False,
         'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
         'attributes': {'jobman.lab.owner': OWNER}},
        {**base, 'clientId': 'jobman-dashboard-web', 'name': 'Dashboard Lab web',
         'publicClient': False, 'clientAuthenticatorType': 'client-secret', 'secret': secret,
         'redirectUris': ['https://dashboard.lab.test:8443/auth/callback'],
         'webOrigins': ['https://dashboard.lab.test:8443']},
        {**base, 'clientId': 'jobman-dashboard-native', 'name': 'Dashboard Lab iPhone',
         'publicClient': True, 'redirectUris': ['jobman-dashboard-auth://callback'], 'webOrigins': []},
    ]


def verify_client(actual, spec):
    for name, value in spec.items():
        if name in ('secret', 'protocolMappers'):
            continue
        if name == 'attributes':
            require(all(actual.get(name, {}).get(k) == v for k, v in value.items()), 'Client policy attributes differ')
        else:
            require(actual.get(name) == value, 'Client configuration differs: ' + spec['clientId'] + '/' + name)
    mappers = {mapper['name']: mapper for mapper in actual.get('protocolMappers', [])}
    for mapper in spec.get('protocolMappers', []):
        current = mappers.get(mapper['name'], {})
        require(current.get('protocolMapper') == mapper['protocolMapper'] and
                all(current.get('config', {}).get(k) == v for k, v in mapper['config'].items()),
                'Dashboard token mapper differs')


def main():
    check = sys.argv[1:] == ['--check']
    require(not sys.argv[1:] or check, 'Only --check is supported')
    inputs = json.loads((ROOT / 'identity-input.json').read_text())
    api = Admin()
    profile = api.get('users/profile')
    wanted = {'name': DIRECTORY_ATTRIBUTE, 'displayName': 'Dashboard synthetic directory identity',
              'permissions': {'view': ['admin', 'user'], 'edit': ['admin']}, 'multivalued': False}
    existing = [entry for entry in profile['attributes'] if entry['name'] == DIRECTORY_ATTRIBUTE]
    require(not existing or existing == [wanted], 'Refusing to adopt a conflicting directory attribute')
    if not existing:
        require(not check, 'Dashboard directory attribute is absent')
        profile['attributes'].append(wanted)
        api.put('users/profile', profile)
    verified_profile = api.get('users/profile')
    require([entry for entry in verified_profile['attributes'] if entry['name'] == DIRECTORY_ATTRIBUTE] == [wanted],
            'Directory attribute is not immutable to users')
    for spec in client_specs(inputs['webSecret']):
        matches = api.get('clients?' + urllib.parse.urlencode({'clientId': spec['clientId']}))
        require(len(matches) <= 1, 'Ambiguous Dashboard client identity')
        if matches:
            require(matches[0].get('attributes', {}).get('jobman.lab.owner') == OWNER,
                    'Refusing to modify an unmarked existing client')
            if not check:
                api.put('clients/' + matches[0]['id'], spec)
        else:
            require(not check, 'Dashboard client is absent')
            api.post('clients', spec)
        current = api.get('clients?' + urllib.parse.urlencode({'clientId': spec['clientId']}))[0]
        verify_client(current, spec)
    users = []
    for ordinal, name in enumerate(['alice', 'bob'], 1):
        username = 'dashboard-' + name
        guid = '71000000-0000-4000-8000-' + str(ordinal).zfill(12)
        matches = api.get('users?' + urllib.parse.urlencode({'username': username, 'exact': 'true'}))
        require(len(matches) <= 1, 'Ambiguous Dashboard user identity')
        if not matches:
            require(not check, 'Dashboard user is absent')
            api.post('users', {'username': username, 'enabled': True, 'firstName': 'Dashboard',
                     'lastName': name.title(), 'email': username + '@lab.test', 'emailVerified': True,
                     'requiredActions': [], 'attributes': {DIRECTORY_ATTRIBUTE: [guid]},
                     'credentials': [{'type': 'password', 'temporary': False, 'value': inputs[name + 'Password']}]})
            matches = api.get('users?' + urllib.parse.urlencode({'username': username, 'exact': 'true'}))
        user = matches[0]
        require(user.get('attributes', {}).get(DIRECTORY_ATTRIBUTE) == [guid] and user['enabled'],
                'Refusing to change a conflicting/disabled existing Dashboard user')
        users.append({'username': username, 'subject': user['id'], 'directoryGuid': guid})
    public = {'issuer': BASE + '/realms/jobman-lab', 'audience': 'jobman-dashboard-api',
              'webClientId': 'jobman-dashboard-web', 'nativeClientId': 'jobman-dashboard-native',
              'clientIdentityClaim': 'azp', 'directoryGuidClaim': CLAIM, 'users': users}
    output = ROOT / 'oidc-public.json'
    if check:
        require(json.loads(output.read_text()) == public, 'Public fixture identity mapping differs')
        print('PASS: isolated OIDC clients, S256-only PKCE policy, audience and signed immutable GUID mappers.')
    else:
        output.write_text(json.dumps(public, indent=2) + '\n')
        output.chmod(0o644)
        print('Dashboard synthetic identity configuration is ready; no existing clients/users were changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Do not print arbitrary exception strings or tracebacks from identity libraries.
        print(str(error) if isinstance(error, RuntimeError) else 'Identity configuration failed; inspect configuration privately.', file=sys.stderr)
        sys.exit(1)
