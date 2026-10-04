#!/usr/bin/env python3
"""Only creates the fixed 25 scale users; never updates a user/client/realm."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import types
import urllib.error
import urllib.parse
import urllib.request

if 'common' not in globals():
    import importlib.util
    spec = importlib.util.spec_from_file_location('scale_common', Path(__file__).with_name('dashboard-scale-identities-common.py'))
    common = importlib.util.module_from_spec(spec); spec.loader.exec_module(common)
c = common
ROOT = Path('/var/lib/jobman-dashboard-scale-identities')
HELPER = Path('/usr/local/libexec/jobman-dashboard-lab/configure-identity.py')
BASE = 'https://oidc.lab.test:8443'
REALM = '/admin/realms/jobman-lab'


def request_allowed(method, path):
    return (method == 'GET' and path.startswith(REALM + '/')) or (method == 'POST' and path in ('/realms/master/protocol/openid-connect/token', REALM + '/users'))


def admin(p):
    raw = c.read(HELPER, mode=0o755, uid=0)
    c.need(c.sha(raw) == p['identityHelperSHA256'], 'existing_identity_helper_changed')
    c.read(Path('/etc/jobman-lab/keycloak.env'), maximum=65536, uid=0)
    module = types.ModuleType('reviewed_existing_identity_helper')
    exec(compile(raw, str(HELPER), 'exec'), module.__dict__)
    class ScaleAdmin(module.Admin):
        def __init__(self):
            self.deadline = time.monotonic() + 180; self.created_location = None
            super().__init__()
            c.need(isinstance(self.token, str) and 0 < len(self.token) <= 16384, 'admin_token_bound')
        def request(self, method, path, body=None, content_type='application/json'):
            is_token = path == '/realms/master/protocol/openid-connect/token'
            c.need(request_allowed(method, path), 'identity_write_boundary')
            if body is not None and not isinstance(body, bytes): body = c.encoded(body)
            c.need(body is None or len(body) <= 65536, 'identity_request_bound')
            remaining = self.deadline - time.monotonic(); c.need(remaining > 0, 'identity_deadline')
            headers = {'Content-Type': content_type}
            if self.token: headers['Authorization'] = 'Bearer ' + self.token
            try:
                with self.opener.open(urllib.request.Request(BASE + path, data=body, headers=headers, method=method), timeout=min(10, remaining)) as response:
                    c.need(response.status == (201 if method == 'POST' and not is_token else 200), 'identity_response_status')
                    raw = response.read((2 << 20) + 1); c.need(len(raw) <= 2 << 20, 'identity_response_bound')
                    if response.status == 201: self.created_location = response.headers.get('Location')
                    return c.decode(raw) if raw else None
            except urllib.error.HTTPError as error: raise c.Failure('identity_http_failed') from error
        def create(self, spec):
            self.created_location = None; self.post('users', spec)
            c.need(isinstance(self.created_location, str), 'created_location_missing')
            prefix = BASE + REALM + '/users/'
            c.need(self.created_location.startswith(prefix), 'created_location_origin')
            subject = self.created_location[len(prefix):]
            c.need(c.UUID.fullmatch(subject), 'created_subject_invalid'); return subject
    return ScaleAdmin(), module


def user_spec(account, password):
    return {'username': account['username'], 'enabled': True, 'firstName': 'Synthetic', 'lastName': 'scale ' + account['login'][-2:],
            'email': account['username'] + '@lab.test', 'emailVerified': True, 'requiredActions': [],
            'attributes': {c.ATTRIBUTE: [account['directoryId']]}, 'credentials': [{'type': 'password', 'temporary': False, 'value': password}]}


def verify_user(actual, account, subject):
    wanted = user_spec(account, '')
    c.need(c.UUID.fullmatch(subject) and actual.get('id') == subject and all(actual.get(key) == value for key, value in wanted.items() if key != 'credentials'), 'created_user_identity_changed')


def user_inventory(api):
    users = api.get('users?' + urllib.parse.urlencode({'max': 101, 'first': 0, 'briefRepresentation': 'false'}))
    c.need(isinstance(users, list) and len(users) <= 100 and all(isinstance(x, dict) and c.UUID.fullmatch(x.get('id', '')) and isinstance(x.get('username'), str) for x in users), 'user_inventory_bound')
    c.need(len({x['id'] for x in users}) == len(users) and len({x['username'].casefold() for x in users}) == len(users), 'duplicate_user_inventory')
    return users


def preserved_snapshot(api, module, owned=None):
    owned = {} if owned is None else owned
    users = user_inventory(api); expected = {a['username']: a for a in c.accounts()}; result = {}
    for user in users:
        username = user['username']; guids = user.get('attributes', {}).get(c.ATTRIBUTE, [])
        if username in owned:
            verify_user(user, expected[username], owned[username]); continue
        c.need(username.casefold() not in expected and not any(guid == a['directoryId'] for guid in guids for a in expected.values()), 'scale_user_conflict')
        result[user['id']] = c.sha(c.encoded(user))
    c.need(all(any(v['username'] == name and v['id'] == subject for v in users) for name, subject in owned.items()), 'created_user_disappeared')
    profile = api.get('users/profile')
    wanted = {'name': c.ATTRIBUTE, 'displayName': 'Dashboard synthetic directory identity', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin']}, 'multivalued': False}
    c.need([a for a in profile['attributes'] if a['name'] == c.ATTRIBUTE] == [wanted], 'directory_attribute_policy_changed')
    clients = api.get('clients?max=65&first=0')
    c.need(isinstance(clients, list) and 3 <= len(clients) <= 64 and len({v['id'] for v in clients}) == len(clients), 'client_inventory_bound')
    for spec in module.client_specs('unused-private-secret'):
        matches = [v for v in clients if v['clientId'] == spec['clientId']]
        c.need(len(matches) == 1, 'dashboard_client_missing'); module.verify_client(matches[0], spec)
    # Full realm/profile/client representations are hashed in memory only.
    # User login sessions and credentials are not requested or exported.
    realm = api.request('GET', REALM + '/')
    return {'users': result, 'userCount': len(result), 'profileSHA256': c.sha(c.encoded(profile)),
            'clientsSHA256': c.sha(c.encoded(sorted(clients, key=lambda v: v['id']))), 'realmSHA256': c.sha(c.encoded(realm))}


def subject_receipts(root, passwords):
    result = {}
    for account in c.accounts():
        path = root / (account['login'] + '.complete.json')
        if not path.exists(): continue
        record = c.decode(c.read(path, uid=0))
        expected = c.sha(c.encoded(user_spec(account, passwords[account['passwordKey']])))
        c.need(record['username'] == account['username'] and record['requestSHA256'] == expected and c.UUID.fullmatch(record['subject']), 'user_receipt_changed')
        result[account['username']] = record['subject']
    c.need(len(set(result.values())) == len(result), 'duplicate_created_subject')
    return result


def apply_users(api, module, root, passwords, baseline):
    owned = subject_receipts(root, passwords)
    c.need(preserved_snapshot(api, module, owned) == baseline, 'preexisting_identity_state_changed')
    for account in c.accounts():
        name = account['username']; path = root / (account['login'] + '.complete.json')
        if name in owned: continue
        pending = root / (account['login'] + '.pending.json')
        # Never infer ownership from a matching account after an uncertain POST.
        c.need(not pending.exists(), 'uncertain_user_creation_requires_review')
        spec = user_spec(account, passwords[account['passwordKey']]); digest = c.sha(c.encoded(spec))
        c.put(pending, c.encoded({'username': name, 'requestSHA256': digest}))
        subject = api.create(spec)
        actual = api.get('users/' + subject); verify_user(actual, account, subject)
        c.put(path, c.encoded({'username': name, 'subject': subject, 'requestSHA256': digest}))
        owned[name] = subject
    c.need(len(owned) == 25 and preserved_snapshot(api, module, owned) == baseline, 'identity_postcondition_changed')
    return [{'username': a['login'], 'keycloakUsername': a['username'], 'directoryId': a['directoryId'], 'subject': owned[a['username']], 'name': a['name']} for a in c.accounts()]


def execute(p):
    c.need(os.geteuid() == 0 and sys.platform == 'linux' and os.uname().nodename.split('.')[0] == 'control01', 'fixed_identity_guest')
    c.need(p['phase'] in ('preflight', 'apply', 'verify') and all(isinstance(p.get(k), str) and len(p[k]) == 64 and all(ch in '0123456789abcdef' for ch in p[k]) for k in ('implementationSHA256', 'identityHelperSHA256')), 'identity_execution_shape')
    api, module = admin(p)
    if p['phase'] == 'preflight': return {'epoch': int(time.time()), 'preserved': preserved_snapshot(api, module)}
    c.need(p['phase'] != 'apply' or p.get('apply') is True, 'explicit_identity_apply_required')
    c.need(isinstance(p.get('executionId'), str) and len(p['executionId']) == 64 and all(ch in '0123456789abcdef' for ch in p['executionId']), 'identity_execution_id')
    passwords = p['passwords']; c.append_credentials(b'EXISTING=preserved\n', passwords)
    if p['phase'] == 'apply':
        if not ROOT.exists(): c.mkdir(ROOT)
        c.private_directory(ROOT, 0)
        root = ROOT / p['executionId']
        if not root.exists(): c.mkdir(root)
    else: root = ROOT / p['executionId']
    c.private_directory(ROOT, 0); c.private_directory(root, 0)
    lock = ROOT / '.lock'
    try:
        if p['phase'] == 'verify': raise FileExistsError()
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.fchmod(fd, 0o600)
    except FileExistsError: fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        import stat
        info = os.fstat(fd); c.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'identity_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        binding = c.encoded({'executionId': p['executionId'], 'implementationSHA256': p['implementationSHA256'], 'identityHelperSHA256': p['identityHelperSHA256'], 'baseline': p['baseline'], 'passwordsSHA256': c.sha(c.encoded(passwords))})
        if p['phase'] == 'apply': c.retain(root / 'binding.json', binding)
        else: c.need(c.read(root / 'binding.json', uid=0) == binding, 'identity_binding_changed')
        if p['phase'] == 'apply': users = apply_users(api, module, root, passwords, p['baseline']['preserved'])
        else:
            owned = subject_receipts(root, passwords)
            c.need(len(owned) == 25 and preserved_snapshot(api, module, owned) == p['baseline']['preserved'], 'identity_verification_failed')
            users = [{'username': a['login'], 'keycloakUsername': a['username'], 'directoryId': a['directoryId'], 'subject': owned[a['username']], 'name': a['name']} for a in c.accounts()]
        result = {'version': 1, 'synthetic': True, 'issuer': c.ISSUER, 'users': users, 'preservedSHA256': c.sha(c.encoded(p['baseline']['preserved']))}
        if p['phase'] == 'apply': c.retain(root / 'complete.json', c.encoded(result))
        else: c.need(c.read(root / 'complete.json', uid=0) == c.encoded(result), 'identity_completion_changed')
        return result
    finally: os.close(fd)
