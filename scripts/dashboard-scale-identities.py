#!/usr/bin/env python3
"""Receipt-bound scale identities; all guest changes require the apply phase."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scale_common', HERE / 'dashboard-scale-identities-common.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
FILES = ('dashboard-scale-identities.py', 'dashboard-scale-identities-common.py', 'dashboard-scale-identities-guest.py')
HELPER = 'ansible/roles/dashboard_identity/files/configure-identity.py'
HEX = re.compile('[0-9a-f]{64}\\Z')


def implementation_file(path):
    info = path.lstat()
    c.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'implementation_identity')
    return c.read(path, mode=stat.S_IMODE(info.st_mode))


def implementation(): return {name: c.sha(implementation_file(HERE / name)) for name in FILES}


@contextmanager
def locked(root):
    c.private_directory(root)
    path = root / '.scale-identities.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.fchmod(fd, 0o600)
    except FileExistsError: fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        c.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, 'lock_identity')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); yield
    finally: os.close(fd)


def ssh_args(lab):
    inventory = c.decode(c.read(lab / '.lab/dashboard/ssh-connections.json', 65536)); value = inventory['control01']
    address = ipaddress.ip_address(value['ansible_host'])
    c.need(value['ansible_user'] == 'vagrant' and type(value['ansible_port']) is int and 1 <= value['ansible_port'] <= 65535 and Path(value['ansible_ssh_private_key_file']).is_absolute() and (str(address) in ('127.0.0.1', '10.77.0.21') or address in ipaddress.ip_network('10.211.55.0/24')), 'pinned_ssh_inventory')
    return ['ssh', '-i', value['ansible_ssh_private_key_file'], '-p', str(value['ansible_port']), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(lab / '.lab/dashboard/known_hosts'), '-o', 'HostKeyAlgorithms=ssh-ed25519', 'vagrant@' + str(address)]


def remote(lab, payload):
    sources = {name: implementation_file(HERE / name).decode() for name in FILES if name != FILES[0]}
    script = '''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((1<<20)+1)
 if len(raw)>1<<20:raise ValueError()
 p=json.loads(raw);sources=p.pop('_sources');hashes=p.pop('_hashes')
 if set(sources)!={'dashboard-scale-identities-common.py','dashboard-scale-identities-guest.py'}:raise ValueError()
 for name,value in sources.items():
  if hashlib.sha256(value.encode()).hexdigest()!=hashes[name]:raise ValueError()
 common=types.ModuleType('common');exec(compile(sources['dashboard-scale-identities-common.py'],'common','exec'),common.__dict__)
 namespace={'__name__':'reviewed_guest','common':common}
 exec(compile(sources['dashboard-scale-identities-guest.py'],'guest','exec'),namespace)
 result=namespace['execute'](p);print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','identity_guest_failed')
 print(json.dumps({'ok':False,'code':code},sort_keys=True))
'''
    body = dict(payload, _sources=sources, _hashes={name: c.sha(raw.encode()) for name, raw in sources.items()})
    result = c.decode(c.run(ssh_args(lab) + [shlex.join(['sudo', 'python3', '-c', script])], c.encoded(body)))
    if result.get('ok') is not True:
        code = result.get('code', 'identity_guest_failed'); c.need(isinstance(code, str) and c.CODE.fullmatch(code), 'invalid_guest_code'); raise c.Failure(code)
    return result['result']


def append_cas(path, before, after, staging):
    """Never roll back credentials after an account could have been created."""
    c.private_directory(path.parent)
    with locked(path.parent):
        pending = staging / 'credentials.pending.json'
        binding = c.encoded({'path': str(path), 'beforeSHA256': c.sha(before), 'afterSHA256': c.sha(after)})
        current = c.read(path, 65536)
        if current == after:
            c.need(c.read(pending) == binding and c.read(staging / 'credentials.backup.env') == before, 'credential_retry_evidence_missing')
        else:
            c.need(current == before, 'credential_compare_and_swap_failed')
            c.retain(staging / 'credentials.backup.env', before); c.retain(pending, binding)
            temporary = path.parent / ('.dashboard-scale-' + c.sha(binding) + '.tmp')
            c.retain(temporary, after)
            c.need(c.read(path, 65536) == before, 'credential_compare_and_swap_failed')
            os.replace(temporary, path); c.sync(path.parent)
        c.need(c.read(path, 65536) == after, 'credential_append_postcondition')
        c.retain(staging / 'credentials.complete.json', binding)


def load_stage(staging, expected, impl):
    raw = c.read(staging / 'stage.json'); record = c.decode(raw)
    c.need(isinstance(expected, str) and HEX.fullmatch(expected) and c.sha(raw) == expected, 'stage_digest')
    preflight_raw = c.read(staging / 'preflight.json'); preflight = c.decode(preflight_raw)
    passwords_raw = c.read(staging / 'passwords.json'); passwords = c.decode(passwords_raw)
    before = c.read(staging / 'credentials.before.env', 65536); after = c.read(staging / 'credentials.after.env', 65536)
    c.need(record == {'version': 1, 'issuer': c.ISSUER, 'accounts': c.accounts(), 'implementationSHA256': impl, 'preflightSHA256': c.sha(preflight_raw), 'passwordsSHA256': c.sha(passwords_raw), 'beforeSHA256': c.sha(before), 'afterSHA256': c.sha(after)}, 'stage_binding')
    c.need(preflight['implementationSHA256'] == impl and preflight['credentialsSHA256'] == c.sha(before) and after == c.append_credentials(before, passwords), 'stage_credential_transform')
    return record, preflight, passwords, before, after


def validate_result(result, baseline):
    c.need(result.get('version') == 1 and result.get('synthetic') is True and result.get('issuer') == c.ISSUER and result.get('preservedSHA256') == c.sha(c.encoded(baseline['preserved'])) and len(result.get('users', [])) == 25, 'identity_result_shape')
    subjects = set()
    for user, account in zip(result['users'], c.accounts()):
        subject = user.get('subject', '')
        c.need(c.UUID.fullmatch(subject) and subject != '00000000-0000-0000-0000-000000000000' and subject not in subjects and user == {'username': account['login'], 'keycloakUsername': account['username'], 'directoryId': account['directoryId'], 'subject': subject, 'name': account['name']}, 'identity_result_user')
        subjects.add(subject)


def handoff(result, history_at, now):
    c.need(isinstance(history_at, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', history_at), 'history_time_format')
    parsed = datetime.strptime(history_at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    c.need(now - timedelta(days=7) <= parsed < now - timedelta(minutes=1), 'history_time_window')
    users = [{key: row[key] for key in ('directoryId', 'subject', 'name')} for row in result['users']]
    return {name: {'instanceId': instance, 'issuer': c.ISSUER, 'historyAt': history_at, 'users': users} for name, instance in c.INSTANCES.items()}


def execute(args):
    c.need(args.lab_root.is_absolute() and args.lab_root.resolve() == args.lab_root, 'lab_root_alias')
    impl = c.sha(c.encoded(implementation()))
    if args.phase == 'digest': return {'implementationSHA256': impl}
    c.need(isinstance(args.implementation_sha256, str) and HEX.fullmatch(args.implementation_sha256) and args.implementation_sha256 == impl, 'implementation_digest')
    c.need(args.staging is not None and args.staging.is_absolute(), 'staging_path')
    if args.phase == 'preflight' and not args.staging.exists(): c.mkdir(args.staging)
    with locked(args.staging):
        credentials = args.lab_root / '.lab/credentials/dashboard.env'
        c.private_directory(credentials.parent)
        if args.phase == 'preflight':
            c.need(not (args.staging / 'preflight.json').exists(), 'preflight_already_recorded')
            before = c.read(credentials, 65536); values = c.credential_map(before)
            c.need(not any(a['passwordKey'] in values for a in c.accounts()), 'scale_credential_conflict')
            helper = c.sha(implementation_file(args.lab_root / HELPER))
            observed = remote(args.lab_root, {'phase': 'preflight', 'implementationSHA256': impl, 'identityHelperSHA256': helper})
            c.need(type(observed['epoch']) is int and abs(time.time() - observed['epoch']) <= 30, 'identity_clock_skew')
            c.need(c.read(credentials, 65536) == before, 'credential_compare_and_swap_failed')
            c.put(args.staging / 'credentials.before.env', before)
            record = {'version': 1, 'implementationSHA256': impl, 'identityHelperSHA256': helper, 'credentialsSHA256': c.sha(before), 'baseline': observed}
            c.put(args.staging / 'preflight.json', c.encoded(record))
            return {'phase': 'preflight', 'accountsAbsent': 25, 'preflightSHA256': c.sha(c.encoded(record))}
        preflight = c.decode(c.read(args.staging / 'preflight.json'))
        c.need(preflight['implementationSHA256'] == impl and c.sha(implementation_file(args.lab_root / HELPER)) == preflight['identityHelperSHA256'], 'preflight_implementation_changed')
        if args.phase == 'stage':
            c.need(not (args.staging / 'stage.json').exists() and not (args.staging / 'passwords.json').exists(), 'staging_already_started')
            before = c.read(args.staging / 'credentials.before.env', 65536)
            c.need(c.sha(before) == preflight['credentialsSHA256'] and c.read(credentials, 65536) == before, 'credential_compare_and_swap_failed')
            passwords = {a['passwordKey']: secrets.token_hex(32) for a in c.accounts()}
            after = c.append_credentials(before, passwords)
            c.put(args.staging / 'passwords.json', c.encoded(passwords)); c.put(args.staging / 'credentials.after.env', after)
            record = {'version': 1, 'issuer': c.ISSUER, 'accounts': c.accounts(), 'implementationSHA256': impl, 'preflightSHA256': c.sha(c.read(args.staging / 'preflight.json')), 'passwordsSHA256': c.sha(c.encoded(passwords)), 'beforeSHA256': c.sha(before), 'afterSHA256': c.sha(after)}
            c.put(args.staging / 'stage.json', c.encoded(record))
            return {'phase': 'stage', 'stageSHA256': c.sha(c.encoded(record)), 'accounts': 25, 'guestChanges': False}
        record, preflight, passwords, before, after = load_stage(args.staging, args.stage_sha256, impl)
        payload = {'implementationSHA256': impl, 'identityHelperSHA256': preflight['identityHelperSHA256'], 'executionId': args.stage_sha256, 'passwords': passwords, 'baseline': preflight['baseline']}
        if args.phase == 'apply':
            if not (args.staging / 'credentials.pending.json').exists():
                c.need(0 <= time.time() - preflight['baseline']['epoch'] <= 900, 'preflight_expired')
                observed = remote(args.lab_root, dict(payload, phase='preflight'))
                c.need(abs(time.time() - observed['epoch']) <= 30 and observed['preserved'] == preflight['baseline']['preserved'], 'identity_preflight_drift')
            append_cas(credentials, before, after, args.staging)
            result = remote(args.lab_root, dict(payload, phase='apply', apply=True))
            validate_result(result, preflight['baseline'])
            c.retain(args.staging / 'identities.json', c.encoded(result))
            c.retain(args.staging / 'apply.complete.json', c.encoded({'stageSHA256': args.stage_sha256, 'identitiesSHA256': c.sha(c.encoded(result))}))
            return {'phase': 'apply', 'accounts': 25, 'identitiesSHA256': c.sha(c.encoded(result))}
        result_raw = c.read(args.staging / 'identities.json'); result = c.decode(result_raw)
        validate_result(result, preflight['baseline'])
        c.need(c.read(credentials, 65536) == after and c.decode(c.read(args.staging / 'apply.complete.json')) == {'stageSHA256': args.stage_sha256, 'identitiesSHA256': c.sha(result_raw)}, 'identity_apply_receipt')
        if args.phase == 'verify':
            observed = remote(args.lab_root, dict(payload, phase='verify'))
            c.need(observed == result, 'identity_verify_changed')
            c.retain(args.staging / 'verify.complete.json', c.encoded({'stageSHA256': args.stage_sha256, 'identitiesSHA256': c.sha(result_raw)}))
            return {'phase': 'verify', 'accounts': 25, 'existingIdentityPolicyPreserved': True}
        c.need(args.phase == 'handoff' and args.output_directory is not None, 'handoff_arguments')
        c.need(c.read(args.staging / 'verify.complete.json') == c.read(args.staging / 'apply.complete.json'), 'identity_verification_receipt')
        values = handoff(result, args.history_at, datetime.now(timezone.utc))
        if not args.output_directory.exists(): c.mkdir(args.output_directory)
        c.private_directory(args.output_directory)
        with locked(args.output_directory):
            for name, value in values.items(): c.retain(args.output_directory / (name + '-scale-input.json'), c.encoded(value))
            c.retain(args.output_directory / 'identities.json', result_raw)
            c.retain(args.output_directory / 'handoff.json', c.encoded({'stageSHA256': args.stage_sha256, 'historyAt': args.history_at, 'files': {name + '-scale-input.json': c.sha(c.encoded(value)) for name, value in values.items()}}))
        return {'phase': 'handoff', 'accounts': 25, 'sources': 2, 'guestChanges': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('digest', 'preflight', 'stage', 'apply', 'verify', 'handoff'), default='preflight')
    parser.add_argument('--lab-root', required=True, type=Path)
    parser.add_argument('--staging', type=Path)
    parser.add_argument('--implementation-sha256')
    parser.add_argument('--stage-sha256')
    parser.add_argument('--history-at')
    parser.add_argument('--output-directory', type=Path)
    args = parser.parse_args()
    try: print(c.encoded(execute(args)).decode(), end='')
    except Exception as error:
        code = getattr(error, 'code', 'identity_phase_failed')
        print('dashboard-scale-identities: ' + (code if isinstance(code, str) and c.CODE.fullmatch(code) else 'identity_phase_failed'), file=sys.stderr); return 1
    return 0

if __name__ == '__main__': sys.exit(main())
