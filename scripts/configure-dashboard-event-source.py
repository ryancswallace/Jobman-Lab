#!/usr/bin/env python3
"""Add only events.read to the existing isolated Dashboard Lab registration.

Default is read-only validation; --apply atomically updates the public policy
and reloads only the isolated Control. No key is rotated,
no user grant is changed, and no original Control service is touched.
"""
import argparse
import importlib.util
import inspect
import json
from pathlib import Path
import re
import time


def event_registry(raw, namespace_ids):
    import base64
    import json
    import re
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate policy field')
            result[key] = value
        return result
    if len(raw) > 65536 or len(namespace_ids) != 2 or len(set(namespace_ids)) != 2:
        raise ValueError('Invalid bounded synthetic registration')
    if any(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is None for value in namespace_ids):
        raise ValueError('Invalid namespace identity')
    document = json.loads(raw, object_pairs_hook=unique)
    if set(document) != {'services'} or not isinstance(document['services'], list) or len(document['services']) != 2:
        raise ValueError('Unexpected synthetic registry')
    if any(not isinstance(service, dict) for service in document['services']):
        raise ValueError('Invalid service entry')
    selected = [s for s in document['services'] if s.get('serviceId') == 'dashboard-lab']
    if len(selected) != 1:
        raise ValueError('Expected one Dashboard service')
    service = selected[0]
    required = {'namespace.read', 'jobs.read', 'groups.read', 'targets.read', 'logs.read', 'artifacts.read', 'evidence.read'}
    operations = service.get('operations')
    if (set(service) != {'serviceId', 'keyId', 'audience', 'publicKey', 'certificateThumbprints', 'namespaceIds', 'operations', 'enabled'}
            or service['keyId'] != 'synthetic-lab-v1' or service['audience'] != 'urn:jobman:dashboard-lab:control'
            or service['enabled'] is not True or sorted(service['namespaceIds']) != sorted(namespace_ids)
            or not isinstance(operations, list) or len(set(operations)) != len(operations)
            or set(operations) not in (required, required | {'events.read'})
            or len(base64.b64decode(service['publicKey'], validate=True)) != 32
            or len(service['certificateThumbprints']) != 1
            or re.fullmatch('[A-Za-z0-9_-]{43}', service['certificateThumbprints'][0]) is None):
        raise ValueError('Existing service differs from expected synthetic policy')
    other = next(s for s in document['services'] if s is not service)
    if other.get('serviceId') != 'dashboard-log-broker-lab' or set(other.get('operations', [])) != {'namespace.read', 'logs.read'}:
        raise ValueError('Unexpected broker registration')
    if 'events.read' in operations:
        return raw
    operations.append('events.read')
    return (json.dumps(document, indent=2) + '\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('checks', Path(__file__).with_name('check-dashboard-infra.py'))
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    fixture = json.loads((checks.STATE / 'fixture-info.json').read_text())
    checks.require(fixture.get('synthetic') is True and fixture['endpoint'] == 'https://10.77.0.21:18443', 'Wrong isolated source')
    instance = fixture['instanceId']
    checks.require(re.fullmatch('[0-9a-f-]{36}', instance), 'Invalid source instance')
    namespaces = [item['id'] for item in fixture['namespaces']]
    capability_command = 'sudo -u jobman-dashboard-source curl --silent --fail --max-time 3 --cacert /etc/jobman-dashboard-lab/control-fixture/fixture-ca.crt https://127.0.0.1:18443/v1/capabilities'
    result = checks.ssh('control01', capability_command)
    checks.require(result.returncode == 0 and len(result.stdout) < 65536, 'Source capabilities unavailable')
    capability = json.loads(result.stdout)['capabilities']
    checks.require(capability.get('instanceId') == instance and 'durable-monitoring-events' in capability.get('features', []), 'Upgrade the isolated Control to the reviewed durable-event revision first')
    script = inspect.getsource(event_registry) + '''
import json,os,stat
from pathlib import Path
root=Path('/etc/jobman-dashboard-lab/control-fixture')
st=root.lstat()
assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode)==0o700 and st.st_uid==21902
info=json.loads((root/'fixture-info.json').read_text())
assert info['synthetic'] is True and info['instanceId']==EXPECTED_INSTANCE
assert sorted(n['id'] for n in info['namespaces'])==sorted(EXPECTED_NAMESPACES)
policy=root/'delegation.json';st=policy.lstat()
assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==21902 and st.st_size<=65536
original=policy.read_bytes();updated=event_registry(original,EXPECTED_NAMESPACES)
changed=updated!=original
if APPLY and changed:
 backup=root/'delegation.before-events.json'
 if backup.exists():
  saved=backup.lstat();assert stat.S_ISREG(saved.st_mode) and stat.S_IMODE(saved.st_mode)==0o600 and saved.st_size<=65536
  assert backup.read_bytes()==original
 else:
  fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as stream:
   os.fchown(stream.fileno(),21902,21902);stream.write(original);stream.flush();os.fsync(stream.fileno())
 temporary=root/'.delegation.events.pending'
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:
  os.fchown(stream.fileno(),21902,21902);stream.write(updated);stream.flush();os.fsync(stream.fileno())
 os.replace(temporary,policy)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
print('changed' if changed else 'unchanged')
'''
    script = 'EXPECTED_INSTANCE=' + repr(instance) + '\nEXPECTED_NAMESPACES=' + repr(namespaces) + '\nAPPLY=' + repr(args.apply) + '\n' + script
    result = checks.ssh('control01', 'sudo python3 -', script)
    checks.require(result.returncode == 0 and result.stdout.strip() in ('changed', 'unchanged'), 'Event registration validation failed; inspect isolated policy without resetting it')
    if not args.apply:
        print('PASS: source and registration validated; ' + ('events.read can be added explicitly' if result.stdout.strip() == 'changed' else 'events.read is already registered'))
        return
    # Repeating explicit apply also recovers a process interruption between the
    # atomic policy write and the service reload. Check-only never restarts.
    result = checks.ssh('control01', 'sudo systemctl restart jobman-dashboard-lab-control')
    checks.require(result.returncode == 0, 'Isolated source restart failed; inspect the retained public policy and source service')
    ready = False
    for attempt in range(5):
        result = checks.ssh('control01', capability_command)
        if result.returncode == 0 and len(result.stdout) < 65536 and json.loads(result.stdout).get('capabilities', {}).get('instanceId') == instance:
            ready = True
            break
        if attempt < 4:
            time.sleep(1)
    checks.require(ready, 'Isolated source did not regain identity readiness')
    print('PASS: events.read registered for the existing Dashboard service and namespace set; source identity preserved')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, TypeError, StopIteration):
        raise SystemExit('Synthetic event registration failed; inspect the isolated policy and service. No keys, grants or databases were reset.') from None
