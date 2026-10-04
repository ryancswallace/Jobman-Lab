#!/usr/bin/env python3
"""Fixed-host Lab restore phases. Input stays on stdin; output is bounded receipts."""
import base64
from contextlib import contextmanager
import fcntl
from datetime import datetime, timezone
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.request

HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
PRIMARY = {'api': ('/etc/jobman-dashboard-api-lab', 21904), 'worker': ('/etc/jobman-dashboard-worker-lab', 21905)}
CLONE = {'api': ('jobman-dash-restore-api', 21909), 'worker': ('jobman-dash-restore-worker', 21910)}
UNIT = {role: 'jobman-dashboard-lab-' + role + '.service' for role in PRIMARY}
BASE = Path('/var/lib/jobman-dashboard-restore-operator')
DATABASE = 'jobman_dashboard_restore'
PUBLIC_CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'
COMMAND_DEADLINE = None


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


@contextmanager
def phase_deadline(deadline):
    global COMMAND_DEADLINE
    previous = COMMAND_DEADLINE
    COMMAND_DEADLINE = min(previous,deadline) if previous is not None else deadline
    try:
        yield
    finally:
        COMMAND_DEADLINE = previous


def command_timeout(seconds):
    if COMMAND_DEADLINE is not None:
        seconds = min(seconds, COMMAND_DEADLINE-time.monotonic())
    need(seconds > 0, 'Critical phase deadline exceeded before command')
    return seconds


def run(args, data=None, timeout=15, maximum=4 << 20):
    result = subprocess.run(args, input=data, capture_output=True, timeout=command_timeout(timeout), check=False)
    need(result.returncode == 0 and len(result.stdout) <= maximum, 'Bounded guest command failed')
    return result.stdout


def read(path, maximum=1 << 20, owner=None, mode=None):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'Real absolute file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum, 'Bounded single-link file required')
        if owner is not None:
            need((before.st_uid, before.st_gid) == owner, 'File ownership differs')
        if mode is not None:
            need(stat.S_IMODE(before.st_mode) == mode, 'File mode differs')
        raw = stream.read(maximum + 1)
        after, named = os.fstat(stream.fileno()), path.lstat()
        need(len(raw) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
             (named.st_dev, named.st_ino) == (after.st_dev, after.st_ino), 'File changed during read')
        return raw, before


def hash_file(path, maximum, owner=(0, 0), mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (*owner, mode) and
             0 < before.st_size <= maximum, 'Expected bounded immutable archive')
        total, checksum = 0, hashlib.sha256()
        while True:
            raw = stream.read(65536)
            if not raw:
                break
            total += len(raw)
            need(total <= maximum, 'Archive exceeds bound')
            checksum.update(raw)
        after, named = os.fstat(stream.fileno()), path.lstat()
        need(total == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
             (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino), 'Archive changed while hashing')
        return {'bytes': total, 'sha256': checksum.hexdigest()}


def directory(path, uid=0, gid=0, mode=0o700):
    path = Path(path)
    created = False
    old = os.umask(0o077)
    try:
        try:
            path.mkdir(mode=mode)
            created = True
        except FileExistsError:
            pass
    finally:
        os.umask(old)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if created:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
        info = os.fstat(fd)
        need(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode), 'Directory ownership differs')
        named = path.lstat()
        need((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino), 'Directory replaced')
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, raw, uid=0, gid=0, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), uid, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sql(query, database='jobman_dashboard', timeout=15):
    need(database in ('jobman_dashboard', DATABASE, 'postgres'), 'Database outside fixed scope')
    bounded = f"SET statement_timeout='{max(1,timeout-1)*1000}ms'; SET lock_timeout='5000ms';\n" + query
    return run(['podman', 'exec', '-i', '--user', 'postgres', 'jobman-postgres', 'psql', '-X', '-q', '-A', '-t', '-U', 'jobman_control',
                '-v', 'ON_ERROR_STOP=1', '-d', database], bounded.encode(), timeout=timeout).decode().strip()


def candidate(payload):
    value = payload['candidate']
    need(COMMIT.fullmatch(value['revision']) and HEX.fullmatch(value['binarySHA256']), 'Exact candidate pin required')
    path = '/opt/jobman-dashboard-lab/releases/' + value['revision'] + '/bin/jobman-dashboard'
    raw, _ = read(path, 96 << 20, owner=(0, 0), mode=0o755)
    need(digest(raw) == value['binarySHA256'], 'Installed candidate bytes changed')
    return path


def process(role, binary, allow_stopped=False):
    unit = Path('/etc/systemd/system') / UNIT[role]
    raw, _ = read(unit, 16384, owner=(0, 0), mode=0o644)
    need(raw.count(b'TimeoutStopSec=') == 1 and b'\nTimeoutStopSec=90s\n' in raw, 'Reviewed primary stop budget changed')
    # KillMode defaults to control-group in the deployed split templates. Bind
    # the effective policy as well as the exact raw unit hash retained below.
    policy_raw = run(['systemctl','show',UNIT[role],'--property=KillMode','--property=TimeoutStopUSec','--property=DropInPaths'], timeout=5, maximum=2048)
    pairs = [line.split('=',1) for line in policy_raw.decode().splitlines()]
    need(len(pairs) == 3 and all(len(pair) == 2 for pair in pairs), 'Effective primary stop policy is invalid')
    policy = dict(pairs)
    need(set(policy) == {'KillMode','TimeoutStopUSec','DropInPaths'} and policy['KillMode'] == 'control-group' and
         policy['TimeoutStopUSec'] in ('1min 30s','90s') and policy['DropInPaths'] == '', 'Effective primary stop budget or override changed')
    active = subprocess.run(['systemctl', 'is-active', '--quiet', UNIT[role]], capture_output=True, timeout=command_timeout(5)).returncode
    if active != 0:
        state = run(['systemctl', 'show', UNIT[role], '--property=ActiveState', '--value']).decode().strip()
        need(allow_stopped and active == 3 and state in ('inactive', 'failed'), 'Primary service is not stopped')
        return {'unitSHA256': digest(raw), 'active': False}
    pid = run(['systemctl', 'show', UNIT[role], '--property=MainPID', '--value']).decode().strip()
    need(pid.isdecimal() and int(pid) > 1, 'Invalid running primary process')
    image = Path('/proc') / pid / 'exe'
    need(image.parent.stat().st_uid == PRIMARY[role][1] and os.readlink(image) == binary, 'Primary process UID/executable changed')
    fd = os.open(image, os.O_RDONLY)
    try:
        current, expected = os.fstat(fd), os.stat(binary)
        need((current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino), 'Primary process image changed')
    finally:
        os.close(fd)
    started = run(['systemctl', 'show', UNIT[role], '--property=ExecMainStartTimestampMonotonic', '--value']).decode().strip()
    return {'unitSHA256': digest(raw), 'active': True, 'pid': pid, 'startedMonotonic': started}


def material_refs(value):
    result = set()
    def walk(item):
        if isinstance(item, dict):
            for key, value in item.items():
                if key.endswith('File') and key not in ('databaseURLFile', 'operatorConfigFile'):
                    need(isinstance(value, str) and value.startswith('/'), 'Unexpected material reference')
                    result.add(value)
                elif not key.endswith('File'):
                    walk(value)
        elif isinstance(item, list):
            for value in item:
                walk(value)
    walk(value)
    return result


def unused_storage():
    for name, uid in list(CLONE.values()) + [('jobman-dash-restore-readers', 21911)]:
        for getter, value in ((pwd.getpwuid, uid), (pwd.getpwnam, name), (grp.getgrgid, uid), (grp.getgrnam, name)):
            try:
                getter(value)
            except KeyError:
                continue
            raise ValueError('Clone OS identity already exists')
    for path in ([Path('/etc/jobman-dashboard-restore-' + role + '-lab') for role in ('api', 'worker', 'operator')] +
                 [Path('/run/jobman-dashboard-restore-' + role + '-lab') for role in CLONE] +
                 [Path('/var/lib/jobman-dashboard-restore-reports-lab')]):
        need(not path.exists() and not path.is_symlink(), 'Clone root already exists')
    for role in CLONE:
        unit = Path('/etc/systemd/system') / ('jobman-dashboard-restore-' + role + '-lab.service')
        need(not unit.exists() and not unit.is_symlink(), 'Clone unit already exists')
    need(not re.search(r':38443\s', run(['ss', '-H', '-lnt']).decode()), 'Clone API port already used')


def source_capability(control):
    need(control['origin'] in ('https://10.77.0.21:18443', 'https://10.77.0.21:28443'), 'Unapproved Control origin')
    trust, _ = read(control['trustRootsFile'], 1 << 20)
    context = ssl.create_default_context(cadata=trust.decode())
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
    with opener.open(control['origin'] + '/v1/capabilities', timeout=8) as response:
        raw = response.read(65537)
        need(response.status == 200 and len(raw) <= 65536, 'Control capabilities unavailable')
    result = decode(raw)['capabilities']
    need(result['instanceId'] == control['expectedInstanceId'] and re.fullmatch('[1-9][0-9]{0,18}', result['recoveryEpoch']), 'Current Control identity differs')
    return {'deploymentId': control['id'], 'instanceId': result['instanceId'], 'recoveryEpoch': result['recoveryEpoch'], 'serviceTime': result['serviceTime']}


def storage_snapshot(payload):
    binary = candidate(payload)
    unused_storage()
    configs, files, processes, capabilities = {}, {}, {}, []
    for role, (root, uid) in PRIMARY.items():
        raw, _ = read(Path(root) / 'config.json', 256 << 10, owner=(uid, uid), mode=0o600)
        config = decode(raw)
        configs[role] = base64.b64encode(raw).decode()
        processes[role] = process(role, binary)
        for path in material_refs(config):
            need(path.startswith(root + '/') or path == PUBLIC_CA, 'Cross-role private material reference')
            content, info = read(path, 1 << 20, owner=(0, 0) if path == PUBLIC_CA else (uid, uid), mode=0o644 if path == PUBLIC_CA else 0o600)
            files[path] = {'path': path, 'sha256': digest(content), 'bytes': len(content), 'uid': info.st_uid, 'gid': info.st_gid, 'mode': format(stat.S_IMODE(info.st_mode), '04o')}
        if role == 'worker':
            capabilities = [source_capability(c) for c in config['controls']]
    memory = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()}
    need(memory['MemAvailable'] >= 1536 << 20, 'Insufficient clone memory headroom')
    storage = os.statvfs('/var/lib')
    status = decode(run([binary, 'status', '--operator-config', '/etc/jobman-dashboard-operator-lab/config.json'], timeout=10))
    return {'epoch': int(time.time()), 'configs': configs, 'files': sorted(files.values(), key=lambda v: v['path']), 'processes': processes,
            'capabilities': capabilities, 'memAvailableBytes': memory['MemAvailable'], 'freeBytes': storage.f_bavail * storage.f_frsize,
            'operatorStatus': status}


def database_snapshot(payload):
    need(sql("SELECT current_setting('ssl')='on' AND NOT EXISTS(SELECT FROM pg_hba_file_rules WHERE error IS NOT NULL)", 'postgres') == 't', 'PostgreSQL TLS/HBA invalid')
    need(sql("SELECT count(*) FROM pg_database WHERE datname='jobman_dashboard_restore'", 'postgres') == '0', 'Clone database already exists')
    need(sql("SELECT count(*) FROM pg_roles WHERE rolname IN ('jobman_dashboard_restore_ddl','jobman_dashboard_restore_api','jobman_dashboard_restore_worker','jobman_dashboard_restore_operator')", 'postgres') == '0', 'Clone role already exists')
    slots = int(sql("SELECT current_setting('max_connections')::int-count(*)-current_setting('superuser_reserved_connections')::int FROM pg_stat_activity", 'postgres'))
    need(slots >= 36, 'Insufficient clone connection headroom')
    ledger = decode(sql("SELECT coalesce(json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name),'[]') FROM dashboard_schema_migrations"))
    sources = decode(sql("SELECT coalesce(json_agg(json_build_object('deploymentId',f.deployment_id,'controlInstanceId',i.control_instance_id,'recoveryEpoch',i.recovery_epoch,'namespaceIds',f.namespace_ids,'configurationRevision',i.configuration_revision,'state',f.status) ORDER BY f.deployment_id),'[]') FROM dashboard_event_feeds f FULL JOIN dashboard_source_identities i USING(deployment_id)"))
    hold = decode(sql("SELECT json_build_object('generation',generation::text,'held',held,'suppressRecordedThrough',to_char(restore_recorded_through AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')) FROM dashboard_notification_delivery_control WHERE singleton"))
    size = int(sql("SELECT pg_database_size(current_database())"))
    space = os.statvfs('/var/lib/containers')
    return {'epoch': int(time.time()), 'ledger': ledger, 'sources': sources, 'hold': hold, 'databaseBytes': size,
            'freeBytes': space.f_bavail * space.f_frsize, 'availableConnectionSlots': slots,
            'hbaSHA256': digest(run(['podman','exec','jobman-postgres','cat','/var/lib/postgresql/data/pg_hba.conf']))}


def execution_root(payload):
    operation, plan = payload['operationId'], payload['plan']
    need(HEX.fullmatch(operation) and HEX.fullmatch(payload['planSHA256']) and
         digest(encoded(plan)) == payload['planSHA256'] and plan.get('scenario') == 'isolated-dashboard-postgresql-restore' and
         plan.get('synthetic') is True and plan.get('applySupported') is False and
         plan['clone']['database'] == DATABASE and plan['clone']['components']['worker'] == ['ingestion', 'notifications', 'reports'] and
         plan['clone']['deliveryAllowed'] is False and plan['clone']['providerCredentialsAllowed'] is False,
         'Fixed isolated restore operation required')
    need(payload.get('apply') is True, 'Explicit apply required')
    need(payload['candidate']['revision'] == plan['candidate']['revision'] and
         HEX.fullmatch(payload['implementationSHA256']), 'Applied candidate/implementation differs')
    directory(BASE)
    root = BASE / operation
    directory(root)
    intent = {'operationId': operation, 'planSHA256': payload['planSHA256'], 'candidate': payload['candidate'],
              'implementationSHA256': payload['implementationSHA256'], 'primaryPinsSHA256': digest(encoded(payload['primaryPins'])),
              'objectHelperSHA256': payload['objectHelperSHA256'], 'passwordsSHA256': digest(encoded(payload['passwords']))}
    path = root / 'intent.json'
    if path.exists():
        need(read(path, owner=(0, 0), mode=0o600)[0] == encoded(intent), 'Existing operation intent differs')
    else:
        put(path, encoded(intent))
    return root


def primary_pins(payload, stopped=False):
    need(run(['systemctl','show','jobman-dashboard-lab-app.service','--property=ActiveState','--value']).decode().strip() in ('inactive','failed'), 'Legacy combined writer must remain inactive')
    binary = candidate(payload)
    pins = payload['primaryPins']
    need(set(pins) == {'configs', 'processes'}, 'Exact primary pins required')
    values = {}
    for role, (root, uid) in PRIMARY.items():
        current, _ = read(Path(root) / 'config.json', 256 << 10, owner=(uid, uid), mode=0o600)
        need(digest(current) == pins['configs'][role], 'Primary config changed; refuse restart against drift')
        state = process(role, binary, allow_stopped=stopped)
        need(state['unitSHA256'] == pins['processes'][role]['unitSHA256'], 'Primary unit changed; refuse arbitrary restart')
        values[role] = state
    return values


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def watchdog_name(payload):
    need(HEX.fullmatch(payload['operationId']), 'Operation ID invalid')
    return 'jobman-dash-restore-watch-' + payload['operationId'][:16]


def arm_backup(payload):
    root = execution_root(payload)
    live = primary_pins(payload)
    need(all(live[role] == payload['primaryPins']['processes'][role] for role in PRIMARY), 'Primary restarted after fresh snapshot')
    for name in ('armed.json', 'fired.json', 'disarmed.json', 'backup-complete.json', 'backup.pending.json'):
        need(not (root / name).exists(), 'Backup operation is single-use; inspect existing receipts')
    code = base64.b64decode(payload['guestCode'], validate=True)
    need(len(code) <= 1 << 20 and digest(code) == payload['implementationSHA256'], 'Watchdog implementation differs')
    put(root / 'guest.py', code)
    watchdog = dict(payload, phase='watchdog')
    watchdog.pop('guestCode')
    put(root / 'watchdog.json', encoded(watchdog))
    unit = watchdog_name(payload)
    state = run(['systemctl', 'show', unit + '.timer', '--property=LoadState', '--value']).decode().strip()
    need(state == 'not-found', 'Watchdog unit already exists')
    started = time.monotonic()
    armed = {'operationId': payload['operationId'], 'planSHA256': payload['planSHA256'],
             'bootId': boot_id(),
             'armedMonotonic': started, 'restartAtMonotonic': started + 150,
             'stoppedWindowLimitSeconds': 180, 'watchdog': unit, 'fired': False}
    # This receipt precedes arming; a lost reply may be inspected, never rearmed.
    put(root / 'arm.pending.json', encoded(armed))
    run(['systemd-run', '--quiet', '--unit=' + unit, '--on-active=150s', '--timer-property=AccuracySec=1s',
         '--property=Type=oneshot', '--property=TimeoutStartSec=25s', '--collect',
         '/usr/bin/python3', str(root / 'guest.py'), '--watchdog', str(root / 'watchdog.json')])
    need(run(['systemctl', 'show', unit + '.timer', '--property=ActiveState', '--value']).decode().strip() == 'active', 'Watchdog timer not active')
    put(root / 'armed.json', encoded(armed))
    return armed


def backup_window(root, require_stopped=False, payload=None):
    armed = decode(read(root / 'armed.json', owner=(0, 0), mode=0o600)[0])
    need(armed['bootId'] == boot_id() and
         time.monotonic() < armed['restartAtMonotonic'] and not (root / 'fired.json').exists() and
         not (root / 'disarmed.json').exists(), 'Backup coherence window has ended')
    if require_stopped:
        states = primary_pins(payload, stopped=True)
        need(all(not v['active'] for v in states.values()), 'Backup requires all primary writers stopped')
        need(time.monotonic() < armed['restartAtMonotonic'] and not (root/'fired.json').exists() and not (root/'disarmed.json').exists(), 'Backup window changed during checks')
    return armed


def stop_primary(payload):
    root = execution_root(payload)
    # Stop and restart use one lock. An acknowledged timer is not sufficient:
    # it may already have completed while this request was delayed in transit.
    armed = backup_window(root)
    deadline = min(time.monotonic()+40, armed['restartAtMonotonic']-20)
    with phase_deadline(deadline), restart_lock(root, deadline):
        backup_window(root)
        primary_pins(payload)
        need(armed['restartAtMonotonic']-time.monotonic() >= 125, 'Insufficient stop/restart safety window')
        put(root / 'backup.pending.json', encoded({'startedAt': datetime.now(timezone.utc).isoformat(), 'operationId': payload['operationId']}))
        # Reserve the pinned90s unit stop timeout,25s restart and10s margin.
        # The35s client timeout can leave systemd finishing a stop independently.
        # Recheck after receipt IO and immediately before the bounded command.
        backup_window(root)
        need(armed['restartAtMonotonic']-time.monotonic() >= 125, 'Stop safety window elapsed')
        run(['systemctl', 'stop', UNIT['api'], UNIT['worker']], timeout=35)
        backup_window(root, True, payload)
        result = {'stopped': True, 'observedAt': datetime.now(timezone.utc).isoformat(), 'operationId': payload['operationId']}
        put(root / 'stopped.json', encoded(result))
        return result


@contextmanager
def restart_lock(root, deadline=None):
    fd = os.open(root / '.restart.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'Private restart lock required')
        deadline = time.monotonic()+10 if deadline is None else deadline
        while True:
            need(time.monotonic() < deadline, 'Restart coordination lock deadline exceeded')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(0.01,max(0,deadline-time.monotonic())))
        yield
    finally:
        os.close(fd)


def restart_primary(payload, fired=False):
    root = execution_root(payload)
    deadline = time.monotonic()+25
    with phase_deadline(deadline), restart_lock(root, deadline):
        armed = decode(read(root / 'armed.json', owner=(0, 0), mode=0o600)[0])
        if (root / 'disarmed.json').exists():
            primary_pins(payload)
            return decode(read(root / 'disarmed.json', owner=(0, 0), mode=0o600)[0])
        need(armed['bootId'] == boot_id(), 'Host reboot requires explicit recovery inspection')
        primary_pins(payload, stopped=True)
        if fired:
            need(time.monotonic() >= armed['restartAtMonotonic'], 'Watchdog deadline has not elapsed')
        if fired and not (root / 'fired.json').exists():
            put(root / 'fired.json', encoded({'fired': True, 'atMonotonic': time.monotonic(), 'operationId': payload['operationId']}))
        # Fixed units only. No SQL, config replacement, restore or hold operation.
        run(['systemctl', 'start', UNIT['api'], UNIT['worker']], timeout=25)
        states = primary_pins(payload)
        result = {'primaryRestarted': True, 'watchdogFired': (root / 'fired.json').exists(), 'states': states,
                  'operationId': payload['operationId'], 'elapsedSinceArmSeconds': time.monotonic() - armed['armedMonotonic']}
        put(root / 'disarmed.json', encoded(result))
        if not fired:
            run(['systemctl', 'stop', watchdog_name(payload) + '.timer'])
        return result


def complete_backup(payload):
    root = execution_root(payload)
    armed = backup_window(root)
    deadline = min(time.monotonic()+10,armed['restartAtMonotonic']-1)
    with phase_deadline(deadline), restart_lock(root, deadline):
        # Called only once both separately checksummed DB/object receipts exist.
        backup_window(root, True, payload)
        receipts = payload['backupReceipts']
        need(set(receipts) == {'database', 'objects'} and all(v.get('complete') is True and
             v.get('operationId') == payload['operationId'] and v.get('planSHA256') == payload['planSHA256'] for v in receipts.values()),
             'Complete coordinated backup receipts required')
        need(all(HEX.fullmatch(v['manifestSHA256']) for v in receipts.values()), 'Backup checksum missing')
        result = {'complete': True, 'operationId': payload['operationId'], 'planSHA256': payload['planSHA256'],
                  'receipts': receipts, 'completedAt': datetime.now(timezone.utc).isoformat()}
        backup_window(root)
        command_timeout(1)
        put(root / 'backup-complete.json', encoded(result))
        return result


def begin_phase(payload, phase):
    root = execution_root(payload)
    done, pending = root / (phase + '.json'), root / (phase + '.pending.json')
    if done.exists():
        value = decode(read(done, owner=(0, 0), mode=0o600)[0])
        need(value.get('operationId') == payload['operationId'] and value.get('planSHA256') == payload['planSHA256'], 'Completed receipt differs')
        return root, value
    need(not pending.exists(), 'Incomplete phase requires inspection; no blind retry')
    put(pending, encoded({'operationId': payload['operationId'], 'planSHA256': payload['planSHA256'], 'startedAt': datetime.now(timezone.utc).isoformat()}))
    return root, None


def finish_phase(payload, root, phase, value):
    result = dict(value, operationId=payload['operationId'], planSHA256=payload['planSHA256'], complete=True)
    put(root / (phase + '.json'), encoded(result))
    return result


def clone_role_sql(passwords):
    roles = {role: DATABASE + '_' + role for role in ('ddl', 'api', 'worker', 'operator')}
    need(set(passwords) == set(roles) and all(HEX.fullmatch(v) for v in passwords.values()), 'Exact new clone passwords required')
    lines = []
    for role, name in roles.items():
        limit = 16 if role in ('api', 'worker') else 2
        lines.append(f"CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {limit} PASSWORD '{passwords[role]}';")
    lines.extend([f'CREATE DATABASE {DATABASE} OWNER {roles["ddl"]};', f'REVOKE ALL ON DATABASE {DATABASE} FROM PUBLIC;',
                  f'GRANT CONNECT ON DATABASE {DATABASE} TO {roles["api"]},{roles["worker"]},{roles["operator"]};',
                  f'\\connect {DATABASE}', 'REVOKE ALL ON SCHEMA public FROM PUBLIC;', f'ALTER SCHEMA public OWNER TO {roles["ddl"]};'])
    return '\n'.join(lines) + '\n'


def clone_hba():
    roles = ','.join(DATABASE + '_' + role for role in ('ddl', 'api', 'worker', 'operator'))
    return (f'# Reviewed isolated Dashboard restore Lab only\nhostssl {DATABASE} {roles} 10.77.0.10/32 scram-sha-256\n'
            f'host all {roles} 0.0.0.0/0 reject\nhost all {roles} ::/0 reject\n').encode()


def provision_database(payload):
    root, completed = begin_phase(payload, 'database-provision')
    if completed:
        need(sql(f"SELECT oid::text FROM pg_database WHERE datname='{DATABASE}'", 'postgres') == completed['databaseOID'], 'Completed clone DB identity changed')
        return completed
    # The fixed target is never adopted merely because a same-named DB exists.
    slots = int(sql("SELECT current_setting('max_connections')::int-count(*)-current_setting('superuser_reserved_connections')::int FROM pg_stat_activity", 'postgres'))
    need(slots >= 36, 'Clone connection headroom changed')
    need(sql(f"SELECT count(*) FROM pg_database WHERE datname='{DATABASE}'", 'postgres') == '0', 'Clone target exists')
    names = ','.join("'" + DATABASE + '_' + role + "'" for role in ('ddl', 'api', 'worker', 'operator'))
    need(sql('SELECT count(*) FROM pg_roles WHERE rolname IN (' + names + ')', 'postgres') == '0', 'Clone role exists')
    hba = run(['podman','exec','jobman-postgres','cat','/var/lib/postgresql/data/pg_hba.conf'])
    need(digest(hba) == payload['snapshot']['hbaSHA256'], 'PostgreSQL HBA changed since snapshot')
    put(root / 'hba.before', hba)
    put(root / 'hba.after', clone_hba() + hba)
    sql(clone_role_sql(payload['passwords']), 'postgres', timeout=30)
    run(['podman','cp',str(root/'hba.after'),'jobman-postgres:/var/lib/postgresql/data/pg_hba.conf'])
    run(['podman','exec','--user','root','jobman-postgres','chown','postgres:postgres','/var/lib/postgresql/data/pg_hba.conf'])
    run(['podman','exec','--user','root','jobman-postgres','chmod','0600','/var/lib/postgresql/data/pg_hba.conf'])
    need(sql('SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL', 'postgres') == '0', 'HBA parse failed')
    need(sql('SELECT pg_reload_conf()', 'postgres') == 't', 'HBA reload failed')
    return finish_phase(payload, root, 'database-provision', {'database': DATABASE,
        'databaseOID': sql(f"SELECT oid::text FROM pg_database WHERE datname='{DATABASE}'", 'postgres'),
        'hbaSHA256': digest(clone_hba() + hba), 'originalDatabaseUnchanged': True})


def stream_dump(args, path, maximum, seconds):
    import selectors
    import signal
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    process_handle = None
    try:
        os.fchmod(fd, 0o600)
        process_handle = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + seconds
        total, checksum = 0, hashlib.sha256()
        with selectors.DefaultSelector() as selected:
            selected.register(process_handle.stdout, selectors.EVENT_READ)
            while selected.get_map():
                left = deadline - time.monotonic()
                need(left > 0, 'Dump exceeded deadline')
                for event, _ in selected.select(min(1, left)):
                    raw = os.read(event.fileobj.fileno(), 65536)
                    if not raw:
                        selected.unregister(event.fileobj)
                        continue
                    total += len(raw)
                    need(total <= maximum, 'Dump exceeded output bound')
                    checksum.update(raw)
                    view = memoryview(raw)
                    while view:
                        written = os.write(fd, view)
                        need(written > 0, 'Dump write interrupted')
                        view = view[written:]
        need(process_handle.wait(timeout=max(0.01, deadline - time.monotonic())) == 0 and total > 0, 'Dump process failed')
        os.fsync(fd)
        info = os.fstat(fd)
        need(info.st_size == total and info.st_nlink == 1, 'Dump descriptor changed')
        return {'bytes': total, 'sha256': checksum.hexdigest()}
    finally:
        if process_handle is not None:
            if process_handle.poll() is None:
                os.killpg(process_handle.pid, signal.SIGKILL)
                process_handle.wait(timeout=5)
            process_handle.stdout.close()
        os.close(fd)


def database_dump(payload):
    root, completed = begin_phase(payload, 'database-backup')
    if completed:
        value = hash_file(root/'dashboard.dump', 1 << 30)
        need(value['sha256'] == completed['sha256'] and value['bytes'] == completed['bytes'], 'Completed dump changed')
        return completed
    size = int(sql('SELECT pg_database_size(current_database())'))
    free = os.statvfs(BASE)
    need(0 < size <= 1 << 30 and free.f_bavail * free.f_frsize >= 3 * size + (2 << 30) + (256 << 20), 'Dump disk headroom unavailable')
    # The host only dispatches after a verified storage-host stop receipt; the
    # independent watchdog bounds quiescence even if this SSH connection is lost.
    need(payload['stoppedReceipt'].get('stopped') is True and payload['stoppedReceipt']['operationId'] == payload['operationId'], 'Verified primary stop required')
    partial = root/'dashboard.dump.partial'
    result = stream_dump(['podman','exec','--user','postgres','jobman-postgres','pg_dump','-U','jobman_control','-Fc','--no-owner','--no-acl','--lock-wait-timeout=5s','--dbname=jobman_dashboard'], partial, 1 << 30, 90)
    put(root/'dump-process-success.json', encoded(result))
    # pg_restore --list runs against complete successful output; it is never a
    # substitute for successful pg_dump or a reason to accept a failed partial.
    run(['podman','cp',str(partial),'jobman-postgres:/tmp/dashboard-restore-'+payload['operationId']+'.dump'])
    run(['podman','exec','--user','root','jobman-postgres','chown','postgres:postgres','/tmp/dashboard-restore-'+payload['operationId']+'.dump'])
    listing = run(['podman','exec','--user','postgres','jobman-postgres','pg_restore','--list','/tmp/dashboard-restore-'+payload['operationId']+'.dump'], maximum=8 << 20)
    need(all(name.encode() in listing for name in ('dashboard_schema_migrations','dashboard_source_events','dashboard_report_tasks','dashboard_notification_delivery_control')), 'Dump lacks expected schema')
    os.rename(partial, root/'dashboard.dump')
    directory(root)
    result['retainedIdentities'] = retained_identities('jobman_dashboard')
    result['sourceCheckpoints'] = retained_source_checkpoints('jobman_dashboard')
    result['manifestSHA256'] = digest(encoded(result))
    return finish_phase(payload, root, 'database-backup', result)


def retained_identities(database):
    selections = {
        'events':("dashboard_source_events", "deployment_id::text||':'||control_instance_id::text||':'||event_id::text"),
        'inbox':('dashboard_notification_inbox','id::text'),
        'deliveries':('dashboard_notification_deliveries','id::text'),
        'reports':('dashboard_report_tasks','id::text')}
    result = {}
    for name,(table,expression) in selections.items():
        query = f"SELECT json_build_object('count',count(*)::text,'sha256',encode(sha256(convert_to(coalesce(string_agg(identity,E'\\n' ORDER BY identity COLLATE \"C\"),''),'UTF8')),'hex')) FROM (SELECT {expression} AS identity FROM {table} LIMIT 100001) bounded"
        value = decode(sql(query,database))
        need(int(value['count']) <= 100000 and HEX.fullmatch(value['sha256']), 'Identity verification exceeds reviewed bound')
        result[name] = value
    return result



def retained_source_checkpoints(database, allow_paused=False):
    # Only hashes of service-bound private cursor/checkpoint bytes leave SQL.
    query = """SELECT coalesce(json_agg(row_to_json(v) ORDER BY v."deploymentId"),'[]') FROM
      (SELECT f.deployment_id AS "deploymentId",i.control_instance_id AS "controlInstanceId",
       i.recovery_epoch::text AS "recoveryEpoch",i.configuration_revision::text AS "configurationRevision",
       f.namespace_ids AS "namespaceIds",f.status,
       encode(sha256(f.checkpoint),'hex') AS "checkpointSHA256",
       encode(sha256(convert_to(f.cursor,'UTF8')),'hex') AS "cursorSHA256",
       encode(sha256(convert_to(f.last_position::text,'UTF8')),'hex') AS "positionSHA256"
       FROM dashboard_event_feeds f FULL JOIN dashboard_source_identities i USING(deployment_id)
       ORDER BY f.deployment_id LIMIT 3) v"""
    values = decode(sql(query,database))
    expected = {'72000000-0000-4000-8000-000000000001':'e633cf92-258d-48ff-965a-fda88d68ef3a',
                '72000000-0000-4000-8000-000000000002':'a4f0e2ab-7323-4c90-9510-1f073c660f06'}
    need(len(values) == 2 and {v['deploymentId'] for v in values} == set(expected), 'Two independent source checkpoints required')
    for value in values:
        need(value['controlInstanceId'] == expected[value['deploymentId']] and value['recoveryEpoch'] == '1' and
             value['status'] in (('active','paused') if allow_paused else ('active',)) and 1 <= len(value['namespaceIds']) <= 320 and
             all(isinstance(value[key],str) and HEX.fullmatch(value[key]) for key in
                 ('checkpointSHA256','cursorSHA256','positionSHA256')), 'Complete active source checkpoint required')
    return values


def verify_restored_database(payload, completed=False):
    receipt = payload['coherentBackup']['receipts']['database']
    ledger = decode(sql("SELECT coalesce(json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name),'[]') FROM dashboard_schema_migrations",DATABASE))
    need(digest(encoded(ledger)) == payload['plan']['primary']['schema']['ledgerSHA256'], 'Restored migration ledger differs')
    need(retained_identities(DATABASE) == receipt['retainedIdentities'], 'Restored stable identities differ from backup')
    current = retained_source_checkpoints(DATABASE, allow_paused=completed)
    if completed and any(value['status'] == 'paused' for value in current):
        # A successful later hold can outlive a lost host response. It changes
        # status, not source identity or the backed-up opaque checkpoint bytes.
        hold = decode(sql("SELECT json_build_object('held',held,'cutoff',restore_recorded_through) FROM dashboard_notification_delivery_control WHERE singleton",DATABASE))
        need(all(value['status'] == 'paused' for value in current) and hold['held'] is True and
             hold['cutoff'] is not None and datetime.fromisoformat(hold['cutoff']) ==
             datetime.fromisoformat(payload['externalCutoff']), 'Completed restore has an unrelated hold or partially paused source set')
        current = [dict(value,status='active') for value in current]
    need(current == receipt['sourceCheckpoints'], 'Restored independent source checkpoints differ from backup')
    return ledger


def verify_role_permissions():
    # These are effective-role permission probes, not password authentication
    # claims. Actual runtime TLS logins are exercised by API/worker readiness and
    # the operator status command after startup on storage01.
    for role in ('api','worker','operator'):
        name = DATABASE+'_'+role
        answer = sql('SET SESSION AUTHORIZATION '+name+'; SELECT current_user; SELECT count(*) FROM dashboard_schema_migrations;',DATABASE)
        need(answer.endswith(name+'\n18'), 'Restored role schema access differs')
        denied = ['UPDATE dashboard_notification_delivery_control SET held=false WHERE false;']
        if role == 'worker':
            denied += ['UPDATE dashboard_accounts SET directory_id=directory_id WHERE false;',
                       'UPDATE dashboard_identity_aliases SET subject=subject WHERE false;',
                       'UPDATE dashboard_preferences SET timezone=timezone WHERE false;',
                       'SELECT encrypted_refresh_token FROM dashboard_sessions LIMIT 0;']
        if role == 'operator':
            denied += ['SELECT subject FROM dashboard_report_tasks LIMIT 0;']
        for query in denied:
            args = ['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-A','-t','-U','jobman_control',
                    '-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate','-d',DATABASE]
            result = subprocess.run(args,input=('BEGIN; SET SESSION AUTHORIZATION '+name+'; '+query+' ROLLBACK;').encode(),capture_output=True,timeout=10)
            need(result.returncode != 0 and b'42501' in result.stderr, 'Protected restored SQL operation was not denied')


def restore_database(payload):
    root, completed = begin_phase(payload, 'database-restore')
    prior = decode(read(root/'database-provision.json', owner=(0, 0), mode=0o600)[0])
    need(sql(f"SELECT oid::text FROM pg_database WHERE datname='{DATABASE}'", 'postgres') == prior['databaseOID'], 'Clone database identity changed')
    if completed:
        verify_restored_database(payload, completed=True)
        verify_role_permissions()
        return completed
    need(sql(fresh_database_query(), DATABASE) == '0', 'Clone schema is not empty')
    receipt = decode(read(root/'database-backup.json', owner=(0, 0), mode=0o600)[0])
    archived = hash_file(root/'dashboard.dump', 1 << 30)
    need(archived['bytes'] == receipt['bytes'] and archived['sha256'] == receipt['sha256'], 'Restore dump checksum differs')
    need(payload['coherentBackup'].get('complete') is True and payload['coherentBackup']['operationId'] == payload['operationId'] and
         payload['coherentBackup']['planSHA256'] == payload['planSHA256'] and
         payload['coherentBackup']['receipts']['database'] == receipt, 'Coherent backup completion required')
    name = '/tmp/dashboard-restore-' + payload['operationId'] + '.dump'
    # The copied container file is re-created only from the checksum-verified
    # root-owned archive; no caller-controlled database or archive path is used.
    run(['podman','cp',str(root/'dashboard.dump'),'jobman-postgres:'+name])
    run(['podman','exec','--user','root','jobman-postgres','chown','postgres:postgres',name])
    listing = run(['podman','exec','--user','postgres','jobman-postgres','pg_restore','--list',name],maximum=8<<20)
    need(re.search(rb'^[0-9]+; [0-9]+ [0-9]+ SCHEMA - public ',listing,re.MULTILINE), 'Expected dump public schema entry missing')
    # Only this just-provisioned, receipt-bound empty clone schema is removed;
    # pg_restore recreates it as the restricted DDL owner from the exact dump.
    sql('DROP SCHEMA public;', DATABASE)
    run(['podman','exec','--user','postgres','jobman-postgres','pg_restore','-U','jobman_control','--exit-on-error','--no-owner','--no-acl',
         '--role='+DATABASE+'_ddl','--dbname='+DATABASE,name], timeout=180, maximum=1 << 20)
    ledger = decode(sql("SELECT coalesce(json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name),'[]') FROM dashboard_schema_migrations", DATABASE))
    need(digest(encoded(ledger)) == payload['plan']['primary']['schema']['ledgerSHA256'], 'Restored migration ledger differs')
    for role in ('api','worker','operator'):
        name = 'grants/' + role + '.sql'
        grant = base64.b64decode(payload['preparedFiles'][name], validate=True)
        need(digest(grant) == payload['plan']['preparedFiles'][name], 'Reviewed grant plan differs')
        sql(grant.decode(), DATABASE, timeout=40)
    verify_restored_database(payload)
    verify_role_permissions()
    return finish_phase(payload, root, 'database-restore', {'database': DATABASE, 'schemaVerified': True, 'runtimeGrantsApplied': True, 'manifestSHA256': digest(encoded(ledger))})


def fresh_database_query():
    return ("SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')+"
            "(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')+"
            "(SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public')+"
            "(SELECT count(*) FROM pg_namespace WHERE nspname NOT IN('public','pg_catalog','information_schema') "
            "AND nspname !~ '^pg_(toast|temp)(_[0-9]+|_temp_[0-9]+)?$')+"
            "(SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql')")


def object_helper(payload):
    import types
    raw = base64.b64decode(payload['objectHelper'], validate=True)
    need(len(raw) <= 65536 and digest(raw) == payload['objectHelperSHA256'], 'Reviewed object helper changed')
    module = types.ModuleType('restore_object_helper')
    exec(compile(raw, '<reviewed-object-helper>', 'exec'), module.__dict__)
    return module


def prepared(payload, name):
    raw = base64.b64decode(payload['preparedFiles'][name], validate=True)
    need(len(raw) <= 1 << 20 and digest(raw) == payload['plan']['preparedFiles'][name], 'Prepared file changed')
    return raw


def clone_root(role):
    need(role in ('api', 'worker', 'operator'), 'Unknown clone role')
    return Path('/etc/jobman-dashboard-restore-' + role + '-lab')


def clone_unit(role, binary):
    name, _ = CLONE[role]
    config = str(clone_root(role) / 'config.json')
    reports = '/var/lib/jobman-dashboard-restore-reports-lab'
    opposite = clone_root('worker' if role == 'api' else 'api')
    writable = 'ReadOnlyPaths=' if role == 'api' else 'ReadWritePaths='
    return (f'[Unit]\nDescription=Isolated Dashboard restore Lab {role}\nWants=network-online.target\nAfter=network-online.target\n\n'
            f'[Service]\nType=simple\nUser={name}\nGroup={name}\nSupplementaryGroups=jobman-dash-restore-readers\n'
            f'WorkingDirectory={Path(binary).parent.parent}\nEnvironment=GOMAXPROCS=2\n'
            f'ExecStartPre={binary} --mode check-config --check-mode {role} --config {config}\n'
            f'ExecStart={binary} --mode {role} --config {config}\nRestart=on-failure\nRestartSec=5s\n'
            'TimeoutStopSec=30s\nKillMode=control-group\nUMask=0077\n'
            f'RuntimeDirectory=jobman-dashboard-restore-{role}-lab\nRuntimeDirectoryMode=0700\n'
            'NoNewPrivileges=true\nPrivateTmp=true\nPrivateDevices=true\nProtectSystem=strict\nProtectHome=true\n'
            'ProtectKernelTunables=true\nProtectKernelModules=true\nProtectControlGroups=true\nProtectKernelLogs=true\n'
            'ProtectClock=true\nRestrictSUIDSGID=true\nRestrictRealtime=true\nLockPersonality=true\nMemoryDenyWriteExecute=true\n'
            'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nCapabilityBoundingSet=\n'
            f'{writable}{reports}\nInaccessiblePaths=-{opposite} -{clone_root("operator")} '
            '-/etc/jobman-dashboard-api-lab -/etc/jobman-dashboard-worker-lab -/etc/jobman-dashboard-operator-lab\n'
            f'LimitNOFILE=2048\nTasksMax=256\nMemoryMax={512 if role == "api" else 768}M\n'
            '\n[Install]\nWantedBy=multi-user.target\n').encode()


def verify_clone_identities():
    for role, (name, uid) in CLONE.items():
        user, group = pwd.getpwnam(name), grp.getgrnam(name)
        need(user.pw_uid == uid and user.pw_gid == uid and user.pw_dir == '/nonexistent' and
             user.pw_shell == '/usr/sbin/nologin' and group.gr_gid == uid, 'Clone service identity changed')
        need(set(os.getgrouplist(name, uid)) == {uid, 21911}, 'Unexpected clone supplementary groups')
    need(grp.getgrnam('jobman-dash-restore-readers').gr_gid == 21911, 'Clone reader identity changed')


def provision_storage(payload):
    root, done = begin_phase(payload, 'storage-provision')
    binary = candidate(payload)
    if done:
        verify_clone_identities()
        for role, (_, uid) in CLONE.items():
            directory(clone_root(role), uid, uid)
            need(read('/etc/systemd/system/jobman-dashboard-restore-' + role + '-lab.service', owner=(0, 0), mode=0o644)[0] == clone_unit(role, binary), 'Clone unit changed')
        return done
    unused_storage()
    primary_pins(payload)
    memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))) * 1024
    need(memory >= 1536 << 20, 'Clone memory headroom changed')
    for name, gid in list(CLONE.values()) + [('jobman-dash-restore-readers', 21911)]:
        run(['groupadd', '--gid', str(gid), name])
    for role, (name, uid) in CLONE.items():
        run(['useradd','--uid',str(uid),'--gid',str(uid),'--groups','jobman-dash-restore-readers','--no-create-home',
             '--home-dir','/nonexistent','--shell','/usr/sbin/nologin',name])
        directory(clone_root(role), uid, uid)
        directory(clone_root(role)/'material', uid, uid)
        directory('/run/jobman-dashboard-restore-' + role + '-lab', uid, uid)
        put('/etc/systemd/system/jobman-dashboard-restore-' + role + '-lab.service', clone_unit(role, binary), mode=0o644)
    directory(clone_root('operator'))
    verify_clone_identities()
    run(['systemctl', 'daemon-reload'])
    return finish_phase(payload, root, 'storage-provision', {'created': True, 'unitsStarted': False, 'manifestSHA256': digest(encoded(payload['plan']['clone']))})


def objects_backup(payload):
    root, done = begin_phase(payload, 'objects-backup')
    if done:
        verify_objects_backup(payload, root, done)
        return done
    backup_window(root, True, payload)
    helper = object_helper(payload)
    profile = (21905, 21906, 0o750, 0o640)
    source = '/var/lib/jobman-dashboard-reports-lab'
    inventory = helper.inventory(source, [profile])
    free = os.statvfs(root)
    demand = 2 * inventory['bytes'] + (1 << 30) + (384 << 20) + (32 << 20) + (256 << 20)
    need(free.f_bavail * free.f_frsize >= demand, 'Report snapshot capacity changed')
    directory(root/'material')
    materials = {}
    for item in payload['plan']['materialCopies']:
        path = item['path']
        if path in materials:
            continue
        raw, _ = read(path, 1 << 20, owner=(item['uid'], item['gid']), mode=int(item['mode'], 8))
        need(len(raw) == item['bytes'] and digest(raw) == item['sha256'], 'Source material changed since snapshot')
        name = digest(path.encode()) + '.bin'
        put(root/'material'/name, raw)
        materials[path] = {'name': name, 'bytes': len(raw), 'sha256': digest(raw)}
    need(len(materials) <= 128 and sum(v['bytes'] for v in materials.values()) <= 32 << 20, 'Material bound exceeded')
    # Existing helper inventories only bounded UUID.json objects, rejects links,
    # ACLs and unknown entries, and checks the stopped source before and after.
    helper.backup(source, root/'reports', inventory, profile)
    for role, (path, uid) in PRIMARY.items():
        raw, _ = read(Path(path)/'config.json', 256 << 10, owner=(uid, uid), mode=0o600)
        need(digest(raw) == payload['primaryPins']['configs'][role], 'Primary configuration drift')
        put(root/(role+'.config.before.json'), raw)
    worker = decode(read(Path(PRIMARY['worker'][0])/'config.json',256<<10,owner=(21905,21905),mode=0o600)[0])
    expected = {item['deploymentId']:item for item in payload['plan']['sources']}
    for control in worker['controls']:
        current = source_capability(control)
        prior = expected[current['deploymentId']]
        need(current['instanceId'] == prior['controlInstanceId'] and current['recoveryEpoch'] == prior['recoveryEpoch'], 'Source changed during coordinated backup')
    backup_window(root, True, payload)
    manifest = {'inventory': inventory, 'materials': materials, 'configSHA256': payload['primaryPins']['configs']}
    put(root/'objects-manifest.json', encoded(manifest))
    return finish_phase(payload, root, 'objects-backup', {'files': len(inventory['entries']), 'bytes': inventory['bytes'],
        'materialFiles': len(materials), 'manifestSHA256': digest(encoded(manifest))})


def verify_objects_backup(payload, root, receipt):
    helper = object_helper(payload)
    manifest = decode(read(root/'objects-manifest.json', 4 << 20, owner=(0, 0), mode=0o600)[0])
    need(digest(encoded(manifest)) == receipt['manifestSHA256'], 'Objects backup manifest changed')
    need(len(manifest['inventory']['entries']) <= 10000 and manifest['inventory']['bytes'] <= 1 << 30, 'Report backup bound exceeded')
    directory(root/'reports')
    directory(root/'material')
    need(read(root/'reports'/'manifest.json',4<<20,owner=(0,0),mode=0o600)[0] == helper.canonical(manifest['inventory']), 'Report backup metadata changed')
    names = {'manifest.json'}
    for entry in manifest['inventory']['entries']:
        need(helper.OBJECT.fullmatch(entry['name']), 'Unexpected report name')
        names.add(entry['name'])
        fact = hash_file(root/'reports'/entry['name'], (6 << 20)+(16 << 10))
        need(fact == {'bytes': entry['size'], 'sha256': entry['sha256']}, 'Report backup checksum changed')
    need(set(os.listdir(root/'reports')) == names, 'Unexpected report backup entry')
    for item in manifest['materials'].values():
        need(re.fullmatch('[0-9a-f]{64}\\.bin', item['name']), 'Unsafe material backup name')
        need(hash_file(root/'material'/item['name'], 1 << 20) == {'bytes':item['bytes'], 'sha256':item['sha256']}, 'Material backup checksum changed')
    return manifest


def clone_dsn(role, password):
    from urllib.parse import urlencode
    need(role in ('ddl','api','worker','operator') and HEX.fullmatch(password), 'Fixed clone identity required')
    query = urlencode({'sslmode':'verify-full','sslrootcert':PUBLIC_CA,'connect_timeout':'5'})
    return ('postgres://'+DATABASE+'_'+role+':'+password+'@10.77.0.20:5432/'+DATABASE+'?'+query+'\n').encode()


def clone_stopped():
    for role in CLONE:
        value = run(['systemctl','show','jobman-dashboard-restore-'+role+'-lab.service','--property=ActiveState','--value']).decode().strip()
        need(value in ('inactive','failed'), 'Clone writers must be stopped')


def install_snapshot(payload):
    root, done = begin_phase(payload, 'snapshot-install')
    if done:
        return done
    clone_stopped()
    primary_pins(payload)
    coherent = decode(read(root/'backup-complete.json', 4 << 20, owner=(0,0), mode=0o600)[0])
    need(coherent == payload['coherentBackup'], 'Exact completed coherent snapshot required')
    manifest = verify_objects_backup(payload, root, coherent['receipts']['objects'])
    destination = Path('/var/lib/jobman-dashboard-restore-reports-lab')
    directory(destination, 21910, 21911, 0o750)
    need(not os.listdir(destination), 'Clone report root is not empty')
    for entry in manifest['inventory']['entries']:
        raw, _ = read(root/'reports'/entry['name'], (6 << 20)+(16 << 10), owner=(0,0), mode=0o600)
        need(digest(raw) == entry['sha256'] and len(raw) == entry['size'], 'Report content changed')
        put(destination/entry['name'], raw, 21910, 21911, 0o640)
    observed = object_helper(payload).inventory(destination, [(21910,21911,0o750,0o640)])
    need(observed['entries'] == manifest['inventory']['entries'] and observed['bytes'] == manifest['inventory']['bytes'], 'Restored report bytes differ')
    for item in payload['plan']['materialCopies']:
        role = item['role']
        _, uid = CLONE[role]
        material = manifest['materials'][item['path']]
        raw, _ = read(root/'material'/material['name'], owner=(0,0), mode=0o600)
        need(digest(raw) == item['sha256'] and Path(item['destination']).parent == clone_root(role)/'material', 'Clone material destination differs')
        put(item['destination'], raw, uid, uid)
    for role, (_, uid) in CLONE.items():
        put(clone_root(role)/'config.json', prepared(payload,'configs/'+role+'.json'), uid, uid)
        put(clone_root(role)/'database-url', clone_dsn(role,payload['passwords'][role]), uid, uid)
    put(clone_root('operator')/'config.json', prepared(payload,'configs/operator.json'))
    put(clone_root('operator')/'recovery.json', prepared(payload,'configs/recovery.json'))
    put(clone_root('operator')/'database-url', clone_dsn('operator',payload['passwords']['operator']))
    put(clone_root('operator')/'recovery-database-url', clone_dsn('ddl',payload['passwords']['ddl']))
    return finish_phase(payload, root, 'snapshot-install', {'installed':True, 'files':len(observed['entries']),
        'bytes':observed['bytes'], 'manifestSHA256':coherent['receipts']['objects']['manifestSHA256'], 'sourceRegistrationsChanged':False})


def hold_clone(payload):
    root, done = begin_phase(payload, 'clone-hold')
    clone_stopped()
    primary_pins(payload)
    config = str(clone_root('operator')/'recovery.json')
    binary = candidate(payload)
    current = decode(run([binary,'events','hold-status','--config',config], timeout=15))
    if done:
        need(current['held'] is True and current['generation'] == done['hold']['generation'], 'Restored hold changed')
        return done
    need(current['held'] is False and current['generation'] == payload['plan']['primary']['hold']['generation'], 'Restored control differs from backed-up state')
    cutoff = payload['externalCutoff']
    need(isinstance(cutoff,str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z',cutoff), 'External UTC cutoff required')
    parsed = datetime.fromisoformat(cutoff.replace('Z','+00:00'))
    backup = decode(read(root/'backup-complete.json', 4 << 20, owner=(0,0), mode=0o600)[0])
    need(datetime.fromisoformat(backup['completedAt']) <= parsed and 0 <= time.time()-parsed.timestamp() <= 1800, 'External cutoff must follow backup within bounded exercise window')
    result = decode(run([binary,'events','hold','--config',config,'--generation',current['generation'],'--restore-through',cutoff],timeout=15))
    need(result['held'] is True and int(result['generation']) == int(current['generation'])+1, 'Clone hold was not established')
    return finish_phase(payload, root, 'clone-hold', {'hold':result, 'externalCutoff':cutoff,
        'manifestSHA256':digest(encoded(result)), 'primaryHoldChanged':False})


class ReadinessPending(ValueError):
    pass


def clone_process(role, binary):
    path = '/etc/systemd/system/jobman-dashboard-restore-' + role + '-lab.service'
    need(read(path,owner=(0,0),mode=0o644)[0] == clone_unit(role,binary), 'Clone unit content differs')
    unit = 'jobman-dashboard-restore-'+role+'-lab.service'
    active = subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True,timeout=command_timeout(5))
    if active.returncode != 0:
        state = run(['systemctl','show',unit,'--property=ActiveState','--value']).decode().strip()
        if active.returncode == 3 and state in ('activating','inactive'):
            raise ReadinessPending('Clone process is starting')
        raise ValueError('Clone service failed to start')
    pid = run(['systemctl','show',unit,'--property=MainPID','--value']).decode().strip()
    need(pid.isdecimal() and int(pid)>1, 'Clone PID missing')
    image = Path('/proc')/pid/'exe'
    need(image.parent.stat().st_uid == CLONE[role][1] and os.readlink(image) == binary and
         (image.stat().st_dev,image.stat().st_ino)==(os.stat(binary).st_dev,os.stat(binary).st_ino), 'Clone process executable or owner differs')
    return {'pid':pid, 'uid':CLONE[role][1]}


def verify_clone(payload):
    root = execution_root(payload)
    binary = candidate(payload)
    primary_pins(payload)
    hold = decode(run([binary,'events','hold-status','--config',str(clone_root('operator')/'recovery.json')],timeout=15))
    expected = decode(read(root/'clone-hold.json',owner=(0,0),mode=0o600)[0])
    need(hold['held'] is True and hold['generation'] == expected['hold']['generation'], 'Clone persisted hold differs')
    values = {}
    for role,(name,uid) in CLONE.items():
        state = clone_process(role,binary)
        config, _ = read(clone_root(role)/'config.json',256<<10,owner=(uid,uid),mode=0o600)
        need(config == prepared(payload,'configs/'+role+'.json'), 'Clone configuration changed')
        path = '/run/jobman-dashboard-restore-'+role+'-lab/observe.sock'
        try:
            info = Path(path).lstat()
        except FileNotFoundError as error:
            raise ReadinessPending('Clone observation socket is starting') from error
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == uid, 'Clone observation socket identity differs')
        try:
            ready_raw = run(['runuser','-u',name,'--','curl','--silent','--show-error','--fail','--max-time','3','--unix-socket',path,'http://localhost/readyz'],timeout=4)
            metrics = run(['runuser','-u',name,'--','curl','--silent','--fail','--max-time','3','--unix-socket',path,'http://localhost/metrics'],timeout=4,maximum=256<<10)
        except (ValueError,subprocess.SubprocessError) as error:
            raise ReadinessPending('Clone dependencies are starting') from error
        ready = decode(ready_raw)
        need(ready.get('state') == 'ready' and ready.get('role') == role, 'Clone readiness identity differs')
        revisions = re.findall(rb'^jobman_dashboard_configuration_revision ([0-9]+)$',metrics,re.MULTILINE)
        need(revisions == [str(payload['plan']['configurationRevision']).encode()], 'Clone observed revision differs')
        need(b'jobman_dashboard_' in metrics, 'Clone metric family missing')
        values[role] = {'process':state,'ready':ready,'metricsSHA256':digest(metrics),'metricsBytes':len(metrics)}
    status = decode(run([binary,'status','--operator-config',str(clone_root('operator')/'config.json')],timeout=10))
    return {'held':True,'holdGeneration':hold['generation'],'components':values,'operatorStatus':status,'deliveryComponent':False,'apnsProvider':False}


def await_clone_ready(payload, timeout=25):
    deadline = time.monotonic()+timeout
    if COMMAND_DEADLINE is not None:
        deadline = min(deadline,COMMAND_DEADLINE)
    with phase_deadline(deadline):
        while True:
            need(time.monotonic() < deadline, 'Clone readiness deadline exceeded')
            try:
                return verify_clone(payload)
            except ReadinessPending:
                need(time.monotonic() < deadline, 'Clone readiness deadline exceeded')
                time.sleep(min(0.2,max(0,deadline-time.monotonic())))


def start_clone(payload):
    with phase_deadline(time.monotonic()+50):
        return start_clone_bounded(payload)


def start_clone_bounded(payload):
    root, done = begin_phase(payload,'clone-start')
    if done:
        await_clone_ready(payload)
        return done
    clone_stopped()
    binary = candidate(payload)
    expected = decode(read(root/'clone-hold.json',owner=(0,0),mode=0o600)[0])
    actual = decode(run([binary,'events','hold-status','--config',str(clone_root('operator')/'recovery.json')],timeout=15))
    need(actual['held'] is True and actual['generation'] == expected['hold']['generation'], 'Cannot start restored workers without persisted hold')
    for role,(name,uid) in CLONE.items():
        directory('/run/jobman-dashboard-restore-'+role+'-lab',uid,uid)
        raw, _ = read(clone_root(role)/'config.json',256<<10,owner=(uid,uid),mode=0o600)
        need(raw == prepared(payload,'configs/'+role+'.json'), 'Clone startup configuration differs')
        run(['runuser','-u',name,'--',binary,'--mode','check-config','--check-mode',role,'--config',str(clone_root(role)/'config.json')])
    run(['systemctl','start','jobman-dashboard-restore-api-lab.service','jobman-dashboard-restore-worker-lab.service'],timeout=30)
    result = await_clone_ready(payload)
    return finish_phase(payload,root,'clone-start',dict(result,manifestSHA256=digest(encoded(result))))


def dispatch(payload):
    need(os.geteuid() == 0 and sys.platform == 'linux', 'Privileged Linux Lab guest required')
    host = socket.gethostname().split('.')[0]
    need(host == payload['host'] and host in ('pg01', 'storage01'), 'Unapproved guest')
    if payload['phase'] == 'inspect-operation':
        root = BASE / payload['operationId']
        need(HEX.fullmatch(payload['operationId']) and root.is_dir(), 'Known operation required')
        names = ('intent','database-provision','database-backup','database-restore','storage-provision','armed','stopped','objects-backup','backup-complete','disarmed','fired','snapshot-install','clone-hold','clone-start')
        return {name: decode(read(root/(name+'.json'),4<<20,owner=(0,0),mode=0o600)[0]) for name in names if (root/(name+'.json')).exists()}
    if payload['phase'] == 'snapshot':
        return database_snapshot(payload) if host == 'pg01' else storage_snapshot(payload)
    if host == 'pg01':
        actions = {'provision-database': provision_database, 'database-backup': database_dump, 'restore-database': restore_database}
        need(payload['phase'] in actions, 'Unimplemented database phase')
        return actions[payload['phase']](payload)
    need(host == 'storage01', 'Backup control is storage-host only')
    actions = {'arm-backup': arm_backup, 'stop-primary': stop_primary, 'restart-primary': restart_primary,
               'watchdog': lambda value: restart_primary(value, fired=True), 'complete-backup': complete_backup,
               'provision-storage': provision_storage, 'objects-backup': objects_backup, 'install-snapshot': install_snapshot,
               'hold-clone': hold_clone, 'start-clone': start_clone, 'verify-clone': verify_clone}
    need(payload['phase'] in actions, 'Unimplemented guest phase')
    return actions[payload['phase']](payload)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) == 3 and sys.argv[1] == '--watchdog':
            raw, _ = read(sys.argv[2], 4 << 20, owner=(0, 0), mode=0o600)
            need(decode(raw).get('phase') == 'watchdog', 'Watchdog payload required')
        else:
            need(len(sys.argv) == 1, 'Unsupported guest argument')
            raw = sys.stdin.buffer.read((4 << 20) + 1)
        need(len(raw) <= 4 << 20, 'Payload bound exceeded')
        print(encoded(dispatch(decode(raw))).decode(), end='')
    except Exception:
        print('Restore phase failed. Preserve private receipts; no implicit restore, hold release or cleanup.', file=sys.stderr)
        sys.exit(1)
