#!/usr/bin/env python3
"""Fixed-scope guest phases, invoked only by the reviewed split apply driver.

Receives private input over stdin. Emits bounded nonsecret receipts only. No
automatic hold release, database restore, old-binary downgrade or state cleanup.
"""
import base64
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import types
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit, parse_qs

APP = Path('/etc/jobman-dashboard-app-lab')
BROKER = Path('/etc/jobman-dashboard-broker-lab')
FIXTURE = Path('/etc/jobman-dashboard-lab/control-fixture')
BASE = Path('/var/lib/jobman-dashboard-split-lab')
CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'
ROLES = ('api', 'worker', 'operator')
UNITS = ('jobman-dashboard-lab-app', 'jobman-dashboard-lab-api', 'jobman-dashboard-lab-worker')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def run(args, data=None, timeout=30):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    need(result.returncode == 0 and len(result.stdout) < 16 << 20, 'Guest command failed; preserve receipts for private inspection')
    return result.stdout


def read(path, maximum=1 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, 'Unexpected bounded regular file')
        raw = stream.read(maximum + 1)
        need(len(raw) == info.st_size, 'File changed while read')
        return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(fd, uid, gid, mode, kind):
    info = os.fstat(fd)
    need(kind(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode), 'Created path ownership differs')
    return info


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def directory(path, uid=0, gid=0, mode=0o700):
    created = False
    try:
        path.mkdir(mode=mode)
        created = True
    except FileExistsError:
        pass
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if created:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
        info = identity(fd, uid, gid, mode, stat.S_ISDIR)
        final = path.lstat()
        need((final.st_dev, final.st_ino) == (info.st_dev, info.st_ino), 'Directory identity changed')
    finally: os.close(fd)


def put(path, raw, uid=0, gid=0, mode=0o600):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)) == (uid,gid,mode) and read(path,96<<20) == raw,
             'Existing staged file differs')
        return
    with os.fdopen(fd, 'wb') as out:
        os.fchown(out.fileno(), uid, gid)
        os.fchmod(out.fileno(), mode)
        identity(out.fileno(), uid, gid, mode, stat.S_ISREG)
        out.write(raw);out.flush();os.fsync(out.fileno())
        info = identity(out.fileno(), uid, gid, mode, stat.S_ISREG)
        final = path.lstat()
        need(info.st_size == len(raw) and (final.st_dev, final.st_ino) == (info.st_dev, info.st_ino), 'Created file identity changed')


def capacity(path, required):
    path = Path(path)
    while not path.exists(): path = path.parent
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        values = os.fstatvfs(fd)
        available = values.f_bavail * values.f_frsize
        need(available >= required, 'Insufficient filesystem capacity for reviewed bounded operation')
        return {'availableBytes': available, 'requiredBytes': required, 'device': os.fstat(fd).st_dev}
    finally: os.close(fd)


def capacity_policy(plan):
    expected = {'maximumDatabaseBytes': 1 << 30, 'maximumDumpBytes': 1 << 30,
                'reserveBytes': 256 << 20, 'migrationDatabaseMultiplier': 2, 'dumpTimeoutSeconds': 120}
    need(plan['capacity'] == expected, 'Capacity policy differs')
    return expected


def staging_capacity(plan, host, report_bytes=0):
    policy = capacity_policy(plan)
    sizes = plan['preparedFileBytes']
    need(set(sizes) == set(plan['preparedFiles']) and all(type(n) is int and 0 < n <= 96 << 20 for n in sizes.values()), 'Prepared sizes differ')
    if host == 'storage01':
        staged = sum(sizes.values())
        release = sum(n for key, n in sizes.items() if key.startswith('candidate/'))
    elif host == 'control01':
        staged = sum(n for key, n in sizes.items() if key in ('candidate/bin/jobman-log-broker','configs/broker.json','configs/api.json','units/jobman-dashboard-lab-broker.service') or
                     key.startswith('material/') and key.endswith(('-control-client.csr','-control-signing-public.pem','-broker-signing-public.pem')))
        release = sizes['candidate/bin/jobman-log-broker']
    else:
        staged = sum(n for key, n in sizes.items() if key.startswith('grants/') or key == 'material/database-passwords.json')
        release = 0
    # Sum demands sharing a filesystem; otherwise prove each mount separately.
    demands = [(BASE, staged + report_bytes), (Path(plan['releaseRoot']), release)]
    by_device = {}
    for path, amount in demands:
        available = capacity(path, 0)
        item = by_device.setdefault(available['device'], [path, 0])
        item[1] += amount
    return [capacity(path, amount + policy['reserveBytes']) for path, amount in by_device.values()]


def database_capacity(plan):
    policy = capacity_policy(plan)
    size = int(sql('SELECT pg_database_size(current_database())::text'))
    need(0 < size <= policy['maximumDatabaseBytes'], 'Database exceeds reviewed size bound')
    required = policy['maximumDumpBytes'] + size * policy['migrationDatabaseMultiplier'] + policy['reserveBytes']
    backup = capacity(BASE, required)
    raw = run(['podman','exec','jobman-postgres','stat','-f','--format=%a:%S','/var/lib/postgresql/data']).decode().strip()
    need(re.fullmatch(r'[0-9]+:[0-9]+', raw), 'PostgreSQL storage capacity unavailable')
    blocks, block_size = map(int, raw.split(':'))
    need(blocks * block_size >= required, 'PostgreSQL storage insufficient for schema rewrite')
    return {'databaseBytes': size, 'backup': backup, 'postgresAvailableBytes': blocks * block_size, 'postgresRequiredBytes': required}


def verified_object_helper(payload):
    helper = base64.b64decode(payload['objectHelper'], validate=True)
    need(digest(helper) == payload['plan']['implementationSHA256']['dashboard-split-files.py'], 'Object helper differs from reviewed plan')
    module = types.ModuleType('reviewed_split_objects')
    exec(compile(helper, '<reviewed-split-objects>', 'exec'), module.__dict__)
    return module


def replace(path, raw, expected, backup, uid, gid, mode=0o600):
    current = read(path,96 << 20)
    if current == raw:
        need(backup.exists(), 'Replacement has no preserved prior version')
        return
    need(digest(current) == expected, 'Live file hash changed; regenerate plan')
    old = path.lstat()
    need(stat.S_ISREG(old.st_mode) and old.st_uid == uid and old.st_gid == gid and stat.S_IMODE(old.st_mode) == mode, 'Live file ownership changed')
    put(backup,current)
    pending=Path(str(path)+'.split-pending')
    put(pending,raw,uid,gid,mode)
    os.replace(pending,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def sql(query):
    return run(['podman','exec','-i','jobman-postgres','psql','-X','-At','-v','ON_ERROR_STOP=1','-U','jobman_control','-d','jobman_dashboard'],query.encode()).decode().strip()


def schema():
    return sql("SELECT string_agg(name,',' ORDER BY name) FROM dashboard_schema_migrations")


def check_schema(number):
    names=schema().split(',')
    need(len(names)==number and all(name.startswith('migrations/'+str(i).zfill(6)+'_') for i,name in enumerate(names,1)), 'Schema ledger differs')


def stopped():
    for unit in UNITS:
        result=subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True)
        need(result.returncode in (3,4), 'A Dashboard process is still active')
    # The systemd units are the only supported process launcher in this fixture.
    processes=run(['ps','-eo','uid=,args=']).decode()
    for line in processes.splitlines():
        if re.match(r'\s*(21903|21904|21905)\s',line) and ('jobman-dashboard ' in line or 'jobman-dashboard\x00' in line):
            raise ValueError('Unexpected Dashboard process outside stopped units')


def active(*units):
    for unit in units:run(['systemctl','is-active','--quiet',unit])


def original_processes():
    return {'control':run(['systemctl','show','jobman-control','--property=ExecMainStartTimestampMonotonic','--value']).decode().strip(),
            'directory':run(['systemctl','show','jobman-dashboard-lab-directory','--property=ExecMainStartTimestampMonotonic','--value']).decode().strip(),
            'keycloak':run(['podman','inspect','jobman-keycloak','--format','{{.State.StartedAt}}']).decode().strip()}


def legacy_material():
    app=json.loads(read(APP/'config.json'))
    url=urlsplit(read(APP/'database-url').decode().strip())
    need(url.scheme=='postgres' and url.hostname=='10.77.0.20' and url.port==5432 and url.path=='/jobman_dashboard' and url.username=='jobman_dashboard' and
         parse_qs(url.query)=={'sslmode':['verify-full'],'sslrootcert':[CA]},'Legacy database connection scope differs')
    paths=[APP/name for name in ('database-url','server.crt','server.key','web-client-secret','encryption-key','control-ca.crt','redaction.json')]
    for item in app.get('notifications',{}).get('previousTokenKeys',[]):
        path=Path(item['keyFile']);need(path.parent==APP,'Previous key outside legacy private directory');paths.append(path)
    result={}
    for path in paths:
        st=path.lstat();need(stat.S_ISREG(st.st_mode) and st.st_uid==21903 and stat.S_IMODE(st.st_mode)==0o600,'Legacy material ownership differs')
        result[path.name]=digest(read(path))
    return result


def common(payload, mutate=False):
    need(os.getuid()==0,'Guest phases require the scoped Lab operator')
    plan=payload['plan'];key=payload['planSHA256']
    need(re.fullmatch('[0-9a-f]{64}',key) and digest(encoded(plan))==key and
         plan.get('format')=='jobman.dashboard.lab-split/v1' and plan.get('synthetic') is True and
         re.fullmatch('[0-9a-f]{40}',plan['revision']) and plan['deploymentId']=='72000000-0000-4000-8000-000000000001' and
         plan['database']=='jobman_dashboard' and plan['schemaBefore']==17 and plan['schemaAfter']==18 and
         plan['releaseRoot']=='/opt/jobman-dashboard-lab/releases/'+plan['revision'], 'Plan scope is invalid')
    root=BASE/key
    if mutate:
        directory(BASE)
        directory(root)
        put(root/'plan.json',encoded(plan))
    return plan,root


def snapshot(payload):
    plan,_=common(payload)
    host=payload['host']
    result={'epoch':int(time.time()),'host':host}
    if host=='storage01':
        raw=read(APP/'config.json');need(digest(raw)==plan['inputSHA256']['app'],'Application config changed')
        need(pwd.getpwnam('jobman-dashboard-app').pw_uid==21903,'Legacy UID differs')
        for name,number in [('jobman-dashboard-api',21904),('jobman-dashboard-worker',21905)]:
            for value in (name,number):
                try:pwd.getpwnam(value) if isinstance(value,str) else pwd.getpwuid(value)
                except KeyError:continue
                raise ValueError('New service identity is already allocated')
        for name,number in [('jobman-dashboard-api',21904),('jobman-dashboard-worker',21905),('jobman-dashboard-report-readers',21906)]:
            for value in (name,number):
                try:grp.getgrnam(value) if isinstance(value,str) else grp.getgrgid(value)
                except KeyError:continue
                raise ValueError('New group identity is already allocated')
        need(not Path(plan['reportRootAfter']).exists(),'New report root already exists')
        need(run(['stat','-f','--format=%T',plan['reportRootBefore']]).strip() in (b'ext2/ext3',b'ext4',b'xfs',b'btrfs',b'tmpfs'),'Unsupported report filesystem')
        need(Path(plan['reportRootBefore']).stat().st_dev==Path('/var/lib').stat().st_dev,'Report roots cross devices')
        manifest=verified_object_helper(payload).inventory(plan['reportRootBefore'],[(21903,21903,0o700,0o600)])
        result['capacity']=staging_capacity(plan,host,manifest['bytes'])
        result['reportBytes']=manifest['bytes']
        result.update(configSHA256=digest(raw),unitSHA256=digest(read('/etc/systemd/system/jobman-dashboard-lab-app.service')),
                      legacyBinarySHA256=digest(read('/usr/local/libexec/jobman-dashboard-lab/jobman-dashboard',96<<20)),legacyMaterialSHA256=legacy_material())
    elif host=='control01':
        raw=read(BROKER/'config.json');need(digest(raw)==plan['inputSHA256']['broker'],'Broker config changed')
        info=json.loads(read(FIXTURE/'fixture-info.json'));need(info['instanceId']==plan['sourceInstanceId'] and info['synthetic'] is True,'Source instance changed')
        policy=read(FIXTURE/'delegation.json')
        need(len(json.loads(policy)['services'])==2,'Source registrations changed')
        capability=json.loads(run(['runuser','-u','jobman-dashboard-source','--','curl','--silent','--fail','--max-time','5','--cacert',str(FIXTURE/'fixture-ca.crt'),'https://127.0.0.1:18443/v1/capabilities']))['capabilities']
        need(capability['instanceId']==plan['sourceInstanceId'],'Live source instance differs')
        result['capacity']=staging_capacity(plan,host)
        result.update(configSHA256=digest(raw),registrySHA256=digest(policy),sourceEpoch=capability['recoveryEpoch'],
                      unitSHA256=digest(read('/etc/systemd/system/jobman-dashboard-lab-broker.service')),preservedProcessStarts=original_processes())
    elif host=='pg01':
        check_schema(17)
        result['capacity']=database_capacity(plan)
        need(sql("SELECT count(*) FROM pg_roles WHERE rolname IN ('jobman_dashboard_api','jobman_dashboard_worker','jobman_dashboard_operator')")=='0','New database roles already exist')
        need(sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")=='jobman_dashboard_ddl','Database owner differs')
        result.update(schemaSHA256=digest(schema().encode()),hold=json.loads(sql("SELECT json_build_object('generation',generation::text,'held',held)::text FROM dashboard_notification_delivery_control WHERE singleton")),
                      hbaSHA256=digest(run(['podman','exec','jobman-postgres','cat','/var/lib/postgresql/data/pg_hba.conf'])))
    else:raise ValueError('Unexpected host')
    return result


def recheck_database_capacity(payload):
    plan,_=common(payload)
    return database_capacity(plan)


def stage_files(payload):
    plan,root=common(payload,True)
    host=payload['host'];files=payload['files']
    staging_capacity(plan,host)
    need(len(files)<=4096,'Stage file bound')
    for name,value in files.items():
        need(name in plan['preparedFiles'] and '..' not in Path(name).parts and not Path(name).is_absolute(),'Unreviewed staged file')
        raw=base64.b64decode(value,validate=True)
        need(digest(raw)==plan['preparedFiles'][name] and len(raw)==plan['preparedFileBytes'][name],'Staged file hash or size differs')
        target=root/name
        parent=root
        for part in target.parent.relative_to(root).parts:
            parent=parent/part;directory(parent)
        put(target,raw,mode=0o700 if name.startswith('candidate/bin/') else 0o600)
    if host in ('storage01','control01'):
        directory(Path('/opt/jobman-dashboard-lab'),mode=0o755)
        directory(Path('/opt/jobman-dashboard-lab/releases'),mode=0o755)
        release=Path(plan['releaseRoot']);directory(release,mode=0o755)
        for name in files:
            if not name.startswith('candidate/'):
                continue
            relative=name[len('candidate/'):]
            if host=='control01' and relative!='bin/jobman-log-broker':continue
            target=release/relative;parent=release
            for part in target.parent.relative_to(release).parts:
                parent=parent/part;directory(parent,mode=0o755)
            put(target,read(root/name,96<<20),mode=0o755 if relative.startswith('bin/') else 0o644)
    put(root/'staged.json',encoded({'planSHA256':payload['planSHA256'],'host':host}))
    return {'staged':True,'host':host}


def source_certificates(payload):
    plan,root=common(payload,True)
    need(digest(read(BROKER/'config.json'))==plan['inputSHA256']['broker'],'Broker config changed before certification')
    directory(root/'certificates')
    output={}
    for role in ('api','worker'):
        csr=root/'material'/(role+'-control-client.csr');certificate=root/'certificates'/(role+'-control-client.crt')
        if not certificate.exists():
            run(['openssl','req','-in',str(csr),'-verify','-noout'])
            run(['openssl','x509','-req','-sha256','-days','7','-in',str(csr),'-CA',str(FIXTURE/'fixture-ca.crt'),'-CAkey',str(FIXTURE/'fixture-ca.key'),
                 '-set_serial','0x'+digest(read(csr))[:30],'-copy_extensions','copyall','-out',str(certificate)])
            certificate.chmod(0o600)
        run(['openssl','verify','-purpose','sslclient','-CAfile',str(FIXTURE/'fixture-ca.crt'),str(certificate)])
        run(['openssl','x509','-in',str(certificate),'-checkend','3600','-noout'])
        need(run(['openssl','req','-in',str(csr),'-pubkey','-noout'])==run(['openssl','x509','-in',str(certificate),'-pubkey','-noout']),'CSR public key differs')
        output[role]=base64.b64encode(read(certificate)).decode()
    return {'certificates':output}


def provision_database(payload):
    plan,root=common(payload,True)
    check_schema(17)
    passwords=json.loads(read(root/'material/database-passwords.json'))
    need(set(passwords)==set(ROLES) and all(re.fullmatch('[0-9a-f]{64}',v) for v in passwords.values()),'Database credential shape differs')
    marker=root/'roles-created.json'
    if not marker.exists():
        need(sql("SELECT count(*) FROM pg_roles WHERE rolname IN ('jobman_dashboard_api','jobman_dashboard_worker','jobman_dashboard_operator')")=='0','Database role conflict')
        statements=['BEGIN;','SET LOCAL password_encryption=\'scram-sha-256\';']
        for role in ROLES:
            name='jobman_dashboard_'+role
            statements.extend([f"CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {4 if role=='operator' else 24} PASSWORD '{passwords[role]}';",
                               f'GRANT CONNECT ON DATABASE jobman_dashboard TO {name};'])
        statements.append('COMMIT;');sql('\n'.join(statements))
        put(marker,encoded({'planSHA256':payload['planSHA256']}))
    current=run(['podman','exec','jobman-postgres','cat','/var/lib/postgresql/data/pg_hba.conf'])
    names=','.join('jobman_dashboard_'+r for r in ROLES)
    block=(f'# BEGIN Dashboard split {payload["planSHA256"]}\nlocal all {names} reject\nhostnossl all {names} 0.0.0.0/0 reject\nhostnossl all {names} ::0/0 reject\nhostssl jobman_dashboard {names} 10.77.0.0/24 scram-sha-256\nhostssl jobman_dashboard {names} 127.0.0.1/32 scram-sha-256\nhost all {names} 0.0.0.0/0 reject\nhost all {names} ::0/0 reject\n# END Dashboard split\n').encode()
    if not current.startswith(block):
        need(digest(current)==payload['preflight']['pg01']['hbaSHA256'],'HBA changed since preflight')
        put(root/'pg_hba.before',current);put(root/'pg_hba.after',block+current)
        run(['podman','cp',str(root/'pg_hba.after'),'jobman-postgres:/var/lib/postgresql/data/pg_hba.conf'])
    run(['podman','exec','--user','root','jobman-postgres','chown','postgres:postgres','/var/lib/postgresql/data/pg_hba.conf'])
    need(sql("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")=='0','New HBA did not parse')
    need(sql('SELECT pg_reload_conf()')=='t','PostgreSQL reload failed')
    return {'rolesPrepared':True,'schema':17}


def identities(payload):
    plan,root=common(payload,True)
    marker=root/'identities-started.json'
    if not marker.exists():
        for name,gid in [('jobman-dashboard-api',21904),('jobman-dashboard-worker',21905),('jobman-dashboard-report-readers',21906)]:
            for value in (name,gid):
                try:grp.getgrnam(value) if isinstance(value,str) else grp.getgrgid(value)
                except KeyError:continue
                raise ValueError('New group identity became occupied')
        for name,uid in [('jobman-dashboard-api',21904),('jobman-dashboard-worker',21905)]:
            for value in (name,uid):
                try:pwd.getpwnam(value) if isinstance(value,str) else pwd.getpwuid(value)
                except KeyError:continue
                raise ValueError('New service identity became occupied')
        put(marker,encoded({'planSHA256':payload['planSHA256']}))
    for name,gid in [('jobman-dashboard-api',21904),('jobman-dashboard-worker',21905),('jobman-dashboard-report-readers',21906)]:
        try:existing=grp.getgrnam(name);need(existing.gr_gid==gid,'Existing named group differs')
        except KeyError:run(['groupadd','--gid',str(gid),name])
    for role,uid in [('api',21904),('worker',21905)]:
        name='jobman-dashboard-'+role
        try:existing=pwd.getpwnam(name);need(existing.pw_uid==uid and existing.pw_gid==uid and existing.pw_shell=='/usr/sbin/nologin','Existing service account differs')
        except KeyError:run(['useradd','--uid',str(uid),'--gid',str(uid),'--groups','jobman-dashboard-report-readers','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',name])
        directory(Path('/etc/jobman-dashboard-'+role+'-lab'),uid,uid)
    directory(Path('/etc/jobman-dashboard-operator-lab'))
    put(root/'identities-created.json',encoded({'planSHA256':payload['planSHA256']}))
    return {'identitiesPrepared':True}


def install_material(payload):
    plan,root=common(payload,True)
    need(digest(read(APP/'config.json'))==plan['inputSHA256']['app'],'Combined config changed')
    need(legacy_material()==payload['preflight']['storage01']['legacyMaterialSHA256'],'Legacy private material changed')
    app=json.loads(read(APP/'config.json'))
    passwords=json.loads(read(root/'material/database-passwords.json'))
    for role,uid in [('api',21904),('worker',21905),('operator',0)]:
        target=Path('/etc/jobman-dashboard-'+role+'-lab')
        url='postgres://jobman_dashboard_'+role+':'+passwords[role]+'@10.77.0.20:5432/jobman_dashboard?'+urlencode({'sslmode':'verify-full','sslrootcert':CA})+'\n'
        put(target/'database-url',url.encode(),uid,uid)
        put(target/'config.json',read(root/'configs'/(role+'.json')),uid,uid)
        if role=='operator':continue
        for name in ('control-ca.crt','redaction.json'):
            put(target/name,read(APP/name),uid,uid)
        for kind in ('control','broker'):
            for suffix in ('client.key','signing-key.pem'):
                put(target/(kind+'-'+suffix),read(root/'material'/(role+'-'+kind+'-'+suffix)),uid,uid)
            certificate=base64.b64decode(payload['certificates'][role+'-'+kind],validate=True)
            need(len(certificate)<16384 and b'PRIVATE' not in certificate,'Invalid public certificate')
            put(target/(kind+'-client.crt'),certificate,uid,uid)
        if role=='api':
            for name in ('server.crt','server.key','web-client-secret','encryption-key'):
                put(target/name,read(APP/name),uid,uid)
    put(root/'material-installed.json',encoded({'planSHA256':payload['planSHA256']}))
    return {'materialPrepared':True}


def stop_and_hold(payload, use_new=False):
    plan,root=common(payload,True)
    need(digest(read(APP/'config.json'))==plan['inputSHA256']['app'],'Combined config changed before stop')
    for unit in UNITS:
        # stop also accepts a not-yet-installed unit as a no-op only for the new
        # names; the retained combined unit must exist.
        found=subprocess.run(['systemctl','cat',unit],capture_output=True)
        if found.returncode==0:run(['systemctl','stop',unit],timeout=100)
        else:need(unit!='jobman-dashboard-lab-app','Legacy unit missing')
    stopped()
    legacy='/usr/local/libexec/jobman-dashboard-lab/jobman-dashboard'
    need(digest(read(legacy,96<<20))==payload['preflight']['storage01']['legacyBinarySHA256'],'Legacy binary changed')
    binary=plan['releaseRoot']+'/bin/jobman-dashboard' if use_new else legacy
    status=json.loads(run([binary,'events','hold-status','--config',str(APP/'config.json')]))
    if not status['held']:
        status=json.loads(run([binary,'events','hold','--config',str(APP/'config.json'),'--generation',status['generation']]))
    need(status['held'] is True,'Persisted hold not established')
    put(root/('rollback-hold.json' if use_new else 'hold.json'),encoded(status))
    put(root/'legacy-config.json',read(APP/'config.json'))
    put(root/'legacy-unit.service',read('/etc/systemd/system/jobman-dashboard-lab-app.service'))
    return {'held':True,'generation':status['generation']}


def assert_stopped_held(payload):
    plan,_=common(payload);stopped()
    need(payload['schema'] in (17,18),'Unexpected schema assertion')
    binary='/usr/local/libexec/jobman-dashboard-lab/jobman-dashboard' if payload['schema']==17 else plan['releaseRoot']+'/bin/jobman-dashboard'
    status=json.loads(run([binary,'events','hold-status','--config',str(APP/'config.json')]))
    need(status['held'] is True,'Persisted hold no longer established')
    return {'held':True,'generation':status['generation'],'stopped':True}


def file_checksum(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum and
             before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600, 'Backup file shape differs')
        checksum = hashlib.sha256(); total = 0
        while True:
            chunk = source.read(65536)
            if not chunk: break
            total += len(chunk); need(total <= maximum, 'Backup exceeds byte cap'); checksum.update(chunk)
        after = os.fstat(source.fileno())
        final = path.lstat()
        need(total == before.st_size and (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) ==
             (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) and
             (final.st_dev,final.st_ino)==(before.st_dev,before.st_ino), 'Backup changed during checksum')
        return {'sha256': checksum.hexdigest(), 'bytes': total}


def bounded_dump(args, target, maximum, timeout):
    # A failed partial is preserved for inspection and never adopted on retry.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    total = 0; checksum = hashlib.sha256(); failure = 'command'
    with os.fdopen(fd, 'wb') as out:
        os.fchmod(out.fileno(), 0o600)
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0: failure = 'timeout'; raise ValueError('Database dump deadline exceeded')
                    if not ready.select(remaining): failure = 'timeout'; raise ValueError('Database dump deadline exceeded')
                    chunk = os.read(process.stdout.fileno(), min(65536, maximum - total + 1))
                    if not chunk: break
                    if total + len(chunk) > maximum: failure = 'byte-cap'; raise ValueError('Database dump exceeded byte cap')
                    out.write(chunk); total += len(chunk); checksum.update(chunk)
                need(process.wait(timeout=max(0.001, deadline-time.monotonic())) == 0, 'Database dump failed')
            need(total > 0, 'Database dump was empty')
            out.flush(); os.fsync(out.fileno())
        except BaseException:
            process.kill(); process.wait(timeout=5)
            out.flush(); os.fsync(out.fileno())
            put(Path(str(target)+'.failed.json'), encoded({'complete': False, 'reason': failure, 'bytes': total, 'sha256': checksum.hexdigest()}),os.getuid(),os.getgid())
            sync_directory(target.parent)
            raise
        finally: process.stdout.close()
    return {'bytes': total, 'sha256': checksum.hexdigest()}


def database_backup(payload):
    plan,root=common(payload,True)
    policy=capacity_policy(plan)
    need(sql('SELECT held FROM dashboard_notification_delivery_control WHERE singleton')=='t','Backup requires persisted hold')
    target=root/'dashboard-before.dump';partial=root/'dashboard-before.dump.partial'
    completed=root/'database-backup-complete.json'
    if completed.exists():
        receipt=json.loads(read(completed))
        need(receipt['schema']==17 and receipt['planSHA256']==payload['planSHA256'],'Completed backup scope differs')
        need(target.exists() != partial.exists(),'Completed backup pathname is ambiguous')
        actual=file_checksum(target if target.exists() else partial,policy['maximumDumpBytes'])
        need(all(receipt[k]==actual[k] for k in ('bytes','sha256')),'Completed backup bytes differ')
        if partial.exists():os.replace(partial,target);sync_directory(root)
        put(root/'database-backup.json',encoded(receipt))
        return receipt
    need(not target.exists() and not partial.exists(),'Incomplete backup requires private operator inspection; never reuse a partial dump')
    check_schema(17);database_capacity(plan)
    receipt=bounded_dump(['podman','exec','jobman-postgres','timeout','--signal=TERM','120','pg_dump','-U','jobman_control','-d','jobman_dashboard','--format=custom'],
                         partial,policy['maximumDumpBytes'],policy['dumpTimeoutSeconds'])
    # Validate the TOC only AFTER pg_dump exited successfully and bytes synced.
    # A readable TOC alone is never evidence that table data was fully dumped.
    try:
        with partial.open('rb') as source:
            result=subprocess.run(['podman','exec','-i','jobman-postgres','pg_restore','--list'],stdin=source,capture_output=True,timeout=60)
        need(result.returncode==0 and len(result.stdout)<16<<20 and b'dashboard_schema_migrations' in result.stdout and
             b'dashboard_report_tasks' in result.stdout,'Completed dump listing lacks expected schema')
        need(file_checksum(partial,policy['maximumDumpBytes'])==receipt,'Dump changed during listing')
    except BaseException:
        put(root/'database-backup-validation-failed.json',encoded(dict(receipt,complete=False,reason='validation')))
        sync_directory(root)
        raise
    receipt.update(schema=17,planSHA256=payload['planSHA256'])
    put(completed,encoded(receipt));sync_directory(root)
    os.replace(partial,target);sync_directory(root)
    put(root/'database-backup.json',encoded(receipt));sync_directory(root)
    return receipt


def object_module(root):
    spec=importlib.util.spec_from_file_location('split_objects',root/'dashboard-split-files.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def objects_and_keys(payload):
    plan,root=common(payload,True);stopped()
    helper=base64.b64decode(payload['objectHelper'],validate=True)
    need(digest(helper)==payload['objectHelperSHA256'],'Object helper hash differs')
    put(root/'dashboard-split-files.py',helper)
    objects=object_module(root)
    manifest=objects.inventory(plan['reportRootBefore'],[(21903,21903,0o700,0o600)])
    backup=root/'report-backup'
    if not backup.exists():
        capacity(root,manifest['bytes']+capacity_policy(plan)['reserveBytes'])
        objects.backup(plan['reportRootBefore'],backup,manifest,(21903,21903,0o700,0o600))
    need(json.loads(read(backup/'manifest.json',4<<20))==manifest,'Report backup differs')
    put(root/'reports-before.json',encoded(manifest))
    export=root/'purpose-keys'
    if not export.exists():run([plan['releaseRoot']+'/bin/jobman-dashboard','keys','export','--config',str(APP/'config.json'),'--output-directory',str(export)])
    exported=json.loads(read(export/'manifest.json'))
    need(exported['format']=='jobman.dashboard.purpose-keys/v1','Purpose export incomplete')
    for role,uid in [('api',21904),('worker',21905)]:
        target=Path('/etc/jobman-dashboard-'+role+'-lab')
        for name in ('report-policy.key','log-cursor.key'):put(target/name,read(export/name),uid,uid)
        if role=='api':
            keys=[exported['tokenEncryption']['current']]+exported['tokenEncryption'].get('previous',[])
            for i,key in enumerate(keys):
                need(Path(key['keyFile'])==export/('token-'+str(i)+'.key'),'Export key path differs')
                put(target/('token-'+str(i)+'.key'),read(key['keyFile']),uid,uid)
    put(root/'keys-exported.json',encoded({'complete':True,'tokenKeyIds':[x['keyId'] for x in [exported['tokenEncryption']['current']]+exported['tokenEncryption'].get('previous',[])]}))
    return {'objects':len(manifest['entries']),'objectBytes':manifest['bytes'],'backedUp':True,'purposeKeysExported':True}


def schema_state(payload):
    plan,root=common(payload)
    candidate=plan['releaseRoot']+'/bin/jobman-dashboard'
    need(digest(read(candidate,96<<20))==plan['preparedFiles']['candidate/bin/jobman-dashboard'],'Installed candidate changed')
    # hold-status calls Store.CheckSchema: exact migration names AND checksums.
    # Probe binaries without exposing diagnostics or accepting a row-count check.
    for number,binary in ((18,candidate),(17,'/usr/local/libexec/jobman-dashboard-lab/jobman-dashboard')):
        result=subprocess.run([binary,'events','hold-status','--config',str(APP/'config.json')],capture_output=True,timeout=30)
        if result.returncode != 0:continue
        need(len(result.stdout)<65536,'Hold response exceeds bound')
        status=json.loads(result.stdout)
        need(status['held'] is True,'Persisted hold no longer established')
        if number==18:
            started=json.loads(read(root/'migration-started.json'))
            need(started['revision']==plan['revision'] and started['planSHA256']==payload['planSHA256'],'Schema18 has no matching migration intent receipt')
        return {'schema':number,'held':True,'generation':status['generation']}
    raise ValueError('Neither pinned binary verifies the exact migration ledger; operator inspection required')


def migrate(payload):
    plan,root=common(payload,True);stopped()
    need(payload['backup']['schema']==17 and payload['backup']['planSHA256']==payload['planSHA256'] and
         re.fullmatch('[0-9a-f]{64}',payload['backup']['sha256']),'Database backup receipt required')
    intent={'revision':plan['revision'],'planSHA256':payload['planSHA256'],'backupSHA256':payload['backup']['sha256']}
    state=schema_state(payload)
    if state['schema']==18:
        need(json.loads(read(root/'migration-started.json'))==intent,'Migration intent differs')
    else:
        password=payload['ddlPassword'];need(re.fullmatch('[0-9a-f]{64}',password),'DDL credential shape differs')
        dsn=root/'migration-database-url'
        url='postgres://jobman_dashboard_ddl:'+password+'@10.77.0.20:5432/jobman_dashboard?'+urlencode({'sslmode':'verify-full','sslrootcert':CA})+'\n'
        put(dsn,url.encode())
        put(root/'migration-started.json',encoded(intent));sync_directory(root)
        try:run([plan['releaseRoot']+'/bin/jobman-dashboard','--mode','migrate','--config','/etc/jobman-dashboard-api-lab/config.json','--migration-database-url-file',str(dsn)],timeout=120)
        finally:dsn.unlink()
        need(schema_state(payload)['schema']==18,'Candidate did not verify completed schema18')
    put(root/'schema18-applied.json',encoded(intent));sync_directory(root)
    return {'schemaApplied':18}


def recover_state(payload):
    plan,root=common(payload)
    state=schema_state(payload)
    result={'schema':state['schema'],'held':True}
    if state['schema']==18:
        completed=root/'schema18-applied.json'
        need(completed.exists(),'Missing completed migration receipt; retry stopped cutover to finalize verified migration first')
        receipt=json.loads(read(completed))
        need(receipt==json.loads(read(root/'migration-started.json')),'Migration receipts disagree')
        result['migration']={'schemaApplied':18}
    started=root/'split-started.json'
    if started.exists():
        need(json.loads(read(started))=={'revision':plan['revision'],'held':True},'Activation receipt differs')
        for role in ('api','worker'):
            need(digest(read('/etc/jobman-dashboard-'+role+'-lab/config.json'))==plan['configSHA256'][role],'Activated config changed')
            unit='units/jobman-dashboard-lab-'+role+'.service'
            need(digest(read('/etc/systemd/system/jobman-dashboard-lab-'+role+'.service'))==plan['preparedFiles'][unit],'Activated unit changed')
        verify(payload)
        result['activation']={'splitStarted':True,'held':True}
    else:stopped()
    return result


def apply_grants(payload):
    plan,root=common(payload,True);check_schema(18)
    need(sql('SELECT held FROM dashboard_notification_delivery_control WHERE singleton')=='t','Grants require persisted hold')
    for role in ROLES:sql(read(root/'grants'/(role+'.sql')).decode())
    put(root/'grants-applied.json',encoded({'schema':18}))
    return {'grantsApplied':list(ROLES)}


def convert_objects(payload, reverse=False):
    plan,root=common(payload,True);stopped();objects=object_module(root)
    assert_stopped_held(dict(payload,schema=18))
    source,destination=plan['reportRootBefore'],plan['reportRootAfter']
    before,after=(21903,21903,0o700,0o600),(21905,21906,0o750,0o640)
    receipt=root/('report-rollback.json' if reverse else 'report-conversion.json')
    if reverse:
        source,destination=destination,source;before,after=after,before
        manifest=json.loads(read(receipt,4<<20))['inventory'] if receipt.exists() else objects.inventory(source,[before])
        backup=root/'rollback-report-backup'
        if not backup.exists():
            capacity(root,manifest['bytes']+capacity_policy(plan)['reserveBytes'])
            objects.backup(source,backup,manifest,before)
        need(json.loads(read(backup/'manifest.json',4<<20))==manifest,'Rollback backup differs')
    else:manifest=json.loads(read(root/'reports-before.json',4<<20))
    put(receipt,objects.canonical({'source':source,'destination':destination,'before':list(before),'after':list(after),'inventory':manifest}))
    objects.convert(source,destination,receipt,before,after)
    return {'reportsConverted':True,'rollback':reverse,'objects':len(manifest['entries'])}


def source_activate(payload):
    plan,root=common(payload,True)
    capabilities=json.loads(run(['runuser','-u','jobman-dashboard-source','--','curl','--silent','--fail','--max-time','5','--cacert',str(FIXTURE/'fixture-ca.crt'),'https://127.0.0.1:18443/v1/capabilities']))['capabilities']
    need(capabilities['instanceId']==plan['sourceInstanceId'] and capabilities['recoveryEpoch']==payload['preflight']['control01']['sourceEpoch'],'Source authority changed since preflight')
    original=read(FIXTURE/'delegation.json');policy=json.loads(original)
    backup=root/'delegation.before.json'
    if backup.exists():policy=json.loads(read(backup))
    else:need(digest(original)==payload['preflight']['control01']['registrySHA256'],'Source registration drift')
    need(len(policy['services'])==2,'Original source registrations differ')
    app=json.loads(read(root/'configs/api.json'));namespaces=app['controls'][0]['namespaceIds'];audience=app['controls'][0]['audience']
    for role in ('api','worker'):
        cert=root/'certificates'/(role+'-control-client.crt')
        der=run(['openssl','x509','-in',str(cert),'-outform','DER'])
        public=run(['openssl','pkey','-pubin','-in',str(root/'material'/(role+'-control-signing-public.pem')),'-outform','DER'])
        need(public[:12]==bytes.fromhex('302a300506032b6570032100') and len(public)==44,'Signing key is not Ed25519')
        operations=['namespace.read','jobs.read','logs.read','evidence.read','events.read']
        if role=='api':operations+=['groups.read','targets.read','artifacts.read']
        policy['services'].append({'serviceId':'dashboard-'+role+'-lab','keyId':'split-'+role+'-control-v1','audience':audience,
             'publicKey':base64.b64encode(public[12:]).decode(),'certificateThumbprints':[base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip('=')],
             'namespaceIds':namespaces,'operations':operations,'enabled':True})
    replace(FIXTURE/'delegation.json',encoded(policy),payload['preflight']['control01']['registrySHA256'],backup,21902,21902)
    for role in ('api','worker'):
        put(BROKER/(role+'-client.crt'),base64.b64decode(payload['brokerCertificates'][role],validate=True),21901,21901)
        put(BROKER/(role+'-signing-public.pem'),read(root/'material'/(role+'-broker-signing-public.pem')),21901,21901)
    replace(BROKER/'config.json',read(root/'configs/broker.json'),plan['inputSHA256']['broker'],root/'broker-config.before.json',21901,21901)
    run(['runuser','-u','jobman-dashboard-log','--',plan['releaseRoot']+'/bin/jobman-log-broker','--mode','check-config','--config',str(BROKER/'config.json')])
    replace(Path('/etc/systemd/system/jobman-dashboard-lab-broker.service'),read(root/'units/jobman-dashboard-lab-broker.service'),payload['preflight']['control01']['unitSHA256'],root/'broker-unit.before.service',0,0,0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','restart','jobman-dashboard-lab-control'],timeout=30);run(['systemctl','restart','jobman-dashboard-lab-broker'],timeout=30)
    active('jobman-dashboard-lab-control','jobman-dashboard-lab-broker')
    put(root/'source-activated.json',encoded({'revision':plan['configurationRevision']}))
    return {'sourceRegistrations':4,'brokerCallers':3,'sourceInstanceId':plan['sourceInstanceId']}


def prepare_runtime_directories():
    # Standalone check-config resolves the socket parent before systemd has had
    # an opportunity to create RuntimeDirectory. Match the unit's exact shape.
    for role,uid in [('api',21904),('worker',21905)]:
        account=pwd.getpwnam('jobman-dashboard-'+role)
        need(account.pw_uid==uid and account.pw_gid==uid,'Split runtime identity differs')
        directory(Path('/run/jobman-dashboard-'+role+'-lab'),uid,uid,0o700)


def activate(payload,rollback=False):
    plan,root=common(payload,True);stopped()
    assert_stopped_held(dict(payload,schema=18))
    if rollback:
        target=root/'rollback-config.json';put(target,read(root/'configs/rollback.json'),21903,21903)
        # The legacy service cannot traverse a root-only receipt directory. Place
        # only its approved fallback config beside its preserved credentials.
        path=APP/'split-rollback.json';put(path,read(target),21903,21903)
        old=read(root/'legacy-unit.service').decode()
        old=old.replace('/usr/local/libexec/jobman-dashboard-lab/jobman-dashboard',plan['releaseRoot']+'/bin/jobman-dashboard')
        old=old.replace(str(APP/'config.json'),str(path))
        unit=Path('/etc/systemd/system/jobman-dashboard-lab-app.service')
        replace(unit,old.encode(),payload['preflight']['storage01']['unitSHA256'],root/'legacy-unit.before-rollback.service',0,0,0o644)
        run(['systemctl','daemon-reload']);run(['systemctl','start','jobman-dashboard-lab-app'],timeout=30)
        return {'rollbackStarted':True,'configurationRevision':plan['rollback']['configurationRevision']}
    prepare_runtime_directories()
    for role in ('api','worker'):
        config='/etc/jobman-dashboard-'+role+'-lab/config.json'
        run(['runuser','-u','jobman-dashboard-'+role,'--',plan['releaseRoot']+'/bin/jobman-dashboard','--mode','check-config','--check-mode',role,'--config',config])
        put(Path('/etc/systemd/system/jobman-dashboard-lab-'+role+'.service'),read(root/'units'/('jobman-dashboard-lab-'+role+'.service')),mode=0o644)
    run(['systemctl','daemon-reload'])
    for role in ('api','worker'):run(['systemctl','start','jobman-dashboard-lab-'+role],timeout=30)
    active('jobman-dashboard-lab-api','jobman-dashboard-lab-worker')
    put(root/'split-started.json',encoded({'revision':plan['revision'],'held':True}))
    return {'splitStarted':True,'held':True}


def verify(payload):
    plan,root=common(payload)
    if payload['host']=='storage01':
        active('jobman-dashboard-lab-api','jobman-dashboard-lab-worker')
        need(subprocess.run(['systemctl','is-active','--quiet','jobman-dashboard-lab-app'],capture_output=True).returncode==3,'Legacy service still active')
        for role in ('api','worker'):
            socket='/run/jobman-dashboard-'+role+'-lab/observe.sock'
            need(stat.S_ISSOCK(Path(socket).lstat().st_mode),'Private observation socket unavailable')
            run(['runuser','-u','jobman-dashboard-'+role,'--','curl','--silent','--fail','--max-time','5','--unix-socket',socket,'http://localhost/livez'])
        for role,path in [('worker','/etc/jobman-dashboard-api-lab/encryption-key'),('worker','/etc/jobman-dashboard-api-lab/token-0.key'),
                          ('api','/etc/jobman-dashboard-worker-lab/control-client.key')]:
            denied=subprocess.run(['runuser','-u','jobman-dashboard-'+role,'--','test','-r',path],capture_output=True)
            need(denied.returncode==1,'Cross-process private material is readable')
        denied=subprocess.run(['runuser','-u','jobman-dashboard-api','--','test','-w',plan['reportRootAfter']],capture_output=True)
        need(denied.returncode==1,'API can write shared report root')
        raw=run([plan['releaseRoot']+'/bin/jobman-dashboard','status','--operator-config','/etc/jobman-dashboard-operator-lab/config.json'])
        need(len(raw)<1<<20,'Operator snapshot bound')
        return {'apiWorkerActive':True,'privateObservationReachable':True,'operatorStatusAvailable':True}
    if payload['host']=='control01':
        active('jobman-dashboard-lab-control','jobman-dashboard-lab-directory','jobman-dashboard-lab-broker','jobman-control')
        need(original_processes()==payload['preflight']['control01']['preservedProcessStarts'],'An original Control/Keycloak/directory process was restarted')
        socket='/run/jobman-dashboard-broker-lab/observe.sock'
        run(['runuser','-u','jobman-dashboard-log','--','curl','--silent','--fail','--max-time','5','--unix-socket',socket,'http://localhost/livez'])
        return {'sourceAndBrokerActive':True,'privateObservationReachable':True}
    check_schema(18);need(sql('SELECT held FROM dashboard_notification_delivery_control WHERE singleton')=='t','Persisted hold was released')
    passwords=json.loads(read(root/'material/database-passwords.json'))
    for role in ROLES:
        # Secret travels only on stdin. psql diagnostics are never emitted.
        shell="IFS= read -r PGPASSWORD; export PGPASSWORD; exec env PGSSLMODE=verify-full PGSSLROOTCERT=/var/lib/postgresql/data/dashboard-tls/ca.crt PGCONNECT_TIMEOUT=5 psql -X -At -v ON_ERROR_STOP=1 -v VERBOSITY=sqlstate -h 127.0.0.1 -U jobman_dashboard_"+role+" -d jobman_dashboard"
        args=['podman','exec','-i','jobman-postgres','sh','-c',shell]
        positive="SELECT current_user; SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid(); SELECT count(*) FROM dashboard_schema_migrations;"
        answer=run(args,(passwords[role]+'\n'+positive+'\n').encode()).decode().strip()
        need(answer=='jobman_dashboard_'+role+'\nt\n18','Actual runtime login/schema/TLS check failed')
        denied=['UPDATE dashboard_accounts SET directory_id=directory_id WHERE false;',
                'UPDATE dashboard_notification_delivery_control SET held=false WHERE false;']
        if role=='worker':denied+=['UPDATE dashboard_preferences SET timezone=timezone WHERE false;',
                                  'UPDATE dashboard_identity_aliases SET subject=subject WHERE false;',
                                  'SELECT encrypted_refresh_token FROM dashboard_sessions LIMIT 0;']
        if role=='operator':denied+=['SELECT subject FROM dashboard_report_tasks LIMIT 0;']
        for query in denied:
            result=subprocess.run(args,input=(passwords[role]+'\nBEGIN; '+query+' ROLLBACK;\n').encode(),capture_output=True,timeout=10)
            need(result.returncode!=0 and b'42501' in result.stderr,'Protected database operation was not denied')
    return {'schema':18,'held':True,'actualRestrictedLogins':list(ROLES)}


def main():
    data=sys.stdin.buffer.read(512<<20)
    need(len(data)<512<<20,'Private phase input exceeds bound')
    payload=json.loads(data);action=payload['action']
    actions={'snapshot':snapshot,'stage':stage_files,'source-certificates':source_certificates,'database-provision':provision_database,
             'identities':identities,'material':install_material,'stop-hold':stop_and_hold,'database-backup':database_backup,
             'objects-keys':objects_and_keys,'migrate':migrate,'grants':apply_grants,'convert':convert_objects,
             'source-activate':source_activate,'activate':activate,'verify':verify,
             'rollback-convert':lambda p:convert_objects(p,True),'rollback-start':lambda p:activate(p,True)}
    actions['rollback-stop-hold']=lambda p:stop_and_hold(p,True)
    actions['assert-stopped-held']=assert_stopped_held
    actions['schema-state']=schema_state
    actions['database-capacity']=recheck_database_capacity
    actions['recover-state']=recover_state
    need(action in actions,'Unknown phase')
    print(json.dumps(actions[action](payload),sort_keys=True))


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Split phase failed. Keep stopped services and retained private receipts; no automatic rollback or hold release was attempted.') from None
