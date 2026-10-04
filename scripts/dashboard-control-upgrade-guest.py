#!/usr/bin/env python3
"""Fixed-host, binary-only Control phases; no source configuration or SQL writes."""
import base64
import contextlib
import copy
import fcntl
import importlib.util
import os
from pathlib import Path
import socket
import stat
import time

HERE=Path(__file__).resolve().parent
if 'p' not in globals():
    spec=importlib.util.spec_from_file_location('upgrade_plan',HERE/'dashboard-control-upgrade-plan.py')
    p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
if 'f' not in globals():
    spec=importlib.util.spec_from_file_location('fault_guest',HERE/'dashboard-dependency-fault-guest.py')
    f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
BASE=Path('/var/lib/jobman-dashboard-control-upgrades')
HELPER=Path('/usr/local/libexec/jobman-dashboard-scale/367006818e72315b01860f56f971004e17c24886/jobman-control-lab-helper')
HELPER_SHA='6f511e91434dac2499d464f0b424607fe0b099b966148c992499e5371a333f65'


@contextlib.contextmanager
def locked():
    f.directory(BASE,create=True)
    try:fd=os.open(BASE/'.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600);os.fchmod(fd,0o600)
    except FileExistsError:fd=os.open(BASE/'.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        value=os.fstat(fd);p.need(stat.S_ISREG(value.st_mode) and value.st_nlink==1 and value.st_uid==value.st_gid==0 and stat.S_IMODE(value.st_mode)==0o600,'operation_lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)


def inventory_file(path,uid,mode):
    # Operational lock files may be empty. Preserve them too, with the same
    # no-follow, private owner/mode, finite-size and stable-inode proof.
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        p.need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==uid and before.st_nlink==1 and
               stat.S_IMODE(before.st_mode)==mode and 0<=before.st_size<=1<<20,'inventory_file_identity')
        raw=stream.read((1<<20)+1);after=os.fstat(stream.fileno());named=path.lstat()
        p.need(len(raw)==before.st_size and
               (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
               (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and
               (before.st_dev,before.st_ino)==(named.st_dev,named.st_ino),'inventory_file_changed')
    return p.sha(raw)


def source_inventory():
    result={}
    for root,uid in f.SOURCE_FILES.items():
        f.source_preflight(root,uid)
        entries=list(Path(root).iterdir());p.need(len(entries)<=128,'source_file_count')
        for path in entries:
            info=path.lstat()
            p.need(stat.S_ISREG(info.st_mode) and info.st_uid in (0,uid) and info.st_gid==info.st_uid and
                   stat.S_IMODE(info.st_mode) in (0o600,0o644),'source_file_boundary')
            result[str(path)]={'uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),
                              'sha256':inventory_file(path,info.st_uid,stat.S_IMODE(info.st_mode))}
    p.need(p.sha(f.read(HELPER,0,0o755,64<<20))==HELPER_SHA,'existing_helper_changed')
    result[str(HELPER)]={'uid':0,'mode':0o755,'sha256':HELPER_SHA}
    return result


def validate_environment(profile):
    spec=p.PROFILES[profile];raw=f.read(spec['root']+'/control.env',spec['uid'],maximum=65536)
    values={}
    for line in raw.decode().splitlines():
        key,separator,value=line.partition('=')
        p.need(separator=='=' and p.re.fullmatch('[A-Z][A-Z0-9_]*',key) and key not in values,'source_environment_shape')
        values[key]=p.decode(value);p.need(isinstance(values[key],str),'source_environment_type')
    p.need(values.get('JOBMAN_CONTROL_MIGRATE_ON_START')=='false' and values.get('JOBMAN_CONTROL_DIRECTORY_MODE')=='enforce' and
           values.get('JOBMAN_CONTROL_DIRECTORY_CONFIG_FILE')==spec['root']+'/directory.json','source_no_migration')


def source_host(profile,revision):
    validate_environment(profile);spec=p.PROFILES[profile]
    properties=f.properties(spec['unit'])
    p.need(properties['KillMode']=='control-group' and properties['TimeoutStopUSec'] in ('1min 30s','90s'),'source_stop_policy')
    return {'profile':profile,'baseline':f.host_snapshot('control01',revision),'inventory':source_inventory(),
            'unit':base64.b64encode(f.read('/etc/systemd/system/'+spec['unit']+'.service',0,0o644,32768)).decode()}


SOURCE_SQL="""BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='15000ms'; SET LOCAL lock_timeout='500ms'; SET LOCAL TIME ZONE 'UTC';
WITH principal_rows AS (SELECT id,issuer,subject FROM principals ORDER BY id LIMIT 1001),
 account_rows AS (SELECT directory_id,principal_id,enabled,source_id FROM directory_accounts ORDER BY directory_id LIMIT 1001),
 alias_rows AS (SELECT issuer,subject,directory_id,principal_id,provenance,source_id FROM principal_aliases ORDER BY issuer,subject LIMIT 1001),
 binding_rows AS (SELECT group_id,namespace_id,role,enabled,revision FROM directory_role_bindings ORDER BY group_id LIMIT 1001),
 grant_rows AS (SELECT id,namespace_id,principal_id,role,provenance,source_key,revoked_at IS NOT NULL AS revoked FROM membership_grants ORDER BY id LIMIT 20001),
 directory_rows AS (SELECT source_id,revision,configuration_digest,mapping FROM directory_sources ORDER BY source_id LIMIT 1001),
 delegation_rows AS (SELECT service_id,key_id,audience,public_key,certificate_thumbprints,namespace_ids,operations,enabled FROM delegation_service_keys ORDER BY service_id,key_id LIMIT 1001)
SELECT json_build_object(
 'database',current_database(),'oid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'instance',(SELECT id::text FROM control_instance),'epoch',(SELECT restore_epoch::text FROM service_recovery_state WHERE singleton),
 'feed',(SELECT json_build_object('head',head_position::text,'retired',retired_through::text,'retention',retention_seconds::text) FROM monitoring_feed_state WHERE singleton),
 'identityCounts',json_build_object('principals',(SELECT count(*) FROM principal_rows),'accounts',(SELECT count(*) FROM account_rows),
   'aliases',(SELECT count(*) FROM alias_rows),'bindings',(SELECT count(*) FROM binding_rows),'grants',(SELECT count(*) FROM grant_rows),
   'sources',(SELECT count(*) FROM directory_rows),'delegationKeys',(SELECT count(*) FROM delegation_rows)),
 'identitySHA256',encode(sha256(convert_to(json_build_object(
   'principals',(SELECT json_agg(row_to_json(x) ORDER BY id) FROM principal_rows x),
   'accounts',(SELECT json_agg(row_to_json(x) ORDER BY directory_id) FROM account_rows x),
   'aliases',(SELECT json_agg(row_to_json(x) ORDER BY issuer,subject) FROM alias_rows x),
   'bindings',(SELECT json_agg(row_to_json(x) ORDER BY group_id) FROM binding_rows x),
   'grants',(SELECT json_agg(row_to_json(x) ORDER BY id) FROM grant_rows x),
   'sources',(SELECT json_agg(row_to_json(x) ORDER BY source_id) FROM directory_rows x),
   'delegationKeys',(SELECT json_agg(row_to_json(x) ORDER BY service_id,key_id) FROM delegation_rows x)
 )::text,'UTF8')),'hex'),
 'ledger',(SELECT json_agg(json_build_object('name',version,'sha256',checksum) ORDER BY version) FROM schema_migrations),
 'namespaces',(SELECT json_build_object('count',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(row_to_json(x)::text,E'\\n' ORDER BY id),''),'UTF8')),'hex')) FROM (SELECT id,name,created_at FROM namespaces ORDER BY id LIMIT 321) x),
 'scale',(SELECT json_agg(row_to_json(x) ORDER BY name) FROM (SELECT n.name,count(*) FILTER(WHERE j.imported) AS imported,count(*) FILTER(WHERE NOT j.imported AND j.phase='accepted') AS accepted,count(*) AS total FROM namespaces n JOIN jobs j ON j.namespace_id=n.id WHERE n.name LIKE 'dashboard-scale-%' GROUP BY n.name ORDER BY n.name LIMIT 11) x),
 'jobs',(SELECT json_build_object('count',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(digest,'' ORDER BY id),''),'UTF8')),'hex')) FROM (SELECT id,encode(sha256(convert_to(json_build_array(id,namespace_id,owner_principal_id,name,labels,placement_target,placement_partition,workload_digest,request_digest,request_document,created_at,imported)::text,'UTF8')),'hex') AS digest FROM jobs ORDER BY id LIMIT 200001) x),
 'runs',(SELECT json_build_object('count',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(row_to_json(x)::text,E'\\n' ORDER BY id),''),'UTF8')),'hex')) FROM (SELECT id,namespace_id,job_id,run_number,created_at FROM runs ORDER BY id LIMIT 10001) x),
 'executions',(SELECT json_build_object('count',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(row_to_json(x)::text,E'\\n' ORDER BY id),''),'UTF8')),'hex')) FROM (SELECT id,namespace_id,run_id,target_id,target_generation_id,agent_id,effective_spec_digest,created_at FROM executions ORDER BY id LIMIT 10001) x),
 'terminalEvents',(SELECT json_build_object('count',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(digest,'' ORDER BY id),''),'UTF8')),'hex')) FROM (SELECT id,encode(sha256(convert_to(json_build_array(id,namespace_id,aggregate_id,payload,created_at)::text,'UTF8')),'hex') AS digest FROM outbox WHERE topic='monitoring.job_terminal.v1' ORDER BY id LIMIT 10001) x));
COMMIT;
"""


def source_database(profile):
    spec=p.PROFILES[profile]
    command=['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-q','-A','-t','-U','jobman_control','-v','ON_ERROR_STOP=1','-d',spec['database']]
    value=p.decode(f.run(command,'source_database_snapshot',data=SOURCE_SQL.encode(),timeout=20,maximum=2<<20))
    return p.source_database(value,profile,value['ledger'])


def databases():
    return {'dashboard':f.database(),'sources':{name:source_database(name) for name in p.PROFILES}}


def check_databases(plan):
    current=databases();p.b.database_preserved(plan['snapshot']['pg01']['dashboard'],current['dashboard'])
    for name,value in current['sources'].items():
        old=plan['snapshot']['pg01']['sources'][name]
        p.need(int(value['feed']['head'])>=int(old['feed']['head']),'source_feed_regressed')
        value['feed']['head']=old['feed']['head']
        p.need(value==old,'source_data_or_schema_changed')
    return {'databasePreserved':True}


def authority(plan,host,applied=False,new=False):
    if host=='pg01':return check_databases(plan)
    if host=='storage01':
        p.host_preserved(plan,host,f.host_snapshot(host,plan['snapshot'][host]['revision']));return
    validate_environment(plan['profile']);current=source_host(plan['profile'],plan['snapshot']['storage01']['revision'])
    p.need(current['inventory']==plan['snapshot']['control01']['inventory'],'source_files_or_helper_changed')
    expected=plan['afterUnit'] if applied else plan['snapshot']['control01']['unit']
    p.need(current['unit']==expected,'selected_unit_changed')
    p.host_preserved(plan,host,current['baseline'],applied,new)
    return current['baseline']['processes'][p.PROFILES[plan['profile']]['unit']]


def marker(root,name,value):
    path=root/(name+'.json');raw=p.encoded(value)
    if path.exists():p.need(f.read(path)==raw,'operation_receipt_changed')
    else:f.put(path,raw)


def open_operation(plan,create=False):
    root=BASE/plan['operationId'];f.directory(root,create=create)
    if create:marker(root,'plan',plan)
    p.need(f.read(root/'plan.json')==p.encoded(plan),'operation_plan_changed')
    return root


def candidate_directory(path,create=False):
    for parent in path.parents:
        info=parent.lstat()
        p.need(parent.resolve()==parent and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not stat.S_IMODE(info.st_mode)&0o022,'candidate_ancestor')
    if create:
        try:path.mkdir(mode=0o755);path.chmod(0o755);f.sync(path.parent)
        except FileExistsError:pass
    info=path.lstat();p.need(path.resolve()==path and stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755,'candidate_directory')


def verify_candidate(plan):
    info=plan['candidate'];binary=Path(info['path']);candidate_directory(binary.parent)
    raw=f.read(binary,0,0o755,64<<20);p.need(p.sha(raw)==info['sha256'] and len(raw)==info['bytes'],'candidate_binary_changed')
    p.need(f.read(binary.parent/'candidate.json')==p.encoded(info),'candidate_metadata_changed')
    result=f.run(['runuser','--user',p.PROFILES[plan['profile']]['user'],'--',str(binary),'--version'],'candidate_version',timeout=5,maximum=1024).decode()
    p.need(p.re.fullmatch(r'jobman-control [A-Za-z0-9._+/-]+ \('+info['revision'][:12]+r'\)\n',result),'candidate_version_identity')


def stage(plan,binary):
    p.need(p.sha(binary)==plan['candidate']['sha256'] and len(binary)==plan['candidate']['bytes'],'stage_binary_hash')
    with locked(),f.bounded(60):
        authority(plan,'control01')
        entries=list(BASE.iterdir());p.need(len(entries)<=65,'guest_history_bound')
        for path in entries:
            if path.name!='.lock':
                f.directory(path)
                if path.name!=plan['operationId']:p.need((path/'verified.json').exists(),'another_source_upgrade_pending')
        root=open_operation(plan,create=True)
        if (root/'stage-intent.json').exists():
            p.need((root/'staged.json').exists(),'uncertain_stage_requires_inspection');verify_candidate(plan)
            return p.decode(f.read(root/'staged.json'))
        marker(root,'stage-intent',{'candidate':plan['candidate'],'planSHA256':p.sha(p.encoded(plan))})
        base=Path(p.BINARY_ROOT);candidate_directory(base,create=True)
        target=Path(plan['candidate']['path'])
        if target.parent.exists():verify_candidate(plan)
        else:
            candidate_directory(target.parent,create=True)
            f.put(target,binary,0o755);f.put(target.parent/'candidate.json',p.encoded(plan['candidate']))
            verify_candidate(plan)
        value={'staged':True,'operationId':plan['operationId'],'candidateSHA256':plan['candidate']['sha256']}
        marker(root,'staged',value);return value


def apply(plan):
    with locked(),f.bounded(45):
        root=open_operation(plan);p.need((root/'staged.json').exists(),'stage_missing')
        p.need(not (root/'apply-intent.json').exists(),'uncertain_apply_requires_observation')
        authority(plan,'control01');verify_candidate(plan)
        unit=Path('/etc/systemd/system/'+p.PROFILES[plan['profile']]['unit']+'.service')
        original=f.read(unit,0,0o644,32768);p.need(p.sha(original)==plan['beforeUnitSHA256'],'unit_compare_exchange')
        f.put(root/'original.service',original)
        marker(root,'apply-intent',{'before':plan['beforeUnitSHA256'],'after':plan['afterUnitSHA256']})
        pending=unit.parent/('.dashboard-source-'+plan['operationId']+'.pending')
        f.put(pending,p.unb64(plan['afterUnit']),0o644)
        p.need(p.sha(f.read(unit,0,0o644,32768))==plan['beforeUnitSHA256'],'unit_compare_exchange')
        os.replace(pending,unit);f.sync(unit.parent)
        f.run(['systemctl','daemon-reload'],'unit_daemon_reload',timeout=10)
        loaded_command(plan)
        authority(plan,'control01',applied=True)
        value={'applied':True,'operationId':plan['operationId'],'unitSHA256':plan['afterUnitSHA256']}
        marker(root,'applied',value);return value


def wait_ready(plan):
    # A single restart may take the existing90s stop window. Every observation
    # and positive identity check shares the remaining bounded deadline.
    with f.bounded(120):
        while True:
            f.remaining(1)
            try:
                process=authority(plan,'control01',applied=True,new=True);f.remaining(1);return process
            except (ValueError,OSError):pass
            time.sleep(f.remaining(.25))


def restart(plan):
    with locked():
        root=open_operation(plan);p.need((root/'applied.json').exists(),'apply_missing')
        p.need(not (root/'restart-intent.json').exists(),'uncertain_restart_requires_observation')
        with f.bounded(40):authority(plan,'control01',applied=True);verify_candidate(plan);loaded_command(plan)
        marker(root,'restart-intent',{'process':plan['snapshot']['control01']['baseline']['processes'][p.PROFILES[plan['profile']]['unit']]})
        f.run(['systemctl','restart','--no-block',p.PROFILES[plan['profile']]['unit']],'source_restart_request',timeout=5)
        process=wait_ready(plan)
        value={'restarted':True,'operationId':plan['operationId'],'process':process}
        marker(root,'restarted',value);return value


def observe(plan):
    # No daemon-reload/start/restart is allowed on the recovery path. Missing
    # progress leaves explicit pending evidence for separate operator review.
    with locked(),f.bounded(40):
        root=open_operation(plan);verify_candidate(plan)
        if not (root/'apply-intent.json').exists():
            p.need((root/'stage-intent.json').exists() and (root/'staged.json').exists(),'stage_not_completed')
            authority(plan,'control01');f.remaining(1)
            value={'staged':True,'operationId':plan['operationId'],'candidateSHA256':plan['candidate']['sha256']}
            p.need(p.decode(f.read(root/'staged.json'))==value,'stage_receipt_changed')
            return value
        loaded_command(plan)
        if not (root/'restart-intent.json').exists():
            authority(plan,'control01',applied=True);f.remaining(1)
            value={'applied':True,'operationId':plan['operationId'],'unitSHA256':plan['afterUnitSHA256']}
            marker(root,'applied',value);return value
        process=authority(plan,'control01',applied=True,new=True);f.remaining(1)
        value={'restarted':True,'operationId':plan['operationId'],'process':process}
        marker(root,'restarted',value);return value


def loaded_command(plan):
    unit=p.PROFILES[plan['profile']]['unit']
    raw=f.run(['systemctl','show',unit,'--property=NeedDaemonReload','--property=ExecStart'],'loaded_unit',maximum=8192).decode()
    rows=dict(line.split('=',1) for line in raw.splitlines())
    p.need(set(rows)=={'NeedDaemonReload','ExecStart'} and rows['NeedDaemonReload']=='no','daemon_reload_unconfirmed')
    expected=plan['candidate']['path']
    p.need(p.re.findall(r'(?:^|[ ;])path=([^ ;]+)',rows['ExecStart'])==[expected] and
           p.re.findall(r'argv\[\]=([^;]+) ;',rows['ExecStart'])==[expected],'loaded_source_command')


def execute(value):
    phase=value['phase'];host=value['host']
    p.need(host in ('pg01','storage01','control01') and socket.gethostname().split('.')[0]==host and os.geteuid()==0,'guest_identity')
    p.need(phase in ('snapshot','authority','stage','apply','restart','observe','verify'),'guest_phase')
    if phase=='snapshot':
        with f.bounded(60):
            if host=='pg01':return databases()
            if host=='storage01':return f.host_snapshot(host,value['dashboardRevision'])
            return source_host(value['profile'],value['dashboardRevision'])
    plan=value['plan'];p.validate(plan);p.need(p.sha(p.encoded(plan))==value['planSHA256'],'reviewed_plan_hash')
    if phase=='authority':
        with f.bounded(60):authority(plan,host,value.get('applied',False),value.get('new',False))
        return {'preserved':True}
    p.need(host=='control01','source_mutation_host')
    if phase in ('stage','apply','restart'):
        p.need(value.get('apply') is True and 0<=time.time()-plan['createdAt']<=3600,'explicit_fresh_apply_required')
    if phase=='stage':return stage(plan,base64.b64decode(value['binary'],validate=True))
    if phase=='apply':return apply(plan)
    if phase=='restart':return restart(plan)
    if phase=='observe':return observe(plan)
    with locked(),f.bounded(40):
        root=open_operation(plan);p.need((root/'restarted.json').exists(),'restart_proof_missing')
        authority(plan,'control01',applied=True,new=True)
        result={'verified':True,'operationId':plan['operationId'],'candidateSHA256':plan['candidate']['sha256']}
        marker(root,'verified',result);return result
