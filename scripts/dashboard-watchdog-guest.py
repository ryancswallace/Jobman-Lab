#!/usr/bin/env python3
"""Timer-only primary restart acceptance. No clone, backup, restore, or SQL writes."""
import base64
import contextlib
import datetime as dt
import fcntl
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time

# p, f, g, r and SOURCES are injected only by the hash-bound loader.

def guard(host):
    p.need(os.geteuid()==0 and sys.platform=='linux','linux_root_required')
    p.need(host in p.HOSTS and socket.gethostname().split('.')[0]==host,'fixed_host_required')

def report_objects():
    root=Path('/var/lib/jobman-dashboard-reports-lab');s=root.lstat()
    p.need(root.resolve()==root and stat.S_ISDIR(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(21905,21906,0o750),'report_root')
    entries=[];total=0
    with os.scandir(root) as names:
        for entry in names:
            p.need(len(entries)<10000 and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json',entry.name),'report_entry')
            item=r.hash_file(root/entry.name,8<<20,(21905,21906),0o640)
            total+=item['bytes'];p.need(total<=256<<20,'report_byte_bound')
            entries.append({'name':entry.name,**item})
    p.need(root.lstat().st_ino==s.st_ino and root.lstat().st_dev==s.st_dev,'report_root_changed')
    return {'count':len(entries),'bytes':total,'sha256':p.sha(p.encoded(sorted(entries,key=lambda v:v['name'])))}

def quiet_database():
    query="""BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms';
SELECT NOT EXISTS(SELECT FROM dashboard_report_tasks WHERE state IN('queued','collecting','analyzing'))
 AND NOT EXISTS(SELECT FROM dashboard_notification_evaluations WHERE state='pending')
 AND NOT EXISTS(SELECT FROM dashboard_notification_fanout WHERE NOT done)
 AND NOT EXISTS(SELECT FROM dashboard_notification_deliveries WHERE state='pending')
 AND NOT EXISTS(SELECT FROM dashboard_notification_rules WHERE enabled AND deleted_at IS NULL);
COMMIT;"""
    p.need(r.sql(query)=='t','pending_work');return True

def postgres_process(value):
    # Podman's Go-template formatter may print Go Time.String rather than
    # RFC3339. Validate either exact format; retain every original byte for
    # the before/after process identity (including nanoseconds and zone).
    common=r'([1-9][0-9]{0,9}) ([0-9]{4}-[0-9]{2}-[0-9]{2})'
    clock=r'([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?'
    iso=re.fullmatch(common+'T'+clock+r'(Z|[+-][0-9]{2}:[0-9]{2})',value)
    go=re.fullmatch(common+' '+clock+r' ([+-][0-9]{4}) ([A-Za-z]{1,10})',value)
    match=iso or go
    p.need(match is not None and int(match[1])<=2147483647,'postgres_process')
    offset=match[5]
    if go:offset=offset[:3]+':'+offset[3:]
    if offset=='Z':offset='+00:00'
    p.need(int(offset[1:3])<=23 and int(offset[4:6])<=59,'postgres_process')
    fraction=('.'+match[4][:6].ljust(6,'0')) if match[4] else ''
    try:parsed=dt.datetime.fromisoformat(match[2]+'T'+match[3]+fraction+offset)
    except ValueError:raise p.Failure('postgres_process') from None
    p.need(parsed.utcoffset() is not None,'postgres_process')
    return value

def snapshot(host,candidate):
    guard(host)
    if host=='pg01':
        process=g.run(['podman','inspect','--format','{{.State.Pid}} {{.State.StartedAt}}','jobman-postgres'],'postgres_process',maximum=1024).decode().strip()
        postgres_process(process)
        return {'host':host,'observedAt':int(time.time()),'database':g.database(),'retained':r.retained_identities('jobman_dashboard'),
                'quiet':quiet_database(),'postgresProcess':process,'bootId':r.boot_id()}
    result={'host':host,'observedAt':int(time.time()),'preserved':g.host_snapshot(host,candidate['revision'])}
    if host=='storage01':
        binary=r.candidate({'candidate':candidate});pins={'configs':{},'processes':{}}
        for role,(root,uid) in r.PRIMARY.items():
            raw,_=r.read(Path(root)/'config.json',256<<10,owner=(uid,uid),mode=0o600)
            config=p.decode(raw)
            p.need(config.get('reports',{}).get('objectRoot')=='/var/lib/jobman-dashboard-reports-lab','report_config')
            pins['configs'][role]=p.sha(raw);pins['processes'][role]=r.process(role,binary)
        r.primary_pins({'candidate':candidate,'primaryPins':pins})
        result.update(primaryPins=pins,objects=report_objects())
    return result

def compare(plan,host,current,restarts=None):
    before=plan['snapshot'][host]
    if host=='pg01':
        f.database_preserved(before['database'],current['database'])
        p.need({k:v for k,v in before.items() if k not in ('database','observedAt')}=={k:v for k,v in current.items() if k not in ('database','observedAt')},'database_retained_changed')
    else:
        p.preserved_host(before['preserved'],current['preserved'],restarts)
        if host=='storage01':
            p.need(current['objects']==before['objects'] and current['primaryPins']['configs']==before['primaryPins']['configs'],'storage_retained_changed')
            expected=restarts if restarts is not None else before['primaryPins']['processes']
            p.need(current['primaryPins']['processes']==expected,'primary_process_changed')

def private_dir(path):
    info=path.lstat()
    p.need(path.resolve()==path and stat.S_ISDIR(info.st_mode) and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(0,0,0o700),'operation_directory')

def code():return p.loader(SOURCES)

def payload(plan):
    return {'operationId':plan['operationId'],'planSHA256':p.sha(p.encoded(plan)),'plan':plan,'apply':True,
            'candidate':plan['candidate'],'primaryPins':plan['snapshot']['storage01']['primaryPins'],
            'implementationSHA256':p.sha(code()),'phase':'begin','guestCode':base64.b64encode(code()).decode()}

def adapter(value):
    # This is the ONLY substituted symbol in the original restore module.
    # No clone-shaped plan, fake dump or completed-backup receipt is accepted.
    plan=p.validate(value['plan']);expected=payload(plan)
    if value.get('phase')=='watchdog':expected['phase']='watchdog';expected.pop('guestCode')
    p.need(value==expected,'original_payload_changed')
    root=Path(p.BASE)/plan['operationId'];private_dir(Path(p.BASE));private_dir(root)
    p.need(r.read(root/'plan.json',2<<20,owner=(0,0),mode=0o600)[0]==p.encoded(plan),'staged_plan_changed')
    p.need(r.read(root/'intent.json',owner=(0,0),mode=0o600)[0]==p.encoded(intent(plan)),'staged_intent_changed')
    return root

def intent(plan):return {'scenario':p.SCENARIO,'operationId':plan['operationId'],'planSHA256':p.sha(p.encoded(plan)),
                         'timerCodeSHA256':p.sha(code()),'originalRestoreSHA256':plan['implementationSHA256']['dashboard-restore-guest.py']}

@contextlib.contextmanager
def operation_lock():
    r.directory(p.BASE)
    path=Path(p.BASE)/'.operation.lock'
    try:fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600);os.fchmod(fd,0o600)
    except FileExistsError:fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);p.need(stat.S_ISREG(info.st_mode) and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_nlink)==(0,0,0o600,1),'lock_identity')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)

def no_other_timers():
    raw=g.run(['systemctl','list-units','--state=activating,active','--no-legend','--no-pager','--plain',
               'jobman-dash-restore-watch-*.timer','jobman-dash-restore-watch-*.service',
               'jobman-dashboard-fault-*.timer','jobman-dashboard-fault-*.service'],'concurrent_timer',maximum=32768)
    p.need(raw.strip()==b'','another_timer_active')



def aborted_operation(root):
    """Validate a reviewed staged-only retirement; never infer acceptance."""
    private_dir(root)
    p.need(p.HEX.fullmatch(root.name) is not None,'retirement_operation')
    names={entry.name for entry in root.iterdir()}
    p.need(names=={'plan.json','intent.json','staged.json','begin.pending.json','aborted.json'},'retirement_artifacts')
    raw={name:r.read(root/name,2<<20,owner=(0,0),mode=0o600)[0] for name in names}
    values={name:p.decode(data) for name,data in raw.items()}
    old=p.validate(values['plan.json']);operation=old['operationId']
    p.need(operation==root.name and all(raw[name]==p.encoded(value) for name,value in values.items()),'retirement_original_changed')
    marker=values['intent.json']
    p.need(set(marker)=={'scenario','operationId','planSHA256','timerCodeSHA256','originalRestoreSHA256'} and
           marker['scenario']==p.SCENARIO and marker['operationId']==operation and
           marker['planSHA256']==p.sha(raw['plan.json']) and p.HEX.fullmatch(marker['timerCodeSHA256']) and
           marker['originalRestoreSHA256']==old['implementationSHA256']['dashboard-restore-guest.py'],'retirement_intent')
    p.need(values['staged.json']=={'staged':True,'operationId':operation} and values['staged.json']['staged'] is True,'retirement_stage')
    tombstone=values['begin.pending.json']
    p.need(set(tombstone)=={'operationId','planSHA256','outcome','accepted','failureEvidenceSHA256','retirementProofSHA256'} and
           tombstone['operationId']==operation and tombstone['planSHA256']==p.sha(raw['plan.json']) and
           tombstone['outcome']=='aborted_before_arm' and tombstone['accepted'] is False and
           p.HEX.fullmatch(tombstone['failureEvidenceSHA256']) and p.HEX.fullmatch(tombstone['retirementProofSHA256']),'retirement_tombstone')
    expected={'format':1,'operationId':operation,'outcome':'aborted_before_arm','accepted':False,
              'originalSHA256':{name:p.sha(raw[name]) for name in ('plan.json','intent.json','staged.json')},
              'beginTombstoneSHA256':p.sha(raw['begin.pending.json']),
              'failureEvidenceSHA256':tombstone['failureEvidenceSHA256'],
              'retirementProofSHA256':tombstone['retirementProofSHA256']}
    p.need(values['aborted.json']==expected and type(values['aborted.json'].get('format')) is int and
           values['aborted.json'].get('accepted') is False,'retirement_receipt')
    return expected


def prior_operation_closed(root):
    private_dir(root)
    if (root/'aborted.json').exists():
        return aborted_operation(root)
    p.need((root/'accepted.json').exists(),'another_watchdog_pending')
    return None


def stage(plan):
    with operation_lock():
        no_other_timers()
        p.need(0<=time.time()-min(v['observedAt'] for v in plan['snapshot'].values())<=900,'plan_expired')
        compare(plan,'storage01',snapshot('storage01',plan['candidate']))
        base=Path(p.BASE);entries=list(base.iterdir());p.need(len(entries)<=33,'operation_bound')
        for entry in entries:
            if entry.name=='.operation.lock':continue
            prior_operation_closed(entry)
        root=base/plan['operationId'];p.need(not root.exists(),'operation_exists')
        r.directory(root);r.put(root/'plan.json',p.encoded(plan));r.put(root/'intent.json',p.encoded(intent(plan)))
        r.put(root/'staged.json',p.encoded({'staged':True,'operationId':plan['operationId']}))
        return {'staged':True,'operationId':plan['operationId']}

def begin(plan):
    with operation_lock():
        no_other_timers()
        value=payload(plan);root=adapter(value)
        p.need(0<=time.time()-min(v['observedAt'] for v in plan['snapshot'].values())<=900,'plan_expired')
        p.need(not (root/'begin.pending.json').exists(),'uncertain_begin_no_retry')
        compare(plan,'storage01',snapshot('storage01',plan['candidate']))
        r.put(root/'begin.pending.json',p.encoded({'operationId':plan['operationId'],'planSHA256':p.sha(p.encoded(plan))}))
        # Original functions arm BEFORE stopping; failure never calls restart.
        r.arm_backup(value)
        stopped=r.stop_primary(value)
        return {'operationId':plan['operationId'],'stopped':stopped['stopped'],'watchdogSeconds':150,'hostRestartAllowed':False}

def status(plan):
    root=adapter(payload(plan));result={'operationId':plan['operationId'],'armed':False,'stopped':False,'fired':False,'restarted':False}
    for file,key in (('armed.json','armed'),('stopped.json','stopped'),('fired.json','fired')):
        if (root/file).exists():
            value=p.decode(r.read(root/file,owner=(0,0),mode=0o600)[0]);p.need(value['operationId']==plan['operationId'],'receipt_operation')
            result[key]=True
            if file=='armed.json':
                p.need(value['bootId']==r.boot_id(),'boot_changed');result['elapsedSeconds']=time.monotonic()-value['armedMonotonic']
    if (root/'disarmed.json').exists():
        receipt=p.restarted(plan,p.decode(r.read(root/'disarmed.json',owner=(0,0),mode=0o600)[0]))
        p.need(result['armed'] and result['stopped'] and result['fired'],'watchdog_receipts_missing')
        p.need(r.primary_pins(payload(plan))==receipt['states'],'restart_observation')
        result.update(restarted=True,receipt=receipt)
    return result

def observe(plan):
    value=status(plan);p.need(value['restarted'],'watchdog_incomplete')
    compare(plan,'storage01',snapshot('storage01',plan['candidate']),value['receipt']['states'])
    observations={}
    for role in ('api','worker'):
        raw=g.run(['runuser','-u','jobman-dashboard-'+role,'--','curl','--silent','--fail','--max-time','3','--unix-socket',
                   '/run/jobman-dashboard-'+role+'-lab/observe.sock','http://localhost/readyz'],'readiness',timeout=4,maximum=32768)
        body=p.decode(raw);p.need(set(body)=={'state','role','checkedAt','scope'} and body['state']=='ready' and body['role']==role and body['scope']=='local_required_dependencies','readiness_shape');observations[role]=body
    return {'operationId':plan['operationId'],'restarted':True,'receipt':value['receipt'],'ready':observations}

def accept(plan):
    root=adapter(payload(plan));value=observe(plan)
    r.put(root/'accepted.json',p.encoded({'operationId':plan['operationId'],'timerObserved':True}))
    return value

def timer_main(path):
    guard('storage01')
    requested=Path(path);raw,_=r.read(requested,2<<20,owner=(0,0),mode=0o600);value=p.decode(raw)
    plan=p.validate(value['plan']);root=adapter(value)
    p.need(requested==root/'watchdog.json' and Path(sys.argv[0])==root/'guest.py','timer_path')
    p.need(r.read(root/'guest.py',1<<20,owner=(0,0),mode=0o600)[0]==code(),'timer_code_changed')
    unit=r.watchdog_name(value)+'.service'
    groups=Path('/proc/self/cgroup').read_text().splitlines()
    p.need(os.environ.get('INVOCATION_ID') and any(line.split(':',2)[-1].endswith('/'+unit) for line in groups),'timer_service_required')
    r.execution_root=adapter
    # Only the actual systemd timer service may call this restart function.
    return r.restart_primary(value,fired=True)

def execute(value):
    host=value['host'];guard(host);phase=value['phase']
    p.need(phase in ('snapshot','stage','begin','status','observe','verify','accept'),'phase_denied')
    if phase=='snapshot':return snapshot(host,value['candidate'])
    plan=p.validate(value['plan'])
    p.need(all(p.sha(text.encode())==plan['implementationSHA256'][name] for name,text in SOURCES.items()),'implementation_changed')
    if phase in ('stage','begin','accept'):p.need(host=='storage01' and value.get('apply') is True,'explicit_apply_required')
    if phase in ('status','observe'):p.need(host=='storage01','observation_host')
    r.execution_root=adapter
    if phase=='stage':return stage(plan)
    if phase=='begin':return begin(plan)
    if phase=='status':return status(plan)
    if phase=='observe':return observe(plan)
    if phase=='accept':return accept(plan)
    p.need(host in ('control01','pg01'),'verification_host')
    compare(plan,host,snapshot(host,plan['candidate']));return {'host':host,'preserved':True}
