#!/usr/bin/env python3
"""Supplemental clone-only hold-flag CAS; supplied hash-pinned restore primitives."""
import base64
import copy
import fcntl
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
from datetime import datetime,timezone
from urllib.parse import urlparse,parse_qs

g=restore
ROLES=('api','worker','recovery')

def instant(value):
 g.need(isinstance(value,str) and len(value)<=40,'Bounded explicit timezone floor required')
 parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
 g.need(parsed.tzinfo is not None,'Explicit timezone floor required')
 return parsed.astimezone(timezone.utc)

def transition(raw,role):
 value=g.decode(raw);expected=copy.deepcopy(value)
 if role=='worker':g.need(expected['deliveryHold'] is True,'Worker startup hold changed');expected['deliveryHold']=False
 else:g.need(expected['events']['deliveryHold'] is True,'API/recovery startup hold changed');expected['events']['deliveryHold']=False
 return g.encoded(expected)

def location(role):
 g.need(role in ROLES,'Fixed clone config role required')
 return (g.clone_root('operator')/'recovery.json',0) if role=='recovery' else (g.clone_root(role)/'config.json',g.CLONE[role][1])

def retain(path,raw):
 if path.exists():g.need(g.read(path,owner=(0,0),mode=0o600)[0]==raw,'Immutable release receipt changed')
 else:g.put(path,raw)

def policy(role):
 unit='jobman-dashboard-restore-'+role+'-lab.service'
 pairs=[line.split('=',1) for line in g.run(['systemctl','show',unit,'--property=KillMode','--property=TimeoutStopUSec','--property=DropInPaths'],timeout=5,maximum=2048).decode().splitlines()]
 g.need(len(pairs)==3 and all(len(v)==2 for v in pairs),'Clone stop policy response invalid');values=dict(pairs)
 g.need(values=={'KillMode':'control-group','TimeoutStopUSec':'30s','DropInPaths':''},'Clone effective stop policy differs')
 return unit

def process(role,binary,stopped=False):
 unit=policy(role)
 g.need(g.read('/etc/systemd/system/'+unit,owner=(0,0),mode=0o644)[0]==g.clone_unit(role,binary),'Clone unit changed')
 active=g.run(['systemctl','show',unit,'--property=ActiveState','--value'],timeout=5,maximum=256).decode().strip()
 if stopped:g.need(active=='inactive','Clone is not inactive');return {'active':False}
 if active in ('activating','inactive'):raise g.ReadinessPending('Clone process is starting')
 g.need(active=='active','Clone not active')
 value=g.clone_process(role,binary);value['started']=g.run(['systemctl','show',unit,'--property=ExecMainStartTimestampMonotonic','--value'],timeout=5,maximum=128).decode().strip();g.need(value['started'].isdigit() and int(value['started'])>0,'Clone start identity missing');return value

def database_proof(database):
 g.need(database in ('jobman_dashboard',g.DATABASE),'Fixed proof database required')
 query="""SELECT json_build_object('database',current_database(),'hold',(SELECT json_build_object('held',held,'generation',generation::text,'restoreRecordedThrough',to_char(restore_recorded_through AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM dashboard_notification_delivery_control WHERE singleton),
 'openGaps',(SELECT count(*) FROM dashboard_event_gaps WHERE resolved_at IS NULL),
 'sources',(SELECT json_agg(row_to_json(v) ORDER BY v."deploymentId") FROM (
 SELECT f.deployment_id AS "deploymentId",i.control_instance_id AS "controlInstanceId",i.recovery_epoch::text AS "recoveryEpoch",i.configuration_revision::text AS "configurationRevision",
 f.namespace_ids AS "namespaceIds",f.status,f.last_position::text AS position,encode(sha256(f.checkpoint),'hex') AS "checkpointSHA256",encode(sha256(convert_to(f.cursor,'UTF8')),'hex') AS "cursorSHA256"
 FROM dashboard_event_feeds f FULL JOIN dashboard_source_identities i USING(deployment_id) ORDER BY f.deployment_id LIMIT 3) v));"""
 raw=g.run(['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-q','-A','-t','-U','jobman_control','-v','ON_ERROR_STOP=1','-d',database],
  ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='500ms'; "+query+' ROLLBACK;').encode(),timeout=5,maximum=65536)
 return g.decode(raw)

def validate_sources(proof,plan,previous=None):
 g.need(proof['database'] in ('jobman_dashboard',g.DATABASE) and proof['openGaps']==0 and len(proof['sources'])==2,'Complete active source proof required')
 expected={v['deploymentId']:v for v in plan['sources']};g.need(len(expected)==2 and {v['deploymentId'] for v in proof['sources']}==set(expected),'Source set changed')
 for value in proof['sources']:
  entry=expected[value['deploymentId']]
  g.need(value['controlInstanceId']==entry['controlInstanceId'] and value['recoveryEpoch']==entry['recoveryEpoch'] and value['configurationRevision']==str(plan['configurationRevision']) and value['namespaceIds']==entry['namespaceIds'] and value['status']=='active','Source identity, scope or state changed')
  g.need(isinstance(value['position'],str) and re.fullmatch(r'0|[1-9][0-9]{0,18}',value['position']) and int(value['position'])<1<<63 and all(g.HEX.fullmatch(value[k]) for k in ('checkpointSHA256','cursorSHA256')),'Bounded private-checkpoint proof required')
 if previous:
  g.need(proof['database']==previous['database'],'Proof database changed')
  prior={v['deploymentId']:v for v in previous['sources']}
  for value in proof['sources']:g.need(int(value['position'])>=int(prior[value['deploymentId']]['position']),'Running source position regressed')


def validate_hold(value,release,state):
 expected=int(release['hold']['generation']);offset={'held':0,'released':1,'retired':2}[state]
 g.need(value['held'] is (state!='released') and value['generation']==str(expected+offset) and instant(value['restoreRecordedThrough'])==instant(release['hold']['restoreRecordedThrough']),'Clone generation or restore floor changed')

def existing(payload):
 # Check prior successful intent before invoking any reusable directory helper.
 root=g.BASE/payload['operationId'];g.need(g.HEX.fullmatch(payload['operationId']),'Fixed operation ID required')
 g.read(root/'intent.json',owner=(0,0),mode=0o600)
 g.execution_root(payload)
 return root

def hold(binary):
 return g.decode(g.run([binary,'events','hold-status','--config',str(location('recovery')[0])],timeout=15,maximum=65536))

def snapshot(payload):
 root=existing(payload);g.read(root/'clone-start.json',owner=(0,0),mode=0o600);binary=g.candidate(payload)
 primary=g.primary_pins(payload);values={role:process(role,binary) for role in g.CLONE}
 for role in ROLES:
  path,uid=location(role);g.need(g.read(path,owner=(uid,uid),mode=0o600)[0]==g.prepared(payload,'configs/'+role+'.json'),'Clone config differs from prepared backup')
 recovery=g.decode(g.prepared(payload,'configs/recovery.json'));url=urlparse(g.read(recovery['databaseURLFile'],16384,owner=(0,0),mode=0o600)[0].decode().strip())
 g.need(recovery['databaseURLFile']==str(g.clone_root('operator')/'recovery-database-url') and url.path=='/'+g.DATABASE and url.username=='jobman_dashboard_restore_ddl' and url.hostname=='10.77.0.20' and parse_qs(url.query).get('sslmode')==['verify-full'],'Clone recovery DSN differs')
 expected=g.decode(g.read(root/'clone-hold.json',owner=(0,0),mode=0o600)[0]);current=hold(binary)
 validate_hold(current,{'hold':expected['hold']},'held')
 return {'operationId':payload['operationId'],'primary':primary,'clones':values,'hold':current,'epoch':int(time.time())}

def material(payload):
 release=payload['release'];g.need(g.digest(g.encoded(release))==payload['releaseSHA256'] and release['operationId']==payload['operationId'] and release['restorePlanSHA256']==payload['planSHA256'] and release['configurationRevision']==payload['plan']['configurationRevision'],'Exact release plan required')
 result={}
 for role in ROLES:
  before=g.prepared(payload,'configs/'+role+'.json');after=base64.b64decode(payload['after'][role],validate=True)
  g.need(after==transition(before,role) and g.digest(before)==release['files'][role]['before'] and g.digest(after)==release['files'][role]['after'],'Only one startup hold flag per config may change')
  result[role]=(before,after)
 return release,result

def ensure_root(payload,release):
 root=existing(payload)/'release';g.directory(root)
 retain(root/'plan.json',g.encoded(release));return root

def same_primary(payload,release):
 g.need(g.primary_pins(payload)==release['snapshot']['primary'],'Primary process/config identity changed')

def configs_match(materials,after=False):
 for role,(before,new) in materials.items():
  path,uid=location(role);g.need(g.read(path,owner=(uid,uid),mode=0o600)[0]==(new if after else before),'Exact clone config required')

def replace_one(root,role,before,after):
 path,uid=location(role);live=g.read(path,owner=(uid,uid),mode=0o600)[0];backup=root/(role+'.before.json')
 if live==after:g.need(g.read(backup,owner=(0,0),mode=0o600)[0]==before,'Changed config lacks original backup');return
 g.need(live==before,'Clone config CAS failed');retain(backup,before)
 staged=path.parent/'config.release-staged.json'
 if staged.exists():g.need(g.read(staged,owner=(uid,uid),mode=0o600)[0]==after,'Staged config differs')
 else:g.put(staged,after,uid,uid)
 g.need(g.read(path,owner=(uid,uid),mode=0o600)[0]==before,'Clone config changed before replacement');os.replace(staged,path)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def ready(payload,release,materials,state):
 binary=g.candidate(payload);same_primary(payload,release);configs_match(materials,True);validate_hold(hold(binary),release,state)
 observed={}
 for role,(name,uid) in g.CLONE.items():
  item=process(role,binary);sock='/run/jobman-dashboard-restore-'+role+'-lab/observe.sock'
  try:info=Path(sock).lstat()
  except FileNotFoundError as error:raise g.ReadinessPending('Clone socket is starting') from error
  g.need(stat.S_ISSOCK(info.st_mode) and info.st_uid==uid,'Clone socket owner differs')
  try:
   ready_raw=g.run(['runuser','-u',name,'--','curl','--silent','--show-error','--fail','--max-time','2','--unix-socket',sock,'http://localhost/readyz'],timeout=3,maximum=32768)
   metrics=g.run(['runuser','-u',name,'--','curl','--silent','--fail','--max-time','2','--unix-socket',sock,'http://localhost/metrics'],timeout=3,maximum=256<<10)
  except (ValueError,g.subprocess.SubprocessError) as error:raise g.ReadinessPending('Clone local dependencies are starting') from error
  ready=g.decode(ready_raw)
  g.need(ready.get('state')=='ready' and ready.get('role')==role and re.findall(rb'^jobman_dashboard_configuration_revision ([0-9]+)$',metrics,re.MULTILINE)==[str(release['configurationRevision']).encode()],'Clone readiness/revision differs')
  observed[role]={'process':item,'ready':ready,'metricsSHA256':g.digest(metrics),'metricsBytes':len(metrics)}
 same_primary(payload,release);validate_hold(hold(binary),release,state)
 return {'state':state,'hold':hold(binary),'components':observed,'primaryPreserved':True}

def await_ready(payload,release,materials):
 deadline=time.monotonic()+25
 with g.phase_deadline(deadline):
  while True:
   g.need(time.monotonic()<deadline,'Clone readiness deadline exceeded')
   # Immutable drift fails immediately; only process/socket readiness retries.
   same_primary(payload,release);configs_match(materials,True);validate_hold(hold(g.candidate(payload)),release,'held')
   try:return ready(payload,release,materials,'held')
   except g.ReadinessPending:
    g.need(time.monotonic()<deadline,'Clone readiness deadline exceeded');time.sleep(min(.2,max(0,deadline-time.monotonic())))

def configure(payload,release,materials,root):
 binary=g.candidate(payload);same_primary(payload,release);validate_hold(hold(binary),release,'held')
 pending=root/'configure.pending.json';started=root/'start.pending.json'
 if not pending.exists():
  configs_match(materials)
  g.need({role:process(role,binary) for role in g.CLONE}==release['snapshot']['clones'],'Clone process changed before configure')
  # Validate staged bytes before stopping. The filenames reside in the same
  # private config roots; all material references stay absolute and untouched.
  for role,(before,after) in materials.items():
   path,uid=location(role);stage=path.parent/'config.release-staged.json'
   if stage.exists():g.need(g.read(stage,owner=(uid,uid),mode=0o600)[0]==after,'Existing staged config differs')
   else:g.put(stage,after,uid,uid)
   if role in g.CLONE:g.run(['runuser','-u',g.CLONE[role][0],'--',binary,'--mode','check-config','--check-mode',role,'--config',str(stage)],timeout=10)
  retain(pending,g.encoded({'releaseSHA256':payload['releaseSHA256']}))
 else:g.need(g.decode(g.read(pending,owner=(0,0),mode=0o600)[0])=={'releaseSHA256':payload['releaseSHA256']},'Configure intent changed')
 if not started.exists():
  for role in g.CLONE:
   active=g.run(['systemctl','show',policy(role),'--property=ActiveState','--value'],timeout=5,maximum=256).decode().strip()
   if active=='active':g.need(process(role,binary)==release['snapshot']['clones'][role],'Unexpected clone process before stop')
   else:g.need(active=='inactive','Uncertain clone process state')
  g.run(['systemctl','stop',*[policy(role) for role in g.CLONE]],timeout=70)
  for role in g.CLONE:process(role,binary,True)
  same_primary(payload,release);validate_hold(hold(binary),release,'held')
  for role,(before,after) in materials.items():replace_one(root,role,before,after)
  for role,(name,uid) in g.CLONE.items():
   g.directory('/run/jobman-dashboard-restore-'+role+'-lab',uid,uid)
   g.run(['runuser','-u',name,'--',binary,'--mode','check-config','--check-mode',role,'--config',str(location(role)[0])],timeout=10)
  retain(started,g.encoded({'releaseSHA256':payload['releaseSHA256']}))
  g.run(['systemctl','start',*[policy(role) for role in g.CLONE]],timeout=30)
 else:g.need(g.decode(g.read(started,owner=(0,0),mode=0o600)[0])=={'releaseSHA256':payload['releaseSHA256']},'Start intent changed')
 result=await_ready(payload,release,materials)
 retain(root/'configured.json',g.encoded({'releaseSHA256':payload['releaseSHA256'],'configured':True}));return result

def retire(payload,release,materials,root):
 g.need(g.decode(g.read(root/'configured.json',owner=(0,0),mode=0o600)[0])=={'releaseSHA256':payload['releaseSHA256'],'configured':True},'Configure completion missing')
 binary=g.candidate(payload);same_primary(payload,release);configs_match(materials,True);validate_hold(hold(binary),release,'retired')
 for role in g.CLONE:
  unit=policy(role);g.need(g.read('/etc/systemd/system/'+unit,owner=(0,0),mode=0o644)[0]==g.clone_unit(role,binary),'Clone retirement unit changed')
  enabled=g.subprocess.run(['systemctl','is-enabled',unit],capture_output=True,timeout=g.command_timeout(5))
  g.need(enabled.returncode==1 and enabled.stdout.strip()==b'disabled','Unexpected clone enablement')
  active=g.run(['systemctl','show',unit,'--property=ActiveState','--value'],timeout=5,maximum=256).decode().strip()
  if active=='active':process(role,binary)
  else:g.need(active=='inactive','Clone retirement state unknown')
 retain(root/'retire.pending.json',g.encoded({'releaseSHA256':payload['releaseSHA256']}))
 g.run(['systemctl','stop',*[policy(role) for role in g.CLONE]],timeout=70)
 for role in g.CLONE:process(role,binary,True)
 with socket.socket() as probe:
  probe.settimeout(1);g.need(probe.connect_ex(('10.77.0.10',38443))!=0,'Clone port remains open')
 same_primary(payload,release);validate_hold(hold(binary),release,'retired')
 result={'retired':True,'dataRetained':True,'primaryPreserved':True,'hold':hold(binary),'releaseSHA256':payload['releaseSHA256']};retain(root/'retired.json',g.encoded(result));return result

def execute(payload):
 g.need(os.geteuid()==0 and sys.platform=='linux' and socket.gethostname().split('.')[0]==payload['host'],'Fixed root Linux host required')
 action=payload['action'];g.need(action in ('proof','snapshot','configure','observe','retire'),'Unknown clone release action')
 if action=='proof':
  g.need(payload['host']=='pg01','Proof host differs');return {name:database_proof(name) for name in ('jobman_dashboard',g.DATABASE)}
 g.need(payload['host']=='storage01','Clone host differs')
 if action=='snapshot':return snapshot(payload)
 release,materials=material(payload)
 g.need(payload.get('explicitApply') is True or action=='observe','Explicit supplemental apply required')
 root=ensure_root(payload,release)
 fd=os.open(root/'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  st=os.fstat(fd);g.need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,'Private clone release lock required');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  with g.phase_deadline(time.monotonic()+145):
   if action=='configure':return configure(payload,release,materials,root)
   if action=='retire':return retire(payload,release,materials,root)
   return ready(payload,release,materials,payload['holdState'])
 finally:os.close(fd)
