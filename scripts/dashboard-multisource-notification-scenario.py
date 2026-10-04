#!/usr/bin/env python3
"""Fixed two-Control normal cancellation scenarios and read-only event barriers.

No service/configuration changes, SQL job/event writes or helper installation.
The reviewed helper must already be staged. Only four fresh jobs per test run
are admitted by normal Control Store methods; receipts survive uncertain calls.
"""
import argparse
import base64
import errno
from contextlib import contextmanager
from datetime import datetime
import importlib.util
import os
from pathlib import Path
import re
import shlex
import sys

COMMON_SHA = 'deb95b8dc32334cddcbcb2f7c1d24584d43de699212f26661c24499339b8cecb'
NAMESPACES = {'primary':'4156b832-9be8-40ff-a471-cb3061b6001d', 'secondary':'455525f6-5d8a-4d4f-bea3-2d3f1ed4698f'}
SOURCE_SHA = '7faac82263dfa281d2fec7c3e8a52a55a121294e39e7e2d1706115751d4a2123'
RECEIPT = re.compile('[0-9a-f]{32}\\Z')
HOST_RECEIPT_PARENT = Path('/private/tmp')
RETAINED_RECEIPTS = frozenset(('7ae1782e0d424061e8f056f7d4dde9bf','ecf5578b777a10c0a997e3a15218fcfb','63861951db782332bb16cc5f58a0a5d6','28bd57c3d4a8d292c37c0b1d1520c821','8281f530b049327cf138cfeabd32f268','e406f287dc15461d0d79351de1d5485c','bb399d49f2dc05be412399b5b474feb5','59373e309864f44603cc5fc183e61d4c'))


STAGES=frozenset(('host_input','host_transport','host_decode','host_validate','host_receipt','guest_preflight','guest_material','helper_run','guest_cleanup','guest_postflight','guest_barrier','guest_barrier_input','guest_barrier_source','guest_barrier_dashboard','guest_barrier_result'))
COMMON_REASONS=frozenset(('file_parent_alias','file_identity','file_changed','immutable_receipt_changed','directory_identity','duplicate_json_field','invalid_json_number','command_failed','command_deadline','command_output_bound','command_error_bound'))
OS_REASONS={errno.EACCES:'os_permission_denied',errno.EPERM:'os_permission_denied',errno.ENOENT:'os_not_found',errno.ELOOP:'os_symlink',errno.ENOTDIR:'os_not_directory',errno.EISDIR:'os_is_directory',errno.EEXIST:'os_exists',errno.EBADF:'os_bad_descriptor',errno.EMFILE:'os_process_file_limit',errno.ENFILE:'os_system_file_limit',errno.ENOSPC:'os_no_space',errno.EDQUOT:'os_quota',errno.EIO:'os_io',errno.ESTALE:'os_stale',errno.EAGAIN:'os_would_block',errno.EINTR:'os_interrupted',errno.ETIMEDOUT:'os_timeout'}
PYTHON_REASONS={KeyError:'python_key_error',TypeError:'python_type_error',NameError:'python_name_error',ValueError:'python_value_error',AttributeError:'python_attribute_error',UnboundLocalError:'python_unbound_local_error'}
CODES=frozenset(PYTHON_REASONS.values())|frozenset(('failed','invalid_result','common_failure','os_error'))|frozenset('common_'+v for v in COMMON_REASONS)|frozenset(OS_REASONS.values())
COMMON_FAILURE_TYPE=None


def failure_code(error):
 # Recognize only the exact class from the hash-pinned common module. Never
 # serialize arbitrary exception strings, filenames, errno values or attributes.
 if COMMON_FAILURE_TYPE is not None and type(error) is COMMON_FAILURE_TYPE:
  return 'common_'+error.code if error.code in COMMON_REASONS else 'common_failure'
 if isinstance(error,OSError):return OS_REASONS.get(error.errno,'os_error')
 return PYTHON_REASONS.get(type(error),'failed')


class ScenarioFailure(Exception):
 def __init__(self,stage,code='failed'):
  if stage not in STAGES or code not in CODES:stage,code='host_decode','invalid_result'
  self.stage,self.code=stage,code
  super().__init__('scenario_'+stage+'_'+code)


@contextmanager
def at_stage(stage):
 try:yield
 except ScenarioFailure:raise
 except Exception as error:raise ScenarioFailure(stage,failure_code(error)) from None


def failure_frame(error,default='host_input'):
 if not isinstance(error,ScenarioFailure):error=ScenarioFailure(default,failure_code(error))
 return {'scenarioFailure':{'stage':error.stage,'code':error.code}}


def checked_result(c,raw):
 with at_stage('host_decode'):
  value=c.decode(raw)
  if isinstance(value,dict) and 'scenarioFailure' in value:
   failure=value['scenarioFailure']
   if set(value)!={'scenarioFailure'} or not isinstance(failure,dict) or set(failure)!={'stage','code'} or failure['stage'] not in STAGES or failure['code'] not in CODES:raise ScenarioFailure('host_decode','invalid_result')
   raise ScenarioFailure(failure['stage'],failure['code'])
  return value


def common_module():
 global COMMON_FAILURE_TYPE
 import hashlib
 path=Path(__file__).resolve().with_name('dashboard-scale-source-common.py')
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=COMMON_SHA:raise ValueError('reviewed_common_changed')
 spec=importlib.util.spec_from_file_location('common',path);c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
 COMMON_FAILURE_TYPE=c.Failure
 return c,raw


def validate_fixture(c,value,profile,receipt):
 p=c.PROFILES[profile]
 fields={'synthetic','fixtureVersion','observationMode','helperCommit','receipt','deploymentId','controlInstanceId','recoveryEpoch','namespaceId','namespace','jobs'}
 if profile=='secondary':fields.add('profile')
 c.need(isinstance(value,dict) and set(value)==fields and value.get('profile','')==('secondary-v1' if profile=='secondary' else '') and value['synthetic'] is True and value['fixtureVersion']==1 and value['observationMode']=='normal-cancel-no-execution','scenario_shape')
 c.need(value['receipt']==receipt and value['deploymentId']==p['deployment'] and value['controlInstanceId']==p['instance'] and value['recoveryEpoch']=='1' and value['namespaceId']==NAMESPACES[profile] and value['namespace']=='dashboard-research' and value['helperCommit']==c.COMMIT,'scenario_source')
 jobs=value['jobs'];c.need(isinstance(jobs,list) and len(jobs)==2 and [j.get('case') for j in jobs]==['first','stopped'] and all(set(j)=={'case','jobId'} and c.UUID.fullmatch(j['jobId']) for j in jobs) and jobs[0]['jobId']!=jobs[1]['jobId'],'scenario_jobs')
 return value


def validate_event(c,value,fixture,selected):
 required={'synthetic','receipt','case','deploymentId','controlInstanceId','recoveryEpoch','namespaceId','jobId','eventId','outcome','jobRevision','recordedAt'}
 c.need(isinstance(value,dict) and required<=set(value)<=required|{'runId','executionId'} and value['synthetic'] is True and value['case']==selected and value['jobId']==next(j['jobId'] for j in fixture['jobs'] if j['case']==selected) and c.UUID.fullmatch(value['eventId']) and value['outcome']=='cancelled','event_shape')
 c.need(all(value[k]==fixture[k] for k in ('receipt','deploymentId','controlInstanceId','recoveryEpoch','namespaceId')),'event_source')
 revision=value['jobRevision'];c.need(isinstance(revision,str) and re.fullmatch('[1-9][0-9]{0,18}',revision) and int(revision)<=9223372036854775807,'event_revision')
 when=datetime.fromisoformat(value['recordedAt'].replace('Z','+00:00'));c.need(when.tzinfo is not None,'event_time')
 # These scenarios cancel accepted jobs before execution: a run would mean
 # another agent unexpectedly claimed this otherwise inert fixture target.
 c.need('runId' not in value and 'executionId' not in value,'unexpected_execution')
 return value


def barrier_queries(c,fixture,event):
 # Inputs have already passed exact profile/UUID validation before interpolation.
 dep,instance,ns,job,identity=(event[k] for k in ('deploymentId','controlInstanceId','namespaceId','jobId','eventId'))
 source=f"SELECT json_build_object('published',EXISTS(SELECT 1 FROM monitoring_feed WHERE event_id='{identity}'::uuid AND namespace_id='{ns}'::uuid AND payload->>'jobId'='{job}' AND payload->>'jobRevision'='{event['jobRevision']}' AND payload->>'outcome'='cancelled'),'instance',(SELECT id::text FROM control_instance),'epoch',(SELECT restore_epoch::text FROM service_recovery_state));"
 dashboard=f"""SELECT json_build_object('settled',EXISTS(SELECT 1 FROM dashboard_source_events e
JOIN dashboard_notification_fanout f USING(deployment_id,control_instance_id,event_id)
JOIN dashboard_event_feeds s USING(deployment_id)
WHERE e.deployment_id='{dep}'::uuid AND e.control_instance_id='{instance}'::uuid AND e.event_id='{identity}'::uuid
AND e.namespace_id='{ns}'::uuid AND e.job_id='{job}'::uuid AND e.processed_at IS NOT NULL AND f.done AND s.status='active'
AND convert_from(s.checkpoint,'UTF8')::jsonb->>'controlInstanceId'=e.control_instance_id::text
AND convert_from(s.checkpoint,'UTF8')::jsonb->>'recoveryEpoch'='{event['recoveryEpoch']}'
AND NOT EXISTS(SELECT 1 FROM dashboard_notification_evaluations n WHERE (n.deployment_id,n.control_instance_id,n.event_id)=(e.deployment_id,e.control_instance_id,e.event_id) AND n.state='pending')));"""
 return source,dashboard


REMOTE = r'''
import fcntl,os,stat,sys
from pathlib import Path
from urllib.parse import urlparse,parse_qs

def process(c,profile):
 p=c.PROFILES[profile];unit='jobman-dashboard-lab-control'+('-secondary' if profile=='secondary' else '')
 c.run(['systemctl','is-active','--quiet',unit],timeout=3)
 pid=c.run(['systemctl','show',unit,'--property=MainPID','--value'],timeout=3).decode().strip();c.need(pid.isdigit() and int(pid)>0,'source_pid')
 proc=Path('/proc')/pid;c.need(proc.stat().st_uid==p['uid'],'source_uid')
 executable=Path(os.readlink(proc/'exe'));c.need(c.sha(c.read(executable,128<<20,uid=0,mode=0o755))==SOURCE_SHA,'source_binary')
 start=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
 return pid,start,str(executable)

def operation_lock(c,path):
 try:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
 except FileExistsError:
  fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 else:
  try:os.fchmod(fd,0o600)
  except Exception:os.close(fd);raise
 try:
  s=os.fstat(fd);c.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600,'operation_lock')
  return fd
 except Exception:os.close(fd);raise

def directory_preflight(c,profile):
 p=c.PROFILES[profile]
 # The secondary LDAP tree is deliberately separate from the Control service.
 # Inspect metadata/guard names only: never copy its bind or TLS credentials.
 for path,uid in ((Path(p['root']),p['uid']),(Path(p['directory']),p['directoryUID'])):
  info=path.lstat();c.need(path.resolve()==path and stat.S_ISDIR(info.st_mode) and info.st_uid==uid and stat.S_IMODE(info.st_mode)==0o700,'fixture_directory_identity')
  for pattern in ('.directory-acceptance-*.json','.diagnostic-prepare.json','.secondary-prepare.json'):
   c.need(not list(path.glob(pattern)),'unfinished_directory_or_fixture_operation')
 # Scale retains equal start/completion receipts. An incomplete pair still
 # requires inspection; never delete evidence or mistake its start for recovery.
  pending,complete=path/'.scale-seed.pending.json',path/'.scale-seed.completed.json'
  if pending.exists() or complete.exists():
   c.need(pending.exists() and complete.exists() and c.read(pending,8192)==c.read(complete,8192),'unfinished_scale_preparation')

def guest(c,payload):
 with at_stage('guest_preflight'):return _guest(c,payload)

def _guest(c,payload):
 c.need(os.geteuid()==0 and sys.platform=='linux','guest_root_required')
 c.need(os.uname().nodename.split('.')[0]==('pg01' if payload['action']=='settled' else 'control01'),'fixed_guest')
 profile=payload['profile'];c.need(profile in c.PROFILES and RECEIPT.fullmatch(payload['receipt']),'fixed_scenario')
 p=c.PROFILES[profile];action=payload['action'];c.need(action in ('prepare','complete','settled') and (action=='prepare' and payload['case'] is None or action!='prepare' and payload['case'] in ('first','stopped')),'scenario_action')
 if action=='settled':
  with at_stage('guest_barrier_input'):
   fixture=validate_fixture(c,payload['fixture'],profile,payload['receipt']);event=validate_event(c,payload['event'],fixture,payload['case'])
   source_query,dashboard_query=barrier_queries(c,fixture,event)
  def sql(database,query):
   raw=c.run(['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','jobman_control','-d',database],("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='500ms'; "+query+' ROLLBACK;').encode(),timeout=9,maximum=8192)
   return c.decode(raw)
  with at_stage('guest_barrier_source'):source=sql(p['database'],source_query)
  with at_stage('guest_barrier_dashboard'):dashboard=sql('jobman_dashboard',dashboard_query)
  with at_stage('guest_barrier_result'):
   c.need(source['instance']==p['instance'] and source['epoch']=='1' and type(source['published']) is bool and type(dashboard['settled']) is bool,'barrier_source')
   return {'receipt':payload['receipt'],'case':payload['case'],'deploymentId':p['deployment'],'controlInstanceId':p['instance'],'namespaceId':fixture['namespaceId'],'jobId':event['jobId'],'eventId':event['eventId'],'settled':source['published'] and dashboard['settled']}
 directory_preflight(c,profile)
 before=process(c,profile);root=Path(p['root']);s=root.lstat();c.need(root.resolve()==root and stat.S_ISDIR(s.st_mode) and s.st_uid==p['uid'] and stat.S_IMODE(s.st_mode)==0o700,'source_root')
 for parent in (c.BINARY.parent,c.BINARY.parent.parent):c.directory(parent,0o755)
 c.need(c.sha(c.read(c.BINARY,32<<20,uid=0,mode=0o755))==c.BINARY_SHA,'reviewed_helper_required')
 original=c.decode(c.read(root/'fixture-info.json',uid=p['uid']))
 c.need(original['synthetic'] is True and original['instanceId']==p['instance'] and original.get('profile','')==('secondary-v1' if profile=='secondary' else '') and any(n['id']==NAMESPACES[profile] and n['name']=='dashboard-research' for n in original['namespaces']),'original_fixture')
 raw=c.read(root/'control.env',65536,uid=p['uid']);env={}
 for line in raw.decode().splitlines():
  key,sep,value=line.partition('=');c.need(sep and re.fullmatch('JOBMAN_CONTROL_[A-Z0-9_]+',key) and key not in env,'source_env');env[key]=c.decode(value)
 dsn=env['JOBMAN_CONTROL_DATABASE_URL'];u=urlparse(dsn)
 c.need(u.scheme in ('postgres','postgresql') and u.hostname=='10.77.0.20' and u.port==5432 and u.path=='/'+p['database'] and parse_qs(u.query).get('sslmode')==['verify-full'] and bool(u.username) and bool(u.password) and not any(x in dsn for x in ('\r','\n','\x00')),'source_database')
 c.need(env.get('JOBMAN_CONTROL_DIAGNOSTIC_DEPLOYMENT_ID')==p['deployment'] and env.get('JOBMAN_CONTROL_DIRECTORY_MODE')=='enforce' and env.get('JOBMAN_CONTROL_MIGRATE_ON_START')=='false','source_configuration')
 # Shared with the primary wrapper; prevent concurrent scenarios in this root.
 fd=operation_lock(c,root/'.notification-operation.lock')
 try:
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  temporary=root/'.multisource-notification-database-url';c.need(not temporary.exists(),'uncertain_private_material')
  with at_stage('guest_material'):c.put(temporary,dsn.encode()+b'\n')
  try:
   args=[str(c.BINARY),'notifications','--profile',p['cli'],'--root',str(root),'--database-url-file',str(temporary),'--deployment-id',p['deployment'],'--receipt',payload['receipt'],'--action',action]
   if action=='complete':args+=['--case',payload['case']]
   with at_stage('helper_run'):
    result=c.decode(c.run(args,timeout=35,maximum=8192,env={'PATH':'/usr/bin:/bin','GOMAXPROCS':'2','GOMEMLIMIT':'256MiB'}))
  finally:
   with at_stage('guest_cleanup'):temporary.unlink();c.sync(root)
  with at_stage('guest_postflight'):
   c.need(process(c,profile)==before and c.read(root/'control.env',65536,uid=p['uid'])==raw,'source_changed_during_scenario')
  return result
 finally:os.close(fd)
'''


def host_receipt_directory(c,state,profile,receipt,action,explicit):
 # Public synthetic receipts alone may use this explicit local store. Source
 # roots, SSH inventory, credentials and remote payloads remain unchanged.
 c.need(profile in c.PROFILES and RECEIPT.fullmatch(receipt),'explicit_scenario_required')
 if explicit is not None:
  directory=Path(explicit)
  c.need(str(directory)==explicit and directory.parent==HOST_RECEIPT_PARENT and re.fullmatch(r'jobman-dashboard-notification-receipts-[A-Za-z0-9_-]{1,64}',directory.name),'host_receipt_root')
  c.directory(directory) # Pre-created owner0700 real directory; never chmod/adopt.
  c.need(receipt not in RETAINED_RECEIPTS,'retained_scenario_excluded')
 else:
  directory=state/'multisource-notifications';c.directory(directory,create=True)
 directory=directory/profile;c.directory(directory,create=True)
 if explicit is not None and action=='prepare':
  c.need(not any(directory.glob(receipt+'*.json')),'new_receipt_required')
 return directory


def guest_program(common_raw,wrapper_raw):
 return "import base64,types,json\nc=types.ModuleType('common');exec(base64.b64decode(%r),c.__dict__)\nexec(base64.b64decode(%r))\nexec(REMOTE)\nCOMMON_FAILURE_TYPE=c.Failure\ntry:\n result=guest(c,c.decode(__import__('sys').stdin.buffer.read(65537)))\nexcept Exception as error:\n result=failure_frame(error,'guest_preflight')\nprint(c.encoded(result).decode(),end='')"%(base64.b64encode(common_raw).decode(),base64.b64encode(wrapper_raw.replace(b"if __name__ == '__main__':",b"if False:")).decode())


def main():
 with at_stage('host_input'):return _main()

def _main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('profile',choices=('primary','secondary'));parser.add_argument('action',choices=('prepare','complete','settled'));parser.add_argument('receipt');parser.add_argument('case',nargs='?',choices=('first','stopped'))
 parser.add_argument('--host-receipt-root',help='Pre-created private /private/tmp receipt directory for new scenarios only')
 args=parser.parse_args();c,common_raw=common_module()
 c.need(RECEIPT.fullmatch(args.receipt) and (args.action=='prepare' and args.case is None or args.action!='prepare' and args.case is not None),'explicit_scenario_required')
 root=Path(__file__).resolve().parent.parent;state=root/'.lab/dashboard'
 connections=c.decode(c.read(state/'ssh-connections.json'))
 directory=host_receipt_directory(c,state,args.profile,args.receipt,args.action,args.host_receipt_root)
 path=directory/(args.receipt+'.json');payload={'profile':args.profile,'action':args.action,'receipt':args.receipt,'case':args.case}
 if args.action!='prepare':payload['fixture']=validate_fixture(c,c.decode(c.read(path,8192)),args.profile,args.receipt)
 if args.action=='settled':payload['event']=validate_event(c,c.decode(c.read(directory/(args.receipt+'-'+args.case+'.json'),8192)),payload['fixture'],args.case)
 host='pg01' if args.action=='settled' else 'control01';connection=connections[host]
 # Both local dependencies and the transmitted program are exact reviewed bytes;
 # all dynamic selections travel as JSON stdin, never shell interpolation.
 code=guest_program(common_raw,Path(__file__).read_bytes())
 with at_stage('host_transport'):
  raw=c.run(['ssh','-i',connection['ansible_ssh_private_key_file'],'-p',str(connection['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={state / "known_hosts"}','-o','HostKeyAlgorithms=ssh-ed25519',f'{connection["ansible_user"]}@{connection["ansible_host"]}','sudo python3 -c '+shlex.quote(code)],c.encoded(payload),timeout=50,maximum=8192)
 result=checked_result(c,raw)
 retain_result(c,result,payload,path,directory)
 sys.stdout.buffer.write(c.encoded(result))


def retain_result(c,result,payload,path,directory):
 with at_stage('host_validate'):
  if payload['action']=='prepare':validate_fixture(c,result,payload['profile'],payload['receipt'])
  elif payload['action']=='complete':validate_event(c,result,payload['fixture'],payload['case'])
  else:
   event=payload['event'];c.need(set(result)=={'receipt','case','deploymentId','controlInstanceId','namespaceId','jobId','eventId','settled'} and all(result[k]==event[k] for k in result if k!='settled') and type(result['settled']) is bool,'barrier_receipt')
 if payload['action']!='settled':
  destination=path if payload['action']=='prepare' else directory/(payload['receipt']+'-'+payload['case']+'.json')
  with at_stage('host_receipt'):c.retain(destination,c.encoded(result))


if __name__ == '__main__':
 try:main()
 except Exception as error:
  import json
  sys.stderr.write(json.dumps(failure_frame(error),sort_keys=True)+'\n')
  raise SystemExit(1) from None
