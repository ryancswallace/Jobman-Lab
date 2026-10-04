#!/usr/bin/env python3
"""Fixed guest phases for an inert graph; no service restart or config writes."""
import base64
import contextlib
import fcntl
import os
from pathlib import Path
import stat
import time

# p (pure plan) and c (pinned bounded I/O) are supplied by the reviewed host.
BASE=Path('/var/lib/jobman-dashboard-graph-ceiling')
DSN=Path('/etc/jobman-dashboard-lab/control-database-url')

DEADLINE=None

def run(args,payload=b'',timeout=30,**kwargs):
 remaining=timeout if DEADLINE is None else min(timeout,DEADLINE-time.monotonic())
 p.need(remaining>0,'guest_phase_deadline')
 result=c.run(args,payload,timeout=remaining,**kwargs)
 p.need(DEADLINE is None or time.monotonic()<=DEADLINE,'guest_phase_deadline')
 return result

@contextlib.contextmanager
def locked(root,create=False):
 c.directory(root,create=create)
 if create:
  try:fd=os.open(root/'.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.fchmod(fd,0o600)
  except FileExistsError:fd=os.open(root/'.lock',os.O_RDWR|os.O_NOFOLLOW)
 else:fd=os.open(root/'.lock',os.O_RDWR|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);p.need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'guest_lock_identity');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
 finally:os.close(fd)

def process(unit):
 run(['systemctl','is-active','--quiet',unit],timeout=3)
 pid=run(['systemctl','show',unit,'--property=MainPID','--value'],timeout=3).decode().strip();p.need(pid.isdigit() and int(pid)>0,'active_process')
 p.need(run(['systemctl','show',unit,'--property=DropInPaths','--value'],timeout=3).strip()==b'','unexpected_unit_override')
 exe=os.readlink('/proc/'+pid+'/exe');fields=Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()
 return {'pid':pid,'uid':os.stat('/proc/'+pid).st_uid,'exe':exe,'start':fields[19],
  'binarySHA256':c.sha(c.read(Path(exe),128<<20,uid=0,mode=0o755)),
  'unitSHA256':c.sha(c.read(Path('/etc/systemd/system')/(unit+'.service'),65536,uid=0,mode=0o644))}
def processes():return {unit:process(unit) for unit in sorted(p.UNITS)}

def files():
 root=Path(p.ROOT);s=root.lstat();p.need(root.resolve()==root and stat.S_ISDIR(s.st_mode) and s.st_uid==21902 and stat.S_IMODE(s.st_mode)==0o700,'source_root_identity')
 for pattern in ('.directory-acceptance-*.json','.diagnostic-prepare.json'):
  p.need(not list(root.glob(pattern)),'pending_source_operation')
 return {name:c.sha(c.read(root/name,2<<20,uid=21902)) for name in sorted(p.SOURCE_FILES)}

def helper(command,spec,output=None,approved=None):
 c.read(DSN,16384,uid=0)
 p.helper_spec(spec);p.need(c.sha(c.read(Path(spec['path']),32<<20,uid=0,mode=0o755))==spec['binarySHA256'],'staged_helper_changed')
 args=[spec['path'],'graph-ceiling','--action',command,'--root',p.ROOT,'--database-url-file',str(DSN)]
 if output is not None:args+=['--output',str(output)]
 if approved is not None:args+=['--config',str(approved)]
 # All stdout is bounded, public manifest metadata; wrapped driver errors remain
 # withheld by both the helper and the command primitive.
 raw=run(args,timeout=490 if command in ('seed','verify') else 30,maximum=2<<20,
  env={'PATH':'/usr/bin:/bin','GOMAXPROCS':'2','GOMEMLIMIT':'512MiB'})
 return c.decode(raw)

def stage(payload):
 spec=p.helper_spec(payload['helper']);binary=base64.b64decode(payload['binary'],validate=True)
 p.need(p.candidate({k:v for k,v in spec.items() if k!='path'},binary)==spec,'helper_stage_binding')
 before=processes();source=files()
 for path in (Path('/usr'),Path('/usr/local'),Path('/usr/local/libexec')):c.directory(path,0o755)
 path=Path(spec['path'])
 for directory in (path.parent.parent,path.parent):c.directory(directory,0o755,True)
 if path.exists():p.need(c.read(path,32<<20,uid=0,mode=0o755)==binary,'existing_helper_differs')
 else:c.put(path,binary,0o755)
 p.need(processes()==before and files()==source,'source_changed_during_stage')
 return {'helper':spec,'sourcePreserved':True}

def source_snapshot(spec):
 before=processes();raw=files();value=helper('preflight',spec);p.preflight(value,spec)
 p.need(files()==raw==value['sourceFiles'] and processes()==before,'source_changed_during_preflight')
 free=os.statvfs('/var/lib');p.need(free.f_bavail*free.f_frsize>=1<<30,'source_storage_headroom')
 return {'epoch':int(time.time()),'preflight':value,'files':raw,'processes':before}

def preserved(plan):
 p.need(files()==plan['source']['files'] and processes()==plan['source']['processes'],'source_preservation_changed')

def identity_projection(table,columns,condition='TRUE'):
 # Called only with fixed literals below, never request/query text.
 return "(SELECT json_build_object('count',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(digest,'' ORDER BY id),''),'UTF8')),'hex')) FROM (SELECT id,encode(sha256(convert_to(json_build_array("+columns+")::text,'UTF8')),'hex') AS digest FROM "+table+' WHERE '+condition+' ORDER BY id LIMIT 200001) x)'

def database_snapshot():
 graph="SELECT g.id FROM graphs g JOIN namespaces n ON n.id=g.namespace_id WHERE n.name='dashboard-operations' AND g.name='synthetic-ceiling-graph-v1'"
 target="SELECT t.id FROM targets t JOIN namespaces n ON n.id=t.namespace_id WHERE n.name='dashboard-operations' AND t.name='dashboard-graph-ceiling-no-executor'"
 projections={
  'jobs':identity_projection('jobs','id,namespace_id,owner_principal_id,name,labels,placement_target,placement_partition,workload_digest,request_digest,created_at,imported',"graph_id IS NULL OR graph_id NOT IN("+graph+')'),
  'targets':identity_projection('targets','id,namespace_id,name,current_generation_id,created_at','id NOT IN('+target+')'),
  'runs':identity_projection('runs','id,namespace_id,job_id,run_number,created_at'),
  'executions':identity_projection('executions','id,namespace_id,run_id,target_id,target_generation_id,agent_id,effective_spec_digest,created_at'),
  'agents':identity_projection('agents','id,namespace_id,target_id,target_generation_id,principal_id,created_at'),
  'enrollments':identity_projection('agent_enrollment_tokens','id,namespace_id,target_id,target_generation_id,principal_id,created_by_principal_id,created_at')}
 query="""SELECT json_build_object('database',current_database(),'instance',(SELECT id::text FROM control_instance),
 'epoch',(SELECT restore_epoch::text FROM service_recovery_state WHERE singleton),'migrations',(SELECT count(*) FROM schema_migrations),
 'ledgerSHA256',(SELECT encode(sha256(convert_to(string_agg(version||':'||checksum,E'\\n' ORDER BY version),'UTF8')),'hex') FROM schema_migrations),
 'namespaceId',(SELECT id::text FROM namespaces WHERE name='dashboard-operations'),
 'graphCount',(SELECT count(*) FROM ("""+graph+") g),'targetCount',(SELECT count(*) FROM ("+target+") t),"+','.join("'"+name+"',"+value for name,value in projections.items())+');'
 command=['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-q','-A','-t','-U','jobman_control','-v','ON_ERROR_STOP=1','-d',p.DATABASE]
 raw=run(command,("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='500ms'; SET LOCAL TIME ZONE 'UTC'; "+query+' ROLLBACK;').encode(),timeout=20,maximum=65536)
 return c.decode(raw)

def operation(payload):
 plan=payload['plan'];p.validate(plan);preserved(plan);phase=payload['phase'];root=BASE/plan['executionId']
 with locked(BASE,create=phase=='quota'):
  c.directory(root,create=phase=='quota')
  if phase=='quota':c.retain(root/'plan.json',p.encoded(plan))
  p.need(c.read(root/'plan.json',2<<20)==p.encoded(plan),'operation_plan_changed')
  output=root/'output';intent={'planSHA256':c.sha(p.encoded(plan)),'phase':phase}
  complete=root/(phase+'.complete.json');pending=root/(phase+'.pending.json')
  if phase=='quota':
   if not complete.exists():
    p.need(not pending.exists(),'quota_pending_requires_inspection');c.put(pending,p.encoded(intent));c.directory(output,create=True)
    c.put(root/'approved.json',p.encoded(plan['source']['preflight']))
    result=helper('quota',plan['helper'],output,root/'approved.json');p.quota_receipt(result,plan)
    preserved(plan);c.put(complete,p.encoded(result))
   result=c.decode(c.read(complete));p.quota_receipt(result,plan)
   current=helper('preflight',plan['helper']);p.need(current['policy']==result['after'] and current['sourceFiles']==plan['source']['files'],'completed_quota_changed')
   p.need(c.read(pending)==p.encoded(intent),'quota_pending_binding');return result
  quota=c.decode(c.read(root/'quota.complete.json'));p.quota_receipt(quota,plan)
  if phase=='seed' and not complete.exists():
   p.need(not pending.exists(),'seed_pending_requires_inspection');c.put(pending,p.encoded(intent))
   value=helper('seed',plan['helper'],output);p.graph_manifest(value,plan);preserved(plan)
   c.put(complete,p.encoded({'graphSHA256':c.sha(c.read(output/'graph.json',2<<20)),'helper':plan['helper']}))
  else:p.need((root/'seed.complete.json').exists(),'completed_seed_required')
  value=helper('verify',plan['helper'],output);p.graph_manifest(value,plan);preserved(plan)
  files={name:c.read(output/name,2<<20) for name in ('quota.intent.json','quota.complete.json','seed.intent.json','graph.json','seed.complete.json')}
  expected=c.decode(c.read(root/'seed.complete.json'));p.need(expected=={'graphSHA256':c.sha(files['graph.json']),'helper':plan['helper']},'completed_seed_changed')
  p.need(c.read(root/'seed.pending.json')==p.encoded({'planSHA256':c.sha(p.encoded(plan)),'phase':'seed'}),'seed_pending_binding')
  return {'manifest':value,'files':{name:base64.b64encode(raw).decode() for name,raw in files.items()},'sha256':{name:c.sha(raw) for name,raw in files.items()},'sourcePreserved':True}

def _execute(payload):
 os.umask(0o077);p.need(os.geteuid()==0,'root_required');phase=payload['phase'];host=os.uname().nodename.split('.')[0]
 p.need(phase in ('stage','source-preflight','database','quota','seed','verify'),'phase_not_allowed')
 p.need(host==('pg01' if phase=='database' else 'control01'),'fixed_guest_required')
 if phase=='stage':p.need(payload.get('apply') is True,'apply_required');return stage(payload)
 if phase=='source-preflight':return source_snapshot(payload['helper'])
 if phase=='database':
  free=os.statvfs('/var/lib');p.need(free.f_bavail*free.f_frsize>=2<<30,'database_storage_headroom');return database_snapshot()
 p.need(phase=='verify' or payload.get('apply') is True,'apply_required')
 return operation(payload)

def execute(payload):
 global DEADLINE
 DEADLINE=time.monotonic()+(520 if payload.get('phase') in ('seed','verify') else 100)
 result=_execute(payload)
 p.need(time.monotonic()<=DEADLINE,'guest_phase_deadline')
 return result
