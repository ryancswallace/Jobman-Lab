#!/usr/bin/env python3
"""Fixed control01/pg01 scale preparation phases, executed only by reviewed host."""
import base64
import fcntl
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlparse,parse_qs

c=common
UNITS=('jobman-control','jobman-keycloak','jobman-dashboard-lab-control','jobman-dashboard-lab-directory','jobman-dashboard-lab-control-secondary','jobman-dashboard-lab-directory-secondary','jobman-dashboard-lab-broker')

def process(unit):
 c.run(['systemctl','is-active','--quiet',unit],timeout=3)
 pid=c.run(['systemctl','show',unit,'--property=MainPID','--value'],timeout=3).decode().strip();c.need(pid.isdigit() and int(pid)>0,'active_source_process')
 data=Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()
 files=Path('/etc/systemd/system')/(unit+'.service')
 s=files.lstat();c.need(s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o644,'unit_owner')
 c.need(c.run(['systemctl','show',unit,'--property=DropInPaths','--value'],timeout=3).strip()==b'','unexpected_unit_override')
 executable=os.readlink('/proc/'+pid+'/exe')
 return {'pid':pid,'uid':os.stat('/proc/'+pid).st_uid,'exe':executable,'binarySHA256':c.sha(c.read(Path(executable),128<<20,uid=0,mode=0o755)),'start':data[19],
         'unitSHA256':c.sha(c.read(files,65536,uid=0,mode=0o644))}
def processes():return {unit:process(unit) for unit in UNITS}
def environment(raw):
 c.need(b'\x00' not in raw and len(raw)<=65536,'environment_bound');result={}
 for line in raw.decode().splitlines():
  if not line or line.startswith('#'):continue
  key,sep,value=line.partition('=');c.need(sep and re.fullmatch('JOBMAN_CONTROL_[A-Z0-9_]+',key) and key not in result,'environment_shape');decoded=c.decode(value);c.need(isinstance(decoded,str) and decoded and not any(v in decoded for v in ('\r','\n','\x00')),'environment_value');result[key]=decoded
 return result

def source_files(profile):
 p=c.PROFILES[profile];root=Path(p['root']);directory=Path(p['directory'])
 for path,uid in ((root,p['uid']),(directory,p['directoryUID'])):
  s=path.lstat();c.need(path.resolve()==path and stat.S_ISDIR(s.st_mode) and s.st_uid==uid and stat.S_IMODE(s.st_mode)==0o700,'source_directory_identity')
 files={};raw={}
 for path,uid in ((root/'control.env',p['uid']),(root/'directory.json',p['uid']),(directory/'directory-state.json',p['directoryUID']),(root/'fixture-info.json',p['uid']),(root/'delegation.json',p['uid'])):
  raw[str(path)]=c.read(path,uid=uid);files[str(path)]=c.sha(raw[str(path)])
 info=c.decode(raw[str(root/'fixture-info.json')]);c.need(info['synthetic'] is True and info['instanceId']==p['instance'],'source_instance_receipt')
 env=environment(raw[str(root/'control.env')]);dsn=env.get('JOBMAN_CONTROL_DATABASE_URL','');u=urlparse(dsn)
 c.need(u.scheme in ('postgres','postgresql') and u.path=='/'+p['database'] and u.hostname=='10.77.0.20' and u.port==5432 and parse_qs(u.query).get('sslmode')==['verify-full'] and '\n' not in dsn and '\r' not in dsn and bool(u.username) and bool(u.password),'fixed_private_source_database')
 c.need(env.get('JOBMAN_CONTROL_DIAGNOSTIC_DEPLOYMENT_ID')==p['deployment'] and env.get('JOBMAN_CONTROL_DIRECTORY_MODE')=='enforce' and env.get('JOBMAN_CONTROL_MIGRATE_ON_START')=='false' and env.get('JOBMAN_CONTROL_DIRECTORY_CONFIG_FILE')==str(root/'directory.json'),'source_environment_pins')
 # Completed diagnostic-fixture.json is valid evidence. Only its distinct
 # pending .diagnostic-prepare.json blocks a new source mutation.
 for pattern in ('.directory-acceptance-*.json','.diagnostic-prepare.json'):
  c.need(not list(root.glob(pattern)) and not list(directory.glob(pattern)),'unfinished_source_operation')
 return files,raw,dsn

def stage_binary(payload):
 before=processes();raw=base64.b64decode(payload['binary'],validate=True)
 c.need(0<len(raw)<=32<<20 and c.sha(raw)==c.BINARY_SHA,'helper_binary_hash')
 for path in (Path('/usr'),Path('/usr/local'),Path('/usr/local/libexec')):c.directory(path,0o755)
 for path in (c.BINARY.parent.parent,c.BINARY.parent):c.directory(path,0o755,True)
 if c.BINARY.exists():c.need(c.read(c.BINARY,32<<20,uid=0,mode=0o755)==raw,'existing_helper_differs')
 else:c.put(c.BINARY,raw,0o755)
 c.need(processes()==before,'service_changed_during_stage')
 c.directory(c.RECEIPTS,create=True)
 receipt={'commit':c.COMMIT,'sha256':c.BINARY_SHA,'path':str(c.BINARY),'owner':0,'mode':'0755','servicesPreserved':True}
 c.retain(c.RECEIPTS/'binary-stage.json',c.encoded(receipt));return receipt

def source_preflight(profile):
 files,_,_=source_files(profile);p=c.PROFILES[profile]
 free=os.statvfs('/var/lib');c.need(free.f_bavail*free.f_frsize>=1<<30,'source_storage_headroom')
 for root in (Path(p['root']),Path(p['directory'])):
  c.need(not (root/'.scale-seed.pending.json').exists() and not (root/'.scale-seed.completed.json').exists(),'scale_already_started')
 observed=processes()
 c.need(observed['jobman-dashboard-lab-control'+('-secondary' if profile=='secondary' else '')]['uid']==p['uid'] and observed['jobman-dashboard-lab-directory'+('-secondary' if profile=='secondary' else '')]['uid']==p['directoryUID'],'source_service_identity')
 return {'epoch':int(time.time()),'files':files,'processes':observed}

def sql(profile,query):
 p=c.PROFILES[profile]
 return c.decode(c.run(['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-q','-A','-t','-U','jobman_control','-v','ON_ERROR_STOP=1','-d',p['database']],
  ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='8s'; SET LOCAL lock_timeout='500ms'; "+query+' ROLLBACK;').encode(),timeout=12))

def database_snapshot(profile,value,baseline=None):
 p=c.PROFILES[profile];c.validate_input(value,profile)
 subjects=','.join("'"+u['subject']+"'" for u in value['users'])
 if baseline is None:condition="n.name NOT LIKE 'dashboard-scale-%'"
 else:
  ids=baseline['namespaceIds'];c.need(isinstance(ids,list) and 1<=len(ids)<=100 and all(c.UUID.fullmatch(v) for v in ids),'baseline_namespace_bound');condition='n.id IN ('+','.join("'"+v+"'::uuid" for v in ids)+')'
 query="""SELECT json_build_object('database',current_database(),'instance',(SELECT id::text FROM control_instance),
 'epoch',(SELECT restore_epoch::text FROM service_recovery_state WHERE singleton),
 'ledgerSHA256',(SELECT encode(sha256(convert_to(string_agg(version||':'||checksum,E'\\n' ORDER BY version),'UTF8')),'hex') FROM schema_migrations),
 'migrations',(SELECT count(*) FROM schema_migrations),
 'namespaceIds',(SELECT json_agg(id ORDER BY id) FROM (SELECT n.id FROM namespaces n WHERE """+condition+""" ORDER BY n.id LIMIT 101) x),
 'namespaceSHA256',(SELECT encode(sha256(convert_to(coalesce(string_agg(n.id::text||':'||n.name,E'\\n' ORDER BY n.id),''),'UTF8')),'hex') FROM namespaces n WHERE """+condition+"""),
 'jobs',(SELECT json_build_object('count',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(identity,E'\\n' ORDER BY identity COLLATE "C"),''),'UTF8')),'hex')) FROM (
 SELECT json_build_array(j.id::text,j.namespace_id::text,j.owner_principal_id::text,j.created_at::text,j.name,j.imported,j.request_digest,j.workload_digest)::text AS identity
 FROM jobs j JOIN namespaces n ON n.id=j.namespace_id WHERE """+condition+""" LIMIT 50001) x),
 'namespaceTotal',(SELECT count(*) FROM namespaces),
 'scaleNamespaces',(SELECT count(*) FROM namespaces WHERE name LIKE 'dashboard-scale-%'),
 'scalePrincipals',(SELECT count(*) FROM principals WHERE issuer='https://oidc.lab.test:8443/realms/jobman-lab' AND subject IN ("""+subjects+""")),
 'connectionHeadroom',(SELECT current_setting('max_connections')::int-count(*)-current_setting('superuser_reserved_connections')::int FROM pg_stat_activity),
 'databaseBytes',pg_database_size(current_database()));"""
 result=sql(profile,query)
 c.need(result['database']==p['database'] and result['instance']==p['instance'] and result['epoch']=='1' and result['migrations']==21 and c.HEX.fullmatch(result['ledgerSHA256']) and 1<=len(result['namespaceIds'])<=100 and result['jobs']['count']<=50000 and 0<result['databaseBytes']<=1<<30,'bounded_source_database')
 if baseline is None:
  c.need(result['scaleNamespaces']==result['scalePrincipals']==0 and result['namespaceTotal']==len(result['namespaceIds']),'scale_database_collision')
  c.need(result['connectionHeadroom']>=8,'database_connection_headroom')
 else:
  for key in ('database','instance','epoch','ledgerSHA256','migrations','namespaceIds','namespaceSHA256','jobs'):c.need(result[key]==baseline[key],'old_source_metadata_changed')
  c.need(result['scaleNamespaces']==p['count'] and result['scalePrincipals']==25 and result['namespaceTotal']==baseline['namespaceTotal']+p['count'],'new_scale_metadata_missing')
  counts=sql(profile,"""SELECT coalesce(json_agg(row_to_json(x) ORDER BY name),'[]') FROM (
   SELECT n.name,count(j.id) AS total,count(j.id) FILTER(WHERE j.phase='accepted' AND NOT j.imported) AS active,
   count(j.id) FILTER(WHERE j.imported AND j.outcome='success' AND j.completed_provenance='history_import') AS imported,
   (SELECT count(*) FROM runs r JOIN jobs k ON k.id=r.job_id WHERE k.namespace_id=n.id) AS runs,
   (SELECT count(*) FROM executions e WHERE e.namespace_id=n.id) AS executions,
   (SELECT count(*) FROM agents a JOIN target_generations g ON g.id=a.target_generation_id JOIN targets t ON t.id=g.target_id WHERE t.namespace_id=n.id) AS agents,
   (SELECT count(*) FROM outbox o WHERE o.namespace_id=n.id AND o.topic='monitoring.job_terminal.v1') AS events
   FROM namespaces n JOIN jobs j ON j.namespace_id=n.id WHERE n.name LIKE 'dashboard-scale-%' GROUP BY n.id,n.name LIMIT 11) x;""")
  c.need([v['name'] for v in counts]==c.names(profile) and all(v=={'name':name,'total':10050,'active':50,'imported':10000,'runs':0,'executions':0,'agents':0,'events':0} for name,v in zip(c.names(profile),counts)),'scale_no_execution_counts')
  result['scaleCounts']=counts
 return result

def seed_outputs(profile,value,root,baseline):
 p=c.PROFILES[profile];source=Path(p['root']);files,raw,_=source_files(profile)
 c.need(files==baseline['files'] and processes()==baseline['processes'],'source_baseline_changed')
 names=('seed.json','directory.after.json','directory-state.after.json','receipt.json')
 output={name:c.read(root/'output'/name) for name in names};seed=c.decode(output['seed.json']);receipt=c.decode(output['receipt.json'])
 expected={'version':1,'synthetic':True,'helperCommit':c.COMMIT,'instanceId':p['instance'],'deploymentId':p['deployment'],
 'inputSHA256':c.sha(c.encoded(value)),'directorySHA256':files[str(source/'directory.json')],
 'directoryStateSHA256':files[str(Path(p['directory'])/'directory-state.json')],'output':str(root/'output')}
 c.need(receipt==expected and c.decode(c.read(source/'.scale-seed.pending.json'))==expected and c.decode(c.read(source/'.scale-seed.completed.json'))==expected,'helper_completion_receipt')
 c.need(seed['version']==1 and seed['synthetic'] is True and seed['mode']=='imported-history-no-execution' and seed['deploymentId']==p['deployment'] and seed['instanceId']==p['instance'] and seed['recoveryEpoch']=='1' and seed['historyAt']==value['historyAt'] and len(seed['namespaces'])==p['count'] and len(seed['identities'])==25,'seed_result_shape')
 ids=[]
 for i,row in enumerate(seed['namespaces']):
  c.need(row['name']==c.names(profile)[i] and row['activeJobs']==50 and row['importedHistory']==10000 and all(c.UUID.fullmatch(row[k]) for k in ('id','activeJobId','importedJobId')) and row['activeJobId']!=row['importedJobId'],'scale_namespace_shape');ids.append(row['id'])
 c.need(len(set(ids))==len(ids),'duplicate_scale_namespace')
 c.need(len({v['principalId'] for v in seed['identities']})==25,'duplicate_scale_principal')
 for original,new in zip(value['users'],seed['identities']):
  c.need(set(new)=={'directoryId','principalId','issuer','subject','displayName','aliases'} and new['aliases'] is None and new['directoryId']==original['directoryId'] and new['subject']==original['subject'] and new['displayName']==original['name'] and new['issuer']==c.ISSUER and c.UUID.fullmatch(new['principalId']),'seed_principal_binding')
 before=c.decode(raw[str(source/'directory.json')]);state=c.decode(raw[str(Path(p['directory'])/'directory-state.json')]);after=c.decode(output['directory.after.json']);next_state=c.decode(output['directory-state.after.json'])
 validate_drafts(profile,before,state,after,next_state,seed)
 return output

def validate_drafts(profile,before,state,after,next_state,seed):
 # Construct exactly the helper's documented additive transform; no baseline
 # field, membership, alias, bind file or approval is permitted to disappear.
 expected=c.decode(c.encoded(before));members=c.decode(c.encoded(state));m=expected['mapping'];m['revision']+=1;members['revision']+=1
 for key in ('identities','namespaces','approvedTransitions','bindings'):m[key]=list(m.get(key) or [])
 m['identities'].extend(seed['identities']);guids=[v['directoryId'] for v in seed['identities']]
 members['users'].extend({'directoryId':v,'enabled':True} for v in guids)
 for i,row in enumerate(seed['namespaces']):
  group='78000000-0000-4000-8000-%012d'%((101 if profile=='primary' else 201)+i)
  m['namespaces'].append(row['id']);m['approvedTransitions'].append(row['id']);m['bindings'].append({'groupId':group,'namespaceId':row['id'],'role':'viewer'});members['groups'].append({'id':group,'members':guids[:]})
 c.need(after==expected and next_state==members,'directory_draft_not_exactly_additive')

def source_seed(payload,verify=False):
 profile=payload['profile'];p=c.PROFILES[profile];value=payload['input'];c.validate_input(value,profile)
 c.need(c.HEX.fullmatch(payload['executionId']),'execution_id')
 c.directory(c.RECEIPTS,create=not verify);root=c.RECEIPTS/payload['executionId'];c.directory(root,create=not verify)
 intent={'profile':profile,'executionId':payload['executionId'],'baselineSHA256':c.sha(c.encoded(payload['baseline'])),'inputSHA256':c.sha(c.encoded(value)),'implementationSHA256':payload['implementationSHA256']}
 if verify:c.need(c.read(root/'intent.json')==c.encoded(intent),'verification_intent_missing')
 else:c.retain(root/'intent.json',c.encoded(intent))
 lock=root/'.lock';fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 try:
  os.fchmod(fd,0o600);st=os.fstat(fd);c.need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1,'seed_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  c.need(c.sha(c.read(c.BINARY,32<<20,uid=0,mode=0o755))==c.BINARY_SHA,'staged_helper_changed')
  if not verify and not (root/'completed.json').exists():
   c.need(not (root/'pending.json').exists(),'seed_pending_requires_inspection')
   current=source_preflight(profile);c.need(current['files']==payload['baseline']['files'] and current['processes']==payload['baseline']['processes'],'source_preflight_drift')
   c.put(root/'pending.json',c.encoded(intent));_,_,dsn=source_files(profile)
   c.put(root/'input.json',c.encoded(value));c.put(root/'database-url',dsn.encode()+b'\n');c.directory(root/'output',create=True)
   args=[str(c.BINARY),'scale','--profile',p['cli'],'--root',p['root'],'--config',str(root/'input.json'),'--database-url-file',str(root/'database-url'),'--output',str(root/'output')]
   if profile=='secondary':args+=['--directory-root',p['directory']]
   c.run(args,timeout=490,env={'PATH':'/usr/bin:/bin','GOMAXPROCS':'2','GOMEMLIMIT':'512MiB'})
  else:c.need((root/'pending.json').exists(),'missing_seed_start_evidence')
  c.need(c.read(root/'pending.json')==c.encoded(intent),'seed_pending_intent_changed')
  output=seed_outputs(profile,value,root,payload['baseline'])
  result={'profile':profile,'executionId':payload['executionId'],'helperCommit':c.COMMIT,'helperSHA256':c.BINARY_SHA,'outputSHA256':{k:c.sha(v) for k,v in output.items()},'sourceStatePreserved':True}
  c.retain(root/'completed.json',c.encoded(result))
  return {'receipt':result,'files':{k:base64.b64encode(v).decode() for k,v in output.items()}}
 finally:os.close(fd)

def execute(payload):
 os.umask(0o077);c.need(os.geteuid()==0,'root_required');phase=payload['phase'];host=os.uname().nodename.split('.')[0]
 c.need(phase in ('stage','source-preflight','database-preflight','database-verify','seed','verify'),'phase_not_allowed')
 c.need(host==('pg01' if phase.startswith('database-') else 'control01'),'fixed_guest_required')
 if phase=='stage':c.need(payload.get('apply') is True,'apply_required');return stage_binary(payload)
 profile=payload['profile'];c.need(profile in c.PROFILES,'fixed_profile_required');c.validate_input(payload['input'],profile)
 if phase=='source-preflight':return source_preflight(profile)
 if phase=='database-preflight':
  free=os.statvfs('/var/lib');c.need(free.f_bavail*free.f_frsize>=2<<30,'database_storage_headroom')
  return database_snapshot(profile,payload['input'])
 if phase=='database-verify':return database_snapshot(profile,payload['input'],payload['baseline'])
 c.need(payload.get('apply') is True or phase=='verify','apply_required')
 return source_seed(payload,phase=='verify')
