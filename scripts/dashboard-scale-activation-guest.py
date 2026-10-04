#!/usr/bin/env python3
"""Fixed Lab activation effects. No source seeding, migrations or direct grants."""
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import time

# The host supplies only the exact hash-bound reviewed modules.
a=activation;c=a.c;r=runtime


def process(unit):
 r.run(['systemctl','is-active','--quiet',unit],'service_not_active',timeout=3)
 values=dict(line.split('=',1) for line in r.run(['systemctl','show',unit,'--property=MainPID','--property=ExecMainStartTimestampMonotonic','--property=DropInPaths'],'service_properties',timeout=3).decode().splitlines())
 c.need(values['DropInPaths']=='' and all(values[k].isdigit() and int(values[k])>0 for k in ('MainPID','ExecMainStartTimestampMonotonic')),'service_identity')
 pid=values['MainPID'];exe=Path(os.readlink('/proc/'+pid+'/exe'))
 return dict(values,uid=Path('/proc',pid).stat().st_uid,exe=str(exe),binarySHA256=c.sha(r.read(exe,0,0o755,128<<20)),unitSHA256=c.sha(r.read(Path('/etc/systemd/system')/(unit+'.service'),0,0o644)))


def source_pin(profile):
 p=a.PROFILES[profile];source=process(p['unit']);ldap=process(p['ldapUnit'])
 c.need(source['uid']==p['uid'] and source['exe']==p['binary'] and source['binarySHA256']==a.SOURCE_BINARY_SHA,'source_binary_pin')
 c.need(ldap['uid']==p['directoryUID'] and ldap['exe']==str(c.BINARY) and ldap['binarySHA256']==c.BINARY_SHA,'reviewed_ldap_upgrade_required')
 files={str(Path(p['root'])/name):c.sha(r.read(Path(p['root'])/name,p['uid'])) for name in ('control.env','fixture-info.json','fixture-ca.crt')}
 return {'source':source,'ldap':ldap,'files':files}


def role(role):
 value=r.process(role);r.observations(role,7)
 return value


def material_hashes(config,uid):
 result={}
 def visit(value):
  if isinstance(value,dict):
   for key,item in value.items():
    if key.endswith('File') and isinstance(item,str) and item:
     path=Path(item);s=path.lstat();c.need(s.st_uid in (0,uid) and s.st_gid==s.st_uid and stat.S_IMODE(s.st_mode) in (0o600,0o644),'configured_material_identity')
     result[item]={'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode),'sha256':c.sha(r.read(path,s.st_uid,stat.S_IMODE(s.st_mode),1<<20))}
    else:visit(item)
  elif isinstance(value,list):
   for item in value:visit(item)
 visit(config);c.need(len(result)<=128,'material_file_bound');return result


def snapshot(host):
 result={'epoch':int(time.time())}
 if host=='control01':
  result['sources']={};result['sourcePins']={}
  for name,p in a.PROFILES.items():
   result['sourcePins'][name]=source_pin(name)
   result['sources'][name]={key:a.encoded_file(r.read(path,uid)) for key,path,uid in [('directory',Path(p['root'])/'directory.json',p['uid']),('state',Path(p['directory'])/'directory-state.json',p['directoryUID']),('registry',Path(p['root'])/'delegation.json',p['uid'])]}
  result['preserved']={unit:process(unit) for unit in ('jobman-control','jobman-keycloak')}
  result['roles']={'broker':role('broker')};result['runtime']={'broker':a.encoded_file(r.read(Path(a.ROLE_PATHS['broker']),21901))}
 else:
  result['roles']={name:role(name) for name in ('api','worker')}
  result['runtime']={name:a.encoded_file(r.read(Path(a.ROLE_PATHS[name]),a.ROLE_UIDS[name])) for name in ('api','worker','operator')}
  result['runtime']['recovery']=a.encoded_file(r.read(a.RECOVERY_BEFORE,0))
  c.need(not a.RECOVERY_AFTER.exists(),'activation_recovery_path_exists')
 result['runtimeProcesses']={name:process(r.SPECS[name][4]) for name in result['roles']}
 result['materials']={name:material_hashes(a.document(raw),a.ROLE_UIDS[name]) for name,raw in result['runtime'].items() if name!='recovery'}
 return result


def query(database,text):
 c.need(database in ('jobman_dashboard',*[p['database'] for p in a.PROFILES.values()]),'sql_database_boundary')
 body=("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='500ms'; "+text+' ROLLBACK;').encode()
 return c.decode(r.run(['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-qAt','-v','ON_ERROR_STOP=1','-U','jobman_control','-d',database],'read_only_database',input_data=body,timeout=8,maximum=256<<10))


def database():
 return query('jobman_dashboard',"""SELECT json_build_object('database',current_database(),'migrations',(SELECT count(*) FROM dashboard_schema_migrations),
 'hold',(SELECT json_build_object('generation',generation,'held',held,'restoreRecordedThrough',restore_recorded_through) FROM dashboard_notification_delivery_control WHERE singleton),
 'identities',COALESCE((SELECT json_agg(json_build_object('deploymentId',deployment_id,'instanceId',control_instance_id,'epoch',recovery_epoch,'revision',configuration_revision) ORDER BY deployment_id) FROM dashboard_source_identities),'[]'::json),
 'feeds',COALESCE((SELECT json_agg(json_build_object('deploymentId',deployment_id,'namespaces',namespace_ids,'status',status,'generation',generation,'lastPosition',last_position,'instanceId',convert_from(checkpoint,'UTF8')::jsonb->>'controlInstanceId','epoch',convert_from(checkpoint,'UTF8')::jsonb->>'recoveryEpoch') ORDER BY deployment_id) FROM dashboard_event_feeds),'[]'::json),
 'openGaps',(SELECT count(*) FROM dashboard_event_gaps WHERE resolved_at IS NULL),
 'unfinishedRecoveries',(SELECT count(*) FROM dashboard_event_recoveries WHERE status IN ('replaying','ready','quarantined')),
 'bindingCount',(SELECT count(*) FROM dashboard_notification_device_bindings),
 'bindingSHA256',(SELECT encode(sha256(convert_to(COALESCE(string_agg(to_jsonb(b)::text,E'\\n' ORDER BY id),''),'UTF8')),'hex') FROM (SELECT * FROM dashboard_notification_device_bindings ORDER BY id LIMIT 201) b));""")


def authority(profile,payload,baseline=False):
 p=a.PROFILES[profile];after=payload['plan']['sources'][profile];mapping=a.document(after['directory'])['mapping'];seed=a.document(payload['handoffs'][profile]['seed.json'])
 ns=[row['id'] for row in seed['namespaces']];principals=[row['principalId'] for row in seed['identities']]
 c.need(all(c.UUID.fullmatch(v) for v in ns+principals),'authority_id_bound')
 quoted=lambda values:','.join("'"+v+"'::uuid" for v in values)
 ids=quoted(ns);accounts=quoted(principals)
 value=query(p['database'],"""SELECT json_build_object('database',current_database(),'instance',(SELECT id::text FROM control_instance),'epoch',(SELECT restore_epoch::text FROM service_recovery_state),'migrations',(SELECT count(*) FROM schema_migrations),
 'mapping',(SELECT mapping FROM directory_sources WHERE source_id='"""+p['sourceId']+"""'),
 'sourceFresh',(SELECT COALESCE(last_verified_at>statement_timestamp()-interval '90 seconds' AND last_verified_at<=statement_timestamp()+interval '5 seconds',false) FROM directory_sources WHERE source_id='"""+p['sourceId']+"""'),
 'accountsFresh',(SELECT count(*) FROM directory_accounts WHERE source_id='"""+p['sourceId']+"""' AND enabled AND last_verified_at>statement_timestamp()-interval '90 seconds' AND last_verified_at<=statement_timestamp()+interval '5 seconds'),
 'namespacesFresh',(SELECT count(*) FROM namespace_directory_state WHERE source_id='"""+p['sourceId']+"""' AND configuration_revision="""+str(mapping['revision'])+""" AND last_verified_at>statement_timestamp()-interval '90 seconds' AND last_verified_at<=statement_timestamp()+interval '5 seconds'),
 'aliases',(SELECT COALESCE(json_agg(json_build_object('directoryId',directory_id,'principalId',principal_id,'issuer',issuer,'subject',subject) ORDER BY directory_id),'[]') FROM principal_aliases WHERE source_id='"""+p['sourceId']+"""'),
 'viewerPairs',(SELECT count(*) FROM authorized_memberships WHERE namespace_id IN ("""+ids+""") AND principal_id IN ("""+accounts+""") AND roles=ARRAY['viewer']::text[]),
 'unexpectedNewGrants',(SELECT count(*) FROM authorized_memberships WHERE principal_id IN ("""+accounts+""") AND (namespace_id NOT IN ("""+ids+""") OR roles!=ARRAY['viewer']::text[])),
 'originalGrants',(SELECT COALESCE(json_agg(json_build_array(namespace_id,principal_id,roles) ORDER BY namespace_id,principal_id),'[]') FROM authorized_memberships WHERE namespace_id NOT IN ("""+ids+""")) );""")
 c.need(value['database']==p['database'] and value['instance']==p['instance'] and value['epoch']=='1' and value['migrations']==21,'source_authority_identity')
 original_sha=c.sha(c.encoded(value['originalGrants']))
 if baseline:return {'profile':profile,'originalGrantSHA256':original_sha}
 c.need(value['mapping']==mapping and value['sourceFresh'] is True and value['accountsFresh']==27 and value['namespacesFresh']==p['count']+2 and value['viewerPairs']==25*p['count'] and value['unexpectedNewGrants']==0,'current_viewer_authority_required')
 c.need(original_sha==payload['snapshot']['oldAuthority'][profile]['originalGrantSHA256'],'original_namespace_grants_changed')
 aliases=[{key:row[key] for key in ('directoryId','principalId','issuer','subject')} for row in mapping['identities']]
 c.need(sorted(value['aliases'],key=lambda row:(row['directoryId'],row['issuer'],row['subject']))==sorted(aliases,key=lambda row:(row['directoryId'],row['issuer'],row['subject'])),'canonical_alias_proof')
 return {'profile':profile,'epoch':int(time.time()),'mappingRevision':mapping['revision'],'viewerPairs':value['viewerPairs'],'originalGrantSHA256':original_sha}


def lock(root):
 path=root/'.lock'
 try:fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.fchmod(fd,0o600)
 except FileExistsError:fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
 s=os.fstat(fd);c.need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'private_guest_lock');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return fd


def retain(path,value):
 raw=c.encoded(value)
 if path.exists():c.need(r.read(path,0)==raw,'receipt_changed')
 else:r.put(path,raw)


def begin(root,phase,binding):
 done=root/(phase+'.json');pending=root/(phase+'.pending.json')
 if pending.exists():c.need(c.decode(r.read(pending,0))==binding,'phase_intent_changed')
 elif done.exists():raise c.Failure('completion_missing_intent')
 else:r.put(pending,c.encoded(binding))
 if done.exists():return c.decode(r.read(done,0))
 return None


def swap(root,label,path,before,after,uid,binding):
 before=a.raw(before);after=a.raw(after);current=r.read(path,uid);done=begin(root,label,binding);backup=root/(label+'.before')
 if done is not None:c.need(current==after and done==binding,'completed_swap_changed');return
 if not backup.exists():c.need(current==before,'before_backup_requires_original');r.put(backup,before)
 c.need(r.read(backup,0)==before and current in (before,after),'swap_compare_and_set')
 if current==before:
  temp=path.parent/('.scale-'+binding['executionId']+'-'+label+'.tmp')
  if temp.exists():c.need(r.read(temp,uid)==after,'staged_bytes_changed')
  else:r.put(temp,after,uid)
  c.need(r.read(path,uid)==before,'config_changed_before_rename');os.replace(temp,path);r.sync(path.parent)
 c.need(r.read(path,uid)==after,'config_bytes_not_applied');retain(root/(label+'.json'),binding)


def phase_binding(payload,phase):
 return {'executionId':payload['executionId'],'phase':phase,'planSHA256':c.sha(c.encoded(payload['plan']))}


def seed_evidence(payload):
 for profile,p in a.PROFILES.items():
  handoff=payload['handoffs'][profile];driver=a.document(handoff['driver-receipt.json']);receipt=a.document(handoff['receipt.json']);root=c.RECEIPTS/driver['executionId']
  c.need(c.decode(r.read(root/'completed.json',0))==driver,'seed_guest_completion')
  intent=c.decode(r.read(root/'intent.json',0));c.need(intent['profile']==profile and intent['executionId']==driver['executionId'] and intent['implementationSHA256']==a.SOURCE_IMPLEMENTATION_SHA and intent['inputSHA256']==receipt['inputSHA256'],'seed_guest_implementation')
  c.need(c.decode(r.read(root/'pending.json',0))==intent,'seed_guest_pending')
  for name in ('.scale-seed.pending.json','.scale-seed.completed.json'):c.need(c.decode(r.read(Path(p['root'])/name,0))==receipt,'seed_helper_completion')
  for name,digest in driver['outputSHA256'].items():c.need(c.sha(r.read(root/'output'/name,0))==digest,'seed_immutable_output_changed')


def restart_chain(root,labels,current,baseline,payload):
 expected=baseline
 for label,phase in labels:
  bound=phase_binding(payload,phase);done=root/(label+'.json');pending=root/(label+'.pending.json');started=root/(label+'.started.json')
  if done.exists():
   record=c.decode(r.read(done,0));c.need(c.decode(r.read(pending,0))==bound and c.decode(r.read(started,0))=={'binding':bound,'process':expected} and record['binding']==bound,'restart_receipt_binding')
   expected=record['process'];continue
  if pending.exists() or started.exists():
   c.need(c.decode(r.read(pending,0))==bound and c.decode(r.read(started,0))=={'binding':bound,'process':expected},'restart_pending_binding')
   # Only this unfinished restart can explain a different PID. No completed
   # historical intent permits a later unrelated restart to be adopted.
   for key in ('uid','exe','binarySHA256','unitSHA256'):c.need(current[key]==expected[key],'pending_restart_identity')
   return
 c.need(current==expected,'unexplained_service_restart')


def preserved(payload,host):
 baseline=payload['snapshot'];observed=baseline['hosts'][host]
 for role,files in observed['materials'].items():
  for path,record in files.items():c.need(c.sha(r.read(Path(path),record['uid'],record['mode']))==record['sha256'],'runtime_material_changed')
 if host=='control01':
  seed_evidence(payload)
  for unit,original in observed['preserved'].items():c.need(process(unit)==original,'original_service_changed')
  for profile,pin in observed['sourcePins'].items():
   p=a.PROFILES[profile];current=source_pin(profile)
   c.need(current['ldap']==pin['ldap'] and current['files']==pin['files'],'directory_process_or_immutable_source_changed')
   for key in ('uid','exe','binarySHA256','unitSHA256'):c.need(current['source'][key]==pin['source'][key],'source_runtime_identity_changed')


def restart(root,label,unit,before,pin,ready,binding):
 done=begin(root,label,binding)
 if done is not None:c.need(process(unit)==done['process'] and done['binding']==binding,'completed_restart_changed');ready();return
 pending=root/(label+'.started.json')
 if pending.exists():c.need(c.decode(r.read(pending,0))=={'binding':binding,'process':before},'restart_start_intent_changed')
 if not pending.exists():
  c.need(process(unit)==before,'restart_baseline_drift');retain(pending,{'binding':binding,'process':before})
  r.run(['systemctl','--no-block','restart',unit],'restart_'+label.replace('-','_'),timeout=5)
 deadline=time.monotonic()+40
 while True:
  try:
   value=process(unit);c.need(value['ExecMainStartTimestampMonotonic']!=before['ExecMainStartTimestampMonotonic'],'restart_not_observed');pin(value);ready();break
  except (ValueError,OSError):c.need(time.monotonic()<deadline,'startup_not_ready_'+label.replace('-','_'));time.sleep(.25)
 retain(root/(label+'.json'),{'binding':binding,'process':value})


def source_ready(profile):
 p=a.PROFILES[profile]
 cap=c.decode(r.run(['runuser','-u',p['user'],'--','curl','--silent','--fail','--max-time','2','--cacert',str(Path(p['root'])/'fixture-ca.crt'),'https://127.0.0.1:'+str(p['port'])+'/v1/capabilities'],'source_capabilities',timeout=3))['capabilities']
 c.need(cap['instanceId']==p['instance'] and cap['recoveryEpoch']=='1','source_identity_changed')


def cli(payload,command,*args):
 binary=payload['snapshot']['hosts']['storage01']['roles']['api']['binary']
 config=a.RECOVERY_BEFORE if command in ('hold','hold-status') and not a.RECOVERY_AFTER.exists() else a.RECOVERY_AFTER
 return c.decode(r.run([binary,'events',command,'--config',str(config),*args],'operator_'+command.replace('-','_'),timeout=140,maximum=256<<10))


def hold_guard(payload):
 actual=cli(payload,'hold-status');expected=payload['held']
 c.need(actual==expected and actual['held'] is True,'exact_durable_hold_required');return actual


def same_hold(actual,expected):return a.same_hold(actual,expected)


def guards(payload,host):
 c.need(host in ('control01','storage01'),'guard_host');preserved(payload,host);root=a.ROOT/payload['executionId'];snapshot_value=payload['snapshot'];plan=payload['plan']
 def current(path,uid,before,after,label,phase):
  actual=r.read(path,uid);original=a.raw(before);updated=a.raw(after)
  c.need(actual in (original,updated),'guard_file_drift')
  if actual!=original:
   pending=c.decode(r.read(root/(label+'.pending.json'),0))
   c.need(pending=={'executionId':payload['executionId'],'phase':phase,'planSHA256':c.sha(c.encoded(plan))},'changed_file_requires_exact_pending')
 if host=='control01':
  for name,p in a.PROFILES.items():
   for key in ('directory','state','registry'):
    phase=('trust-' if key=='registry' else 'directory-')+name
    path=Path(p['directory'])/'directory-state.json' if key=='state' else Path(p['root'])/('directory.json' if key=='directory' else 'delegation.json')
    current(path,p['directoryUID'] if key=='state' else p['uid'],snapshot_value['sources'][name][key],plan['sources'][name][key],phase+'-'+key,phase)
   original=source_pin(name)['source'];expected=snapshot_value['hosts'][host]['sourcePins'][name]['source']
   restart_chain(root,[(prefix+name+'-restart',prefix+name) for prefix in ('directory-','trust-')],original,expected,payload)
 else:
  c.need(r.read(a.RECOVERY_BEFORE,0)==a.raw(snapshot_value['runtime']['recovery']),'original_operator_config_changed')
  if a.RECOVERY_AFTER.exists():c.need(r.read(a.RECOVERY_AFTER,0)==a.raw(plan['runtime']['recovery']),'new_operator_config_changed')
  state=r.run(['systemctl','show',r.SPECS['worker'][4],'--property=ActiveState','--value'],'worker_guard_state',timeout=3).decode().strip()
  c.need(state in ('active','inactive'),'worker_transition_in_progress')
  if payload.get('workerStopped') is True:c.need(state=='inactive','worker_must_stay_stopped')
  if state=='inactive':c.need(c.decode(r.read(root/'stop-worker.pending.json',0))==phase_binding(payload,'stop-worker'),'worker_stop_intent_required')
  elif (root/'restart-worker.json').exists():
   completed=c.decode(r.read(root/'restart-worker.json',0));c.need(completed['binding']==phase_binding(payload,'restart-worker') and process(r.SPECS['worker'][4])==completed['process'],'completed_worker_start_changed')
  elif (root/'restart-worker.started.json').exists():c.need(c.decode(r.read(root/'restart-worker.started.json',0))==phase_binding(payload,'restart-worker') and r.process('worker')==snapshot_value['hosts'][host]['roles']['worker'],'pending_worker_start_identity')
  else:c.need(process(r.SPECS['worker'][4])==snapshot_value['hosts'][host]['runtimeProcesses']['worker'],'unexpected_worker_start')
 for name in snapshot_value['hosts'][host]['roles']:
  if name!='worker':restart_chain(root,[('restart-'+name,'restart-'+name)],process(r.SPECS[name][4]),snapshot_value['hosts'][host]['runtimeProcesses'][name],payload)
  current(Path(a.ROLE_PATHS[name]),a.ROLE_UIDS[name],snapshot_value['runtime'][name],plan['runtime'][name],'runtime-'+name,'runtime-broker' if name=='broker' else 'runtime-storage')
 return {'host':host,'verified':True}


def execute(payload):
 host=payload['host'];phase=payload['phase'];c.need(os.geteuid()==0 and os.uname().nodename.split('.')[0]==host and host in ('control01','storage01','pg01'),'fixed_root_guest')
 if phase=='snapshot':c.need(host in ('control01','storage01'),'snapshot_host');return snapshot(host)
 if phase=='database':c.need(host=='pg01','read_only_pg_host');return database()
 c.need(phase in a.PHASES or phase in ('authority','authority-baseline','guards'),'fixed_phase');plan=payload['plan'];snapshot_value=payload['snapshot'];handoffs=payload['handoffs']
 execution=a.binding(snapshot_value,handoffs,plan,payload['implementationSHA256']);c.need(payload['executionId']==execution,'exact_plan_implementation_binding')
 if phase in ('authority','authority-baseline'):c.need(host=='pg01','read_only_authority_host');return authority(payload['profile'],payload,phase=='authority-baseline')
 if phase=='guards':return guards(payload,host)
 c.need(host!='pg01','database_mutation_forbidden')
 expected_host='control01' if phase.startswith(('directory-','trust-')) or phase in ('runtime-broker','restart-broker') else 'storage01'
 c.need(phase=='verify' or host==expected_host,'phase_host_boundary')
 if phase!='verify':c.need(payload.get('apply') is True,'explicit_apply_required')
 root=a.ROOT/execution
 for path in (a.ROOT,root):
  if not path.exists():c.need(phase!='verify','verification_receipt_missing');r.create_directory(path)
  r.private_directory(path)
 if phase=='verify':c.need((root/'.lock').exists() and (root/'plan.json').exists(),'verification_receipt_missing')
 fd=lock(root)
 try:
  bound={'executionId':execution,'phase':phase,'planSHA256':c.sha(c.encoded(plan))};retain(root/'plan.json',plan);preserved(payload,host)
  # Full cross-host DB/authority fences are performed and hash-bound by the
  # orchestrator before each phase; serving-host mutation also checks live hold.
  if host=='storage01' and phase not in ('hold','resume','verify'):hold_guard(payload)
  if phase=='hold':
   c.need(host=='storage01','hold_host');before=payload['snapshot']['database']['hold'];prior=(root/(phase+'.pending.json')).exists();done=begin(root,phase,bound);actual=cli(payload,'hold-status')
   if done is None:
    expected={'generation':str(before['generation']+1),'held':True}
    if before.get('restoreRecordedThrough') is not None:expected['restoreRecordedThrough']=before['restoreRecordedThrough']
    if actual['held'] is True:c.need(prior,'uncertain_hold_without_receipt')
    if actual['held'] is False:
     c.need(actual['generation']==str(before['generation']),'hold_generation_changed');actual=cli(payload,'hold','--generation',actual['generation'])
    c.need(same_hold(actual,expected),'ordinary_hold_changed_cutoff');retain(root/(phase+'.json'),actual)
   else:c.need(actual==done,'completed_hold_changed')
   return actual
  if phase=='stop-worker':
   c.need(host=='storage01','worker_host');prior=(root/(phase+'.pending.json')).exists();done=begin(root,phase,bound)
   if done is None:
    active=r.run(['systemctl','show',r.SPECS['worker'][4],'--property=ActiveState','--value'],'worker_state',timeout=3).decode().strip()
    if active!='active':c.need(prior,'uncertain_stop_without_receipt')
    if active=='active':c.need(r.process('worker')==snapshot_value['hosts'][host]['roles']['worker'],'worker_identity');r.run(['systemctl','stop',r.SPECS['worker'][4]],'stop_worker',timeout=40)
    c.need(r.run(['systemctl','show',r.SPECS['worker'][4],'--property=ActiveState','--value'],'worker_state',timeout=3).strip()==b'inactive','worker_not_stopped');retain(root/(phase+'.json'),bound)
   c.need(r.run(['systemctl','show',r.SPECS['worker'][4],'--property=ActiveState','--value'],'worker_state',timeout=3).strip()==b'inactive','completed_stop_changed')
   return {'stopped':True}
  if phase.startswith('directory-') or phase.startswith('trust-'):
   c.need(host=='control01','source_host');kind,profile=phase.split('-',1);p=a.PROFILES[profile];before=snapshot_value['sources'][profile];after=plan['sources'][profile]
   keys=('state','directory') if kind=='directory' else ('registry',)
   if kind=='trust':c.need(payload['authority'][profile]['viewerPairs']==p['count']*25 and 0<=time.time()-payload['authority'][profile]['epoch']<30,'recent_viewer_proof_required')
   for key in keys:
    path=Path(p['directory'])/'directory-state.json' if key=='state' else Path(p['root'])/('directory.json' if key=='directory' else 'delegation.json');uid=p['directoryUID'] if key=='state' else p['uid']
    swap(root,phase+'-'+key,path,before[key],after[key],uid,bound)
   baseline=snapshot_value['hosts'][host]['sourcePins'][profile]['source']
   if kind=='trust':baseline=c.decode(r.read(root/('directory-'+profile+'-restart.json'),0))['process']
   pin=lambda value:c.need(value['uid']==p['uid'] and value['exe']==p['binary'] and value['binarySHA256']==a.SOURCE_BINARY_SHA,'restarted_source_pin')
   restart(root,phase+'-restart',p['unit'],baseline,pin,lambda:source_ready(profile),bound)
   return {'profile':profile,'phase':phase,'sourceRestarted':True}
  if phase.startswith('runtime-'):
   roles=('api','worker') if phase=='runtime-storage' else ('broker',);c.need(host==('storage01' if len(roles)==2 else 'control01'),'runtime_host')
   for name in roles:
    swap(root,'runtime-'+name,Path(a.ROLE_PATHS[name]),snapshot_value['runtime'][name],plan['runtime'][name],a.ROLE_UIDS[name],bound)
    binary=snapshot_value['hosts'][host]['roles'][name]['binary'];mode=['--mode','check-config','--check-mode',name] if name!='broker' else ['--mode','check-config']
    r.run(['runuser','-u',r.SPECS[name][3],'--',binary,*mode,'--config',a.ROLE_PATHS[name]],'validate_'+name,timeout=25)
   if host=='storage01':
    retain(a.RECOVERY_AFTER,a.document(plan['runtime']['recovery']));r.run([snapshot_value['hosts'][host]['roles']['api']['binary'],'--mode','check-config','--check-mode','api','--config',str(a.RECOVERY_AFTER)],'validate_recovery',timeout=25)
   return {'revision':8,'roles':roles}
  if phase.startswith('restart-'):
   name=phase[len('restart-'):];c.need(name in ('api','worker','broker') and host==r.SPECS[name][0],'restart_host');expected=snapshot_value['hosts'][host]['roles'][name];unit=r.SPECS[name][4]
   c.need(r.read(Path(a.ROLE_PATHS[name]),a.ROLE_UIDS[name])==a.raw(plan['runtime'][name]),'restart_config_bytes')
   if name=='worker':
    done=begin(root,phase,bound)
    if done is None:
     started=root/(phase+'.started.json')
     if not started.exists():
      c.need(r.run(['systemctl','show',unit,'--property=ActiveState','--value'],'worker_start_state',timeout=3).strip()==b'inactive','worker_start_baseline');retain(started,bound)
      r.run(['systemctl','--no-block','start',unit],'start_worker',timeout=5)
     else:c.need(c.decode(r.read(started,0))==bound,'worker_start_intent_changed')
     r.await_ready(name,8,expected,timeout=40);retain(root/(phase+'.json'),{'binding':bound,'process':process(unit)})
    else:c.need(done['binding']==bound and process(unit)==done['process'],'completed_worker_start_changed');r.await_ready(name,8,expected,timeout=5)
   else:
    # Runtime process identity omits PID/start; explicitly pin the prior process
    # captured at snapshot for restart evidence.
    old=snapshot_value['hosts'][host]['runtimeProcesses'][name]
    restart(root,phase,unit,old,lambda _:c.need(r.process(name)==expected,'runtime_process_pin'),lambda:r.observations(name,8),bound)
   return {'role':name,'ready':True,'revision':8}
  if phase.startswith('recovery-'):
   c.need(host=='storage01','recovery_host');return recover(payload,root,bound)
  if phase=='resume':
   c.need(host=='storage01','resume_host');prior=(root/(phase+'.pending.json')).exists();done=begin(root,phase,bound);actual=cli(payload,'hold-status');held=payload['held']
   if done is None:
    if actual['held'] is False:c.need(prior,'uncertain_resume_without_receipt')
    if actual==held:actual=cli(payload,'resume','--generation',held['generation'],'--acknowledge-gap')
    c.need(actual['held'] is False and int(actual['generation'])==int(held['generation'])+1 and actual.get('restoreRecordedThrough')==held.get('restoreRecordedThrough'),'resume_generation_or_cutoff');retain(root/(phase+'.json'),actual)
   else:c.need(actual==done,'completed_resume_changed')
   return actual
  c.need(phase=='verify','unsupported_phase')
  if host=='storage01':a.resumed_hold(cli(payload,'hold-status'),payload['resumed'])
  if host=='control01':
   for profile,p in a.PROFILES.items():
    expected=c.decode(r.read(root/('trust-'+profile+'-restart.json'),0));c.need(process(p['unit'])==expected['process'],'verified_source_restart_changed');source_ready(profile)
    for key in ('directory','state','registry'):
     path=Path(p['directory'])/'directory-state.json' if key=='state' else Path(p['root'])/('directory.json' if key=='directory' else 'delegation.json')
     c.need(r.read(path,p['directoryUID'] if key=='state' else p['uid'])==a.raw(plan['sources'][profile][key]),'verified_source_bytes')
  for name in snapshot_value['hosts'][host]['roles']:
   c.need(r.read(Path(a.ROLE_PATHS[name]),a.ROLE_UIDS[name])==a.raw(plan['runtime'][name]),'verified_runtime_bytes');r.await_ready(name,8,snapshot_value['hosts'][host]['roles'][name],timeout=5)
  return {'host':host,'revision':8,'verified':True}
 finally:os.close(fd)


def recover(payload,root,bound):
 profile=payload['profile'];c.need(profile in a.PROFILES,'recovery_profile');step=payload['phase'];plan=payload['plan'];deployment=a.PROFILES[profile]['deployment'];prefix='recovery-'+profile
 planfile=root/(prefix+'-plan.json')
 if step=='recovery-plan':
  done=begin(root,prefix+'-plan',bound)
  if done is not None:a.validate_recovery(done,profile,plan);return done
  # A lost plan reply cannot be reconstructed from an assumed current head.
  marker=root/(prefix+'-command.pending.json');c.need(not marker.exists(),'uncertain_plan_requires_inspection')
  deadline=time.monotonic()+35
  while True:
   try:
    gap=cli(payload,'gap','--deployment',deployment);c.need(gap['status']=='paused' and c.UUID.fullmatch(gap['gapId']),'scope_binding_gap_required');break
   except ValueError:
    c.need(time.monotonic()<deadline,'scope_binding_gap_not_ready');time.sleep(1)
  retain(marker,{'gap':gap,'binding':bound});value=cli(payload,'plan','--deployment',deployment,'--gap',gap['gapId'],'--generation',gap['generation']);a.validate_recovery(value,profile,plan);retain(planfile,value);return value
 original=c.decode(r.read(planfile,0));current=cli(payload,'status','--recovery',original['id']);a.validate_recovery(current,profile,plan);c.need(current['digest']==original['digest'],'recovery_digest_changed')
 if step=='recovery-step':
  pages=int(current['pages']);c.need(current['status'] in ('replaying','ready') and pages<=500,'bounded_recovery_pages')
  if current['status']=='replaying':
   c.need(pages<500,'bounded_recovery_pages');limit=min(50,500-pages)
   current=cli(payload,'step','--recovery',current['id'],'--digest',current['digest'],'--pages',str(limit));a.validate_recovery(current,profile,plan)
   c.need(current['id']==original['id'] and current['digest']==original['digest'] and pages<=int(current['pages'])<=pages+limit,'recovery_step_bound')
  retain(root/(prefix+'-step-'+current['revision']+'.json'),current);return current
 if step=='recovery-reconcile':
  c.need(current['status']=='ready','recovery_not_ready');receipt=cli(payload,'reconcile','--recovery',current['id'],'--digest',current['digest']);c.need(receipt['planDigest']==current['digest'],'coverage_digest');value={'recovery':current,'reconciliation':receipt};a.validate_coverage(value,profile,plan,current);retain(root/(prefix+'-coverage-'+c.sha(c.encoded(value))+'.json'),value);return value
 c.need(step=='recovery-apply' and current['status'] in ('ready','applied'),'recovery_apply_state');coverage=payload['coverage'];digest=c.sha(c.encoded(coverage));c.need(digest==payload['coverageSHA256'] and coverage['recovery']['digest']==current['digest'] and coverage['reconciliation']['planDigest']==current['digest'],'reviewed_coverage_required')
 a.validate_coverage(coverage,profile,plan,current);c.need(payload['acknowledgeGap'] is True,'explicit_gap_acknowledgement');args=['--recovery',current['id'],'--digest',current['digest'],'--revision',current['revision'],'--acknowledge-gap']
 if payload.get('allowIncomplete') is True:args.append('--allow-incomplete')
 c.need(current['status']!='applied' or (root/(prefix+'-apply.pending.json')).exists(),'uncertain_apply_without_receipt')
 done=begin(root,prefix+'-apply',dict(bound,coverageSHA256=digest,allowIncomplete=payload.get('allowIncomplete') is True))
 if current['status']!='applied':current=cli(payload,'apply',*args)['recovery']
 a.validate_recovery(current,profile,plan);c.need(current['status']=='applied','recovery_not_applied');retain(root/(prefix+'-apply.json'),current);return current
