#!/usr/bin/env python3
"""Fixed identities and pure, hash-bound scale activation plan construction."""
import base64
import copy
import importlib.util
from pathlib import Path
import re

if 'source_common' not in globals():
 def load(name):
  spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
 source_common=load('dashboard-scale-source-common');scale_plan=load('dashboard-scale-plan')
c=source_common
ROOT=Path('/var/lib/jobman-dashboard-scale-activation')
RECOVERY_BEFORE=Path('/etc/jobman-dashboard-operator-lab/multisource-recovery.json')
RECOVERY_AFTER=Path('/etc/jobman-dashboard-operator-lab/scale-recovery.json')
PRIVILEGED_DSN='/etc/jobman-dashboard-app-lab/database-url'
SOURCE_IMPLEMENTATION_SHA='c788ff6f7f1301de573887092aaa578d24853088bfe643bbbe01d4ab56dad2bc'
SOURCE_MANIFEST_SHA='08bda5657bf052db70cfce15185f51d57d58fe37f13fe45189416f79a7a2bb23'
LEGACY_WEB_ROOT='/opt/jobman-dashboard-lab/releases/b8f25afdd90f83b4602f32440a89e74dfa866b6c/web'
SOURCE_BINARY_SHA='38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e'
PROFILES=copy.deepcopy(c.PROFILES)
for name,p in PROFILES.items():
 secondary=name=='secondary';suffix='-secondary' if secondary else ''
 p.update(unit='jobman-dashboard-lab-control'+suffix,ldapUnit='jobman-dashboard-lab-directory'+suffix,
  binary='/usr/local/libexec/'+('jobman-dashboard-secondary' if secondary else 'jobman-dashboard-lab')+'/jobman-control',
  sourceId='synthetic-dashboard-lab-secondary' if secondary else 'synthetic-dashboard-lab',port=28443 if secondary else 18443,
  user='jobman-dashboard-source2' if secondary else 'jobman-dashboard-source')
ROLE_PATHS={role:'/etc/jobman-dashboard-'+role+'-lab/config.json' for role in ('api','worker','broker','operator')}
ROLE_UIDS={'api':21904,'worker':21905,'broker':21901,'operator':0}
READ_PHASES={'snapshot','database','authority','verify'}
PHASES=('hold','stop-worker','directory-primary','directory-secondary','trust-primary','trust-secondary','runtime-storage','runtime-broker','restart-broker','restart-api','restart-worker','recovery-plan','recovery-step','recovery-reconcile','recovery-apply','resume','verify')


def raw(value):
 c.need(isinstance(value,str),'encoded_file_required');result=base64.b64decode(value,validate=True);c.need(0<len(result)<=1<<20,'encoded_file_bound');return result

def encoded_file(value):return base64.b64encode(value).decode()
def document(value):return c.decode(raw(value))


def additive_directory(profile,before,state,after,next_state,seed):
 expected=copy.deepcopy(before);members=copy.deepcopy(state);m=expected['mapping'];p=PROFILES[profile]
 c.need(m['sourceId']==p['sourceId'] and type(m['revision']) is int and type(members['revision']) is int,'directory_source_revision')
 c.need(len(m['identities'])==2 and len(m['namespaces'])==2 and len(state['users'])==2 and len(state['groups'])==8,'original_directory_bounds')
 m['revision']+=1;members['revision']+=1
 for key in ('identities','namespaces','approvedTransitions','bindings'):m[key]=list(m.get(key) or [])
 m['identities'].extend(seed['identities']);guids=[row['directoryId'] for row in seed['identities']]
 members['users'].extend({'directoryId':guid,'enabled':True} for guid in guids)
 for i,ns in enumerate(seed['namespaces']):
  group='78000000-0000-4000-8000-%012d'%((101 if profile=='primary' else 201)+i)
  c.need(group not in {row['id'] for row in state['groups']},'directory_group_collision')
  m['namespaces'].append(ns['id']);m['approvedTransitions'].append(ns['id']);m['bindings'].append({'groupId':group,'namespaceId':ns['id'],'role':'viewer'});members['groups'].append({'id':group,'members':guids[:]})
 c.need(after==expected and next_state==members,'directory_drafts_must_be_exactly_additive')


def validate_handoff(profile,handoff,source):
 p=PROFILES[profile];names={'seed.json','directory.after.json','directory-state.after.json','receipt.json','driver-receipt.json'}
 c.need(set(handoff)==names,'handoff_file_set');files={name:raw(value) for name,value in handoff.items()};value={name:c.decode(data) for name,data in files.items()}
 seed=value['seed.json'];c.need(all(set(row)=={'directoryId','principalId','issuer','subject','displayName','aliases'} and row['aliases'] is None for row in seed['identities']),'seed_alias_bound');receipt=value['receipt.json'];driver=value['driver-receipt.json']
 c.need(set(driver)=={'profile','executionId','helperCommit','helperSHA256','outputSHA256','sourceStatePreserved'} and driver['profile']==profile and c.HEX.fullmatch(driver['executionId']) and driver['helperCommit']==c.COMMIT and driver['helperSHA256']==c.BINARY_SHA and driver['sourceStatePreserved'] is True,'verified_seed_driver')
 c.need(set(driver['outputSHA256'])==names-{'driver-receipt.json'} and all(c.sha(files[name])==digest for name,digest in driver['outputSHA256'].items()),'seed_output_hash')
 c.need(set(receipt)=={'version','synthetic','helperCommit','instanceId','deploymentId','inputSHA256','directorySHA256','directoryStateSHA256','output'} and receipt['version']==1 and receipt['synthetic'] is True and receipt['helperCommit']==c.COMMIT and receipt['instanceId']==p['instance'] and receipt['deploymentId']==p['deployment'] and c.HEX.fullmatch(receipt['inputSHA256']) and receipt['output']==str(c.RECEIPTS/driver['executionId']/'output'),'helper_receipt_identity')
 c.need(c.sha(raw(source['directory']))==receipt['directorySHA256'] and c.sha(raw(source['state']))==receipt['directoryStateSHA256'],'directory_original_cas')
 c.need(seed['deploymentId']==p['deployment'] and seed['instanceId']==p['instance'],'seed_source_identity')
 additive_directory(profile,document(source['directory']),document(source['state']),value['directory.after.json'],value['directory-state.after.json'],seed)
 return seed


def recovery(api,worker):
 result=copy.deepcopy(api);result['controls']=copy.deepcopy(worker['controls']);result['databaseURLFile']=PRIVILEGED_DSN;result.pop('observability',None);return result


def draft(snapshot,handoffs):
 c.need(set(handoffs)==set(PROFILES) and snapshot.get('version')==1 and set(snapshot['runtime'])=={'api','worker','broker','operator','recovery'} and set(snapshot['sources'])==set(PROFILES),'snapshot_shape')
 configs={name:document(value) for name,value in snapshot['runtime'].items() if name!='recovery'}
 previous_recovery=document(snapshot['runtime']['recovery']);expected_recovery=recovery(configs['api'],configs['worker'])
 # RC2 deliberately preserves the immutable b8 operator static root. Only this
 # exact prior release path may differ; all authority and material stays equal.
 if previous_recovery.get('webRoot')==LEGACY_WEB_ROOT:expected_recovery['webRoot']=LEGACY_WEB_ROOT
 c.need(previous_recovery==expected_recovery,'existing_recovery_identity')
 registries={p['deployment']:document(snapshot['sources'][name]['registry']) for name,p in PROFILES.items()}
 seeds={p['deployment']:validate_handoff(name,handoffs[name],snapshot['sources'][name]) for name,p in PROFILES.items()}
 delta=scale_plan.patch(configs,registries,seeds)
 after={name:encoded_file(c.encoded(value)) for name,value in delta['configs'].items()}
 # The dedicated read-only operator configuration stays byte-for-byte unchanged.
 after['operator']=snapshot['runtime']['operator']
 after['recovery']=encoded_file(c.encoded(recovery(delta['configs']['api'],delta['configs']['worker'])))
 sources={}
 for name,p in PROFILES.items():
  sources[name]={'directory':handoffs[name]['directory.after.json'],'state':handoffs[name]['directory-state.after.json'],'registry':encoded_file(c.encoded(delta['registries'][p['deployment']]))}
 return {'version':1,'synthetic':True,'sourceDriverManifestSHA256':SOURCE_MANIFEST_SHA,'snapshotSHA256':c.sha(c.encoded(snapshot)),'handoffSHA256':{name:c.sha(c.encoded(h)) for name,h in handoffs.items()},
  'runtime':after,'sources':sources,'feedRecoveryRequired':delta['feedRecoveryRequired'],'automaticFeedReset':False}


def binding(snapshot,handoffs,plan,implementation):
 c.need(c.HEX.fullmatch(implementation) and draft(snapshot,handoffs)==plan,'recomputed_review_plan');return c.sha(c.encoded({'plan':plan,'implementationSHA256':implementation}))


def validate_database(value,snapshot,plan,held=None,revision=7):
 before=snapshot.get('database',value);c.need(type(value['bindingCount']) is int and 0<=value['bindingCount']<=200 and c.HEX.fullmatch(value['bindingSHA256']),'binding_snapshot_bound');c.need(value['database']=='jobman_dashboard' and value['migrations']==18 and len(value['identities'])==len(value['feeds'])==2,'dashboard_database_identity')
 c.need(value['bindingCount']==before['bindingCount'] and value['bindingSHA256']==before['bindingSHA256'] and value['hold'].get('restoreRecordedThrough')==before['hold'].get('restoreRecordedThrough'),'durable_binding_or_cutoff_drift')
 if held is not None:c.need(value['hold']['held'] is held,'delivery_hold_state')
 identities={row['deploymentId']:row for row in value['identities']};feeds={row['deploymentId']:row for row in value['feeds']}
 c.need(set(identities)==set(feeds)==set(scale_plan.INSTANCES),'source_set_changed')
 for expected in plan['feedRecoveryRequired']:
  key=expected['deploymentId'];row=identities[key];feed=feeds[key]
  c.need(row['instanceId']==expected['instanceId'] and row['epoch']=='1' and row['revision'] in ((revision,) if type(revision) is int else revision),'source_registry_fence')
  c.need(feed['instanceId']==expected['instanceId'] and feed['epoch']=='1','feed_source_identity')
  old=next(row for row in before['feeds'] if row['deploymentId']==key)
  c.need(feed['generation']>=old['generation'] and feed['lastPosition']>=old['lastPosition'],'feed_monotonic_fence')
  c.need(feed['namespaces'] in (expected['oldNamespaceIds'],expected['newNamespaceIds']),'unexpected_feed_scope')
 return value


def validate_recovery(value,profile,plan):
 expected=next(row for row in plan['feedRecoveryRequired'] if row['deploymentId']==PROFILES[profile]['deployment'])
 c.need(c.UUID.fullmatch(value['id']) and c.UUID.fullmatch(value['gapId']) and c.HEX.fullmatch(value['digest']) and value['deploymentId']==expected['deploymentId'] and value['configurationRevision']=='8' and value['mode']=='retained' and value['reason']==value['effectiveReason']=='event_cursor_scope_changed' and value['removedNamespaceIds']==[] and sorted(value['addedNamespaceIds'])==sorted(set(expected['newNamespaceIds'])-set(expected['oldNamespaceIds'])) and sorted(value['namespaceIds'])==expected['newNamespaceIds'],'recovery_scope_fence')
 for field in ('revision','feedGeneration','pages','scanned','added'):c.need(isinstance(value[field],str) and re.fullmatch('0|[1-9][0-9]{0,18}',value[field]),'recovery_counter_bound')
 c.need(value['uncertainty']['dashboardRestored'] is False and value['uncertainty']['suppressAllRecovered'] is False,'unexpected_recovery_policy')
 c.need(value['status'] in ('replaying','ready','applied'),'recovery_state');return value


def validate_coverage(value,profile,plan,current=None):
 c.need(set(value)=={'recovery','reconciliation'},'coverage_shape');state=validate_recovery(value['recovery'],profile,plan);receipt=value['reconciliation']
 c.need(state['status']=='ready' and set(receipt)=={'planDigest','acknowledgedGap','namespaces','completedAt'} and receipt['planDigest']==state['digest'] and receipt['acknowledgedGap'] is True,'coverage_binding')
 c.need(isinstance(receipt['namespaces'],list) and [row['namespaceId'] for row in receipt['namespaces']]==state['namespaceIds'],'coverage_scope')
 total=0
 for row in receipt['namespaces']:
  c.need(set(row) in ({'namespaceId','status','jobsRead'},{'namespaceId','status','jobsRead','asOf'}) and row['status'] in ('complete','partial','unavailable','inaccessible') and isinstance(row['jobsRead'],str) and re.fullmatch('0|[1-9][0-9]{0,6}',row['jobsRead']),'coverage_namespace_bound')
  count=int(row['jobsRead']);total+=count
  if row['status'] in ('unavailable','inaccessible'):c.need(count==0 and 'asOf' not in row,'coverage_unavailable_values')
  else:c.need(isinstance(row.get('asOf'),str),'coverage_timestamp')
 c.need(total<=1000000 and isinstance(receipt['completedAt'],str),'coverage_total_bound')
 from datetime import datetime
 for stamp in [receipt['completedAt']]+[row['asOf'] for row in receipt['namespaces'] if 'asOf' in row]:
  c.need(isinstance(stamp,str) and len(stamp)<=40 and datetime.fromisoformat(stamp.replace('Z','+00:00')).utcoffset() is not None,'coverage_timestamp')
 if current is not None:
  c.need(current['id']==state['id'] and current['digest']==state['digest'] and current['gapId']==state['gapId'] and current['feedGeneration']==state['feedGeneration'],'coverage_current_identity')
  if current['status']=='ready':c.need(current['revision']==state['revision'],'coverage_revision_changed')
 return value


def same_hold(actual,expected):
 from datetime import datetime
 stamp=lambda value:None if value is None else datetime.fromisoformat(value.replace('Z','+00:00'))
 return str(actual['generation'])==str(expected['generation']) and actual['held'] is expected['held'] and stamp(actual.get('restoreRecordedThrough'))==stamp(expected.get('restoreRecordedThrough'))


def resumed_hold(actual,expected):
 c.need(expected['held'] is False and same_hold(actual,expected),'completed_resume_changed')
