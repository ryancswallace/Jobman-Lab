#!/usr/bin/env python3
"""Pure plans and receipt validation for one inert synthetic ceiling graph."""
import copy
from datetime import datetime
import hashlib
import json
import re

INSTANCE='e633cf92-258d-48ff-965a-fda88d68ef3a'
DEPLOYMENT='72000000-0000-4000-8000-000000000001'
SOURCE_REVISION='04bd83db28bc24155c87e0ceea61c047320fca07'
SOURCE_SHA='7faac82263dfa281d2fec7c3e8a52a55a121294e39e7e2d1706115751d4a2123'
SOURCE_BINARY='/usr/local/libexec/jobman-dashboard-control-upgrades/'+SOURCE_SHA+'/jobman-control'
NAMESPACE='dashboard-operations'
ROOT='/etc/jobman-dashboard-lab/control-fixture'
DATABASE='jobman_dashboard_control'
SOURCE_FILES={'control.env','fixture-input.json','fixture-info.json','directory.json','directory-state.json','delegation.json'}
UNITS={'jobman-control','jobman-keycloak','jobman-dashboard-lab-control','jobman-dashboard-lab-directory','jobman-dashboard-lab-control-secondary','jobman-dashboard-lab-directory-secondary','jobman-dashboard-lab-broker'}
FILES={'dashboard-graph-ceiling-plan.py','dashboard-graph-ceiling-guest.py','prepare-dashboard-graph-ceiling.py','dashboard-scale-source-common.py'}
POLICY={'namespace','maxActiveJobs','maxQueuedJobs','maxCollectionItems','maxGraphNodes','idempotencyRetention','publishedOutboxRetention','revision','createdAt','updatedAt'}
HEX=re.compile(r'[0-9a-f]{64}\Z');COMMIT=re.compile(r'[0-9a-f]{40}\Z');UUID=re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')

class Failure(ValueError):
 def __init__(self,code):
  if not re.fullmatch('[a-z][a-z0-9_]{0,63}',code):raise ValueError('invalid failure code')
  self.code=code;super().__init__(code)
def need(value,code):
 if not value:raise Failure(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def identifier(value):return isinstance(value,str) and UUID.fullmatch(value) and value!='00000000-0000-0000-0000-000000000000'
def timestamp(value):
 need(isinstance(value,str) and len(value)<=40 and value.endswith('Z'),'timestamp_shape')
 result=datetime.fromisoformat(value.replace('Z','+00:00'));need(result.year==2026,'synthetic_time_range');return result

def helper_spec(value):
 need(set(value)=={'revision','os','architecture','binarySHA256','twiceIdentical','path'} and COMMIT.fullmatch(value['revision']) and value['os']=='linux' and value['architecture']=='arm64' and value['twiceIdentical'] is True and HEX.fullmatch(value['binarySHA256']) and value['path']=='/usr/local/libexec/jobman-dashboard-graph-ceiling/'+value['binarySHA256']+'/jobman-control-lab-helper','fixed_helper_descriptor')
 return value

def candidate(metadata,binary):
 need(set(metadata)=={'revision','os','architecture','binarySHA256','twiceIdentical'} and COMMIT.fullmatch(metadata['revision']) and metadata['os']=='linux' and metadata['architecture']=='arm64' and metadata['twiceIdentical'] is True and HEX.fullmatch(metadata['binarySHA256']),'helper_metadata')
 need(20<len(binary)<=32<<20 and binary[:6]==b'\x7fELF\x02\x01' and int.from_bytes(binary[18:20],'little')==183 and sha(binary)==metadata['binarySHA256'],'helper_binary')
 need(metadata['revision'].encode() in binary,'helper_linked_revision')
 return helper_spec(dict(metadata,path='/usr/local/libexec/jobman-dashboard-graph-ceiling/'+metadata['binarySHA256']+'/jobman-control-lab-helper'))

def preflight(value,helper):
 need(set(value)=={'version','synthetic','helperCommit','instanceId','recoveryEpoch','namespaceId','policy','nonterminal','proposedMaxQueued','sourceFiles'},'helper_preflight_shape')
 need(value['version']==1 and value['synthetic'] is True and value['helperCommit']==helper['revision'] and value['instanceId']==INSTANCE and value['recoveryEpoch']=='1' and identifier(value['namespaceId']),'helper_source_identity')
 policy=value['policy'];need(set(policy)==POLICY and policy['namespace']==NAMESPACE,'policy_shape')
 for name in POLICY-{'namespace','createdAt','updatedAt'}:need(type(policy[name]) is int and 0<policy[name]<=10**16,'policy_integer')
 need(policy['maxGraphNodes']>=10000 and policy['maxQueuedJobs']<=1000000,'existing_graph_policy')
 timestamp(policy['createdAt']);timestamp(policy['updatedAt'])
 current=value['nonterminal'];need(type(current) is int and 0<=current<=policy['maxQueuedJobs'],'queue_count')
 proposed=policy['maxQueuedJobs']+(10000 if current+10000>policy['maxQueuedJobs'] else 0)
 need(proposed<=1000000 and value['proposedMaxQueued']==proposed,'exact_quota_plan')
 need(set(value['sourceFiles'])==SOURCE_FILES and all(HEX.fullmatch(v) for v in value['sourceFiles'].values()),'source_file_pins')
 return value

def database(value):
 need(set(value)=={'database','instance','epoch','migrations','ledgerSHA256','jobs','targets','runs','executions','agents','enrollments','graphCount','targetCount','namespaceId'},'database_shape')
 need(value['database']==DATABASE and value['instance']==INSTANCE and value['epoch']=='1' and value['migrations']==21 and HEX.fullmatch(value['ledgerSHA256']) and identifier(value['namespaceId']),'database_identity')
 for name in ('jobs','targets','runs','executions','agents','enrollments'):
  item=value[name];need(set(item)=={'count','sha256'} and type(item['count']) is int and 0<=item['count']<=200000 and HEX.fullmatch(item['sha256']),'bounded_existing_identity')
 need(value['graphCount']==value['targetCount']==0,'ceiling_collision')
 return value

def make(source,db,helper,implementation,execution,created):
 helper_spec(helper)
 need(identifier(execution) and type(created) is int and created>0,'operation_identity')
 need(set(implementation)==FILES and all(HEX.fullmatch(v) for v in implementation.values()),'implementation_pins')
 need(set(source)=={'epoch','preflight','processes','files'},'source_snapshot_shape');preflight(source['preflight'],helper);database(db)
 need(source['preflight']['namespaceId']==db['namespaceId'] and type(source['epoch']) is int and abs(source['epoch']-created)<=30,'snapshot_coherence')
 need(source['files']==source['preflight']['sourceFiles'] and set(source['processes'])==UNITS,'source_preservation')
 current=source['processes']['jobman-dashboard-lab-control']
 need(current['uid']==21902 and current['exe']==SOURCE_BINARY and current['binarySHA256']==SOURCE_SHA,'running_source_pin')
 for value in source['processes'].values():
  need(set(value)=={'pid','uid','exe','binarySHA256','start','unitSHA256'} and isinstance(value['pid'],str) and value['pid'].isdigit() and int(value['pid'])>0 and isinstance(value['start'],str) and value['start'].isdigit() and HEX.fullmatch(value['unitSHA256']) and HEX.fullmatch(value['binarySHA256']),'process_snapshot')
 return {'version':1,'synthetic':True,'executionId':execution,'createdAt':created,'sourceRevision':SOURCE_REVISION,'source':source,'database':db,'helper':helper,'implementation':implementation,'forbidden':['migration','restart','directory-change','runtime-config-change','enrollment','execution','quota-reduction','reset','automatic-partial-retry']}

def validate(plan):
 need(plan==make(plan['source'],plan['database'],plan['helper'],plan['implementation'],plan['executionId'],plan['createdAt']),'plan_reconstruction')

def quota_receipt(value,plan):
 before=plan['source']['preflight'];need(set(value)=={'before','after'} and value['before']==before,'quota_receipt_identity')
 expected=copy.deepcopy(before['policy']);after=value['after']
 if before['proposedMaxQueued']!=expected['maxQueuedJobs']:
  expected['maxQueuedJobs']=before['proposedMaxQueued'];expected['revision']+=1
  need(timestamp(after['updatedAt'])>=timestamp(expected['updatedAt']),'quota_time_regressed');expected['updatedAt']=after['updatedAt']
 need(after==expected,'quota_receipt_unrelated_change')
 return value

def graph_manifest(value,plan):
 keys={'version','synthetic','mode','deploymentId','instanceId','recoveryEpoch','namespaceId','namespace','targetId','targetGenerationId','graphId','revision','totalNodes','totalEdges','requestDigest','nodes'}
 need(set(value)==keys and value['version']==1 and value['synthetic'] is True and value['mode']=='admitted-no-execution' and value['deploymentId']==DEPLOYMENT and value['instanceId']==INSTANCE and value['recoveryEpoch']=='1' and value['namespaceId']==plan['source']['preflight']['namespaceId'] and value['namespace']==NAMESPACE,'graph_manifest_identity')
 need(all(identifier(value[n]) for n in ('targetId','targetGenerationId','graphId')) and value['revision']=='1' and value['totalNodes']=='10000' and value['totalEdges']=='100000' and re.fullmatch('sha256:[0-9a-f]{64}',value['requestDigest']),'graph_manifest_bounds')
 need(isinstance(value['nodes'],list) and len(value['nodes'])==10000,'graph_node_count');seen=set()
 for index,node in enumerate(value['nodes']):
  need(set(node)=={'index','id'} and type(node['index']) is int and node['index']==index and identifier(node['id']) and node['id'] not in seen,'graph_node_mapping');seen.add(node['id'])
 return value

def database_preserved(before,after,seeded):
 need(set(before)==set(after),'database_verification_shape')
 for key in before.keys()-{'graphCount','targetCount'}:need(before[key]==after[key],'existing_source_metadata_changed')
 need(after['graphCount']==after['targetCount']==(1 if seeded else 0),'exact_new_graph_and_target')
 return after
