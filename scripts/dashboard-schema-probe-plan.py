#!/usr/bin/env python3
"""Pure, fixed-target plans for actual packaged startup refusal."""
import copy
import hashlib
import json
import re

DATABASE = 'jobman_schema_probe_v1'
ROLES = {r:'jobman_schema_probe_'+r for r in ('ddl','api','worker','operator')}
ROOTS = {r:'/etc/jobman-dashboard-schema-probe-'+r+'-lab' for r in ('api','worker','operator')}
RUN = {r:'/run/jobman-dashboard-schema-probe-'+r+'-lab' for r in ('api','worker')}
USERS = {'api':21920,'worker':21921}
READER = 21922
PORT = 48444
CA = '/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt'
BASE = '/var/lib/jobman-dashboard-schema-probe-operations'
FUTURE = {'name':'migrations/999999_lab_schema_probe.sql',
          'sha256':hashlib.sha256(b'Lab ledger marker only; no migration body or product schema change.\n').hexdigest()}
ERROR = 'Dashboard schema is incompatible with this binary: migration version'
HEX = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
FILES = ('dashboard-schema-probe-plan.py','dashboard-schema-probe-guest.py','probe-dashboard-schema.py')
INSTALL_FILES = ('dashboard-install-plan.py','dashboard-install-guest.py','install-dashboard-fresh.py',
                 'dashboard-split-plan.py','dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py',
                 'dashboard-dependency-faults.py','dashboard-control-upgrade-plan.py','dashboard-control-upgrade-guest.py')
PHASES = {'database':'pg01','material':'storage01','migrate':'storage01','grants':'pg01',
          'positive':'storage01','future':'pg01','refuse':'storage01'}
COMPONENTS = {'api':['api'],'worker':['retention'],'operator':['operator']}

class Failure(ValueError):
    def __init__(self,code):
        if not re.fullmatch('[a-z][a-z0-9_]{0,63}',code):raise ValueError('failure_code')
        self.code=code;super().__init__(code)

def need(ok,code):
    if not ok:raise Failure(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:need(key not in value,'duplicate_json_field');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _ : (_ for _ in ()).throw(Failure('json_number')))

def install_resources(install):
    scope=install.get('scope','v1')
    need(scope in ('v1','v2','v3'),'install_scope')
    return {'users':{'api':21920,'worker':21921} if scope=='v1' else {'api':21923,'worker':21924} if scope=='v2' else {'api':21926,'worker':21927},
            'reader':{'v1':21922,'v2':21925,'v3':21928}[scope],
            'releases':'/opt/jobman-dashboard-install'+('' if scope=='v1' else '-'+scope)+'-lab/releases'}

def configs(install,selected):
    api=copy.deepcopy(install['configs']['api'])
    api['databaseURLFile']=ROOTS['api']+'/database-url'
    api['listen']='127.0.0.1:'+str(PORT)
    api['publicOrigin']='https://dashboard.lab.test:'+str(PORT)
    api['webRoot']=install_resources(install)['releases']+'/'+install['candidates'][selected]['revision']+'/web'
    api['events']={'enabled':False,'deliveryHold':False}
    api['notifications']={'deviceTopics':[]}
    # No real source/identity request is needed to check the ledger. If the
    # binary incorrectly continues, these endpoints cannot reach a Lab source.
    api['oidc']['issuer']='https://127.0.0.1:48445'
    for index,control in enumerate(api['controls']):
        control['origin']='https://127.0.0.1:'+str(48445+index)
    for key in ('reports','logBrokers','logMappings','logCursorKeyFile'):api.pop(key,None)
    api['observability']={'socketPath':RUN['api']+'/observe.sock'}
    worker={'configurationRevision':1,'databaseURLFile':ROOTS['worker']+'/database-url',
            'components':['retention'],'controls':[], 'observability':{'socketPath':RUN['worker']+'/observe.sock'}}
    operator={'schemaVersion':1,'databaseURLFile':ROOTS['operator']+'/database-url',
              'deployments':[{'id':c['id']} for c in api['controls']]}
    return {'api':api,'worker':worker,'operator':operator}

def validate_install_complete(install,complete,continuation_sha256=None):
    base={'operationId':install['operationId'],'complete':True,'retained':True}
    if continuation_sha256 is None:
        need(encoded(complete)==encoded(base),'closed_install_required')
        return
    need(isinstance(continuation_sha256,str) and HEX.fullmatch(continuation_sha256),
         'continuation_review_hash')
    need(isinstance(complete,dict) and set(complete)==set(base)|{'continuation'} and
         encoded({k:complete[k] for k in base})==encoded(base),'closed_install_required')
    proof=complete['continuation']
    fields={'adapterSHA256','originalImplementationSHA256','failureSHA256','diagnosticSHA256','mapperDifference'}
    need(isinstance(proof,dict) and set(proof)==fields and
         all(isinstance(proof[k],str) and HEX.fullmatch(proof[k]) for k in fields-{'mapperDifference'}),
         'continuation_provenance_shape')
    need(proof['originalImplementationSHA256']==sha(encoded(install['implementationSHA256'])) and
         proof['mapperDifference']=={'name':'dashboard-api-audience','config':{'userinfo.token.claim':'false'}} and
         sha(encoded(proof))==continuation_sha256,'continuation_provenance_changed')

def validate(plan):
    need(set(plan)-{'installContinuationSHA256'}=={'format','synthetic','operationId','createdAt','install','installComplete','selected','snapshot',
                    'configs','implementationSHA256','secretSHA256','grantSHA256'},'plan_shape')
    need(plan['format']==1 and plan['synthetic'] is True and UUID.fullmatch(plan['operationId']) and
         type(plan['createdAt']) is int and plan['createdAt']>0,'plan_identity')
    install=plan['install']; selected=plan['selected']
    need(selected in ('baseline','upgrade'),'selected_candidate')
    if 'installContinuationSHA256' in plan:
        need(plan['installContinuationSHA256'] is not None,'continuation_review_hash')
    validate_install_complete(install,plan['installComplete'],plan.get('installContinuationSHA256'))
    need(set(plan['implementationSHA256'])==set(FILES+INSTALL_FILES) and
         all(isinstance(v,str) and HEX.fullmatch(v) for v in plan['implementationSHA256'].values()),'implementation_hashes')
    need(all(plan['implementationSHA256'][k]==v for k,v in install['implementationSHA256'].items()),'install_archive_changed')
    need(set(plan['secretSHA256'])==set(ROLES) and len(set(plan['secretSHA256'].values()))==4 and
         all(HEX.fullmatch(v) for v in plan['secretSHA256'].values()),'distinct_secrets_required')
    need(set(plan['grantSHA256'])==set(COMPONENTS) and all(HEX.fullmatch(v) for v in plan['grantSHA256'].values()),'grant_hashes')
    need(plan['configs']==configs(install,selected),'config_derivation_changed')
    need(set(plan['snapshot'])=={'storage01','pg01','control01'} and
         plan['snapshot']['storage01']['unused'] is True and plan['snapshot']['pg01']['unused'] is True and
         plan['snapshot']['storage01']['freeBytes']>=256<<20 and plan['snapshot']['pg01']['freeBytes']>=1<<30 and
         plan['snapshot']['pg01']['connections']>=20,'probe_capacity')
    need(len(install['candidates'][selected]['ledger'])==18 and FUTURE not in install['candidates'][selected]['ledger'],
         'exact_schema_18_required')
    return plan

def refusal(returncode,raw,elapsed):
    need(returncode==1 and 0<=elapsed<=15 and 0<len(raw)<=65536,'startup_did_not_refuse')
    text=raw.decode('utf-8',errors='strict')
    # main uses slog's default handler (the standard logger's date/time frame).
    # Also retain the explicit TextHandler form; require the whole exact line.
    stamp=r'[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}'
    instant=r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})'
    default=stamp+r' ERROR dashboard stopped error="'+re.escape(ERROR)+r'"\n'
    explicit=r'time='+instant+r' level=ERROR msg="dashboard stopped" error="'+re.escape(ERROR)+r'"\n'
    need(re.fullmatch(default,text) is not None or re.fullmatch(explicit,text) is not None,'schema_refusal_reason')
    return {'refused':True,'exitCode':1,'reason':'schema_version','elapsedSeconds':round(elapsed,6),'logSHA256':sha(raw)}
