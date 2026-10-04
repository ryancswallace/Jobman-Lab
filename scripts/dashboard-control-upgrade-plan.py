#!/usr/bin/env python3
"""Pure one-source plans for a reviewed, same-schema Control binary upgrade."""
import base64
import copy
import importlib.util
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
if 'b' not in globals():
    spec=importlib.util.spec_from_file_location('fault_plan',HERE/'dashboard-dependency-fault-plan.py')
    b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
need,sha,encoded,decode=b.need,b.sha,b.encoded,b.decode
OLD='d332a2b569333ae8aed9c2fc9ebc648d8eb5ba4e'
NEW='04bd83db28bc24155c87e0ceea61c047320fca07'
NEW_SHA='7faac82263dfa281d2fec7c3e8a52a55a121294e39e7e2d1706115751d4a2123'
OLD_SHA='38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e'
HEX=re.compile('[0-9a-f]{64}\\Z');REVISION=re.compile('[0-9a-f]{40}\\Z')
PROFILES={
 'primary':{'unit':'jobman-dashboard-lab-control','uid':21902,'user':'jobman-dashboard-source',
   'root':'/etc/jobman-dashboard-lab/control-fixture','oldBinary':'/usr/local/libexec/jobman-dashboard-lab/jobman-control',
   'database':'jobman_dashboard_control','instance':'e633cf92-258d-48ff-965a-fda88d68ef3a','scopes':12,'scaleScopes':10,'port':18443},
 'secondary':{'unit':'jobman-dashboard-lab-control-secondary','uid':21907,'user':'jobman-dashboard-source2',
   'root':'/etc/jobman-dashboard-secondary/control','oldBinary':'/usr/local/libexec/jobman-dashboard-secondary/jobman-control',
   'database':'jobman_dashboard_control_secondary','instance':'a4f0e2ab-7323-4c90-9510-1f073c660f06','scopes':7,'scaleScopes':5,'port':28443}}
BINARY_ROOT='/usr/local/libexec/jobman-dashboard-control-upgrades'
FILES=('dashboard-control-upgrade-plan.py','dashboard-control-upgrade-guest.py','upgrade-dashboard-controls.py',
       'dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py','dashboard-dependency-faults.py')


def candidate(metadata,binary,build_information):
    revision=metadata.get('revision');digest=metadata.get('binarySHA256')
    need(isinstance(revision,str) and revision==NEW and
         metadata.get('os')=='linux' and metadata.get('architecture')=='arm64' and metadata.get('twiceIdentical') is True and
         metadata.get('version')=='dashboard-lab-'+NEW[:12] and digest==NEW_SHA and sha(binary)==digest,'candidate_metadata')
    need(0<len(binary)<=64<<20 and len(binary)>=20 and binary[:6]==b'\x7fELF\x02\x01' and
         int.from_bytes(binary[18:20],'little')==183,'candidate_elf')
    need(isinstance(build_information,str) and len(build_information)<=65536 and '\x00' not in build_information,'build_information')
    need('go1.26.6' in build_information and '\tbuild\tGOOS=linux\n' in build_information and
         '\tbuild\tGOARCH=arm64\n' in build_information and '\tbuild\tCGO_ENABLED=0\n' in build_information and
         'vcs.modified=true' not in build_information,'candidate_go_settings')
    # buildvcs=false/trimpath omits linker flags from go version -m. The exact
    # reviewed digest pins the full artifact; require its linked metadata strings
    # too, then inspect the actual --version output before service use.
    need(binary.count(revision.encode())==1 and binary.count(metadata['version'].encode())==1,'candidate_embedded_commit')
    return {'revision':revision,'sha256':digest,'platform':'linux/arm64','toolchain':'go1.26.6',
            'bytes':len(binary),'buildInformationSHA256':sha(build_information.encode()),
            'path':BINARY_ROOT+'/'+digest+'/jobman-control'}


def unb64(value):
    need(isinstance(value,str) and len(value)<=65536,'unit_bytes_bound')
    raw=base64.b64decode(value,validate=True);need(0<len(raw)<=32768,'unit_bytes_bound');return raw


def transform_unit(profile,raw,new_binary):
    spec=PROFILES[profile];text=raw.decode()
    need(text.endswith('\n') and '\r' not in text and '\\\n' not in text and len(raw)<=32768,'unit_encoding')
    values={};section=''
    for line in text.splitlines():
        if line.startswith('['):section=line
        elif '=' in line and not line.lstrip().startswith(('#',';')):
            key,value=line.split('=',1);values.setdefault((section,key),[]).append(value)
    expected={'Type':'simple','User':spec['user'],'Group':spec['user'],
              'EnvironmentFile':spec['root']+'/control.env','ExecStart':spec['oldBinary']}
    need(all(values.get(('[Service]',key))==[value] for key,value in expected.items()),'source_unit_semantics')
    need(not any(key[1] in ('ExecStartPre','ExecStartPost','ExecStop','ExecStopPost') for key in values),'source_unit_extra_commands')
    need(text.count(spec['oldBinary'])==1 and re.fullmatch(re.escape(BINARY_ROOT)+r'/[0-9a-f]{64}/jobman-control',new_binary),'source_unit_binary_sites')
    return text.replace('ExecStart='+spec['oldBinary']+'\n','ExecStart='+new_binary+'\n').encode()


def source_database(value,profile,ledger):
    spec=PROFILES[profile]
    need(set(value)=={'database','oid','instance','epoch','ledger','namespaces','scale','jobs','runs','executions','terminalEvents','identitySHA256','identityCounts','feed'},'source_database_shape')
    need(value['database']==spec['database'] and value['instance']==spec['instance'] and value['epoch']=='1' and
         isinstance(value['oid'],str) and value['oid'].isdigit() and value['ledger']==ledger,'source_database_identity')
    need(len(ledger)==21 and ledger[-1]['name']=='000021_monitoring_events.sql' and
         all(set(v)=={'name','sha256'} and re.fullmatch(r'[0-9]{6}_[a-z_]+\.sql',v['name']) and HEX.fullmatch(v['sha256']) for v in ledger) and
         len({v['name'] for v in ledger})==21,'source_schema_21')
    need(value['namespaces']['count']==spec['scopes'] and HEX.fullmatch(value['namespaces']['sha256']),'source_namespace_count')
    expected=[{'name':'dashboard-scale-%02d'%n,'imported':10000,'accepted':50,'total':10050} for n in range(1,spec['scaleScopes']+1)]
    need(value['scale']==expected,'accepted_scale_preservation')
    for key,limit in [('jobs',200000),('runs',10000),('executions',10000),('terminalEvents',10000)]:
        need(type(value[key]['count']) is int and 0<=value[key]['count']<=limit and HEX.fullmatch(value[key]['sha256']),'source_data_bound')
    need(value['jobs']['count']>=spec['scaleScopes']*10050,'source_scale_count')
    need(set(value['identityCounts'])=={'principals','accounts','aliases','bindings','grants','sources','delegationKeys'} and
         all(type(count) is int and 0<=count<=({'grants':20000}.get(name,1000)) for name,count in value['identityCounts'].items()),'source_identity_count')
    need(HEX.fullmatch(value['identitySHA256']) and set(value['feed'])=={'head','retired','retention'} and
         all(b.decimal(v) for v in value['feed'].values()) and int(value['feed']['retired'])<=int(value['feed']['head']),'source_identity_or_feed')
    return value


def make(snapshot,profile,candidate_value,ledger,implementation,operation,created):
    need(profile in PROFILES and b.UUID.fullmatch(operation) and type(created) is int,'plan_identity')
    need(set(snapshot)=={'control01','storage01','pg01'} and set(implementation)==set(FILES) and
         all(HEX.fullmatch(v) for v in implementation.values()),'plan_snapshot_or_implementation')
    need(candidate_value['path']==BINARY_ROOT+'/'+candidate_value['sha256']+'/jobman-control' and
         candidate_value['revision']==NEW and
         candidate_value['sha256']==NEW_SHA and HEX.fullmatch(candidate_value['buildInformationSHA256']) and
         candidate_value['platform']=='linux/arm64' and candidate_value['toolchain']=='go1.26.6' and 0<candidate_value['bytes']<=64<<20,'plan_candidate')
    for name in PROFILES:source_database(snapshot['pg01']['sources'][name],name,ledger)
    b.stable_database(snapshot['pg01']['dashboard'])
    spec=PROFILES[profile];host=snapshot['control01'];unit=unb64(host['unit'])
    need(host['profile']==profile and host['baseline']['revision']==snapshot['storage01']['revision'],'snapshot_selected_source')
    old=host['baseline']['processes'][spec['unit']]
    need(old['binary']==spec['oldBinary'] and old['binarySHA256']==OLD_SHA and old['uid']==spec['uid'] and
         old['unitSHA256']==sha(unit),'old_source_binary')
    after=transform_unit(profile,unit,candidate_value['path'])
    return {'format':1,'synthetic':True,'profile':profile,'operationId':operation,'createdAt':created,
            'oldRevision':OLD,'candidate':candidate_value,'ledger':ledger,'snapshot':snapshot,
            'beforeUnitSHA256':sha(unit),'afterUnitSHA256':sha(after),'afterUnit':base64.b64encode(after).decode(),
            'implementationSHA256':implementation,'forbidden':['migration','config-change','helper-repin','hold-change','feed-reset','automatic-retry','rollback']}


def validate(plan):
    need(plan==make(plan['snapshot'],plan['profile'],plan['candidate'],plan['ledger'],plan['implementationSHA256'],plan['operationId'],plan['createdAt']),'plan_reconstruction')


def host_preserved(plan,host,current,unit_applied=False,new_process=False):
    baseline=copy.deepcopy(plan['snapshot'][host]['baseline'] if host=='control01' else plan['snapshot'][host])
    if host=='control01':
        spec=PROFILES[plan['profile']];unit=spec['unit'];path='/etc/systemd/system/'+unit+'.service'
        if unit_applied:
            baseline['files'][path]=plan['afterUnitSHA256']
            baseline['processes'][unit]['unitSHA256']=plan['afterUnitSHA256']
            baseline['preservedSHA256']=sha(encoded({k:baseline[k] for k in ('files','capabilities','configurationRevisions')}))
        if new_process:
            old=baseline['processes'][unit];new=current['processes'][unit]
            need(new['binary']==plan['candidate']['path'] and new['binarySHA256']==plan['candidate']['sha256'] and
                 new['uid']==old['uid'] and new['bootId']==old['bootId'] and new['unitSHA256']==old['unitSHA256'] and
                 int(new['start'])>int(old['start']) and new['argumentsSHA256']==sha((plan['candidate']['path']+'\0').encode()),'new_source_process')
            baseline['processes'][unit]=new
    need(baseline==current,'preserved_host_changed')
