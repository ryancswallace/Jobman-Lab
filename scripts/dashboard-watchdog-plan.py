#!/usr/bin/env python3
"""Pure plans for the real primary restart watchdog, without a restore operation."""
import copy
import hashlib
import json
import re

BASE='/var/lib/jobman-dashboard-watchdog-acceptance'
SCENARIO='primary-restore-watchdog-intervention'
HEX=re.compile(r'[0-9a-f]{64}\Z')
REV=re.compile(r'[0-9a-f]{40}\Z')
FILES=('dashboard-watchdog-plan.py','dashboard-watchdog-guest.py','dashboard-watchdog.py')
DEPS=('dashboard-restore-guest.py','dashboard-dependency-fault-plan.py','dashboard-dependency-fault-guest.py','dashboard-dependency-faults.py')
HOSTS=('control01','storage01','pg01')

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
        for k,v in pairs:need(k not in value,'duplicate_json');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _ : (_ for _ in ()).throw(Failure('json_number')))

def validate(plan):
    need(set(plan)=={'format','synthetic','scenario','operationId','createdAt','candidate','snapshot','implementationSHA256'},'plan_shape')
    need(type(plan['format']) is int and plan['format']==1 and plan['synthetic'] is True and plan['scenario']==SCENARIO and HEX.fullmatch(plan['operationId']) and
         type(plan['createdAt']) is int and plan['createdAt']>0,'plan_identity')
    need(set(plan['candidate'])=={'revision','binarySHA256'} and REV.fullmatch(plan['candidate']['revision']) and HEX.fullmatch(plan['candidate']['binarySHA256']),'candidate_pin')
    need(set(plan['implementationSHA256'])==set(FILES+DEPS) and all(HEX.fullmatch(v) for v in plan['implementationSHA256'].values()),'implementation_pins')
    snap=plan['snapshot'];need(set(snap)==set(HOSTS),'snapshot_hosts')
    for host in HOSTS:
        need(snap[host]['host']==host and type(snap[host]['observedAt']) is int and 0<=plan['createdAt']-snap[host]['observedAt']<=900,'snapshot_host_or_age')
    storage=snap['storage01'];pins=storage['primaryPins']
    need(set(pins)=={'configs','processes'} and set(pins['configs'])==set(pins['processes'])=={'api','worker'},'primary_pins')
    need(set(storage['preserved']['processes'])=={'jobman-dashboard-lab-api','jobman-dashboard-lab-worker'},'primary_units')
    for role in ('api','worker'):
        state=pins['processes'][role]
        need(set(state)=={'unitSHA256','active','pid','startedMonotonic'} and state['active'] is True and HEX.fullmatch(state['unitSHA256']) and
             HEX.fullmatch(pins['configs'][role]) and state['pid'].isdecimal() and int(state['pid'])>1 and
             state['startedMonotonic'].isdecimal() and int(state['startedMonotonic'])>0,'primary_process')
        process=storage['preserved']['processes']['jobman-dashboard-lab-'+role]
        need(process['pid']==state['pid'] and process['start']==state['startedMonotonic'] and process['unitSHA256']==state['unitSHA256'] and
             process['binarySHA256']==plan['candidate']['binarySHA256'] and process['uid']=={'api':21904,'worker':21905}[role] and
             process['binary']=='/opt/jobman-dashboard-lab/releases/'+plan['candidate']['revision']+'/bin/jobman-dashboard','primary_snapshot_disagrees')
    need(snap['pg01']['quiet'] is True,'pending_work')
    return plan

def restarted(plan,value):
    need(set(value)=={'primaryRestarted','watchdogFired','states','operationId','elapsedSinceArmSeconds'} and
         value['operationId']==plan['operationId'] and value['primaryRestarted'] is True and value['watchdogFired'] is True and
         type(value['elapsedSinceArmSeconds']) in (int,float) and 150<=value['elapsedSinceArmSeconds']<=180,'watchdog_result')
    need(set(value['states'])=={'api','worker'},'restart_states')
    for role,state in value['states'].items():
        before=plan['snapshot']['storage01']['primaryPins']['processes'][role]
        need(set(state)==set(before) and state['active'] is True and state['unitSHA256']==before['unitSHA256'] and
             state['pid'].isdecimal() and state['pid']!=before['pid'] and int(state['pid'])>1 and
             state['startedMonotonic'].isdecimal() and int(state['startedMonotonic'])>int(before['startedMonotonic']),'restart_identity')
    return value

def preserved_host(before,after,restarts=None):
    value=copy.deepcopy(after)
    if restarts is not None:
        for role,state in restarts.items():
            name='jobman-dashboard-lab-'+role
            actual=value['processes'][name];old=before['processes'][name]
            need(actual['pid']==state['pid'] and actual['start']==state['startedMonotonic'],'restart_observation')
            actual['pid']=old['pid'];actual['start']=old['start']
    need(value==before,'preserved_host_changed')

# The timer is self-contained. Each embedded source is hash-checked before exec.
# Importing the original restore module does not invoke its CLI dispatch.
BOOT='''import hashlib,json,os,sys,types
os.umask(0o077)
SOURCES=__SOURCES__
HASHES=__HASHES__
def module(name,file,extra=None):
 text=SOURCES[file]
 if hashlib.sha256(text.encode()).hexdigest()!=HASHES[file]:raise ValueError('implementation_changed')
 m=types.ModuleType(name);m.__file__='/reviewed/'+file
 if extra:m.__dict__.update(extra)
 exec(compile(text,m.__file__,'exec'),m.__dict__);return m
try:
 p=module('watchdog_plan','dashboard-watchdog-plan.py')
 f=module('fault_plan','dashboard-dependency-fault-plan.py')
 g=module('fault_guest','dashboard-dependency-fault-guest.py',{'p':f})
 r=module('original_restore','dashboard-restore-guest.py')
 w=module('watchdog_guest','dashboard-watchdog-guest.py',{'p':p,'f':f,'g':g,'r':r,'SOURCES':SOURCES})
 if len(sys.argv)==3 and sys.argv[1]=='--watchdog':
  value=w.timer_main(sys.argv[2])
 else:
  if len(sys.argv)!=1:raise ValueError('arguments')
  if '_REQUEST' in globals():value=w.execute(_REQUEST)
  else:
   raw=sys.stdin.buffer.read((2<<20)+1)
   if len(raw)>2<<20:raise ValueError('request_bound')
   value=w.execute(p.decode(raw))
 print(json.dumps({'ok':True,'result':value},sort_keys=True))
except Exception as error:
 code=getattr(error,'code','watchdog_failed')
 if not isinstance(code,str) or not __import__('re').fullmatch('[a-z][a-z0-9_]{0,63}',code):code='watchdog_failed'
 print(json.dumps({'ok':False,'code':code},sort_keys=True));sys.exit(1)
'''

def loader(sources):
    names=set(FILES[:2]+DEPS[:3]);need(set(sources)==names,'loader_sources')
    code=BOOT.replace('__HASHES__',repr({n:sha(v.encode()) for n,v in sources.items()}),1).replace('__SOURCES__',repr(sources),1).encode()
    need(len(code)<=1<<20,'loader_bound');return code
