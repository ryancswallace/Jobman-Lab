#!/usr/bin/env python3
"""Fixed-role Slurm log-mapping phases; never restarts a Control source."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

SPECS={
 'api':('storage01','/etc/jobman-dashboard-api-lab/config.json',21904,'jobman-dashboard-api','jobman-dashboard-lab-api','jobman-dashboard','api'),
 'reports':('storage01','/etc/jobman-dashboard-worker-lab/config.json',21905,'jobman-dashboard-worker','jobman-dashboard-lab-worker','jobman-dashboard','worker'),
 'broker':('control01','/etc/jobman-dashboard-broker-lab/config.json',21901,'jobman-dashboard-log','jobman-dashboard-lab-broker','jobman-log-broker','broker')}
ROOT=Path('/var/lib/jobman-dashboard-slurm-mapping-operator')
DEPLOYMENT='72000000-0000-4000-8000-000000000001'


def need(value,message):
 if not value:raise ValueError(message)

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def sync(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def read(path,uid,mode=0o600,maximum=1048576):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==uid and s.st_gid==uid and stat.S_IMODE(s.st_mode)==mode and 0<s.st_size<=maximum,'File identity differs')
  raw=f.read(maximum+1);a=os.fstat(f.fileno());z=path.lstat()
  need(len(raw)==s.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns) and (z.st_dev,z.st_ino)==(s.st_dev,s.st_ino),'File changed during read')
  return raw

def directory(path):
 try:path.mkdir(mode=0o700);os.chmod(path,0o700);sync(path.parent)
 except FileExistsError:pass
 s=path.lstat();need(path.resolve()==path and stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'Operator directory differs')

def put(path,raw,uid=0):
 try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 except FileExistsError:need(read(path,uid)==raw,'Retained file differs');return
 with os.fdopen(fd,'wb') as f:os.fchown(f.fileno(),uid,uid);os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 sync(path.parent)

def run(args,timeout=15,input_data=None):
 # Bound both pipes while reading; never retain private command errors.
 with subprocess.Popen(args,stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True) as child:
  streams=selectors.DefaultSelector();streams.register(child.stdout,selectors.EVENT_READ,'out');streams.register(child.stderr,selectors.EVENT_READ,'err')
  if input_data is not None:
   os.set_blocking(child.stdin.fileno(),False);streams.register(child.stdin,selectors.EVENT_WRITE,'in')
  position=0;result=bytearray();errors=0;deadline=time.monotonic()+timeout
  try:
   while streams.get_map():
    remaining=deadline-time.monotonic();need(remaining>0,'Scoped command timed out')
    for key,_ in streams.select(min(remaining,0.2)):
     if key.data=='in':
      position+=os.write(key.fileobj.fileno(),input_data[position:position+16384])
      if position==len(input_data):streams.unregister(key.fileobj);key.fileobj.close()
      continue
     raw=os.read(key.fileobj.fileno(),65536)
     if not raw:streams.unregister(key.fileobj);continue
     if key.data=='out':result.extend(raw);need(len(result)<=1048576,'Command output bound exceeded')
     else:errors+=len(raw);need(errors<=65536,'Command error bound exceeded')
   need(child.wait(timeout=max(0.01,deadline-time.monotonic()))==0,'Scoped command failed; preserve receipts')
   return bytes(result)
  finally:
   streams.close()
   if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait()

def remaining(deadline,maximum=15):
 if deadline is None:return maximum
 value=min(maximum,deadline-time.monotonic());need(value>0,'Verification deadline expired');return value

def process(spec,deadline=None):
 _,config,uid,user,unit,binary,mode=spec
 need(pwd.getpwnam(user).pw_uid==uid,'Service user differs')
 run(['systemctl','is-active','--quiet',unit],timeout=remaining(deadline))
 pid=run(['systemctl','show',unit,'--property=MainPID','--value'],timeout=remaining(deadline)).decode().strip()
 need(pid.isdigit() and int(pid)>0 and Path('/proc',pid).stat().st_uid==uid,'Service process identity differs')
 path=Path(os.readlink('/proc/'+pid+'/exe'))
 need(re.fullmatch('/opt/jobman-dashboard-lab/releases/[0-9a-f]{40}/bin/'+binary,str(path)),'Installed candidate path differs')
 args=Path('/proc',pid,'cmdline').read_bytes().split(b'\0')
 need(b'--config' in args and args[args.index(b'--config')+1]==config.encode(),'Service configuration argument differs')
 if mode!='broker':need(b'--mode' in args and args[args.index(b'--mode')+1]==mode.encode(),'Service mode differs')
 return {'binary':str(path),'binarySHA256':sha(read(path,0,0o755,96<<20)),
         'unitSHA256':sha(read(Path('/etc/systemd/system')/(unit+'.service'),0,0o644)),
         'uid':uid,'unit':unit}

def source_state(fixture):
 result={}
 for name in ('jobman-dashboard-lab-control','jobman-dashboard-lab-directory','jobman-control','jobman-keycloak'):
  run(['systemctl','is-active','--quiet',name]);result[name]=run(['systemctl','show',name,'--property=ExecMainStartTimestampMonotonic','--value']).decode().strip()
 capabilities=json.loads(run(['runuser','-u','jobman-dashboard-source','--','curl','--silent','--fail','--max-time','5','--cacert','/etc/jobman-dashboard-lab/control-fixture/fixture-ca.crt','https://127.0.0.1:18443/v1/capabilities']))['capabilities']
 need(capabilities['instanceId']==fixture['controlInstanceId'] and capabilities['recoveryEpoch']==fixture['recoveryEpoch'],'Source instance or epoch changed')
 return {'processes':result,'instanceId':capabilities['instanceId'],'recoveryEpoch':capabilities['recoveryEpoch']}

def process_start(spec):
 values=run(['systemctl','show',spec[4],'--property=MainPID','--property=ExecMainStartTimestampMonotonic']).decode().splitlines()
 result=dict(line.split('=',1) for line in values)
 need(result.keys()=={'MainPID','ExecMainStartTimestampMonotonic'} and all(x.isdigit() and int(x)>0 for x in result.values()),'Process start identity unavailable')
 return result

def running_revision(role,spec,revision,deadline=None):
 socket={'api':'/run/jobman-dashboard-api-lab/observe.sock','reports':'/run/jobman-dashboard-worker-lab/observe.sock','broker':'/run/jobman-dashboard-broker-lab/observe.sock'}[role]
 prefix=['runuser','-u',spec[3],'--','curl','--silent','--fail','--max-time','2','--unix-socket',socket]
 live=json.loads(run(prefix+['http://localhost/livez'],timeout=remaining(deadline,3)))
 need(live.get('state')=='alive' and live.get('role')==spec[6],'Process liveness role differs')
 metrics=run(prefix+['http://localhost/metrics'],timeout=remaining(deadline,3)).decode('utf-8')
 values=re.findall(r'^jobman_dashboard_configuration_revision ([0-9]+)$',metrics,re.MULTILINE)
 need(values==[str(revision)],'Running configuration revision differs')

class RestartVerificationError(ValueError):
 pass

def await_restart(role,spec,revision,expected,path):
 deadline=time.monotonic()+10;stage='process_identity'
 while True:
  try:
   stage='process_identity';need(process(spec,deadline)==expected,'Restarted process differs')
   stage='config_validation';config_check(spec,expected['binary'],path,deadline)
   stage='loaded_revision';running_revision(role,spec,revision,deadline)
   return
  except (ValueError,OSError,subprocess.SubprocessError):
   if time.monotonic()>=deadline:raise RestartVerificationError('Restart verification failed at '+stage+'; preserve pending receipt') from None
   time.sleep(max(0,min(0.2,deadline-time.monotonic())))

def input_value(p):
 need(os.geteuid()==0 and sys.platform=='linux','Root Linux operator required')
 role=p['role'];need(role in SPECS,'Unknown role');spec=SPECS[role];item=p['file']
 need(os.uname().nodename.split('.')[0]==spec[0],'Wrong guest')
 need((item['host'],item['path'],item['uid'],item['gid'],item['mode'])==(spec[0],spec[1],spec[2],spec[2],0o600),'Fixed role boundary differs')
 review=p['review'];need(sha(encoded(review))==p['reviewSHA256'] and re.fullmatch('[0-9a-f]{64}',p['reviewSHA256']) and item in review['files'],'Reviewed mapping identity differs')
 before=base64.b64decode(p['before'],validate=True);after=base64.b64decode(p['after'],validate=True)
 need(0<len(before)<=1048576 and 0<len(after)<=1048576 and sha(before)==item['beforeSHA256'] and sha(after)==item['afterSHA256'],'Exact mapping bytes differ')
 original=json.loads(before);desired=json.loads(after);fixture=p['fixture'];key='logRoots' if role=='broker' else 'logMappings'
 need(fixture['mode']=='actual-slurm-execution' and fixture['deploymentId']==DEPLOYMENT and fixture['namespace']=='dashboard-operations' and fixture['targetGenerationId']==review['targetGenerationId'] and fixture['controlInstanceId']==review['sourceInstanceId'],'Slurm fixture source differs')
 mapping={'deploymentId':DEPLOYMENT,'targetGenerationId':fixture['targetGenerationId'],'storeName':'lab-nfs','storeVersion':'1'}
 if role=='broker':mapping['root']='/data/jobman/alice/dashboard-slurm-logs'
 else:mapping['brokerId']='control01-nfs'
 controls=[x for x in original['controls'] if x['id']==DEPLOYMENT]
 need(len(controls)==1 and controls[0]['origin']=='https://10.77.0.21:18443' and controls[0]['expectedInstanceId']==fixture['controlInstanceId'] and fixture['namespaceId'] in controls[0]['namespaceIds'],'Configured source identity differs')
 current=original['configurationRevision'];need(type(current) is int and 0<current<(1<<63)-1 and current==review['currentRevision'] and review['nextRevision']==current+1,'Monotonic revision differs')
 expected=dict(original);expected['configurationRevision']=current+1;expected[key]=original.get(key,[])+[mapping]
 need(len(expected[key])<=64 and desired==expected and item['addedMapping']==mapping and not any(x.get('targetGenerationId')==fixture['targetGenerationId'] and x.get('deploymentId')==DEPLOYMENT for x in original.get(key,[])),'Non-additive mapping rejected')
 return spec,Path(spec[1]),before,after

def paths(p,path):
 prefix='.slurm-mapping-'+p['reviewSHA256']
 return path.parent/(prefix+'.before.json'),path.parent/(prefix+'.after.json'),ROOT/p['reviewSHA256']/p['role']

def config_check(spec,binary,path,deadline=None):
 command=[binary,'--mode','check-config','--check-mode',spec[6],'--config',str(path)] if spec[6]!='broker' else [binary,'--mode','check-config','--config',str(path)]
 run(['runuser','-u',spec[3],'--']+command,timeout=remaining(deadline))

def execute(p):
 spec,path,before,after=input_value(p);phase=p['phase'];need(phase in ('preflight','stage','swap-state','apply','restart','verify'),'Unknown phase')
 backup,staged,root=paths(p,path);uid=spec[2]
 if phase=='preflight':
  need(read(path,uid)==before,'Current config differs from reviewed original')
  result={'epoch':int(time.time()),'process':process(spec),'beforeSHA256':sha(before)}
  if p['role']=='broker':result['sourceProcesses']=source_state(p['fixture'])
  return result
 baseline=p['baseline'];need(process(spec)==baseline['process'],'Installed binary, unit or role changed')
 if p['role']=='broker':need(source_state(p['fixture'])==baseline['sourceProcesses'],'An original source service changed')
 if phase=='swap-state':
  identity={'beforeSHA256':sha(before),'afterSHA256':sha(after),'process':baseline['process'],'reviewSHA256':p['reviewSHA256']}
  need(json.loads(read(root/'stage.json',0))==identity and read(backup,uid)==before,'Staging boundary changed')
  current=read(path,uid)
  if current==after:need(json.loads(read(root/'apply.pending.json',0))==identity,'Applied bytes lack pending receipt')
  else:need(current==before and read(staged,uid)==after,'Config differs from both reviewed states')
  return {'state':'applied' if current==after else 'original'}
 if phase=='verify':
  need(read(path,uid)==after,'Applied config differs');config_check(spec,baseline['process']['binary'],path)
  completed=json.loads(read(root/'restart.json',0));need(completed['afterSHA256']==sha(after),'Restart receipt differs')
  running_revision(p['role'],spec,p['review']['nextRevision'])
  return {'role':p['role'],'configurationRevision':p['review']['nextRevision'],'afterSHA256':sha(after),'live':True,'sourceServicesRechecked':p['role']=='broker'}
 need(p.get('apply') is True,'Mutation requires explicit apply')
 for d in (ROOT,ROOT/p['reviewSHA256'],root):directory(d)
 identity={'beforeSHA256':sha(before),'afterSHA256':sha(after),'process':baseline['process'],'reviewSHA256':p['reviewSHA256']}
 if phase=='stage':
  need(read(path,uid)==before,'Current config changed before staging')
  put(backup,before,uid);put(staged,after,uid);config_check(spec,baseline['process']['binary'],staged)
  put(root/'stage.json',encoded(identity));return dict(identity,staged=True)
 need(json.loads(read(root/'stage.json',0))==identity and read(backup,uid)==before,'Staged receipt or backup differs')
 if phase=='apply':
  marker=root/'apply.pending.json';done=root/'apply.json';current=read(path,uid)
  if done.exists():need(json.loads(read(done,0))==identity and current==after,'Completed swap differs');return dict(identity,applied=True)
  if current==after:need(json.loads(read(marker,0))==identity,'New bytes lack pending CAS identity')
  else:
   need(current==before and read(staged,uid)==after,'Compare-and-swap precondition differs')
   put(marker,encoded(identity));need(read(path,uid)==before,'Config changed at CAS boundary')
   os.replace(staged,path);sync(path.parent);need(read(path,uid)==after,'Installed config differs')
  put(done,encoded(identity));return dict(identity,applied=True)
 need(read(path,uid)==after and json.loads(read(root/'apply.json',0))==identity,'Applied receipt differs')
 done=root/'restart.json'
 if done.exists():need(json.loads(read(done,0))==identity,'Restart receipt differs');return dict(identity,restarted=True)
 pending=root/'restart.pending.json'
 if pending.exists():
  # A lost response can finish only after proof of a new, healthy process.
  # Never issue another restart for an uncertain first command.
  recorded=json.loads(read(pending,0));need(recorded['identity']==identity and process_start(spec)!=recorded['beforeProcess'],'Uncertain restart requires inspection')
 else:
  put(pending,encoded({'identity':identity,'beforeProcess':process_start(spec)}));run(['systemctl','restart',spec[4]],timeout=30)
 await_restart(p['role'],spec,p['review']['nextRevision'],baseline['process'],path)
 put(done,encoded(identity));return dict(identity,restarted=True)

if __name__=='__main__':
 try:
  raw=sys.stdin.buffer.read((4<<20)+1);need(len(raw)<=4<<20,'Input bound exceeded');print(encoded(execute(json.loads(raw))).decode(),end='')
 except RestartVerificationError as error:raise SystemExit(str(error)) from None
 except Exception:raise SystemExit('Slurm mapping phase failed; preserve receipts and files. No automatic rollback or source restart attempted.') from None
