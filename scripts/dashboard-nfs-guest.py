#!/usr/bin/env python3
"""Explicit isolated NFS keeper/probe phases; no existing service mutations."""
import base64
import contextlib
import fcntl
import importlib.util
import os
from pathlib import Path
import socket
import stat
import sys
import time

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
if 'p' not in globals(): p = load('dashboard-nfs-plan')
if 'f' not in globals(): f = load('dashboard-dependency-fault-guest')
if 'relay' not in globals(): relay = load('dashboard-nfs-relay')
BASE = Path(p.BASE)


def directory(path,mode=0o700,new=False):
    if new:
        path.mkdir(mode=mode); path.chmod(mode); f.sync(path.parent)
    info = path.lstat()
    p.need(path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
           stat.S_IMODE(info.st_mode) == mode,'nfs_directory')


@contextlib.contextmanager
def lock(create=False):
    p.need(BASE.exists() or create,'operation_not_staged')
    if not BASE.exists(): directory(BASE,0o711,True)
    directory(BASE,0o711)
    path = BASE/'.lock'
    try: fd = os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600); os.fchmod(fd,0o600)
    except FileExistsError: fd = os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s = os.fstat(fd); p.need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o600,'nfs_lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); yield
    finally: os.close(fd)


def shared_mounts():
    # Compare the existing host's NFS rows, excluding only this operation's
    # different mount namespace (which can never appear here).
    rows = [line for line in Path('/proc/self/mountinfo').read_text().splitlines() if ' - nfs' in line]
    p.need(len(rows) <= 16 and sum(map(len,rows)) < 32768,'shared_mounts_bound')
    return p.sha(p.encoded(rows))


def exports():
    paths=[Path('/etc/exports')]
    parent=Path('/etc/exports.d'); p.need(parent.resolve()==parent,'exports_directory')
    entries=list(parent.iterdir()); p.need(len(entries)<=16,'exports_count')
    paths.extend(sorted(x for x in entries if x.name.endswith('.exports')))
    result={}
    for path in paths:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            p.need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o644 and before.st_size<=65536,'exports_identity')
            raw=stream.read(65537); after=os.fstat(stream.fileno())
            p.need(len(raw)==before.st_size and (before.st_ino,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_mtime_ns,after.st_ctime_ns),'exports_changed')
        result[str(path)]=p.sha(raw)
    active=f.run(['exportfs','-s'],'exports_active',maximum=65536)
    rows=[x for x in active.decode().splitlines() if x.split() and x.split()[0]==p.EXPORT]
    p.need(len(rows)==1 and ',secure,' in rows[0] and 'insecure' not in rows[0] and 'root_squash' in rows[0],'secure_export_required')
    return {'filesSHA256':p.sha(p.encoded(result)),'activeSHA256':p.sha(active)}


def snapshot(host,revision):
    if host == 'pg01': return {'database':f.database()}
    value = f.host_snapshot(host,revision)
    value['sharedNFSMountsSHA256'] = shared_mounts()
    if host == 'storage01': value['nfsExports'] = exports()
    return value


def preserved(plan,host):
    current = snapshot(host,plan['snapshot'].get(host,{}).get('revision',''))
    if host == 'pg01': p.b.database_preserved(plan['snapshot'][host]['database'],current['database'])
    else: p.need(current == plan['snapshot'][host],'existing_host_changed')
    return {'preserved':True,'host':host}


def staged(plan):
    root = Path(plan['root']); directory(root,0o711)
    p.need(f.read(root/'plan.json') == p.encoded(plan),'staged_plan_changed')
    for name,digest in plan['implementationSHA256'].items():
        p.need(p.sha(f.read(root/name,0,0o444,256<<10)) == digest,'staged_implementation_changed')
    for name,expected in (('jobman-log-broker',plan['candidate']['binary']),('probe',plan['probe']['binary'])):
        data = f.read(root/name,0,0o555,128<<20)
        p.need(len(data) == expected['bytes'] and p.sha(data) == expected['sha256'],'staged_binary_changed')
    return root


def receipt(root,name,value):
    path = root/(name+'.json'); raw = p.encoded(value)
    if path.exists(): p.need(f.read(path) == raw,'receipt_changed')
    else: f.put(path,raw)


def unit_text(plan):
    root = plan['root']
    return ('[Unit]\nDescription=Isolated Dashboard hard NFS acceptance keeper\n'
            '[Service]\nType=simple\nUser=root\nGroup=root\nUMask=0077\n'
            'ExecStart=/usr/bin/python3 '+root+'/dashboard-nfs-relay.py serve '+root+'\n'
            'Restart=no\nKillMode=process\nSendSIGKILL=no\nTimeoutStopSec=10s\n'
            'TasksMax=32\nLimitNOFILE=128\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n').encode()


def keeper(plan):
    unit = p.unit(plan)
    props = dict(x.split('=',1) for x in f.run(['systemctl','show',unit,'--property=MainPID','--property=ActiveState','--property=ExecMainStartTimestampMonotonic','--property=FragmentPath','--property=DropInPaths'],'keeper_properties').decode().splitlines())
    p.need(props.get('ActiveState') == 'active' and p.b.decimal(props.get('MainPID')) and int(props['MainPID'])>0 and
           props.get('FragmentPath') == '/etc/systemd/system/'+unit+'.service' and props.get('DropInPaths') == '', 'keeper_not_active')
    p.need(f.read(props['FragmentPath'],0,0o644,16384) == unit_text(plan),'keeper_unit_changed')
    pid = int(props['MainPID']); argv = Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')[:-1]
    p.need(argv == [b'/usr/bin/python3',(plan['root']+'/dashboard-nfs-relay.py').encode(),b'serve',plan['root'].encode()], 'keeper_argv')
    p.need(Path('/proc/'+str(pid)).stat().st_uid == 0,'keeper_owner')
    state = relay.control(Path(plan['root']),'state')
    p.need(state['operationId'] == plan['operationId'] and state['ready'] and state['failure'] is None,'keeper_not_ready')
    p.need(all(state['namespaces'][k] != state['originalNamespaces'][k] for k in ('net','mnt','uts')),'keeper_namespaces')
    return {'pid':pid,'start':props['ExecMainStartTimestampMonotonic'],'namespaces':state['namespaces']}


def watchdog(root):
    plan = p.decode(f.read(root/'plan.json')); p.validate(plan); staged(plan)
    ack = p.decode(f.read(root/'watchdog-ack.json'))
    p.need(ack['operationId'] == plan['operationId'],'watchdog_plan')
    # An earlier explicit release may already have completed cleanup. Only the
    # durable unmount proof permits this idempotent no-socket path.
    if (root/'unmounted.json').exists():
        p.need(p.decode(f.read(root/'unmounted.json')) == {'operationId':plan['operationId'],'unmounted':True},'unmount_proof')
    else:
        state = relay.control(root,'resume',3)
        p.need(state['state'] == 'resumed','watchdog_resume')
    receipt(root,'watchdog-complete',{'operationId':plan['operationId'],'forwardingRestored':True})
    return {'forwardingRestored':True}


def phase(payload):
    plan = payload['plan']; p.validate(plan); host = payload['host']; name = payload['phase']
    if name == 'preserved': return preserved(plan,host)
    p.need(host == 'control01','nfs_host')
    root = Path(plan['root'])
    if name == 'stage':
        preserved(plan,host)
        p.need(not root.exists() and not Path('/etc/systemd/system/'+p.unit(plan)+'.service').exists(),'new_operation_required')
        # Global unfinished operation prevents more than one namespace/mount
        # probe from accumulating. Failed evidence is never automatically erased.
        if BASE.exists():
            operations = [x for x in BASE.iterdir() if x.is_dir()]
            p.need(len(operations)<16 and all((x/'closed.json').exists() for x in operations),'prior_operation_unclosed')
        disk=os.statvfs(BASE); p.need(disk.f_bavail*disk.f_frsize>=512<<20,'stage_disk_capacity')
        directory(root,0o711,True)
        receipt(root,'stage.pending',{'operationId':plan['operationId']})
        f.put(root/'plan.json',p.encoded(plan))
        sources = payload['sources']; p.need(set(sources) == set(p.FILES),'source_set')
        for name,text in sources.items():
            data=text.encode(); p.need(p.sha(data)==plan['implementationSHA256'][name],'source_hash'); f.put(root/name,data,0o444)
        for key,name,expected in (('broker','jobman-log-broker',plan['candidate']['binary']),('probe','probe',plan['probe']['binary'])):
            data=base64.b64decode(payload[key],validate=True)
            p.need(len(data)==expected['bytes'] and p.sha(data)==expected['sha256'] and data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\xb7\x00','binary_identity'); f.put(root/name,data,0o555)
        directory(root/'mount',0o755,True)
        config={'operationId':plan['operationId'],'root':plan['root'],'brokerSHA256':plan['candidate']['binary']['sha256'],
                'chunks':[dict(root=str(root/'mount'),**{k:v for k,v in c.items() if k!='acceptedEvidenceSHA256'}) for c in plan['chunks']]}
        f.put(root/'probe.json',p.encoded(config),0o400); os.chown(root/'probe.json',p.UID,p.UID)
        f.put(Path('/etc/systemd/system/'+p.unit(plan)+'.service'),unit_text(plan),0o644)
        f.run(['systemctl','daemon-reload'],'new_keeper_daemon_reload')
        receipt(root,'stage',{'operationId':plan['operationId'],'staged':True}); return {'staged':True}
    staged(plan)
    if name == 'state':
        return relay.control(root,'state')
    if name == 'start':
        p.need(not (root/'start.pending.json').exists(),'start_uncertain_no_retry')
        preserved(plan,host); receipt(root,'start.pending',{'operationId':plan['operationId']})
        f.run(['systemctl','start',p.unit(plan)],'keeper_start',timeout=8)
        deadline=time.monotonic()+25
        while True:
            try: value=keeper(plan); p.need(time.monotonic()<deadline,'keeper_ready_deadline'); break
            except Exception: p.need(time.monotonic()<deadline,'keeper_not_ready'); time.sleep(.1)
        receipt(root,'started',value); return value
    if name == 'arm':
        current=keeper(plan); p.need(current==p.decode(f.read(root/'started.json')),'keeper_restarted')
        p.need(not (root/'arm.pending.json').exists(),'arm_uncertain_no_retry')
        before=time.monotonic(); receipt(root,'arm.pending',{'operationId':plan['operationId'],'beforeMonotonic':before})
        timer=p.unit(plan)+'-watchdog'
        f.run(['systemd-run','--unit='+timer,'--on-active=40s','--timer-property=AccuracySec=100ms',
               '--property=Type=oneshot','--property=User=root','--property=Group=root','--property=TimeoutStartSec=10s',
               '/usr/bin/python3',str(root/'dashboard-nfs-guest.py'),'--watchdog',str(root)],'watchdog_arm',timeout=5)
        state=f.run(['systemctl','is-active',timer+'.timer'],'watchdog_active').decode().strip()
        p.need(state=='active' and time.monotonic()-before<10,'watchdog_ack_deadline')
        # A 40s timer plus at most 5s acknowledgement overhead stays inside the
        # declared 45s maximum; the relay also enforces before+45 itself.
        ack={'operationId':plan['operationId'],'bootId':plan['snapshot']['control01']['bootId'],
             'deadlineMonotonic':before+p.TIMEOUT,'timer':timer+'.timer'}
        receipt(root,'watchdog-ack',ack); return ack
    if name == 'probe':
        p.need(not (root/'probe.pending.json').exists(),'probe_uncertain_no_retry')
        current=keeper(plan); p.need(current==p.decode(f.read(root/'started.json')),'keeper_restarted')
        ack=p.decode(f.read(root/'watchdog-ack.json'))
        p.need(ack['deadlineMonotonic']-time.monotonic()>20,'probe_watchdog_budget')
        receipt(root,'probe.pending',{'operationId':plan['operationId']})
        return relay.control(root,'probe')
    if name == 'resume': return relay.control(root,'resume')
    if name == 'observe':
        if (root/'closed.json').exists(): return p.decode(f.read(root/'closed.json'))
        if (root/'close.pending.json').exists() and (root/'unmounted.json').exists():
            result=p.decode(f.read(root/'probe-result.json')) if (root/'probe-result.json').exists() else {'exitCode':None,'outputSHA256':None}; preserved(plan,host)
            value={'operationId':plan['operationId'],'closed':True,'probePassed':result['exitCode']==0,'outputSHA256':result['outputSHA256']}
            receipt(root,'closed',value); return value
        # Observe-only recovery never repeats start/arm/probe side effects.
        state=relay.control(root,'state')
        if (root/'start.pending.json').exists() and not (root/'started.json').exists(): receipt(root,'started',keeper(plan))
        return state
    if name == 'close':
        p.need(not (root/'close.pending.json').exists(),'close_uncertain_observe_only')
        state=relay.control(root,'state')
        p.need(state['state']=='resumed' and (not state['probeStarted'] or state['probeResult'] is not None) and not state['children'],'probe_not_reaped')
        p.need((root/'watchdog-complete.json').exists(),'watchdog_not_completed')
        preserved(plan,host); receipt(root,'close.pending',{'operationId':plan['operationId']})
        relay.control(root,'shutdown')
        deadline=time.monotonic()+10
        while not (root/'unmounted.json').exists(): p.need(time.monotonic()<deadline,'unmount_pending'); time.sleep(.1)
        result=state['probeResult'] or {'exitCode':None,'outputSHA256':None}
        value={'operationId':plan['operationId'],'closed':True,'probePassed':result['exitCode']==0,'outputSHA256':result['outputSHA256']}
        receipt(root,'closed',value); return value
    raise p.b.Failure('phase_unknown')


def execute(payload):
    p.need(os.getuid()==0 and sys.platform=='linux','root_linux_required')
    host=socket.gethostname().split('.')[0]
    p.need(host in ('control01','storage01','pg01') and payload.get('host')==host,'host_boundary')
    if payload['phase']=='snapshot': return snapshot(host,payload['revision'])
    p.need(payload['phase'] in ('stage','start','arm','probe','state','resume','observe','close','preserved'),'phase_boundary')
    p.need(payload['phase'] in ('state','preserved','observe') or payload.get('apply') is True,'explicit_mutation_required')
    p.validate(payload['plan'])
    if payload['phase']=='preserved': return phase(payload)
    with lock(create=payload['phase']=='stage'): return phase(payload)


if __name__=='__main__':
    try:
        p.need(len(sys.argv)==3 and sys.argv[1]=='--watchdog' and os.getuid()==0,'watchdog_arguments')
        print(p.encoded(watchdog(Path(sys.argv[2]))).decode(),end='')
    except Exception:
        print('isolated_nfs_recovery_failed',file=sys.stderr); sys.exit(1)
