#!/usr/bin/env python3
"""Fixed Lab dependency faults with pre-armed, independently durable recovery."""
import base64
import contextlib
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
if 'p' not in globals():
    spec = importlib.util.spec_from_file_location('fault_plan', HERE/'dashboard-dependency-fault-plan.py')
    p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
BASE = Path('/var/lib/jobman-dashboard-dependency-faults')
ROLES = {
 'api': ('storage01', '/etc/jobman-dashboard-api-lab', 21904, 'jobman-dashboard-api', 'jobman-dashboard-lab-api'),
 'worker': ('storage01', '/etc/jobman-dashboard-worker-lab', 21905, 'jobman-dashboard-worker', 'jobman-dashboard-lab-worker'),
 'broker': ('control01', '/etc/jobman-dashboard-broker-lab', 21901, 'jobman-dashboard-log', 'jobman-dashboard-lab-broker')}
SOURCE_FILES = {
 '/etc/jobman-dashboard-lab/control-fixture': 21902,
 '/etc/jobman-dashboard-secondary/control': 21907,
 '/etc/jobman-dashboard-secondary/directory': 21908}
PRESERVED_UNITS = ('jobman-control', 'jobman-keycloak', 'jobman-dashboard-lab-control',
                   'jobman-dashboard-lab-control-secondary', 'jobman-dashboard-lab-directory',
                   'jobman-dashboard-lab-directory-secondary', 'jobman-dashboard-lab-broker')


ACTIVE_DEADLINE = None


@contextlib.contextmanager
def bounded(seconds):
    global ACTIVE_DEADLINE
    previous = ACTIVE_DEADLINE
    ACTIVE_DEADLINE = min(previous or float('inf'), time.monotonic()+seconds)
    try: yield
    finally: ACTIVE_DEADLINE = previous


def remaining(timeout):
    if ACTIVE_DEADLINE is not None: timeout = min(timeout, ACTIVE_DEADLINE-time.monotonic())
    p.need(timeout > 0, 'operation_deadline')
    return timeout


def run(args, code, timeout=5, data=None, maximum=1<<20):
    p.need(p.re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code), 'invalid_failure_code')
    timeout = remaining(timeout)
    # All programs/arguments come from fixed code and validated plan identities.
    # Process output is bounded while read, rather than after communicate().
    import selectors
    with subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as child:
        selector = selectors.DefaultSelector(); output = bytearray(); errors = 0; sent = 0
        deadline = time.monotonic()+timeout
        for stream, name in ((child.stdout, 'out'), (child.stderr, 'err')):
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, name)
        if data is not None:
            os.set_blocking(child.stdin.fileno(), False); selector.register(child.stdin, selectors.EVENT_WRITE, 'in')
        try:
            while selector.get_map():
                p.need(time.monotonic()<deadline, code)
                for key, _ in selector.select(min(.1, max(.001, deadline-time.monotonic()))):
                    if key.data == 'in':
                        if sent<len(data): sent += os.write(key.fileobj.fileno(), data[sent:sent+16384])
                        if sent == len(data): selector.unregister(key.fileobj); key.fileobj.close()
                        continue
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw: selector.unregister(key.fileobj); continue
                    if key.data == 'out': output.extend(raw); p.need(len(output)<=maximum, code)
                    else: errors += len(raw); p.need(errors<=65536, code)
            p.need(child.wait(timeout=max(.001, deadline-time.monotonic())) == 0, code)
            return bytes(output)
        finally:
            selector.close()
            if child.poll() is None: os.killpg(child.pid, signal.SIGKILL); child.wait()


def read(path, uid=0, mode=0o600, maximum=1<<20):
    path = Path(path); p.need(path.is_absolute() and path.parent.resolve()==path.parent, 'file_parent')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        p.need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==uid and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==mode and 0<before.st_size<=maximum, 'private_file')
        data = stream.read(maximum+1); after = os.fstat(stream.fileno()); named=path.lstat()
        p.need(len(data)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and (before.st_dev,before.st_ino)==(named.st_dev,named.st_ino), 'file_changed')
        return data


def sync(path):
    fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def put(path, data, mode=0o600):
    fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode); stream.write(data); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def directory(path, create=False):
    if create:
        try: path.mkdir(mode=0o700); path.chmod(0o700); sync(path.parent)
        except FileExistsError: pass
    info=path.lstat(); p.need(path.resolve()==path and stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700, 'operation_directory')


@contextlib.contextmanager
def locked(timeout=5):
    directory(BASE, create=True)
    try: fd=os.open(BASE/'.lock', os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600); os.fchmod(fd,0o600)
    except FileExistsError: fd=os.open(BASE/'.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd); p.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600,'lock_identity')
        deadline=time.monotonic()+timeout
        while True:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError: p.need(time.monotonic()<deadline,'lock_busy'); time.sleep(.05)
        yield
    finally: os.close(fd)


def properties(unit):
    names=('MainPID','ExecMainStartTimestampMonotonic','ActiveState','DropInPaths','FragmentPath','KillMode','TimeoutStopUSec')
    value=dict(line.split('=',1) for line in run(['systemctl','show',unit,*['--property='+x for x in names]],'unit_properties').decode().splitlines())
    p.need(set(value)==set(names) and value['DropInPaths']=='','unit_properties_shape')
    p.need(value['FragmentPath']=='/etc/systemd/system/'+unit+'.service','unit_fragment')
    if unit in ('jobman-dashboard-lab-directory', 'jobman-dashboard-lab-broker'):
        p.need(value['KillMode']=='control-group' and value['TimeoutStopUSec'] in ('1min 30s','90s'),'stop_policy')
    return value


def process(unit, binary_proof=True):
    value=properties(unit); pid=value['MainPID']
    p.need(value['ActiveState']=='active' and p.decimal(pid) and int(pid)>0 and p.decimal(value['ExecMainStartTimestampMonotonic']),'process_inactive')
    proc=Path('/proc')/pid; image=Path(os.readlink(proc/'exe'))
    p.need(image.is_absolute() and image.resolve()==image,'process_image')
    actual=(proc/'exe').stat(); named=image.stat()
    p.need((actual.st_dev,actual.st_ino)==(named.st_dev,named.st_ino),'process_image_replaced')
    return {'pid':pid,'start':value['ExecMainStartTimestampMonotonic'], 'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'uid':proc.stat().st_uid,'binary':str(image),'binarySHA256':p.sha(read(image,0,0o755,128<<20)) if binary_proof else None,
            'unitSHA256':p.sha(read(value['FragmentPath'],0,0o644,32768)), 'argumentsSHA256':p.sha((proc/'cmdline').read_bytes())}


def material_paths(value):
    result=set()
    if isinstance(value,dict):
        for key, item in value.items():
            if key.endswith('File') and isinstance(item,str) and item: result.add(item)
            else: result.update(material_paths(item))
    elif isinstance(value,list):
        for item in value: result.update(material_paths(item))
    return result


def source_capabilities(port, root, uid):
    user={21902:'jobman-dashboard-source',21907:'jobman-dashboard-source2'}[uid]
    raw=run(['runuser','-u',user,'--','curl','--silent','--fail','--max-time','3','--cacert',root+'/fixture-ca.crt',f'https://127.0.0.1:{port}/v1/capabilities'],'source_capabilities',timeout=4,maximum=65536)
    value=p.decode(raw)['capabilities']
    return {key:value[key] for key in ('instanceId','recoveryEpoch')}


def source_preflight(root,uid):
    path=Path(root); info=path.lstat()
    p.need(path.resolve()==path and stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==uid and stat.S_IMODE(info.st_mode)==0o700,'source_root_identity')
    for pattern in ('.directory-acceptance-*.json','.diagnostic-prepare.json','.secondary-prepare.json'):
        p.need(not list(path.glob(pattern)),'pending_source_operation')
    pending,complete=path/'.scale-seed.pending.json',path/'.scale-seed.completed.json'
    if pending.exists() or complete.exists():
        p.need(pending.exists() and complete.exists() and read(pending,0,maximum=8192)==read(complete,0,maximum=8192),'pending_scale_operation')


def host_snapshot(host, revision, allow_fault=None):
    p.need(host in ('control01','storage01') and p.REVISION.fullmatch(revision),'snapshot_host')
    files={}; processes={}; revisions=[]
    for role,(owner,root,uid,_,unit) in ROLES.items():
        if owner!=host: continue
        raw=read(root+'/config.json',uid); config=p.decode(raw); files[root+'/config.json']=p.sha(raw)
        revisions.append(config['configurationRevision'])
        for name in material_paths(config):
            if name=='/etc/pki/ca-trust/source/anchors/jobman-lab-ca.crt': owner_uid,mode=0,0o644
            else:
                p.need(name.startswith(root+'/'),'secret_reference_scope'); owner_uid,mode=uid,0o600
            files[name]=p.sha(read(name,owner_uid,mode))
        files['/etc/systemd/system/'+unit+'.service']=p.sha(read('/etc/systemd/system/'+unit+'.service',0,0o644,32768))
        if unit!=allow_fault:
            processes[unit]=process(unit)
            p.need(processes[unit]['uid']==uid and processes[unit]['binary'].startswith('/opt/jobman-dashboard-lab/releases/'+revision+'/bin/'),'dashboard_release')
    if host=='control01':
        for unit in PRESERVED_UNITS:
            if unit!=allow_fault: processes[unit]=process(unit, binary_proof=unit not in ('jobman-control','jobman-keycloak'))
            files['/etc/systemd/system/'+unit+'.service']=p.sha(read('/etc/systemd/system/'+unit+'.service',0,0o644,32768))
        for root,uid in SOURCE_FILES.items():
            source_preflight(root,uid)
            for name in ('control.env','directory.json','delegation.json','fixture-info.json','directory-state.json'):
                path=Path(root)/name
                if path.exists(): files[str(path)]=p.sha(read(path,uid,0o600,1<<20))
        caps=[source_capabilities(18443,'/etc/jobman-dashboard-lab/control-fixture',21902),source_capabilities(28443,'/etc/jobman-dashboard-secondary/control',21907)]
        p.need({v['instanceId'] for v in caps}==set(p.SOURCE_IDS.values()) and all(p.decimal(v['recoveryEpoch']) for v in caps),'source_identity')
    else: caps=[]
    return {'host':host,'revision':revision,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'configurationRevisions':revisions,'processes':processes,'files':files,'capabilities':caps,
            'firewallSHA256': firewall_preserved() if host=='storage01' else None,
            'preservedSHA256':p.sha(p.encoded({'files':files,'capabilities':caps,'configurationRevisions':revisions}))}


def expected_processes(plan,host,fault=None):
    expected=copy.deepcopy(plan['snapshot'][host]['processes'])
    if fault:
        for prior in plan['faults'][:plan['faults'].index(fault)]:
            if p.FAULTS[prior]['host']!=host: continue
            root=intent_path(plan,prior)
            result=p.decode(read(root/'restored.json'))
            p.need(result['operationId']==plan['operationId'] and result['fault']==prior and result['restored'] is True and
                   p.decode(read(root/'watchdog-complete.json'))['restored'] is True,'previous_fault_unrestored')
            unit=p.FAULTS[prior]['unit']
            if unit:
                old=expected[unit]; new=result['process']
                p.need(set(new)==set(old) and all(new[k]==old[k] for k in old if k not in ('pid','start')) and
                       int(new['start'])>=int(old['start']),'previous_recovery_identity')
                expected[unit]=new
    return expected


def unchanged(plan, host, fault=None, restarted=None, allow_target=False):
    before=plan['snapshot'][host]; unit=p.FAULTS[fault]['unit'] if fault and allow_target else None
    current=host_snapshot(host,plan['revision'],allow_fault=unit)
    p.need(current['bootId']==before['bootId'] and current['preservedSHA256']==before['preservedSHA256'] and current['firewallSHA256']==before['firewallSHA256'],'host_authority_changed')
    expected={k:v for k,v in expected_processes(plan,host,fault).items() if k!=unit}
    p.need(current['processes']==expected,'unrelated_process_changed')
    if restarted is not None: p.need(process(unit)==restarted,'recovered_process_changed')


def nft_table(operation):
    name=p.table_name(operation)
    raw=run(['/usr/sbin/nft','--json','--numeric','list','tables'],'nft_tables',maximum=1<<20)
    tables=p.decode(raw).get('nftables',[])
    if not any(v.get('table',{}).get('family')=='inet' and v.get('table',{}).get('name')==name for v in tables): return None
    value=p.decode(run(['/usr/sbin/nft','--json','--numeric','list','table','inet',name],'nft_table',maximum=65536))
    return value


def normalize_nft(value):
    if isinstance(value,list): return [normalize_nft(v) for v in value if not isinstance(v,dict) or 'metainfo' not in v]
    if isinstance(value,dict):
        result={k:normalize_nft(v) for k,v in value.items() if k != 'handle'}
        if 'counter' in result and isinstance(result['counter'],dict):
            for key in ('packets','bytes'): result['counter'].pop(key,None)
        return result
    return value


def firewall_preserved(operation=None):
    value=p.decode(run(['/usr/sbin/nft','--json','--numeric','list','ruleset'],'firewall_baseline',maximum=2<<20))
    allowed=p.table_name(operation) if operation else None
    rows=[item for item in value['nftables'] if not any(allowed is not None and isinstance(v,dict) and v.get('family')=='inet' and
          (v.get('table')==allowed or k=='table' and v.get('name')==allowed) for k,v in item.items())]
    return p.sha(p.encoded(normalize_nft({'nftables':rows})))


def validate_table(table, plan, fault):
    # This expected semantic form existed BEFORE the write. It permits safe
    # restoration even when apply succeeded and its response/receipt was lost.
    expected={'nftables':p.firewall_elements(plan['operationId'],fault)}
    p.need(normalize_nft(table)==expected,'firewall_table_drift')
    counters=[v['counter'] for obj in table['nftables'] for v in obj.get('rule',{}).get('expr',[]) if 'counter' in v]
    p.need(len(counters)==1 and all(type(counters[0].get(k)) is int and counters[0][k]>=0 for k in ('packets','bytes')),'firewall_counter')
    return counters[0]


def intent_path(plan, fault):
    p.need(fault in plan['faults'],'fault_not_planned')
    return BASE/plan['operationId']/fault


def receipt(root, name, value):
    path=root/(name+'.json'); raw=p.encoded(value)
    if path.exists(): p.need(read(path)==raw,'receipt_changed')
    else: put(path,raw)


def timer_name(plan,fault): return 'jobman-dashboard-fault-'+plan['operationId'].replace('-','')+'-'+fault.replace('_','-')


def arm_watchdog(plan,fault,root):
    name=timer_name(plan,fault); seconds=p.FAULTS[fault]['watchdogSeconds']
    armed_at=time.monotonic()
    run(['systemd-run','--quiet','--unit='+name,'--on-active='+str(seconds)+'s','--timer-property=AccuracySec=1s','--timer-property=RandomizedDelaySec=0','--property=Type=oneshot','--property=TimeoutStartSec=30s',
         '/usr/bin/python3',str(root.parent/'dashboard-dependency-fault-guest.py'),'--watchdog',str(root)],'watchdog_arm',timeout=7)
    values=dict(v.split('=',1) for v in run(['systemctl','show',name+'.timer','--property=ActiveState','--property=Triggers'],'watchdog_ack').decode().splitlines())
    p.need(values=={'ActiveState':'active','Triggers':name+'.service'},'watchdog_not_armed')
    # Earliest possible expiry, captured before successful timer creation.
    # We only shorten the usable interval; no formatted systemd timespan is
    # misread as a raw monotonic timestamp. Timer creation is bounded7s.
    due=armed_at+seconds
    p.need(time.monotonic()<due,'watchdog_deadline')
    receipt(root,'watchdog-armed',{'timer':name+'.timer','deadlineMonotonic':due,'bootId':plan['snapshot'][p.FAULTS[fault]['host']]['bootId']})
    return due


def require_window(root, due, reserve):
    p.need(not (root/'restored.json').exists() and due-time.monotonic()>=reserve,'fault_window_expired')


def target_pins(plan, fault):
    host=p.FAULTS[fault]['host']; unit=p.FAULTS[fault]['unit']
    p.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['snapshot'][host]['bootId'],'boot_changed')
    if unit:
        old=expected_processes(plan,host,fault)[unit]
        p.need(p.sha(read('/etc/systemd/system/'+unit+'.service',0,0o644,32768))==old['unitSHA256'] and
               p.sha(read(old['binary'],0,0o755,128<<20))==old['binarySHA256'],'target_binary_or_unit_changed')
        properties(unit)
        root,uid=('/etc/jobman-dashboard-broker-lab',21901) if fault.startswith('broker_') else ('/etc/jobman-dashboard-lab/control-fixture',21902)
        for filename,digest in plan['snapshot'][host]['files'].items():
            if filename.startswith(root+'/'):
                p.need(p.sha(read(filename,uid))==digest,'target_material_changed')
    else:
        p.need(firewall_preserved(plan['operationId'])==plan['snapshot'][host]['firewallSHA256'],'unrelated_firewall_changed')


def wait_state(pid, stopped):
    deadline=time.monotonic()+1
    while True:
        state=Path('/proc',pid,'status').read_text().split('State:',1)[1].lstrip().startswith('T')
        if state==stopped: return
        p.need(time.monotonic()<deadline,'signal_unconfirmed'); time.sleep(.02)


def begin(plan,fault):
    host=p.FAULTS[fault]['host']; root=intent_path(plan,fault)
    p.need(0<=time.time()-plan['createdAt']<=3600,'plan_expired')
    with locked():
        directory(root.parent); verify_staged(root.parent,plan)
        p.need(not root.exists(),'fault_already_started')
        for old in BASE.glob('*/*/intent.json'): p.need((old.parent/'restored.json').exists(),'another_fault_pending')
        with bounded(40): unchanged(plan,host,fault)
        directory(root,create=True)
        receipt(root,'intent',{'planSHA256':p.sha(p.encoded(plan)),'fault':fault,'createdAt':time.time()})
        # All expensive unrelated proofs precede arming. The remaining critical
        # section is bounded below the watchdog deadline, including stop90s.
        due=arm_watchdog(plan,fault,root)
        with bounded(100 if fault.endswith('_stop') else 15):
            require_window(root,due,p.FAULTS[fault]['applyReserveSeconds'])
            target_pins(plan,fault)
            require_window(root,due,p.FAULTS[fault]['applyReserveSeconds'])
            unit=p.FAULTS[fault]['unit']
            if fault.endswith('_stop'):
                receipt(root,'stop-intent',{'process':expected_processes(plan,host,fault)[unit]})
                require_window(root,due,p.FAULTS[fault]['applyReserveSeconds'])
                # Killing a timed-out client never authorizes reissuing stop.
                # A pending result goes only through inspect/recover/watchdog.
                run(['systemctl','stop',unit],'fault_stop',timeout=95)
                p.need(properties(unit)['ActiveState']=='inactive','fault_stop_unconfirmed')
                if fault=='directory_stop': require_window(root,due,125)
            elif fault in ('broker_pause','control_pause'):
                expected=expected_processes(plan,host,fault)[unit]
                p.need(process(unit)==expected,'pause_process_changed')
                receipt(root,'pause-intent',{'process':expected})
                p.need(process(unit)==expected,'pause_process_changed')
                require_window(root,due,p.FAULTS[fault]['applyReserveSeconds'])
                os.kill(int(expected['pid']),signal.SIGSTOP); wait_state(expected['pid'],True)
            else:
                p.need(nft_table(plan['operationId']) is None,'firewall_table_exists')
                batch=p.firewall_batch(plan['operationId'],fault)
                run(['/usr/sbin/nft','--json','--check','--file','-'],'firewall_check',data=batch)
                receipt(root,'firewall-intent',{'batchSHA256':p.sha(batch),'expected':p.firewall_elements(plan['operationId'],fault)})
                require_window(root,due,20)
                run(['/usr/sbin/nft','--json','--file','-'],'firewall_apply',data=batch)
                table=nft_table(plan['operationId']); p.need(table is not None,'firewall_apply_unconfirmed')
                counters=validate_table(table,plan,fault)
                receipt(root,'firewall-applied',{'counter':counters})
            receipt(root,'applied',{'fault':fault,'atMonotonic':time.monotonic()})
            return {'fault':fault,'operationId':plan['operationId'],'applied':True,'watchdogDeadlineMonotonic':due}


def recover(plan,fault,watchdog=False):
    root=intent_path(plan,fault); host=p.FAULTS[fault]['host']; unit=p.FAULTS[fault]['unit']
    # The begin critical section ends at least20s before the timer. This short
    # lock wait is not permission for a late stop after a completed recovery.
    with locked(timeout=2), bounded(25):
        directory(root); verify_staged(root.parent,plan)
        intent=p.decode(read(root/'intent.json'))
        p.need(intent['planSHA256']==p.sha(p.encoded(plan)) and intent['fault']==fault,'intent_changed')
        target_pins(plan,fault)
        if (root/'restored.json').exists():
            result=p.decode(read(root/'restored.json'))
            if unit: p.need(process(unit)==result['process'],'completed_recovery_changed')
            else: p.need(nft_table(plan['operationId']) is None,'firewall_reappeared')
        else:
            receipt(root,'recovery-intent',{'planSHA256':p.sha(p.encoded(plan)),'fault':fault})
            if fault.endswith('_stop'):
                state=properties(unit)['ActiveState']; p.need(state in ('active','inactive','deactivating','failed'),'unit_transitional')
                # A manually requested recovery may precede the original stop
                # job finishing. Do not start until systemd confirms completion;
                # leave the independent timer intact if this bounded call fails.
                while state=='deactivating':
                    time.sleep(.1); state=properties(unit)['ActiveState']
                p.need(state in ('active','inactive','failed'),'unit_transitional')
                if state!='active': run(['systemctl','start','--no-block',unit],'fault_restart')
                old=expected_processes(plan,host,fault)[unit]
                confirmed_stop=(root/'applied.json').exists()
                while True:
                    remaining(1)
                    try:
                        recovered=process(unit)
                        remaining(1)
                        # Type=simple can become active while the ExecStart
                        # wrapper is still transitioning to its final image.
                        # Observe convergence under the same recovery deadline;
                        # never issue another start or accept a weaker identity.
                        if (set(recovered)==set(old) and
                            all(recovered[k]==old[k] for k in old if k not in ('pid','start')) and
                            int(recovered['start'])>=int(old['start']) and
                            (not confirmed_stop or int(recovered['start'])>int(old['start']))): break
                    except (ValueError,OSError): pass
                    time.sleep(remaining(.1))
            elif fault in ('broker_pause','control_pause'):
                old=expected_processes(plan,host,fault)[unit]; p.need(process(unit)==old,'paused_process_replaced')
                os.kill(int(old['pid']),signal.SIGCONT); wait_state(old['pid'],False); recovered=process(unit)
                p.need(recovered==old,'continued_process_changed')
            else:
                table=nft_table(plan['operationId']); counters=None
                if table is not None:
                    recorded=p.decode(read(root/'firewall-intent.json'))
                    p.need(recorded=={'batchSHA256':p.sha(p.firewall_batch(plan['operationId'],fault)),'expected':p.firewall_elements(plan['operationId'],fault)},'firewall_intent_changed')
                    counters=validate_table(table,plan,fault)
                    proof={'counter':counters,'expectedSHA256':p.sha(p.encoded(recorded['expected']))}
                    if (root/'firewall-removal-proof.json').exists():
                        prior=p.decode(read(root/'firewall-removal-proof.json'))
                        p.need(prior['expectedSHA256']==proof['expectedSHA256'] and all(counters[k]>=prior['counter'][k] for k in ('packets','bytes')),'firewall_counter_regressed')
                    else: receipt(root,'firewall-removal-proof',proof)
                    run(['/usr/sbin/nft','delete','table','inet',p.table_name(plan['operationId'])],'firewall_remove')
                p.need(nft_table(plan['operationId']) is None,'firewall_remove_unconfirmed'); recovered=None
            result={'operationId':plan['operationId'],'fault':fault,'restored':True,'process':recovered,'atMonotonic':time.monotonic()}
            receipt(root,'restored',result)
        # Calling the very same durable watchdog recovery path manually permits
        # immediate proof; its still-armed timer later verifies, never reapplies.
        if watchdog: receipt(root,'watchdog-complete',{'restored':True,'operationId':plan['operationId'],'fault':fault})
        return result


def verify_staged(root,plan):
    directory(root)
    p.need(read(root/'plan.json')==p.encoded(plan),'staged_plan_changed')
    for name,digest in plan['implementationSHA256'].items():
        p.need(p.sha(read(root/name,maximum=256<<10))==digest,'staged_implementation_changed')


def stage(plan,host,sources):
    p.need(host in {p.FAULTS[f]['host'] for f in plan['faults']},'stage_host')
    p.need(set(sources)==set(p.IMPLEMENTATION),'stage_files')
    decoded={k:base64.b64decode(v,validate=True) for k,v in sources.items()}
    p.need(all(0<len(v)<=256<<10 and p.sha(v)==plan['implementationSHA256'][k] for k,v in decoded.items()),'stage_hashes')
    with locked():
        with bounded(40): unchanged(plan,host)
        root=BASE/plan['operationId']
        if root.exists():
            verify_staged(root,plan); p.need((root/'stage-complete.json').exists(),'stage_incomplete')
        else:
            directory(root,create=True); put(root/'plan.json',p.encoded(plan))
            for name,raw in decoded.items(): put(root/name,raw)
            receipt(root,'stage-complete',{'planSHA256':p.sha(p.encoded(plan)),'host':host})
        return {'staged':True,'operationId':plan['operationId'],'host':host}


DATABASE_SQL = """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms';
SELECT json_build_object(
 'ledger',(SELECT json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name) FROM dashboard_schema_migrations),
 'databaseOID',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
 'hold',(SELECT json_build_object('generation',generation::text,'held',held,'suppressRecordedThrough',restore_recorded_through::text) FROM dashboard_notification_delivery_control WHERE singleton),
 'sources',(SELECT json_agg(json_build_object('deploymentId',f.deployment_id,'controlInstanceId',i.control_instance_id,
   'recoveryEpoch',i.recovery_epoch,'namespaceIds',f.namespace_ids,'configurationRevision',i.configuration_revision,'status',f.status,'generation',f.generation::text,'lastPosition',f.last_position::text,
   'openGaps',(SELECT count(*) FROM dashboard_event_gaps g WHERE g.deployment_id=f.deployment_id AND g.resolved_at IS NULL),
   'unfinishedRecoveries',(SELECT count(*) FROM dashboard_event_recoveries x WHERE x.deployment_id=f.deployment_id AND x.status IN('replaying','ready','quarantined')))
   ORDER BY f.deployment_id) FROM dashboard_event_feeds f FULL JOIN dashboard_source_identities i USING(deployment_id)),
 'roleProof',json_build_object(
   'roles',(SELECT json_agg(json_build_object('name',rolname,'super',rolsuper,'inherit',rolinherit,'createRole',rolcreaterole,'createDB',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,'bypassRLS',rolbypassrls,'limit',rolconnlimit) ORDER BY rolname) FROM pg_roles WHERE rolname IN('jobman_dashboard_ddl','jobman_dashboard_api','jobman_dashboard_worker','jobman_dashboard_operator')),
   'members',(SELECT coalesce(json_agg(json_build_object('role',r.rolname,'member',m.rolname,'admin',a.admin_option,'inherit',a.inherit_option,'set',a.set_option) ORDER BY r.rolname,m.rolname),'[]') FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member WHERE r.rolname IN('jobman_dashboard_ddl','jobman_dashboard_api','jobman_dashboard_worker','jobman_dashboard_operator') OR m.rolname IN('jobman_dashboard_ddl','jobman_dashboard_api','jobman_dashboard_worker','jobman_dashboard_operator')),
   'tables',(SELECT json_agg(json_build_object('name',c.relname,'owner',pg_get_userbyid(c.relowner),'acl',c.relacl::text) ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
   'columns',(SELECT coalesce(json_agg(json_build_object('table',c.relname,'column',a.attname,'acl',a.attacl::text) ORDER BY c.relname,a.attnum),'[]') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL),
   'functions',(SELECT coalesce(json_agg(json_build_object('oid',f.oid,'owner',pg_get_userbyid(f.proowner),'acl',f.proacl::text) ORDER BY f.oid),'[]') FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='public'),
   'defaults',(SELECT coalesce(json_agg(json_build_object('role',pg_get_userbyid(d.defaclrole),'namespace',d.defaclnamespace,'kind',d.defaclobjtype,'acl',d.defaclacl::text) ORDER BY d.oid),'[]') FROM pg_default_acl d),
   'database',(SELECT json_build_object('owner',pg_get_userbyid(datdba),'acl',datacl::text) FROM pg_database WHERE datname=current_database()),
   'schema',(SELECT json_build_object('owner',pg_get_userbyid(nspowner),'acl',nspacl::text) FROM pg_namespace WHERE nspname='public')));
COMMIT;
"""


def database():
    args=['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-q','-A','-t','-U','jobman_control','-v','ON_ERROR_STOP=1','-d','jobman_dashboard']
    value=p.decode(run(args,'database_snapshot',data=DATABASE_SQL.encode(),timeout=15,maximum=2<<20))
    ledger=value.pop('ledger'); roles=value.pop('roleProof')
    p.need(len(ledger)==18 and ledger[-1]['name']=='migrations/000018_runtime_lock_privileges.sql' and
           all(set(v)=={'name','sha256'} and p.HEX.fullmatch(v['sha256']) for v in ledger),'database_schema')
    p.need(len(roles['roles'])==4,'database_roles')
    value['schemaSHA256']=p.sha(p.encoded(ledger)); value['rolesSHA256']=p.sha(p.encoded(roles))
    return p.stable_database(value)


def execute(payload):
    p.need(os.geteuid()==0 and sys.platform=='linux','guest_required')
    phase=payload['phase']; host=socket.gethostname().split('.')[0]
    p.need(payload.get('host')==host and host in ('control01','storage01','pg01'),'guest_host')
    p.need(phase in ('snapshot','stage','begin','recover','status','verify','database-check','observe-api'),'phase_invalid')
    if phase=='snapshot': return {'database':database()} if host=='pg01' else host_snapshot(host,payload['revision'])
    plan=payload['plan']; p.validate(plan)
    if phase=='database-check':
        p.need(host=='pg01','database_host'); p.database_preserved(plan['snapshot']['pg01']['database'],database())
        return {'preserved':True}
    if phase=='observe-api':
        p.need(host=='storage01','observer_host')
        rows=[]
        for endpoint in ('livez','readyz'):
            began=time.monotonic()
            raw=run(['runuser','-u','jobman-dashboard-api','--','curl','--silent','--show-error','--max-time','3','--unix-socket','/run/jobman-dashboard-api-lab/observe.sock','--write-out','\n%{http_code}','http://localhost/'+endpoint],'api_observability',timeout=3.2,maximum=16384)
            body,status=raw.rsplit(b'\n',1); value=p.decode(body)
            p.need(status in (b'200',b'503') and value.get('role')=='api' and value.get('state') in ('alive','ready','unavailable'),'api_observability_shape')
            rows.append({'endpoint':endpoint,'status':int(status),'milliseconds':(time.monotonic()-began)*1000,'state':value['state']})
        return {'observations':rows}
    if phase=='stage':
        p.need(payload.get('apply') is True,'explicit_stage_required'); return stage(plan,host,payload['sources'])
    fault=payload.get('fault'); p.need(fault in plan['faults'] and host==p.FAULTS[fault]['host'],'fault_host')
    p.need(phase in ('status','verify') or payload.get('apply') is True,'explicit_phase_required')
    if phase=='begin': return begin(plan,fault)
    if phase=='recover':
        # Invoke the already-armed systemd recovery service, independent of this
        # SSH process. Its bounded script also runs if the timer expires.
        run(['systemctl','start',timer_name(plan,fault)+'.service'],'recovery_watchdog',timeout=33)
        result=run(['systemctl','show',timer_name(plan,fault)+'.service','--property=Result','--value'],'watchdog_result').decode().strip()
        p.need(result=='success','watchdog_service_failed')
        return p.decode(read(intent_path(plan,fault)/'restored.json'))
    if phase=='verify':
        root=intent_path(plan,fault); result=p.decode(read(root/'restored.json'))
        unchanged(plan,host,fault,result.get('process'),allow_target=True)
        p.need(p.decode(read(root/'watchdog-complete.json'))['restored'] is True,'watchdog_unconfirmed')
        return {'verified':True,'operationId':plan['operationId'],'fault':fault}
    root=intent_path(plan,fault); directory(root); verify_staged(root.parent,plan)
    with locked():
        result={'operationId':plan['operationId'],'fault':fault,'receipts':{v.stem:p.decode(read(v)) for v in root.glob('*.json')}}
        result['watchdogState']=dict(line.split('=',1) for line in run(['systemctl','show',timer_name(plan,fault)+'.service','--property=ActiveState','--property=Result'],'watchdog_status').decode().splitlines())
        if fault=='control_pause':
            target_pins(plan,fault)
            current=expected_processes(plan,host,fault)[p.FAULTS[fault]['unit']]
            p.need(process(p.FAULTS[fault]['unit'])==current,'paused_process_replaced')
            restored=result['receipts'].get('restored')
            if restored is not None:
                p.need(restored.get('operationId')==plan['operationId'] and restored.get('fault')==fault and
                       restored.get('restored') is True and restored.get('process')==current,'control_restore_receipt_changed')
            wait_state(current['pid'],restored is None)
            result['paused']=restored is None
        if fault.startswith('database_'):
            table=nft_table(plan['operationId'])
            result['counter']=validate_table(table,plan,fault) if table is not None else None
        return result


def main():
    p.need(os.geteuid()==0 and sys.platform=='linux','guest_required')
    if len(sys.argv)==3 and sys.argv[1]=='--watchdog':
        root=Path(sys.argv[2]); p.need(root.parent.parent==BASE and root.name in p.FAULTS,'watchdog_path')
        plan=p.decode(read(root.parent/'plan.json')); p.validate(plan)
        p.need(socket.gethostname().split('.')[0]==p.FAULTS[root.name]['host'],'watchdog_host')
        try: result=recover(plan,root.name,watchdog=True)
        except Exception as error:
            # Preserve the first sanitized recovery failure beside any later
            # successful restoration; never erase or reinterpret the attempt.
            directory(root)
            if not (root/'watchdog-failed.json').exists():
                code=getattr(error,'code','watchdog_failed')
                p.need(p.re.fullmatch(r'[a-z][a-z0-9_]{0,63}',str(code)),'failure_code')
                receipt(root,'watchdog-failed',{'operationId':plan['operationId'],'fault':root.name,'code':code})
            raise
    else:
        raw=sys.stdin.buffer.read((2<<20)+1); p.need(len(raw)<=2<<20,'request_bound')
        result=execute(p.decode(raw))
    sys.stdout.buffer.write(p.encoded(result))


if __name__=='__main__':
    try: main()
    except Exception:
        print('Dependency fault phase failed; preserve private receipts and inspect the exact operation.',file=sys.stderr)
        raise SystemExit(1) from None
