#!/usr/bin/env python3
"""Fixed synthetic LDAP binary upgrade; no directory, source or database edits."""
import base64
import fcntl
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import stat
import time

REVISION = '367006818e72315b01860f56f971004e17c24886'
BINARY = Path('/usr/local/libexec/jobman-dashboard-scale') / REVISION / 'jobman-control-lab-helper'
BINARY_SHA = '6f511e91434dac2499d464f0b424607fe0b099b966148c992499e5371a333f65'
ROOT = Path('/var/lib/jobman-dashboard-scale-directory')
SPECS = {
 'primary': {'unit': 'jobman-dashboard-lab-directory', 'user': 'jobman-dashboard-source', 'uid': 21902,
  'old': '/usr/local/libexec/jobman-dashboard-lab/jobman-control-lab-helper',
  'oldSHA256': '962d468f1506a0450d9175871c5092e861fa69b21e644e36d0bba2826a1978d7',
  'unitSHA256': 'fcc6f2cd4fe5fe9dff93b79ab72dd97c0bf9efbb107f55a91ce10bcd9e42cf1d',
  'args': ['directory','--root','/etc/jobman-dashboard-lab/control-fixture'], 'port': 18636,
  'control': '/etc/jobman-dashboard-lab/control-fixture', 'directory': '/etc/jobman-dashboard-lab/control-fixture', 'sourceUID': 21902},
 'secondary': {'unit': 'jobman-dashboard-lab-directory-secondary', 'user': 'jobman-dashboard-directory2', 'uid': 21908,
  'old': '/usr/local/libexec/jobman-dashboard-secondary/jobman-control-lab-helper',
  'oldSHA256': '5b6f50215097c727b511a721d9e5ae16af7a25390dc5bacf87d211c6c28252f7',
  'unitSHA256': 'b2b7bd47f596f759ae537b04d5e3869095ff8d4b898055d63d3bb8ea7dbb845e',
  'args': ['directory','--profile','secondary-v1','--root','/etc/jobman-dashboard-secondary/directory'], 'port': 28636,
  'control': '/etc/jobman-dashboard-secondary/control', 'directory': '/etc/jobman-dashboard-secondary/directory', 'sourceUID': 21907}}


def remaining(deadline,maximum):
    value=maximum if deadline is None else min(maximum,deadline-time.monotonic())
    c.need(value>0,'verification_deadline');return value


def command(args, timeout=5): return c.run(args,b'',timeout=timeout)


def root_directory(path):
    c.need(path.is_absolute() and path.resolve()==path,'directory_alias')
    for ancestor in [path,*path.parents]:
        info=ancestor.lstat()
        c.need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not stat.S_IMODE(info.st_mode)&0o022,'unsafe_directory_ancestor')


def properties(unit,deadline=None):
    names=('MainPID','ExecMainStartTimestampMonotonic','DropInPaths','User','Group')
    values=dict(line.split('=',1) for line in command(['systemctl','show',unit,*['--property='+name for name in names]],remaining(deadline,5)).decode().splitlines())
    c.need(set(values)==set(names) and values['DropInPaths']=='','unexpected_unit_properties')
    for name in names[:2]:c.need(values[name].isdigit() and int(values[name])>0,'service_not_running')
    command(['systemctl','is-active','--quiet',unit],remaining(deadline,5))
    return values


def identity(spec, upgraded=False,deadline=None):
    value=properties(spec['unit'],deadline);pid=value['MainPID']
    c.need(value['User']==value['Group']==spec['user'] and Path('/proc',pid).stat().st_uid==spec['uid'],'ldap_process_role')
    binary=BINARY if upgraded else Path(spec['old'])
    c.need(os.readlink('/proc/'+pid+'/exe')==str(binary),'ldap_executable_identity')
    root_directory(binary.parent)
    c.need(c.sha(c.read(binary,64<<20,mode=0o755,uid=0))==(BINARY_SHA if upgraded else spec['oldSHA256']),'ldap_binary_hash')
    raw=Path('/proc',pid,'cmdline').read_bytes()
    c.need(len(raw)<=8192 and raw.rstrip(b'\0').split(b'\0')==[x.encode() for x in [str(binary),*spec['args']]],'ldap_process_arguments')
    return value


def preserved():
    services={name:properties(name) for name in ('jobman-dashboard-lab-control','jobman-dashboard-lab-control-secondary','jobman-control','jobman-keycloak')}
    files={}
    for spec in SPECS.values():
        for name in ('control.env','directory.json','delegation.json','fixture-info.json'):
            path=Path(spec['control'])/name
            files[str(path)]=c.sha(c.read(path,uid=spec['sourceUID']))
        path=Path(spec['directory'])/'directory-state.json'
        files[str(path)]=c.sha(c.read(path,uid=spec['uid']))
    return {'services':services,'files':files}


def unit_bytes(spec):
    path=Path('/etc/systemd/system')/(spec['unit']+'.service');root_directory(path.parent)
    return path,c.read(path,16384,mode=0o644,uid=0)


def transformed(before,spec):
    c.need(c.sha(before)==spec['unitSHA256'],'original_unit_hash')
    lines=[line for line in before.decode().splitlines() if line.startswith('ExecStart=')]
    expected=[spec['old'],*spec['args']]
    c.need(len(lines)==1 and shlex.split(lines[0][len('ExecStart='):])==expected and before.count(spec['old'].encode())==1,'original_unit_command')
    return before.replace(spec['old'].encode(),str(BINARY).encode())


def tls_ready(spec,deadline=None):
    context=ssl.create_default_context(cafile=str(Path(spec['control'])/'fixture-ca.crt'))
    with socket.create_connection(('127.0.0.1',spec['port']),timeout=remaining(deadline,1)) as raw:
        raw.settimeout(remaining(deadline,1))
        with context.wrap_socket(raw,server_hostname='127.0.0.1') as connection:
            c.need(connection.version() in ('TLSv1.2','TLSv1.3'),'ldap_tls_version')


def write_mode(path,raw,mode):
    if path.exists():c.need(c.read(path,len(raw)+1,mode=mode,uid=0)==raw,'retained_file_differs');return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),mode);os.fchown(stream.fileno(),0,0);stream.write(raw);stream.flush();os.fsync(stream.fileno())
    c.sync(path.parent)


def restart(spec,snapshot,root,binding,phase):
    pending=root/'restart.pending.json';complete=root/'restart.json'
    if phase=='restart' and not pending.exists():
        c.need(identity(spec)==snapshot['process'],'pre_restart_process_drift')
        command(['systemctl','daemon-reload'],timeout=10);c.retain(pending,c.encoded(binding))
        command(['systemctl','--no-block','restart',spec['unit']],timeout=5)
    c.need(c.decode(c.read(pending))==binding,'restart_pending_required')
    if complete.exists():
        expected=c.decode(c.read(complete));actual=identity(spec,True)
        c.need(expected==dict(binding,process=actual),'completed_restart_identity');tls_ready(spec)
    else:
        c.need(phase=='restart','completed_restart_required');deadline=time.monotonic()+40
        while True:
            try:
                actual=identity(spec,True,deadline)
                c.need(actual['ExecMainStartTimestampMonotonic']!=snapshot['process']['ExecMainStartTimestampMonotonic'],'restart_not_observed');tls_ready(spec,deadline);break
            except (ValueError,OSError):
                c.need(time.monotonic()<deadline,'ldap_restart_not_ready');time.sleep(min(.2,max(0,deadline-time.monotonic())))
        c.retain(complete,c.encoded(dict(binding,process=actual)))


def execute(p):
    c.need(os.geteuid()==0 and os.uname().nodename.split('.')[0]=='control01','fixed_root_guest')
    profile=p['profile'];c.need(profile in SPECS,'fixed_profile');spec=SPECS[profile];phase=p['phase']
    c.need(phase in ('snapshot','stage','swap','restart','verify'),'phase_boundary')
    if phase=='snapshot':
        _,before=unit_bytes(spec);after=transformed(before,spec);process=identity(spec);tls_ready(spec)
        return {'version':1,'profile':profile,'epoch':int(time.time()),'process':process,'preserved':preserved(),
                'before':base64.b64encode(before).decode(),'afterSHA256':c.sha(after),'binarySHA256':BINARY_SHA}
    snapshot=p['snapshot'];digest=c.sha(c.encoded(snapshot))
    c.need(re.fullmatch('[0-9a-f]{64}',p['snapshotSHA256']) and digest==p['snapshotSHA256'] and snapshot['profile']==profile and snapshot['binarySHA256']==BINARY_SHA,'snapshot_binding')
    before=base64.b64decode(snapshot['before'],validate=True);after=transformed(before,spec)
    c.need(c.sha(after)==snapshot['afterSHA256'] and preserved()==snapshot['preserved'],'preserved_source_drift')
    root_directory(BINARY.parent);c.need(c.sha(c.read(BINARY,64<<20,mode=0o755,uid=0))==BINARY_SHA,'staged_helper_hash')
    if phase!='verify':c.need(p.get('apply') is True,'explicit_apply_required')
    root=ROOT/digest
    if phase=='stage':
        c.need(0<=time.time()-snapshot['epoch']<=900,'snapshot_expired')
        c.need(identity(spec)==snapshot['process'],'ldap_process_drift')
        for directory in (ROOT,root):
            if not directory.exists():c.mkdir(directory)
            c.private_directory(directory,uid=0);root_directory(directory)
    else:c.private_directory(root,uid=0);root_directory(root)
    fd=os.open(root/'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(fd);c.need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'lock_identity')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        path,current=unit_bytes(spec);binding={'profile':profile,'snapshotSHA256':digest,'beforeSHA256':c.sha(before),'afterSHA256':c.sha(after),'binarySHA256':BINARY_SHA}
        if phase=='stage':
            c.need(current==before,'stage_current_unit');c.retain(root/'snapshot.json',c.encoded(snapshot));write_mode(root/'unit.before',before,0o644);write_mode(root/'unit.after',after,0o644)
            c.retain(root/'stage.json',c.encoded(binding))
        else:
            c.need(c.decode(c.read(root/'stage.json'))==binding and c.read(root/'unit.before',16384,mode=0o644)==before,'stage_receipt')
            if phase=='swap':
                c.need(identity(spec)==snapshot['process'],'pre_swap_process_drift')
                if current==after:c.need(c.decode(c.read(root/'swap.pending.json'))==binding,'swap_pending_required')
                else:
                    c.need(current==before,'swap_compare_failed');c.retain(root/'swap.pending.json',c.encoded(binding))
                    staged=path.parent/('.scale-directory-'+digest+'.service');write_mode(staged,after,0o644)
                    c.need(unit_bytes(spec)[1]==before,'unit_changed_before_swap');os.replace(staged,path);c.sync(path.parent)
                c.retain(root/'swap.json',c.encoded(binding))
            else:
                c.need(current==after and c.decode(c.read(root/'swap.json'))==binding,'swapped_unit_required')
                restart(spec,snapshot,root,binding,phase)
        c.need(preserved()==snapshot['preserved'],'post_phase_source_drift')
        return dict(binding,phase=phase,sourcePreserved=True)
    finally:os.close(fd)
