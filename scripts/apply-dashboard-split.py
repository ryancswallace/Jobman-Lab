#!/usr/bin/env python3
"""Explicit, receipt-gated phases for the reviewed synthetic Lab split.

Default preflight reads guests only. Mutating phases require --apply, an exact
prepared plan digest, and retained preflight/stage/phase receipts. No resume of
notification delivery or automatic rollback is performed.
"""
import argparse
import base64
import fcntl
import stat
from contextlib import contextmanager
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


HERE=Path(__file__).resolve().parent
plan=load('split_plan',HERE/'dashboard-split-plan.py')
prep=load('split_prepare',HERE/'prepare-dashboard-split.py')
HOSTS=('pg01','storage01','control01')


def verified_staging(root,expected):
    raw=plan.read(root/'plan.json',4<<20,private=True)
    plan.require(plan.HEX.fullmatch(expected) and plan.sha(raw)==expected,'Prepared plan digest differs')
    value=plan.decode(raw)
    plan.require(value['format']=='jobman.dashboard.lab-split/v1' and value['synthetic'] is True and value['applies'] is False,'Prepared plan kind differs')
    for name,digest in value['preparedFiles'].items():
        path=Path(name)
        plan.require(not path.is_absolute() and '..' not in path.parts and name==path.as_posix() and plan.HEX.fullmatch(digest),'Prepared file path differs')
        file=root/path;info=file.lstat()
        expected_mode=0o700 if name.startswith('candidate/bin/') else 0o600
        plan.require(info.st_uid==os.getuid() and info.st_mode&0o777==expected_mode and
                     info.st_size==value['preparedFileBytes'][name] and plan.sha(plan.read(file,96<<20))==digest,'Prepared file changed')
    for name,digest in value['implementationSHA256'].items():
        plan.require(name in ('apply-dashboard-split.py','dashboard-split-guest.py','dashboard-split-files.py') and
                     plan.sha(plan.read(HERE/name,1<<20))==digest,'Reviewed apply implementation changed')
    return value


def ssh_connections(lab):
    raw=plan.read(lab/'.lab/dashboard/ssh-connections.json',65536,private=True)
    values=plan.decode(raw)
    plan.require(set(values)==set(HOSTS),'Only existing three Lab guests may be used')
    for c in values.values():
        address=ipaddress.ip_address(c['ansible_host'])
        plan.require(c['ansible_user']=='vagrant' and (str(address) in ('127.0.0.1','10.77.0.10','10.77.0.20','10.77.0.21') or address in ipaddress.ip_network('10.211.55.0/24')) and
                     type(c['ansible_port']) is int and 1<=c['ansible_port']<=65535 and Path(c['ansible_ssh_private_key_file']).is_absolute(),'Unexpected Lab SSH endpoint')
    return values


def remote(lab,connections,host,payload):
    c=connections[host]
    code=plan.read(HERE/'dashboard-split-guest.py',1<<20).decode()
    args=['ssh','-i',c['ansible_ssh_private_key_file'],'-p',str(c['ansible_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
          '-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={lab}/.lab/dashboard/known_hosts',
          '-o','HostKeyAlgorithms=ssh-ed25519',f'{c["ansible_user"]}@{c["ansible_host"]}',shlex.join(['sudo','python3','-c',code])]
    result=subprocess.run(args,input=plan.encoded(dict(payload,host=host)),capture_output=True,timeout=240)
    plan.require(result.returncode==0 and len(result.stdout)<4<<20,'Guest phase failed; retain private receipts and inspect scoped state')
    return plan.decode(result.stdout)


def save(path,value):
    raw=plan.encoded(value)
    if path.exists():
        plan.require(plan.read(path,4<<20,private=True)==raw,'Existing phase receipt differs')
    else:plan.write_new(path,raw)


def password(lab,key):
    raw=plan.read(lab/'.lab/credentials/dashboard.env',65536,private=True).decode()
    values=[line.partition('=')[2] for line in raw.splitlines() if line.partition('=')[0]==key]
    plan.require(len(values)==1 and re.fullmatch('[0-9a-f]{64}',values[0]),'Required synthetic credential unavailable')
    return values[0]


def certificates(lab,root,receipt):
    result={}
    for role in ('api','worker'):
        csr=root/'material'/(role+'-broker-client.csr');cert=receipt/(role+'-broker-client.crt')
        if not cert.exists():
            prep.run(['openssl','x509','-req','-sha256','-days','7','-in',str(csr),'-CA',str(lab/'.lab/certs/lab-ca.crt'),
                      '-CAkey',str(lab/'.lab/certs/lab-ca.key'),'-set_serial','0x'+plan.sha(plan.read(csr,16384))[:30],
                      '-copy_extensions','copyall','-out',str(cert)])
            cert.chmod(0o600)
        prep.run(['openssl','verify','-purpose','sslclient','-CAfile',str(lab/'.lab/certs/lab-ca.crt'),str(cert)])
        prep.run(['openssl','x509','-in',str(cert),'-checkend','3600','-noout'])
        plan.require(prep.run(['openssl','req','-in',str(csr),'-pubkey','-noout'])==prep.run(['openssl','x509','-in',str(cert),'-pubkey','-noout']),'Broker CSR key differs')
        result[role]=base64.b64encode(plan.read(cert,16384)).decode()
    return result


def selected_files(value,root,host):
    selected={}
    for name in value['preparedFiles']:
        keep=host=='storage01'
        if host=='pg01':keep=name.startswith('grants/') or name=='material/database-passwords.json'
        if host=='control01':
            keep=(name in ('candidate/bin/jobman-log-broker','configs/broker.json','configs/api.json','units/jobman-dashboard-lab-broker.service') or
                  name.startswith('material/') and name.endswith(('-control-client.csr','-control-signing-public.pem','-broker-signing-public.pem')))
        if keep:selected[name]=base64.b64encode(plan.read(root/name,96<<20)).decode()
    return selected


@contextmanager
def receipt_lock(root):
    receipts=root/'apply-receipts'
    try:receipts.mkdir(mode=0o700)
    except FileExistsError:pass
    info=receipts.lstat()
    plan.require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'Private receipt directory required')
    fd=os.open(receipts/'.phase.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        plan.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'Private phase lock required')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:os.close(fd)


def execute(args):
    value=verified_staging(args.staging,args.expected_plan_sha256)
    plan.require(args.phase=='preflight' or args.apply,'Mutating phase requires explicit --apply')
    with receipt_lock(args.staging):return execute_locked(args,value)


def execute_locked(args,value):
    connections=ssh_connections(args.lab_root)
    receipts=args.staging/'apply-receipts'
    receipts.mkdir(mode=0o700,exist_ok=True)
    plan.require(receipts.stat().st_uid==os.getuid() and receipts.stat().st_mode&0o077==0,'Private receipts directory required')
    base={'plan':value,'planSHA256':args.expected_plan_sha256}
    def call(host,action,**extra):return remote(args.lab_root,connections,host,dict(base,action=action,**extra))
    def phase(name,host,action,**extra):
        target=receipts/(name+'.json')
        if target.exists():return plan.decode(plan.read(target,4<<20,private=True))
        output=call(host,action,**extra);save(target,output);return output
    if args.phase=='preflight':
        helper=plan.read(HERE/'dashboard-split-files.py',1<<20)
        snapshots={host:call(host,'snapshot',objectHelper=base64.b64encode(helper).decode()) for host in HOSTS}
        now=int(time.time())
        plan.require(all(abs(item['epoch']-now)<=10 for item in snapshots.values()),'Lab clocks differ; synchronize before proceeding')
        save(receipts/'preflight.json',{'planSHA256':args.expected_plan_sha256,'snapshots':snapshots})
        return {'preflight':True,'mutatedGuests':False}
    preflight=plan.decode(plan.read(receipts/'preflight.json',4<<20,private=True))
    plan.require(preflight['planSHA256']==args.expected_plan_sha256,'Preflight plan differs')
    snapshots=preflight['snapshots']
    if args.phase=='stage':
        plan.require(int(time.time())-min(s['epoch'] for s in snapshots.values())<=900,'Preflight older than15minutes; prepare a fresh reviewed plan')
        for host in HOSTS:phase('stage-'+host,host,'stage',files=selected_files(value,args.staging,host))
        broker_certificates=certificates(args.lab_root,args.staging,receipts)
        control=phase('source-certificates','control01','source-certificates')['certificates']
        certs={role+'-'+kind:values[role] for kind,values in [('control',control),('broker',broker_certificates)] for role in ('api','worker')}
        save(receipts/'certificates.json',certs)
        phase('database-provision','pg01','database-provision',preflight=snapshots)
        phase('identities','storage01','identities')
        phase('material','storage01','material',certificates=certs,preflight=snapshots)
        return {'staged':True,'runningServicesChanged':False,'deliveryReleased':False}
    plan.read(receipts/'material.json',65536,private=True)
    if args.phase=='cutover':
        phase('stop-hold','storage01','stop-hold',preflight=snapshots)
        state=call('storage01','schema-state')
        call('storage01','assert-stopped-held',schema=state['schema'])
        backup=phase('database-backup','pg01','database-backup')
        helper=plan.read(HERE/'dashboard-split-files.py',1<<20)
        phase('objects-keys','storage01','objects-keys',objectHelper=base64.b64encode(helper).decode(),objectHelperSHA256=plan.sha(helper))
        if state['schema']==17:call('pg01','database-capacity')
        phase('migration','storage01','migrate',backup=backup,ddlPassword=password(args.lab_root,'JOBMAN_LAB_DASHBOARD_DDL_PASSWORD'))
        call('storage01','assert-stopped-held',schema=18)
        phase('grants','pg01','grants')
        phase('conversion','storage01','convert')
        certs=plan.decode(plan.read(receipts/'certificates.json',65536,private=True))
        phase('source-activate','control01','source-activate',preflight=snapshots,brokerCertificates={r:certs[r+'-broker'] for r in ('api','worker')})
        phase('activation','storage01','activate')
        return {'splitStarted':True,'deliveryHeld':True,'accepted':False}
    if args.phase=='recover-receipts':
        state=call('storage01','recover-state',preflight=snapshots)
        for name in ('migration','activation'):
            if name in state:save(receipts/(name+'.json'),state[name])
        return {'receiptsRecovered':True,'schema':state['schema'],'splitStarted':'activation' in state,'deliveryHeld':True}
    if args.phase=='verify':
        plan.read(receipts/'activation.json',65536,private=True)
        checks={host:call(host,'verify',preflight=snapshots) for host in HOSTS}
        save(receipts/'verified.json',checks)
        return {'processChecks':True,'deliveryHeld':True,'applicationAcceptanceStillRequired':True}
    if args.phase=='rollback':
        plan.read(receipts/'migration.json',65536,private=True)
        phase('rollback-stop-hold','storage01','rollback-stop-hold',preflight=snapshots)
        phase('rollback-conversion','storage01','rollback-convert')
        phase('rollback-start','storage01','rollback-start',preflight=snapshots)
        return {'combinedFallbackStarted':True,'deliveryHeld':True,'databaseRestored':False}
    raise ValueError('Unknown phase')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['preflight','stage','cutover','recover-receipts','verify','rollback'])
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--staging',type=Path,required=True)
    parser.add_argument('--expected-plan-sha256',required=True)
    parser.add_argument('--lab-root',type=Path,default=HERE.parent)
    args=parser.parse_args()
    plan.require(args.staging.is_absolute() and args.lab_root.is_absolute(),'Absolute roots required')
    os.umask(0o077)
    print(json.dumps(execute(args),sort_keys=True))


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Split phase failed. Keep private receipts and inspect scoped state; no automatic rollback or notification resume occurred.') from None
