#!/usr/bin/env python3
"""Apply separately reviewed isolated restore phases; never restore primary DB."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
import subprocess

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

plan = load('restore_apply_plan', 'dashboard-restore-plan.py')
ssh = load('restore_apply_ssh', 'apply-dashboard-split.py')


@contextmanager
def lock(path):
    fd = os.open(path, os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        plan.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'Private operation lock required')
        fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def local_record(path, value):
    raw = plan.encoded(value)
    if path.exists():
        plan.require(plan.private_read(path, 4<<20) == raw, 'Immutable local receipt differs')
    else:
        plan.write_new(path, raw)


def remote(lab, host, payload, phase, timeout=60):
    plan.require(host in ('pg01','storage01'), 'Unsupported restore host')
    conn = ssh.ssh_connections(lab)[host]
    code = (HERE/'dashboard-restore-guest.py').read_bytes()
    plan.require(plan.sha(code) == payload['implementationSHA256'], 'Guest implementation changed')
    args = ['ssh','-i',conn['ansible_ssh_private_key_file'],'-p',str(conn['ansible_port']),
            '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile='+str(lab/'.lab/dashboard/known_hosts'),'-o','HostKeyAlgorithms=ssh-ed25519',
            conn['ansible_user']+'@'+conn['ansible_host'],shlex.join(['sudo','python3','-c',code.decode()])]
    data = plan.encoded(dict(payload,host=host,phase=phase))
    plan.require(len(data) <= 4<<20, 'Guest request bound exceeded')
    result = subprocess.run(args,input=data,capture_output=True,timeout=timeout,check=False)
    plan.require(result.returncode == 0 and len(result.stdout) <= 4<<20, 'Phase failed or response lost; inspect exact private receipts before retry')
    return plan.decode(result.stdout)


def operation(args):
    staging = args.prepared_directory
    raw = plan.private_read(staging/'plan.json',1<<20)
    plan.require(plan.sha(raw) == args.plan_sha256, 'Exact reviewed plan required')
    document = plan.decode(raw)
    plan.require(document['scenario'] == 'isolated-dashboard-postgresql-restore' and document['synthetic'] is True and
                 document['applySupported'] is False, 'Prepared isolated restore plan required')
    metadata, files = plan.shared.candidate_files(args.candidate,args.candidate_sha256)
    plan.require(metadata == document['candidate'] and args.candidate_sha256 == document['archiveSHA256'], 'Candidate archive differs')
    prepared_files = {}
    for name, expected in document['preparedFiles'].items():
        path = staging/name
        plan.require(path.resolve().is_relative_to(staging) and path.is_file(), 'Unsafe prepared path')
        content = plan.private_read(path,1<<20)
        plan.require(plan.sha(content) == expected, 'Prepared content changed')
        prepared_files[name] = base64.b64encode(content).decode()
    snapshot = plan.decode(plan.private_read(staging/'inputs/snapshot.json',1<<20))
    source = (HERE/'dashboard-restore-guest.py').read_bytes()
    helper = (HERE/'dashboard-split-files.py').read_bytes()
    plan.require(plan.sha(source) == args.guest_sha256 and plan.sha(helper) == args.object_helper_sha256, 'Exact reviewed implementation required')
    output = args.operation_directory
    plan.require(output.is_absolute() and output.resolve() == output, 'Real operation directory required')
    if not output.exists():
        plan.require(args.command == 'initialize', 'Initialize private operator intent before any guest action')
        info = output.parent.stat()
        plan.require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Private operator parent required')
        plan.directory(output)
        secret = {'operationId':secrets.token_hex(32),'passwords':{role:secrets.token_hex(32) for role in ('ddl','api','worker','operator')}}
        plan.write_new(output/'private.json',plan.encoded(secret))
    secret = plan.decode(plan.private_read(output/'private.json'))
    intent = {'operationId':secret['operationId'],'planSHA256':args.plan_sha256,
              'guestSHA256':args.guest_sha256,'objectHelperSHA256':args.object_helper_sha256,
              'candidateSHA256':args.candidate_sha256,'candidateRevision':metadata['revision']}
    local_record(output/'intent.json',intent)
    return output, {'apply':True,'operationId':secret['operationId'],'passwords':secret['passwords'],
        'plan':document,'planSHA256':args.plan_sha256,'snapshot':snapshot,
        'candidate':{'revision':metadata['revision'],'binarySHA256':plan.sha(files['bin/jobman-dashboard'])},
        'implementationSHA256':args.guest_sha256,'guestCode':base64.b64encode(source).decode(),
        'objectHelperSHA256':args.object_helper_sha256,'objectHelper':base64.b64encode(helper).decode(),
        'primaryPins':{'configs':{'api':snapshot['apiSHA256'],'worker':snapshot['workerSHA256']},'processes':snapshot['processes']},
        'preparedFiles':prepared_files}


def call(args, output, payload, host, phase, timeout=60):
    value = remote(args.lab_root,host,payload,phase,timeout)
    local_record(output/(host+'-'+phase+'.json'),value)
    return value


def coordinated_backup(args, output, payload):
    # Arm acknowledgement must precede stopping. The independent guest timer
    # restores only the exact fixed primary units if the host disappears.
    completed, restart = None, None
    try:
        call(args,output,payload,'storage01','arm-backup')
        stopped = call(args,output,payload,'storage01','stop-primary',50)
        active = dict(payload,stoppedReceipt=stopped)
        # Two independent hosts operate while primary API and all workers are
        # stopped. Both finish before a single storage-host coherence receipt.
        with ThreadPoolExecutor(max_workers=2) as executor:
            database = executor.submit(call,args,output,active,'pg01','database-backup',125)
            objects = executor.submit(call,args,output,active,'storage01','objects-backup',125)
            receipts = {'database':database.result(),'objects':objects.result()}
        completed = call(args,output,dict(payload,backupReceipts=receipts),'storage01','complete-backup')
    finally:
        # Also executes after a lost stop/dump/complete reply. If even this SSH
        # fails, the already armed fixed-unit timer remains independent.
        restart = remote(args.lab_root,'storage01',payload,'restart-primary',45)
        local_record(output/'storage01-restart-primary.json',restart)
    plan.require(completed and restart and not restart['watchdogFired'] and restart['elapsedSinceArmSeconds'] <= 180,
                 'Backup was not accepted within the coordinated restart window')
    local_record(output/'coherent-backup.json',completed)
    return {'backupComplete':True,'primaryRestarted':True,'watchdogFired':False,
            'operationId':payload['operationId'],'reportFiles':completed['receipts']['objects']['files']}


def execute(args):
    output,payload = operation(args)
    with lock(output/'.lock'):
        if args.command == 'initialize':
            return {'initialized':True,'guestMutations':False,'operationId':payload['operationId']}
        if args.command == 'inspect':
            # Inspection does not claim a successful phase or remove pending
            # receipts. Completed guest receipts are retained separately.
            results = {host:remote(args.lab_root,host,payload,'inspect-operation') for host in ('storage01','pg01')}
            destination = output/('inspection-'+secrets.token_hex(8)+'.json')
            plan.write_new(destination,plan.encoded(results))
            return {'inspected':True,'operationId':payload['operationId'],'receipt':str(destination)}
        if args.command == 'verify-held':
            return remote(args.lab_root,'storage01',payload,'verify-clone',60)
        plan.require(args.apply, 'Explicit --apply required for reviewed mutation phases')
        if args.command == 'provision':
            call(args,output,payload,'pg01','provision-database')
            call(args,output,payload,'storage01','provision-storage')
            return {'provisioned':True,'cloneStarted':False,'operationId':payload['operationId']}
        if args.command == 'backup':
            return coordinated_backup(args,output,payload)
        if args.command == 'restore-held':
            coherent = plan.decode(plan.private_read(output/'coherent-backup.json',4<<20))
            plan.require(coherent['complete'] is True and coherent['operationId'] == payload['operationId'], 'Completed coordinated backup required')
            plan.timestamp(args.external_cutoff)
            active = dict(payload,coherentBackup=coherent,externalCutoff=args.external_cutoff)
            # No clone unit starts until isolated database restore/grants and a
            # monotonic externally supplied restore floor are durably complete.
            call(args,output,active,'pg01','restore-database',210)
            call(args,output,active,'storage01','install-snapshot',90)
            call(args,output,active,'storage01','hold-clone',30)
            call(args,output,active,'storage01','start-clone',60)
            return {'restored':True,'held':True,'deliveryComponent':False,'operationId':payload['operationId']}
        raise ValueError('Unsupported restore command')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['initialize','inspect','provision','backup','restore-held','verify-held'])
    parser.add_argument('--lab-root',type=Path,required=True)
    parser.add_argument('--prepared-directory',type=Path,required=True)
    parser.add_argument('--operation-directory',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--candidate-sha256',required=True)
    parser.add_argument('--guest-sha256',required=True)
    parser.add_argument('--object-helper-sha256',required=True)
    parser.add_argument('--external-cutoff')
    parser.add_argument('--apply',action='store_true')
    print(json.dumps(execute(parser.parse_args()),sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Isolated restore phase failed. Preserve private host and guest receipts. Primary restart was attempted for every armed backup; the independent watchdog remains the fallback. No primary restore or hold release is performed.') from None
