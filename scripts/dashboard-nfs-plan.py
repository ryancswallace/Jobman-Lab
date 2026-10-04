#!/usr/bin/env python3
"""Pure plan for one isolated hard-NFS read; no shared mount or export changes."""
import importlib.util
import posixpath
from pathlib import Path

HERE = Path(__file__).resolve().parent
if 'b' not in globals():
    spec = importlib.util.spec_from_file_location('nfs_base', HERE/'dashboard-dependency-fault-plan.py')
    b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
need, sha, encoded, decode = b.need, b.sha, b.encoded, b.decode
BASE = '/var/lib/jobman-dashboard-nfs-stall'
UID = 21901
SERVER = '10.77.0.10'
EXPORT = '/srv/lab/data'
PORTS = list(range(900, 916))
TIMEOUT = 45
FIX = '2e8f1b15c58889c52023d49d396fd600b31eecd2'
FILES = ('dashboard-nfs-plan.py', 'dashboard-nfs-protocol.py', 'dashboard-nfs-relay.py',
         'dashboard-nfs-guest.py', 'dashboard-nfs-stall.py',
         'dashboard-dependency-fault-plan.py', 'dashboard-dependency-fault-guest.py',
         'dashboard-dependency-faults.py')
MOUNT_OPTIONS = 'ro,hard,vers=4.1,proto=tcp,port=20490,nconnect=1,nosharecache,actimeo=0,lookupcache=none,rsize=262144,wsize=262144,timeo=600,retrans=2,retry=0,sec=sys'


def artifact(value):
    need(set(value) == {'sha256','bytes'} and b.HEX.fullmatch(value['sha256']) and
         type(value['bytes']) is int and 1 <= value['bytes'] <= 128<<20, 'artifact_bound')


def chunk(value):
    need(set(value) == {'objectKey','byteLength','checksum','acceptedEvidenceSHA256'}, 'chunk_shape')
    key = value['objectKey']
    need(isinstance(key,str) and 1 <= len(key) <= 1024 and key.startswith('jobman/') and
         posixpath.normpath(key) == key and not any(c in key for c in '\x00\r\n\\:') and
         all(part not in ('.','..','') for part in key.split('/')), 'chunk_key')
    need(type(value['byteLength']) is int and 1 <= value['byteLength'] <= 256<<10 and
         isinstance(value['checksum'],str) and value['checksum'].startswith('sha256:') and
         b.HEX.fullmatch(value['checksum'][7:]) and b.HEX.fullmatch(value['acceptedEvidenceSHA256']), 'chunk_identity')


def make(snapshot, operation, candidate, probe, chunks, implementation, created):
    need(b.UUID.fullmatch(operation) and type(created) is int and created > 0, 'operation_identity')
    need(set(implementation) == set(FILES) and all(b.HEX.fullmatch(x) for x in implementation.values()), 'implementation_identity')
    # The unchanged dependency snapshot proves all active runtimes, source
    # instances/epochs/scopes, SQL role/schema/hold state and shared NFS config.
    need(set(snapshot) == {'control01','storage01','pg01'}, 'snapshot_hosts')
    b.stable_database(snapshot['pg01']['database'])
    for host in ('control01','storage01'):
        value = snapshot[host]
        need(value['host'] == host and b.UUID.fullmatch(value['bootId']) and
             b.HEX.fullmatch(value['preservedSHA256']), 'snapshot_identity')
    need(set(candidate) == {'revision','binary','buildReceiptSHA256','outputFixAncestor'} and
         b.REVISION.fullmatch(candidate['revision']) and candidate['outputFixAncestor'] == FIX and
         b.HEX.fullmatch(candidate['buildReceiptSHA256']), 'candidate_identity')
    artifact(candidate['binary'])
    need(set(probe) == {'binary','sourceSHA256','revision'} and probe['revision'] == candidate['revision'] and
         b.HEX.fullmatch(probe['sourceSHA256']), 'probe_identity'); artifact(probe['binary'])
    need(isinstance(chunks,list) and len(chunks) == 2, 'chunk_count')
    for value in chunks: chunk(value)
    need(chunks[0]['objectKey'] != chunks[1]['objectKey'], 'cold_chunk_required')
    return {'format':1,'scenario':'isolated-hard-nfs','synthetic':True,'operationId':operation,'createdAt':created,
            'snapshot':snapshot,'candidate':candidate,'probe':probe,'chunks':chunks,
            'implementationSHA256':implementation,'root':BASE+'/'+operation,
            'server':SERVER,'export':EXPORT,'sourcePorts':PORTS,'mountOptions':MOUNT_OPTIONS,
            'watchdogSeconds':TIMEOUT,'readerUid':UID,'readerTimeoutSeconds':2,'readerConcurrency':1}


def validate(value):
    need(value == make(value['snapshot'],value['operationId'],value['candidate'],value['probe'],
                      value['chunks'],value['implementationSHA256'],value['createdAt']), 'plan_changed')


def unit(plan): return 'jobman-dashboard-nfs-'+plan['operationId']
