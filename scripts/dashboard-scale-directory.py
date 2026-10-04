#!/usr/bin/env python3
"""Explicit fixed LDAP-helper upgrade phases using immutable private snapshots."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import shlex
import sys

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('identities',HERE/'dashboard-scale-identities.py')
i=importlib.util.module_from_spec(spec);spec.loader.exec_module(i);c=i.c
FILES=('dashboard-scale-directory.py','dashboard-scale-directory-guest.py','dashboard-scale-identities.py','dashboard-scale-identities-common.py')


def implementation():return {name:c.sha(i.implementation_file(HERE/name)) for name in FILES}


def remote(lab,p):
    names=('dashboard-scale-identities-common.py','dashboard-scale-directory-guest.py')
    sources={name:i.implementation_file(HERE/name).decode() for name in names}
    script='''import hashlib,json,os,sys,types
os.umask(0o077)
try:
 raw=sys.stdin.buffer.read((2<<20)+1)
 if len(raw)>2<<20:raise ValueError()
 p=json.loads(raw);sources=p.pop('_sources');hashes=p.pop('_hashes')
 if set(sources)!={'dashboard-scale-identities-common.py','dashboard-scale-directory-guest.py'}:raise ValueError()
 for name,value in sources.items():
  if hashlib.sha256(value.encode()).hexdigest()!=hashes[name]:raise ValueError()
 common=types.ModuleType('common');exec(compile(sources['dashboard-scale-identities-common.py'],'common','exec'),common.__dict__)
 namespace={'__name__':'reviewed_guest','c':common}
 exec(compile(sources['dashboard-scale-directory-guest.py'],'guest','exec'),namespace)
 print(json.dumps({'ok':True,'result':namespace['execute'](p)},sort_keys=True))
except Exception as error:
 print(json.dumps({'ok':False,'code':getattr(error,'code','directory_guest_failed')},sort_keys=True))
'''
    payload=dict(p,_sources=sources,_hashes={name:c.sha(raw.encode()) for name,raw in sources.items()})
    result=c.decode(c.run(i.ssh_args(lab)+[shlex.join(['sudo','python3','-c',script])],c.encoded(payload),timeout=180))
    if result.get('ok') is not True:
        code=result.get('code','directory_guest_failed');c.need(isinstance(code,str) and c.CODE.fullmatch(code),'invalid_guest_code');raise c.Failure(code)
    return result['result']


def execute(args):
    digest=c.sha(c.encoded(implementation()))
    if args.phase=='digest':return {'implementationSHA256':digest}
    c.need(args.implementation_sha256==digest,'implementation_digest')
    c.need(args.lab_root.is_absolute() and args.lab_root.resolve()==args.lab_root,'lab_root_alias')
    c.need(args.staging is not None and args.staging.is_absolute(),'staging_required')
    if args.phase=='snapshot' and not args.staging.exists():c.mkdir(args.staging)
    with i.locked(args.staging):
        if args.phase=='snapshot':
            c.need(not (args.staging/'snapshot.json').exists(),'existing_snapshot')
            snapshot=remote(args.lab_root,{'phase':'snapshot','profile':args.profile})
            record={'implementationSHA256':digest,'snapshot':snapshot,'snapshotSHA256':c.sha(c.encoded(snapshot))}
            c.put(args.staging/'snapshot.json',c.encoded(record))
            return {'phase':'snapshot','profile':args.profile,'snapshotSHA256':record['snapshotSHA256'],'guestChanges':False}
        record=c.decode(c.read(args.staging/'snapshot.json'))
        c.need(record['implementationSHA256']==digest and re.fullmatch('[0-9a-f]{64}',args.snapshot_sha256 or '') and record['snapshotSHA256']==args.snapshot_sha256 and c.sha(c.encoded(record['snapshot']))==args.snapshot_sha256 and record['snapshot']['profile']==args.profile,'reviewed_snapshot')
        if args.phase!='verify':c.need(args.apply,'explicit_apply_required')
        result=remote(args.lab_root,{'phase':args.phase,'profile':args.profile,'snapshot':record['snapshot'],'snapshotSHA256':args.snapshot_sha256,'apply':args.apply})
        c.retain(args.staging/(args.phase+'.json'),c.encoded(result))
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',required=True,choices=('digest','snapshot','stage','swap','restart','verify'))
    parser.add_argument('--profile',choices=('primary','secondary'),default='primary')
    parser.add_argument('--lab-root',type=Path,default=Path('/Users/rcw/home/code/jobman-lab'))
    parser.add_argument('--staging',type=Path);parser.add_argument('--implementation-sha256');parser.add_argument('--snapshot-sha256');parser.add_argument('--apply',action='store_true')
    args=parser.parse_args();os.umask(0o077)
    print(c.encoded(execute(args)).decode(),end='')


if __name__=='__main__':
    try:main()
    except Exception as error:
        code=getattr(error,'code','directory_phase_failed')
        print('Scale directory phase failed: '+code+'; preserve all receipts.',file=sys.stderr);raise SystemExit(1) from None
