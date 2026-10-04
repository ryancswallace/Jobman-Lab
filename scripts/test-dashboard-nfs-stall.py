#!/usr/bin/env python3
"""Offline admission, ordering, watchdog, and relay failure regressions."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import types
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
p=load('dashboard-nfs-plan');g=load('dashboard-nfs-guest');r=load('dashboard-nfs-relay');h=load('dashboard-nfs-stall')
ID='11111111-1111-4111-8111-111111111111'; HASH='a'*64


def plan():
    sources=[]
    for i,(dep,instance) in enumerate(p.b.SOURCE_IDS.items()):
        sources.append({'deploymentId':dep,'controlInstanceId':instance,'recoveryEpoch':'1','configurationRevision':8,
          'namespaceIds':[ID],'status':'active','generation':'7','lastPosition':'6','openGaps':0,'unfinishedRecoveries':0})
    db={'schemaSHA256':HASH,'rolesSHA256':HASH,'databaseOID':'100','sources':sources,
        'hold':{'held':False,'generation':'5','suppressRecordedThrough':None}}
    snapshot={'pg01':{'database':db}}
    for host in ('control01','storage01'):
        snapshot[host]={'host':host,'bootId':ID,'preservedSHA256':HASH,'revision':'b'*40}
    candidate={'revision':'c'*40,'binary':{'sha256':HASH,'bytes':100},'buildReceiptSHA256':HASH,'outputFixAncestor':p.FIX}
    probe={'revision':'c'*40,'binary':{'sha256':HASH,'bytes':100},'sourceSHA256':HASH}
    chunks=[{'objectKey':'jobman/alice/chunk'+str(i),'byteLength':30,'checksum':'sha256:'+HASH,'acceptedEvidenceSHA256':HASH} for i in (1,2)]
    return p.make(snapshot,ID,candidate,probe,chunks,{name:HASH for name in p.FILES},1)


class Tests(unittest.TestCase):
    def test_plan_fixed_scope(self):
        value=plan();p.validate(value)
        for key,item in (('server','10.77.0.20'),('sourcePorts',[2048]),('watchdogSeconds',100),('mountOptions','soft'),('readerConcurrency',2)):
            bad=copy.deepcopy(value);bad[key]=item
            with self.assertRaises(ValueError):p.validate(bad)
        self.assertIn('nosharecache',value['mountOptions']);self.assertEqual(value['readerUid'],21901)

    def test_chunk_cold_and_path_identity(self):
        value=plan()
        for key in ('jobman/../x','/data/jobman/x','jobman/a\n','jobman/a:b'):
            bad=copy.deepcopy(value);bad['chunks'][1]['objectKey']=key
            with self.assertRaises(ValueError):p.validate(bad)
        bad=copy.deepcopy(value);bad['chunks'][1]=bad['chunks'][0]
        with self.assertRaises(ValueError):p.validate(bad)
        bad=copy.deepcopy(value);bad['candidate']['outputFixAncestor']='d'*40
        with self.assertRaises(ValueError):p.validate(bad)

    def test_reserved_source_port_never_reuses(self):
        first,second=mock.Mock(),mock.Mock();first.bind.side_effect=OSError()
        with mock.patch.object(r.socket,'socket',side_effect=[first,second]):
            actual,port=r.reserved_connection()
        self.assertEqual(port,901);self.assertIs(actual,second);first.close.assert_called_once()
        second.bind.assert_called_once_with(('10.77.0.21',901));second.connect.assert_called_once_with(('10.77.0.10',2049))
        first.setsockopt.assert_not_called();second.setsockopt.assert_not_called()

    def test_isolation_before_any_mount_command(self):
        libc=mock.Mock();libc.prctl.return_value=libc.unshare.return_value=libc.sethostname.return_value=0
        calls=[]
        with mock.patch.object(r.ctypes,'CDLL',return_value=libc),mock.patch.object(r.f,'run',side_effect=lambda args,*a,**k:calls.append(args)):
            r.isolate(ID)
        libc.unshare.assert_called_once_with(0x40000000|0x00020000|0x04000000)
        self.assertEqual(calls,[['mount','--make-rprivate','/'],['ip','link','set','lo','up']])
        libc.unshare.return_value=-1
        with mock.patch.object(r.ctypes,'CDLL',return_value=libc),mock.patch.object(r.f,'run') as command:
            with self.assertRaises(ValueError):r.isolate(ID)
            command.assert_not_called()

    def test_watchdog_ack_deadline_and_late_resume(self):
        relay=object.__new__(r.Relay);relay.root=Path('/fixture');relay.plan=plan();relay.ready=True;relay.probe_started=True;relay.failure=None
        relay.hold=r.protocol.Hold();relay.status=lambda:{}
        ack={'operationId':ID,'bootId':ID,'deadlineMonotonic':145}
        with mock.patch.object(r.f,'read',return_value=p.encoded(ack)),mock.patch.object(r.time,'monotonic',return_value=100):relay.arm()
        self.assertEqual(relay.hold.state,'armed')
        relay.hold=r.protocol.Hold();relay.hold.resume()
        with mock.patch.object(r.f,'read',return_value=p.encoded(ack)),mock.patch.object(r.time,'monotonic',return_value=100):
            with self.assertRaises(ValueError):relay.arm()
        relay.hold=r.protocol.Hold()
        with mock.patch.object(r.f,'read',return_value=p.encoded(ack)),mock.patch.object(r.time,'monotonic',return_value=135):
            with self.assertRaises(ValueError):relay.arm()
        self.assertEqual(relay.hold.state,'unarmed')

    def test_bad_framing_resumes_exact_unforwarded_bytes(self):
        relay=object.__new__(r.Relay);relay.client=mock.Mock();relay.client.recv.return_value=b'\xff\xff\xff\xff'
        relay.to_client=bytearray();relay.to_server=bytearray();relay.parser=r.protocol.Records();relay.hold=r.protocol.Hold()
        relay.hold.arm(True);relay.passthrough=False;relay.failure=None;relay.resumed_at=None
        relay.status=lambda:{}
        r.Relay.process_network(relay,'client',r.selectors.EVENT_READ)
        self.assertEqual(relay.to_server,b'\xff\xff\xff\xff');self.assertEqual(relay.hold.state,'resumed')
        self.assertEqual(relay.failure,'unrecognized_rpc_framing');self.assertTrue(relay.passthrough)

    def test_unreaped_children_prevent_shutdown(self):
        relay=object.__new__(r.Relay);relay.hold=r.protocol.Hold();relay.hold.resume()
        relay.probe_started=True;relay.probe_result={'exitCode':1};relay.unmount=None;relay.root=Path('/fixture')
        with mock.patch.object(r,'child_ids',return_value={123}),mock.patch.object(r.subprocess,'Popen') as child:
            with self.assertRaises(ValueError):relay.command('shutdown',0)
            child.assert_not_called()
        with self.assertRaises(ValueError):relay.command('shutdown',21901)

    def test_watchdog_does_not_cancel_timer_or_restart(self):
        value=plan();root=Path(value['root']);ack={'operationId':ID}
        def read(path,*a,**k):return p.encoded(value if Path(path).name=='plan.json' else ack)
        with mock.patch.object(g.f,'read',side_effect=read),mock.patch.object(g,'staged'),mock.patch.object(g.relay,'control',return_value={'state':'resumed'}) as control,mock.patch.object(g,'receipt') as record,mock.patch.object(g.f,'run') as run:
            g.watchdog(root)
        control.assert_called_once_with(root,'resume',3);run.assert_not_called()
        self.assertEqual(record.call_args.args[1],'watchdog-complete')

    def test_service_never_forces_unreaped_children(self):
        unit=g.unit_text(plan()).decode()
        self.assertIn('Restart=no\n',unit);self.assertIn('KillMode=process\n',unit);self.assertIn('SendSIGKILL=no\n',unit)
        self.assertNotIn('ExecStop=',unit);self.assertNotIn('WantedBy',unit)

    def test_arm_persists_intent_before_timer_and_ack(self):
        value=plan();events=[];identity={'pid':123,'start':'100','namespaces':{}}
        def run(args,*a,**k):
            events.append(('run',args));return b'active\n' if args[0]=='systemctl' else b''
        def record(root,name,data):events.append(('receipt',name))
        with mock.patch.object(g,'staged'),mock.patch.object(g,'keeper',return_value=identity),mock.patch.object(g.f,'read',return_value=p.encoded(identity)),mock.patch.object(g.Path,'exists',return_value=False),mock.patch.object(g,'receipt',side_effect=record),mock.patch.object(g.f,'run',side_effect=run),mock.patch.object(g.time,'monotonic',side_effect=[100,102]):
            ack=g.phase({'host':'control01','phase':'arm','plan':value})
        self.assertEqual(events[0],('receipt','arm.pending'))
        self.assertIn('--on-active=40s',events[1][1]);self.assertEqual(events[-1],('receipt','watchdog-ack'))
        self.assertEqual(ack['deadlineMonotonic'],145)

    def test_late_ack_never_admits_probe(self):
        value=plan();identity={'pid':123,'start':'100','namespaces':{}}
        with mock.patch.object(g,'staged'),mock.patch.object(g,'keeper',return_value=identity),mock.patch.object(g.f,'read',return_value=p.encoded(identity)),mock.patch.object(g.Path,'exists',return_value=False),mock.patch.object(g,'receipt') as receipt,mock.patch.object(g.f,'run',return_value=b'active\n'),mock.patch.object(g.time,'monotonic',side_effect=[100,111]):
            with self.assertRaises(ValueError):g.phase({'host':'control01','phase':'arm','plan':value})
        self.assertEqual([x.args[1] for x in receipt.call_args_list],['arm.pending'])

    def test_uncertain_probe_never_launches_twice(self):
        with mock.patch.object(g,'staged'),mock.patch.object(g.Path,'exists',return_value=True),mock.patch.object(g.relay,'control') as control:
            with self.assertRaises(ValueError):g.phase({'host':'control01','phase':'probe','plan':plan()})
        control.assert_not_called()

    def test_snapshot_dispatch_does_not_take_mutation_lock(self):
        with mock.patch.object(g.os,'getuid',return_value=0),mock.patch.object(g.sys,'platform','linux'),mock.patch.object(g.socket,'gethostname',return_value='control01'),mock.patch.object(g,'snapshot',return_value={}) as snapshot,mock.patch.object(g,'lock') as lock:
            self.assertEqual(g.execute({'host':'control01','phase':'snapshot','revision':'b'*40}),{})
        snapshot.assert_called_once();lock.assert_not_called()

    def test_rpc_bootstrap_modules_are_importable_without_disk_calls(self):
        # Exercise exactly the injected-module seam; the remote path must not
        # accidentally import absent /reviewed sibling files.
        import types
        def module(name,injected=None):
            m=types.ModuleType(name);m.__file__='/reviewed/'+name+'.py';m.__dict__.update(injected or {})
            exec(compile((HERE/(name+'.py')).read_bytes(),name,'exec'),m.__dict__);return m
        b=module('dashboard-dependency-fault-plan');f=module('dashboard-dependency-fault-guest',{'p':b})
        np=module('dashboard-nfs-plan',{'b':b});protocol=module('dashboard-nfs-protocol')
        relay=module('dashboard-nfs-relay',{'p':np,'protocol':protocol,'f':f})
        guest=module('dashboard-nfs-guest',{'p':np,'f':f,'relay':relay})
        self.assertEqual(guest.p.TIMEOUT,45)


if __name__=='__main__':unittest.main()
