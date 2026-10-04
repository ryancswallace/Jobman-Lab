#!/usr/bin/env python3
"""Dedicated namespace keeper and bounded one-connection NFS relay.

Never changes a shared mount/network namespace. Recovery releases forwarding,
not a process kill. A failed/unreaped probe keeps this keeper alive for recovery.
"""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import selectors
import socket
import stat
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
if 'p' not in globals(): p = load('dashboard-nfs-plan')
if 'protocol' not in globals(): protocol = load('dashboard-nfs-protocol')
if 'f' not in globals(): f = load('dashboard-dependency-fault-guest')
MAX_QUEUE = 4<<20


def child_ids():
    result = set()
    for task in Path('/proc/self/task').iterdir():
        try: result.update(int(x) for x in (task/'children').read_text().split())
        except FileNotFoundError: pass
    p.need(len(result) <= 16, 'child_bound'); return result


def namespace_ids(pid='self'):
    return {name:os.readlink('/proc/'+str(pid)+'/ns/'+name) for name in ('mnt','net','uts')}


def reserved_connection():
    # These fixed privileged ports are tried only when unused; no reuse flags,
    # export weakening, firewall changes, or shared client transport are used.
    for port in p.PORTS:
        conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM); conn.settimeout(5)
        try: conn.bind(('10.77.0.21',port))
        except OSError: conn.close(); continue
        try: conn.connect((p.SERVER,2049)); return conn,port
        except BaseException: conn.close(); raise
    raise p.b.Failure('reserved_source_ports_busy')


def isolate(operation):
    libc = ctypes.CDLL(None,use_errno=True)
    # Become subreaper BEFORE starting the test. Orphaned helpers remain visible
    # and prevent teardown until waitpid actually reports their exit.
    p.need(libc.prctl(36,1,0,0,0) == 0, 'subreaper')
    p.need(libc.unshare(0x40000000|0x00020000|0x04000000) == 0, 'namespace_create')
    name = ('dashboard-nfs-'+operation).encode()
    p.need(libc.sethostname(name,len(name)) == 0, 'private_hostname')
    f.run(['mount','--make-rprivate','/'],'mount_propagation')
    f.run(['ip','link','set','lo','up'],'private_loopback')


def control(root,command,timeout=2):
    conn = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); conn.settimeout(timeout)
    try:
        conn.connect(str(root/'control.sock')); conn.sendall(p.encoded({'command':command})); conn.shutdown(socket.SHUT_WR)
        output = bytearray()
        while True:
            data = conn.recv(16384)
            if not data: break
            output.extend(data); p.need(len(output) <= 32768,'control_reply_bound')
        value = p.decode(bytes(output)); p.need(value.get('ok') is True,'control_rejected'); return value['result']
    finally: conn.close()


class Relay:
    def __init__(self,root,plan,upstream,port,original):
        self.root,self.plan,self.upstream,self.port,self.original = root,plan,upstream,port,original
        self.sel = selectors.DefaultSelector(); self.parser = protocol.Records(); self.hold = protocol.Hold()
        self.to_server,self.to_client = bytearray(),bytearray()
        self.client = None; self.accepted = False; self.failure = None; self.shutdown = False
        self.mount = None; self.unmount = None; self.probe = None; self.probe_result = None
        self.probe_output = bytearray(); self.started = time.monotonic(); self.ready = False
        self.reads = 0; self.held_at = None; self.resumed_at = None; self.last_read = None
        self.watchdog_deadline = None; self.probe_started = False; self.passthrough = False
        upstream.setblocking(False)
        self.listener = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1',20490)); self.listener.listen(1); self.listener.setblocking(False)
        self.local = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.local.bind(str(root/'control.sock')); os.chmod(root/'control.sock',0o660); os.chown(root/'control.sock',0,p.UID)
        self.local.listen(4); self.local.setblocking(False)
        self.sel.register(self.local,selectors.EVENT_READ,'control')
        self.sel.register(self.listener,selectors.EVENT_READ,'accept')

    def status(self):
        return {'operationId':self.plan['operationId'],'ready':self.ready,'state':self.hold.state,
                'proof':self.hold.proof,'readCount':self.reads,'lastRead':self.last_read,
                'sourcePort':self.port,'namespaces':namespace_ids(),'originalNamespaces':self.original,
                'failure':self.failure,'probeStarted':self.probe_started,'probeResult':self.probe_result,
                'children':sorted(child_ids()),'heldAt':self.held_at,'resumedAt':self.resumed_at,
                'watchdogDeadline':self.watchdog_deadline}

    def resume(self):
        data = self.hold.resume()
        p.need(len(self.to_server)+len(data) <= MAX_QUEUE,'resume_queue_bound')
        self.to_server.extend(data)
        if self.resumed_at is None: self.resumed_at = time.monotonic()
        return self.status()

    def arm(self):
        ack = p.decode(f.read(self.root/'watchdog-ack.json'))
        deadline = ack.get('deadlineMonotonic')
        p.need(ack.get('operationId') == self.plan['operationId'] and ack.get('bootId') == self.plan['snapshot']['control01']['bootId'] and
               type(deadline) in (int,float) and 15 < deadline-time.monotonic() <= p.TIMEOUT,'watchdog_admission')
        p.need(self.ready and self.probe_started and self.failure is None,'hold_not_ready')
        self.watchdog_deadline = deadline
        self.hold.arm(True)
        return self.status()

    def command(self,command,uid):
        if command == 'state': return self.status()
        if command == 'resume': return self.resume()
        if command == 'hold': return self.arm()
        p.need(uid == 0,'root_control_required')
        if command == 'probe':
            p.need(self.ready and not self.probe_started and self.failure is None,'probe_admission')
            # The durable intent must predate admission, even when the SSH reply
            # is lost. The authenticated local caller cannot start another run.
            p.need(p.decode(f.read(self.root/'probe.pending.json'))['operationId'] == self.plan['operationId'],'probe_intent')
            self.probe_started = True
            def drop():
                os.setgroups([]); os.setgid(p.UID); os.setuid(p.UID)
            self.probe = subprocess.Popen([str(self.root/'probe'),'-test.run=^TestLabHardNFSRead$','-test.v','-test.timeout=80s'],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                env={'LANG':'C','JOBMAN_DASHBOARD_LAB_NFS_PROBE':str(self.root/'probe.json')},preexec_fn=drop)
            os.set_blocking(self.probe.stdout.fileno(),False)
            self.sel.register(self.probe.stdout,selectors.EVENT_READ,'probe_output'); return self.status()
        if command == 'shutdown':
            p.need(self.hold.state == 'resumed' and (not self.probe_started or self.probe_result is not None) and not child_ids(),'unreaped_children')
            p.need(self.unmount is None,'unmount_already_started')
            if not self.ready and self.mount is None:
                rows = Path('/proc/self/mountinfo').read_text().splitlines()
                p.need(not any(len(x.split())>4 and x.split()[4] == str(self.root/'mount') for x in rows),'unexpected_private_mount')
                f.put(self.root/'unmounted.json',p.encoded({'operationId':self.plan['operationId'],'unmounted':True}))
                self.shutdown = True; return self.status()
            self.unmount = subprocess.Popen(['umount',str(self.root/'mount')],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            return self.status()
        raise p.b.Failure('control_command')

    def local_request(self):
        conn,_ = self.local.accept(); conn.settimeout(.3)
        try:
            _,uid,_ = struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            p.need(uid in (0,p.UID),'control_peer')
            raw = bytearray()
            while len(raw) <= 256:
                data = conn.recv(257-len(raw))
                if not data: break
                raw.extend(data)
            p.need(len(raw) <= 256,'control_request_bound')
            value = p.decode(bytes(raw)); p.need(set(value) == {'command'},'control_request')
            result = {'ok':True,'result':self.command(value['command'],uid)}
        except Exception as error:
            result = {'ok':False,'code':getattr(error,'code','control_failed')}
        try: conn.sendall(p.encoded(result))
        finally: conn.close()

    def watch(self,sock,read,write,name):
        events = (selectors.EVENT_READ if read else 0)|(selectors.EVENT_WRITE if write else 0)
        try: self.sel.unregister(sock)
        except KeyError: pass
        if events: self.sel.register(sock,events,name)

    def process_network(self,name,events):
        if name == 'server':
            if events & selectors.EVENT_WRITE:
                sent = self.upstream.send(self.to_server[:65536]); del self.to_server[:sent]
            if events & selectors.EVENT_READ:
                raw = self.upstream.recv(65536); p.need(raw,'upstream_disconnected'); self.to_client.extend(raw)
        elif name == 'client':
            if events & selectors.EVENT_WRITE:
                sent = self.client.send(self.to_client[:65536]); del self.to_client[:sent]
            if events & selectors.EVENT_READ:
                raw = self.client.recv(65536); p.need(raw,'client_disconnected')
                if self.passthrough:
                    self.to_server.extend(raw); return
                pending = bytes(self.parser.wire)+bytes(self.parser.pending)
                try: records = self.parser.feed(raw)
                except protocol.Invalid:
                    self.failure = 'unrecognized_rpc_framing'; self.resume(); self.passthrough = True
                    self.to_server.extend(pending+raw); self.parser=protocol.Records(); return
                for wire,body in records:
                    proof = protocol.read_proof(body)
                    if proof: self.reads += 1; self.last_read = proof
                    previous = self.hold.state
                    self.to_server.extend(self.hold.consume(wire,body))
                    if previous != 'held' and self.hold.state == 'held': self.held_at = time.monotonic()
        p.need(max(len(self.to_client),len(self.to_server)) <= MAX_QUEUE,'relay_queue_bound')

    def run(self):
        self.mount = subprocess.Popen(['mount','-t','nfs4','-o',p.MOUNT_OPTIONS,'127.0.0.1:'+p.EXPORT,str(self.root/'mount')],
                                      stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        while not self.shutdown:
            now = time.monotonic()
            if self.watchdog_deadline is not None and now >= self.watchdog_deadline: self.resume()
            if self.mount is not None and self.mount.poll() is not None:
                code = self.mount.returncode; self.mount = None
                if code == 0:
                    self.ready = True; f.put(self.root/'ready.json',p.encoded(self.status()))
                else: self.failure = 'mount_failed'; self.resume()
            if self.unmount is not None and self.unmount.poll() is not None:
                code = self.unmount.returncode; self.unmount = None
                if code == 0:
                    f.put(self.root/'unmounted.json',p.encoded({'operationId':self.plan['operationId'],'unmounted':True})); self.shutdown = True; continue
                self.failure = 'private_unmount_failed'
            if self.probe is not None and self.probe.poll() is not None:
                # Drain the pipe separately; completion cannot infer that every
                # orphaned helper was reaped. The shutdown gate checks children.
                code = self.probe.returncode
                try: self.sel.get_key(self.probe.stdout)
                except (KeyError,ValueError):
                    self.probe_result = {'exitCode':code,'outputSHA256':p.sha(bytes(self.probe_output))}
                    f.put(self.root/'probe-output.log',bytes(self.probe_output) or b'empty\n')
                    f.put(self.root/'probe-result.json',p.encoded(self.probe_result)); self.probe = None
            # Reap only adopted descendants. Never steal Popen's direct child.
            direct = {x.pid for x in (self.mount,self.unmount,self.probe) if x is not None}
            for pid in child_ids()-direct:
                try: os.waitpid(pid,os.WNOHANG)
                except ChildProcessError: pass
            if self.client is not None and self.failure != 'relay_transport_failed':
                self.watch(self.upstream,len(self.to_client)<MAX_QUEUE-65536,bool(self.to_server),'server')
                # Reserve capacity for a maximum framed record. Backpressure
                # pauses reads; it never drops or reconnects the held transport.
                capacity = len(self.hold.pending)+len(self.parser.payload)+len(self.parser.pending)
                self.watch(self.client,len(self.to_server)<MAX_QUEUE-(2<<20) and capacity < protocol.MAX_BUFFER-(1<<20)-1024,bool(self.to_client),'client')
            for key,events in self.sel.select(.02):
                if key.data == 'control': self.local_request()
                elif key.data == 'accept':
                    conn,_ = self.listener.accept()
                    if self.accepted: conn.close(); self.failure = 'additional_nfs_transport'; continue
                    self.client = conn; self.client.setblocking(False); self.accepted = True
                elif key.data == 'probe_output':
                    raw = os.read(key.fileobj.fileno(),65536)
                    if not raw: self.sel.unregister(key.fileobj); key.fileobj.close()
                    elif len(self.probe_output)+len(raw) <= 65536: self.probe_output.extend(raw)
                    else: self.failure = 'probe_output_bound'; self.resume()
                else:
                    try: self.process_network(key.data,events)
                    except (BlockingIOError,InterruptedError): pass
                    except Exception:
                        self.failure = 'relay_transport_failed'; self.resume()
                        # Keep the mount namespace, watchdog endpoint and any
                        # unreaped helpers alive for explicit root recovery.
                        try: self.sel.unregister(key.fileobj)
                        except KeyError: pass
        self.local.close(); self.listener.close(); self.upstream.close()
        if self.client is not None: self.client.close()


def serve(root):
    p.need(os.getuid() == 0 and root.parent == Path(p.BASE),'serve_boundary')
    plan = p.decode(f.read(root/'plan.json')); p.validate(plan)
    p.need(str(root) == plan['root'],'serve_root')
    for name,digest in plan['implementationSHA256'].items():
        p.need(p.sha(f.read(root/name,0,0o444,256<<10)) == digest,'implementation_changed')
    original = namespace_ids(); connection,port = reserved_connection()
    isolate(plan['operationId']); current = namespace_ids()
    p.need(all(current[k] != original[k] for k in current),'namespace_not_isolated')
    Relay(root,plan,connection,port,original).run()


if __name__ == '__main__':
    try:
        p.need(len(sys.argv) == 3 and sys.argv[1] == 'serve','relay_arguments')
        serve(Path(sys.argv[2]))
    except Exception:
        # Errors are finite codes only; this script never logs NFS data/paths.
        print('isolated_nfs_keeper_failed',file=sys.stderr); sys.exit(1)
