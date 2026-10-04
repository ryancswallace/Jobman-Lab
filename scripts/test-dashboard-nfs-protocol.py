#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('nfs',Path(__file__).with_name('dashboard-nfs-protocol.py'))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
def uint(*values): return b''.join(struct.pack('!I',v) for v in values)
def opaque(value): return uint(len(value))+value+b'\0'*((-len(value))%4)
def request(uid=21901, count=4096, tail=False):
    auth = uint(0)+opaque(b'isolated-client')+uint(uid,21901,0)
    return uint(123,0,2,100003,4,1,1)+opaque(auth)+uint(0)+opaque(b'')+opaque(b'')+uint(1,4 if tail else 3,53)+b's'*16+uint(1,0,0,0,22)+opaque(b'file-handle')+uint(25)+b'\0'*16+struct.pack('!Q',0)+uint(count)+(uint(9,2,1,2) if tail else b'')
def record(raw): return uint(0x80000000|len(raw))+raw

class NFSTests(unittest.TestCase):
    def test_exact_auth_sys_session_read_only(self):
        for tail in (False,True):
            proof=p.read_proof(request(tail=tail));self.assertEqual(proof['uid'],21901);self.assertEqual(proof['count'],4096);self.assertEqual(proof['minorVersion'],1)
        for value in (request(uid=0),request(count=0),request(count=p.MAX_READ+1),request()+b'\0',request()[:-1],b'',b'log text containing READ'):
            self.assertIsNone(p.read_proof(value))

    def test_no_arbitrary_opcode_search(self):
        raw=request();self.assertIsNone(p.read_proof(raw.replace(uint(53),uint(99),1)))
        self.assertIsNone(p.read_proof(raw.replace(uint(22),uint(15),1)))
        self.assertIsNone(p.read_proof(raw.replace(uint(25),uint(27),1)))

    def test_fragmentation_preserves_wire_and_handles_short_tcp_reads(self):
        raw=request();wire=uint(11)+raw[:11]+uint(0x80000000|len(raw[11:]))+raw[11:]
        r=p.Records();got=[]
        for byte in wire:got+=r.feed(bytes([byte]))
        self.assertEqual(got,[(wire,raw)])
        self.assertEqual(r.feed(record(raw)+record(raw)),[(record(raw),raw),(record(raw),raw)])

    def test_oversize_declared_record_rejected_before_body(self):
        for word in (0x80000000|p.MAX_RECORD+1,0,0x80000000):
            with self.assertRaises(p.Invalid):p.Records().feed(uint(word))
        r=p.Records()
        with self.assertRaises(p.Invalid):r.feed((uint(1)+b'x')*(p.MAX_FRAGMENTS+1))

    def test_watchdog_wins_before_arm(self):
        h=p.Hold();self.assertEqual(h.resume(),b'')
        with self.assertRaises(p.Invalid):h.arm(True)
        raw=request();self.assertEqual(h.consume(record(raw),raw),record(raw));self.assertIsNone(h.proof)

    def test_only_acknowledged_real_read_stalls_and_resume_is_irreversible(self):
        h=p.Hold()
        with self.assertRaises(p.Invalid):h.arm(False)
        h.arm(True);metadata=request(uid=0);raw=request()
        self.assertEqual(h.consume(record(metadata),metadata),record(metadata))
        self.assertEqual(h.consume(record(raw),raw),b'');self.assertEqual(h.state,'held')
        self.assertEqual(h.consume(record(metadata),metadata),b'')
        self.assertEqual(h.resume(),record(raw)+record(metadata));self.assertEqual(h.resume(),b'')
        self.assertEqual(h.consume(record(raw),raw),record(raw))
        with self.assertRaises(p.Invalid):h.arm(True)

if __name__=='__main__':unittest.main()
