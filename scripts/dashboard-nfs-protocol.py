#!/usr/bin/env python3
"""Bounded NFSv4.1 READ recognition for an isolated Lab TCP relay.

RPC framing: RFC5531 section11. NFSv4.1 READ/SEQUENCE: RFC5661 sections
18.22/18.46. This is not a general NFS decoder and never interprets log bytes.
Unknown, malformed, different-user, or other operations cannot prove a READ.
"""
import hashlib
import struct

MAX_RECORD = 1 << 20
MAX_FRAGMENTS = 64
MAX_BUFFER = 2 << 20
MAX_READ = 256 << 10
READER_UID = 21901


class Invalid(ValueError):
    pass


class Records:
    """Preserve exact TCP record bytes, with bounded pre-decode allocation."""
    def __init__(self):
        self.pending = bytearray()
        self.payload = bytearray()
        self.wire = bytearray()
        self.fragments = 0
        self.next_size = None
        self.last = False

    def feed(self, data):
        if len(data) > 65536 or len(self.pending)+len(data) > MAX_RECORD+4:
            raise Invalid('rpc_input_bound')
        self.pending.extend(data)
        complete = []
        while True:
            if self.next_size is None:
                if len(self.pending) < 4:
                    break
                word = struct.unpack('!I', self.pending[:4])[0]
                self.next_size = word & 0x7fffffff
                self.last = bool(word & 0x80000000)
                self.fragments += 1
                if not self.next_size or self.fragments > MAX_FRAGMENTS or len(self.payload)+self.next_size > MAX_RECORD:
                    raise Invalid('rpc_record_bound')
                self.wire.extend(self.pending[:4]); del self.pending[:4]
            if len(self.pending) < self.next_size:
                break
            body = self.pending[:self.next_size]; del self.pending[:self.next_size]
            self.payload.extend(body); self.wire.extend(body); self.next_size = None
            if self.last:
                complete.append((bytes(self.wire), bytes(self.payload)))
                self.payload.clear(); self.wire.clear(); self.fragments = 0
        return complete


class XDR:
    def __init__(self, raw):
        self.raw, self.position = raw, 0

    def take(self, size):
        if size < 0 or size > len(self.raw)-self.position:
            raise Invalid('xdr_short')
        start = self.position; self.position += size
        return self.raw[start:self.position]

    def uint(self): return struct.unpack('!I', self.take(4))[0]
    def hyper(self): return struct.unpack('!Q', self.take(8))[0]

    def opaque(self, limit):
        count = self.uint()
        if count > limit:
            raise Invalid('xdr_bound')
        value = self.take(count)
        if any(self.take((-count) % 4)):
            raise Invalid('xdr_padding')
        return value

    def done(self): return self.position == len(self.raw)


def read_proof(raw):
    """Recognize exact Linux session READ with AUTH_SYS for the broker UID.

    SEQUENCE, PUTFH, READ, and optional trailing GETATTR are sufficient for the
    intended Linux4.1 client. Everything else is forwarded without a proof.
    """
    if not 0 < len(raw) <= MAX_RECORD:
        return None
    try:
        x = XDR(raw); xid = x.uint()
        if [x.uint() for _ in range(5)] != [0, 2, 100003, 4, 1]:
            return None
        if x.uint() != 1: return None  # AUTH_SYS, not AUTH_NONE/RPCSEC_GSS.
        credential = XDR(x.opaque(400)); credential.uint(); credential.opaque(255)
        uid, gid, groups = credential.uint(), credential.uint(), credential.uint()
        if uid != READER_UID or groups > 16: return None
        credential.take(groups*4)
        if not credential.done() or x.uint() != 0 or x.opaque(400) != b'': return None
        x.opaque(1024)
        if x.uint() != 1: return None
        operations = x.uint()
        if operations not in (3, 4) or x.uint() != 53: return None
        x.take(16); x.uint(); x.uint(); x.uint()
        if x.uint() not in (0, 1) or x.uint() != 22: return None
        handle = x.opaque(128)
        if not handle or x.uint() != 25: return None
        x.take(16); offset, count = x.hyper(), x.uint()
        if offset != 0 or not 0 < count <= MAX_READ: return None
        if operations == 4:
            if x.uint() != 9: return None
            words = x.uint()
            if words > 4: return None
            x.take(words*4)
        if not x.done(): return None
        return {'xid': xid, 'uid': uid, 'gid': gid, 'offset': offset, 'count': count,
                'fileHandleSHA256': hashlib.sha256(handle).hexdigest(), 'minorVersion': 1}
    except (Invalid, struct.error):
        return None


class Hold:
    """A single READ hold; resume is irreversible, including watchdog races."""
    def __init__(self):
        self.state = 'unarmed'
        self.proof = None
        self.pending = bytearray()

    def arm(self, acknowledged):
        if self.state != 'unarmed' or acknowledged is not True:
            raise Invalid('hold_admission')
        self.state = 'armed'

    def consume(self, wire, payload):
        if len(wire) > MAX_RECORD+4*MAX_FRAGMENTS:
            raise Invalid('hold_record_bound')
        if self.state == 'armed':
            proof = read_proof(payload)
            if proof is not None:
                self.proof, self.state = proof, 'held'
        if self.state == 'held':
            if len(self.pending)+len(wire) > MAX_BUFFER:
                raise Invalid('hold_buffer_bound')
            self.pending.extend(wire)
            return b''
        return wire

    def resume(self):
        self.state = 'resumed'
        value = bytes(self.pending); self.pending.clear()
        return value
