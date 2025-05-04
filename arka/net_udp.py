
from __future__ import annotations
from typing import Generator, Callable, Coroutine, Any
from collections.abc import Buffer
import types
import asyncio
import time
import logging
import struct
import socket

from os import urandom


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Message Types
class MSG:
    
    # Peer discovery
    PEERS_SUB = b'\x00'
    PEERS_PUB = b'\x01'
    PEERS_REQ = b'\x02'
    PEERS_RES = b'\x03'

    # Transaction gossip
    TX_SUB = b'\x10'
    TX_PUB = b'\x11'
    TX_REQ = b'\x12'
    TX_RES = b'\x13'

    # Block gossip
    BLOCK_SUB = b'\x20'
    BLOCK_PUB = b'\x21'
    BLOCK_REQ = b'\x22'
    BLOCK_RES = b'\x23'

    # Request to send/recv tips for good peer behavior
    TIP_SUB = b'\x30'
    TIP_PUB = b'\x31'
    TIP_REQ = b'\x32'
    TIP_RES = b'\x33'

    # Manage Proof-of-Work subnet
    WORK_SUB = b'\x40'
    WORK_PUB = b'\x41'
    WORK_REQ = b'\x42'
    WORK_RES = b'\x43'

    # EOF, gracefully close connection after peers exchange NONE
    NONE = b'\xfd'

    # Ignored, but planned conditional responses
    EXT = b'\xfe'

    # Ignored, but planned conditional responses
    ERROR = b'\xff'


# Type aliases
Address = tuple[str, int]
Datagram = Buffer
MessageList = Buffer
Message = Buffer


### Helpers

def seq_lt(a: int, b: int) -> bool:
    return (a - b) & 0xffffffff > 0x8fffffff

def mlen_to_bytes(n: int) -> bytes:
    if n < 0x80:
        return (n << 1).to_bytes(1, 'little')
    elif n < 0x4000:
        return ((n << 2) | 1).to_bytes(2, 'little')
    elif n < 0x2000_0000:
        return ((n << 3) | 0b11).to_bytes(4, 'little')
    elif n < 0x1000_0000_0000_0000:
        return ((n << 4) | 0b111).to_bytes(8, 'little')
    else:
        return b'\x0f' + n.to_bytes(8, 'little')

def parse_mlen(x: Buffer, pos: int = 0) -> tuple[int, int] | None:
    if pos >= len(x):
        return
    n = x[pos]
    if n & 1:
        try:
            if n & 0b10:
                if n & 0b100:
                    if n & 0b1000:
                        return struct.unpack_from('<Q', x, pos + 1), 9
                    return struct.unpack_from('<Q', x, pos) >> 4, 8
                return struct.unpack_from('<I', x, pos) >> 3, 4
            return struct.unpack_from('<H', x, pos) >> 2, 2
        except struct.error as e:
            return
    return n >> 1, 1

def parse_message_list(x: MessageList) -> list[Message] | None:
    msgs: list[Message] = []
    pos = 0
    while pos < len(x):
        match parse_mlen(x, pos):
            case mlen, nread:
                pos += nread
                if pos + mlen > len(x):
                    return
                msgs.append(bytes(x[pos:pos+mlen]))
                pos += mlen
            case _:
                return
    return msgs

def interleave_msg_size(x: list[Message]) -> Generator[bytes, None, None]:
    for msg in x:
        yield mlen_to_bytes(len(msg))
        yield msg

def pack_message_list(x: list[Message]) -> MessageList:
    return b''.join(interleave_msg_size(x))

def ipv6_to_bytes(ipv6_str: str) -> bytes:
    try:
        # Convert IPv6 address to binary form
        binary = socket.inet_pton(socket.AF_INET6, ipv6_str)
        return binary
    except socket.error as e:
        raise ValueError(f"Invalid IPv6 address: {e}")

def bytes_to_ipv6(binary: bytes) -> str:
    try:
        # Ensure input is 16 bytes
        if len(binary) != 16:
            raise ValueError("Binary input must be 16 bytes")
        # Convert binary back to IPv6 string
        ipv6_str = socket.inet_ntop(socket.AF_INET6, binary)
        return ipv6_str
    except socket.error as e:
        raise ValueError(f"Invalid binary data: {e}")

def addr_to_bytes(addr: Address) -> bytes:
    host, port = addr
    return ipv6_to_bytes(host) + struct.pack('<H', port)

def bytes_to_addr(binary: bytes) -> Address:
    return bytes_to_ipv6(binary[:16]), struct.unpack('<H', binary[16:])[0]


### Message serializers

def msg_peers_update(added: set[Address], removed: set[Address]) -> Message:
    msg_type = MSG.PEERS_UPDATE
    num_added = len(added)
    if num_added < 0x80:
        num_added = bytes([num_added << 1])
    elif num_added < 0x8000:
        num_added = struct.pack('<H', (num_added << 1) | 1)
    else:
        raise ValueError('Too many peers added.')
    num_removed = len(removed)
    if num_removed < 0x80:
        num_removed = bytes([num_removed << 1])
    elif num_removed < 0x8000:
        num_removed = struct.pack('<H', (num_removed << 1) | 1)
    else:
        raise ValueError('Too many peers removed.')
    return b''.join(
        [msg_type, num_added, num_removed]
        + [addr_to_bytes(x) for x in added]
        + [addr_to_bytes(x) for x in removed]
    )

def msg_meet_request(neighbor: Address) -> Message:
    return MSG.MEET_REQUEST + addr_to_bytes(neighbor)

def msg_meet_intro(neighbor: Address) -> Message:
    return MSG.MEET_INTRO + addr_to_bytes(neighbor)


### Message deserializers

class PeersUpdateMessage(object):

    def __init__(self, msg: Message):
        if msg[1] & 1:
            num_added = struct.unpack_from('<H', msg, 1)[0] >> 1
            offset = 3
        else:
            num_added = msg[1] >> 1
            offset = 2
        if msg[offset] & 1:
            num_removed = struct.unpack_from('<H', msg, offset)[0] >> 1
            offset += 2
        if len(msg) != offset + 32 * (num_added + num_removed):
            raise ValueError('Invalid msg passed to `PeersUpdateMessage`.')
        start, end = offset, offset + 18 * num_added
        self.added: set[Address] = {
            bytes_to_addr(msg[i:i+18]) for i in range(start, end, 18)
        }
        start, end = end, end + 18 * num_removed
        self.removed: set[Address] = {
            bytes_to_addr(msg[i:i+18]) for i in range(start, end, 18)
        }


class MeetRequestMessage(object):

    def __init__(self, msg: Message):
        if len(msg) != 19:
            raise ValueError('Invalid message size for `MeetRequestMessage`.')
        self.neighbor: Address = bytes_to_addr(msg[1:])


class MeetIntroMessage(Message):

    def __init__(self, msg: Message):
        if len(msg) != 19:
            raise ValueError('Invalid message size for `MeetIntroMessage`.')
        self.neighbor: Address = bytes_to_addr(msg[1:])


### MeshProtocol

class MeshProtocol(asyncio.DatagramProtocol):
    '''Protocol to handle UDP datagrams for the Mesh class.'''
    def __init__(self, mesh: Mesh, blacklist: dict[Address, float] = {}):
        self.mesh = mesh
        self.blacklist = blacklist

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
    
    def datagram_received(self, data: Datagram, addr: Address):
        # Check blacklist
        timeout = self.blacklist.get(addr, 0)
        if timeout:
            if time.time() < timeout:
                # Drop Datagrams from blacklisted peers
                return
            del self.blacklist[addr]
        # Route Datagram to mesh.peers[addr]
        peer = self.mesh.peers.get(addr)
        if peer is None:
            peer = self.mesh.accept(addr, data)
            if peer is None:
                return
        peer.datagram_received(data)

    def error_received(self, exc: OSError):
        logging.err(f'Error receieved: {exc}')


### Socket

class Socket(object):
    _HDR = struct.Struct('<IIB')    # seq, ack, flags
    FLAG_SYN = 0x1
    FLAG_ACK = 0x2
    FLAG_SACK = 0x4
    FLAG_FIN = 0x8

    # Congestion control defaults
    INITIAL_CWND = 16.0
    INITIAL_SSTHRESH = 1000.0
    MAX_RETRIES = 5

    # Timers
    RESEND_TIMEOUT = 0.2
    BACKOFF_MULTIPLIER = 1.5
    DELAYED_ACK_MS = 0.04
    KEEPALIVE_SECS = 15.0
    TIMEOUT_SECS = 60.0

    MAX_PAYLOAD = 1024
    MAX_MSG_SIZE = 2**23

    def __init__(self,
        addr: Address,
        transport: asyncio.DatagramTransport,
        on_close: Callable[[Address, bool], None] | None = None
    ):
        self.addr = addr
        self.transport = transport
        self.on_close = on_close

        # sequence numbers
        self.seq = int.from_bytes(urandom(4))
        self.ack = 0
        self.peer_ack: int | None = None

        # send/recv buffers
        self._sent: dict[int, tuple[int, float, bytes]] = {}
        self._recd: dict[int, bytes] = {}
        self._reader = asyncio.StreamReader()

        # congestion control
        self.cwnd = self.INITIAL_CWND
        self.ssthresh = self.INITIAL_SSTHRESH
        self._dup_ack_count = 0
        self._in_fast_recovery = False
        self._wait_ack: asyncio.Future[None] | None = None

        # state
        self.closed: bool = False
        self.last_send_time = time.monotonic()
        self.last_recv_time = time.monotonic()

        # RTT + RTO
        self._srtt: float | None = None
        self._rttvar: float | None = None
        self._rto: float = 0.5

        # background tasks
        self._resend_task: asyncio.Task | None = None
        self._ack_task: asyncio.Task | None = None
    
    async def send(self, data: bytes):
        if len(data) > self.MAX_MSG_SIZE:
            raise ValueError('Message is too large to send.')
        mlen = mlen_to_bytes(len(data))
        if len(mlen) + len(data) <= self.MAX_PAYLOAD:
            await self._send_datagram(mlen + data)
            return
        async with self._send_lock:
            offset = self.MAX_PAYLOAD - len(mlen)
            await self._send_datagram(mlen + data[:offset])
            for i in range(offset, len(data), self.MAX_PAYLOAD):
                await self._send_datagram(data[i:i+self.MAX_PAYLOAD])

    async def _send_datagram(self, data: bytes):
        while len(self._sent) > self.cwnd:
            self._wait_ack = asyncio.Future()
            await self._wait_ack
        self._wait_ack = None
        flags = self.FLAG_ACK
        hdr = self._HDR.pack(self.seq, self.ack, flags)
        pkt = b''.join([hdr, data])
        self.transport.sendto(pkt, self.addr)
        now = time.monotonic()
        self.last_send_time = now
        self._sent[self.seq] = now, pkt, 0
        self.seq = (self.seq + 1) & 0xffffffff

    async def recv(self) -> bytes | None:
        if self.closed:
            return
        try:
            mlen = await self._reader.readexactly(1)
            if mlen[0] & 1:
                if mlen[0] & 2:
                    if mlen[0] & 4:
                        await self.close()
                        return
                    mlen += await self._reader.readexactly(3)
                    mlen = int.from_bytes(mlen, 'little') >> 3
                else:
                    mlen += await self._reader.readexactly(1)
                    mlen = int.from_bytes(mlen, 'little') >> 2
            else:
                mlen = mlen[0] >> 1
            if mlen <= self.MAX_MSG_SIZE:
                return await self._reader.readexactly(mlen)
        except asyncio.IncompleteReadError as e:
            return

    def datagram_received(self, data: Datagram):
        if len(data) < self._HDR.size:
            # Close Socket on malformed packet
            return self.close()
        now = time.monotonic()
        self.last_recv_time = now
        # Unpack header
        seq, ack, flags = self._HDR.unpack_from(data)
        offset = self._HDR.size
        # Process payload
        if (
            offset < len(data)
            and len(self._reader._buffer) <= self.MAX_READER_SIZE
            and (seq - self.ack) & 0xffffffff <= self.MAX_RECV_WINDOW
        ):
            self._recd[seq] = data[offset:]
            # Move data in self._recd into self._reader
            while True:
                data = self._recd.pop(self.ack, None)
                if data is None:
                    break
                self._reader.feed_data(data)
                self.ack = (self.ack + 1) & 0xffffffff
            # Ensure ACK is sent
            if self._ack_task is None:
                self._ack_task = asyncio.create_task(self._ensure_ack())
        # Process ACK
        if seq_lt(ack, self.seq):
            if ack == self._last_ack_recd:
                self._dup_ack_count += 1
                if self._dup_ack_count == 3:
                    # Fast retransmit
                    match self._sent.get(ack):
                        case retries, ts, data:
                            self.transport.sendto(data, self.addr)
                            # Enter fast recovery
                            self.ssthresh = max(self.cwnd // 2, 1)
                            self.cwnd = self.ssthresh + 3
            else:
                self._last_ack_recd = ack
                self._dup_ack_count = 0
                acked = False
                while seq_lt(self.peer_ack, ack):
                    # Clear delivered packets sent
                    match self._sent.pop(self.peer_ack, None):
                        case attempts, ts, data:
                            acked = True
                            # Update smoothed round trip time and resend timeout
                            rtt = now - ts
                            if self._rtt is None:
                                self._srtt = rtt
                                self._rttvar = rtt / 2
                            else:
                                delta = rtt - self._srtt
                                self._srtt += 0.125 * delta
                                self._rttvar += 0.25 * (abs(delta) - self._rttvar)
                                self._rto = self._srtt + max(0.01, 4 * self._rttvar)
                            # Congestion control
                            if self.cwnd < self.ssthresh:
                                # Slow start
                                self.cwnd += 1
                            else:
                                # Congestion avoidance
                                self.cwnd += 1 / self.cwnd
                    self.peer_ack = (self.peer_ack + 1) & 0xffffffff
                if acked and self._wait_ack is not None:
                    # Notify _send_datagram that _sent has been reduced
                    self._wait_ack.set_result(None)
        if not self._sent and self._resend_task is not None:
            # Cancel resend if sent is empty
            self._resend_task.cancel()

    async def accept(self, data: Datagram) -> Socket | None:
        pass

    async def connect(self) -> Socket | None:
        pass

    async def close(self):
        pass


class Socket(object):

    def __init__(self,
        id: int,
        addr: Address,
        loop: asyncio.AbstractEventLoop | None = None,
        handle_recv_q: Callable[[Socket], Coroutine[Any, Any, None]] | None = None,
        handle_close: Callable[[Socket, bool], None] | None = None
    ):
        self.addr = addr
        self.id = id
        self.loop = loop or asyncio.get_running_loop()
        self.handle_recv_q = handle_recv_q
        self.handle_close = handle_close
        self.connected: bool = False

    def connect(self) -> Socket:
        if not self.connected:
            self.connected = True
            self.sent: dict[int, tuple[float, int, Datagram]] = {}
            self.window: int = WINDOW
            self.seq: int = int.from_bytes(urandom(4), 'little')
            self.ack: int | None = None
            self.sack: int | None = None
            self.peer_window: int | None = None
            self.peer_seq: int | None = None
            self.peer_ack: int | None = None
            self.peer_sack: int | None = None
            self.frag_q: asyncio.Queue[Datagram] = asyncio.Queue()
            self.recv_q: asyncio.Queue[Message] = asyncio.Queue()
            self.send_q: asyncio.Queue[Message] = asyncio.Queue()
            self.ack_q: asyncio.Queue[tuple[int, int | None]] = asyncio.Queue()
            self.loop.create_task(self.handle_frag_q())
            if self.handle_recv_q is not None:
                self.loop.create_task(self.handle_recv_q(self))
            self.loop.create_task(self.handle_send_q())
        return self

    def close(self, blacklist: bool = True):
        if self.connected:
            self.connected = False
            self.frag_q.put_nowait(None)
            self.recv_q.put_nowait(None)
            self.send_q.put_nowait(None)
            if self.handle_close is not None:
                self.handle_close(self, blacklist)

    async def handle_frag_q(self):
        '''Process async Datagrams received from frag_q
            into stream of ordered Messages to recv_q
        '''
        recd: dict[int, tuple[int | None, Datagram]] = {}
        acks: dict[int, int] = {}
        min_recd: int = -1
        max_recd: int = -1
        last_seen: float = time.time()
        while self.connected:
            # Consume Datagrams from frag_q
            timeout: float = time.time() + RECV_TIMEOUT
            while time.time() < timeout and self.connected:
                if not self.frag_q.empty:
                    data: Datagram = self.frag_q.get_nowait()
                else:
                    try:
                        wait = max(0, timeout - time.time())
                        data: Datagram = await asyncio.wait_for(
                            fut=self.frag_q.get(), timeout=wait
                        )
                    except asyncio.TimeoutError as e:
                        if time.time() > last_seen + KEEPALIVE_TIMEOUT * MAX_RETRIES:
                            # Terminate pipeline when peer does not send keepalive
                            self.close()
                            return
                        break
                if data is None:
                    # Terminate task on EOF
                    return
                if len(data) < 8:
                    # Terminate pipeline on malformed Datagram
                    self.close()
                    return
                seq: int = struct.unpack_from('<Q', data, 0)[0]
                if seq & 1:
                    if len(data) < 12:
                        # Terminate pipeline on malformed Datagram
                        self.close()
                        return
                    n_frags = struct.unpack_from('<I', data, 4)[0]
                    offset = 12
                else:
                    n_frags = None
                    offset = 8
                frag_id = seq >> 1
                data = data[offset:]
                if n_frags == 1:
                    for msg in self.parse_msg_concat(data):
                        await self.recv_q.put(msg)
                else:
                    self.recd[frag_id] = n_frags, data
                self.last_seen = time.time()
                if frag_id < min_acked:
                    min_acked = frag_id
                elif frag_id > max_acked:
                    max_acked = frag_id
                self.last_recd = max(self.last_recd, frag_id)
                acks[frag_id] = frag_id

            # Defragment acks
            start = unacked
            while start <= self.last_recd:
                end = acks.pop(start, None)
                

### Mesh

class Mesh(object):

    def __init__(self,
            bootstrap: list[Address] = [],
            loop: asyncio.AbstractEventLoop | None = None
    ):
        self.bootstrap = bootstrap
        self.loop = loop or asyncio.get_running_loop()
        self.peer_counter: int = 0
        self.peers: dict[Address | int, Socket] = {}
        self.blacklist: dict[Address, float] = {}
        self.transport: asyncio.DatagramTransport = None
        self.running: bool = False

    def connect(self, addr: Address) -> Socket:
        # Create connection
        peer = Socket(
            id=self.peer_counter,
            addr=addr,
            handle_recv_q=self.handle_recv,
            handle_close=self.handle_close
        ).connect()
        self.peer_counter += 1
        # Add peer to self.peers
        self.peers[peer.id] = peer
        self.peers[addr] = peer
        return peer

    def disconnect(self, peer: Socket, blacklist: bool = True):
        peer = self.peers.pop(peer.id, None)
        if peer is not None:
            self.peers.pop(peer.addr, None)
            peer.close(blacklist=blacklist)

    def handle_close(self, peer: Socket, blacklist: bool = True):
        if blacklist:
            self.blacklist[peer.addr] = time.time() + BLACKLIST_TIMEOUT
        self.peers.pop(peer.id, None)
        self.peers.pop(peer.addr, None)

    async def handle_recv(self, peer: Socket):
        '''Listen for Messages on peer['recv'] queue and
            respond with Messages on peer['send'] queue.
        '''
        # Send MSG_INIT
        local_challenge: Challenge = urandom(32)
        msg = msg_init(self.peer_id, local_challenge)
        await peer.send(msg)
        # Await MSG_INIT
        msg = await peer['recv'].get()

    async def handle_send(self, peer: Socket):
        addr: Address = peer['addr']
        send_q: asyncio.Queue[Message] = peer['send']
        sent: dict[int, tuple[float, int, Datagram]] = peer['sent']
        while self.running:
            # Process peer['send'] continuously
            send_batch: list[Message] = []
            send_timeout = time.time() + SEND_TIMEOUT
            # Consume send_q
            try:
                while time.time() < send_timeout:
                    wait = max(0, send_timeout - time.time())
                    msg: Message = await asyncio.wait_for(send_q.get(), wait)
                    if msg is None:
                        # Terminate pipeline on send_q EOF
                        return
                    send_batch.append(msg)
            except asyncio.TimeoutError as e:
                pass
            # Concatenate Messages into single buffer
            if not send_batch:
                continue
            if len(send_batch) == 1:
                buffer = prefix_len_to_bytes(send_batch[0].msg)
            else:
                buffer = b''.join(
                prefix_len_to_bytes(m.msg) for m in send_batch
            )
            # Fragment buffer into <= 1024 byte fragments,
            # prefix with fragment metadata
            # and send Datagram to peer
            view = memoryview(buffer)
            n_frags = len(buffer) >> 10 + (1 if len(buffer) & 1023 else 0)
            for i in range(n_frags):
                frag = bytes(view[i<<10:(i+1)<<10])
                id = peer['seq_num']
                peer['seq_num'] = id + 1
                timeout = time.time() + ACK_TIMEOUT
                retries = 0
                if not i:
                    data: Datagram = struct.pack('<QI', (id << 1) + 1, n_frags) + frag
                else:
                    data: Datagram = struct.pack('<Q', id << 1) + frag
                self.transport.sendto(data, addr)
                peer['keepalive'] = time.time() + KEEPALIVE_TIMEOUT
                sent[id] = timeout, retries, data

    async def handle_acks(self, peer: Socket):
        addr: Address = peer['addr']
        ack_q: asyncio.Queue[tuple[int, int]] = peer['ack']
        sent: dict[int, tuple[float, int, Datagram]] = peer['sent']
        acks: dict[int, int] = {}
        ack_timeout = time.time() + ACK_TIMEOUT
        while self.running:
            # Process ACKs periodically
            if time.time() > ack_timeout:
                seq_num = peer['seq_num']
                unacked = peer['unacked']
                # Add (ack_start) -> (ack_end) to acks dict
                while not ack_q.empty():
                    ack = await ack_q.get()
                    if ack is None:
                        # Terminate pipeline if ack_q EOF
                        return
                    ack_start, ack_end = ack
                    if unacked <= ack_start <= ack_end < seq_num:
                        acks[ack_start] = ack_end
                # Iterate through acks dict consuming acks and sent
                # while updating unacked
                while unacked < seq_num:
                    acked = acks.pop(unacked, None)
                    if acked is None:
                        break
                    for i in range(unacked, acked + 1):
                        sent.pop(i, None)
                    unacked = acked + 1
                peer['unacked'] = unacked
                # Defragment acks
                start = unacked
                while start < seq_num:
                    end = acks.pop(start, None)
                    _end = end
                    while _end is not None:
                        _end = acks.pop(end, None)
                        if _end is not None:
                            end = _end
                    if end is not None:
                        acks[start] = end
                        start = end + 1
                    else:
                        start += 1
                # Send unACKed fragments
                frag_id = unacked
                while frag_id < seq_num:
                    acked = acks.get(frag_id)
                    if acked is not None:
                        frag_id = acked + 1
                        continue
                    timeout, retries, data = sent[frag_id]
                    if time.time() < timeout:
                        frag_id += 1
                        continue
                    if retries < MAX_RETRIES:
                        self.transport.sendto(data, addr)
                        peer['keepalive'] = time.time() + KEEPALIVE_TIMEOUT
                        retries += 1
                        timeout = time.time() + ACK_TIMEOUT
                        sent[frag_id] = timeout, retries, data
                        frag_id += 1
                    else:
                        return await self.disconnect(peer)
                # Reschedule ack processing
                ack_timeout = time.time() + ACK_TIMEOUT
