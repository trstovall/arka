
from __future__ import annotations
from typing import Generator, Callable, Coroutine, Any
from collections.abc import Buffer
from os import urandom

import types
import asyncio
import time
import logging
import struct
import socket
import heapq


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


### Socket

class Socket(object):

    # Header
    HEADER = struct.Struct('<IIB')    # seq, ack, flags
    FLAG_SYN = 0x1
    FLAG_ACK = 0x2
    FLAG_FIN = 0x4

    # Congestion control defaults
    INITIAL_CWND = 16.0
    INITIAL_SSTHRESH = 1000.0
    MAX_ATTEMPTS = 5
    MAX_PAYLOAD = 1024
    MAX_MSG_SIZE = 2**23        # 8 MB
    MAX_READER_SIZE = 2**24     # 16 MB
    MAX_RECV_WINDOW = 1024

    # Timers
    BACKOFF_MULTIPLIER = 1.5
    DELAYED_ACK_TO = 0.04
    KEEPALIVE_TO = 15.0
    TIMEOUT = 60.0

    def __init__(self,
        addr: Address,
        transport: asyncio.DatagramTransport,
        on_connect: Callable[[Address], None] | None = None,
        on_close: Callable[[Address, bool], None] | None = None
    ):
        self.addr = addr
        self.transport = transport
        self.on_connect = on_connect
        self.on_close = on_close

        # state
        self.closed: bool = False
        self._last_sent: float = time.monotonic()
        self._last_recd: float = time.monotonic()

        # sequence numbers
        self._seq: int = int.from_bytes(urandom(4))
        self._ack: int | None = None
        self._peer_ack: int | None = None

        # send/recv buffers
        self._sent: dict[int, tuple[int, float, bytes]] = {}
        self._sent_heap: list[float, int] = []
        self._recd: dict[int, bytes] = {}
        self._reader: asyncio.StreamReader = asyncio.StreamReader()

        # congestion control
        self._cwnd: float = self.INITIAL_CWND
        self._ssthresh: float = self.INITIAL_SSTHRESH
        self._last_ack_recd: int | None = None
        self._dup_ack_count: int = 0
        self._wait_ack: asyncio.Future[None] | None = None

        # RTT + RTO
        self._srtt: float | None = None
        self._rttvar: float | None = None
        self._rto: float = 1.0

        # background tasks
        self._ensure_syn_task: asyncio.Task | None = None
        self._ensure_seq_task: asyncio.Task | None = None
        self._ensure_ack_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task = asyncio.create_task(self._keepalive())

    def datagram_received(self, data: Datagram):
        if self.closed:
            return
        if len(data) < self.HEADER.size:
            # Close Socket on malformed packet
            return self.close()
        now = time.monotonic()
        self.last_recv_time = now
        # Unpack header
        seq, ack, flags = self.HEADER.unpack_from(data)
        offset = self.HEADER.size
        # Ensure 3-way handshake
        if self._ack is None and flags & self.FLAG_SYN:
            # SYN received
            self._ack = seq
            if self._ensure_ack_task is None:
                # Ensure received SYN is ACKed
                self._ensure_ack_task = asyncio.create_task(self._ensure_ack())
            if self._peer_ack is None and self._ensure_syn_task is None:
                # Ensure sent SYN is delivered
                self._ensure_syn_task = asyncio.create_task(self._ensure_syn())
            if not flags & self.FLAG_ACK:
                return
        if (
            self._peer_ack is None
            and flags & self.FLAG_ACK
            and ack == self._seq
        ):
            # ACK received for SYN
            self._peer_ack = ack
        if self._ack is None or self._peer_ack is None:
            # Handshake is incomplete
            return
        # Process ACK
        if flags & self.FLAG_ACK and not seq_lt(self._seq, ack):
            if ack == self._last_ack_recd:
                self._dup_ack_count += 1
                if self._dup_ack_count == 3:
                    # Fast retransmit
                    match self._sent.get(ack):
                        case retries, ts, data:
                            self.transport.sendto(data, self.addr)
                            # Enter fast recovery
                            self._ssthresh = max(self._cwnd // 2, 1)
                            self._cwnd = self._ssthresh + 3
            else:
                self._last_ack_recd = ack
                self._dup_ack_count = 0
                acked = False
                while seq_lt(self._peer_ack, ack):
                    # Clear delivered packets sent
                    match self._sent.pop(self._peer_ack, None):
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
                            if self._cwnd < self._ssthresh:
                                # Slow start
                                self._cwnd += 1
                            else:
                                # Congestion avoidance
                                self._cwnd += 1 / self._cwnd
                    self._peer_ack = (self._peer_ack + 1) & 0xffffffff
                if acked and self._wait_ack is not None:
                    # Notify _send_datagram that _sent has been reduced
                    self._wait_ack.set_result(None)
        if not self._sent and self._ensure_seq_task is not None:
            # Cancel resend if sent is empty
            self._ensure_seq_task.cancel()
        # Process payload
        if (
            offset < len(data)
            and len(self._reader._buffer) <= self.MAX_READER_SIZE
            and (seq - self._ack) & 0xffffffff <= self.MAX_RECV_WINDOW
        ):
            self._recd[seq] = data[offset:]
            # Move data in self._recd into self._reader
            while True:
                data = self._recd.pop(self._ack, None)
                if data is None:
                    break
                self._reader.feed_data(data)
                self._ack = (self._ack + 1) & 0xffffffff
            # Ensure ACK is sent
            if self._ensure_ack_task is None:
                self._ensure_ack_task = asyncio.create_task(self._ensure_ack())
        # Process FIN
        if flags & self.FLAG_FIN:
            return self.close()

    async def recv(self) -> bytes | None:
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
            else:
                return self.close()
        except asyncio.IncompleteReadError as e:
            return

    async def send(self, data: bytes):
        if len(data) > self.MAX_MSG_SIZE:
            raise ValueError('Message is too large to send.')
        mlen = mlen_to_bytes(len(data))
        if len(mlen) + len(data) <= self.MAX_PAYLOAD:
            await self._send_datagram(mlen + data)
        else:
            offset = self.MAX_PAYLOAD - len(mlen)
            await self._send_datagram(mlen + data[:offset])
            for i in range(offset, len(data), self.MAX_PAYLOAD):
                await self._send_datagram(data[i:i+self.MAX_PAYLOAD])

    async def _send_datagram(self, data: bytes, flags: int = FLAG_ACK):
        while len(self._sent) > self._cwnd:
            self._wait_ack = asyncio.Future()
            await self._wait_ack
        self._wait_ack = None
        hdr = self.HEADER.pack(self._seq, self._ack, flags)
        pkt = b''.join([hdr, data])
        self.transport.sendto(pkt, self.addr)
        now = time.monotonic()
        self._last_sent = now
        self._sent[self._seq] = 1, now, pkt
        heapq.heappush(self._sent_heap, (now + self._rto, self._seq))
        self._seq = (self._seq + 1) & 0xffffffff
        if self._ensure_seq_task is None:
            self._ensure_seq_task = asyncio.create_task(self._ensure_seq())

    async def _ensure_syn(self):
        for attempt in range(self.MAX_ATTEMPTS):
            if self._peer_ack is not None:
                break
            # Send SYN
            seq, ack, flags = self._seq, self._ack, self.FLAG_SYN
            if ack is None:
                ack = 0
            else:
                # Send SYN + ACK
                flags |= self.FLAG_ACK
            hdr = self.HEADER.pack(seq, ack, flags)
            self.transport.sendto(hdr, self.addr)
            await asyncio.sleep(self._rto)
        if self._peer_ack is None:
            return self.close()

    async def _ensure_seq(self):
        while self._sent_heap:
            now = time.monotonic()
            while self._sent_heap and self._sent_heap[0][0] <= now:
                seq = heapq.heappop(self._sent_heap)[1]
                match self._sent.pop(seq, None):
                    case attempts, ts, pkt:
                        self.transport.sendto(pkt, self.addr)
                        self._sent[seq] = attempts + 1, now, pkt
                        heapq.heappush(self._sent_heap, (now + self._rto, seq))
            if self._sent_heap:
                wait = max(0.01, self._sent_heap[0][0] - time.monotonic())
                await asyncio.sleep(wait)

    async def _ensure_ack(self):
        pass

    def connect(self):
        pass

    def close(self):
        pass


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
            peer = self.mesh.accept(addr)
            if peer is None:
                return
        peer.datagram_received(data)

    def error_received(self, exc: OSError):
        logging.err(f'Error receieved: {exc}')


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

    async def start(self):
        pass

    async def stop(self):
        pass

    def connect(self, addr: Address) -> Socket:
        # Create connection
        peer = Socket(
            addr=addr,
            transport=self.transport,
            on_connect=self.handle_connect,
            on_close=self.handle_close
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
