
from __future__ import annotations
from typing import Callable, Generator, Coroutine, Any
import asyncio
import time
import logging
import struct
import socket

from os import urandom


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Constants
BLACKLIST_TIMEOUT = 600 # seconds
ACK_TIMEOUT = 1         # seconds
RECV_TIMEOUT = 0.1      # seconds
SEND_TIMEOUT = 0.1      # seconds
KEEPALIVE_TIMEOUT = 15  # seconds
MAX_RETRIES = 5
RETRY_DELAY = 2         # seconds
BACKOFF_MULTIPLIER = 1.5
ARKA_BANNER = b'arka'
MAX_FRAGMENTS = 2**13
FRAGMENT_SIZE = 1024

# Message Types
MSG_ACK = 1
MSG_PEERS_UPDATE = 4
MSG_MEET_REQUEST = 5
MSG_MEET_INTRO = 6
MSG_SUB_TX_HASH = 7
MSG_PUB_TX_HASH = 8
MSG_TX_REQUEST = 9
MSG_TX_RESPONSE = 10
MSG_SUB_BLOCK_HASH = 11
MSG_PUB_BLOCK_HASH = 12
MSG_BLOCK_REQUEST = 13
MSG_BLOCK_RESPONSE = 14
MSG_ERROR = 255


# Type aliases
Address = tuple[str, int]
Datagram = bytes
MessageList = bytes
Message = bytes | bytearray


### Helpers

def varint_to_bytes(n: int) -> bytes:
    if n < 0x80:
        n = bytes([n << 1])
    elif n < 0x4000:
        n = struct.pack('<H', (n << 2) | 1)
    else:
        n = struct.pack('<I', (n << 2) | 3)
    return n

def parse_message_list(x: MessageList) -> list[Message]:
    n = x[0]
    if n & 1:
        if n & 2:
            return struct.unpack('<I', x)[0] >> 2
        return struct.unpack('<H', x)[0] >> 2
    return n >> 1

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

def msg_ack(acks: list[tuple[int, int]]) -> Message:
    buffer = [bytes([MSG_ACK]), varint_to_bytes(len(acks))]
    if not acks:
        return b''.join(buffer)
    min_ack = acks[0][0]
    max_ack = acks[-1][1]
    diff = max_ack - min_ack
    if diff < 0x100:
        format = '<BB'
        ack_len = 1
    elif diff < 0x10000:
        format = '<HH'
        ack_len = 2
    else:
        raise ValueError('Too many acks to serialize.')
    buffer.append(struct.pack('<QB', min_ack, ack_len))
    for s, e in acks:
        buffer.append(struct.pack(format, s, e))
    return b''.join(buffer)


def msg_peers_update(added: set[Address], removed: set[Address]) -> Message:
    msg_type = bytes([MSG_PEERS_UPDATE])
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
    return bytes([MSG_MEET_REQUEST]) + addr_to_bytes(neighbor)


def msg_meet_intro(neighbor: Address) -> Message:
    return bytes([MSG_MEET_INTRO]) + addr_to_bytes(neighbor)


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
        peer = self.mesh.peers.get(addr) or self.mesh.connect(addr)
        # Push Datagram into Socket pipeline
        peer.frag_q.put_nowait(data)

    def error_received(self, exc: OSError):
        logging.err(f'Error receieved: {exc}')


### Socket

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
            self.seq_num: int = 0   # Strictly increasing number for next fragment
            self.unacked: int = 0
            self.sent: dict[int, tuple[float, int, Datagram]] = {}
            self.frag_q: asyncio.Queue[Datagram] = asyncio.Queue()
            self.recv_q: asyncio.Queue[Message] = asyncio.Queue()
            self.send_q: asyncio.Queue[Message] = asyncio.Queue()
            self.s_ack_q: asyncio.Queue[tuple[int, int]] = asyncio.Queue()
            self.r_ack_q: asyncio.Queue[tuple[int, int]] = asyncio.Queue()
            self.loop.create_task(self.handle_frag_q())
            if self.handle_recv_q is not None:
                self.loop.create_task(self.handle_recv_q())
            self.loop.create_task(self.handle_send_q())
            self.loop.create_task(self.handle_s_ack_q())
            self.loop.create_task(self.handle_r_ack_q())
        return self

    def close(self, blacklist: bool = True):
        if self.connected:
            self.connected = False
            self.frag_q.put_nowait(None)
            self.recv_q.put_nowait(None)
            self.send_q.put_nowait(None)
            self.s_ack_q.put_nowait(None)
            self.r_ack_q.put_nowait(None)
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
        while self.connected:
            # Consume Datagrams from frag_q
            timeout: float = time.time() + RECV_TIMEOUT
            while time.time() < timeout and self.connected:
                if not self.frag_q.empty:
                    data: Datagram = self.frag_q.get_nowait()
                else:
                    try:
                        data: Datagram = await asyncio.wait_for(
                            fut=self.frag_q.get(), timeout=RECV_TIMEOUT
                        )
                    except asyncio.TimeoutError as e:
                        if time.time() > self.last_seen + KEEPALIVE_TIMEOUT * MAX_RETRIES:
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
