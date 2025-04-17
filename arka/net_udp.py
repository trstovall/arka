
from __future__ import annotations
from typing import Callable, Generator, Coroutine, Any
import asyncio
import time
import logging
import struct

from os import urandom

import arka._crypto as crypto


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Constants
TIMEOUT = 10            # seconds
ACK_TIMEOUT = 1         # seconds
RECV_TIMEOUT = 0.1    # seconds
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
MSG_INIT = 2
MSG_CHALLENGE_ANSWER = 3
MSG_PUB_PEERS_UPDATE = 4
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


Address = tuple[str, int]
Socket = dict[str, asyncio.Queue]
Datagram = bytes
Keypair = bytes
PublicKey = bytes
Challenge = bytes
ChallengeAnswer = bytes




def len_to_bytes(n: int) -> bytes:
    if n < 0x80:
        n = bytes([n << 1])
    elif n < 0x4000:
        n = struct.pack('<H', (n << 2) | 1)
    else:
        n = struct.pack('<I', (n << 2) | 3)
    return n


def parse_len(x: bytes | bytearray) -> int:
    n = x[0]
    if n & 1:
        if n & 2:
            return struct.unpack('<I', x)[0] >> 2
        return struct.unpack('<H', x)[0] >> 2
    return n >> 1


def msg_ack(acks: list[tuple[int, int]]) -> bytes:
    buffer = [bytes([MSG_ACK]), len_to_bytes(len(acks))]
    if not acks:
        return b''.join(buffer)
    offset = acks[0][0]
    buffer.append(struct.pack('<Q', offset))
    for s, e in acks:
        buffer.append(len_to_bytes(s))
        buffer.append(len_to_bytes(e))
    return b''.join(buffer)


def msg_init(peer_id: PublicKey, challenge: Challenge) -> bytes:
        return b''.join([
            bytes([MSG_INIT]), ARKA_BANNER, peer_id, challenge
        ])


def msg_challenge_answer(answer: ChallengeAnswer) -> bytes:
        return bytes([MSG_CHALLENGE_ANSWER]) + answer


def msg_pub_peers_update(added: set[PublicKey], removed: set[PublicKey]) -> bytes:
    msg_type = bytes([MSG_PUB_PEERS_UPDATE])
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
        + list(added) + list(removed)
    )


def msg_meet_request(neighbor: PublicKey) -> bytes:
    return bytes([MSG_MEET_REQUEST]) + neighbor


def msg_meet_intro(neighbor: PublicKey, addr: Address) -> bytes:
    host = addr[0].encode()
    addr = b''.join([host, struct.pack('<H', addr[1])])
    return b''.join([bytes([MSG_MEET_INTRO]), neighbor, addr])


class Message(object):

    def __init__(self, msg: bytes | bytearray):
        self.msg = msg
        self.view = memoryview(self.msg)


class InitMessage(Message):

    def __init__(self, msg: bytes | bytearray):
        if len(msg) != 69:
            raise ValueError("msg argument for InitMessage must be 69 bytes long.")
        if msg[1:5] != b'arka':
            raise ValueError("arka banner not set for msg argument to InitMessage.")
        super().__init__(self, msg)
    
    @property
    def peer_id(self) -> PublicKey:
        return bytes(self.view[5:37])
    
    @property
    def challenge(self) -> Challenge:
        return bytes(self.view[37:69])


class ChallengeAnswerMessage(Message):

    def __init__(self, msg: bytes | bytearray):
        if len(msg) != 65:
            raise ValueError("msg argument for ChallengeAnswerMessage must be 65 bytes long.")
        super().__init__(self, msg)

    @property
    def answer(self) -> ChallengeAnswer:
        return bytes(self.view[1:])


class PubPeersUpdateMessage(Message):

    def __init__(self, msg: bytes | bytearray):
        super().__init__(self, msg)
        offset = 1
        if self.view[offset] & 1:
            self.num_added = struct.unpack_from('<H', self.view, offset)[0] >> 1
            offset += 2
        else:
            self.num_added = self.view[offset] >> 1
            offset += 1
        if self.view[offset] & 1:
            self.num_removed = struct.unpack_from('<H', self.view, offset)[0] >> 1
            offset += 2
        if len(msg) != offset + 32 * (self.num_added + self.num_removed):
            raise ValueError('Invalid msg passed to `PubPeersUpdateMessage`.')
        self.offset = offset

    @property
    def added(self) -> set[PublicKey]:
        start, end = self.offset, self.offset + 32 * self.num_added
        return {bytes(self.view[i:i+32]) for i in range(start, end, 32)}

    @property
    def removed(self) -> set[PublicKey]:
        start = self.offset + 32 * self.num_added
        end = start + 32 * self.num_removed
        return {bytes(self.view[i:i+32]) for i in range(start, end, 32)}


class MeetRequestMessage(Message):

    def __init__(self, msg: bytes | bytearray):
        if len(msg) != 33:
            raise ValueError('Invalid message size for `MeetRequestMessage`.')
        super().__init__(self, msg)
    
    @property
    def neighbor(self) -> PublicKey:
        return bytes(self.view[1:33])


class MeetIntroMessage(Message):

    @property
    def neighbor(self) -> PublicKey:
        n = bytes(self.view[2:34])
        if len(n) != 32:
            raise ValueError('Invalid message size for `MeetIntroMessage`.')
        return n

    @property
    def addr(self) -> Address:
        host = bytes(self.view[34:-2]).decode()
        port = struct.unpack('<H', self.msg[-2:])[0]
        return host, port


class MeshProtocol(asyncio.DatagramProtocol):
    '''Protocol to handle UDP datagrams for the Mesh class.'''
    def __init__(self, mesh: Mesh):
        self.mesh = mesh

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
    
    def datagram_received(self, data: Datagram, addr: Address):
        peer = self.mesh.peers.get(addr)
        if peer is not None:
            peer.frag_q.put_nowait(data)

    def error_received(self, exc: OSError):
        logging.err(f'Error receieved: {exc}')


RecvCoroutine = Callable[[Message, Socket], Coroutine[Any, Any, None]]


class Socket(object):

    def __init__(self,
        id: int,
        addr: Address,
        loop: asyncio.AbstractEventLoop | None = None,
        handle_recv_q: RecvCoroutine = None,
        handle_close: Callable[[Socket], None] = None,

        **kws
    ):
        self.addr = addr
        self.id = id
        self.loop = loop or asyncio.get_running_loop()
        self.handle_recv_q = handle_recv_q
        self.handle_close = handle_close
        self.connected: bool = False

    def __await__(self) -> Generator[Any, None, Socket]:
        return self.connect().__await__()
    
    async def connect(self) -> Socket:
        if not self.connected:
            self.connected = True
            self.seq_num: int = 0   # Strictly increasing number for next fragment
            self.unacked: int = 0
            self.last_seen: float = time.time()
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

    async def close(self):
        if self.connected:
            self.connected = False
            await self.frag_q.put(None)
            await self.recv_q.put(None)
            await self.send_q.put(None)
            await self.s_ack_q.put(None)
            await self.r_ack_q.put(None)
            if self.handle_close is not None:
                self.handle_close(self)

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
                

class Mesh(object):

    def __init__(self,
            keypair: Keypair, bootstrap: list[Address] = [],
            loop: asyncio.AbstractEventLoop | None = None
    ):
        self.keypair = keypair
        self.bootstrap = bootstrap
        self.loop = loop or asyncio.get_running_loop()
        self.peer_id: PublicKey = keypair[32:64]
        self.peers: dict[Address, Socket] = {}
        self.blacklist: dict[Address | PublicKey, float] = {}
        self.transport: asyncio.DatagramTransport = None
        self.running: bool = False

    async def handle_datagram(self, data: Datagram, addr: Address):
        '''Map Datagram to self.peers[addr]['defrag'] queue.'''
        # 
        peer = self.peers.get(addr)
        if peer is None:
            peer = await self.connect(addr)
        await peer.send(data)

    async def connect(self, addr: Address) -> Socket:
        peer = await Socket(
            addr=addr,
            disconnect_cb=self.disconnect,
            recv_cb=self.handle_recv
        )
        # Add (addr) -> (peer) to self.peers
        self.peers[addr] = peer
        return peer

    async def disconnect(self, peer: Socket):
        peer = self.peers.pop(peer.addr, None)
        if peer is not None:
            await peer.disconnect()

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

    async def keepalive(self, peer: Socket):
        addr: Address = peer['addr']
        sent: dict[int, tuple[float, int, Datagram]] = peer['sent']
        while peer['keepalive'] is not None:
            await asyncio.sleep(max(0, peer['keepalive'] - time.time()))
            if peer['keepalive'] is None:
                break
            if time.time() > peer['keepalive']:
                # Send keepalive
                id = peer['seq_num']
                data: Datagram = struct.pack('<QI', (id << 1) + 1, 1)
                retries = 0
                timeout = time.time() + ACK_TIMEOUT
                self.transport.sendto(data, addr)
                peer['keepalive'] = time.time() + KEEPALIVE_TIMEOUT
                sent[id] = timeout, retries, data
