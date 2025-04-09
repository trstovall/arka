
from __future__ import annotations
import asyncio
import logging
import struct
import arka._crypto as crypto
import time

from os import urandom


# Constants
TIMEOUT = 10        # seconds
ACK_TIMEOUT = 1     # seconds
MAX_RETRIES = 3
RETRY_DELAY = 2     # seconds
BACKOFF_MULTIPLIER = 1.5
ARKA_BANNER = b'arka'
MAX_FRAGMENTS = 2**13
FRAGMENT_SIZE = 1024

# Message Types
MSG_INIT = 1
MSG_CHALLENGE_ANSWER = 2
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


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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
    return bytes([MSG_MEET_INTRO]) + neighbor + addr


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


class PeerProtocol(asyncio.DatagramProtocol):
    '''Protocol to handle UDP datagrams for the Peer class.'''
    def __init__(self, peer: Peer):
        self.peer = peer

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
    
    def datagram_received(self, data: Datagram, addr: Address):
        loop = asyncio.get_running_loop()
        loop.create_task(self.peer.handle_message(data, addr))

    def error_received(self, exc: Exception):
        logging.err(f'Error receieved: {exc}')


class Peer(object):

    def __init__(self,
            keypair: Keypair, bootstrap: list[Address] = [],
            loop: asyncio.AbstractEventLoop | None = None
    ):
        self.keypair = keypair
        self.bootstrap = bootstrap
        self.loop = loop or asyncio.get_running_loop()
        self.peer_id: PublicKey = keypair[32:64]
        self.peers: dict[Address, Socket] = {}
        self.blacklist: dict[Address | PublicKey, int] = {}
        self.transport: asyncio.DatagramTransport = None
        self.running = False

    async def handle_message(self, data: Datagram, addr: Address):
        '''Map Datagram to self.peers[addr]['defrag'] queue.'''
        peer = self.peers.get(addr) or self.connect(addr)
        if peer is None:
            return
        await peer['defrag'].put(data)

    def connect(self, addr: Address) -> Socket | None:
        # Check blacklist
        timeout = self.blacklist.get(addr, 0)
        if timeout:
            if time.time() < timeout:
                # Drop Datagrams from blacklisted peers
                return
            del self.blacklist[addr]
        # Create peer
        defrag: asyncio.Queue[Datagram] = asyncio.Queue()
        recv: asyncio.Queue[Message] = asyncio.Queue()
        send: asyncio.Queue[Message] = asyncio.Queue()
        ack: asyncio.Queue[tuple[int, int]] = asyncio.Queue()
        keys = 'addr defrag recv send ack'.split()
        peer: Socket = {k: locals()[k] for k in keys}
        # Add (addr) -> (peer) to self.peers
        self.peers[addr] = peer
        # Add tasks to process pipeline
        self.loop.create_task(self.handle_peer(peer))
        self.loop.create_task(self.send(peer))
        self.loop.create_task(self.recv(peer))
        return peer

    async def disconnect(self, peer: Socket):
        del self.peers[peer['addr']]
        await peer['defrag'].put(None)
        await peer['recv'].put(None)
        await peer['send'].put(None)

    async def handle_peer(self, peer: Socket):
        '''Listen for Messages on peer['recv'] queue and
            respond with Messages on peer['send'] queue.
        '''
        # Send MSG_INIT
        local_challenge: Challenge = urandom(32)
        msg = msg_init(self.peer_id, local_challenge)
        await peer['send'].put(msg)
        # Await MSG_INIT
        msg = await peer['recv'].get()


    async def send(self, peer: Socket):
        def prefix_len_to_bytes(x: bytes) -> bytes:
            n = len(x)
            if n < 0x80:
                n = bytes([n << 1])
            elif n < 0x4000:
                n = struct.pack('<H', (n << 2) | 1)
            else:
                n = struct.pack('<I', (n << 2) | 3)
            return n + x
        addr: Address = peer['addr']
        send_q: asyncio.Queue[Message] = peer['send']
        ack_q: asyncio.Queue[tuple[int, int]] = peer['ack']
        seq_num: int = 0
        unacked: int = 0
        acks: dict[int, int] = {}
        sent: dict[int, tuple[float, int, Datagram]] = {}
        process_acks_schedule = time.time() + ACK_TIMEOUT
        process_send_schedule = time.time() + ACK_TIMEOUT / 10
        while self.running:
            # Process ACKs periodically
            if time.time() > process_acks_schedule:
                # Add (ack_start) -> (ack_end) to acks dict
                while not ack_q.empty():
                    ack_start, ack_end = await ack_q.get()
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
                    if acked:
                        frag_id = acked + 1
                        continue
                    match sent[frag_id]:
                        case timeout, retries, data:
                            if time.time() < timeout:
                                frag_id += 1
                                continue
                            if retries < MAX_RETRIES:
                                self.transport.sendto(data, addr)
                                retries += 1
                                timeout += ACK_TIMEOUT
                                sent[frag_id] = timeout, retries, data
                                frag_id += 1
                            else:
                                return await self.disconnect(peer)
                # reschedule ack processing
                process_acks_schedule = time.time() + ACK_TIMEOUT
            # Process peer['send'] continuously
            send_batch: list[Message] = []
            try:
                while time.time() < process_send_schedule:
                    wait = max(0, process_send_schedule - time.time())
                    msg: Message = asyncio.wait_for(send_q.get(), wait)
                    send_batch.append(msg)
            except asyncio.TimeoutError as e:
                pass
            buffer = b''.join(
                prefix_len_to_bytes(m.msg)
                for m in send_batch
            )
            n_frags = len(buffer) >> 10 + (1 if len(buffer) & 1023 else 0)
            for i in range(n_frags):
                frag = buffer[i<<10:(i+1)<<10]
                id = seq_num
                seq_num += 1
                timeout = time.time() + ACK_TIMEOUT
                retries = 0
                if not i:
                    data = struct.pack('<QI', id, n_frags) + frag
                else:
                    data = struct.pack('<Q', id) + frag
                self.transport.sendto(data, addr)
                sent[id] = timeout, retries, data

            process_send_schedule = time.time() + ACK_TIMEOUT / 10

    async def recv(self, peer: Socket):
        addr: Address = peer['addr']
        while self.peers.get(addr) is not None:
            asyncio.sleep(1)